/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/hidp.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "logging.h"
#include "textfile.h"

#include "device.h"
#include "server.h"
#include "error.h"
#include "manager.h"
#include "storage.h"
#include "glib-helper.h"

struct pending_req {
	char		*adapter_path;	/* Local adapter D-Bus path */
	bdaddr_t	src;		/* Local adapter BT address */
	bdaddr_t	dst;		/* Peer BT address */
	DBusConnection	*conn;
	DBusMessage	*msg;
	sdp_list_t	*pnp_recs;
	sdp_list_t	*hid_recs;
	GIOChannel	*ctrl_channel;
};

static int idle_timeout = 0;

static GSList *device_paths = NULL;	/* Input registered paths */

static DBusConnection *connection = NULL;

static struct pending_req *pending_req_new(DBusConnection *conn,
			DBusMessage *msg, bdaddr_t *src, bdaddr_t *dst)
{
	char adapter[18], adapter_path[32];
	struct pending_req *pr;
	int dev_id;

	pr = g_try_new0(struct pending_req, 1);
	if (!pr)
		return NULL;

	ba2str(src, adapter);
	dev_id = hci_devid(adapter);
	snprintf(adapter_path, 32, "/org/bluez/hci%d", dev_id);

	pr->adapter_path = g_strdup(adapter_path);
	bacpy(&pr->src, src);
	bacpy(&pr->dst, dst);
	pr->conn = dbus_connection_ref(conn);
	pr->msg = dbus_message_ref(msg);

	return pr;
}

static void pending_req_free(struct pending_req *pr)
{
	if (!pr)
		return;

	if (pr->adapter_path)
		g_free(pr->adapter_path);

	if (pr->conn)
		dbus_connection_unref(pr->conn);

	if (pr->msg)
		dbus_message_unref(pr->msg);

	if (pr->pnp_recs)
		sdp_list_free(pr->pnp_recs, (sdp_free_func_t) sdp_record_free);

	if (pr->hid_recs)
		sdp_list_free(pr->hid_recs, (sdp_free_func_t) sdp_record_free);

	g_free(pr);
}

static void epox_endian_quirk(unsigned char *data, int size)
{
	/* USAGE_PAGE (Keyboard)	05 07
	 * USAGE_MINIMUM (0)		19 00
	 * USAGE_MAXIMUM (65280)	2A 00 FF   <= must be FF 00
	 * LOGICAL_MINIMUM (0)		15 00
	 * LOGICAL_MAXIMUM (65280)	26 00 FF   <= must be FF 00
	 */
	unsigned char pattern[] = { 0x05, 0x07, 0x19, 0x00, 0x2a, 0x00, 0xff,
						0x15, 0x00, 0x26, 0x00, 0xff };
	int i;

	if (!data)
		return;

	for (i = 0; i < size - sizeof(pattern); i++) {
		if (!memcmp(data + i, pattern, sizeof(pattern))) {
			data[i + 5] = 0xff;
			data[i + 6] = 0x00;
			data[i + 10] = 0xff;
			data[i + 11] = 0x00;
		}
	}
}

static void extract_hid_record(sdp_record_t *rec, struct hidp_connadd_req *req)
{
	sdp_data_t *pdlist, *pdlist2;
	uint8_t attr_val;

	pdlist = sdp_data_get(rec, 0x0101);
	pdlist2 = sdp_data_get(rec, 0x0102);
	if (pdlist) {
		if (pdlist2) {
			if (strncmp(pdlist->val.str, pdlist2->val.str, 5)) {
				strncpy(req->name, pdlist2->val.str, 127);
				strcat(req->name, " ");
			}
			strncat(req->name, pdlist->val.str, 127 - strlen(req->name));
		} else
			strncpy(req->name, pdlist->val.str, 127);
	} else {
		pdlist2 = sdp_data_get(rec, 0x0100);
		if (pdlist2)
			strncpy(req->name, pdlist2->val.str, 127);
 	}

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_PARSER_VERSION);
	req->parser = pdlist ? pdlist->val.uint16 : 0x0100;

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_DEVICE_SUBCLASS);
	req->subclass = pdlist ? pdlist->val.uint8 : 0;

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_COUNTRY_CODE);
	req->country = pdlist ? pdlist->val.uint8 : 0;

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_VIRTUAL_CABLE);
	attr_val = pdlist ? pdlist->val.uint8 : 0;
	if (attr_val)
		req->flags |= (1 << HIDP_VIRTUAL_CABLE_UNPLUG);

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_BOOT_DEVICE);
	attr_val = pdlist ? pdlist->val.uint8 : 0;
	if (attr_val)
		req->flags |= (1 << HIDP_BOOT_PROTOCOL_MODE);

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_DESCRIPTOR_LIST);
	if (pdlist) {
		pdlist = pdlist->val.dataseq;
		pdlist = pdlist->val.dataseq;
		pdlist = pdlist->next;

		req->rd_data = g_try_malloc0(pdlist->unitSize);
		if (req->rd_data) {
			memcpy(req->rd_data, (unsigned char *) pdlist->val.str,
								pdlist->unitSize);
			req->rd_size = pdlist->unitSize;
			epox_endian_quirk(req->rd_data, req->rd_size);
		}
	}
}

static void extract_pnp_record(sdp_record_t *rec, struct hidp_connadd_req *req)
{
	sdp_data_t *pdlist;

	pdlist = sdp_data_get(rec, SDP_ATTR_VENDOR_ID);
	req->vendor = pdlist ? pdlist->val.uint16 : 0x0000;

	pdlist = sdp_data_get(rec, SDP_ATTR_PRODUCT_ID);
	req->product = pdlist ? pdlist->val.uint16 : 0x0000;

	pdlist = sdp_data_get(rec, SDP_ATTR_VERSION);
	req->version = pdlist ? pdlist->val.uint16 : 0x0000;
}

static void interrupt_connect_cb(GIOChannel *chan, int err,
			const bdaddr_t *src, const bdaddr_t *dst,
			gpointer user_data)
{
	struct pending_req *pr = user_data;
	struct hidp_connadd_req hidp;
	const char *path;

	memset(&hidp, 0, sizeof(hidp));

	if (err < 0) {
		error("connect(): %s (%d)", strerror(-err), -err);
		goto failed;
	}

	g_io_channel_close(chan);
	g_io_channel_unref(chan);

	hidp.idle_to = idle_timeout * 60;

	extract_hid_record(pr->hid_recs->data, &hidp);
	if (pr->pnp_recs)
		extract_pnp_record(pr->pnp_recs->data, &hidp);

	store_device_info(&pr->src, &pr->dst, &hidp);

	if (input_device_register(pr->conn, &pr->src,
					&pr->dst, &hidp, &path) < 0) {
		error_failed(pr->conn, pr->msg, "path registration failed");
		goto cleanup;
	}

	g_dbus_emit_signal(pr->conn, INPUT_PATH,
			INPUT_MANAGER_INTERFACE, "DeviceCreated",
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	device_paths = g_slist_append(device_paths, g_strdup(path));

	g_dbus_send_reply(pr->conn, pr->msg,  DBUS_TYPE_STRING, &path,
							DBUS_TYPE_INVALID);

	goto cleanup;

failed:
	error_connection_attempt_failed(pr->conn, pr->msg, err);

cleanup:
	g_io_channel_close(pr->ctrl_channel);
	g_io_channel_unref(pr->ctrl_channel);
	pending_req_free(pr);

	if (hidp.rd_data)
		g_free(hidp.rd_data);
}

static void control_connect_cb(GIOChannel *chan, int err, const bdaddr_t *src,
			const bdaddr_t *dst, gpointer user_data)
{
	struct pending_req *pr = user_data;

	if (err < 0) {
		error("connect(): %s (%d)", strerror(-err), -err);
		goto failed;
	}

	/* Set HID control channel */
	pr->ctrl_channel = chan;

	/* Connect to the HID interrupt channel */
	err = bt_l2cap_connect(&pr->src, &pr->dst, L2CAP_PSM_HIDP_INTR, 0,
			interrupt_connect_cb, pr);
	if (err < 0) {
		error("L2CAP connect failed:%s (%d)", strerror(-err), -err);
		goto failed;
	}

	return;

failed:
	error_connection_attempt_failed(pr->conn, pr->msg, -err);
	pending_req_free(pr);
}

static void create_bonding_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	DBusError derr;
	int err;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("CreateBonding failed: %s(%s)",
					derr.name, derr.message);
		error_failed(pr->conn, pr->msg, "Authentication failed (CreateBonding)");
		dbus_error_free(&derr);
		dbus_message_unref(reply);
		pending_req_free(pr);
		return;
	}

	dbus_message_unref(reply);

	err = bt_l2cap_connect(&pr->src, &pr->dst, L2CAP_PSM_HIDP_CTRL, 0,
			control_connect_cb, pr);
	if (err < 0) {
		error("L2CAP connect failed:%s (%d)", strerror(-err), -err);
		error_connection_attempt_failed(pr->conn, pr->msg, -err);
		pending_req_free(pr);
	}
}

static int create_bonding(struct pending_req *pr)
{
	DBusPendingCall *pending;
	DBusMessage *msg;
	char address[18], *addr_ptr = address;

	msg = dbus_message_new_method_call("org.bluez", pr->adapter_path,
					"org.bluez.Adapter", "CreateBonding");
	if (!msg) {
		error("Unable to allocate new method call");
		return -1;
	}

	ba2str(&pr->dst, address);
	dbus_message_append_args(msg, DBUS_TYPE_STRING, &addr_ptr, DBUS_TYPE_INVALID);
	if (dbus_connection_send_with_reply(pr->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		dbus_message_unref(msg);
		return -1;
	}
	dbus_pending_call_set_notify(pending, create_bonding_reply, pr, NULL);
	dbus_pending_call_unref(pending);
	dbus_message_unref(msg);
	return 0;
}

static void hid_record_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct pending_req *pr = user_data;

	if (err < 0) {
		error_not_supported(pr->conn, pr->msg);
		error("SDP search error: %s (%d)", strerror(-err), -err);
		goto fail;
	}

	if (!recs || !recs->data) {
		error_not_supported(pr->conn, pr->msg);
		error("Invalid HID service record length");
		goto fail;
	}

	pr->hid_recs = recs;

	if (strcmp("CreateSecureDevice", dbus_message_get_member(pr->msg)) == 0) {
		sdp_data_t *d;

		/* Pairing mandatory for keyboard and combo */
		d = sdp_data_get(pr->hid_recs->data,
				SDP_ATTR_HID_DEVICE_SUBCLASS);
		if (d && (d->val.uint8 & 0x40) &&
				!has_bonding(&pr->src, &pr->dst)) {
			if (create_bonding(pr) < 0) {
				error_failed(pr->conn, pr->msg,
					"Unable to initialize bonding process");
				goto fail;
			}
			/* Wait bonding reply */
			return;
		}

		/* Otherwise proceede L2CAP connection */
	}

	/* No encryption or link key already exists -- connect control channel */
	err = bt_l2cap_connect(&pr->src, &pr->dst, L2CAP_PSM_HIDP_CTRL, 0,
			control_connect_cb, pr);
	if (err < 0) {
		error("L2CAP connect failed:%s (%d)", strerror(-err), -err);
		error_connection_attempt_failed(pr->conn, pr->msg, -err);
		goto fail;
	}

	/* Wait L2CAP connect */
	return;

fail:
	pending_req_free(pr);
}

static void pnp_record_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct pending_req *pr = user_data;
	uuid_t uuid;

	if (err < 0) {
		error_not_supported(pr->conn, pr->msg);
		error("SDP search error: %s (%d)", strerror(-err), -err);
		goto fail;
	}

	if (!recs || !recs->data) {
		error_not_supported(pr->conn, pr->msg);
		error("Invalid PnP service record length");
		goto fail;
	}

	pr->pnp_recs = recs;
	sdp_uuid16_create(&uuid, HID_SVCLASS_ID);
	err = bt_search_service(&pr->src, &pr->dst, &uuid, hid_record_cb,
			pr, NULL);
	if (err < 0) {
		error_not_supported(pr->conn, pr->msg);
		error("HID service search request failed");
		goto fail;
	}

	return;

fail:
	pending_req_free(pr);
}

static void headset_record_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct pending_req *pr = user_data;
	sdp_record_t *rec;
	sdp_list_t *protos;
	const char *path;
	uint8_t ch;

	if (err < 0) {
		error_not_supported(pr->conn, pr->msg);
		error("SDP search error: %s (%d)", strerror(-err), -err);
		goto fail;
	}

	if (!recs || !recs->data) {
		error_not_supported(pr->conn, pr->msg);
		error("Invalid headset service record length");
		goto fail;
	}

	rec = recs->data;

	if (sdp_get_access_protos(rec, &protos) < 0) {
		error_not_supported(pr->conn, pr->msg);
		goto fail;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);
	sdp_record_free(rec);

	if (ch <= 0) {
		error_not_supported(pr->conn, pr->msg);
		error("Invalid RFCOMM channel");
		goto fail;
	}

	/* FIXME: Store the fake input data */

	if (fake_input_register(pr->conn, &pr->src, &pr->dst, ch, &path) < 0) {
		error("D-Bus path registration failed:%s", path);
		error_failed(pr->conn, pr->msg, "Path registration failed");
		goto fail;
	}

	g_dbus_emit_signal(pr->conn, INPUT_PATH,
			INPUT_MANAGER_INTERFACE, "DeviceCreated",
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	device_paths = g_slist_append(device_paths, g_strdup(path));

	g_dbus_send_reply(pr->conn, pr->msg, DBUS_TYPE_STRING, &path,
							DBUS_TYPE_INVALID);

fail:
	pending_req_free(pr);
}

static inline DBusMessage *adapter_not_available(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
						"Adapter not available");
}

static inline DBusMessage *already_exists(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".AlreadyExists",
						"Input Already exists");
}

static inline DBusMessage *not_supported(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotSupported",
							"Not supported");
}

static inline DBusMessage *does_not_exist(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".AlreadyExists",
							"Input doesn't exist");
}

static DBusMessage *create_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct pending_req *pr;
	const char *addr;
	bdaddr_t src, dst;
	uint32_t cls = 0;
	int dev_id, err;
	uuid_t uuid;
	bt_callback_t cb;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &addr,
							DBUS_TYPE_INVALID))
		return NULL;

	/* Get the default adapter */
	dev_id = hci_get_route(NULL);
	if (dev_id < 0) {
		error("Bluetooth adapter not available");
		return adapter_not_available(msg);
	}

	if (hci_devba(dev_id, &src) < 0) {
		error("Can't get local adapter device info");
		return adapter_not_available(msg);
	}

	str2ba(addr, &dst);
	if (input_device_is_registered(&src, &dst))
		return already_exists(msg);

	if (read_device_class(&src, &dst, &cls) < 0) {
		error("Device class not available");
		return not_supported(msg);
	}

	pr = pending_req_new(conn, msg, &src, &dst);
	if (!pr)
		return NULL;

	switch (cls & 0x1f00) {
		case 0x0500: /* Peripheral */
		case 0x0200: /* Phone */
			sdp_uuid16_create(&uuid, PNP_INFO_SVCLASS_ID);
			cb = pnp_record_cb;
			break;
		case 0x0400: /* Fake input */
			sdp_uuid16_create(&uuid, HEADSET_SVCLASS_ID);
			cb = headset_record_cb;
			break;
		default:
			pending_req_free(pr);
			return not_supported(msg);
	}

	err = bt_search_service(&src, &dst, &uuid, cb, pr, NULL);
	if (err < 0) {
		pending_req_free(pr);
		return not_supported(msg);
	}

	return NULL;
}

static DBusMessage *remove_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	GSList *l;
	const char *path;
	int err;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &path,
							DBUS_TYPE_INVALID))
		return NULL;

	l = g_slist_find_custom(device_paths, path, (GCompareFunc) strcmp);
	if (!l)
		return does_not_exist(msg);

	err = input_device_unregister(conn, path);
	if (err < 0)
		return create_errno_message(msg, -err);

	g_free(l->data);
	device_paths = g_slist_remove(device_paths, l->data);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *list_devices(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter, iter_array;
	DBusMessage *reply;
	GSList *paths;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &iter_array);

	for (paths = device_paths; paths != NULL; paths = paths->next) {
		const char *ppath = paths->data;
		dbus_message_iter_append_basic(&iter_array,
					DBUS_TYPE_STRING, &ppath);
	}

	dbus_message_iter_close_container(&iter, &iter_array);

	return reply;
}

static void manager_unregister(void *data)
{
	info("Unregistered manager path");

	g_slist_foreach(device_paths, (GFunc) free, NULL);

	g_slist_free(device_paths);
}

/*
 * Stored inputs registration functions
 */

static void stored_input(char *key, char *value, void *data)
{
	const char *path;
	struct hidp_connadd_req hidp;
	bdaddr_t dst, *src = data;

	str2ba(key, &dst);

	memset(&hidp, 0, sizeof(hidp));

	if (parse_stored_device_info(value, &hidp) < 0)
		return;

	/*
	 * Repeated entries for the same remote device are
	 * acceptable since the source is different.
	 */
	if (input_device_register(connection, src, &dst, &hidp, &path) < 0)
		goto cleanup;

	device_paths = g_slist_append(device_paths, g_strdup(path));
cleanup:
	if (hidp.rd_data)
		g_free(hidp.rd_data);
}

/* hidd to input transition function */
static void stored_hidd(char *key, char *value, void *data)
{
	struct hidp_connadd_req hidp;
	char *str, filename[PATH_MAX + 1], addr[18];
	bdaddr_t dst, *src = data;

	ba2str(src, addr);
	create_name(filename, PATH_MAX, STORAGEDIR, addr, "input");

	str = textfile_get(filename, key);
	if (str) {
		/* Skip: entry found in input file */
		free(str);
		return;
	}

	memset(&hidp, 0, sizeof(hidp));

	if (parse_stored_hidd(value, &hidp) < 0)
		return;

	str2ba(key, &dst);
	store_device_info(src, &dst, &hidp);
	if (hidp.rd_data)
		g_free(hidp.rd_data);
}

static void register_stored_inputs(void)
{
	char dirname[PATH_MAX + 1];
	char filename[PATH_MAX + 1];
	struct dirent *de;
	DIR *dir;
	bdaddr_t src;

	snprintf(dirname, PATH_MAX, "%s", STORAGEDIR);

	dir = opendir(dirname);
	if (!dir)
		return;

	while ((de = readdir(dir)) != NULL) {
		if (!isdigit(de->d_name[0]))
			continue;

		str2ba(de->d_name, &src);

		/* move the hidd entries to the input storage */
		create_name(filename, PATH_MAX, STORAGEDIR,
						de->d_name, "hidd");
		textfile_foreach(filename, stored_hidd, &src);

		/* load the input stored devices */
		create_name(filename, PATH_MAX, STORAGEDIR,
						de->d_name, "input");

		textfile_foreach(filename, stored_input, &src);
	}

	closedir(dir);
}

static GDBusMethodTable manager_methods[] = {
	{ "ListDevices",	"",	"as",	list_devices },
	{ "CreateDevice",	"s",	"s",	create_device,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "CreateSecureDevice",	"s",	"s",	create_device,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "RemoveDevice",	"s",	"",	remove_device },
	{ }
};

static GDBusSignalTable manager_signals[] = {
	{ "DeviceCreated",	"s"	},
	{ "DeviceRemoved",	"s"	},
	{ }
};

int input_manager_init(DBusConnection *conn, GKeyFile *config)
{
	GError *err = NULL;
 
	if (config) {
		idle_timeout = g_key_file_get_integer(config, "General",
						"IdleTimeout", &err);
		if (err) {
			debug("input.conf: %s", err->message);
			g_error_free(err);
		}
	}

	if (g_dbus_register_interface(conn, INPUT_PATH, INPUT_MANAGER_INTERFACE,
					manager_methods, manager_signals, NULL,
					NULL, manager_unregister) == FALSE) {
		error("Failed to register %s interface to %s",
				INPUT_MANAGER_INTERFACE, INPUT_PATH);
		return -1;
	}

	connection = dbus_connection_ref(conn);

	info("Registered input manager path:%s", INPUT_PATH);

	/* Register well known HID devices */
	register_stored_inputs();

	server_start();

	return 0;
}

void input_manager_exit(void)
{
	g_dbus_unregister_interface(connection, INPUT_PATH,
						INPUT_MANAGER_INTERFACE);

	server_stop();

	dbus_connection_unref(connection);

	connection = NULL;
}
