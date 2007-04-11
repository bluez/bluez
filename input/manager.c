/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdlib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/hidp.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "logging.h"
#include "textfile.h"

#include "device.h"
#include "server.h"
#include "error.h"
#include "manager.h"
#include "storage.h"

const char *pnp_uuid		= "00001200-0000-1000-8000-00805f9b34fb";
const char *hid_uuid 		= "00001124-0000-1000-8000-00805f9b34fb";
const char *headset_uuid	= "00001108-0000-1000-8000-00805f9b34fb";

struct pending_req {
	char		*adapter_path;	/* Local adapter D-Bus path */
	bdaddr_t	src;		/* Local adapter BT address */
	bdaddr_t	dst;		/* Peer BT address */
	DBusConnection	*conn;
	DBusMessage	*msg;
	sdp_record_t	*pnp_rec;
	sdp_record_t	*hid_rec;
};

struct manager {
	bdaddr_t	src;
	GSList		*paths;		/* Input registered paths */
};

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
	if (pr->pnp_rec)
		sdp_record_free(pr->pnp_rec);
	if (pr->hid_rec)
		sdp_record_free(pr->hid_rec);
	g_free(pr);
}

static int path_bdaddr_cmp(const char *path, const bdaddr_t *bdaddr)
{
	struct device *idev;

	if (!dbus_connection_get_object_path_data(connection, path,
							(void *) &idev))
		return -1;

	if (!idev)
		return -1;

	return bacmp(&idev->dst, bdaddr);
}

static int get_record(struct pending_req *pr, uint32_t handle,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	char addr[18];
	const char *paddr = addr;

	msg = dbus_message_new_method_call("org.bluez", pr->adapter_path,
			"org.bluez.Adapter", "GetRemoteServiceRecord");
	if (!msg)
		return -1;

	ba2str(&pr->dst, addr);
	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &paddr,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(pr->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pr, NULL);
	dbus_message_unref(msg);

	return 0;
}

static int get_handles(struct pending_req *pr, const char *uuid,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	char addr[18];
	const char *paddr = addr;

	msg  = dbus_message_new_method_call("org.bluez", pr->adapter_path,
			"org.bluez.Adapter", "GetRemoteServiceHandles");
	if (!msg)
		return -1;

	ba2str(&pr->dst, addr);
	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &paddr,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);
	
	if (dbus_connection_send_with_reply(pr->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pr, NULL);
	dbus_message_unref(msg);

	return 0;
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
			memcpy(req->rd_data, (unsigned char *) pdlist->val.str, pdlist->unitSize);
			req->rd_size = pdlist->unitSize;
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

static void hid_record_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessage *pr_reply;
	struct manager *mgr;
	struct pending_req *pr = data;
	struct hidp_connadd_req hidp;
	DBusError derr;
	uint8_t *rec_bin;
	const char *path;
	int len, scanned;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
			"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pr->conn, pr->msg, derr.message);
		else
			err_not_supported(pr->conn, pr->msg);

		error("GetRemoteServiceRecord failed: %s(%s)",
					derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &rec_bin, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Invalid HID service record length");
		goto fail;
	}

	pr->hid_rec = sdp_extract_pdu(rec_bin, &scanned);
	if (!pr->hid_rec) {
		err_not_supported(pr->conn, pr->msg);
		goto fail;
	}

	memset(&hidp, 0, sizeof(struct hidp_connadd_req));
	extract_hid_record(pr->hid_rec, &hidp);
	if (pr->pnp_rec)
		extract_pnp_record(pr->pnp_rec, &hidp);

	store_device_info(&pr->src, &pr->dst, &hidp);

	if (input_device_register(pr->conn, &pr->src,
					&pr->dst, &hidp, &path) < 0) {
		err_failed(pr->conn, pr->msg, "D-Bus path registration failed");
		goto fail;
	}

	dbus_connection_get_object_path_data(pr->conn, INPUT_PATH, (void *) &mgr);
	mgr->paths = g_slist_append(mgr->paths, g_strdup(path));

	pr_reply = dbus_message_new_method_return(pr->msg);
	dbus_message_append_args(pr_reply,
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);
	send_message_and_unref(pr->conn, pr_reply);
fail:
	dbus_error_free(&derr);
	pending_req_free(pr);
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void hid_handle_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	uint32_t *phandle;
	DBusError derr;
	int len;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
			"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pr->conn, pr->msg, derr.message);
		else
			err_not_supported(pr->conn, pr->msg);

		error("GetRemoteServiceHandles: %s(%s)",
					derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("HID record handle not found");
		goto fail;
	}

	if (get_record(pr, *phandle, hid_record_reply) < 0) {
		err_not_supported(pr->conn, pr->msg);
		error("HID service attribute request failed");
		goto fail;
	} else {
		/* Wait record reply */
		goto done;
	}
fail:
	dbus_error_free(&derr);
	pending_req_free(pr);
done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void pnp_record_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	DBusError derr;
	uint8_t *rec_bin;
	int len, scanned;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
			"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pr->conn, pr->msg, derr.message);
		else
			err_not_supported(pr->conn, pr->msg);

		error("GetRemoteServiceRecord: %s(%s)",
				derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &rec_bin, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Invalid PnP service record length");
		goto fail;
	}

	pr->pnp_rec = sdp_extract_pdu(rec_bin, &scanned);
	if (get_handles(pr, hid_uuid, hid_handle_reply) < 0) {
		err_not_supported(pr->conn, pr->msg);
		error("HID service search request failed");
		goto fail;
	} else {
		/* Wait handle reply */
		goto done;
	}

fail:
	dbus_error_free(&derr);
	pending_req_free(pr);
done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void pnp_handle_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	DBusError derr;
	uint32_t *phandle;
	int len;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
			"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pr->conn, pr->msg, derr.message);
		else
			err_not_supported(pr->conn, pr->msg);

		error("GetRemoteServiceHandles: %s(%s)",
				derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		/* PnP is optional: Ignore it and request the HID handle  */
		if (get_handles(pr, hid_uuid, hid_handle_reply) < 0) {
			err_not_supported(pr->conn, pr->msg);
			error("HID service search request failed");
			goto fail;
		}
	} else {
		/* Request PnP record */
		if (get_record(pr, *phandle, pnp_record_reply) < 0) {
			err_not_supported(pr->conn, pr->msg);
			error("PnP service attribute request failed");
			goto fail;
		}
	}

	/* Wait HID handle reply or PnP record reply */
	goto done;

fail:
	dbus_error_free(&derr);
	pending_req_free(pr);
done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void headset_record_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessage *pr_reply;
	DBusError derr;
	struct manager *mgr;
	struct pending_req *pr = data;
	uint8_t *rec_bin;
	sdp_record_t *rec;
	sdp_list_t *protos;
	const char *path;
	int len, scanned;
	uint8_t ch;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
			"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pr->conn, pr->msg, derr.message);
		else
			err_not_supported(pr->conn, pr->msg);

		error("GetRemoteServiceRecord: %s(%s)",
				derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &rec_bin, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Invalid headset service record length");
		goto fail;
	}

	rec = sdp_extract_pdu(rec_bin, &scanned);
	if (!rec) {
		err_not_supported(pr->conn, pr->msg);
		goto fail;
	}

	if (sdp_get_access_protos(rec, &protos) < 0) {
		err_not_supported(pr->conn, pr->msg);
		goto fail;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t)sdp_list_free, NULL);
	sdp_list_free(protos, NULL);
	sdp_record_free(rec);

	if (ch <= 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Invalid RFCOMM channel");
		goto fail;
	}

	/* FIXME: Store the fake input data */

	if (fake_input_register(pr->conn, &pr->src, &pr->dst, ch, &path) < 0) {
		error("D-Bus path registration failed:%s", path);
		err_failed(pr->conn, pr->msg, "Path registration failed");
		goto fail;
	}

	dbus_connection_get_object_path_data(pr->conn, INPUT_PATH, (void *) &mgr);
	mgr->paths = g_slist_append(mgr->paths, g_strdup(path));

	pr_reply = dbus_message_new_method_return(pr->msg);
	dbus_message_append_args(pr_reply,
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);
	send_message_and_unref(pr->conn, pr_reply);
fail:
	dbus_error_free(&derr);
	pending_req_free(pr);
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void headset_handle_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	DBusError derr;
	uint32_t *phandle;
	int len;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
			"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pr->conn, pr->msg, derr.message);
		else
			err_not_supported(pr->conn, pr->msg);

		error("GetRemoteServiceHandles: %s(%s)",
				derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Headset record handle not found");
		goto fail;
	}

	if (get_record(pr, *phandle, headset_record_reply) < 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Headset service attribute request failed");
		goto fail;
	} else {
		/* Wait record reply */
		goto done;
	}
fail:
	dbus_error_free(&derr);
	pending_req_free(pr);
done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static DBusHandlerResult create_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct manager *mgr = data;
	struct pending_req *pr;
	DBusError derr;
	const char *addr;
	GSList *l;
	bdaddr_t src, dst;
	uint32_t cls = 0;
	int dev_id;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Get the default adapter */
	dev_id = hci_get_route(NULL);
	if (dev_id < 0) {
		error("Bluetooth adapter not available");
		return err_failed(conn, msg, "Adapter not available");
	}

	if (hci_devba(dev_id, &src) < 0) {
		error("Can't get local adapter device info");
		return err_failed(conn, msg, "Adapter not available");
	}

	str2ba(addr, &dst);

	l = g_slist_find_custom(mgr->paths, &dst,
			(GCompareFunc) path_bdaddr_cmp);
	if (l)
		return err_already_exists(conn, msg, "Input Already exists");

	if (read_device_class(&src, &dst, &cls) < 0) {
		error("Device class not available");
		return err_not_supported(conn, msg);
	}

	pr = pending_req_new(conn, msg, &src, &dst);
	if (!pr)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	switch (cls & 0x1f00) {
		case 0x0500: /* Peripheral */
			if (get_handles(pr, pnp_uuid, pnp_handle_reply) < 0) {
				pending_req_free(pr);
				return err_not_supported(conn, msg);
			}
			break;
		case 0x0400: /* Fake input */
			if (get_handles(pr, headset_uuid,
						headset_handle_reply) < 0) {
				pending_req_free(pr);
				return err_not_supported(conn, msg);
			}
			break;
		default:
			pending_req_free(pr);
			return err_not_supported(conn, msg);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult remove_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct manager *mgr = data;
	struct device *idev;
	DBusMessage *reply;
	DBusError derr;
	GSList *l;
	const char *path;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	l = g_slist_find_custom(mgr->paths, path, (GCompareFunc) strcmp);
	if (!l)
		return err_does_not_exist(conn, msg, "Input doesn't exist");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	g_free(l->data);
	mgr->paths = g_slist_remove(mgr->paths, l->data);

	if (!dbus_connection_get_object_path_data(connection,
					path, (void *) &idev))
		return err_does_not_exist(conn, msg, "Input doesn't exist");

	del_stored_device_info(&idev->src, &idev->dst);

	if (input_device_unregister(conn, path) < 0) {
		dbus_message_unref(reply);
		return err_failed(conn, msg, "D-Bus path unregistration failed");
	}

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult list_devices(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct manager *mgr = data;
	DBusMessageIter iter, iter_array;
	DBusMessage *reply;
	GSList *paths;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &iter_array);

	for (paths = mgr->paths; paths != NULL; paths = paths->next) {
		const char *ppath = paths->data;
		dbus_message_iter_append_basic(&iter_array,
				DBUS_TYPE_STRING, &ppath);
	}

	dbus_message_iter_close_container(&iter, &iter_array);

	return send_message_and_unref(conn, reply);
}
static DBusHandlerResult manager_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *path, *iface, *member;

	path = dbus_message_get_path(msg);
	iface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	/* Catching fallback paths */
	if (strcmp(INPUT_PATH, path) != 0)
		return err_unknown_device(conn, msg);

	/* Accept messages from the input manager interface only */
	if (strcmp(INPUT_MANAGER_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "ListDevices") == 0)
		return list_devices(conn, msg, data);

	if (strcmp(member, "CreateDevice") == 0)
		return create_device(conn, msg, data);

	if (strcmp(member, "RemoveDevice") == 0)
		return remove_device(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void manager_free(struct manager *mgr)
{
	if (!mgr)
		return;

	if (mgr->paths) {
		g_slist_foreach(mgr->paths, (GFunc) free, NULL);
		g_slist_free(mgr->paths);
	}

	g_free(mgr);
}

static void manager_unregister(DBusConnection *conn, void *data)
{
	struct manager *mgr = data;

	info("Unregistered manager path");

	manager_free(mgr);
}

/* Virtual table to handle manager object path hierarchy */
static const DBusObjectPathVTable manager_table = {
	.message_function = manager_message,
	.unregister_function = manager_unregister,
};

/*
 * Stored inputs registration functions
 */

static void stored_input(char *key, char *value, void *data)
{
	struct manager *mgr = data;
	const char *path;
	struct hidp_connadd_req hidp; 
	bdaddr_t dst;

	str2ba(key, &dst);

	memset(&hidp, 0, sizeof(struct hidp_connadd_req));
	if (parse_stored_device_info(value, &hidp) < 0) {
		return;
	}

	/* FIXME: Ignore already registered devices */
	if (input_device_register(connection, &mgr->src, &dst, &hidp, &path) < 0)
		return;

	mgr->paths = g_slist_append(mgr->paths, g_strdup(path));
}

static void register_stored_inputs(struct manager *mgr)
{
	char dirname[PATH_MAX + 1];
	char filename[PATH_MAX + 1];
	struct dirent *de;
	DIR *dir;
	int dev_id;

	dev_id = hci_get_route(BDADDR_ANY);
	if (dev_id < 0) {
		error("Bluetooth device not available");
		return;
	}

	if (hci_devba(dev_id, &mgr->src) < 0) {
		error("Can't get local adapter device info");
		return;
	}

	snprintf(dirname, PATH_MAX, "%s", STORAGEDIR);

	dir = opendir(dirname);
	if (!dir)
		return;

	while ((de = readdir(dir)) != NULL) {
		if (!isdigit(de->d_name[0]))
			continue;

		create_name(filename, PATH_MAX, STORAGEDIR,
					de->d_name, "input");
		textfile_foreach(filename, stored_input, mgr);
	}

	closedir(dir);
}

int input_init(DBusConnection *conn)
{
	struct manager *mgr;

	connection = dbus_connection_ref(conn);

	dbus_connection_set_exit_on_disconnect(connection, TRUE);

	mgr = g_new0(struct manager, 1);

	/* Fallback to catch invalid device path */
	if (!dbus_connection_register_fallback(connection, INPUT_PATH,
						&manager_table, mgr)) {
		error("D-Bus failed to register %s path", INPUT_PATH);
		goto fail;
	}

	info("Registered input manager path:%s", INPUT_PATH);

	/* Register well known HID devices */
	register_stored_inputs(mgr);

	server_start(connection);

	return 0;

fail:
	manager_free(mgr);

	return -1;
}

void input_exit(void)
{
	dbus_connection_unregister_object_path(connection, INPUT_PATH);

	server_stop();

	dbus_connection_unref(connection);

	connection = NULL;
}
