/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "logging.h"
#include "textfile.h"

#include "hcid.h"
#include "adapter.h"
#include "device.h"
#include "dbus-common.h"
#include "dbus-hci.h"
#include "error.h"
#include "glib-helper.h"
#include "agent.h"
#include "sdp-xml.h"
#include "storage.h"

#define DEFAULT_XML_BUF_SIZE	1024
#define DISCONNECT_TIMER	2

struct btd_driver_data {
	struct btd_device_driver *driver;
	void *priv;
};

struct btd_device {
	gchar		*address;
	gchar		*path;
	struct btd_adapter	*adapter;
	GSList		*uuids;
	GSList		*drivers;		/* List of driver_data */
	gboolean	temporary;
	struct agent	*agent;
	guint		disconn_timer;
	int		discov_active;		/* Service discovery active */
	char		*discov_requestor;	/* discovery requestor unique name */
	guint		discov_listener;

	/* For Secure Simple Pairing */
	uint8_t		cap;
	uint8_t		auth;
};

struct browse_req {
	DBusConnection *conn;
	DBusMessage *msg;
	struct btd_device *device;
	GSList *uuids_added;
	GSList *uuids_removed;
	sdp_list_t *records;
	int search_uuid;
	gboolean browse;
};

static uint16_t uuid_list[] = {
	PUBLIC_BROWSE_GROUP,
	PNP_INFO_SVCLASS_ID,
	HID_SVCLASS_ID,
	GENERIC_AUDIO_SVCLASS_ID,
	ADVANCED_AUDIO_SVCLASS_ID,
	AV_REMOTE_SVCLASS_ID,
	PANU_SVCLASS_ID,
	GN_SVCLASS_ID,
	NAP_SVCLASS_ID,
	SERIAL_PORT_SVCLASS_ID,
	0
};

static GSList *device_drivers = NULL;

static void device_free(gpointer user_data)
{
	struct btd_device *device = user_data;

	if (device->agent)
		agent_destroy(device->agent, FALSE);

	g_slist_foreach(device->uuids, (GFunc) g_free, NULL);
	g_slist_free(device->uuids);

	if (device->disconn_timer)
		g_source_remove(device->disconn_timer);

	g_free(device->address);
	g_free(device->path);
	g_free(device);
}

static gboolean device_is_paired(struct btd_device *device)
{
	struct btd_adapter *adapter = device->adapter;
	char filename[PATH_MAX + 1], *str, addr[18];
	gboolean ret;
	bdaddr_t bdaddr;

	adapter_get_address(adapter, &bdaddr);
	ba2str(&bdaddr, addr);

	create_name(filename, PATH_MAX, STORAGEDIR,
			addr, "linkkeys");
	str = textfile_caseget(filename, device->address);
	ret = str ? TRUE : FALSE;
	g_free(str);

	return ret;
}

static DBusMessage *get_properties(DBusConnection *conn,
				DBusMessage *msg, void *user_data)
{
	struct btd_device *device = user_data;
	struct btd_adapter *adapter = device->adapter;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	bdaddr_t src, dst;
	char name[248], src_addr[18];
	char **uuids;
	const char *ptr;
	dbus_bool_t boolean;
	uint32_t class;
	int i;
	GSList *l;
	struct active_conn_info *dev;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Address */
	dbus_message_iter_append_dict_entry(&dict, "Address", DBUS_TYPE_STRING,
			&device->address);

	/* Name */
	ptr = NULL;
	memset(name, 0, sizeof(name));
	adapter_get_address(adapter, &src);
	ba2str(&src, src_addr);

	if (read_device_name(src_addr, device->address, name) == 0) {
		ptr = name;
		dbus_message_iter_append_dict_entry(&dict, "Name",
				DBUS_TYPE_STRING, &ptr);
	}

	if (read_device_alias(src_addr, device->address, name, sizeof(name)) > 0)
		ptr = name;

	/* Alias: use Name if Alias doesn't exist */
	if (ptr)
		dbus_message_iter_append_dict_entry(&dict, "Alias",
				DBUS_TYPE_STRING, &ptr);

	str2ba(device->address, &dst);

	/* Class */
	if (read_remote_class(&src, &dst, &class) == 0) {
		dbus_message_iter_append_dict_entry(&dict, "Class",
				DBUS_TYPE_UINT32, &class);
	}

	/* Paired */
	boolean = device_is_paired(device);
	dbus_message_iter_append_dict_entry(&dict, "Paired",
			DBUS_TYPE_BOOLEAN, &boolean);

	/* Trusted */
	boolean = read_trust(&src, device->address, GLOBAL_TRUST);
	dbus_message_iter_append_dict_entry(&dict, "Trusted",
			DBUS_TYPE_BOOLEAN, &boolean);

	/* Connected */
	dev = adapter_search_active_conn_by_bdaddr(adapter, &dst);
	if (dev)
		boolean = TRUE;
	else
		boolean = FALSE;

	dbus_message_iter_append_dict_entry(&dict, "Connected",
			DBUS_TYPE_BOOLEAN, &boolean);

	/* UUIDs */
	uuids = g_new0(char *, g_slist_length(device->uuids) + 1);
	for (i = 0, l = device->uuids; l; l = l->next, i++)
		uuids[i] = l->data;
	dbus_message_iter_append_dict_entry(&dict, "UUIDs",
			DBUS_TYPE_ARRAY, &uuids);
	g_free(uuids);

	/* Adapter */
	ptr = adapter_get_path(adapter);
	dbus_message_iter_append_dict_entry(&dict, "Adapter",
			DBUS_TYPE_OBJECT_PATH, &ptr);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *set_alias(DBusConnection *conn, DBusMessage *msg,
					const char *alias, void *data)
{
	struct btd_device *device = data;
	struct btd_adapter *adapter = device->adapter;
	char addr[18];
	bdaddr_t bdaddr;
	int err;

	adapter_get_address(adapter, &bdaddr);
	ba2str(&bdaddr, addr);

	 /* Remove alias if empty string */
	err = write_device_alias(addr, device->address,
			g_str_equal(alias, "") ? NULL : alias);
	if (err < 0)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".Failed",
				strerror(-err));

	dbus_connection_emit_property_changed(conn, dbus_message_get_path(msg),
					DEVICE_INTERFACE, "Alias",
					DBUS_TYPE_STRING, &alias);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *set_trust(DBusConnection *conn, DBusMessage *msg,
					dbus_bool_t value, void *data)
{
	struct btd_device *device = data;
	struct btd_adapter *adapter = device->adapter;
	char addr[18];
	bdaddr_t bdaddr;


	adapter_get_address(adapter, &bdaddr);
	ba2str(&bdaddr, addr);

	write_trust(addr, device->address, GLOBAL_TRUST, value);

	dbus_connection_emit_property_changed(conn, dbus_message_get_path(msg),
					DEVICE_INTERFACE, "Trusted",
					DBUS_TYPE_BOOLEAN, &value);

	return dbus_message_new_method_return(msg);
}

static inline DBusMessage *invalid_args(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".InvalidArguments",
			"Invalid arguments in method call");
}

static DBusMessage *set_property(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter sub;
	const char *property;

	if (!dbus_message_iter_init(msg, &iter))
		return invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return invalid_args(msg);
	dbus_message_iter_recurse(&iter, &sub);

	if (g_str_equal("Trusted", property)) {
		dbus_bool_t value;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_BOOLEAN)
			return invalid_args(msg);
		dbus_message_iter_get_basic(&sub, &value);

		return set_trust(conn, msg, value, data);
	} else if (g_str_equal("Alias", property)) {
		const char *alias;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)
			return invalid_args(msg);
		dbus_message_iter_get_basic(&sub, &alias);

		return set_alias(conn, msg, alias, data);
	}

	return invalid_args(msg);
}

static void discover_services_req_exit(void *user_data)
{
	struct btd_device *device = user_data;
	struct btd_adapter *adapter = device->adapter;
	bdaddr_t src, dst;

	adapter_get_address(adapter, &src);

	debug("DiscoverDevices requestor exited");

	str2ba(device->address, &dst);

	bt_cancel_discovery(&src, &dst);
}

static DBusMessage *discover_services(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct btd_device *device = user_data;
	const char *pattern;
	int err;

	if (device->discov_active)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".InProgress",
							"Discover in progress");

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pattern,
						DBUS_TYPE_INVALID) == FALSE)
		goto fail;

	if (strlen(pattern) == 0) {
		err = device_browse(device, conn, msg, NULL);
		if (err < 0)
			goto fail;
	} else {
		uuid_t uuid;

		if (bt_string2uuid(&uuid, pattern) < 0)
			return invalid_args(msg);

		err = device_browse(device, conn, msg, &uuid);
		if (err < 0)
			goto fail;
	}

	return NULL;

fail:
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
					"Discovery Failed");
}

static DBusMessage *cancel_discover(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct btd_device *device = user_data;
	struct btd_adapter *adapter = device->adapter;
	bdaddr_t src, dst;

	adapter_get_address(adapter, &src);

	if (!device->discov_active)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".Failed",
				"No pending discovery");

	/* only the discover requestor can cancel the inquiry process */
	if (!device->discov_requestor ||
			strcmp(device->discov_requestor, dbus_message_get_sender(msg)))
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".NotAuthorized",
				"Not Authorized");

	str2ba(device->address, &dst);

	if (bt_cancel_discovery(&src, &dst) < 0)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".Failed",
				"No pending discover");

	return dbus_message_new_method_return(msg);
}

static gboolean disconnect_timeout(gpointer user_data)
{
	struct btd_device *device = user_data;
	struct active_conn_info *ci;
	disconnect_cp cp;
	bdaddr_t bda;
	int dd;
	uint16_t dev_id = adapter_get_dev_id(device->adapter);

	device->disconn_timer = 0;

	str2ba(device->address, &bda);

	ci = adapter_search_active_conn_by_bdaddr(device->adapter, &bda);

	if (!ci)
		return FALSE;

	dd = hci_open_dev(dev_id);
	if (dd < 0)
		goto fail;

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(ci->handle);
	cp.reason = HCI_OE_USER_ENDED_CONNECTION;

	hci_send_cmd(dd, OGF_LINK_CTL, OCF_DISCONNECT,
			DISCONNECT_CP_SIZE, &cp);

	close(dd);

fail:
	return FALSE;
}

static DBusMessage *disconnect(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct btd_device *device = user_data;
	bdaddr_t bda;
	struct active_conn_info *dev;

	str2ba(device->address, &bda);

	dev = adapter_search_active_conn_by_bdaddr(device->adapter, &bda);

	if (!dev)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".NotConnected",
				"Device is not connected");

	g_dbus_emit_signal(conn, device->path,
			DEVICE_INTERFACE, "DisconnectRequested",
			DBUS_TYPE_INVALID);

	device->disconn_timer = g_timeout_add_seconds(DISCONNECT_TIMER,
						disconnect_timeout, device);

	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable device_methods[] = {
	{ "GetProperties",	"",	"a{sv}",	get_properties	},
	{ "SetProperty",	"sv",	"",		set_property	},
	{ "DiscoverServices",	"s",	"a{us}",	discover_services,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "CancelDiscovery",	"",	"",		cancel_discover	},
	{ "Disconnect",		"",	"",		disconnect	},
	{ }
};

static GDBusSignalTable device_signals[] = {
	{ "PropertyChanged",		"sv"	},
	{ "DisconnectRequested",	""	},
	{ }
};

struct btd_device *device_create(DBusConnection *conn, struct btd_adapter *adapter,
					const gchar *address)
{
	gchar *address_up;
	struct btd_device *device;
	uint16_t dev_id = adapter_get_dev_id(adapter);

	device = g_try_malloc0(sizeof(struct btd_device));
	if (device == NULL)
		return NULL;

	address_up = g_ascii_strup(address, -1);
	device->path = g_strdup_printf("%s/hci%d/dev_%s", "/org/bluez",
							dev_id, address_up);
	g_strdelimit(device->path, ":", '_');
	g_free(address_up);

	debug("Creating device %s", device->path);

	if (g_dbus_register_interface(conn, device->path, DEVICE_INTERFACE,
				device_methods, device_signals, NULL,
				device, device_free) == FALSE) {
		device_free(device);
		return NULL;
	}

	device->address = g_strdup(address);
	device->adapter = adapter;

	return device;
}

void device_remove(DBusConnection *conn, struct btd_device *device)
{
	GSList *list;
	struct btd_device_driver *driver;
	gchar *path = g_strdup(device->path);

	debug("Removing device %s", path);

	for (list = device->drivers; list; list = list->next) {
		struct btd_driver_data *driver_data = list->data;
		driver = driver_data->driver;

		driver->remove(device);
		g_free(driver_data);
	}

	g_dbus_unregister_interface(conn, path, DEVICE_INTERFACE);

	g_free(path);
}

gint device_address_cmp(struct btd_device *device, const gchar *address)
{
	return strcasecmp(device->address, address);
}

sdp_record_t *get_record(sdp_list_t *recs, const char *uuid)
{
	sdp_list_t *seq;

	for (seq = recs; seq; seq = seq->next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;
		sdp_list_t *svcclass = NULL;
		char *uuid_str;

		if (sdp_get_service_classes(rec, &svcclass) < 0)
			continue;

		/* Extract the uuid */
		uuid_str = bt_uuid2string(svcclass->data);
		if (!uuid_str)
			continue;

		if (!strcasecmp(uuid_str, uuid)) {
			sdp_list_free(svcclass, free);
			free(uuid_str);
			return rec;
		}
		sdp_list_free(svcclass, free);
		free(uuid_str);
	}
	return NULL;
}

void device_probe_drivers(struct btd_device *device, GSList *uuids, sdp_list_t *recs)
{
	GSList *list;
	const char **uuid;
	int err;

	debug("Probe drivers for %s", device->path);

	for (list = device_drivers; list; list = list->next) {
		struct btd_device_driver *driver = list->data;
		GSList *records = NULL;

		for (uuid = driver->uuids; *uuid; uuid++) {
			sdp_record_t *rec;

			if (!g_slist_find_custom(uuids, *uuid,
					(GCompareFunc) strcasecmp))
				continue;

			rec = get_record(recs, *uuid);
			if (!rec)
				continue;

			records = g_slist_append(records, rec);
		}

		if (records) {
			struct btd_driver_data *driver_data = g_new0(struct btd_driver_data, 1);

			err = driver->probe(device, records);
			if (err < 0) {
				error("probe failed for driver %s",
							driver->name);

				g_free(driver_data);
				continue;
			}

			driver_data->driver = driver;
			device->drivers = g_slist_append(device->drivers,
								driver_data);
		}
	}

	for (list = uuids; list; list = list->next)
		device->uuids = g_slist_insert_sorted(device->uuids,
				list->data, (GCompareFunc) strcmp);
}

void device_remove_drivers(struct btd_device *device, GSList *uuids, sdp_list_t *recs)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	GSList *list;
	char src_addr[18];
	bdaddr_t src;

	adapter_get_address(adapter, &src);
	ba2str(&src, src_addr);

	debug("Remove drivers for %s", device->path);

	for (list = device->drivers; list; list = list->next) {
		struct btd_driver_data *driver_data = list->data;
		struct btd_device_driver *driver = driver_data->driver;
		const char **uuid;

		for (uuid = driver->uuids; *uuid; uuid++) {
			sdp_record_t *rec;

			if (!g_slist_find_custom(uuids, *uuid,
					(GCompareFunc) strcasecmp))
				continue;

			driver->remove(device);
			device->drivers = g_slist_remove(device->drivers,
								driver_data);

			g_free(driver_data);

			rec = get_record(recs, *uuid);
			if (!rec)
				continue;

			delete_record(src_addr, device->address, rec->handle);
		}
	}

	for (list = uuids; list; list = list->next)
		device->uuids = g_slist_remove(device->uuids, list->data);
}

static void iter_append_record(DBusMessageIter *dict, uint32_t handle,
							const char *record)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_UINT32, &handle);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &record);

	dbus_message_iter_close_container(dict, &entry);
}

static void append_and_grow_string(void *data, const char *str)
{
	sdp_buf_t *buff = data;
	int len;

	len = strlen(str);

	if (!buff->data) {
		buff->data = malloc(DEFAULT_XML_BUF_SIZE);
		if (!buff->data)
			return;
		buff->buf_size = DEFAULT_XML_BUF_SIZE;
	}

	/* Grow string */
	while (buff->buf_size < (buff->data_size + len + 1)) {
		void *tmp;
		uint32_t new_size;

		/* Grow buffer by a factor of 2 */
		new_size = (buff->buf_size << 1);

		tmp = realloc(buff->data, new_size);
		if (!tmp)
			return;

		buff->data = tmp;
		buff->buf_size = new_size;
	}

	/* Include the NULL character */
	memcpy(buff->data + buff->data_size, str, len + 1);
	buff->data_size += len;
}

static void discover_device_reply(struct browse_req *req, sdp_list_t *recs)
{
	DBusMessage *reply;
	DBusMessageIter iter, dict;
	sdp_list_t *seq;

	reply = dbus_message_new_method_return(req->msg);
	if (!reply)
		return;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_UINT32_AS_STRING DBUS_TYPE_STRING_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	for (seq = recs; seq; seq = seq->next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;
		sdp_buf_t result;

		if (!rec)
			break;

		memset(&result, 0, sizeof(sdp_buf_t));

		convert_sdp_record_to_xml(rec, &result,
				append_and_grow_string);

		if (result.data) {
			const char *val = (char *) result.data;
			iter_append_record(&dict, rec->handle, val);
			free(result.data);
		}
	}

	dbus_message_iter_close_container(&iter, &dict);

	dbus_connection_send(req->conn, reply, NULL);
	dbus_message_unref(reply);
}

static void services_changed(struct browse_req *req)
{
	struct btd_device *device = req->device;
	char **uuids;
	GSList *l;
	int i;

	uuids = g_new0(char *, g_slist_length(device->uuids) + 1);
	for (i = 0, l = device->uuids; l; l = l->next, i++)
		uuids[i] = l->data;

	dbus_connection_emit_property_changed(req->conn, device->path,
					DEVICE_INTERFACE, "UUIDs",
					DBUS_TYPE_ARRAY, &uuids);

	g_free(uuids);
}

static int rec_cmp(const void *a, const void *b)
{
	const sdp_record_t *r1 = a;
	const sdp_record_t *r2 = b;

	return r1->handle - r2->handle;
}

static void update_services(struct browse_req *req, sdp_list_t *recs)
{
	struct btd_device *device = req->device;
	struct btd_adapter *adapter = device_get_adapter(device);
	sdp_list_t *seq;
	char src_addr[18];
	bdaddr_t src;

	adapter_get_address(adapter, &src);
	ba2str(&src, src_addr);

	for (seq = recs; seq; seq = seq->next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;
		sdp_buf_t pdu;
		sdp_list_t *svcclass = NULL;
		gchar *uuid_str;
		GSList *l;

		if (!rec)
			break;

		if (sdp_get_service_classes(rec, &svcclass) < 0)
			continue;

		/* Extract the first element and skip the remainning */
		uuid_str = bt_uuid2string(svcclass->data);
		if (!uuid_str)
			continue;

		/* Check for duplicates */
		if (sdp_list_find(req->records, rec, rec_cmp))
			continue;

		store_record(src_addr, device->address, rec);

		/* Copy record */
		if (sdp_gen_record_pdu(rec, &pdu) == 0) {
			sdp_record_t *record;
			int scanned;

			record = sdp_extract_pdu(pdu.data, pdu.data_size,
						&scanned);
			free(pdu.data);
			req->records = sdp_list_append(req->records, record);
		}

		l = g_slist_find_custom(device->uuids, uuid_str,
				(GCompareFunc) strcmp);
		if (!l)
			req->uuids_added = g_slist_append(req->uuids_added,
					uuid_str);
		else {
			req->uuids_removed = g_slist_remove(req->uuids_removed,
					l->data);
			g_free(uuid_str);
		}

		sdp_list_free(svcclass, free);
	}
}

static void store(struct btd_device *device)
{
	struct btd_adapter *adapter = device->adapter;
	bdaddr_t src, dst;
	char *str;

	adapter_get_address(adapter, &src);
	str2ba(device->address, &dst);

	if (!device->uuids) {
		write_device_profiles(&src, &dst, "");
		return;
	}

	str = bt_list2string(device->uuids);
	write_device_profiles(&src, &dst, str);
	g_free(str);
}

static void browse_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct browse_req *req = user_data;
	struct btd_device *device = req->device;
	struct btd_adapter *adapter = device->adapter;
	bdaddr_t src, dst;
	uuid_t uuid;
	DBusMessage *reply;

	adapter_get_address(adapter, &src);

	if (err < 0) {
		error("%s: error updating services: %s (%d)",
				device->path, strerror(-err), -err);
		goto proceed;
	}

	update_services(req, recs);

	/* Public browsing successful or Single record requested */
	if (req->browse == FALSE || (!req->search_uuid && recs))
		goto probe;

	if (uuid_list[++req->search_uuid]) {
		sdp_uuid16_create(&uuid, uuid_list[req->search_uuid]);
		str2ba(device->address, &dst);
		bt_search_service(&src, &dst, &uuid, browse_cb, user_data, NULL);
		return;
	}

probe:

	if (!req->uuids_added && !req->uuids_removed) {
		debug("%s: No service found", device->path);
		goto proceed;
	}

	/* Probe matching drivers for services added */
	if (req->uuids_added)
		device_probe_drivers(device, req->uuids_added, req->records);

	/* Remove drivers for services removed */
	if (req->uuids_removed)
		device_remove_drivers(device, req->uuids_removed, req->records);

	/* Propagate services changes */
	services_changed(req);

proceed:

	/* Store the device's profiles in the filesystem */
	store(device);

	if (dbus_message_is_method_call(req->msg, DEVICE_INTERFACE,
			"DiscoverServices")) {
		discover_device_reply(req, req->records);
		goto cleanup;
	}

	g_dbus_emit_signal(req->conn, dbus_message_get_path(req->msg),
				ADAPTER_INTERFACE, "DeviceCreated",
				DBUS_TYPE_OBJECT_PATH, &device->path,
				DBUS_TYPE_INVALID);

	/* Reply create device request */
	reply = dbus_message_new_method_return(req->msg);
	if (!reply)
		goto cleanup;

	dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &device->path,
							DBUS_TYPE_INVALID);

	dbus_connection_send(req->conn, reply, NULL);
	dbus_message_unref(reply);

cleanup:
	device->discov_active = 0;

	if (device->discov_requestor) {
		g_dbus_remove_watch(req->conn, device->discov_listener);
		device->discov_listener = 0;
		g_free(device->discov_requestor);
		device->discov_requestor = NULL;
	}

	dbus_message_unref(req->msg);
	dbus_connection_unref(req->conn);
	g_slist_free(req->uuids_added);
	g_slist_free(req->uuids_removed);
	if (req->records)
		sdp_list_free(req->records, (sdp_free_func_t) sdp_record_free);
	g_free(req);
}

int device_browse(struct btd_device *device, DBusConnection *conn,
			DBusMessage *msg, uuid_t *search)
{
	struct btd_adapter *adapter = device->adapter;
	struct browse_req *req;
	bdaddr_t src, dst;
	uuid_t uuid;
	GSList *l;

	adapter_get_address(adapter, &src);

	req = g_new0(struct browse_req, 1);
	req->conn = dbus_connection_ref(conn);
	req->msg = dbus_message_ref(msg);
	req->device = device;

	str2ba(device->address, &dst);

	if (search) {
		memcpy(&uuid, search, sizeof(uuid_t));
		req->browse = FALSE;
	} else {
		sdp_uuid16_create(&uuid, uuid_list[req->search_uuid]);
		req->browse = TRUE;
		for (l = device->uuids; l; l = l->next)
			req->uuids_removed = g_slist_append(req->uuids_removed,
						l->data);
	}

	device->discov_active = 1;
	device->discov_requestor = g_strdup(dbus_message_get_sender(msg));
	/* Track the request owner to cancel it
	 * automatically if the owner exits */
	device->discov_listener = g_dbus_add_disconnect_watch(conn,
						dbus_message_get_sender(msg),
						discover_services_req_exit,
						device, NULL);

	return bt_search_service(&src, &dst, &uuid, browse_cb, req, NULL);
}

struct btd_adapter *device_get_adapter(struct btd_device *device)
{
	if (!device)
		return NULL;

	return device->adapter;
}

void device_get_address(struct btd_device *device, bdaddr_t *bdaddr)
{
	str2ba(device->address, bdaddr);
}

const gchar *device_get_path(struct btd_device *device)
{
	if (!device)
		return NULL;

	return device->path;
}

struct agent *device_get_agent(struct btd_device *device)
{
	if (!device)
		return NULL;

	return  device->agent;
}

void device_set_agent(struct btd_device *device, struct agent *agent)
{
	if (!device)
		return;

	device->agent = agent;
}

gboolean device_is_busy(struct btd_device *device)
{
	return device->discov_active ? TRUE : FALSE;
}

gboolean device_is_temporary(struct btd_device *device)
{
	return device->temporary;
}

void device_set_temporary(struct btd_device *device, gboolean temporary)
{
	if (!device)
		return;

	device->temporary = temporary;
}

void device_set_cap(struct btd_device *device, uint8_t cap)
{
	if (!device)
		return;

	device->cap = cap;
}

void device_set_auth(struct btd_device *device, uint8_t auth)
{
	if (!device)
		return;

	device->auth = auth;
}

uint8_t device_get_auth(struct btd_device *device)
{
	return device->auth;
}

int btd_register_device_driver(struct btd_device_driver *driver)
{
	device_drivers = g_slist_append(device_drivers, driver);

	return 0;
}

void btd_unregister_device_driver(struct btd_device_driver *driver)
{
	device_drivers = g_slist_remove(device_drivers, driver);
}
