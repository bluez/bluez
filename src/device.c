/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
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
#include "btio.h"

#define DEFAULT_XML_BUF_SIZE	1024
#define DISCONNECT_TIMER	2
#define DISCOVERY_TIMER		2

struct btd_driver_data {
	guint id;
	struct btd_device_driver *driver;
	void *priv;
};

struct btd_disconnect_data {
	guint id;
	disconnect_watch watch;
	void *user_data;
	GDestroyNotify destroy;
};

struct bonding_req {
	DBusConnection *conn;
	DBusMessage *msg;
	GIOChannel *io;
	guint io_id;
	guint listener_id;
	struct btd_device *device;
};

struct authentication_req {
	auth_type_t type;
	void *cb;
	struct agent *agent;
	struct btd_device *device;
};

struct browse_req {
	DBusConnection *conn;
	DBusMessage *msg;
	struct btd_device *device;
	GSList *match_uuids;
	GSList *profiles_added;
	GSList *profiles_removed;
	sdp_list_t *records;
	int search_uuid;
	int reconnect_attempt;
	guint listener_id;
	guint timer;
};

struct btd_device {
	bdaddr_t	bdaddr;
	gchar		*path;
	char		name[MAX_NAME_LENGTH + 1];
	struct btd_adapter	*adapter;
	GSList		*uuids;
	GSList		*drivers;		/* List of driver_data */
	GSList		*watches;		/* List of disconnect_data */
	gboolean	temporary;
	struct agent	*agent;
	guint		disconn_timer;
	guint		discov_timer;
	struct browse_req *browse;		/* service discover request */
	struct bonding_req *bonding;
	struct authentication_req *authr;	/* authentication request */
	GSList		*disconnects;		/* disconnects message */

	/* For Secure Simple Pairing */
	uint8_t		cap;
	uint8_t		auth;

	uint16_t	handle;			/* Connection handle */

	/* Whether were creating a security mode 3 connection */
	gboolean	secmode3;

	sdp_list_t	*tmp_records;

	gboolean	paired;
	gboolean	renewed_key;

	gboolean	authorizing;
	gint		ref;
};

static uint16_t uuid_list[] = {
	L2CAP_UUID,
	PNP_INFO_SVCLASS_ID,
	PUBLIC_BROWSE_GROUP,
	0
};

static GSList *device_drivers = NULL;

static DBusHandlerResult error_connection_attempt_failed(DBusConnection *conn,
						DBusMessage *msg, int err)
{
	return error_common_reply(conn, msg,
			ERROR_INTERFACE ".ConnectionAttemptFailed",
			err > 0 ? strerror(err) : "Connection attempt failed");
}

static DBusHandlerResult error_failed(DBusConnection *conn,
					DBusMessage *msg, const char * desc)
{
	return error_common_reply(conn, msg, ERROR_INTERFACE ".Failed", desc);
}

static DBusHandlerResult error_failed_errno(DBusConnection *conn,
						DBusMessage *msg, int err)
{
	const char *desc = strerror(err);

	return error_failed(conn, msg, desc);
}

static inline DBusMessage *no_such_adapter(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NoSuchAdapter",
							"No such adapter");
}

static inline DBusMessage *in_progress(DBusMessage *msg, const char *str)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InProgress", str);
}

static void browse_request_free(struct browse_req *req)
{
	if (req->listener_id)
		g_dbus_remove_watch(req->conn, req->listener_id);
	if (req->msg)
		dbus_message_unref(req->msg);
	if (req->conn)
		dbus_connection_unref(req->conn);
	g_slist_foreach(req->profiles_added, (GFunc) g_free, NULL);
	g_slist_free(req->profiles_added);
	g_slist_free(req->profiles_removed);
	if (req->records)
		sdp_list_free(req->records, (sdp_free_func_t) sdp_record_free);
	g_free(req);
}

static void browse_request_cancel(struct browse_req *req)
{
	struct btd_device *device = req->device;
	struct btd_adapter *adapter = device->adapter;
	bdaddr_t src;

	if (device_is_creating(device, NULL))
		device_set_temporary(device, TRUE);

	adapter_get_address(adapter, &src);

	bt_cancel_discovery(&src, &device->bdaddr);

	browse_request_free(req);
	device->browse = NULL;
}

static void device_free(gpointer user_data)
{
	struct btd_device *device = user_data;
	struct btd_adapter *adapter = device->adapter;
	struct agent *agent = adapter_get_agent(adapter);

	if (device->agent)
		agent_free(device->agent);

	if (agent && (agent_is_busy(agent, device) ||
				agent_is_busy(agent, device->authr)))
		agent_cancel(agent);

	g_slist_foreach(device->uuids, (GFunc) g_free, NULL);
	g_slist_free(device->uuids);

	if (device->tmp_records)
		sdp_list_free(device->tmp_records,
					(sdp_free_func_t) sdp_record_free);

	if (device->disconn_timer)
		g_source_remove(device->disconn_timer);

	if (device->discov_timer)
		g_source_remove(device->discov_timer);

	debug("device_free(%p)", device);

	g_free(device->authr);
	g_free(device->path);
	g_free(device);
}

gboolean device_is_paired(struct btd_device *device)
{
	return device->paired;
}

static DBusMessage *get_properties(DBusConnection *conn,
				DBusMessage *msg, void *user_data)
{
	struct btd_device *device = user_data;
	struct btd_adapter *adapter = device->adapter;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	bdaddr_t src;
	char name[MAX_NAME_LENGTH + 1], srcaddr[18], dstaddr[18];
	char **uuids;
	const char *ptr;
	dbus_bool_t boolean;
	uint32_t class;
	int i;
	GSList *l;

	ba2str(&device->bdaddr, dstaddr);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Address */
	ptr = dstaddr;
	dict_append_entry(&dict, "Address", DBUS_TYPE_STRING, &ptr);

	/* Name */
	ptr = NULL;
	memset(name, 0, sizeof(name));
	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);

	ptr = device->name;
	dict_append_entry(&dict, "Name", DBUS_TYPE_STRING, &ptr);

	/* Alias (fallback to name or address) */
	if (read_device_alias(srcaddr, dstaddr, name, sizeof(name)) < 1) {
		if (strlen(ptr) == 0) {
			g_strdelimit(dstaddr, ":", '-');
			ptr = dstaddr;
		}
	} else
		ptr = name;

	dict_append_entry(&dict, "Alias", DBUS_TYPE_STRING, &ptr);

	/* Class */
	if (read_remote_class(&src, &device->bdaddr, &class) == 0) {
		const char *icon = class_to_icon(class);

		dict_append_entry(&dict, "Class", DBUS_TYPE_UINT32, &class);

		if (icon)
			dict_append_entry(&dict, "Icon",
						DBUS_TYPE_STRING, &icon);
	}

	/* Paired */
	boolean = device_is_paired(device);
	dict_append_entry(&dict, "Paired", DBUS_TYPE_BOOLEAN, &boolean);

	/* Trusted */
	boolean = read_trust(&src, dstaddr, GLOBAL_TRUST);
	dict_append_entry(&dict, "Trusted", DBUS_TYPE_BOOLEAN, &boolean);

	/* Connected */
	boolean = (device->handle != 0);
	dict_append_entry(&dict, "Connected", DBUS_TYPE_BOOLEAN,
				&boolean);

	/* UUIDs */
	uuids = g_new0(char *, g_slist_length(device->uuids) + 1);
	for (i = 0, l = device->uuids; l; l = l->next, i++)
		uuids[i] = l->data;
	dict_append_array(&dict, "UUIDs", DBUS_TYPE_STRING, &uuids, i);
	g_free(uuids);

	/* Adapter */
	ptr = adapter_get_path(adapter);
	dict_append_entry(&dict, "Adapter", DBUS_TYPE_OBJECT_PATH, &ptr);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *set_alias(DBusConnection *conn, DBusMessage *msg,
					const char *alias, void *data)
{
	struct btd_device *device = data;
	struct btd_adapter *adapter = device->adapter;
	char srcaddr[18], dstaddr[18];
	bdaddr_t src;
	int err;

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

	/* Remove alias if empty string */
	err = write_device_alias(srcaddr, dstaddr,
			g_str_equal(alias, "") ? NULL : alias);
	if (err < 0)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".Failed",
				strerror(-err));

	emit_property_changed(conn, dbus_message_get_path(msg),
				DEVICE_INTERFACE, "Alias",
				DBUS_TYPE_STRING, &alias);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *set_trust(DBusConnection *conn, DBusMessage *msg,
					dbus_bool_t value, void *data)
{
	struct btd_device *device = data;
	struct btd_adapter *adapter = device->adapter;
	char srcaddr[18], dstaddr[18];
	bdaddr_t src;

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

	write_trust(srcaddr, dstaddr, GLOBAL_TRUST, value);

	emit_property_changed(conn, dbus_message_get_path(msg),
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

static void discover_services_req_exit(DBusConnection *conn, void *user_data)
{
	struct browse_req *req = user_data;

	debug("DiscoverServices requestor exited");

	browse_request_cancel(req);
}

static DBusMessage *discover_services(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct btd_device *device = user_data;
	const char *pattern;
	int err;

	if (device->browse)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".InProgress",
						"Discover in progress");

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pattern,
						DBUS_TYPE_INVALID) == FALSE)
		goto fail;

	if (strlen(pattern) == 0) {
		err = device_browse(device, conn, msg, NULL, FALSE);
		if (err < 0)
			goto fail;
	} else {
		uuid_t uuid;

		if (bt_string2uuid(&uuid, pattern) < 0)
			return invalid_args(msg);

		sdp_uuid128_to_uuid(&uuid);

		err = device_browse(device, conn, msg, &uuid, FALSE);
		if (err < 0)
			goto fail;
	}

	return NULL;

fail:
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
					"Discovery Failed");
}

static const char *browse_request_get_requestor(struct browse_req *req)
{
	if (!req->msg)
		return NULL;

	return dbus_message_get_sender(req->msg);
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

static void discover_services_reply(struct browse_req *req, int err,
							sdp_list_t *recs)
{
	DBusMessage *reply;
	DBusMessageIter iter, dict;
	sdp_list_t *seq;

	if (err) {
		const char *err_if;

		if (err == -EHOSTDOWN)
			err_if = ERROR_INTERFACE ".ConnectionAttemptFailed";
		else
			err_if = ERROR_INTERFACE ".Failed";

		reply = dbus_message_new_error(req->msg, err_if,
							strerror(-err));
		g_dbus_send_message(req->conn, reply);
		return;
	}

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
		GString *result;

		if (!rec)
			break;

		result = g_string_new(NULL);

		convert_sdp_record_to_xml(rec, result,
				(void *) g_string_append);

		if (result->len)
			iter_append_record(&dict, rec->handle, result->str);

		g_string_free(result, TRUE);
	}

	dbus_message_iter_close_container(&iter, &dict);

	g_dbus_send_message(req->conn, reply);
}

static DBusMessage *cancel_discover(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct btd_device *device = user_data;
	const char *sender = dbus_message_get_sender(msg);
	const char *requestor;

	if (!device->browse)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".Failed",
				"No pending discovery");

	if (!dbus_message_is_method_call(device->browse->msg, DEVICE_INTERFACE,
					"DiscoverServices"))
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".NotAuthorized",
				"Not Authorized");

	requestor = browse_request_get_requestor(device->browse);

	/* only the discover requestor can cancel the inquiry process */
	if (!requestor || !g_str_equal(requestor, sender))
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".NotAuthorized",
				"Not Authorized");

	discover_services_reply(device->browse, -ECANCELED, NULL);

	browse_request_cancel(device->browse);

	return dbus_message_new_method_return(msg);
}

static gboolean do_disconnect(gpointer user_data)
{
	struct btd_device *device = user_data;
	disconnect_cp cp;
	int dd;
	uint16_t dev_id = adapter_get_dev_id(device->adapter);

	device->disconn_timer = 0;

	dd = hci_open_dev(dev_id);
	if (dd < 0)
		goto fail;

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(device->handle);
	cp.reason = HCI_OE_USER_ENDED_CONNECTION;

	hci_send_cmd(dd, OGF_LINK_CTL, OCF_DISCONNECT,
			DISCONNECT_CP_SIZE, &cp);

	close(dd);

fail:
	return FALSE;
}

static void bonding_request_cancel(struct bonding_req *bonding)
{
	if (!bonding->io)
		return;

	if (bonding->io_id) {
		g_source_remove(bonding->io_id);
		bonding->io_id = 0;
	}

	g_io_channel_shutdown(bonding->io, TRUE, NULL);
	g_io_channel_unref(bonding->io);
	bonding->io = NULL;
}

void device_request_disconnect(struct btd_device *device, DBusMessage *msg)
{
	GSList *l;
	DBusConnection *conn = get_dbus_connection();

	if (device->bonding)
		bonding_request_cancel(device->bonding);

	if (device->browse)
		browse_request_cancel(device->browse);

	if (msg)
		device->disconnects = g_slist_append(device->disconnects,
						dbus_message_ref(msg));

	if (device->disconn_timer)
		return;

	l = device->watches;
	while (l) {
		struct btd_disconnect_data *data = l->data;

		l = l->next;

		if (data->watch)
			/* temporary is set if device is going to be removed */
			data->watch(device, device->temporary,
					data->user_data);
	}

	g_slist_foreach(device->watches, (GFunc) g_free, NULL);
	g_slist_free(device->watches);
	device->watches = NULL;

	device->disconn_timer = g_timeout_add_seconds(DISCONNECT_TIMER,
						do_disconnect, device);

	g_dbus_emit_signal(conn, device->path,
			DEVICE_INTERFACE, "DisconnectRequested",
			DBUS_TYPE_INVALID);
}

static DBusMessage *disconnect(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct btd_device *device = user_data;

	if (!device->handle)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".NotConnected",
				"Device is not connected");

	device_request_disconnect(device, msg);

	return NULL;
}

static GDBusMethodTable device_methods[] = {
	{ "GetProperties",	"",	"a{sv}",	get_properties	},
	{ "SetProperty",	"sv",	"",		set_property	},
	{ "DiscoverServices",	"s",	"a{us}",	discover_services,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "CancelDiscovery",	"",	"",		cancel_discover	},
	{ "Disconnect",		"",	"",		disconnect,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ }
};

static GDBusSignalTable device_signals[] = {
	{ "PropertyChanged",		"sv"	},
	{ "DisconnectRequested",	""	},
	{ }
};

gboolean device_is_connected(struct btd_device *device)
{
	return (device->handle != 0);
}

static void device_set_connected(struct btd_device *device,
					DBusConnection *conn,
					gboolean connected)
{
	emit_property_changed(conn, device->path, DEVICE_INTERFACE,
				"Connected", DBUS_TYPE_BOOLEAN, &connected);

	if (connected && device->secmode3) {
		struct btd_adapter *adapter = device_get_adapter(device);
		bdaddr_t sba;

		adapter_get_address(adapter, &sba);

		device->secmode3 = FALSE;

		hcid_dbus_bonding_process_complete(&sba, &device->bdaddr, 0);
	}
}

void device_add_connection(struct btd_device *device, DBusConnection *conn,
				uint16_t handle)
{
	if (device->handle) {
		error("%s: Unable to add connection %u, %u already exist)",
			device->path, handle, device->handle);
		return;
	}

	device->handle = handle;

	device_set_connected(device, conn, TRUE);
}

void device_remove_connection(struct btd_device *device, DBusConnection *conn,
				uint16_t handle)
{
	if (handle && device->handle != handle) {
		error("%s: Unable to remove connection %u, handle mismatch (%u)",
			device->path, handle, device->handle);
		return;
	}

	device->handle = 0;

	if (device->disconn_timer > 0) {
		g_source_remove(device->disconn_timer);
		device->disconn_timer = 0;
	}

	while (device->disconnects) {
		DBusMessage *msg = device->disconnects->data;

		g_dbus_send_reply(conn, msg, DBUS_TYPE_INVALID);
		device->disconnects = g_slist_remove(device->disconnects, msg);
	}

	device_set_connected(device, conn, FALSE);
}

gboolean device_has_connection(struct btd_device *device, uint16_t handle)
{
	return (handle == device->handle);
}

guint device_add_disconnect_watch(struct btd_device *device,
				disconnect_watch watch, void *user_data,
				GDestroyNotify destroy)
{
	struct btd_disconnect_data *data;
	static guint id = 0;

	data = g_new0(struct btd_disconnect_data, 1);
	data->id = ++id;
	data->watch = watch;
	data->user_data = user_data;
	data->destroy = destroy;

	device->watches = g_slist_append(device->watches, data);

	return data->id;
}

void device_remove_disconnect_watch(struct btd_device *device, guint id)
{
	GSList *l;

	for (l = device->watches; l; l = l->next) {
		struct btd_disconnect_data *data = l->data;

		if (data->id == id) {
			device->watches = g_slist_remove(device->watches,
							data);
			if (data->destroy)
				data->destroy(data->user_data);
			g_free(data);
			return;
		}
	}
}

gboolean device_get_secmode3_conn(struct btd_device *device)
{
	return device->secmode3;
}

void device_set_secmode3_conn(struct btd_device *device, gboolean enable)
{
	device->secmode3 = enable;
}

struct btd_device *device_create(DBusConnection *conn,
					struct btd_adapter *adapter,
					const gchar *address)
{
	gchar *address_up;
	struct btd_device *device;
	const gchar *adapter_path = adapter_get_path(adapter);
	bdaddr_t src;
	char srcaddr[18];

	device = g_try_malloc0(sizeof(struct btd_device));
	if (device == NULL)
		return NULL;

	address_up = g_ascii_strup(address, -1);
	device->path = g_strdup_printf("%s/dev_%s", adapter_path, address_up);
	g_strdelimit(device->path, ":", '_');
	g_free(address_up);

	debug("Creating device %s", device->path);

	if (g_dbus_register_interface(conn, device->path, DEVICE_INTERFACE,
				device_methods, device_signals, NULL,
				device, device_free) == FALSE) {
		device_free(device);
		return NULL;
	}

	str2ba(address, &device->bdaddr);
	device->adapter = adapter;
	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
	read_device_name(srcaddr, address, device->name);

	device->auth = 0xff;

	if (read_link_key(&src, &device->bdaddr, NULL, NULL) == 0)
		device->paired = TRUE;

	return btd_device_ref(device);
}

void device_set_name(struct btd_device *device, const char *name)
{
	DBusConnection *conn = get_dbus_connection();
	char alias[MAX_NAME_LENGTH + 1];
	char srcaddr[18], dstaddr[18];
	bdaddr_t src;

	if (strncmp(name, device->name, MAX_NAME_LENGTH) == 0)
		return;

	strncpy(device->name, name, MAX_NAME_LENGTH);

	emit_property_changed(conn, device->path,
				DEVICE_INTERFACE, "Name",
				DBUS_TYPE_STRING, &name);

	adapter_get_address(device->adapter, &src);
	ba2str(&src, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

	if (read_device_alias(srcaddr, dstaddr, alias, sizeof(alias)) == 0)
		return;

	emit_property_changed(conn, device->path,
				DEVICE_INTERFACE, "Alias",
				DBUS_TYPE_STRING, &name);
}

void device_get_name(struct btd_device *device, char *name, size_t len)
{
	strncpy(name, device->name, len);
}

static void device_remove_bonding(struct btd_device *device)
{
	char filename[PATH_MAX + 1];
	char srcaddr[18], dstaddr[18];
	int dd, dev_id;
	bdaddr_t bdaddr;

	adapter_get_address(device->adapter, &bdaddr);
	ba2str(&bdaddr, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr,
			"linkkeys");

	/* Delete the link key from storage */
	textfile_casedel(filename, dstaddr);

	dev_id = adapter_get_dev_id(device->adapter);

	dd = hci_open_dev(dev_id);
	if (dd < 0)
		return;

	/* Delete the link key from the Bluetooth chip */
	hci_delete_stored_link_key(dd, &device->bdaddr, 0, HCI_REQ_TIMEOUT);

	hci_close_dev(dd);
}

static void device_remove_stored(struct btd_device *device)
{
	bdaddr_t src;
	char addr[18];

	adapter_get_address(device->adapter, &src);
	ba2str(&device->bdaddr, addr);

	if (device->paired)
		device_remove_bonding(device);
	delete_entry(&src, "profiles", addr);
	delete_entry(&src, "trusts", addr);
	delete_all_records(&src, &device->bdaddr);
}

void device_remove(struct btd_device *device, gboolean remove_stored)
{
	GSList *list;
	struct btd_device_driver *driver;

	debug("Removing device %s", device->path);

	if (device->bonding)
		device_cancel_bonding(device, HCI_OE_USER_ENDED_CONNECTION);

	if (device->browse)
		browse_request_cancel(device->browse);

	if (device->handle)
		do_disconnect(device);

	if (remove_stored)
		device_remove_stored(device);

	for (list = device->drivers; list; list = list->next) {
		struct btd_driver_data *driver_data = list->data;
		driver = driver_data->driver;

		driver->remove(device);
		g_free(driver_data);
	}

	btd_device_unref(device);
}

gint device_address_cmp(struct btd_device *device, const gchar *address)
{
	char addr[18];

	ba2str(&device->bdaddr, addr);
	return strcasecmp(addr, address);
}

static gboolean record_has_uuid(const sdp_record_t *rec,
				const char *profile_uuid)
{
	sdp_list_t *pat;

	for (pat = rec->pattern; pat != NULL; pat = pat->next) {
		char *uuid;
		int ret;

		uuid = bt_uuid2string(pat->data);
		if (!uuid)
			continue;

		ret = strcasecmp(uuid, profile_uuid);

		g_free(uuid);

		if (ret == 0)
			return TRUE;
	}

	return FALSE;
}

static GSList *device_match_pattern(struct btd_device *device,
					const char *match_uuid,
					GSList *profiles)
{
	GSList *l, *uuids = NULL;

	for (l = profiles; l; l = l->next) {
		char *profile_uuid = l->data;
		const sdp_record_t *rec;

		rec = btd_device_get_record(device, profile_uuid);
		if (!rec)
			continue;

		if (record_has_uuid(rec, match_uuid))
			uuids = g_slist_append(uuids, profile_uuid);
	}

	return uuids;
}

static GSList *device_match_driver(struct btd_device *device,
					struct btd_device_driver *driver,
					GSList *profiles)
{
	const char **uuid;
	GSList *uuids = NULL;

	for (uuid = driver->uuids; *uuid; uuid++) {
		GSList *match;

		/* skip duplicated uuids */
		if (g_slist_find_custom(uuids, *uuid,
				(GCompareFunc) strcasecmp))
			continue;

		/* match profile driver */
		match = g_slist_find_custom(profiles, *uuid,
					(GCompareFunc) strcasecmp);
		if (match) {
			uuids = g_slist_append(uuids, match->data);
			continue;
		}

		/* match pattern driver */
		match = device_match_pattern(device, *uuid, profiles);
		for (; match; match = match->next)
			uuids = g_slist_append(uuids, match->data);
	}

	return uuids;
}

void device_probe_drivers(struct btd_device *device, GSList *profiles)
{
	GSList *list;
	int err;

	debug("Probe drivers for %s", device->path);

	for (list = device_drivers; list; list = list->next) {
		struct btd_device_driver *driver = list->data;
		GSList *probe_uuids;
		struct btd_driver_data *driver_data;

		probe_uuids = device_match_driver(device, driver, profiles);

		if (!probe_uuids)
			continue;

		driver_data = g_new0(struct btd_driver_data, 1);

		err = driver->probe(device, probe_uuids);
		if (err < 0) {
			error("probe failed with driver %s for device %s",
					driver->name, device->path);

			g_free(driver_data);
			g_slist_free(probe_uuids);
			continue;
		}

		driver_data->driver = driver;
		device->drivers = g_slist_append(device->drivers, driver_data);
		g_slist_free(probe_uuids);
	}

	for (list = profiles; list; list = list->next) {
		GSList *l = g_slist_find_custom(device->uuids, list->data,
						(GCompareFunc) strcasecmp);
		if (l)
			continue;

		device->uuids = g_slist_insert_sorted(device->uuids,
						g_strdup(list->data),
						(GCompareFunc) strcasecmp);
	}

	if (device->tmp_records) {
		sdp_list_free(device->tmp_records,
				(sdp_free_func_t) sdp_record_free);
		device->tmp_records = NULL;
	}
}

static void device_remove_drivers(struct btd_device *device, GSList *uuids)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	GSList *list, *next;
	char srcaddr[18], dstaddr[18];
	bdaddr_t src;
	sdp_list_t *records;

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

	records = read_records(&src, &device->bdaddr);

	debug("Remove drivers for %s", device->path);

	for (list = device->drivers; list; list = next) {
		struct btd_driver_data *driver_data = list->data;
		struct btd_device_driver *driver = driver_data->driver;
		const char **uuid;

		next = list->next;

		for (uuid = driver->uuids; *uuid; uuid++) {
			if (!g_slist_find_custom(uuids, *uuid,
						(GCompareFunc) strcasecmp))
				continue;

			debug("UUID %s was removed from device %s",
							*uuid, dstaddr);

			driver->remove(device);
			device->drivers = g_slist_remove(device->drivers,
								driver_data);
			g_free(driver_data);

			break;
		}
	}

	for (list = uuids; list; list = list->next) {
		sdp_record_t *rec;

		device->uuids = g_slist_remove(device->uuids, list->data);

		rec = find_record_in_list(records, list->data);
		if (!rec)
			continue;

		delete_record(srcaddr, dstaddr, rec->handle);

		records = sdp_list_remove(records, rec);
		sdp_record_free(rec);

	}

	if (records)
		sdp_list_free(records, (sdp_free_func_t) sdp_record_free);
}

static void services_changed(struct btd_device *device)
{
	DBusConnection *conn = get_dbus_connection();
	char **uuids;
	GSList *l;
	int i;

	uuids = g_new0(char *, g_slist_length(device->uuids) + 1);
	for (i = 0, l = device->uuids; l; l = l->next, i++)
		uuids[i] = l->data;

	emit_array_property_changed(conn, device->path, DEVICE_INTERFACE,
					"UUIDs", DBUS_TYPE_STRING, &uuids);

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
	char srcaddr[18], dstaddr[18];
	bdaddr_t src;

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

	for (seq = recs; seq; seq = seq->next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;
		sdp_list_t *svcclass = NULL;
		gchar *profile_uuid;
		GSList *l;

		if (!rec)
			break;

		if (sdp_get_service_classes(rec, &svcclass) < 0)
			continue;

		/* Check for empty service classes list */
		if (svcclass == NULL) {
			debug("Skipping record with no service classes");
			continue;
		}

		/* Extract the first element and skip the remainning */
		profile_uuid = bt_uuid2string(svcclass->data);
		if (!profile_uuid) {
			sdp_list_free(svcclass, free);
			continue;
		}

		if (!strcasecmp(profile_uuid, PNP_UUID)) {
			uint16_t source, vendor, product, version;
			sdp_data_t *pdlist;

			pdlist = sdp_data_get(rec, SDP_ATTR_VENDOR_ID_SOURCE);
			source = pdlist ? pdlist->val.uint16 : 0x0000;

			pdlist = sdp_data_get(rec, SDP_ATTR_VENDOR_ID);
			vendor = pdlist ? pdlist->val.uint16 : 0x0000;

			pdlist = sdp_data_get(rec, SDP_ATTR_PRODUCT_ID);
			product = pdlist ? pdlist->val.uint16 : 0x0000;

			pdlist = sdp_data_get(rec, SDP_ATTR_VERSION);
			version = pdlist ? pdlist->val.uint16 : 0x0000;

			if (source || vendor || product || version)
				store_device_id(srcaddr, dstaddr, source,
						vendor, product, version);
		}

		/* Check for duplicates */
		if (sdp_list_find(req->records, rec, rec_cmp)) {
			g_free(profile_uuid);
			sdp_list_free(svcclass, free);
			continue;
		}

		store_record(srcaddr, dstaddr, rec);

		/* Copy record */
		req->records = sdp_list_append(req->records,
							sdp_copy_record(rec));

		l = g_slist_find_custom(device->uuids, profile_uuid,
							(GCompareFunc) strcmp);
		if (!l)
			req->profiles_added =
					g_slist_append(req->profiles_added,
							profile_uuid);
		else {
			req->profiles_removed =
					g_slist_remove(req->profiles_removed,
							l->data);
			g_free(profile_uuid);
		}

		sdp_list_free(svcclass, free);
	}
}

static void store_profiles(struct btd_device *device)
{
	struct btd_adapter *adapter = device->adapter;
	bdaddr_t src;
	char *str;

	adapter_get_address(adapter, &src);

	if (!device->uuids) {
		write_device_profiles(&src, &device->bdaddr, "");
		return;
	}

	str = bt_list2string(device->uuids);
	write_device_profiles(&src, &device->bdaddr, str);
	g_free(str);
}

static void search_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct browse_req *req = user_data;
	struct btd_device *device = req->device;
	DBusMessage *reply;

	if (err < 0) {
		error("%s: error updating services: %s (%d)",
				device->path, strerror(-err), -err);
		goto proceed;
	}

	update_services(req, recs);

	if (device->tmp_records && req->records) {
		sdp_list_free(device->tmp_records,
					(sdp_free_func_t) sdp_record_free);
		device->tmp_records = req->records;
		req->records = NULL;
	}

	if (!req->profiles_added && !req->profiles_removed) {
		debug("%s: No service update", device->path);
		goto proceed;
	}

	/* Probe matching drivers for services added */
	if (req->profiles_added)
		device_probe_drivers(device, req->profiles_added);

	/* Remove drivers for services removed */
	if (req->profiles_removed)
		device_remove_drivers(device, req->profiles_removed);

	/* Propagate services changes */
	services_changed(req->device);

proceed:
	/* Store the device's profiles in the filesystem */
	store_profiles(device);

	if (!req->msg)
		goto cleanup;

	if (dbus_message_is_method_call(req->msg, DEVICE_INTERFACE,
					"DiscoverServices")) {
		discover_services_reply(req, err, req->records);
		goto cleanup;
	}

	/* Reply create device request */
	reply = dbus_message_new_method_return(req->msg);
	if (!reply)
		goto cleanup;

	dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &device->path,
							DBUS_TYPE_INVALID);

	g_dbus_send_message(req->conn, reply);

	device_set_temporary(device, FALSE);

cleanup:
	browse_request_free(req);
	device->browse = NULL;
}

static void browse_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct browse_req *req = user_data;
	struct btd_device *device = req->device;
	struct btd_adapter *adapter = device->adapter;
	bdaddr_t src;
	uuid_t uuid;

	/* If we have a valid response and req->search_uuid == 2, then L2CAP
	 * UUID & PNP searching was successful -- we are done */
	if (err < 0 || (req->search_uuid == 2 && req->records)) {
		if (err == -ECONNRESET && req->reconnect_attempt < 1) {
			req->search_uuid--;
			req->reconnect_attempt++;
		} else
			goto done;
	}

	update_services(req, recs);

	adapter_get_address(adapter, &src);

	/* Search for mandatory uuids */
	if (uuid_list[req->search_uuid]) {
		sdp_uuid16_create(&uuid, uuid_list[req->search_uuid++]);
		bt_search_service(&src, &device->bdaddr, &uuid,
						browse_cb, user_data, NULL);
		return;
	}

done:
	search_cb(recs, err, user_data);
}

static void init_browse(struct browse_req *req, gboolean reverse)
{
	GSList *l;

	/* If we are doing reverse-SDP don't try to detect removed profiles
	 * since some devices hide their service records while they are
	 * connected
	 */
	if (reverse)
		return;

	for (l = req->device->uuids; l; l = l->next)
		req->profiles_removed = g_slist_append(req->profiles_removed,
						l->data);
}

int device_browse(struct btd_device *device, DBusConnection *conn,
			DBusMessage *msg, uuid_t *search, gboolean reverse)
{
	struct btd_adapter *adapter = device->adapter;
	struct browse_req *req;
	bdaddr_t src;
	uuid_t uuid;
	bt_callback_t cb;
	int err;

	if (device->browse)
		return -EBUSY;

	adapter_get_address(adapter, &src);

	req = g_new0(struct browse_req, 1);

	if (conn == NULL)
		conn = get_dbus_connection();

	req->conn = dbus_connection_ref(conn);
	req->device = device;

	if (search) {
		memcpy(&uuid, search, sizeof(uuid_t));
		cb = search_cb;
	} else {
		sdp_uuid16_create(&uuid, uuid_list[req->search_uuid++]);
		init_browse(req, reverse);
		cb = browse_cb;
	}

	device->browse = req;

	if (msg) {
		const char *sender = dbus_message_get_sender(msg);

		req->msg = dbus_message_ref(msg);
		/* Track the request owner to cancel it
		 * automatically if the owner exits */
		req->listener_id = g_dbus_add_disconnect_watch(conn,
						sender,
						discover_services_req_exit,
						req, NULL);
	}

	err = bt_search_service(&src, &device->bdaddr,
				&uuid, cb, req, NULL);
	if (err < 0) {
		browse_request_free(req);
		device->browse = NULL;
	}

	return err;
}

struct btd_adapter *device_get_adapter(struct btd_device *device)
{
	if (!device)
		return NULL;

	return device->adapter;
}

void device_get_address(struct btd_device *device, bdaddr_t *bdaddr)
{
	bacpy(bdaddr, &device->bdaddr);
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
	return device->browse ? TRUE : FALSE;
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

uint8_t device_get_cap(struct btd_device *device)
{
	return device->cap;
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

static gboolean start_discovery(gpointer user_data)
{
	struct btd_device *device = user_data;

	device_browse(device, NULL, NULL, NULL, TRUE);

	device->discov_timer = 0;

	return FALSE;
}

DBusMessage *new_authentication_return(DBusMessage *msg, uint8_t status)
{
	switch (status) {
	case 0x00: /* success */
		return dbus_message_new_method_return(msg);

	case 0x04: /* page timeout */
		return dbus_message_new_error(msg,
				ERROR_INTERFACE ".ConnectionAttemptFailed",
				"Page Timeout");
	case 0x08: /* connection timeout */
		return dbus_message_new_error(msg,
				ERROR_INTERFACE ".ConnectionAttemptFailed",
				"Connection Timeout");
	case 0x10: /* connection accept timeout */
	case 0x22: /* LMP response timeout */
	case 0x28: /* instant passed - is this a timeout? */
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".AuthenticationTimeout",
					"Authentication Timeout");
	case 0x17: /* too frequent pairing attempts */
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".RepeatedAttempts",
					"Repeated Attempts");

	case 0x06:
	case 0x18: /* pairing not allowed (e.g. gw rejected attempt) */
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".AuthenticationRejected",
					"Authentication Rejected");

	case 0x07: /* memory capacity */
	case 0x09: /* connection limit */
	case 0x0a: /* synchronous connection limit */
	case 0x0d: /* limited resources */
	case 0x13: /* user ended the connection */
	case 0x14: /* terminated due to low resources */
	case 0x16: /* connection terminated */
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".AuthenticationCanceled",
					"Authentication Canceled");

	case 0x05: /* authentication failure */
	case 0x0E: /* rejected due to security reasons - is this auth failure? */
	case 0x25: /* encryption mode not acceptable - is this auth failure? */
	case 0x26: /* link key cannot be changed - is this auth failure? */
	case 0x29: /* pairing with unit key unsupported - is this auth failure? */
	case 0x2f: /* insufficient security - is this auth failure? */
	default:
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".AuthenticationFailed",
					"Authentication Failed");
	}
}

static void bonding_request_free(struct bonding_req *bonding)
{
	struct btd_device *device;

	if (!bonding)
		return;

	if (bonding->listener_id)
		g_dbus_remove_watch(bonding->conn, bonding->listener_id);

	if (bonding->msg)
		dbus_message_unref(bonding->msg);

	if (bonding->conn)
		dbus_connection_unref(bonding->conn);

	if (bonding->io_id)
		g_source_remove(bonding->io_id);

	if (bonding->io)
		g_io_channel_unref(bonding->io);

	device = bonding->device;
	g_free(bonding);

	if (!device)
		return;

	device->bonding = NULL;

	if (!device->agent)
		return;

	agent_cancel(device->agent);
	agent_free(device->agent);
	device->agent = NULL;
}

void device_set_paired(struct btd_device *device, gboolean value)
{
	DBusConnection *conn = get_dbus_connection();

	if (device->paired == value)
		return;

	device->paired = value;

	emit_property_changed(conn, device->path, DEVICE_INTERFACE, "Paired",
				DBUS_TYPE_BOOLEAN, &value);
}

static void device_agent_removed(struct agent *agent, void *user_data)
{
	struct btd_device *device = user_data;

	device_set_agent(device, NULL);

	if (device->authr)
		device->authr->agent = NULL;
}

static struct bonding_req *bonding_request_new(DBusConnection *conn,
						DBusMessage *msg,
						struct btd_device *device,
						const char *agent_path,
						uint8_t capability)
{
	struct bonding_req *bonding;
	const char *name = dbus_message_get_sender(msg);
	struct agent *agent;

	debug("%s: requesting bonding", device->path);

	if (!agent_path)
		goto proceed;

	agent = agent_create(device->adapter, name, agent_path,
					capability,
					device_agent_removed,
					device);
	if (!agent) {
		error("Unable to create a new agent");
		return NULL;
	}

	device->agent = agent;

	debug("Temporary agent registered for %s at %s:%s",
			device->path, name, agent_path);

proceed:
	bonding = g_new0(struct bonding_req, 1);

	bonding->conn = dbus_connection_ref(conn);
	bonding->msg = dbus_message_ref(msg);

	return bonding;
}

static gboolean bonding_io_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct btd_device *device = user_data;
	DBusMessage *reply;

	if (!device->bonding)
		return FALSE;

	reply = new_authentication_return(device->bonding->msg,
					HCI_CONNECTION_TERMINATED);
	g_dbus_send_message(device->bonding->conn, reply);

	bonding_request_free(device->bonding);

	return FALSE;
}

static void bonding_connect_cb(GIOChannel *io, GError *err, gpointer user_data)
{
	struct btd_device *device = user_data;
	struct hci_request rq;
	auth_requested_cp cp;
	evt_cmd_status rp;
	int dd;
	uint16_t handle;

	if (!device->bonding) {
		if (!err)
			g_io_channel_shutdown(io, TRUE, NULL);
		return;
	}

	if (err) {
		error("%s", err->message);
		error_connection_attempt_failed(device->bonding->conn,
						device->bonding->msg,
						ENETDOWN);
		goto cleanup;
	}

	if (!bt_io_get(io, BT_IO_L2RAW, &err,
			BT_IO_OPT_HANDLE, &handle,
			BT_IO_OPT_INVALID)) {
		error("Unable to get connection handle: %s", err->message);
		error_connection_attempt_failed(device->bonding->conn,
						device->bonding->msg,
						ENETDOWN);
		g_error_free(err);
		goto failed;
	}

	dd = hci_open_dev(adapter_get_dev_id(device->adapter));
	if (dd < 0) {
		DBusMessage *reply = no_such_adapter(device->bonding->msg);
		g_dbus_send_message(device->bonding->conn, reply);
		goto failed;
	}

	memset(&rp, 0, sizeof(rp));

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(handle);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_AUTH_REQUESTED;
	rq.cparam = &cp;
	rq.clen   = AUTH_REQUESTED_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CMD_STATUS_SIZE;
	rq.event  = EVT_CMD_STATUS;

	if (hci_send_req(dd, &rq, HCI_REQ_TIMEOUT) < 0) {
		error("Unable to send HCI request: %s (%d)",
					strerror(errno), errno);
		error_failed_errno(device->bonding->conn, device->bonding->msg,
				errno);
		hci_close_dev(dd);
		goto failed;
	}

	if (rp.status) {
		error("HCI_Authentication_Requested failed with status 0x%02x",
				rp.status);
		error_failed_errno(device->bonding->conn, device->bonding->msg,
				bt_error(rp.status));
		hci_close_dev(dd);
		goto failed;
	}

	hci_close_dev(dd);

	device->bonding->io_id = g_io_add_watch(io,
					G_IO_NVAL | G_IO_HUP | G_IO_ERR,
					bonding_io_cb, device);

	return;

failed:
	g_io_channel_shutdown(io, TRUE, NULL);

cleanup:
	device->bonding->io_id = 0;
	bonding_request_free(device->bonding);
}

static void create_bond_req_exit(DBusConnection *conn, void *user_data)
{
	struct btd_device *device = user_data;

	debug("%s: requestor exited before bonding was completed", device->path);

	if (device->authr)
		device_cancel_authentication(device, FALSE);

	if (device->bonding) {
		device->bonding->listener_id = 0;
		device_request_disconnect(device, NULL);
	}
}

DBusMessage *device_create_bonding(struct btd_device *device,
					DBusConnection *conn,
					DBusMessage *msg,
					const char *agent_path,
					uint8_t capability)
{
	char filename[PATH_MAX + 1];
	char *str, srcaddr[18], dstaddr[18];
	struct btd_adapter *adapter = device->adapter;
	struct bonding_req *bonding;
	bdaddr_t src;
	GError *err = NULL;
	GIOChannel *io;

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

	if (device->bonding)
		return in_progress(msg, "Bonding in progress");

	/* check if a link key already exists */
	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr,
			"linkkeys");

	str = textfile_caseget(filename, dstaddr);
	if (str) {
		free(str);
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".AlreadyExists",
				"Bonding already exists");
	}


	io = bt_io_connect(BT_IO_L2RAW, bonding_connect_cb, device,
				NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &src,
				BT_IO_OPT_DEST_BDADDR, &device->bdaddr,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_HIGH,
				BT_IO_OPT_INVALID);
	if (io == NULL) {
		DBusMessage *reply;
		reply = g_dbus_create_error(msg,
				ERROR_INTERFACE ".ConnectionAttemptFailed",
				err->message);
		error("bt_io_connect: %s", err->message);
		g_error_free(err);
		return reply;
	}

	bonding = bonding_request_new(conn, msg, device, agent_path,
					capability);
	if (!bonding) {
		g_io_channel_shutdown(io, TRUE, NULL);
		return NULL;
	}

	bonding->io = io;

	bonding->listener_id = g_dbus_add_disconnect_watch(conn,
						dbus_message_get_sender(msg),
						create_bond_req_exit, device,
						NULL);

	device->bonding = bonding;
	bonding->device = device;

	return NULL;
}

void device_simple_pairing_complete(struct btd_device *device, uint8_t status)
{
	struct authentication_req *auth = device->authr;

	if (auth && auth->type == AUTH_TYPE_NOTIFY && auth->agent)
		agent_cancel(auth->agent);
}

void device_bonding_complete(struct btd_device *device, uint8_t status)
{
	struct bonding_req *bonding = device->bonding;
	struct authentication_req *auth = device->authr;

	if (auth && auth->type == AUTH_TYPE_NOTIFY && auth->agent)
		agent_cancel(auth->agent);

	if (status)
		goto failed;

	device->auth = 0xff;

	g_free(device->authr);
	device->authr = NULL;

	if (device->renewed_key)
		return;

	device_set_temporary(device, FALSE);

	/* If we were initiators start service discovery immediately.
	 * However if the other end was the initator wait a few seconds
	 * before SDP. This is due to potential IOP issues if the other
	 * end starts doing SDP at the same time as us */
	if (bonding) {
		/* If we are initiators remove any discovery timer and just
		 * start discovering services directly */
		if (device->discov_timer) {
			g_source_remove(device->discov_timer);
			device->discov_timer = 0;
		}

		device_browse(device, bonding->conn, bonding->msg,
				NULL, FALSE);

		bonding_request_free(bonding);
	} else {
		if (!device->browse && !device->discov_timer &&
				main_opts.reverse_sdp) {
			/* If we are not initiators and there is no currently
			 * active discovery or discovery timer, set discovery
			 * timer */
			debug("setting timer for reverse service discovery");
			device->discov_timer = g_timeout_add_seconds(
							DISCOVERY_TIMER,
							start_discovery,
							device);
		}
	}

	device_set_paired(device, TRUE);

	return;

failed:
	device_cancel_bonding(device, status);
}

gboolean device_is_creating(struct btd_device *device, const char *sender)
{
	DBusMessage *msg;

	if (device->bonding && device->bonding->msg)
		msg = device->bonding->msg;
	else if (device->browse && device->browse->msg)
		msg = device->browse->msg;
	else
		return FALSE;

	if (!dbus_message_is_method_call(msg, ADAPTER_INTERFACE,
						"CreatePairedDevice") &&
			!dbus_message_is_method_call(msg, ADAPTER_INTERFACE,
							"CreateDevice"))
		return FALSE;

	if (sender == NULL)
		return TRUE;

	return g_str_equal(sender, dbus_message_get_sender(msg));
}

gboolean device_is_bonding(struct btd_device *device, const char *sender)
{
	struct bonding_req *bonding = device->bonding;

	if (!device->bonding)
		return FALSE;

	if (!sender)
		return TRUE;

	return g_str_equal(sender, dbus_message_get_sender(bonding->msg));
}

void device_cancel_bonding(struct btd_device *device, uint8_t status)
{
	struct bonding_req *bonding = device->bonding;
	DBusMessage *reply;

	if (!bonding)
		return;

	debug("%s: canceling bonding request", device->path);

	if (device->authr)
		device_cancel_authentication(device, FALSE);

	reply = new_authentication_return(bonding->msg, status);
	g_dbus_send_message(bonding->conn, reply);

	bonding_request_cancel(bonding);
	bonding_request_free(bonding);
}

static void pincode_cb(struct agent *agent, DBusError *err, const char *pincode,
			void *data)
{
	struct authentication_req *auth = data;
	struct btd_device *device = auth->device;

	/* No need to reply anything if the authentication already failed */
	if (!auth || !auth->cb)
		return;

	((agent_pincode_cb) auth->cb)(agent, err, pincode, device);

	device->authr->cb = NULL;
	device->authr->agent = NULL;
}

static void confirm_cb(struct agent *agent, DBusError *err, void *data)
{
	struct authentication_req *auth = data;
	struct btd_device *device = auth->device;

	/* No need to reply anything if the authentication already failed */
	if (!auth || !auth->cb)
		return;

	((agent_cb) auth->cb)(agent, err, device);

	device->authr->cb = NULL;
	device->authr->agent = NULL;
}

static void passkey_cb(struct agent *agent, DBusError *err, uint32_t passkey,
			void *data)
{
	struct authentication_req *auth = data;
	struct btd_device *device = auth->device;

	/* No need to reply anything if the authentication already failed */
	if (!auth || !auth->cb)
		return;

	((agent_passkey_cb) auth->cb)(agent, err, passkey, device);

	device->authr->cb = NULL;
	device->authr->agent = NULL;
}

int device_request_authentication(struct btd_device *device, auth_type_t type,
				uint32_t passkey, void *cb)
{
	struct authentication_req *auth;
	struct agent *agent;
	int ret;

	debug("%s: requesting agent authentication", device->path);

	agent = device->agent;

	if (!agent)
		agent = adapter_get_agent(device->adapter);

	if (!agent) {
		error("No agent available for %u request", type);
		return -EPERM;
	}

	auth = g_new0(struct authentication_req, 1);
	auth->agent = agent;
	auth->device = device;
	auth->cb = cb;
	auth->type = type;
	device->authr = auth;

	switch (type) {
	case AUTH_TYPE_PINCODE:
		ret = agent_request_pincode(agent, device, pincode_cb,
								auth, NULL);
		break;
	case AUTH_TYPE_PASSKEY:
		ret = agent_request_passkey(agent, device, passkey_cb,
								auth, NULL);
		break;
	case AUTH_TYPE_CONFIRM:
		ret = agent_request_confirmation(agent, device, passkey,
						confirm_cb, auth, NULL);
		break;
	case AUTH_TYPE_NOTIFY:
		ret = agent_display_passkey(agent, device, passkey);
		break;
	case AUTH_TYPE_AUTO:
		ret = 0;
		break;
	default:
		ret = -EINVAL;
	}

	if (ret < 0) {
		error("Failed requesting authentication");
		g_free(auth);
		device->authr = NULL;
	}

	return ret;
}

static void cancel_authentication(struct authentication_req *auth)
{
	struct btd_device *device = auth->device;
	struct agent *agent = auth->agent;
	DBusError err;

	if (!auth || !auth->cb)
		return;

	dbus_error_init(&err);
	dbus_set_error_const(&err, "org.bluez.Error.Canceled", NULL);

	switch (auth->type) {
	case AUTH_TYPE_PINCODE:
		((agent_pincode_cb) auth->cb)(agent, &err, NULL, device);
		break;
	case AUTH_TYPE_CONFIRM:
		((agent_cb) auth->cb)(agent, &err, device);
		break;
	case AUTH_TYPE_PASSKEY:
		((agent_passkey_cb) auth->cb)(agent, &err, 0, device);
		break;
	case AUTH_TYPE_NOTIFY:
	case AUTH_TYPE_AUTO:
		/* User Notify/Auto doesn't require any reply */
		break;
	}

	dbus_error_free(&err);
	auth->cb = NULL;
}

void device_cancel_authentication(struct btd_device *device, gboolean aborted)
{
	struct authentication_req *auth = device->authr;

	if (!auth)
		return;

	debug("%s: canceling authentication request", device->path);

	if (auth->agent)
		agent_cancel(auth->agent);

	if (!aborted)
		cancel_authentication(auth);

	device->authr = NULL;
	g_free(auth);
}

gboolean device_is_authenticating(struct btd_device *device)
{
	return (device->authr != NULL);
}

gboolean device_is_authorizing(struct btd_device *device)
{
	return device->authorizing;
}

void device_set_authorizing(struct btd_device *device, gboolean auth)
{
	device->authorizing = auth;
}

void device_set_renewed_key(struct btd_device *device, gboolean renewed)
{
	device->renewed_key = renewed;
}

void btd_device_add_uuid(struct btd_device *device, const char *uuid)
{
	GSList *uuid_list;
	char *new_uuid;

	if (g_slist_find_custom(device->uuids, uuid,
				(GCompareFunc) strcasecmp))
		return;

	new_uuid = g_strdup(uuid);
	uuid_list = g_slist_append(NULL, new_uuid);

	device_probe_drivers(device, uuid_list);

	g_free(new_uuid);
	g_slist_free(uuid_list);

	store_profiles(device);
	services_changed(device);
}

const sdp_record_t *btd_device_get_record(struct btd_device *device,
						const char *uuid)
{
	bdaddr_t src;

	if (device->tmp_records)
		return find_record_in_list(device->tmp_records, uuid);

	adapter_get_address(device->adapter, &src);

	device->tmp_records = read_records(&src, &device->bdaddr);
	if (!device->tmp_records)
		return NULL;

	return find_record_in_list(device->tmp_records, uuid);
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

struct btd_device *btd_device_ref(struct btd_device *device)
{
	device->ref++;

	debug("btd_device_ref(%p): ref=%d", device, device->ref);

	return device;
}

void btd_device_unref(struct btd_device *device)
{
	DBusConnection *conn = get_dbus_connection();
	gchar *path;

	device->ref--;

	debug("btd_device_unref(%p): ref=%d", device, device->ref);

	if (device->ref > 0)
		return;

	path = g_strdup(device->path);

	g_dbus_unregister_interface(conn, path, DEVICE_INTERFACE);

	g_free(path);
}
