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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <dirent.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/uuid.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "log.h"
#include "textfile.h"

#include "hcid.h"
#include "sdpd.h"
#include "adapter.h"
#include "manager.h"
#include "device.h"
#include "profile.h"
#include "dbus-common.h"
#include "error.h"
#include "glib-helper.h"
#include "agent.h"
#include "storage.h"
#include "attrib/gattrib.h"
#include "attrib/att.h"
#include "attrib/gatt.h"
#include "attrib-server.h"
#include "eir.h"
#include "mgmt.h"

/* Flags Descriptions */
#define EIR_LIM_DISC                0x01 /* LE Limited Discoverable Mode */
#define EIR_GEN_DISC                0x02 /* LE General Discoverable Mode */
#define EIR_BREDR_UNSUP             0x04 /* BR/EDR Not Supported */
#define EIR_SIM_CONTROLLER          0x08 /* Simultaneous LE and BR/EDR to Same
					    Device Capable (Controller) */
#define EIR_SIM_HOST                0x10 /* Simultaneous LE and BR/EDR to Same
					    Device Capable (Host) */

#define IO_CAPABILITY_DISPLAYONLY	0x00
#define IO_CAPABILITY_DISPLAYYESNO	0x01
#define IO_CAPABILITY_KEYBOARDONLY	0x02
#define IO_CAPABILITY_NOINPUTNOOUTPUT	0x03
#define IO_CAPABILITY_KEYBOARDDISPLAY	0x04
#define IO_CAPABILITY_INVALID		0xFF

#define REMOVE_TEMP_TIMEOUT (3 * 60)
#define PENDING_FOUND_MAX 5

static const char *base_path = "/org/bluez";
static GSList *adapter_drivers = NULL;

enum session_req_type {
	SESSION_TYPE_MODE_GLOBAL = 0,
	SESSION_TYPE_MODE_SESSION,
	SESSION_TYPE_DISC_INTERLEAVED,
	SESSION_TYPE_DISC_LE_SCAN
};

struct session_req {
	struct btd_adapter	*adapter;
	enum session_req_type	type;
	DBusMessage		*msg;		/* Unreplied message ref */
	GDBusPendingPropertySet prop_id;	/* Pending Properties.Set() */
	char			*owner;		/* Bus name of the owner */
	guint			id;		/* Listener id */
	uint8_t			mode;		/* Requested mode */
	int			refcount;	/* Session refcount */
	gboolean		got_reply;	/* Agent reply received */
};

struct service_auth {
	guint id;
	service_auth_cb cb;
	void *user_data;
	const char *uuid;
	struct btd_device *device;
	struct btd_adapter *adapter;
	struct agent *agent;		/* NULL for queued auths */
};

struct discovery {
	guint id;
	GSList *found;
	GSList *pending;
};

struct btd_adapter {
	uint16_t dev_id;
	gboolean up;
	gboolean already_up;
	char *path;			/* adapter object path */
	bdaddr_t bdaddr;		/* adapter Bluetooth Address */
	uint32_t dev_class;		/* Class of Device */
	char *name;			/* adapter name */
	gboolean allow_name_changes;	/* whether the adapter name can be changed */
	uint32_t discov_timeout;	/* discoverable time(sec) */
	guint pairable_timeout_id;	/* pairable timeout id */
	uint32_t pairable_timeout;	/* pairable time(sec) */
	uint8_t scan_mode;		/* scan mode: SCAN_DISABLED, SCAN_PAGE,
					 * SCAN_INQUIRY */
	uint8_t mode;			/* off, connectable, discoverable,
					 * limited */
	uint8_t global_mode;		/* last valid global mode */
	struct session_req *pending_mode;
	struct agent *agent;		/* For the new API */
	guint auth_idle_id;		/* Pending authorization dequeue */
	GQueue *auths;			/* Ongoing and pending auths */
	GSList *connections;		/* Connected devices */
	GSList *devices;		/* Devices structure pointers */
	guint	remove_temp;		/* Remove devices timer */
	GSList *mode_sessions;		/* Request Mode sessions */
	GSList *disc_sessions;		/* Discovery sessions */
	struct session_req *scanning_session;
	GSList *connect_list;		/* Devices to connect when found */
	guint discov_id;		/* Discovery timer */
	struct discovery *discovery;	/* Discovery active */
	gboolean connecting;		/* Connect active */
	guint waiting_to_connect;	/* # of devices waiting to connect */
	gboolean discov_suspended;	/* Discovery suspended */
	guint auto_timeout_id;		/* Automatic connections timeout */
	sdp_list_t *services;		/* Services associated to adapter */

	gboolean discoverable;		/* discoverable state */
	gboolean pairable;		/* pairable state */
	gboolean initialized;

	gboolean off_requested;		/* DEVDOWN ioctl was called */

	gint ref;

	guint off_timer;

	GSList *powered_callbacks;
	GSList *pin_callbacks;

	GSList *drivers;
	GSList *profiles;

	struct oob_handler *oob_handler;
};

static gboolean process_auth_queue(gpointer user_data);

int btd_adapter_set_class(struct btd_adapter *adapter, uint8_t major,
							uint8_t minor)
{
	return mgmt_set_dev_class(adapter->dev_id, major, minor);
}

static const char *mode2str(uint8_t mode)
{
	switch(mode) {
	case MODE_OFF:
		return "off";
	case MODE_CONNECTABLE:
		return "connectable";
	case MODE_DISCOVERABLE:
		return "discoverable";
	default:
		return "unknown";
	}
}

static uint8_t get_mode(const char *mode)
{
	if (strcasecmp("off", mode) == 0)
		return MODE_OFF;
	else if (strcasecmp("connectable", mode) == 0)
		return MODE_CONNECTABLE;
	else if (strcasecmp("discoverable", mode) == 0)
		return MODE_DISCOVERABLE;
	else
		return MODE_UNKNOWN;
}

static void store_adapter_info(struct btd_adapter *adapter)
{
	GKeyFile *key_file;
	char filename[PATH_MAX + 1];
	char address[18];
	char *str;
	gsize length = 0;

	key_file = g_key_file_new();

	g_key_file_set_string(key_file, "General", "Name", adapter->name);

	g_key_file_set_boolean(key_file, "General", "Powered",
				adapter->mode > MODE_OFF);

	g_key_file_set_boolean(key_file, "General", "Pairable",
				adapter->pairable);

	if (adapter->pairable_timeout != main_opts.pairto)
		g_key_file_set_integer(key_file, "General", "PairableTimeout",
					adapter->pairable_timeout);

	g_key_file_set_boolean(key_file, "General", "Discoverable",
				adapter->discoverable);

	if (adapter->discov_timeout != main_opts.discovto)
		g_key_file_set_integer(key_file, "General",
					"DiscoverableTimeout",
					adapter->discov_timeout);

	ba2str(&adapter->bdaddr, address);
	snprintf(filename, PATH_MAX, STORAGEDIR "/%s/settings", address);
	filename[PATH_MAX] = '\0';

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	str = g_key_file_to_data(key_file, &length, NULL);
	g_file_set_contents(filename, str, length, NULL);
	g_free(str);

	g_key_file_free(key_file);
}

void adapter_store_cached_name(const bdaddr_t *local, const bdaddr_t *peer,
							const char *name)
{
	char filename[PATH_MAX + 1];
	char s_addr[18], d_addr[18];
	GKeyFile *key_file;
	char *data;
	gsize length = 0;

	ba2str(local, s_addr);
	ba2str(peer, d_addr);
	snprintf(filename, PATH_MAX, STORAGEDIR "/%s/cache/%s", s_addr, d_addr);
	filename[PATH_MAX] = '\0';
	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	key_file = g_key_file_new();
	g_key_file_load_from_file(key_file, filename, 0, NULL);
	g_key_file_set_string(key_file, "General", "Name", name);

	data = g_key_file_to_data(key_file, &length, NULL);
	g_file_set_contents(filename, data, length, NULL);
	g_free(data);

	g_key_file_free(key_file);
}

static struct session_req *session_ref(struct session_req *req)
{
	req->refcount++;

	DBG("%p: ref=%d", req, req->refcount);

	return req;
}

static struct session_req *create_session(struct btd_adapter *adapter,
					DBusMessage *msg, uint8_t mode,
					enum session_req_type type,
					GDBusWatchFunction cb)
{
	const char *sender;
	struct session_req *req;

	req = g_new0(struct session_req, 1);
	req->adapter = adapter;
	req->mode = mode;
	req->type = type;

	if (msg == NULL)
		return session_ref(req);

	req->msg = dbus_message_ref(msg);

	if (cb == NULL)
		return session_ref(req);

	sender = dbus_message_get_sender(msg);
	req->owner = g_strdup(sender);
	req->id = g_dbus_add_disconnect_watch(btd_get_dbus_connection(),
							sender, cb, req, NULL);

	info("%s session %p with %s activated",
		req->mode ? "Mode" : "Discovery", req, sender);

	return session_ref(req);
}

static int adapter_set_mode(struct btd_adapter *adapter, uint8_t mode)
{
	int err;

	if (mode == MODE_CONNECTABLE)
		err = mgmt_set_discoverable(adapter->dev_id, FALSE, 0);
	else
		err = mgmt_set_discoverable(adapter->dev_id, TRUE,
						adapter->discov_timeout);

	return err;
}

static struct session_req *find_session_by_msg(GSList *list, const DBusMessage *msg)
{
	for (; list; list = list->next) {
		struct session_req *req = list->data;

		if (req->msg == msg)
			return req;
	}

	return NULL;
}

static int set_mode(struct btd_adapter *adapter, uint8_t new_mode)
{
	int err;

	if (adapter->pending_mode != NULL)
		return -EALREADY;

	if (!adapter->up && new_mode != MODE_OFF) {
		err = mgmt_set_powered(adapter->dev_id, TRUE);
		if (err < 0)
			return err;

		goto done;
	}

	if (adapter->up && new_mode == MODE_OFF) {
		err = mgmt_set_powered(adapter->dev_id, FALSE);
		if (err < 0)
			return err;

		adapter->off_requested = TRUE;

		goto done;
	}

	if (new_mode == adapter->mode)
		return 0;

	err = adapter_set_mode(adapter, new_mode);

	if (err < 0)
		return err;

done:
	store_adapter_info(adapter);

	DBG("%s", mode2str(new_mode));

	return 0;
}

static void set_session_pending_mode(struct btd_adapter *adapter,
					uint8_t new_mode, DBusMessage *msg)
{
	struct session_req *req;

	/*
	 * Schedule the reply to be sent when a mode-change notification
	 * arrives. The reply will be sent by set_mode_complete().
	 */
	req = find_session_by_msg(adapter->mode_sessions, msg);
	if (req) {
		adapter->pending_mode = req;
		session_ref(req);
	} else
		adapter->pending_mode = create_session(adapter, msg, new_mode,
					SESSION_TYPE_MODE_SESSION, NULL);
}

static void set_discoverable(struct btd_adapter *adapter,
			gboolean discoverable, GDBusPendingPropertySet id)
{
	uint8_t mode;
	int err;

	mode = discoverable ? MODE_DISCOVERABLE : MODE_CONNECTABLE;

	if (mode == adapter->mode) {
		adapter->global_mode = mode;
		return g_dbus_pending_property_success(id);
	}

	err = set_mode(adapter, mode);
	if (err < 0)
		return g_dbus_pending_property_error(id,
						ERROR_INTERFACE ".Failed",
						strerror(-err));

	adapter->pending_mode = create_session(adapter, NULL, mode,
					SESSION_TYPE_MODE_GLOBAL, NULL);
	adapter->pending_mode->prop_id = id;
}

static void set_powered(struct btd_adapter *adapter, gboolean powered,
						GDBusPendingPropertySet id)
{
	uint8_t mode;
	int err;

	if (powered)
		return set_discoverable(adapter, adapter->discoverable, id);

	mode = MODE_OFF;

	if (mode == adapter->mode) {
		adapter->global_mode = mode;
		return g_dbus_pending_property_success(id);
	}

	err = set_mode(adapter, mode);
	if (err < 0)
		return g_dbus_pending_property_error(id,
						ERROR_INTERFACE ".Failed",
						strerror(-err));

	adapter->pending_mode = create_session(adapter, NULL, mode,
					SESSION_TYPE_MODE_GLOBAL, NULL);
	adapter->pending_mode->prop_id = id;
}

static void set_pairable(struct btd_adapter *adapter, gboolean pairable,
				bool reply, GDBusPendingPropertySet id)
{
	int err;

	if (adapter->scan_mode == SCAN_DISABLED)
		return g_dbus_pending_property_error(id,
						ERROR_INTERFACE ".NotReady",
						"Resource Not Ready");

	if (pairable == adapter->pairable)
		goto done;

	if (!(adapter->scan_mode & SCAN_INQUIRY))
		goto store;

	err = set_mode(adapter, MODE_DISCOVERABLE);
	if (err < 0) {
		if (reply)
			g_dbus_pending_property_error(id,
						ERROR_INTERFACE ".Failed",
						strerror(-err));
		return;
	}

store:
	mgmt_set_pairable(adapter->dev_id, pairable);

done:
	if (reply)
		g_dbus_pending_property_success(id);
}

static gboolean pairable_timeout_handler(void *data)
{
	set_pairable(data, FALSE, false, 0);

	return FALSE;
}

static void adapter_set_pairable_timeout(struct btd_adapter *adapter,
					guint interval)
{
	if (adapter->pairable_timeout_id) {
		g_source_remove(adapter->pairable_timeout_id);
		adapter->pairable_timeout_id = 0;
	}

	if (interval == 0)
		return;

	adapter->pairable_timeout_id = g_timeout_add_seconds(interval,
						pairable_timeout_handler,
						adapter);
}

void btd_adapter_pairable_changed(struct btd_adapter *adapter,
							gboolean pairable)
{
	adapter->pairable = pairable;

	store_adapter_info(adapter);

	g_dbus_emit_property_changed(btd_get_dbus_connection(), adapter->path,
					ADAPTER_INTERFACE, "Pairable");

	if (pairable && adapter->pairable_timeout)
		adapter_set_pairable_timeout(adapter,
						adapter->pairable_timeout);
}

static struct session_req *find_session(GSList *list, const char *sender)
{
	for (; list; list = list->next) {
		struct session_req *req = list->data;

		/* req->owner may be NULL if the session has been added by the
		 * daemon itself, so we use g_strcmp0 instead of g_str_equal */
		if (g_strcmp0(req->owner, sender) == 0)
			return req;
	}

	return NULL;
}

static uint8_t get_needed_mode(struct btd_adapter *adapter, uint8_t mode)
{
	GSList *l;

	if (adapter->global_mode > mode)
		mode = adapter->global_mode;

	for (l = adapter->mode_sessions; l; l = l->next) {
		struct session_req *req = l->data;

		if (req->mode > mode)
			mode = req->mode;
	}

	return mode;
}

static void send_devices_found(struct btd_adapter *adapter)
{
	struct discovery *discovery = adapter->discovery;
	DBusConnection *conn = btd_get_dbus_connection();
	DBusMessageIter iter, props;
	DBusMessage *signal;

	if (!discovery || !discovery->pending)
		return;

	signal = dbus_message_new_signal(adapter->path, ADAPTER_INTERFACE,
							"DevicesFound");
	if (!signal) {
		error("Unable to allocate DevicesFound signal");
		g_slist_free(discovery->pending);
		discovery->pending = NULL;
		return;
	}

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{oa{sv}}",
								&props);

	while (discovery->pending) {
		struct btd_device *dev = discovery->pending->data;
		const char *path = device_get_path(dev);
		DBusMessageIter entry;

		dbus_message_iter_open_container(&props, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
									&path);
		g_dbus_get_properties(conn, path, DEVICE_INTERFACE, &entry);
		dbus_message_iter_close_container(&props, &entry);

		discovery->pending = g_slist_remove(discovery->pending, dev);
	}

	dbus_message_iter_close_container(&iter, &props);

	g_dbus_send_message(conn, signal);
}

static void invalidate_rssi(gpointer a)
{
	struct btd_device *dev = a;

	device_set_rssi(dev, 0);
}

static void discovery_cleanup(struct btd_adapter *adapter)
{
	struct discovery *discovery = adapter->discovery;

	if (!discovery)
		return;

	if (discovery->id > 0)
		g_source_remove(discovery->id);

	send_devices_found(adapter);

	adapter->discovery = NULL;

	g_slist_free_full(discovery->found, invalidate_rssi);

	g_free(discovery);
}

/* Called when a session gets removed or the adapter is stopped */
static void stop_discovery(struct btd_adapter *adapter)
{
	/* Reset if suspended, otherwise remove timer (software scheduler)
	 * or request inquiry to stop */
	if (adapter->discov_suspended) {
		adapter->discov_suspended = FALSE;
		return;
	}

	if (adapter->discov_id > 0) {
		g_source_remove(adapter->discov_id);
		adapter->discov_id = 0;
		return;
	}

	if (adapter->up)
		mgmt_stop_discovery(adapter->dev_id);
	else
		discovery_cleanup(adapter);
}

static void session_remove(struct session_req *req)
{
	struct btd_adapter *adapter = req->adapter;

	/* Ignore global requests */
	if (req->type == SESSION_TYPE_MODE_GLOBAL)
		return;

	DBG("%s session %p with %s deactivated",
		req->mode ? "Mode" : "Discovery", req, req->owner);

	if (req->mode) {
		uint8_t mode;

		adapter->mode_sessions = g_slist_remove(adapter->mode_sessions,
							req);

		mode = get_needed_mode(adapter, adapter->global_mode);

		if (mode == adapter->mode)
			return;

		DBG("Switching to '%s' mode", mode2str(mode));

		set_mode(adapter, mode);
	} else {
		adapter->disc_sessions = g_slist_remove(adapter->disc_sessions,
							req);

		if (adapter->disc_sessions)
			return;

		DBG("Stopping discovery");

		stop_discovery(adapter);
	}
}

static void session_free(void *data)
{
	struct session_req *req = data;

	if (req->id)
		g_dbus_remove_watch(btd_get_dbus_connection(), req->id);

	if (req->msg) {
		dbus_message_unref(req->msg);
		if (!req->got_reply && req->mode && req->adapter->agent)
			agent_cancel(req->adapter->agent);
	}

	g_free(req->owner);
	g_free(req);
}

static void session_owner_exit(DBusConnection *conn, void *user_data)
{
	struct session_req *req = user_data;

	req->id = 0;

	session_remove(req);
	session_free(req);
}

static void session_unref(struct session_req *req)
{
	req->refcount--;

	DBG("%p: ref=%d", req, req->refcount);

	if (req->refcount)
		return;

	session_remove(req);
	session_free(req);
}

static void confirm_mode_cb(struct agent *agent, DBusError *derr, void *data)
{
	DBusConnection *conn = btd_get_dbus_connection();
	struct session_req *req = data;
	int err;
	DBusMessage *reply;

	req->got_reply = TRUE;

	if (derr && dbus_error_is_set(derr)) {
		reply = dbus_message_new_error(req->msg, derr->name,
						derr->message);
		g_dbus_send_message(conn, reply);
		session_unref(req);
		return;
	}

	err = set_mode(req->adapter, req->mode);
	if (err >= 0 && req->adapter->mode != req->mode) {
		set_session_pending_mode(req->adapter, req->mode, req->msg);
		goto done;
	}

	if (err < 0)
		reply = btd_error_failed(req->msg, strerror(-err));
	else
		reply = dbus_message_new_method_return(req->msg);

	/*
	 * Send reply immediately only if there was an error changing mode, or
	 * change is not needed. Otherwise, reply is sent in
	 * set_mode_complete.
	 */
	g_dbus_send_message(conn, reply);

done:
	session_unref(req);
}

static void set_discoverable_timeout(struct btd_adapter *adapter,
				uint32_t timeout, GDBusPendingPropertySet id)
{
	DBusConnection *conn = btd_get_dbus_connection();

	if (adapter->discov_timeout == timeout && timeout == 0)
		return g_dbus_pending_property_success(id);

	if (adapter->scan_mode & SCAN_INQUIRY)
		mgmt_set_discoverable(adapter->dev_id, TRUE, timeout);

	adapter->discov_timeout = timeout;

	store_adapter_info(adapter);

	g_dbus_emit_property_changed(conn, adapter->path, ADAPTER_INTERFACE,
						"DiscoverableTimeout");
	g_dbus_pending_property_success(id);
}

static void set_pairable_timeout(struct btd_adapter *adapter,
				uint32_t timeout, GDBusPendingPropertySet id)
{
	DBusConnection *conn = btd_get_dbus_connection();

	if (adapter->pairable_timeout == timeout && timeout == 0)
		return g_dbus_pending_property_success(id);

	if (adapter->pairable)
		adapter_set_pairable_timeout(adapter, timeout);

	adapter->pairable_timeout = timeout;

	store_adapter_info(adapter);

	g_dbus_emit_property_changed(conn, adapter->path, ADAPTER_INTERFACE,
							"PairableTimeout");
	g_dbus_pending_property_success(id);
}

void btd_adapter_class_changed(struct btd_adapter *adapter, uint8_t *new_class)
{
	uint32_t class;
	uint8_t cls[3];

	class = new_class[0] | (new_class[1] << 8) | (new_class[2] << 16);

	if (class == adapter->dev_class)
		return;

	adapter->dev_class = class;

	memcpy(cls, new_class, sizeof(cls));

	/* Removes service class */
	cls[1] = cls[1] & 0x1f;
	attrib_gap_set(adapter, GATT_CHARAC_APPEARANCE, cls, 2);

	g_dbus_emit_property_changed(btd_get_dbus_connection(), adapter->path,
						ADAPTER_INTERFACE, "Class");
}

void adapter_name_changed(struct btd_adapter *adapter, const char *name)
{
	if (g_strcmp0(adapter->name, name) == 0)
		return;

	g_free(adapter->name);
	adapter->name = g_strdup(name);

	g_dbus_emit_property_changed(btd_get_dbus_connection(), adapter->path,
						ADAPTER_INTERFACE, "Name");

	attrib_gap_set(adapter, GATT_CHARAC_DEVICE_NAME,
				(const uint8_t *) name, strlen(name));
}

int adapter_set_name(struct btd_adapter *adapter, const char *name)
{
	char maxname[MAX_NAME_LENGTH + 1];

	if (g_strcmp0(adapter->name, name) == 0)
		return 0;

	memset(maxname, 0, sizeof(maxname));
	strncpy(maxname, name, MAX_NAME_LENGTH);
	if (!g_utf8_validate(maxname, -1, NULL)) {
		error("Name change failed: supplied name isn't valid UTF-8");
		return -EINVAL;
	}

	if (adapter->up) {
		int err = mgmt_set_name(adapter->dev_id, maxname);
		if (err < 0)
			return err;
	} else {
		g_free(adapter->name);
		adapter->name = g_strdup(maxname);
	}

	store_adapter_info(adapter);

	return 0;
}

static void set_name(struct btd_adapter *adapter, const char *name,
						GDBusPendingPropertySet id)
{
	int ret;

	if (adapter->allow_name_changes == FALSE)
		return g_dbus_pending_property_error(id,
						ERROR_INTERFACE ".Failed",
						strerror(EPERM));

	ret = adapter_set_name(adapter, name);
	if (ret >= 0)
		return g_dbus_pending_property_success(id);

	if (ret == -EINVAL)
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
	else
		g_dbus_pending_property_error(id, ERROR_INTERFACE ".Failed",
							strerror(-ret));
}

struct btd_device *adapter_find_device(struct btd_adapter *adapter,
							const char *dest)
{
	struct btd_device *device;
	GSList *l;

	if (!adapter)
		return NULL;

	l = g_slist_find_custom(adapter->devices, dest,
					(GCompareFunc) device_address_cmp);
	if (!l)
		return NULL;

	device = l->data;

	return device;
}

static uint8_t get_uuid_mask(uuid_t *uuid)
{
	if (uuid->type != SDP_UUID16)
		return 0;

	switch (uuid->value.uuid16) {
	case DIALUP_NET_SVCLASS_ID:
	case CIP_SVCLASS_ID:
		return 0x42;	/* Telephony & Networking */
	case IRMC_SYNC_SVCLASS_ID:
	case OBEX_OBJPUSH_SVCLASS_ID:
	case OBEX_FILETRANS_SVCLASS_ID:
	case IRMC_SYNC_CMD_SVCLASS_ID:
	case PBAP_PSE_SVCLASS_ID:
		return 0x10;	/* Object Transfer */
	case HEADSET_SVCLASS_ID:
	case HANDSFREE_SVCLASS_ID:
		return 0x20;	/* Audio */
	case CORDLESS_TELEPHONY_SVCLASS_ID:
	case INTERCOM_SVCLASS_ID:
	case FAX_SVCLASS_ID:
	case SAP_SVCLASS_ID:
	/*
	 * Setting the telephony bit for the handsfree audio gateway
	 * role is not required by the HFP specification, but the
	 * Nokia 616 carkit is just plain broken! It will refuse
	 * pairing without this bit set.
	 */
	case HANDSFREE_AGW_SVCLASS_ID:
		return 0x40;	/* Telephony */
	case AUDIO_SOURCE_SVCLASS_ID:
	case VIDEO_SOURCE_SVCLASS_ID:
		return 0x08;	/* Capturing */
	case AUDIO_SINK_SVCLASS_ID:
	case VIDEO_SINK_SVCLASS_ID:
		return 0x04;	/* Rendering */
	case PANU_SVCLASS_ID:
	case NAP_SVCLASS_ID:
	case GN_SVCLASS_ID:
		return 0x02;	/* Networking */
	default:
		return 0;
	}
}

static int uuid_cmp(const void *a, const void *b)
{
	const sdp_record_t *rec = a;
	const uuid_t *uuid = b;

	return sdp_uuid_cmp(&rec->svclass, uuid);
}

void adapter_service_insert(struct btd_adapter *adapter, void *r)
{
	sdp_record_t *rec = r;
	gboolean new_uuid;

	if (sdp_list_find(adapter->services, &rec->svclass, uuid_cmp) == NULL)
		new_uuid = TRUE;
	else
		new_uuid = FALSE;

	adapter->services = sdp_list_insert_sorted(adapter->services, rec,
								record_sort);

	if (new_uuid) {
		uint8_t svc_hint = get_uuid_mask(&rec->svclass);
		mgmt_add_uuid(adapter->dev_id, &rec->svclass, svc_hint);
	}

	if (adapter->initialized)
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
				adapter->path, ADAPTER_INTERFACE, "UUIDs");
}

void adapter_service_remove(struct btd_adapter *adapter, void *r)
{
	sdp_record_t *rec = r;

	adapter->services = sdp_list_remove(adapter->services, rec);

	if (sdp_list_find(adapter->services, &rec->svclass, uuid_cmp) == NULL)
		mgmt_remove_uuid(adapter->dev_id, &rec->svclass);

	if (adapter->initialized)
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
				adapter->path, ADAPTER_INTERFACE, "UUIDs");
}

static struct btd_device *adapter_create_device(struct btd_adapter *adapter,
						const char *address,
						uint8_t bdaddr_type)
{
	struct btd_device *device;

	DBG("%s", address);

	device = device_create(adapter, address, bdaddr_type);
	if (!device)
		return NULL;

	device_set_temporary(device, TRUE);

	adapter->devices = g_slist_append(adapter->devices, device);

	return device;
}

static void service_auth_cancel(struct service_auth *auth)
{
	DBusError derr;

	dbus_error_init(&derr);
	dbus_set_error_const(&derr, "org.bluez.Error.Canceled", NULL);

	auth->cb(&derr, auth->user_data);

	dbus_error_free(&derr);

	if (auth->agent != NULL)
		agent_cancel(auth->agent);

	g_free(auth);
}

void adapter_remove_device(struct btd_adapter *adapter,
						struct btd_device *dev,
						gboolean remove_storage)
{
	struct discovery *discovery = adapter->discovery;
	GList *l;

	adapter->devices = g_slist_remove(adapter->devices, dev);

	if (discovery) {
		discovery->found = g_slist_remove(discovery->found, dev);
		discovery->pending = g_slist_remove(discovery->pending, dev);
	}

	adapter->connections = g_slist_remove(adapter->connections, dev);

	l = adapter->auths->head;
	while (l != NULL) {
		struct service_auth *auth = l->data;
		GList *next = g_list_next(l);

		if (auth->device != dev) {
			l = next;
			continue;
		}

		g_queue_delete_link(adapter->auths, l);
		l = next;

		service_auth_cancel(auth);
	}

	device_remove(dev, remove_storage);
}

struct btd_device *adapter_get_device(struct btd_adapter *adapter,
							const gchar *address)
{
	struct btd_device *device;

	DBG("%s", address);

	if (!adapter)
		return NULL;

	device = adapter_find_device(adapter, address);
	if (device)
		return device;

	return adapter_create_device(adapter, address, BDADDR_BREDR);
}

sdp_list_t *btd_adapter_get_services(struct btd_adapter *adapter)
{
	return adapter->services;
}

static gboolean discovery_cb(gpointer user_data)
{
	struct btd_adapter *adapter = user_data;

	adapter->discov_id = 0;

	if (adapter->scanning_session &&
				g_slist_length(adapter->disc_sessions) == 1)
		mgmt_start_le_scanning(adapter->dev_id);
	else
		mgmt_start_discovery(adapter->dev_id);

	return FALSE;
}

static DBusMessage *adapter_start_discovery(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct session_req *req;
	struct btd_adapter *adapter = data;
	const char *sender = dbus_message_get_sender(msg);
	int err;

	if (!adapter->up)
		return btd_error_not_ready(msg);

	req = find_session(adapter->disc_sessions, sender);
	if (req) {
		session_ref(req);
		return dbus_message_new_method_return(msg);
	}

	if (adapter->disc_sessions)
		goto done;

	if (adapter->discov_suspended)
		goto done;

	err = mgmt_start_discovery(adapter->dev_id);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

done:
	req = create_session(adapter, msg, 0, SESSION_TYPE_DISC_INTERLEAVED,
							session_owner_exit);

	adapter->disc_sessions = g_slist_append(adapter->disc_sessions, req);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *adapter_stop_discovery(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	struct session_req *req;
	const char *sender = dbus_message_get_sender(msg);

	if (!adapter->up)
		return btd_error_not_ready(msg);

	req = find_session(adapter->disc_sessions, sender);
	if (!req)
		return btd_error_failed(msg, "Invalid discovery session");

	session_unref(req);
	info("Stopping discovery");
	return dbus_message_new_method_return(msg);
}

static gboolean adapter_property_get_address(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_adapter *adapter = data;
	char srcaddr[18];
	const char *ptr;

	ba2str(&adapter->bdaddr, srcaddr);
	ptr = srcaddr;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &ptr);

	return TRUE;
}

static gboolean adapter_property_get_name(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_adapter *adapter = data;
	const char *ptr;

	ptr = adapter->name ?: "";

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &ptr);

	return TRUE;
}

static void adapter_property_set_name(const GDBusPropertyTable *property,
					DBusMessageIter *value,
					GDBusPendingPropertySet id, void *data)
{
	const char *name;

	if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_STRING)
		return g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");

	dbus_message_iter_get_basic(value, &name);

	set_name(data, name, id);
}

static gboolean adapter_property_get_class(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_adapter *adapter = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32,
							&adapter->dev_class);

	return TRUE;
}

static gboolean adapter_property_get_powered(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_adapter *adapter = data;
	dbus_bool_t value;

	value = (adapter->up && !adapter->off_requested) ? TRUE : FALSE;
	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &value);

	return TRUE;
}

static void adapter_property_set_powered(
				const GDBusPropertyTable *property,
				DBusMessageIter *value,
				GDBusPendingPropertySet id, void *data)
{
	dbus_bool_t powered;

	if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_BOOLEAN)
		return g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");

	dbus_message_iter_get_basic(value, &powered);

	set_powered(data, powered, id);
}

static gboolean adapter_property_get_discoverable(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_adapter *adapter = data;
	dbus_bool_t value;

	value = adapter->scan_mode & SCAN_INQUIRY ? TRUE : FALSE;
	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &value);

	return TRUE;
}

static void adapter_property_set_discoverable(
				const GDBusPropertyTable *property,
				DBusMessageIter *value,
				GDBusPendingPropertySet id, void *data)
{
	dbus_bool_t discoverable;

	if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_BOOLEAN)
		return g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");

	dbus_message_iter_get_basic(value, &discoverable);

	set_discoverable(data, discoverable, id);
}

static gboolean adapter_property_get_pairable(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_adapter *adapter = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN,
							&adapter->pairable);
	return TRUE;
}

static void adapter_property_set_pairable(const GDBusPropertyTable *property,
		DBusMessageIter *value,
		GDBusPendingPropertySet id, void *data)
{
	dbus_bool_t pairable;

	if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_BOOLEAN)
		return g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");

	dbus_message_iter_get_basic(value, &pairable);

	set_pairable(data, pairable, true, id);
}

static gboolean adapter_property_get_discoverable_timeout(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_adapter *adapter = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32,
						&adapter->discov_timeout);

	return TRUE;
}


static void adapter_property_set_discoverable_timeout(
		const GDBusPropertyTable *property, DBusMessageIter *value,
		GDBusPendingPropertySet id, void *data)
{
	uint32_t timeout;

	if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_UINT32)
		return g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");

	dbus_message_iter_get_basic(value, &timeout);
	set_discoverable_timeout(data, timeout, id);
}

static gboolean adapter_property_get_pairable_timeout(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_adapter *adapter = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32,
						&adapter->pairable_timeout);

	return TRUE;
}

static void adapter_property_set_pairable_timeout(
		const GDBusPropertyTable *property, DBusMessageIter *value,
		GDBusPendingPropertySet id, void *data)
{
	uint32_t timeout;

	if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_UINT32)
		return g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");

	dbus_message_iter_get_basic(value, &timeout);
	set_pairable_timeout(data, timeout, id);
}

static gboolean adapter_property_get_discovering(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_adapter *adapter = data;
	dbus_bool_t discovering = adapter->discovery ? TRUE : FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &discovering);

	return TRUE;
}

static gboolean adapter_property_get_uuids(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_adapter *adapter = data;
	DBusMessageIter entry;
	sdp_list_t *l;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &entry);

	for (l = adapter->services; l != NULL; l = l->next) {
		sdp_record_t *rec = l->data;
		char *uuid;

		uuid = bt_uuid2string(&rec->svclass);
		if (uuid == NULL)
			continue;

		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
								&uuid);
		g_free(uuid);
	}

	dbus_message_iter_close_container(iter, &entry);

	return TRUE;
}

static DBusMessage *request_session(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	struct session_req *req;
	const char *sender = dbus_message_get_sender(msg);
	uint8_t new_mode;
	int err;

	if (!adapter->agent)
		return btd_error_agent_not_available(msg);

	if (!adapter->mode_sessions)
		adapter->global_mode = adapter->mode;

	if (adapter->discoverable)
		new_mode = MODE_DISCOVERABLE;
	else
		new_mode = MODE_CONNECTABLE;

	req = find_session(adapter->mode_sessions, sender);
	if (req) {
		session_ref(req);
		return dbus_message_new_method_return(msg);
	} else {
		req = create_session(adapter, msg, new_mode,
				SESSION_TYPE_MODE_SESSION, session_owner_exit);
		adapter->mode_sessions = g_slist_append(adapter->mode_sessions,
							req);
	}

	/* No need to change mode */
	if (adapter->mode >= new_mode)
		return dbus_message_new_method_return(msg);

	err = agent_confirm_mode_change(adapter->agent, mode2str(new_mode),
					confirm_mode_cb, req, NULL);
	if (err < 0) {
		session_unref(req);
		return btd_error_failed(msg, strerror(-err));
	}

	return NULL;
}

static DBusMessage *release_session(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	struct session_req *req;
	const char *sender = dbus_message_get_sender(msg);

	req = find_session(adapter->mode_sessions, sender);
	if (!req)
		return btd_error_failed(msg, "Invalid Session");

	session_unref(req);

	return dbus_message_new_method_return(msg);
}

static uint8_t parse_io_capability(const char *capability)
{
	if (g_str_equal(capability, ""))
		return IO_CAPABILITY_DISPLAYYESNO;
	if (g_str_equal(capability, "DisplayOnly"))
		return IO_CAPABILITY_DISPLAYONLY;
	if (g_str_equal(capability, "DisplayYesNo"))
		return IO_CAPABILITY_DISPLAYYESNO;
	if (g_str_equal(capability, "KeyboardOnly"))
		return IO_CAPABILITY_KEYBOARDONLY;
	if (g_str_equal(capability, "NoInputNoOutput"))
		return IO_CAPABILITY_NOINPUTNOOUTPUT;
	if (g_str_equal(capability, "KeyboardDisplay"))
		return IO_CAPABILITY_KEYBOARDDISPLAY;
	return IO_CAPABILITY_INVALID;
}

static gint device_path_cmp(struct btd_device *device, const gchar *path)
{
	const gchar *dev_path = device_get_path(device);

	return strcasecmp(dev_path, path);
}

static DBusMessage *remove_device(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct btd_adapter *adapter = data;
	struct btd_device *device;
	const char *path;
	GSList *l;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE)
		return btd_error_invalid_args(msg);

	l = g_slist_find_custom(adapter->devices,
			path, (GCompareFunc) device_path_cmp);
	if (!l)
		return btd_error_does_not_exist(msg);

	device = l->data;

	device_set_temporary(device, TRUE);

	if (!device_is_connected(device)) {
		adapter_remove_device(adapter, device, TRUE);
		return dbus_message_new_method_return(msg);
	}

	device_request_disconnect(device, msg);
	return NULL;
}

static void agent_removed(struct agent *agent, struct btd_adapter *adapter)
{
	mgmt_set_io_capability(adapter->dev_id, IO_CAPABILITY_NOINPUTNOOUTPUT);

	adapter->agent = NULL;
}

static DBusMessage *register_agent(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	const char *path, *name, *capability;
	struct btd_adapter *adapter = data;
	uint8_t cap;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_STRING, &capability, DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	if (adapter->agent)
		return btd_error_already_exists(msg);

	cap = parse_io_capability(capability);
	if (cap == IO_CAPABILITY_INVALID)
		return btd_error_invalid_args(msg);

	name = dbus_message_get_sender(msg);

	adapter->agent = agent_create(adapter, name, path, cap,
				(agent_remove_cb) agent_removed, adapter);

	DBG("Agent registered for hci%d at %s:%s", adapter->dev_id, name,
			path);

	mgmt_set_io_capability(adapter->dev_id, cap);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_agent(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	const char *path, *name;
	struct btd_adapter *adapter = data;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	name = dbus_message_get_sender(msg);

	if (!adapter->agent || !agent_matches(adapter->agent, name, path))
		return btd_error_does_not_exist(msg);

	agent_free(adapter->agent);
	adapter->agent = NULL;

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable adapter_methods[] = {
	{ GDBUS_ASYNC_METHOD("RequestSession", NULL, NULL,
			request_session) },
	{ GDBUS_METHOD("ReleaseSession", NULL, NULL,
			release_session) },
	{ GDBUS_METHOD("StartDiscovery", NULL, NULL,
			adapter_start_discovery) },
	{ GDBUS_ASYNC_METHOD("StopDiscovery", NULL, NULL,
			adapter_stop_discovery) },
	{ GDBUS_ASYNC_METHOD("RemoveDevice",
			GDBUS_ARGS({ "device", "o" }), NULL,
			remove_device) },
	{ GDBUS_METHOD("RegisterAgent",
			GDBUS_ARGS({ "agent", "o" },
					{ "capability", "s" }), NULL,
			register_agent) },
	{ GDBUS_METHOD("UnregisterAgent",
			GDBUS_ARGS({ "agent", "o" }), NULL,
			unregister_agent) },
	{ }
};

static const GDBusSignalTable adapter_signals[] = {
	{ GDBUS_SIGNAL("DevicesFound",
			GDBUS_ARGS({ "devices", "a{oa{sv}}" })) },
	{ }
};

static const GDBusPropertyTable adapter_properties[] = {
	{ "Address", "s", adapter_property_get_address },
	{ "Name", "s", adapter_property_get_name, adapter_property_set_name },
	{ "Class", "u", adapter_property_get_class },
	{ "Powered", "b", adapter_property_get_powered,
					adapter_property_set_powered },
	{ "Discoverable", "b", adapter_property_get_discoverable,
					adapter_property_set_discoverable },
	{ "Pairable", "b", adapter_property_get_pairable,
					adapter_property_set_pairable },
	{ "DiscoverableTimeout", "u",
			adapter_property_get_discoverable_timeout,
			adapter_property_set_discoverable_timeout },
	{ "PairableTimeout", "u", adapter_property_get_pairable_timeout,
				adapter_property_set_pairable_timeout },
	{ "Discovering", "b", adapter_property_get_discovering },
	{ "UUIDs", "as", adapter_property_get_uuids },
	{ }
};

static void create_stored_device_from_profiles(char *key, char *value,
						void *user_data)
{
	char address[18];
	uint8_t bdaddr_type;
	struct btd_adapter *adapter = user_data;
	GSList *list, *uuids = bt_string2list(value);
	struct btd_device *device;

	if (sscanf(key, "%17s#%hhu", address, &bdaddr_type) < 2)
		bdaddr_type = BDADDR_BREDR;

	if (g_slist_find_custom(adapter->devices,
				address, (GCompareFunc) device_address_cmp))
		return;

	device = device_create(adapter, address, bdaddr_type);
	if (!device)
		return;

	device_set_temporary(device, FALSE);
	adapter->devices = g_slist_append(adapter->devices, device);

	list = device_services_from_record(device, uuids);
	if (list)
		device_register_services(device, list, ATT_PSM);

	device_probe_profiles(device, uuids);

	g_slist_free_full(uuids, g_free);
}

struct adapter_keys {
	struct btd_adapter *adapter;
	GSList *keys;
};

static int str2buf(const char *str, uint8_t *buf, size_t blen)
{
	int i, dlen;

	if (str == NULL)
		return -EINVAL;

	memset(buf, 0, blen);

	dlen = MIN((strlen(str) / 2), blen);

	for (i = 0; i < dlen; i++)
		sscanf(str + (i * 2), "%02hhX", &buf[i]);

	return 0;
}

static struct link_key_info *get_key_info(GKeyFile *key_file, const char *peer)
{
	struct link_key_info *info = NULL;
	char *str;

	str = g_key_file_get_string(key_file, "LinkKey", "Key", NULL);
	if (!str || strlen(str) != 34)
		goto failed;

	info = g_new0(struct link_key_info, 1);

	str2ba(peer, &info->bdaddr);
	str2buf(&str[2], info->key, sizeof(info->key));

	info->type = g_key_file_get_integer(key_file, "LinkKey", "Type", NULL);
	info->pin_len = g_key_file_get_integer(key_file, "LinkKey", "PINLength",
						NULL);

failed:
	g_free(str);

	return info;
}

static struct smp_ltk_info *get_ltk_info(GKeyFile *key_file, const char *peer)
{
	struct smp_ltk_info *ltk = NULL;
	char *key;
	char *rand = NULL;
	char *type = NULL;
	uint8_t bdaddr_type;

	key = g_key_file_get_string(key_file, "LongTermKey", "Key", NULL);
	if (!key || strlen(key) != 34)
		goto failed;

	rand = g_key_file_get_string(key_file, "LongTermKey", "Rand", NULL);
	if (!rand || strlen(rand) != 18)
		goto failed;

	type = g_key_file_get_string(key_file, "General", "AddressType", NULL);
	if (!type)
		goto failed;

	if (g_str_equal(type, "public"))
		bdaddr_type = BDADDR_LE_PUBLIC;
	else if (g_str_equal(type, "static"))
		bdaddr_type = BDADDR_LE_RANDOM;
	else
		goto failed;

	ltk = g_new0(struct smp_ltk_info, 1);

	str2ba(peer, &ltk->bdaddr);
	ltk->bdaddr_type = bdaddr_type;
	str2buf(&key[2], ltk->val, sizeof(ltk->val));
	str2buf(&rand[2], ltk->rand, sizeof(ltk->rand));

	ltk->authenticated = g_key_file_get_integer(key_file, "LongTermKey",
							"Authenticated", NULL);
	ltk->master = g_key_file_get_integer(key_file, "LongTermKey", "Master",
						NULL);
	ltk->enc_size = g_key_file_get_integer(key_file, "LongTermKey",
						"EncSize", NULL);
	ltk->ediv = g_key_file_get_integer(key_file, "LongTermKey", "EDiv",
						NULL);

failed:
	g_free(key);
	g_free(rand);
	g_free(type);

	return ltk;
}

static GSList *string_to_primary_list(char *str)
{
	GSList *l = NULL;
	char **services;
	int i;

	if (str == NULL)
		return NULL;

	services = g_strsplit(str, " ", 0);
	if (services == NULL)
		return NULL;

	for (i = 0; services[i]; i++) {
		struct gatt_primary *prim;
		int ret;

		prim = g_new0(struct gatt_primary, 1);

		ret = sscanf(services[i], "%04hX#%04hX#%s", &prim->range.start,
							&prim->range.end, prim->uuid);

		if (ret < 3) {
			g_free(prim);
			continue;
		}

		l = g_slist_append(l, prim);
	}

	g_strfreev(services);

	return l;
}

static void create_stored_device_from_primaries(char *key, char *value,
							void *user_data)
{
	struct btd_adapter *adapter = user_data;
	struct btd_device *device;
	GSList *services, *uuids, *l;
	char address[18];
	uint8_t bdaddr_type;

	if (sscanf(key, "%17s#%hhu", address, &bdaddr_type) < 2)
		return;

	if (g_slist_find_custom(adapter->devices,
			address, (GCompareFunc) device_address_cmp))
		return;

	device = device_create(adapter, address, bdaddr_type);
	if (!device)
		return;

	device_set_temporary(device, FALSE);
	adapter->devices = g_slist_append(adapter->devices, device);

	services = string_to_primary_list(value);
	if (services == NULL)
		return;

	for (l = services, uuids = NULL; l; l = l->next) {
		struct gatt_primary *prim = l->data;
		uuids = g_slist_append(uuids, prim->uuid);
	}

	device_register_services(device, services, -1);

	device_probe_profiles(device, uuids);

	g_slist_free(uuids);
}

static void load_devices(struct btd_adapter *adapter)
{
	char filename[PATH_MAX + 1];
	char srcaddr[18];
	struct adapter_keys keys = { adapter, NULL };
	struct adapter_keys ltks = { adapter, NULL };
	int err;
	DIR *dir;
	struct dirent *entry;

	ba2str(&adapter->bdaddr, srcaddr);

	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr, "profiles");
	textfile_foreach(filename, create_stored_device_from_profiles,
								adapter);

	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr, "primaries");
	textfile_foreach(filename, create_stored_device_from_primaries,
								adapter);

	snprintf(filename, PATH_MAX, STORAGEDIR "/%s", srcaddr);
	filename[PATH_MAX] = '\0';

	dir = opendir(filename);
	if (!dir) {
		error("Unable to open adapter storage directory: %s", filename);
		return;
	}

	while ((entry = readdir(dir)) != NULL) {
		struct btd_device *device;
		char filename[PATH_MAX + 1];
		GKeyFile *key_file;
		struct link_key_info *key_info;
		struct smp_ltk_info *ltk_info;
		GSList *l;

		if (entry->d_type != DT_DIR || bachk(entry->d_name) < 0)
			continue;

		snprintf(filename, PATH_MAX, STORAGEDIR "/%s/%s/info", srcaddr,
				entry->d_name);

		key_file = g_key_file_new();
		g_key_file_load_from_file(key_file, filename, 0, NULL);

		key_info = get_key_info(key_file, entry->d_name);
		if (key_info)
			keys.keys = g_slist_append(keys.keys, key_info);

		ltk_info = get_ltk_info(key_file, entry->d_name);
		if (ltk_info)
			ltks.keys = g_slist_append(ltks.keys, ltk_info);

		g_key_file_free(key_file);

		l = g_slist_find_custom(adapter->devices, entry->d_name,
					(GCompareFunc) device_address_cmp);
		if (l) {
			device = l->data;
			goto device_exist;
		}

		device = device_create(adapter, entry->d_name, BDADDR_BREDR);
		if (!device)
			continue;

		device_set_temporary(device, FALSE);
		adapter->devices = g_slist_append(adapter->devices, device);

device_exist:
		if (key_info || ltk_info) {
			device_set_paired(device, TRUE);
			device_set_bonded(device, TRUE);
		}
	}

	closedir(dir);

	err = mgmt_load_link_keys(adapter->dev_id, keys.keys,
							main_opts.debug_keys);
	if (err < 0)
		error("Unable to load link keys: %s (%d)",
							strerror(-err), -err);

	g_slist_free_full(keys.keys, g_free);

	err = mgmt_load_ltks(adapter->dev_id, ltks.keys);
	if (err < 0)
		error("Unable to load ltks: %s (%d)", strerror(-err), -err);

	g_slist_free_full(ltks.keys, g_free);
}

int btd_adapter_block_address(struct btd_adapter *adapter,
				const bdaddr_t *bdaddr, uint8_t bdaddr_type)
{
	return mgmt_block_device(adapter->dev_id, bdaddr, bdaddr_type);
}

int btd_adapter_unblock_address(struct btd_adapter *adapter,
				const bdaddr_t *bdaddr, uint8_t bdaddr_type)
{
	return mgmt_unblock_device(adapter->dev_id, bdaddr,
								bdaddr_type);
}

static void clear_blocked(struct btd_adapter *adapter)
{
	int err;

	err = mgmt_unblock_device(adapter->dev_id, BDADDR_ANY, 0);
	if (err < 0)
		error("Clearing blocked list failed: %s (%d)",
						strerror(-err), -err);
}

static void probe_driver(struct btd_adapter *adapter, gpointer user_data)
{
	struct btd_adapter_driver *driver = user_data;
	int err;

	if (driver->probe == NULL)
		return;

	err = driver->probe(adapter);
	if (err < 0) {
		error("%s: %s (%d)", driver->name, strerror(-err), -err);
		return;
	}

	adapter->drivers = g_slist_prepend(adapter->drivers, driver);
}

static void load_drivers(struct btd_adapter *adapter)
{
	GSList *l;

	for (l = adapter_drivers; l; l = l->next)
		probe_driver(adapter, l->data);
}

static void probe_profile(struct btd_profile *profile, void *data)
{
	struct btd_adapter *adapter = data;
	int err;

	if (profile->adapter_probe == NULL)
		return;

	err = profile->adapter_probe(profile, adapter);
	if (err < 0) {
		error("%s: %s (%d)", profile->name, strerror(-err), -err);
		return;
	}

	adapter->profiles = g_slist_prepend(adapter->profiles, profile);
}

void adapter_add_profile(struct btd_adapter *adapter, gpointer p)
{
	struct btd_profile *profile = p;

	if (!adapter->initialized)
		return;

	probe_profile(profile, adapter);

	g_slist_foreach(adapter->devices, device_probe_profile, profile);
}

void adapter_remove_profile(struct btd_adapter *adapter, gpointer p)
{
	struct btd_profile *profile = p;

	if (!adapter->initialized)
		return;

	if (profile->device_remove)
		g_slist_foreach(adapter->devices, device_remove_profile, p);

	adapter->profiles = g_slist_remove(adapter->profiles, profile);

	if (profile->adapter_remove)
		profile->adapter_remove(profile, adapter);
}

static void load_connections(struct btd_adapter *adapter)
{
	GSList *l, *conns;
	int err;

	err = mgmt_get_conn_list(adapter->dev_id, &conns);
	if (err < 0) {
		error("Unable to fetch existing connections: %s (%d)",
							strerror(-err), -err);
		return;
	}

	for (l = conns; l != NULL; l = g_slist_next(l)) {
		bdaddr_t *bdaddr = l->data;
		struct btd_device *device;
		char address[18];

		ba2str(bdaddr, address);
		DBG("Adding existing connection to %s", address);

		device = adapter_get_device(adapter, address);
		if (device)
			adapter_add_connection(adapter, device);
	}

	g_slist_free_full(conns, g_free);
}

static void set_auto_connect(gpointer data, gpointer user_data)
{
	struct btd_device *device = data;
	gboolean *enable = user_data;

	device_set_auto_connect(device, *enable);
}

static void call_adapter_powered_callbacks(struct btd_adapter *adapter,
						gboolean powered)
{
	GSList *l;

	for (l = adapter->powered_callbacks; l; l = l->next) {
		btd_adapter_powered_cb cb = l->data;

		cb(adapter, powered);
	}

	g_slist_foreach(adapter->devices, set_auto_connect, &powered);
}

void btd_adapter_get_mode(struct btd_adapter *adapter, uint8_t *mode,
						uint16_t *discoverable_timeout,
						gboolean *pairable)
{
	if (mode)
		*mode = adapter->mode;

	if (discoverable_timeout)
		*discoverable_timeout = adapter->discov_timeout;

	if (pairable)
		*pairable = adapter->pairable;
}

void btd_adapter_get_major_minor(struct btd_adapter *adapter, uint8_t *major,
								uint8_t *minor)
{
	*major = (adapter->dev_class >> 8) & 0xFF;
	*minor = adapter->dev_class & 0xFF;
}

uint32_t btd_adapter_get_class(struct btd_adapter *adapter)
{
	return adapter->dev_class;
}

const char *btd_adapter_get_name(struct btd_adapter *adapter)
{
	return adapter->name;
}

void adapter_connect_list_add(struct btd_adapter *adapter,
					struct btd_device *device)
{
	struct session_req *req;

	if (g_slist_find(adapter->connect_list, device)) {
		DBG("ignoring already added device %s",
						device_get_path(device));
		return;
	}

	adapter->connect_list = g_slist_append(adapter->connect_list,
						btd_device_ref(device));
	DBG("%s added to %s's connect_list", device_get_path(device),
								adapter->name);

	if (!adapter->up)
		return;

	if (adapter->off_requested)
		return;

	if (adapter->scanning_session)
		return;

	if (adapter->disc_sessions == NULL)
		adapter->discov_id = g_idle_add(discovery_cb, adapter);

	req = create_session(adapter, NULL, 0, SESSION_TYPE_DISC_LE_SCAN,
									NULL);
	adapter->disc_sessions = g_slist_append(adapter->disc_sessions, req);
	adapter->scanning_session = req;
}

void adapter_connect_list_remove(struct btd_adapter *adapter,
					struct btd_device *device)
{
	if (!g_slist_find(adapter->connect_list, device)) {
		DBG("device %s is not on the list, ignoring",
						device_get_path(device));
		return;
	}

	adapter->connect_list = g_slist_remove(adapter->connect_list, device);
	DBG("%s removed from %s's connect_list", device_get_path(device),
								adapter->name);
	btd_device_unref(device);
}

void btd_adapter_start(struct btd_adapter *adapter)
{
	struct session_req *req;

	adapter->off_requested = FALSE;
	adapter->up = TRUE;
	adapter->off_timer = 0;

	if (adapter->scan_mode & SCAN_INQUIRY) {
		adapter->mode = MODE_DISCOVERABLE;
		adapter->discoverable = TRUE;
	} else {
		adapter->mode = MODE_CONNECTABLE;
		adapter->discoverable = FALSE;
	}

	g_dbus_emit_property_changed(btd_get_dbus_connection(), adapter->path,
						ADAPTER_INTERFACE, "Powered");

	call_adapter_powered_callbacks(adapter, TRUE);

	info("Adapter %s has been enabled", adapter->path);

	if (g_slist_length(adapter->connect_list) == 0 ||
					adapter->disc_sessions != NULL)
		return;

	req = create_session(adapter, NULL, 0, SESSION_TYPE_DISC_LE_SCAN,
									NULL);
	adapter->disc_sessions = g_slist_append(adapter->disc_sessions, req);
	adapter->scanning_session = req;

	adapter->discov_id = g_idle_add(discovery_cb, adapter);
}

static void reply_pending_requests(struct btd_adapter *adapter)
{
	GSList *l;

	if (!adapter)
		return;

	/* pending bonding */
	for (l = adapter->devices; l; l = l->next) {
		struct btd_device *device = l->data;

		if (device_is_bonding(device, NULL))
			device_cancel_bonding(device,
						HCI_OE_USER_ENDED_CONNECTION);
	}
}

static void remove_driver(gpointer data, gpointer user_data)
{
	struct btd_adapter_driver *driver = data;
	struct btd_adapter *adapter = user_data;

	if (driver->remove)
		driver->remove(adapter);
}

static void remove_profile(gpointer data, gpointer user_data)
{
	struct btd_profile *profile = data;
	struct btd_adapter *adapter = user_data;

	if (profile->adapter_remove)
		profile->adapter_remove(profile, adapter);
}

static void unload_drivers(struct btd_adapter *adapter)
{
	g_slist_foreach(adapter->drivers, remove_driver, adapter);
	g_slist_free(adapter->drivers);
	adapter->drivers = NULL;

	g_slist_foreach(adapter->profiles, remove_profile, adapter);
	g_slist_free(adapter->profiles);
	adapter->profiles = NULL;
}

static void set_mode_complete(struct btd_adapter *adapter)
{
	DBusConnection *conn = btd_get_dbus_connection();
	struct session_req *pending;
	int err;

	DBG("%s", mode2str(adapter->mode));

	if (adapter->mode == MODE_OFF) {
		g_slist_free_full(adapter->mode_sessions, session_free);
		adapter->mode_sessions = NULL;
	}

	if (adapter->pending_mode == NULL)
		return;

	pending = adapter->pending_mode;
	adapter->pending_mode = NULL;

	err = (pending->mode != adapter->mode) ? -EINVAL : 0;

	if (pending->type == SESSION_TYPE_MODE_GLOBAL) {
		if (err < 0)
			g_dbus_pending_property_error(pending->prop_id,
						ERROR_INTERFACE ".Failed",
						strerror(-err));
		else {
			adapter->global_mode = adapter->mode;
			g_dbus_pending_property_success(pending->prop_id);
		}
	} else if (pending->msg != NULL) {
		DBusMessage *msg = pending->msg;
		DBusMessage *reply;

		if (err < 0)
			reply = btd_error_failed(msg, strerror(-err));
		else
			reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

		g_dbus_send_message(conn, reply);
	}

	if (err != 0)
		error("unable to set mode: %s", mode2str(pending->mode));

	store_adapter_info(adapter);

	session_unref(pending);
}

int btd_adapter_stop(struct btd_adapter *adapter)
{
	DBusConnection *conn = btd_get_dbus_connection();
	bool emit_discoverable = false, emit_pairable = false;
	bool emit_discovering = false;

	/* check pending requests */
	reply_pending_requests(adapter);

	adapter->up = FALSE;

	if (adapter->discovery) {
		emit_discovering = true;
		stop_discovery(adapter);
	}

	if (adapter->disc_sessions) {
		g_slist_free_full(adapter->disc_sessions, session_free);
		adapter->disc_sessions = NULL;
	}

	while (adapter->connections) {
		struct btd_device *device = adapter->connections->data;
		adapter_remove_connection(adapter, device);
	}

	if (adapter->scan_mode == (SCAN_PAGE | SCAN_INQUIRY))
		emit_discoverable = true;

	if ((adapter->scan_mode & SCAN_PAGE) && adapter->pairable == TRUE)
		emit_pairable = true;

	adapter->scan_mode = SCAN_DISABLED;
	adapter->mode = MODE_OFF;
	adapter->off_requested = FALSE;

	if (emit_discoverable)
		g_dbus_emit_property_changed(conn, adapter->path,
					ADAPTER_INTERFACE, "Discoverable");
	if (emit_pairable)
		g_dbus_emit_property_changed(conn, adapter->path,
					ADAPTER_INTERFACE, "Pairable");

	if (emit_discovering)
		g_dbus_emit_property_changed(conn, adapter->path,
					ADAPTER_INTERFACE, "Discovering");

	g_dbus_emit_property_changed(conn, adapter->path, ADAPTER_INTERFACE,
								"Powered");

	call_adapter_powered_callbacks(adapter, FALSE);

	info("Adapter %s has been disabled", adapter->path);

	set_mode_complete(adapter);

	return 0;
}

static void off_timer_remove(struct btd_adapter *adapter)
{
	g_source_remove(adapter->off_timer);
	adapter->off_timer = 0;
}

static void adapter_free(gpointer user_data)
{
	struct btd_adapter *adapter = user_data;

	agent_free(adapter->agent);
	adapter->agent = NULL;

	DBG("%p", adapter);

	if (adapter->auth_idle_id)
		g_source_remove(adapter->auth_idle_id);

	g_queue_free_full(adapter->auths, g_free);

	if (adapter->off_timer)
		off_timer_remove(adapter);

	sdp_list_free(adapter->services, NULL);

	g_slist_free(adapter->connections);

	g_free(adapter->path);
	g_free(adapter->name);
	g_free(adapter);
}

struct btd_adapter *btd_adapter_ref(struct btd_adapter *adapter)
{
	adapter->ref++;

	DBG("%p: ref=%d", adapter, adapter->ref);

	return adapter;
}

void btd_adapter_unref(struct btd_adapter *adapter)
{
	gchar *path;

	adapter->ref--;

	DBG("%p: ref=%d", adapter, adapter->ref);

	if (adapter->ref > 0)
		return;

	path = g_strdup(adapter->path);

	g_dbus_unregister_interface(btd_get_dbus_connection(),
						path, ADAPTER_INTERFACE);

	g_free(path);
}

static void convert_names_entry(char *key, char *value, void *user_data)
{
	char *address = user_data;
	char *str = key;
	bdaddr_t local, peer;

	if (strchr(key, '#'))
		str[17] = '\0';

	if (bachk(str) != 0)
		return;

	str2ba(address, &local);
	str2ba(str, &peer);
	adapter_store_cached_name(&local, &peer, value);
}

struct device_converter {
	char *address;
	void (*cb)(GKeyFile *key_file, void *value);
	gboolean force;
};

static void set_device_type(GKeyFile *key_file, char type)
{
	char *techno;
	char *addr_type = NULL;
	char *str;

	switch (type) {
	case BDADDR_BREDR:
		techno = "BR/EDR";
		break;
	case BDADDR_LE_PUBLIC:
		techno = "LE";
		addr_type = "public";
		break;
	case BDADDR_LE_RANDOM:
		techno = "LE";
		addr_type = "static";
		break;
	default:
		return;
	}

	str = g_key_file_get_string(key_file, "General",
					"SupportedTechnologies", NULL);
	if (!str)
		g_key_file_set_string(key_file, "General",
					"SupportedTechnologies", techno);
	else if (!strstr(str, techno))
		g_key_file_set_string(key_file, "General",
					"SupportedTechnologies", "BR/EDR;LE");

	g_free(str);

	if (addr_type)
		g_key_file_set_string(key_file, "General", "AddressType",
					addr_type);
}

static void convert_aliases_entry(GKeyFile *key_file, void *value)
{
	g_key_file_set_string(key_file, "General", "Alias", value);
}

static void convert_trusts_entry(GKeyFile *key_file, void *value)
{
	g_key_file_set_boolean(key_file, "General", "Trusted", TRUE);
}

static void convert_classes_entry(GKeyFile *key_file, void *value)
{
	g_key_file_set_string(key_file, "General", "Class", value);
}

static void convert_blocked_entry(GKeyFile *key_file, void *value)
{
	g_key_file_set_boolean(key_file, "General", "Blocked", TRUE);
}

static void convert_did_entry(GKeyFile *key_file, void *value)
{
	char *vendor_str, *product_str, *version_str;
	uint16_t val;

	vendor_str = strchr(value, ' ');
	if (!vendor_str)
		return;

	*(vendor_str++) = 0;

	if (g_str_equal(value, "FFFF"))
		return;

	product_str = strchr(vendor_str, ' ');
	if (!product_str)
		return;

	*(product_str++) = 0;

	version_str = strchr(product_str, ' ');
	if (!version_str)
		return;

	*(version_str++) = 0;

	val = (uint16_t) strtol(value, NULL, 16);
	g_key_file_set_integer(key_file, "DeviceID", "Source", val);

	val = (uint16_t) strtol(vendor_str, NULL, 16);
	g_key_file_set_integer(key_file, "DeviceID", "Vendor", val);

	val = (uint16_t) strtol(product_str, NULL, 16);
	g_key_file_set_integer(key_file, "DeviceID", "Product", val);

	val = (uint16_t) strtol(version_str, NULL, 16);
	g_key_file_set_integer(key_file, "DeviceID", "Version", val);
}

static void convert_linkkey_entry(GKeyFile *key_file, void *value)
{
	char *type_str, *length_str, *str;
	gint val;

	type_str = strchr(value, ' ');
	if (!type_str)
		return;

	*(type_str++) = 0;

	length_str = strchr(type_str, ' ');
	if (!length_str)
		return;

	*(length_str++) = 0;

	str = g_strconcat("0x", value, NULL);
	g_key_file_set_string(key_file, "LinkKey", "Key", str);
	g_free(str);

	val = strtol(type_str, NULL, 16);
	g_key_file_set_integer(key_file, "LinkKey", "Type", val);

	val = strtol(length_str, NULL, 16);
	g_key_file_set_integer(key_file, "LinkKey", "PINLength", val);
}

static void convert_ltk_entry(GKeyFile *key_file, void *value)
{
	char *auth_str, *rand_str, *str;
	int i, ret;
	unsigned char auth, master, enc_size;
	unsigned short ediv;

	auth_str = strchr(value, ' ');
	if (!auth_str)
		return;

	*(auth_str++) = 0;

	for (i = 0, rand_str = auth_str; i < 4; i++) {
		rand_str = strchr(rand_str, ' ');
		if (!rand_str || rand_str[1] == '\0')
			return;

		rand_str++;
	}

	ret = sscanf(auth_str, " %hhd %hhd %hhd %hd", &auth, &master,
							&enc_size, &ediv);
	if (ret < 4)
		return;

	str = g_strconcat("0x", value, NULL);
	g_key_file_set_string(key_file, "LongTermKey", "Key", str);
	g_free(str);

	g_key_file_set_integer(key_file, "LongTermKey", "Authenticated", auth);
	g_key_file_set_integer(key_file, "LongTermKey", "Master", master);
	g_key_file_set_integer(key_file, "LongTermKey", "EncSize", enc_size);
	g_key_file_set_integer(key_file, "LongTermKey", "EDiv", ediv);

	str = g_strconcat("0x", rand_str, NULL);
	g_key_file_set_string(key_file, "LongTermKey", "Rand", str);
	g_free(str);
}

static void convert_entry(char *key, char *value, void *user_data)
{
	struct device_converter *converter = user_data;
	char type = BDADDR_BREDR;
	char filename[PATH_MAX + 1];
	GKeyFile *key_file;
	char *data;
	gsize length = 0;

	if (key[17] == '#') {
		key[17] = '\0';
		type = key[18] - '0';
	}

	if (bachk(key) != 0)
		return;

	if (converter->force == FALSE) {
		struct stat st;
		int err;

		snprintf(filename, PATH_MAX, STORAGEDIR "/%s/%s",
				converter->address, key);
		filename[PATH_MAX] = '\0';

		err = stat(filename, &st);
		if (err || !S_ISDIR(st.st_mode))
			return;
	}

	snprintf(filename, PATH_MAX, STORAGEDIR "/%s/%s/info",
			converter->address, key);
	filename[PATH_MAX] = '\0';

	key_file = g_key_file_new();
	g_key_file_load_from_file(key_file, filename, 0, NULL);

	set_device_type(key_file, type);

	converter->cb(key_file, value);

	data = g_key_file_to_data(key_file, &length, NULL);
	if (length > 0) {
		create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		g_file_set_contents(filename, data, length, NULL);
	}

	g_free(data);

	g_key_file_free(key_file);
}

static void convert_file(char *file, char *address,
				void (*cb)(GKeyFile *key_file, void *value),
				gboolean force)
{
	char filename[PATH_MAX + 1];
	struct device_converter converter;
	char *str;

	snprintf(filename, PATH_MAX, STORAGEDIR "/%s/%s", address, file);
	filename[PATH_MAX] = '\0';

	str = textfile_get(filename, "converted");
	if (str && strcmp(str, "yes") == 0) {
		DBG("Legacy file %s already converted", filename);
	} else {
		converter.address = address;
		converter.cb = cb;
		converter.force = force;

		textfile_foreach(filename, convert_entry, &converter);
		textfile_put(filename, "converted", "yes");
	}
	free(str);
}

static void convert_device_storage(struct btd_adapter *adapter)
{
	char filename[PATH_MAX + 1];
	char address[18];
	char *str;

	ba2str(&adapter->bdaddr, address);

	/* Convert device's name cache */
	snprintf(filename, PATH_MAX, STORAGEDIR "/%s/names", address);
	filename[PATH_MAX] = '\0';

	str = textfile_get(filename, "converted");
	if (str && strcmp(str, "yes") == 0) {
		DBG("Legacy names file already converted");
	} else {
		textfile_foreach(filename, convert_names_entry, address);
		textfile_put(filename, "converted", "yes");
	}
	free(str);

	/* Convert aliases */
	convert_file("aliases", address, convert_aliases_entry, TRUE);

	/* Convert trusts */
	convert_file("trusts", address, convert_trusts_entry, TRUE);

	/* Convert blocked */
	convert_file("blocked", address, convert_blocked_entry, TRUE);

	/* Convert linkkeys */
	convert_file("linkkeys", address, convert_linkkey_entry, TRUE);

	/* Convert longtermkeys */
	convert_file("longtermkeys", address, convert_ltk_entry, TRUE);

	/* Convert classes */
	convert_file("classes", address, convert_classes_entry, FALSE);

	/* Convert device ids */
	convert_file("did", address, convert_did_entry, FALSE);
}

static void convert_config(struct btd_adapter *adapter, const char *filename,
							GKeyFile *key_file)
{
	char address[18];
	char str[MAX_NAME_LENGTH + 1];
	char config_path[PATH_MAX + 1];
	char *converted;
	gboolean flag;
	int timeout;
	uint8_t mode;
	char *data;
	gsize length = 0;

	ba2str(&adapter->bdaddr, address);
	snprintf(config_path, PATH_MAX, STORAGEDIR "/%s/config", address);
	config_path[PATH_MAX] = '\0';

	converted = textfile_get(config_path, "converted");
	if (converted) {
		if (strcmp(converted, "yes") == 0) {
			DBG("Legacy config file already converted");
			free(converted);
			return;
		}

		free(converted);
	}

	if (read_local_name(&adapter->bdaddr, str) == 0)
		g_key_file_set_string(key_file, "General", "Name", str);

	if (read_device_pairable(&adapter->bdaddr, &flag) == 0)
		g_key_file_set_boolean(key_file, "General", "Pairable", flag);

	if (read_pairable_timeout(address, &timeout) == 0)
		g_key_file_set_integer(key_file, "General",
						"PairableTimeout", timeout);

	if (read_discoverable_timeout(address, &timeout) == 0)
		g_key_file_set_integer(key_file, "General",
						"DiscoverableTimeout", timeout);

	if (read_device_mode(address, str, sizeof(str)) == 0) {
		mode = get_mode(str);
		g_key_file_set_boolean(key_file, "General", "Powered",
					mode > MODE_OFF);
	}

	if (read_on_mode(address, str, sizeof(str)) == 0) {
		mode = get_mode(str);
		g_key_file_set_boolean(key_file, "General", "Discoverable",
					mode == MODE_DISCOVERABLE);
	}

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	data = g_key_file_to_data(key_file, &length, NULL);
	g_file_set_contents(filename, data, length, NULL);
	g_free(data);

	textfile_put(config_path, "converted", "yes");
}

static void load_config(struct btd_adapter *adapter)
{
	GKeyFile *key_file;
	char filename[PATH_MAX + 1];
	char address[18];
	gboolean powered;
	GError *gerr = NULL;

	ba2str(&adapter->bdaddr, address);

	key_file = g_key_file_new();

	snprintf(filename, PATH_MAX, STORAGEDIR "/%s/settings", address);
	filename[PATH_MAX] = '\0';

	if (!g_key_file_load_from_file(key_file, filename, 0, NULL))
		convert_config(adapter, filename, key_file);

	/* Get name */
	adapter->name = g_key_file_get_string(key_file, "General",
								"Name", NULL);

	/* Set class */
	adapter->dev_class = main_opts.class;

	/* Get pairable mode */
	adapter->pairable = g_key_file_get_boolean(key_file, "General",
							"Pairable", &gerr);
	if (gerr) {
		adapter->pairable = TRUE;
		g_error_free(gerr);
		gerr = NULL;
	}

	/* Get pairable timeout */
	adapter->pairable_timeout = g_key_file_get_integer(key_file, "General",
						"PairableTimeout", &gerr);
	if (gerr) {
		adapter->pairable_timeout = main_opts.pairto;
		g_error_free(gerr);
		gerr = NULL;
	}

	/* Get discoverable mode */
	adapter->discoverable = g_key_file_get_boolean(key_file, "General",
							"Discoverable", &gerr);
	if (gerr) {
		adapter->discoverable = (main_opts.mode == MODE_DISCOVERABLE);
		g_error_free(gerr);
		gerr = NULL;
	}

	/* Get discoverable timeout */
	adapter->discov_timeout = g_key_file_get_integer(key_file, "General",
						"DiscoverableTimeout", &gerr);
	if (gerr) {
		adapter->discov_timeout = main_opts.discovto;
		g_error_free(gerr);
		gerr = NULL;
	}

	/* Get powered mode */
	powered = g_key_file_get_boolean(key_file, "General", "Powered",
						&gerr);
	if (gerr) {
		adapter->mode = main_opts.mode;
		g_error_free(gerr);
		gerr = NULL;
	} else if (powered) {
		adapter->mode = adapter->discoverable ? MODE_DISCOVERABLE :
							MODE_CONNECTABLE;
	} else
		adapter->mode = MODE_OFF;

	mgmt_set_connectable(adapter->dev_id, TRUE);
	mgmt_set_discoverable(adapter->dev_id, adapter->discoverable,
				adapter->discov_timeout);

	g_key_file_free(key_file);
}

gboolean adapter_init(struct btd_adapter *adapter, gboolean up)
{
	adapter->up = up;
	adapter->already_up = up;

	adapter->allow_name_changes = TRUE;

	mgmt_read_bdaddr(adapter->dev_id, &adapter->bdaddr);

	if (bacmp(&adapter->bdaddr, BDADDR_ANY) == 0) {
		error("No address available for hci%d", adapter->dev_id);
		return FALSE;
	}

	sdp_init_services_list(&adapter->bdaddr);

	btd_adapter_gatt_server_start(adapter);

	load_config(adapter);
	convert_device_storage(adapter);
	load_drivers(adapter);
	btd_profile_foreach(probe_profile, adapter);
	clear_blocked(adapter);
	load_devices(adapter);

	/* retrieve the active connections: address the scenario where
	 * the are active connections before the daemon've started */
	load_connections(adapter);

	adapter->initialized = TRUE;

	return TRUE;
}

struct btd_adapter *adapter_create(int id)
{
	char path[MAX_PATH_LENGTH];
	struct btd_adapter *adapter;

	adapter = g_try_new0(struct btd_adapter, 1);
	if (!adapter) {
		error("adapter_create: failed to alloc memory for hci%d", id);
		return NULL;
	}

	adapter->dev_id = id;
	adapter->auths = g_queue_new();

	snprintf(path, sizeof(path), "%s/hci%d", base_path, id);
	adapter->path = g_strdup(path);

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
					path, ADAPTER_INTERFACE,
					adapter_methods, adapter_signals,
					adapter_properties, adapter,
					adapter_free)) {
		error("Adapter interface init failed on path %s", path);
		adapter_free(adapter);
		return NULL;
	}

	return btd_adapter_ref(adapter);
}

void adapter_remove(struct btd_adapter *adapter)
{
	GSList *l;

	DBG("Removing adapter %s", adapter->path);

	if (adapter->remove_temp > 0) {
		g_source_remove(adapter->remove_temp);
		adapter->remove_temp = 0;
	}

	discovery_cleanup(adapter);

	for (l = adapter->devices; l; l = l->next)
		device_remove(l->data, FALSE);
	g_slist_free(adapter->devices);

	unload_drivers(adapter);
	btd_adapter_gatt_server_stop(adapter);

	g_slist_free(adapter->pin_callbacks);

	/* Return adapter to down state if it was not up on init */
	if (!adapter->already_up && adapter->up)
		mgmt_set_powered(adapter->dev_id, FALSE);
}

uint16_t adapter_get_dev_id(struct btd_adapter *adapter)
{
	return adapter->dev_id;
}

const gchar *adapter_get_path(struct btd_adapter *adapter)
{
	if (!adapter)
		return NULL;

	return adapter->path;
}

const bdaddr_t *adapter_get_address(struct btd_adapter *adapter)
{
	return &adapter->bdaddr;
}

void adapter_set_allow_name_changes(struct btd_adapter *adapter,
						gboolean allow_name_changes)
{
	adapter->allow_name_changes = allow_name_changes;
}

static gboolean send_found(gpointer user_data)
{
	struct btd_adapter *adapter = user_data;
	struct discovery *discovery = adapter->discovery;

	if (!discovery)
		return FALSE;

	discovery->id = 0;

	if (!discovery->pending)
		return FALSE;

	send_devices_found(adapter);

	discovery->id = g_timeout_add_seconds(1, send_found, adapter);

	return FALSE;
}

static gboolean adapter_remove_temp(gpointer data)
{
	struct btd_adapter *adapter = data;
	GSList *l, *next;

	DBG("%s", adapter->path);

	adapter->remove_temp = 0;

	for (l = adapter->devices; l != NULL; l = next) {
		struct btd_device *dev = l->data;

		next = g_slist_next(l);

		if (device_is_temporary(dev))
			adapter_remove_device(adapter, dev, TRUE);
	}

	return FALSE;
}

void adapter_set_discovering(struct btd_adapter *adapter,
						gboolean discovering)
{
	struct discovery *discovery;
	guint connect_list_len;

	if (discovering && !adapter->discovery)
		adapter->discovery = g_new0(struct discovery, 1);

	discovery = adapter->discovery;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), adapter->path,
					ADAPTER_INTERFACE, "Discovering");

	if (discovering) {
		if (adapter->remove_temp > 0) {
			g_source_remove(adapter->remove_temp);
			adapter->remove_temp = 0;
		}
		discovery->id = g_timeout_add_seconds(1, send_found, adapter);
		return;
	}

	discovery_cleanup(adapter);

	adapter->remove_temp = g_timeout_add_seconds(REMOVE_TEMP_TIMEOUT,
							adapter_remove_temp,
							adapter);

	if (adapter->discov_suspended)
		return;

	connect_list_len = g_slist_length(adapter->connect_list);

	if (connect_list_len == 0 && adapter->scanning_session) {
		session_unref(adapter->scanning_session);
		adapter->scanning_session = NULL;
	}

	if (adapter_has_discov_sessions(adapter)) {
		adapter->discov_id = g_idle_add(discovery_cb, adapter);

		DBG("hci%u restarting discovery: disc_sessions %u",
				adapter->dev_id,
				g_slist_length(adapter->disc_sessions));
		return;
	}
}

static void suspend_discovery(struct btd_adapter *adapter)
{
	if (adapter->disc_sessions == NULL || adapter->discov_suspended)
		return;

	DBG("Suspending discovery");

	adapter->discov_suspended = TRUE;

	if (adapter->discov_id > 0) {
		g_source_remove(adapter->discov_id);
		adapter->discov_id = 0;
	} else
		mgmt_stop_discovery(adapter->dev_id);
}

static gboolean clean_connecting_state(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct btd_device *device = user_data;
	struct btd_adapter *adapter = device_get_adapter(device);

	adapter->connecting = FALSE;

	if (adapter->waiting_to_connect == 0 &&
				g_slist_length(adapter->connect_list) > 0)
		adapter->discov_id = g_idle_add(discovery_cb, adapter);

	btd_device_unref(device);

	return FALSE;
}

static gboolean connect_pending_cb(gpointer user_data)
{
	struct btd_device *device = user_data;
	struct btd_adapter *adapter = device_get_adapter(device);
	GIOChannel *io;

	/* in the future we may want to check here if the controller supports
	 * scanning and connecting at the same time */
	if (adapter->discovery)
		return TRUE;

	if (adapter->connecting)
		return TRUE;

	adapter->connecting = TRUE;
	adapter->waiting_to_connect--;

	io = device_att_connect(device);
	if (io != NULL) {
		g_io_add_watch(io, G_IO_OUT | G_IO_ERR, clean_connecting_state,
						btd_device_ref(device));
		g_io_channel_unref(io);
	}

	btd_device_unref(device);

	return FALSE;
}

void adapter_update_found_devices(struct btd_adapter *adapter,
					const bdaddr_t *bdaddr,
					uint8_t bdaddr_type, int8_t rssi,
					bool confirm_name, bool legacy,
					uint8_t *data, uint8_t data_len)
{
	struct discovery *discovery = adapter->discovery;
	struct btd_device *dev;
	struct eir_data eir_data;
	char addr[18];
	int err;
	GSList *l;

	if (!discovery) {
		error("Device found event while no discovery in progress");
		return;
	}

	memset(&eir_data, 0, sizeof(eir_data));
	err = eir_parse(&eir_data, data, data_len);
	if (err < 0) {
		error("Error parsing EIR data: %s (%d)", strerror(-err), -err);
		return;
	}

	if (eir_data.appearance != 0)
		write_remote_appearance(&adapter->bdaddr, bdaddr, bdaddr_type,
							eir_data.appearance);

	if (eir_data.name != NULL && eir_data.name_complete)
		adapter_store_cached_name(&adapter->bdaddr, bdaddr,
								eir_data.name);

	/* Avoid creating LE device if it's not discoverable */
	if (bdaddr_type != BDADDR_BREDR &&
			!(eir_data.flags & (EIR_LIM_DISC | EIR_GEN_DISC))) {
		eir_data_free(&eir_data);
		return;
	}

	ba2str(bdaddr, addr);

	l = g_slist_find_custom(adapter->devices, bdaddr,
					(GCompareFunc) device_bdaddr_cmp);
	if (l)
		dev = l->data;
	else
		dev = adapter_create_device(adapter, addr, bdaddr_type);

	device_set_legacy(dev, legacy);
	device_set_rssi(dev, rssi);

	if (eir_data.name)
		device_set_name(dev, eir_data.name);

	if (eir_data.class != 0)
		device_set_class(dev, eir_data.class);

	device_add_eir_uuids(dev, eir_data.services);

	eir_data_free(&eir_data);

	if (!g_slist_find(discovery->pending, dev)) {
		guint pending_count;

		discovery->pending = g_slist_prepend(discovery->pending, dev);

		pending_count = g_slist_length(discovery->pending);

		if (discovery->id == 0) {
			discovery->id = g_idle_add(send_found, adapter);
		} else if (pending_count > PENDING_FOUND_MAX) {
			g_source_remove(discovery->id);
			discovery->id = g_idle_add(send_found, adapter);
		}
	}

	if (g_slist_find(discovery->found, dev))
		return;

	if (confirm_name)
		mgmt_confirm_name(adapter->dev_id, bdaddr, bdaddr_type,
						device_name_known(dev));

	discovery->found = g_slist_prepend(discovery->found, dev);

	if (device_is_le(dev) && g_slist_find(adapter->connect_list, dev)) {
		adapter_connect_list_remove(adapter, dev);
		g_idle_add(connect_pending_cb, btd_device_ref(dev));
		stop_discovery(adapter);
		adapter->waiting_to_connect++;
	}
}

void adapter_mode_changed(struct btd_adapter *adapter, uint8_t scan_mode)
{
	bool emit_pairable = false;

	DBG("old 0x%02x new 0x%02x", adapter->scan_mode, scan_mode);

	if (adapter->scan_mode == scan_mode)
		return;

	switch (scan_mode) {
	case SCAN_DISABLED:
		adapter->mode = MODE_OFF;
		break;
	case SCAN_PAGE:
		adapter->mode = MODE_CONNECTABLE;
		adapter->discoverable = FALSE;
		break;
	case (SCAN_PAGE | SCAN_INQUIRY):
		adapter->mode = MODE_DISCOVERABLE;
		adapter->discoverable = TRUE;
		break;
	default:
		/* ignore, reserved */
		return;
	}

	/* If page scanning gets toggled emit the Pairable property */
	if ((adapter->scan_mode & SCAN_PAGE) != (scan_mode & SCAN_PAGE))
		emit_pairable = true;

	adapter->scan_mode = scan_mode;

	if (emit_pairable)
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
				adapter->path, ADAPTER_INTERFACE, "Pairable");

	g_dbus_emit_property_changed(btd_get_dbus_connection(), adapter->path,
					ADAPTER_INTERFACE, "Discoverable");

	set_mode_complete(adapter);
}

struct agent *adapter_get_agent(struct btd_adapter *adapter)
{
	if (!adapter)
		return NULL;

	return adapter->agent;
}

void adapter_add_connection(struct btd_adapter *adapter,
						struct btd_device *device)
{
	if (g_slist_find(adapter->connections, device)) {
		error("Device is already marked as connected");
		return;
	}

	device_add_connection(device);

	adapter->connections = g_slist_append(adapter->connections, device);
}

void adapter_remove_connection(struct btd_adapter *adapter,
						struct btd_device *device)
{
	DBG("");

	if (!g_slist_find(adapter->connections, device)) {
		error("No matching connection for device");
		return;
	}

	device_remove_connection(device);

	adapter->connections = g_slist_remove(adapter->connections, device);

	if (device_is_authenticating(device))
		device_cancel_authentication(device, TRUE);

	if (device_is_temporary(device)) {
		const char *path = device_get_path(device);

		DBG("Removing temporary device %s", path);
		adapter_remove_device(adapter, device, TRUE);
	}
}

gboolean adapter_has_discov_sessions(struct btd_adapter *adapter)
{
	if (!adapter || !adapter->disc_sessions)
		return FALSE;

	return TRUE;
}

int btd_register_adapter_driver(struct btd_adapter_driver *driver)
{
	adapter_drivers = g_slist_append(adapter_drivers, driver);

	if (driver->probe == NULL)
		return 0;

	manager_foreach_adapter(probe_driver, driver);

	return 0;
}

static void unload_driver(struct btd_adapter *adapter, gpointer data)
{
	struct btd_adapter_driver *driver = data;

	if (driver->remove)
		driver->remove(adapter);

	adapter->drivers = g_slist_remove(adapter->drivers, data);
}

void btd_unregister_adapter_driver(struct btd_adapter_driver *driver)
{
	adapter_drivers = g_slist_remove(adapter_drivers, driver);

	manager_foreach_adapter(unload_driver, driver);
}

static void agent_auth_cb(struct agent *agent, DBusError *derr,
							void *user_data)
{
	struct btd_adapter *adapter = user_data;
	struct service_auth *auth = adapter->auths->head->data;

	g_queue_pop_head(adapter->auths);

	auth->cb(derr, auth->user_data);

	g_free(auth);

	adapter->auth_idle_id = g_idle_add(process_auth_queue, adapter);
}

static gboolean process_auth_queue(gpointer user_data)
{
	struct btd_adapter *adapter = user_data;
	DBusError err;

	adapter->auth_idle_id = 0;

	dbus_error_init(&err);
	dbus_set_error_const(&err, "org.bluez.Error.Rejected", NULL);

	while (!g_queue_is_empty(adapter->auths)) {
		struct service_auth *auth = adapter->auths->head->data;
		struct btd_device *device = auth->device;
		const gchar *dev_path;

		if (device_is_trusted(device) == TRUE) {
			auth->cb(NULL, auth->user_data);
			goto next;
		}

		auth->agent = device_get_agent(device);
		if (auth->agent == NULL) {
			warn("Can't find device agent");
			auth->cb(&err, auth->user_data);
			goto next;
		}

		dev_path = device_get_path(device);

		if (agent_authorize_service(auth->agent, dev_path, auth->uuid,
					agent_auth_cb, adapter, NULL) < 0) {
			auth->cb(&err, auth->user_data);
			goto next;
		}

		break;

next:
		g_free(auth);
		g_queue_pop_head(adapter->auths);
	}

	dbus_error_free(&err);

	return FALSE;
}

static int adapter_authorize(struct btd_adapter *adapter, const bdaddr_t *dst,
					const char *uuid, service_auth_cb cb,
					void *user_data)
{
	struct service_auth *auth;
	struct btd_device *device;
	char address[18];
	static guint id = 0;

	ba2str(dst, address);
	device = adapter_find_device(adapter, address);
	if (!device)
		return 0;

	/* Device connected? */
	if (!g_slist_find(adapter->connections, device))
		error("Authorization request for non-connected device!?");

	auth = g_try_new0(struct service_auth, 1);
	if (!auth)
		return 0;

	auth->cb = cb;
	auth->user_data = user_data;
	auth->uuid = uuid;
	auth->device = device;
	auth->adapter = adapter;
	auth->id = ++id;

	g_queue_push_tail(adapter->auths, auth);

	if (adapter->auths->length != 1)
		return auth->id;

	if (adapter->auth_idle_id != 0)
		return auth->id;

	adapter->auth_idle_id = g_idle_add(process_auth_queue, adapter);

	return auth->id;
}

guint btd_request_authorization(const bdaddr_t *src, const bdaddr_t *dst,
					const char *uuid, service_auth_cb cb,
					void *user_data)
{
	struct btd_adapter *adapter;
	GSList *l;

	if (bacmp(src, BDADDR_ANY) != 0) {
		adapter = manager_find_adapter(src);
		if (!adapter)
			return 0;

		return adapter_authorize(adapter, dst, uuid, cb, user_data);
	}

	for (l = manager_get_adapters(); l != NULL; l = g_slist_next(l)) {
		guint id;

		adapter = l->data;

		id = adapter_authorize(adapter, dst, uuid, cb, user_data);
		if (id != 0)
			return id;
	}

	return 0;
}

static struct service_auth *find_authorization(guint id)
{
	GSList *l;
	GList *l2;

	for (l = manager_get_adapters(); l != NULL; l = g_slist_next(l)) {
		struct btd_adapter *adapter = l->data;

		for (l2 = adapter->auths->head; l2 != NULL; l2 = l2->next) {
			struct service_auth *auth = l2->data;

			if (auth->id == id)
				return auth;
		}
	}

	return NULL;
}

int btd_cancel_authorization(guint id)
{
	struct service_auth *auth;

	auth = find_authorization(id);
	if (auth == NULL)
		return -EPERM;

	g_queue_remove(auth->adapter->auths, auth);

	if (auth->agent != NULL)
		agent_cancel(auth->agent);

	g_free(auth);

	return 0;
}

static gchar *adapter_any_path = NULL;
static int adapter_any_refcount = 0;

const char *adapter_any_get_path(void)
{
	return adapter_any_path;
}

const char *btd_adapter_any_request_path(void)
{
	if (adapter_any_refcount++ > 0)
		return adapter_any_path;

	adapter_any_path = g_strdup_printf("%s/any", base_path);

	return adapter_any_path;
}

void btd_adapter_any_release_path(void)
{
	adapter_any_refcount--;

	if (adapter_any_refcount > 0)
		return;

	g_free(adapter_any_path);
	adapter_any_path = NULL;
}

gboolean adapter_powering_down(struct btd_adapter *adapter)
{
	return adapter->off_requested;
}

int btd_adapter_restore_powered(struct btd_adapter *adapter)
{
	if (!main_opts.remember_powered)
		return -EINVAL;

	if (adapter->up)
		return 0;

	if (adapter->mode == MODE_OFF)
		return 0;

	return mgmt_set_powered(adapter->dev_id, TRUE);
}

static gboolean disable_auto(gpointer user_data)
{
	struct btd_adapter *adapter = user_data;
	GSList *l;

	for (l = adapter->devices; l; l = l->next) {
		struct btd_device *device = l->data;

		device_set_auto_connect(device, FALSE);
	}

	adapter->auto_timeout_id = 0;

	return FALSE;
}

void btd_adapter_enable_auto_connect(struct btd_adapter *adapter)
{
	gboolean enable = TRUE;

	if (!adapter->up)
		return;

	DBG("Enabling automatic connections");

	if (adapter->auto_timeout_id)
		return;

	g_slist_foreach(adapter->devices, set_auto_connect, &enable);

	adapter->auto_timeout_id = g_timeout_add_seconds(main_opts.autoto,
						disable_auto, adapter);
}

void btd_adapter_register_pin_cb(struct btd_adapter *adapter,
							btd_adapter_pin_cb_t cb)
{
	adapter->pin_callbacks = g_slist_prepend(adapter->pin_callbacks, cb);
}

void btd_adapter_unregister_pin_cb(struct btd_adapter *adapter,
							btd_adapter_pin_cb_t cb)
{
	adapter->pin_callbacks = g_slist_remove(adapter->pin_callbacks, cb);
}

ssize_t btd_adapter_get_pin(struct btd_adapter *adapter, struct btd_device *dev,
					char *pin_buf, gboolean *display)
{
	GSList *l;
	btd_adapter_pin_cb_t cb;
	ssize_t ret;

	for (l = adapter->pin_callbacks; l != NULL; l = g_slist_next(l)) {
		cb = l->data;
		ret = cb(adapter, dev, pin_buf, display);
		if (ret > 0)
			return ret;
	}

	return read_pin_code(&adapter->bdaddr, device_get_address(dev),
								pin_buf);
}

void btd_adapter_register_powered_callback(struct btd_adapter *adapter,
						btd_adapter_powered_cb cb)
{
	adapter->powered_callbacks =
			g_slist_append(adapter->powered_callbacks, cb);
}

void btd_adapter_unregister_powered_callback(struct btd_adapter *adapter,
						btd_adapter_powered_cb cb)
{
	adapter->powered_callbacks =
			g_slist_remove(adapter->powered_callbacks, cb);
}

int btd_adapter_set_fast_connectable(struct btd_adapter *adapter,
							gboolean enable)
{
	if (!adapter->up)
		return -EINVAL;

	return mgmt_set_fast_connectable(adapter->dev_id, enable);
}

int btd_adapter_read_clock(struct btd_adapter *adapter, const bdaddr_t *bdaddr,
				int which, int timeout, uint32_t *clock,
				uint16_t *accuracy)
{
	if (!adapter->up)
		return -EINVAL;

	return mgmt_read_clock(adapter->dev_id, bdaddr, which,
						timeout, clock, accuracy);
}

int btd_adapter_disconnect_device(struct btd_adapter *adapter,
						const bdaddr_t *bdaddr,
						uint8_t bdaddr_type)

{
	return mgmt_disconnect(adapter->dev_id, bdaddr, bdaddr_type);
}

int btd_adapter_remove_bonding(struct btd_adapter *adapter,
				const bdaddr_t *bdaddr, uint8_t bdaddr_type)
{
	return mgmt_unpair_device(adapter->dev_id, bdaddr, bdaddr_type);
}

int btd_adapter_pincode_reply(struct btd_adapter *adapter,
					const bdaddr_t *bdaddr,
					const char *pin, size_t pin_len)
{
	return mgmt_pincode_reply(adapter->dev_id, bdaddr, pin, pin_len);
}

int btd_adapter_confirm_reply(struct btd_adapter *adapter,
				const bdaddr_t *bdaddr, uint8_t bdaddr_type,
				gboolean success)
{
	return mgmt_confirm_reply(adapter->dev_id, bdaddr, bdaddr_type,
								success);
}

int btd_adapter_passkey_reply(struct btd_adapter *adapter,
				const bdaddr_t *bdaddr, uint8_t bdaddr_type,
				uint32_t passkey)
{
	return mgmt_passkey_reply(adapter->dev_id, bdaddr, bdaddr_type,
								passkey);
}

int btd_adapter_set_did(struct btd_adapter *adapter, uint16_t vendor,
					uint16_t product, uint16_t version,
					uint16_t source)
{
	return mgmt_set_did(adapter->dev_id, vendor, product, version, source);
}

int adapter_create_bonding(struct btd_adapter *adapter, const bdaddr_t *bdaddr,
					uint8_t addr_type, uint8_t io_cap)
{
	suspend_discovery(adapter);
	return mgmt_create_bonding(adapter->dev_id, bdaddr, addr_type, io_cap);
}

int adapter_cancel_bonding(struct btd_adapter *adapter, const bdaddr_t *bdaddr)
{
	return mgmt_cancel_bonding(adapter->dev_id, bdaddr);
}

static void check_oob_bonding_complete(struct btd_adapter *adapter,
					const bdaddr_t *bdaddr, uint8_t status)
{
	if (!adapter->oob_handler || !adapter->oob_handler->bonding_cb)
		return;

	if (bacmp(bdaddr, &adapter->oob_handler->remote_addr) != 0)
		return;

	adapter->oob_handler->bonding_cb(adapter, bdaddr, status,
					adapter->oob_handler->user_data);

	g_free(adapter->oob_handler);
	adapter->oob_handler = NULL;
}

void adapter_bonding_complete(struct btd_adapter *adapter,
					const bdaddr_t *bdaddr, uint8_t status)
{
	struct btd_device *device;
	char addr[18];

	ba2str(bdaddr, addr);
	if (status == 0)
		device = adapter_get_device(adapter, addr);
	else
		device = adapter_find_device(adapter, addr);

	if (device != NULL)
		device_bonding_complete(device, status);

	if (adapter->discov_suspended) {
		adapter->discov_suspended = FALSE;
		mgmt_start_discovery(adapter->dev_id);
	}

	check_oob_bonding_complete(adapter, bdaddr, status);
}

int btd_adapter_read_local_oob_data(struct btd_adapter *adapter)
{
	return mgmt_read_local_oob_data(adapter->dev_id);
}

int btd_adapter_add_remote_oob_data(struct btd_adapter *adapter,
					const bdaddr_t *bdaddr,
					uint8_t *hash, uint8_t *randomizer)
{
	return mgmt_add_remote_oob_data(adapter->dev_id, bdaddr, hash,
								randomizer);
}

int btd_adapter_remove_remote_oob_data(struct btd_adapter *adapter,
							const bdaddr_t *bdaddr)
{
	return mgmt_remove_remote_oob_data(adapter->dev_id, bdaddr);
}

int btd_adapter_ssp_enabled(struct btd_adapter *adapter)
{
	return mgmt_ssp_enabled(adapter->dev_id);
}

void btd_adapter_set_oob_handler(struct btd_adapter *adapter,
						struct oob_handler *handler)
{
	adapter->oob_handler = handler;
}

gboolean btd_adapter_check_oob_handler(struct btd_adapter *adapter)
{
	return adapter->oob_handler != NULL;
}

void adapter_read_local_oob_data_complete(struct btd_adapter *adapter,
					uint8_t *hash, uint8_t *randomizer)
{
	if (!adapter->oob_handler || !adapter->oob_handler->read_local_cb)
		return;

	adapter->oob_handler->read_local_cb(adapter, hash, randomizer,
					adapter->oob_handler->user_data);

	g_free(adapter->oob_handler);
	adapter->oob_handler = NULL;
}
