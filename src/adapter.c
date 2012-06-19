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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/uuid.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "log.h"
#include "textfile.h"

#include "hcid.h"
#include "sdpd.h"
#include "adapter.h"
#include "manager.h"
#include "device.h"
#include "dbus-common.h"
#include "error.h"
#include "glib-helper.h"
#include "agent.h"
#include "storage.h"
#include "gattrib.h"
#include "att.h"
#include "gatt.h"
#include "attrib-server.h"
#include "eir.h"

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

#define check_address(address) bachk(address)

#define OFF_TIMER 3

static DBusConnection *connection = NULL;
static GSList *adapter_drivers = NULL;

static GSList *ops_candidates = NULL;

const struct btd_adapter_ops *adapter_ops = NULL;

struct session_req {
	struct btd_adapter	*adapter;
	DBusConnection		*conn;		/* Connection reference */
	DBusMessage		*msg;		/* Unreplied message ref */
	char			*owner;		/* Bus name of the owner */
	guint			id;		/* Listener id */
	uint8_t			mode;		/* Requested mode */
	int			refcount;	/* Session refcount */
	gboolean		got_reply;	/* Agent reply received */
};

struct service_auth {
	service_auth_cb cb;
	void *user_data;
	struct btd_device *device;
	struct btd_adapter *adapter;
};

struct btd_adapter {
	uint16_t dev_id;
	gboolean up;
	char *path;			/* adapter object path */
	bdaddr_t bdaddr;		/* adapter Bluetooth Address */
	uint32_t dev_class;		/* Class of Device */
	char *name;			/* adapter name */
	gboolean allow_name_changes;	/* whether the adapter name can be changed */
	guint stop_discov_id;		/* stop inquiry/scanning id */
	uint32_t discov_timeout;	/* discoverable time(sec) */
	guint pairable_timeout_id;	/* pairable timeout id */
	uint32_t pairable_timeout;	/* pairable time(sec) */
	uint8_t scan_mode;		/* scan mode: SCAN_DISABLED, SCAN_PAGE,
					 * SCAN_INQUIRY */
	uint8_t mode;			/* off, connectable, discoverable,
					 * limited */
	uint8_t global_mode;		/* last valid global mode */
	struct session_req *pending_mode;
	int state;			/* standard inq, periodic inq, name
					 * resolving, suspended discovery */
	GSList *found_devices;
	GSList *oor_devices;		/* out of range device list */
	struct agent *agent;		/* For the new API */
	guint auth_idle_id;		/* Ongoing authorization */
	GSList *connections;		/* Connected devices */
	GSList *devices;		/* Devices structure pointers */
	GSList *mode_sessions;		/* Request Mode sessions */
	GSList *disc_sessions;		/* Discovery sessions */
	guint discov_id;		/* Discovery timer */
	gboolean discovering;		/* Discovery active */
	gboolean discov_suspended;	/* Discovery suspended */
	guint auto_timeout_id;		/* Automatic connections timeout */
	sdp_list_t *services;		/* Services associated to adapter */

	gboolean pairable;		/* pairable state */
	gboolean initialized;

	gboolean off_requested;		/* DEVDOWN ioctl was called */

	gint ref;

	guint off_timer;

	GSList *powered_callbacks;
	GSList *pin_callbacks;

	GSList *loaded_drivers;
};

static void dev_info_free(void *data)
{
	struct remote_dev_info *dev = data;

	g_free(dev->name);
	g_free(dev->alias);
	g_slist_free_full(dev->services, g_free);
	g_strfreev(dev->uuids);
	g_free(dev);
}

int btd_adapter_set_class(struct btd_adapter *adapter, uint8_t major,
							uint8_t minor)
{
       return adapter_ops->set_dev_class(adapter->dev_id, major, minor);
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

static uint8_t get_mode(const bdaddr_t *bdaddr, const char *mode)
{
	if (strcasecmp("off", mode) == 0)
		return MODE_OFF;
	else if (strcasecmp("connectable", mode) == 0)
		return MODE_CONNECTABLE;
	else if (strcasecmp("discoverable", mode) == 0)
		return MODE_DISCOVERABLE;
	else if (strcasecmp("on", mode) == 0) {
		char onmode[14], srcaddr[18];

		ba2str(bdaddr, srcaddr);
		if (read_on_mode(srcaddr, onmode, sizeof(onmode)) < 0)
			return MODE_CONNECTABLE;

		return get_mode(bdaddr, onmode);
	} else
		return MODE_UNKNOWN;
}

static struct session_req *session_ref(struct session_req *req)
{
	req->refcount++;

	DBG("%p: ref=%d", req, req->refcount);

	return req;
}

static struct session_req *create_session(struct btd_adapter *adapter,
					DBusConnection *conn, DBusMessage *msg,
					uint8_t mode, GDBusWatchFunction cb)
{
	const char *sender = dbus_message_get_sender(msg);
	struct session_req *req;

	req = g_new0(struct session_req, 1);
	req->adapter = adapter;
	req->conn = dbus_connection_ref(conn);
	req->msg = dbus_message_ref(msg);
	req->mode = mode;

	if (cb == NULL)
		return session_ref(req);

	req->owner = g_strdup(sender);
	req->id = g_dbus_add_disconnect_watch(conn, sender, cb, req, NULL);

	info("%s session %p with %s activated",
		req->mode ? "Mode" : "Discovery", req, sender);

	return session_ref(req);
}

static int adapter_set_mode(struct btd_adapter *adapter, uint8_t mode)
{
	int err;

	if (mode == MODE_CONNECTABLE)
		err = adapter_ops->set_discoverable(adapter->dev_id, FALSE, 0);
	else
		err = adapter_ops->set_discoverable(adapter->dev_id, TRUE,
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

static int set_mode(struct btd_adapter *adapter, uint8_t new_mode,
			DBusMessage *msg)
{
	int err;
	const char *modestr;

	if (adapter->pending_mode != NULL)
		return -EALREADY;

	if (!adapter->up && new_mode != MODE_OFF) {
		err = adapter_ops->set_powered(adapter->dev_id, TRUE);
		if (err < 0)
			return err;

		goto done;
	}

	if (adapter->up && new_mode == MODE_OFF) {
		err = adapter_ops->set_powered(adapter->dev_id, FALSE);
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
	modestr = mode2str(new_mode);
	write_device_mode(&adapter->bdaddr, modestr);

	DBG("%s", modestr);

	if (msg != NULL) {
		struct session_req *req;

		req = find_session_by_msg(adapter->mode_sessions, msg);
		if (req) {
			adapter->pending_mode = req;
			session_ref(req);
		} else
			/* Wait for mode change to reply */
			adapter->pending_mode = create_session(adapter,
					connection, msg, new_mode, NULL);
	} else
		/* Nothing to reply just write the new mode */
		adapter->mode = new_mode;

	return 0;
}

static DBusMessage *set_discoverable(DBusConnection *conn, DBusMessage *msg,
				gboolean discoverable, void *data)
{
	struct btd_adapter *adapter = data;
	uint8_t mode;
	int err;

	mode = discoverable ? MODE_DISCOVERABLE : MODE_CONNECTABLE;

	if (mode == adapter->mode) {
		adapter->global_mode = mode;
		return dbus_message_new_method_return(msg);
	}

	err = set_mode(adapter, mode, msg);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return NULL;
}

static DBusMessage *set_powered(DBusConnection *conn, DBusMessage *msg,
				gboolean powered, void *data)
{
	struct btd_adapter *adapter = data;
	uint8_t mode;
	int err;

	if (powered) {
		mode = get_mode(&adapter->bdaddr, "on");
		return set_discoverable(conn, msg, mode == MODE_DISCOVERABLE,
									data);
	}

	mode = MODE_OFF;

	if (mode == adapter->mode) {
		adapter->global_mode = mode;
		return dbus_message_new_method_return(msg);
	}

	err = set_mode(adapter, mode, msg);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return NULL;
}

static DBusMessage *set_pairable(DBusConnection *conn, DBusMessage *msg,
				gboolean pairable, void *data)
{
	struct btd_adapter *adapter = data;
	int err;

	if (adapter->scan_mode == SCAN_DISABLED)
		return btd_error_not_ready(msg);

	if (pairable == adapter->pairable)
		goto done;

	if (!(adapter->scan_mode & SCAN_INQUIRY))
		goto store;

	err = set_mode(adapter, MODE_DISCOVERABLE, NULL);
	if (err < 0 && msg)
		return btd_error_failed(msg, strerror(-err));

store:
	adapter_ops->set_pairable(adapter->dev_id, pairable);

done:
	return msg ? dbus_message_new_method_return(msg) : NULL;
}

static gboolean pairable_timeout_handler(void *data)
{
	set_pairable(NULL, NULL, FALSE, data);

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

	write_device_pairable(&adapter->bdaddr, pairable);

	emit_property_changed(connection, adapter->path,
				ADAPTER_INTERFACE, "Pairable",
				DBUS_TYPE_BOOLEAN, &pairable);

	if (pairable && adapter->pairable_timeout)
		adapter_set_pairable_timeout(adapter,
						adapter->pairable_timeout);
}

static struct session_req *find_session(GSList *list, const char *sender)
{
	for (; list; list = list->next) {
		struct session_req *req = list->data;

		if (g_str_equal(req->owner, sender))
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

static GSList *remove_bredr(GSList *all)
{
	GSList *l, *le;

	for (l = all, le = NULL; l; l = l->next) {
		struct remote_dev_info *dev = l->data;
		if (dev->bdaddr_type == BDADDR_BREDR) {
			dev_info_free(dev);
			continue;
		}

		le = g_slist_append(le, dev);
	}

	g_slist_free(all);

	return le;
}

/* Called when a session gets removed or the adapter is stopped */
static void stop_discovery(struct btd_adapter *adapter)
{
	adapter->found_devices = remove_bredr(adapter->found_devices);

	if (adapter->oor_devices) {
		g_slist_free(adapter->oor_devices);
		adapter->oor_devices = NULL;
	}

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
		adapter_ops->stop_discovery(adapter->dev_id);
}

static void session_remove(struct session_req *req)
{
	struct btd_adapter *adapter = req->adapter;

	/* Ignore set_mode session */
	if (req->owner == NULL)
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

		set_mode(adapter, mode, NULL);
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
		g_dbus_remove_watch(req->conn, req->id);

	if (req->msg) {
		dbus_message_unref(req->msg);
		if (!req->got_reply && req->mode && req->adapter->agent)
			agent_cancel(req->adapter->agent);
	}

	if (req->conn)
		dbus_connection_unref(req->conn);
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
	struct session_req *req = data;
	int err;
	DBusMessage *reply;

	req->got_reply = TRUE;

	if (derr && dbus_error_is_set(derr)) {
		reply = dbus_message_new_error(req->msg, derr->name,
						derr->message);
		g_dbus_send_message(req->conn, reply);
		session_unref(req);
		return;
	}

	err = set_mode(req->adapter, req->mode, req->msg);
	if (err < 0)
		reply = btd_error_failed(req->msg, strerror(-err));
	else if (!req->adapter->pending_mode)
		reply = dbus_message_new_method_return(req->msg);
	else
		reply = NULL;

	if (reply) {
		/*
		 * Send reply immediately only if there was an error changing
		 * mode, or change is not needed. Otherwise, reply is sent in
		 * set_mode_complete.
		 */
		g_dbus_send_message(req->conn, reply);

		dbus_message_unref(req->msg);
		req->msg = NULL;
	}

	if (!find_session(req->adapter->mode_sessions, req->owner))
		session_unref(req);
}

static DBusMessage *set_discoverable_timeout(DBusConnection *conn,
							DBusMessage *msg,
							uint32_t timeout,
							void *data)
{
	struct btd_adapter *adapter = data;
	const char *path;

	if (adapter->discov_timeout == timeout && timeout == 0)
		return dbus_message_new_method_return(msg);

	if (adapter->scan_mode & SCAN_INQUIRY)
		adapter_ops->set_discoverable(adapter->dev_id, TRUE, timeout);

	adapter->discov_timeout = timeout;

	write_discoverable_timeout(&adapter->bdaddr, timeout);

	path = dbus_message_get_path(msg);

	emit_property_changed(conn, path,
				ADAPTER_INTERFACE, "DiscoverableTimeout",
				DBUS_TYPE_UINT32, &timeout);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *set_pairable_timeout(DBusConnection *conn,
						DBusMessage *msg,
						uint32_t timeout,
						void *data)
{
	struct btd_adapter *adapter = data;
	const char *path;

	if (adapter->pairable_timeout == timeout && timeout == 0)
		return dbus_message_new_method_return(msg);

	if (adapter->pairable)
		adapter_set_pairable_timeout(adapter, timeout);

	adapter->pairable_timeout = timeout;

	write_pairable_timeout(&adapter->bdaddr, timeout);

	path = dbus_message_get_path(msg);

	emit_property_changed(conn, path,
				ADAPTER_INTERFACE, "PairableTimeout",
				DBUS_TYPE_UINT32, &timeout);

	return dbus_message_new_method_return(msg);
}

void btd_adapter_class_changed(struct btd_adapter *adapter, uint32_t new_class)
{
	uint8_t class[3];

	class[2] = (new_class >> 16) & 0xff;
	class[1] = (new_class >> 8) & 0xff;
	class[0] = new_class & 0xff;

	write_local_class(&adapter->bdaddr, class);

	adapter->dev_class = new_class;

	if (main_opts.gatt_enabled) {
		/* Removes service class */
		class[1] = class[1] & 0x1f;
		attrib_gap_set(adapter, GATT_CHARAC_APPEARANCE, class, 2);
	}

	emit_property_changed(connection, adapter->path,
				ADAPTER_INTERFACE, "Class",
				DBUS_TYPE_UINT32, &new_class);
}

void adapter_name_changed(struct btd_adapter *adapter, const char *name)
{
	if (g_strcmp0(adapter->name, name) == 0)
		return;

	g_free(adapter->name);
	adapter->name = g_strdup(name);

	if (connection)
		emit_property_changed(connection, adapter->path,
					ADAPTER_INTERFACE, "Name",
					DBUS_TYPE_STRING, &name);

	if (main_opts.gatt_enabled)
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
		int err = adapter_ops->set_name(adapter->dev_id, maxname);
		if (err < 0)
			return err;
	} else {
		g_free(adapter->name);
		adapter->name = g_strdup(maxname);
	}

	write_local_name(&adapter->bdaddr, maxname);

	return 0;
}

static DBusMessage *set_name(DBusConnection *conn, DBusMessage *msg,
					const char *name, void *data)
{
	struct btd_adapter *adapter = data;
	int ret;

	if (adapter->allow_name_changes == FALSE)
		return btd_error_failed(msg, strerror(EPERM));

	ret = adapter_set_name(adapter, name);
	if (ret == -EINVAL)
		return btd_error_invalid_args(msg);
	else if (ret < 0)
		return btd_error_failed(msg, strerror(-ret));

	return dbus_message_new_method_return(msg);
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

static void adapter_update_devices(struct btd_adapter *adapter)
{
	char **devices;
	int i;
	GSList *l;

	/* Devices */
	devices = g_new0(char *, g_slist_length(adapter->devices) + 1);
	for (i = 0, l = adapter->devices; l; l = l->next, i++) {
		struct btd_device *dev = l->data;
		devices[i] = (char *) device_get_path(dev);
	}

	emit_array_property_changed(connection, adapter->path,
					ADAPTER_INTERFACE, "Devices",
					DBUS_TYPE_OBJECT_PATH, &devices, i);
	g_free(devices);
}

static void adapter_emit_uuids_updated(struct btd_adapter *adapter)
{
	char **uuids;
	int i;
	sdp_list_t *list;

	if (!adapter->initialized)
		return;

	uuids = g_new0(char *, sdp_list_len(adapter->services) + 1);

	for (i = 0, list = adapter->services; list; list = list->next) {
		char *uuid;
		sdp_record_t *rec = list->data;

		uuid = bt_uuid2string(&rec->svclass);
		if (uuid)
			uuids[i++] = uuid;
	}

	emit_array_property_changed(connection, adapter->path,
			ADAPTER_INTERFACE, "UUIDs", DBUS_TYPE_STRING, &uuids, i);

	g_strfreev(uuids);
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
		adapter_ops->add_uuid(adapter->dev_id, &rec->svclass, svc_hint);
	}

	adapter_emit_uuids_updated(adapter);
}

void adapter_service_remove(struct btd_adapter *adapter, void *r)
{
	sdp_record_t *rec = r;

	adapter->services = sdp_list_remove(adapter->services, rec);

	if (sdp_list_find(adapter->services, &rec->svclass, uuid_cmp) == NULL)
		adapter_ops->remove_uuid(adapter->dev_id, &rec->svclass);

	adapter_emit_uuids_updated(adapter);
}

static struct btd_device *adapter_create_device(DBusConnection *conn,
						struct btd_adapter *adapter,
						const char *address,
						uint8_t bdaddr_type)
{
	struct btd_device *device;
	const char *path;

	DBG("%s", address);

	device = device_create(conn, adapter, address, bdaddr_type);
	if (!device)
		return NULL;

	device_set_temporary(device, TRUE);

	adapter->devices = g_slist_append(adapter->devices, device);

	path = device_get_path(device);
	g_dbus_emit_signal(conn, adapter->path,
			ADAPTER_INTERFACE, "DeviceCreated",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);

	adapter_update_devices(adapter);

	return device;
}

void adapter_remove_device(DBusConnection *conn, struct btd_adapter *adapter,
						struct btd_device *device,
						gboolean remove_storage)
{
	const gchar *dev_path = device_get_path(device);
	struct agent *agent;

	adapter->devices = g_slist_remove(adapter->devices, device);
	adapter->connections = g_slist_remove(adapter->connections, device);

	adapter_update_devices(adapter);

	g_dbus_emit_signal(conn, adapter->path,
			ADAPTER_INTERFACE, "DeviceRemoved",
			DBUS_TYPE_OBJECT_PATH, &dev_path,
			DBUS_TYPE_INVALID);

	agent = device_get_agent(device);

	if (agent && device_is_authorizing(device))
		agent_cancel(agent);

	device_remove(device, remove_storage);
}

struct btd_device *adapter_get_device(DBusConnection *conn,
						struct btd_adapter *adapter,
						const gchar *address)
{
	struct btd_device *device;

	DBG("%s", address);

	if (!adapter)
		return NULL;

	device = adapter_find_device(adapter, address);
	if (device)
		return device;

	return adapter_create_device(conn, adapter, address,
						BDADDR_BREDR);
}

static gboolean discovery_cb(gpointer user_data)
{
	struct btd_adapter *adapter = user_data;
	int err;

	adapter->discov_id = 0;

	err = adapter_ops->start_discovery(adapter->dev_id);
	if (err < 0)
		error("start_discovery: %s (%d)", strerror(-err), -err);

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

	g_slist_free_full(adapter->found_devices, dev_info_free);
	adapter->found_devices = NULL;

	g_slist_free(adapter->oor_devices);
	adapter->oor_devices = NULL;

	if (adapter->discov_suspended)
		goto done;

	err = adapter_ops->start_discovery(adapter->dev_id);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

done:
	req = create_session(adapter, conn, msg, 0,
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

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	const char *property;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	char srcaddr[18];
	gboolean value;
	char **devices, **uuids;
	int i;
	GSList *l;
	sdp_list_t *list;

	ba2str(&adapter->bdaddr, srcaddr);

	if (check_address(srcaddr) < 0)
		return btd_error_invalid_args(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Address */
	property = srcaddr;
	dict_append_entry(&dict, "Address", DBUS_TYPE_STRING, &property);

	/* Name */
	property = adapter->name ? : "";

	dict_append_entry(&dict, "Name", DBUS_TYPE_STRING, &property);

	/* Class */
	dict_append_entry(&dict, "Class",
				DBUS_TYPE_UINT32, &adapter->dev_class);

	/* Powered */
	value = (adapter->up && !adapter->off_requested) ? TRUE : FALSE;
	dict_append_entry(&dict, "Powered", DBUS_TYPE_BOOLEAN, &value);

	/* Discoverable */
	value = adapter->scan_mode & SCAN_INQUIRY ? TRUE : FALSE;
	dict_append_entry(&dict, "Discoverable", DBUS_TYPE_BOOLEAN, &value);

	/* Pairable */
	dict_append_entry(&dict, "Pairable", DBUS_TYPE_BOOLEAN,
				&adapter->pairable);

	/* DiscoverableTimeout */
	dict_append_entry(&dict, "DiscoverableTimeout",
				DBUS_TYPE_UINT32, &adapter->discov_timeout);

	/* PairableTimeout */
	dict_append_entry(&dict, "PairableTimeout",
				DBUS_TYPE_UINT32, &adapter->pairable_timeout);


	/* Discovering */
	dict_append_entry(&dict, "Discovering", DBUS_TYPE_BOOLEAN,
							&adapter->discovering);

	/* Devices */
	devices = g_new0(char *, g_slist_length(adapter->devices) + 1);
	for (i = 0, l = adapter->devices; l; l = l->next, i++) {
		struct btd_device *dev = l->data;
		devices[i] = (char *) device_get_path(dev);
	}
	dict_append_array(&dict, "Devices", DBUS_TYPE_OBJECT_PATH,
								&devices, i);
	g_free(devices);

	/* UUIDs */
	uuids = g_new0(char *, sdp_list_len(adapter->services) + 1);

	for (i = 0, list = adapter->services; list; list = list->next) {
		sdp_record_t *rec = list->data;
		char *uuid;

		uuid = bt_uuid2string(&rec->svclass);
		if (uuid)
			uuids[i++] = uuid;
	}

	dict_append_array(&dict, "UUIDs", DBUS_TYPE_STRING, &uuids, i);

	g_strfreev(uuids);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter sub;
	const char *property;

	if (!dbus_message_iter_init(msg, &iter))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return btd_error_invalid_args(msg);
	dbus_message_iter_recurse(&iter, &sub);

	if (g_str_equal("Name", property)) {
		const char *name;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)
			return btd_error_invalid_args(msg);
		dbus_message_iter_get_basic(&sub, &name);

		return set_name(conn, msg, name, data);
	} else if (g_str_equal("Powered", property)) {
		gboolean powered;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_BOOLEAN)
			return btd_error_invalid_args(msg);

		dbus_message_iter_get_basic(&sub, &powered);

		return set_powered(conn, msg, powered, data);
	} else if (g_str_equal("Discoverable", property)) {
		gboolean discoverable;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_BOOLEAN)
			return btd_error_invalid_args(msg);

		dbus_message_iter_get_basic(&sub, &discoverable);

		return set_discoverable(conn, msg, discoverable, data);
	} else if (g_str_equal("DiscoverableTimeout", property)) {
		uint32_t timeout;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_UINT32)
			return btd_error_invalid_args(msg);

		dbus_message_iter_get_basic(&sub, &timeout);

		return set_discoverable_timeout(conn, msg, timeout, data);
	} else if (g_str_equal("Pairable", property)) {
		gboolean pairable;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_BOOLEAN)
			return btd_error_invalid_args(msg);

		dbus_message_iter_get_basic(&sub, &pairable);

		return set_pairable(conn, msg, pairable, data);
	} else if (g_str_equal("PairableTimeout", property)) {
		uint32_t timeout;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_UINT32)
			return btd_error_invalid_args(msg);

		dbus_message_iter_get_basic(&sub, &timeout);

		return set_pairable_timeout(conn, msg, timeout, data);
	}

	return btd_error_invalid_args(msg);
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

	new_mode = get_mode(&adapter->bdaddr, "on");

	req = find_session(adapter->mode_sessions, sender);
	if (req) {
		session_ref(req);
		return dbus_message_new_method_return(msg);
	} else {
		req = create_session(adapter, conn, msg, new_mode,
					session_owner_exit);
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

static DBusMessage *list_devices(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	DBusMessage *reply;
	GSList *l;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	const gchar *dev_path;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &array_iter);

	for (l = adapter->devices; l; l = l->next) {
		struct btd_device *device = l->data;

		dev_path = device_get_path(device);

		dbus_message_iter_append_basic(&array_iter,
				DBUS_TYPE_OBJECT_PATH, &dev_path);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return reply;
}

static DBusMessage *cancel_device_creation(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	const gchar *address, *sender = dbus_message_get_sender(msg);
	struct btd_device *device;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &address,
						DBUS_TYPE_INVALID) == FALSE)
		return btd_error_invalid_args(msg);

	if (check_address(address) < 0)
		return btd_error_invalid_args(msg);

	device = adapter_find_device(adapter, address);
	if (!device || !device_is_creating(device, NULL))
		return btd_error_does_not_exist(msg);

	if (!device_is_creating(device, sender))
		return btd_error_not_authorized(msg);

	device_set_temporary(device, TRUE);

	if (device_is_connected(device)) {
		device_request_disconnect(device, msg);
		return NULL;
	}

	adapter_remove_device(conn, adapter, device, TRUE);

	return dbus_message_new_method_return(msg);
}

static struct btd_device *create_device_internal(DBusConnection *conn,
						struct btd_adapter *adapter,
						const char *address, int *err)
{
	struct remote_dev_info *dev;
	struct btd_device *device;
	bdaddr_t addr;
	uint8_t bdaddr_type;

	str2ba(address, &addr);

	dev = adapter_search_found_devices(adapter, &addr);
	if (dev)
		bdaddr_type = dev->bdaddr_type;
	else
		bdaddr_type = BDADDR_BREDR;

	device = adapter_create_device(conn, adapter, address, bdaddr_type);
	if (!device && err)
		*err = -ENOMEM;

	return device;
}

static DBusMessage *create_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	struct btd_device *device;
	const gchar *address;
	DBusMessage *reply;
	int err;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &address,
						DBUS_TYPE_INVALID) == FALSE)
		return btd_error_invalid_args(msg);

	if (check_address(address) < 0)
		return btd_error_invalid_args(msg);

	if (!adapter->up)
		return btd_error_not_ready(msg);

	if (adapter_find_device(adapter, address))
		return btd_error_already_exists(msg);

	DBG("%s", address);

	device = create_device_internal(conn, adapter, address, &err);
	if (!device)
		goto failed;

	if (device_is_bredr(device))
		err = device_browse_sdp(device, conn, msg, NULL, FALSE);
	else
		err = device_browse_primary(device, conn, msg, FALSE);

	if (err < 0) {
		adapter_remove_device(conn, adapter, device, TRUE);
		return btd_error_failed(msg, strerror(-err));
	}

	return NULL;

failed:
	if (err == -ENOTCONN) {
		/* Device is not connectable */
		const char *path = device_get_path(device);

		reply = dbus_message_new_method_return(msg);

		dbus_message_append_args(reply,
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID);
	} else
		reply = btd_error_failed(msg, strerror(-err));

	return reply;
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

static DBusMessage *create_paired_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	struct btd_device *device;
	const gchar *address, *agent_path, *capability, *sender;
	uint8_t cap;
	int err;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &address,
					DBUS_TYPE_OBJECT_PATH, &agent_path,
					DBUS_TYPE_STRING, &capability,
					DBUS_TYPE_INVALID) == FALSE)
		return btd_error_invalid_args(msg);

	if (check_address(address) < 0)
		return btd_error_invalid_args(msg);

	if (!adapter->up)
		return btd_error_not_ready(msg);

	sender = dbus_message_get_sender(msg);
	if (adapter->agent &&
			agent_matches(adapter->agent, sender, agent_path)) {
		error("Refusing adapter agent usage as device specific one");
		return btd_error_invalid_args(msg);
	}

	cap = parse_io_capability(capability);
	if (cap == IO_CAPABILITY_INVALID)
		return btd_error_invalid_args(msg);

	device = adapter_find_device(adapter, address);
	if (!device) {
		device = create_device_internal(conn, adapter, address, &err);
		if (!device)
			return btd_error_failed(msg, strerror(-err));
	}

	return device_create_bonding(device, conn, msg, agent_path, cap);
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

	if (device_is_temporary(device) || device_is_busy(device))
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".DoesNotExist",
				"Device creation in progress");

	device_set_temporary(device, TRUE);

	if (!device_is_connected(device)) {
		adapter_remove_device(conn, adapter, device, TRUE);
		return dbus_message_new_method_return(msg);
	}

	device_request_disconnect(device, msg);
	return NULL;
}

static DBusMessage *find_device(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct btd_adapter *adapter = data;
	struct btd_device *device;
	DBusMessage *reply;
	const gchar *address;
	GSList *l;
	const gchar *dev_path;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &address,
						DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	l = g_slist_find_custom(adapter->devices,
			address, (GCompareFunc) device_address_cmp);
	if (!l)
		return btd_error_does_not_exist(msg);

	device = l->data;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dev_path = device_get_path(device);

	dbus_message_append_args(reply,
				DBUS_TYPE_OBJECT_PATH, &dev_path,
				DBUS_TYPE_INVALID);

	return reply;
}

static void agent_removed(struct agent *agent, struct btd_adapter *adapter)
{
	adapter_ops->set_io_capability(adapter->dev_id,
					IO_CAPABILITY_NOINPUTNOOUTPUT);

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
		return NULL;

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

	adapter_ops->set_io_capability(adapter->dev_id, cap);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_agent(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	const char *path, *name;
	struct btd_adapter *adapter = data;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID))
		return NULL;

	name = dbus_message_get_sender(msg);

	if (!adapter->agent || !agent_matches(adapter->agent, name, path))
		return btd_error_does_not_exist(msg);

	agent_free(adapter->agent);
	adapter->agent = NULL;

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable adapter_methods[] = {
	{ GDBUS_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_properties) },
	{ GDBUS_ASYNC_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }), NULL,
			set_property) },
	{ GDBUS_ASYNC_METHOD("RequestSession", NULL, NULL,
			request_session) },
	{ GDBUS_METHOD("ReleaseSession", NULL, NULL,
			release_session) },
	{ GDBUS_METHOD("StartDiscovery", NULL, NULL,
			adapter_start_discovery) },
	{ GDBUS_ASYNC_METHOD("StopDiscovery", NULL, NULL,
			adapter_stop_discovery) },
	{ GDBUS_DEPRECATED_METHOD("ListDevices",
			NULL, GDBUS_ARGS({ "devices", "ao" }),
			list_devices) },
	{ GDBUS_ASYNC_METHOD("CreateDevice",
			GDBUS_ARGS({ "address", "s" }),
			GDBUS_ARGS({ "device", "o" }),
			create_device) },
	{ GDBUS_ASYNC_METHOD("CreatePairedDevice",
			GDBUS_ARGS({ "address", "s" }, { "agent", "o" },
							{ "capability", "s" }),
			GDBUS_ARGS({ "device", "o" }),
			create_paired_device) },
	{ GDBUS_ASYNC_METHOD("CancelDeviceCreation",
			GDBUS_ARGS({ "address", "s" }), NULL,
			cancel_device_creation) },
	{ GDBUS_ASYNC_METHOD("RemoveDevice",
			GDBUS_ARGS({ "device", "o" }), NULL,
			remove_device) },
	{ GDBUS_METHOD("FindDevice",
			GDBUS_ARGS({ "address", "s" }),
			GDBUS_ARGS({ "device", "o" }),
			find_device) },
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
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ GDBUS_SIGNAL("DeviceCreated",
			GDBUS_ARGS({ "device", "o" })) },
	{ GDBUS_SIGNAL("DeviceRemoved",
			GDBUS_ARGS({ "device", "o" })) },
	{ GDBUS_SIGNAL("DeviceFound",
			GDBUS_ARGS({ "address", "s" },
						{ "values", "a{sv}" })) },
	{ GDBUS_SIGNAL("DeviceDisappeared",
			GDBUS_ARGS({ "address", "s" })) },
	{ }
};

static void create_stored_device_from_profiles(char *key, char *value,
						void *user_data)
{
	struct btd_adapter *adapter = user_data;
	GSList *list, *uuids = bt_string2list(value);
	struct btd_device *device;

	if (g_slist_find_custom(adapter->devices,
				key, (GCompareFunc) device_address_cmp))
		return;

	device = device_create(connection, adapter, key, BDADDR_BREDR);
	if (!device)
		return;

	device_set_temporary(device, FALSE);
	adapter->devices = g_slist_append(adapter->devices, device);

	list = device_services_from_record(device, uuids);
	if (list)
		device_register_services(connection, device, list, ATT_PSM);

	device_probe_drivers(device, uuids);

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

static struct link_key_info *get_key_info(const char *addr, const char *value)
{
	struct link_key_info *info;
	char tmp[3];
	long int l;

	if (strlen(value) < 36) {
		error("Unexpectedly short (%zu) link key line", strlen(value));
		return NULL;
	}

	info = g_new0(struct link_key_info, 1);

	str2ba(addr, &info->bdaddr);

	str2buf(value, info->key, sizeof(info->key));

	memcpy(tmp, value + 33, 2);
	info->type = (uint8_t) strtol(tmp, NULL, 10);

	memcpy(tmp, value + 35, 2);
	l = strtol(tmp, NULL, 10);
	if (l < 0)
		l = 0;
	info->pin_len = l;

	return info;
}

static struct smp_ltk_info *get_ltk_info(const char *addr, uint8_t bdaddr_type,
							const char *value)
{
	struct smp_ltk_info *ltk;
	char *ptr;
	int i, ret;

	if (strlen(value) < 60) {
		error("Unexpectedly short (%zu) LTK", strlen(value));
		return NULL;
	}

	ltk = g_new0(struct smp_ltk_info, 1);

	str2ba(addr, &ltk->bdaddr);

	ltk->bdaddr_type = bdaddr_type;

	str2buf(value, ltk->val, sizeof(ltk->val));

	ptr = (char *) value + 2 * sizeof(ltk->val) + 1;

	ret = sscanf(ptr, " %hhd %hhd %hhd %hd %n",
		     &ltk->authenticated, &ltk->master, &ltk->enc_size,
							&ltk->ediv, &i);
	if (ret < 2) {
		g_free(ltk);
		return NULL;
	}
	ptr += i;

	str2buf(ptr, ltk->rand, sizeof(ltk->rand));

	return ltk;
}

static void create_stored_device_from_linkkeys(char *key, char *value,
							void *user_data)
{
	struct adapter_keys *keys = user_data;
	struct btd_adapter *adapter = keys->adapter;
	struct btd_device *device;
	struct link_key_info *info;

	info = get_key_info(key, value);
	if (info)
		keys->keys = g_slist_append(keys->keys, info);

	if (g_slist_find_custom(adapter->devices, key,
					(GCompareFunc) device_address_cmp))
		return;

	device = device_create(connection, adapter, key, BDADDR_BREDR);
	if (device) {
		device_set_temporary(device, FALSE);
		adapter->devices = g_slist_append(adapter->devices, device);
	}
}

static void create_stored_device_from_ltks(char *key, char *value,
							void *user_data)
{
	struct adapter_keys *keys = user_data;
	struct btd_adapter *adapter = keys->adapter;
	struct btd_device *device;
	struct smp_ltk_info *info;
	char address[18], srcaddr[18];
	uint8_t bdaddr_type;
	bdaddr_t src;

	if (sscanf(key, "%17s#%hhu", address, &bdaddr_type) < 2)
		return;

	info = get_ltk_info(address, bdaddr_type, value);
	if (info == NULL)
		return;

	keys->keys = g_slist_append(keys->keys, info);

	if (g_slist_find_custom(adapter->devices, address,
					(GCompareFunc) device_address_cmp))
		return;

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);

	if (g_strcmp0(srcaddr, address) == 0)
		return;

	device = device_create(connection, adapter, address, bdaddr_type);
	if (device) {
		device_set_temporary(device, FALSE);
		adapter->devices = g_slist_append(adapter->devices, device);
	}
}

static void create_stored_device_from_blocked(char *key, char *value,
							void *user_data)
{
	struct btd_adapter *adapter = user_data;
	struct btd_device *device;

	if (g_slist_find_custom(adapter->devices,
				key, (GCompareFunc) device_address_cmp))
		return;

	device = device_create(connection, adapter, key, BDADDR_BREDR);
	if (device) {
		device_set_temporary(device, FALSE);
		adapter->devices = g_slist_append(adapter->devices, device);
	}
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

	device = device_create(connection, adapter, address, bdaddr_type);
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

	device_register_services(connection, device, services, -1);

	device_probe_drivers(device, uuids);

	g_slist_free(uuids);
}

static void smp_key_free(void *data)
{
	struct smp_ltk_info *info = data;

	g_free(info);
}

static void load_devices(struct btd_adapter *adapter)
{
	char filename[PATH_MAX + 1];
	char srcaddr[18];
	struct adapter_keys keys = { adapter, NULL };
	int err;

	ba2str(&adapter->bdaddr, srcaddr);

	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr, "profiles");
	textfile_foreach(filename, create_stored_device_from_profiles,
								adapter);

	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr, "primaries");
	textfile_foreach(filename, create_stored_device_from_primaries,
								adapter);

	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr, "linkkeys");
	textfile_foreach(filename, create_stored_device_from_linkkeys, &keys);

	err = adapter_ops->load_keys(adapter->dev_id, keys.keys,
							main_opts.debug_keys);
	if (err < 0)
		error("Unable to load keys to adapter_ops: %s (%d)",
							strerror(-err), -err);

	g_slist_free_full(keys.keys, g_free);
	keys.keys = NULL;

	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr, "longtermkeys");
	textfile_foreach(filename, create_stored_device_from_ltks, &keys);

	err = adapter_ops->load_ltks(adapter->dev_id, keys.keys);
	if (err < 0)
		error("Unable to load keys to adapter_ops: %s (%d)",
							strerror(-err), -err);
	g_slist_free_full(keys.keys, smp_key_free);
	keys.keys = NULL;

	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr, "blocked");
	textfile_foreach(filename, create_stored_device_from_blocked, adapter);
}

int btd_adapter_block_address(struct btd_adapter *adapter, bdaddr_t *bdaddr,
							uint8_t bdaddr_type)
{
	return adapter_ops->block_device(adapter->dev_id, bdaddr, bdaddr_type);
}

int btd_adapter_unblock_address(struct btd_adapter *adapter, bdaddr_t *bdaddr,
							uint8_t bdaddr_type)
{
	return adapter_ops->unblock_device(adapter->dev_id, bdaddr,
								bdaddr_type);
}

static void clear_blocked(struct btd_adapter *adapter)
{
	int err;

	err = adapter_ops->unblock_device(adapter->dev_id, BDADDR_ANY, 0);
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

	adapter->loaded_drivers = g_slist_prepend(adapter->loaded_drivers,
									driver);
}

static void load_drivers(struct btd_adapter *adapter)
{
	GSList *l;

	for (l = adapter_drivers; l; l = l->next)
		probe_driver(adapter, l->data);
}

static void load_connections(struct btd_adapter *adapter)
{
	GSList *l, *conns;
	int err;

	err = adapter_ops->get_conn_list(adapter->dev_id, &conns);
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

		device = adapter_get_device(connection, adapter, address);
		if (device)
			adapter_add_connection(adapter, device);
	}

	g_slist_free_full(conns, g_free);
}

static int get_discoverable_timeout(const char *src)
{
	int timeout;

	if (read_discoverable_timeout(src, &timeout) == 0)
		return timeout;

	return main_opts.discovto;
}

static int get_pairable_timeout(const char *src)
{
	int timeout;

	if (read_pairable_timeout(src, &timeout) == 0)
		return timeout;

	return main_opts.pairto;
}

static void call_adapter_powered_callbacks(struct btd_adapter *adapter,
						gboolean powered)
{
	GSList *l;

	for (l = adapter->powered_callbacks; l; l = l->next) {
		btd_adapter_powered_cb cb = l->data;

		cb(adapter, powered);
       }
}

static void emit_device_disappeared(gpointer data, gpointer user_data)
{
	struct remote_dev_info *dev = data;
	struct btd_adapter *adapter = user_data;
	char address[18];
	const char *paddr = address;

	ba2str(&dev->bdaddr, address);

	g_dbus_emit_signal(connection, adapter->path,
			ADAPTER_INTERFACE, "DeviceDisappeared",
			DBUS_TYPE_STRING, &paddr,
			DBUS_TYPE_INVALID);

	adapter->found_devices = g_slist_remove(adapter->found_devices, dev);
}

void btd_adapter_get_mode(struct btd_adapter *adapter, uint8_t *mode,
						uint8_t *on_mode,
						uint16_t *discoverable_timeout,
						gboolean *pairable)
{
	char str[14], address[18];

	ba2str(&adapter->bdaddr, address);

	if (mode) {
		if (main_opts.remember_powered == FALSE)
			*mode = main_opts.mode;
		else if (read_device_mode(address, str, sizeof(str)) == 0)
			*mode = get_mode(&adapter->bdaddr, str);
		else
			*mode = main_opts.mode;
	}

	if (on_mode)
		*on_mode = get_mode(&adapter->bdaddr, "on");

	if (discoverable_timeout)
		*discoverable_timeout = get_discoverable_timeout(address);

	if (pairable)
		*pairable = adapter->pairable;
}

void btd_adapter_get_class(struct btd_adapter *adapter, uint8_t *major,
								uint8_t *minor)
{
	uint8_t cls[3];

	if (read_local_class(&adapter->bdaddr, cls) < 0) {
		uint32_t class = htobl(main_opts.class);
		memcpy(cls, &class, 3);
	}

	*major = cls[1];
	*minor = cls[0];
}

const char *btd_adapter_get_name(struct btd_adapter *adapter)
{
	return adapter->name;
}

void btd_adapter_start(struct btd_adapter *adapter)
{
	char address[18];
	gboolean powered;

	ba2str(&adapter->bdaddr, address);

	adapter->dev_class = 0;
	adapter->off_requested = FALSE;
	adapter->up = TRUE;
	adapter->discov_timeout = get_discoverable_timeout(address);
	adapter->pairable_timeout = get_pairable_timeout(address);
	adapter->off_timer = 0;

	if (adapter->scan_mode & SCAN_INQUIRY)
		adapter->mode = MODE_DISCOVERABLE;
	else
		adapter->mode = MODE_CONNECTABLE;

	powered = TRUE;
	emit_property_changed(connection, adapter->path,
					ADAPTER_INTERFACE, "Powered",
					DBUS_TYPE_BOOLEAN, &powered);

	call_adapter_powered_callbacks(adapter, TRUE);

	adapter_ops->disable_cod_cache(adapter->dev_id);

	info("Adapter %s has been enabled", adapter->path);
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

static void unload_drivers(struct btd_adapter *adapter)
{
	g_slist_foreach(adapter->loaded_drivers, remove_driver, adapter);
	g_slist_free(adapter->loaded_drivers);
	adapter->loaded_drivers = NULL;
}

static void set_mode_complete(struct btd_adapter *adapter)
{
	struct session_req *pending;
	const char *modestr;
	int err;

	DBG("");

	if (adapter->mode == MODE_OFF) {
		g_slist_free_full(adapter->mode_sessions, session_free);
		adapter->mode_sessions = NULL;
	}

	if (adapter->pending_mode == NULL)
		return;

	pending = adapter->pending_mode;
	adapter->pending_mode = NULL;

	err = (pending->mode != adapter->mode) ? -EINVAL : 0;

	if (pending->msg != NULL) {
		DBusMessage *msg = pending->msg;
		DBusMessage *reply;

		if (err < 0)
			reply = btd_error_failed(msg, strerror(-err));
		else {
			if (strcmp(dbus_message_get_member(msg),
						"SetProperty") == 0)
				adapter->global_mode = adapter->mode;
			reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
		}

		g_dbus_send_message(connection, reply);
	}

	modestr = mode2str(adapter->mode);

	DBG("%s", modestr);

	/* restore if the mode doesn't matches the pending */
	if (err != 0) {
		write_device_mode(&adapter->bdaddr, modestr);
		error("unable to set mode: %s", mode2str(pending->mode));
	}

	session_unref(pending);
}

int btd_adapter_stop(struct btd_adapter *adapter)
{
	gboolean prop_false = FALSE;

	/* check pending requests */
	reply_pending_requests(adapter);

	adapter->up = FALSE;

	stop_discovery(adapter);

	if (adapter->disc_sessions) {
		g_slist_free_full(adapter->disc_sessions, session_free);
		adapter->disc_sessions = NULL;
	}

	while (adapter->connections) {
		struct btd_device *device = adapter->connections->data;
		adapter_remove_connection(adapter, device);
	}

	if (adapter->scan_mode == (SCAN_PAGE | SCAN_INQUIRY))
		emit_property_changed(connection, adapter->path,
					ADAPTER_INTERFACE, "Discoverable",
					DBUS_TYPE_BOOLEAN, &prop_false);

	if ((adapter->scan_mode & SCAN_PAGE) && adapter->pairable == TRUE)
		emit_property_changed(connection, adapter->path,
					ADAPTER_INTERFACE, "Pairable",
					DBUS_TYPE_BOOLEAN, &prop_false);

	if (adapter->discovering)
		emit_property_changed(connection, adapter->path,
					ADAPTER_INTERFACE, "Discovering",
					DBUS_TYPE_BOOLEAN, &prop_false);

	emit_property_changed(connection, adapter->path, ADAPTER_INTERFACE,
				"Powered", DBUS_TYPE_BOOLEAN, &prop_false);

	adapter->discovering = FALSE;
	adapter->scan_mode = SCAN_DISABLED;
	adapter->mode = MODE_OFF;
	adapter->off_requested = FALSE;

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

	if (adapter->off_timer)
		off_timer_remove(adapter);

	sdp_list_free(adapter->services, NULL);

	g_slist_free_full(adapter->found_devices, dev_info_free);

	g_slist_free(adapter->oor_devices);

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

	g_dbus_unregister_interface(connection, path, ADAPTER_INTERFACE);

	g_free(path);
}

gboolean adapter_init(struct btd_adapter *adapter, gboolean up)
{
	adapter->up = up;

	adapter->allow_name_changes = TRUE;

	adapter_ops->read_bdaddr(adapter->dev_id, &adapter->bdaddr);

	if (bacmp(&adapter->bdaddr, BDADDR_ANY) == 0) {
		error("No address available for hci%d", adapter->dev_id);
		return FALSE;
	}

	sdp_init_services_list(&adapter->bdaddr);

	if (main_opts.gatt_enabled)
		btd_adapter_gatt_server_start(adapter);

	load_drivers(adapter);
	clear_blocked(adapter);
	load_devices(adapter);

	/* Set pairable mode */
	if (read_device_pairable(&adapter->bdaddr, &adapter->pairable) < 0)
		adapter->pairable = TRUE;

	/* retrieve the active connections: address the scenario where
	 * the are active connections before the daemon've started */
	load_connections(adapter);

	adapter->initialized = TRUE;

	return TRUE;
}

struct btd_adapter *adapter_create(DBusConnection *conn, int id)
{
	char path[MAX_PATH_LENGTH];
	struct btd_adapter *adapter;
	const char *base_path = manager_get_base_path();

	if (!connection)
		connection = conn;

	adapter = g_try_new0(struct btd_adapter, 1);
	if (!adapter) {
		error("adapter_create: failed to alloc memory for hci%d", id);
		return NULL;
	}

	adapter->dev_id = id;

	snprintf(path, sizeof(path), "%s/hci%d", base_path, id);
	adapter->path = g_strdup(path);

	if (!g_dbus_register_interface(conn, path, ADAPTER_INTERFACE,
					adapter_methods, adapter_signals, NULL,
					adapter, adapter_free)) {
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

	for (l = adapter->devices; l; l = l->next)
		device_remove(l->data, FALSE);
	g_slist_free(adapter->devices);

	unload_drivers(adapter);
	if (main_opts.gatt_enabled)
		btd_adapter_gatt_server_stop(adapter);

	g_slist_free(adapter->pin_callbacks);

	/* Return adapter to down state if it was not up on init */
	adapter_ops->restore_powered(adapter->dev_id);
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

void adapter_get_address(struct btd_adapter *adapter, bdaddr_t *bdaddr)
{
	bacpy(bdaddr, &adapter->bdaddr);
}

void adapter_set_allow_name_changes(struct btd_adapter *adapter,
						gboolean allow_name_changes)
{
	adapter->allow_name_changes = allow_name_changes;
}

void adapter_set_discovering(struct btd_adapter *adapter,
						gboolean discovering)
{
	const char *path = adapter->path;

	adapter->discovering = discovering;

	emit_property_changed(connection, path,
				ADAPTER_INTERFACE, "Discovering",
				DBUS_TYPE_BOOLEAN, &discovering);

	if (discovering)
		return;

	g_slist_foreach(adapter->oor_devices, emit_device_disappeared, adapter);
	g_slist_free_full(adapter->oor_devices, dev_info_free);
	adapter->oor_devices = g_slist_copy(adapter->found_devices);

	if (!adapter_has_discov_sessions(adapter) || adapter->discov_suspended)
		return;

	DBG("hci%u restarting discovery, disc_sessions %u", adapter->dev_id,
					g_slist_length(adapter->disc_sessions));

	adapter->discov_id = g_idle_add(discovery_cb, adapter);
}

static void suspend_discovery(struct btd_adapter *adapter)
{
	if (adapter->disc_sessions == NULL || adapter->discov_suspended)
		return;

	DBG("Suspending discovery");

	if (adapter->oor_devices) {
		g_slist_free(adapter->oor_devices);
		adapter->oor_devices = NULL;
	}

	adapter->discov_suspended = TRUE;

	if (adapter->discov_id > 0) {
		g_source_remove(adapter->discov_id);
		adapter->discov_id = 0;
	} else
		adapter_ops->stop_discovery(adapter->dev_id);
}

static int found_device_cmp(gconstpointer a, gconstpointer b)
{
	const struct remote_dev_info *d = a;
	const bdaddr_t *bdaddr = b;

	if (bacmp(bdaddr, BDADDR_ANY) == 0)
		return 0;

	return bacmp(&d->bdaddr, bdaddr);
}

struct remote_dev_info *adapter_search_found_devices(struct btd_adapter *adapter,
							bdaddr_t *bdaddr)
{
	GSList *l;

	l = g_slist_find_custom(adapter->found_devices, bdaddr,
							found_device_cmp);
	if (l)
		return l->data;

	return NULL;
}

static int dev_rssi_cmp(struct remote_dev_info *d1, struct remote_dev_info *d2)
{
	int rssi1, rssi2;

	rssi1 = d1->rssi < 0 ? -d1->rssi : d1->rssi;
	rssi2 = d2->rssi < 0 ? -d2->rssi : d2->rssi;

	return rssi1 - rssi2;
}

static void append_dict_valist(DBusMessageIter *iter,
					const char *first_key,
					va_list var_args)
{
	DBusMessageIter dict;
	const char *key;
	int type;
	int n_elements;
	void *val;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	key = first_key;
	while (key) {
		type = va_arg(var_args, int);
		val = va_arg(var_args, void *);
		if (type == DBUS_TYPE_ARRAY) {
			n_elements = va_arg(var_args, int);
			if (n_elements > 0)
				dict_append_array(&dict, key, DBUS_TYPE_STRING,
						val, n_elements);
		} else
			dict_append_entry(&dict, key, type, val);
		key = va_arg(var_args, char *);
	}

	dbus_message_iter_close_container(iter, &dict);
}

static void emit_device_found(const char *path, const char *address,
				const char *first_key, ...)
{
	DBusMessage *signal;
	DBusMessageIter iter;
	va_list var_args;

	signal = dbus_message_new_signal(path, ADAPTER_INTERFACE,
					"DeviceFound");
	if (!signal) {
		error("Unable to allocate new %s.DeviceFound signal",
				ADAPTER_INTERFACE);
		return;
	}
	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &address);

	va_start(var_args, first_key);
	append_dict_valist(&iter, first_key, var_args);
	va_end(var_args);

	g_dbus_send_message(connection, signal);
}

static char **strlist2array(GSList *list)
{
	unsigned int i, n;
	char **array;

	if (list == NULL)
		return NULL;

	n = g_slist_length(list);
	array = g_new0(char *, n + 1);

	for (i = 0; list; list = list->next, i++)
		array[i] = g_strdup((const gchar *) list->data);

	return array;
}

void adapter_emit_device_found(struct btd_adapter *adapter,
						struct remote_dev_info *dev)
{
	struct btd_device *device;
	char peer_addr[18], local_addr[18];
	const char *icon, *paddr = peer_addr;
	dbus_bool_t paired = FALSE, trusted = FALSE;
	dbus_int16_t rssi = dev->rssi;
	char *alias;
	size_t uuid_count;

	ba2str(&dev->bdaddr, peer_addr);
	ba2str(&adapter->bdaddr, local_addr);

	device = adapter_find_device(adapter, paddr);
	if (device) {
		paired = device_is_paired(device);
		trusted = device_is_trusted(device);
	}

	/* The uuids string array is updated only if necessary */
	uuid_count = g_slist_length(dev->services);
	if (dev->services && dev->uuid_count != uuid_count) {
		g_strfreev(dev->uuids);
		dev->uuids = strlist2array(dev->services);
		dev->uuid_count = uuid_count;
	}

	if (!dev->alias) {
		if (!dev->name) {
			alias = g_strdup(peer_addr);
			g_strdelimit(alias, ":", '-');
		} else
			alias = g_strdup(dev->name);
	} else
		alias = g_strdup(dev->alias);

	if (dev->bdaddr_type != BDADDR_BREDR) {
		gboolean broadcaster;
		uint16_t app;

		if (dev->flags & (EIR_LIM_DISC | EIR_GEN_DISC))
			broadcaster = FALSE;
		else
			broadcaster = TRUE;

		dev->legacy = FALSE;

		if (read_remote_appearance(&adapter->bdaddr, &dev->bdaddr,
						dev->bdaddr_type, &app) == 0)
			icon = gap_appearance_to_icon(app);
		else
			icon = NULL;

		emit_device_found(adapter->path, paddr,
				"Address", DBUS_TYPE_STRING, &paddr,
				"Class", DBUS_TYPE_UINT32, &dev->class,
				"Icon", DBUS_TYPE_STRING, &icon,
				"RSSI", DBUS_TYPE_INT16, &rssi,
				"Name", DBUS_TYPE_STRING, &dev->name,
				"Alias", DBUS_TYPE_STRING, &alias,
				"LegacyPairing", DBUS_TYPE_BOOLEAN, &dev->legacy,
				"Paired", DBUS_TYPE_BOOLEAN, &paired,
				"Broadcaster", DBUS_TYPE_BOOLEAN, &broadcaster,
				"UUIDs", DBUS_TYPE_ARRAY, &dev->uuids, uuid_count,
				NULL);
	} else {
		icon = class_to_icon(dev->class);

		emit_device_found(adapter->path, paddr,
				"Address", DBUS_TYPE_STRING, &paddr,
				"Class", DBUS_TYPE_UINT32, &dev->class,
				"Icon", DBUS_TYPE_STRING, &icon,
				"RSSI", DBUS_TYPE_INT16, &rssi,
				"Name", DBUS_TYPE_STRING, &dev->name,
				"Alias", DBUS_TYPE_STRING, &alias,
				"LegacyPairing", DBUS_TYPE_BOOLEAN, &dev->legacy,
				"Paired", DBUS_TYPE_BOOLEAN, &paired,
				"Trusted", DBUS_TYPE_BOOLEAN, &trusted,
				"UUIDs", DBUS_TYPE_ARRAY, &dev->uuids, uuid_count,
				NULL);
	}

	g_free(alias);
}

static struct remote_dev_info *found_device_new(const bdaddr_t *bdaddr,
					uint8_t bdaddr_type, const char *name,
					const char *alias, uint32_t class,
					gboolean legacy, int flags)
{
	struct remote_dev_info *dev;

	dev = g_new0(struct remote_dev_info, 1);
	bacpy(&dev->bdaddr, bdaddr);
	dev->bdaddr_type = bdaddr_type;
	dev->name = g_strdup(name);
	dev->alias = g_strdup(alias);
	dev->class = class;
	dev->legacy = legacy;
	if (flags >= 0)
		dev->flags = flags;

	return dev;
}

static void remove_same_uuid(gpointer data, gpointer user_data)
{
	struct remote_dev_info *dev = user_data;
	GSList *l;

	for (l = dev->services; l; l = l->next) {
		char *current_uuid = l->data;
		char *new_uuid = data;

		if (strcmp(current_uuid, new_uuid) == 0) {
			g_free(current_uuid);
			dev->services = g_slist_delete_link(dev->services, l);
			break;
		}
	}
}

static void dev_prepend_uuid(gpointer data, gpointer user_data)
{
	struct remote_dev_info *dev = user_data;
	char *new_uuid = data;

	dev->services = g_slist_prepend(dev->services, g_strdup(new_uuid));
}

static gboolean pairing_is_legacy(bdaddr_t *local, bdaddr_t *peer,
					const uint8_t *eir, const char *name)
{
	unsigned char features[8];

	if (eir)
		return FALSE;

	if (name == NULL)
		return TRUE;

	if (read_remote_features(local, peer, NULL, features) < 0)
		return TRUE;

	if (features[0] & 0x01)
		return FALSE;
	else
		return TRUE;
}

static char *read_stored_data(bdaddr_t *local, bdaddr_t *peer, const char *file)
{
	char local_addr[18], peer_addr[18], filename[PATH_MAX + 1];

	ba2str(local, local_addr);
	ba2str(peer, peer_addr);

	create_name(filename, PATH_MAX, STORAGEDIR, local_addr, file);

	return textfile_get(filename, peer_addr);
}

void adapter_update_found_devices(struct btd_adapter *adapter,
					bdaddr_t *bdaddr, uint8_t bdaddr_type,
					int8_t rssi, uint8_t confirm_name,
					uint8_t *data, uint8_t data_len)
{
	struct remote_dev_info *dev;
	struct eir_data eir_data;
	char *alias, *name;
	gboolean legacy, name_known;
	uint32_t dev_class;
	int err;

	memset(&eir_data, 0, sizeof(eir_data));
	err = eir_parse(&eir_data, data, data_len);
	if (err < 0) {
		error("Error parsing EIR data: %s (%d)", strerror(-err), -err);
		return;
	}

	dev_class = eir_data.dev_class[0] | (eir_data.dev_class[1] << 8) |
						(eir_data.dev_class[2] << 16);
	if (dev_class != 0)
		write_remote_class(&adapter->bdaddr, bdaddr, dev_class);

	if (eir_data.appearance != 0)
		write_remote_appearance(&adapter->bdaddr, bdaddr, bdaddr_type,
							eir_data.appearance);

	if (eir_data.name != NULL && eir_data.name_complete)
		write_device_name(&adapter->bdaddr, bdaddr, eir_data.name);

	dev = adapter_search_found_devices(adapter, bdaddr);
	if (dev) {
		adapter->oor_devices = g_slist_remove(adapter->oor_devices,
							dev);

		/* If an existing device had no name but the newly received EIR
		 * data has (complete or not), we want to present it to the
		 * user. */
		if (dev->name == NULL && eir_data.name != NULL) {
			dev->name = g_strdup(eir_data.name);
			goto done;
		}

		if (dev->rssi != rssi)
			goto done;

		eir_data_free(&eir_data);

		return;
	}

	/* New device in the discovery session */

	name = read_stored_data(&adapter->bdaddr, bdaddr, "names");

	if (bdaddr_type == BDADDR_BREDR) {
		legacy = pairing_is_legacy(&adapter->bdaddr, bdaddr, data,
									name);

		if (!name && main_opts.name_resolv &&
				adapter_has_discov_sessions(adapter))
			name_known = FALSE;
		else
			name_known = TRUE;
	} else {
		legacy = FALSE;
		name_known = TRUE;
	}

	if (confirm_name)
		adapter_ops->confirm_name(adapter->dev_id, bdaddr, bdaddr_type,
								name_known);

	alias = read_stored_data(&adapter->bdaddr, bdaddr, "aliases");

	dev = found_device_new(bdaddr, bdaddr_type, name, alias, dev_class,
						legacy, eir_data.flags);
	free(name);
	free(alias);

	adapter->found_devices = g_slist_prepend(adapter->found_devices, dev);

done:
	dev->rssi = rssi;

	adapter->found_devices = g_slist_sort(adapter->found_devices,
						(GCompareFunc) dev_rssi_cmp);

	g_slist_foreach(eir_data.services, remove_same_uuid, dev);
	g_slist_foreach(eir_data.services, dev_prepend_uuid, dev);

	adapter_emit_device_found(adapter, dev);

	eir_data_free(&eir_data);
}

void adapter_mode_changed(struct btd_adapter *adapter, uint8_t scan_mode)
{
	const gchar *path = adapter_get_path(adapter);
	gboolean discoverable, pairable;

	DBG("old 0x%02x new 0x%02x", adapter->scan_mode, scan_mode);

	if (adapter->scan_mode == scan_mode)
		return;

	switch (scan_mode) {
	case SCAN_DISABLED:
		adapter->mode = MODE_OFF;
		discoverable = FALSE;
		pairable = FALSE;
		break;
	case SCAN_PAGE:
		adapter->mode = MODE_CONNECTABLE;
		discoverable = FALSE;
		pairable = adapter->pairable;
		break;
	case (SCAN_PAGE | SCAN_INQUIRY):
		adapter->mode = MODE_DISCOVERABLE;
		discoverable = TRUE;
		pairable = adapter->pairable;
		break;
	default:
		/* ignore, reserved */
		return;
	}

	/* If page scanning gets toggled emit the Pairable property */
	if ((adapter->scan_mode & SCAN_PAGE) != (scan_mode & SCAN_PAGE))
		emit_property_changed(connection, adapter->path,
					ADAPTER_INTERFACE, "Pairable",
					DBUS_TYPE_BOOLEAN, &pairable);

	emit_property_changed(connection, path,
				ADAPTER_INTERFACE, "Discoverable",
				DBUS_TYPE_BOOLEAN, &discoverable);

	adapter->scan_mode = scan_mode;

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

	device_add_connection(device, connection);

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

	device_remove_connection(device, connection);

	adapter->connections = g_slist_remove(adapter->connections, device);

	if (device_is_authenticating(device))
		device_cancel_authentication(device, TRUE);

	if (device_is_temporary(device)) {
		const char *path = device_get_path(device);

		DBG("Removing temporary device %s", path);
		adapter_remove_device(connection, adapter, device, TRUE);
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
	adapter->loaded_drivers = g_slist_remove(adapter->loaded_drivers, data);
}

void btd_unregister_adapter_driver(struct btd_adapter_driver *driver)
{
	adapter_drivers = g_slist_remove(adapter_drivers, driver);

	manager_foreach_adapter(unload_driver, driver);
}

static void agent_auth_cb(struct agent *agent, DBusError *derr,
							void *user_data)
{
	struct service_auth *auth = user_data;

	device_set_authorizing(auth->device, FALSE);

	auth->cb(derr, auth->user_data);
}

static gboolean auth_idle_cb(gpointer user_data)
{
	struct service_auth *auth = user_data;
	struct btd_adapter *adapter = auth->adapter;

	adapter->auth_idle_id = 0;

	auth->cb(NULL, auth->user_data);

	return FALSE;
}

static int adapter_authorize(struct btd_adapter *adapter, const bdaddr_t *dst,
					const char *uuid, service_auth_cb cb,
					void *user_data)
{
	struct service_auth *auth;
	struct btd_device *device;
	struct agent *agent;
	char address[18];
	const gchar *dev_path;
	int err;

	ba2str(dst, address);
	device = adapter_find_device(adapter, address);
	if (!device)
		return -EPERM;

	/* Device connected? */
	if (!g_slist_find(adapter->connections, device))
		error("Authorization request for non-connected device!?");

	if (adapter->auth_idle_id)
		return -EBUSY;

	auth = g_try_new0(struct service_auth, 1);
	if (!auth)
		return -ENOMEM;

	auth->cb = cb;
	auth->user_data = user_data;
	auth->device = device;
	auth->adapter = adapter;

	if (device_is_trusted(device) == TRUE) {
		adapter->auth_idle_id = g_idle_add_full(G_PRIORITY_DEFAULT_IDLE,
							auth_idle_cb, auth,
							g_free);
		return 0;
	}

	agent = device_get_agent(device);
	if (!agent) {
		warn("Can't find device agent");
		g_free(auth);
		return -EPERM;
	}

	dev_path = device_get_path(device);

	err = agent_authorize(agent, dev_path, uuid, agent_auth_cb, auth, g_free);
	if (err < 0)
		g_free(auth);
	else
		device_set_authorizing(device, TRUE);

	return err;
}

int btd_request_authorization(const bdaddr_t *src, const bdaddr_t *dst,
					const char *uuid, service_auth_cb cb,
					void *user_data)
{
	struct btd_adapter *adapter;
	GSList *l;

	if (bacmp(src, BDADDR_ANY) != 0) {
		adapter = manager_find_adapter(src);
		if (!adapter)
			return -EPERM;

		return adapter_authorize(adapter, dst, uuid, cb, user_data);
	}

	for (l = manager_get_adapters(); l != NULL; l = g_slist_next(l)) {
		int err;

		adapter = l->data;

		err = adapter_authorize(adapter, dst, uuid, cb, user_data);
		if (err == 0)
			return 0;
	}

	return -EPERM;
}

int btd_cancel_authorization(const bdaddr_t *src, const bdaddr_t *dst)
{
	struct btd_adapter *adapter = manager_find_adapter(src);
	struct btd_device *device;
	struct agent *agent;
	char address[18];
	int err;

	if (!adapter)
		return -EPERM;

	ba2str(dst, address);
	device = adapter_find_device(adapter, address);
	if (!device)
		return -EPERM;

	if (adapter->auth_idle_id) {
		g_source_remove(adapter->auth_idle_id);
		adapter->auth_idle_id = 0;
		return 0;
	}

	/*
	 * FIXME: Cancel fails if authorization is requested to adapter's
	 * agent and in the meanwhile CreatePairedDevice is called.
	 */

	agent = device_get_agent(device);
	if (!agent)
		return -EPERM;

	err = agent_cancel(agent);

	if (err == 0)
		device_set_authorizing(device, FALSE);

	return err;
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

	adapter_any_path = g_strdup_printf("%s/any", manager_get_base_path());

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
	char mode[14], address[18];

	if (!adapter_ops)
		return -EINVAL;

	if (!main_opts.remember_powered)
		return -EINVAL;

	if (adapter->up)
		return 0;

	ba2str(&adapter->bdaddr, address);
	if (read_device_mode(address, mode, sizeof(mode)) == 0 &&
						g_str_equal(mode, "off"))
		return 0;

	return adapter_ops->set_powered(adapter->dev_id, TRUE);
}

static gboolean switch_off_timeout(gpointer user_data)
{
	struct btd_adapter *adapter = user_data;

	adapter_ops->set_powered(adapter->dev_id, FALSE);
	adapter->off_timer = 0;

	return FALSE;
}

int btd_adapter_switch_online(struct btd_adapter *adapter)
{
	if (!adapter_ops)
		return -EINVAL;

	if (adapter->up)
		return -EALREADY;

	if (adapter->off_timer)
		off_timer_remove(adapter);

	return adapter_ops->set_powered(adapter->dev_id, TRUE);
}

int btd_adapter_switch_offline(struct btd_adapter *adapter)
{
	if (!adapter_ops)
		return -EINVAL;

	if (!adapter->up)
		return -EALREADY;

	if (adapter->off_timer)
		return 0;

	adapter->global_mode = MODE_OFF;

	if (adapter->connections == NULL)
		return adapter_ops->set_powered(adapter->dev_id, FALSE);

	g_slist_foreach(adapter->connections,
				(GFunc) device_request_disconnect, NULL);

	adapter->off_timer = g_timeout_add_seconds(OFF_TIMER,
						switch_off_timeout, adapter);

	return 0;
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

static void set_auto_connect(gpointer data, gpointer user_data)
{
	struct btd_device *device = data;

	device_set_auto_connect(device, TRUE);
}

void btd_adapter_enable_auto_connect(struct btd_adapter *adapter)
{
	if (!adapter->up)
		return;

	DBG("Enabling automatic connections");

	if (adapter->auto_timeout_id)
		return;

	g_slist_foreach(adapter->devices, set_auto_connect, NULL);

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
	bdaddr_t sba, dba;
	ssize_t ret;

	for (l = adapter->pin_callbacks; l != NULL; l = g_slist_next(l)) {
		cb = l->data;
		ret = cb(adapter, dev, pin_buf, display);
		if (ret > 0)
			return ret;
	}

	adapter_get_address(adapter, &sba);
	device_get_address(dev, &dba, NULL);

	return read_pin_code(&sba, &dba, pin_buf);
}

int btd_register_adapter_ops(struct btd_adapter_ops *ops, gboolean priority)
{
	if (ops->setup == NULL)
		return -EINVAL;

	if (priority)
		ops_candidates = g_slist_prepend(ops_candidates, ops);
	else
		ops_candidates = g_slist_append(ops_candidates, ops);

	return 0;
}

void btd_adapter_cleanup_ops(struct btd_adapter_ops *ops)
{
	ops_candidates = g_slist_remove(ops_candidates, ops);
	ops->cleanup();

	if (adapter_ops == ops)
		adapter_ops = NULL;
}

int adapter_ops_setup(void)
{
	GSList *l;
	int ret;

	if (!ops_candidates)
		return -EINVAL;

	for (l = ops_candidates; l != NULL; l = g_slist_next(l)) {
		struct btd_adapter_ops *ops = l->data;

		ret = ops->setup();
		if (ret < 0)
			continue;

		adapter_ops = ops;
		break;
	}

	return ret;
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
	if (!adapter_ops)
		return -EINVAL;

	if (!adapter->up)
		return -EINVAL;

	return adapter_ops->set_fast_connectable(adapter->dev_id, enable);
}

int btd_adapter_read_clock(struct btd_adapter *adapter, bdaddr_t *bdaddr,
				int which, int timeout, uint32_t *clock,
				uint16_t *accuracy)
{
	if (!adapter_ops)
		return -EINVAL;

	if (!adapter->up)
		return -EINVAL;

	return adapter_ops->read_clock(adapter->dev_id, bdaddr, which,
						timeout, clock, accuracy);
}

int btd_adapter_disconnect_device(struct btd_adapter *adapter,
					bdaddr_t *bdaddr, uint8_t bdaddr_type)

{
	return adapter_ops->disconnect(adapter->dev_id, bdaddr, bdaddr_type);
}

int btd_adapter_remove_bonding(struct btd_adapter *adapter, bdaddr_t *bdaddr,
							uint8_t bdaddr_type)
{
	return adapter_ops->remove_bonding(adapter->dev_id, bdaddr,
								bdaddr_type);
}

int btd_adapter_pincode_reply(struct btd_adapter *adapter, bdaddr_t *bdaddr,
					const char *pin, size_t pin_len)
{
	return adapter_ops->pincode_reply(adapter->dev_id, bdaddr, pin,
								pin_len);
}

int btd_adapter_confirm_reply(struct btd_adapter *adapter, bdaddr_t *bdaddr,
					uint8_t bdaddr_type, gboolean success)
{
	return adapter_ops->confirm_reply(adapter->dev_id, bdaddr, bdaddr_type,
								success);
}

int btd_adapter_passkey_reply(struct btd_adapter *adapter, bdaddr_t *bdaddr,
					uint8_t bdaddr_type, uint32_t passkey)
{
	return adapter_ops->passkey_reply(adapter->dev_id, bdaddr, bdaddr_type,
								passkey);
}

int btd_adapter_encrypt_link(struct btd_adapter *adapter, bdaddr_t *bdaddr,
					bt_hci_result_t cb, gpointer user_data)
{
	return adapter_ops->encrypt_link(adapter->dev_id, bdaddr, cb, user_data);
}

int btd_adapter_set_did(struct btd_adapter *adapter, uint16_t vendor,
					uint16_t product, uint16_t version,
					uint16_t source)
{
	return adapter_ops->set_did(adapter->dev_id, vendor, product, version,
								source);
}

int adapter_create_bonding(struct btd_adapter *adapter, bdaddr_t *bdaddr,
					uint8_t addr_type, uint8_t io_cap)
{
	suspend_discovery(adapter);
	return adapter_ops->create_bonding(adapter->dev_id, bdaddr,
						addr_type, io_cap);
}

int adapter_cancel_bonding(struct btd_adapter *adapter, bdaddr_t *bdaddr)
{
	return adapter_ops->cancel_bonding(adapter->dev_id, bdaddr);
}

void adapter_bonding_complete(struct btd_adapter *adapter, bdaddr_t *bdaddr,
								uint8_t status)
{
	struct btd_device *device;
	char addr[18];

	ba2str(bdaddr, addr);
	if (status == 0)
		device = adapter_get_device(connection, adapter, addr);
	else
		device = adapter_find_device(adapter, addr);

	if (device != NULL)
		device_bonding_complete(device, status);

	if (adapter->discov_suspended) {
		adapter->discov_suspended = FALSE;
		adapter_ops->start_discovery(adapter->dev_id);
	}
}

int btd_adapter_read_local_oob_data(struct btd_adapter *adapter)
{
	return adapter_ops->read_local_oob_data(adapter->dev_id);
}

int btd_adapter_add_remote_oob_data(struct btd_adapter *adapter,
			bdaddr_t *bdaddr, uint8_t *hash, uint8_t *randomizer)
{
	return adapter_ops->add_remote_oob_data(adapter->dev_id, bdaddr, hash,
								randomizer);
}

int btd_adapter_remove_remote_oob_data(struct btd_adapter *adapter,
							bdaddr_t *bdaddr)
{
	return adapter_ops->remove_remote_oob_data(adapter->dev_id, bdaddr);
}
