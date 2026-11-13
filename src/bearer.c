// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  Intel Corporation
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/mgmt.h"
#include "bluetooth/uuid.h"

#include "gdbus/gdbus.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/timeout.h"

#include "log.h"
#include "error.h"
#include "btd.h"
#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "service.h"
#include "dbus-common.h"
#include "bearer.h"

#define DISCONNECT_TIMER	2

struct btd_bearer {
	struct btd_device *device;
	uint8_t type;
	const char *path;
	unsigned int disconn_timer;
	struct queue *disconnects; /* disconnects message */

	/* Connect() is defined as a single in-flight operation. To preserve
	 * the API semantics of org.bluez.Device1.Connect(), we do not queue
	 * additional connect messages.
	 */
	DBusMessage *connect; /* connect message */

	/* ReadRSSI calls waiting for the Get Connection Information reply */
	unsigned int conn_info_id;
	struct queue *rssi_reads;

	/* LE connection parameters, only valid while connected */
	bool conn_params;
	uint32_t interval; /* in microseconds */
	uint16_t latency;
	uint16_t supv_timeout; /* in milliseconds */
	uint16_t subrate;
};

static void bearer_free_dbus_message(void *data)
{
	dbus_message_unref((DBusMessage *)data);
}

static void bearer_free(void *data)
{
	struct btd_bearer *bearer = data;

	if (bearer->disconn_timer)
		timeout_remove(bearer->disconn_timer);

	free(bearer);
}

static void bearer_disconnect_service(struct btd_service *service,
						void *user_data)
{
	uint8_t bdaddr_type = *(uint8_t *)user_data;
	struct btd_profile *profile = btd_service_get_profile(service);
	struct btd_device *device = btd_service_get_device(service);

	if (!profile || !device)
		return;

	if (bdaddr_type == BDADDR_BREDR) {
		if (profile->bearer == BTD_PROFILE_BEARER_LE)
			return;
	} else {
		if (profile->bearer == BTD_PROFILE_BEARER_BREDR)
			return;
	}

	DBG("Disconnecting profile %s for bearer addr type %u",
	profile->name ?: "(unknown)", bdaddr_type);

	btd_service_disconnect(service);
}


static bool bearer_disconnect_link(gpointer user_data)
{
	struct btd_bearer *bearer = user_data;
	struct btd_device *device = bearer->device;

	bearer->disconn_timer = 0;

	if (btd_device_bdaddr_type_connected(device, bearer->type))
		btd_adapter_disconnect_device(device_get_adapter(device),
						device_get_address(device),
						bearer->type);
	return FALSE;
}

static DBusMessage *bearer_connect(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct btd_bearer *bearer = user_data;
	struct btd_device *device = bearer->device;
	DBusMessage *reply;
	int err;

	if (btd_device_bdaddr_type_connected(device, bearer->type)) {
		if (msg)
			return btd_error_already_connected(msg);
		return NULL;
	}

	if (device_is_bonding(device, NULL)) {
		if (msg)
			return btd_error_in_progress(msg);
		return NULL;
	}

	if (device_is_connecting(device) ||
		bearer->connect) {
		if (msg)
			return btd_error_in_progress(msg);
		return NULL;
	}

	if (bearer->type == BDADDR_BREDR) {
		reply = device_connect_profiles(device, BDADDR_BREDR, msg,
									NULL);
		if (reply)
			return reply;
	} else {
		btd_device_set_temporary(device, false);
		device_resume_auto_connect(device);
		err = device_connect_le(device);
		if (err < 0)
			return btd_error_failed(msg, strerror(-err));
	}

	if (msg)
		bearer->connect = dbus_message_ref(msg);

	return NULL;
}

static DBusMessage *bearer_disconnect(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct btd_bearer *bearer = user_data;
	struct btd_device *device = bearer->device;

	if (!btd_device_bdaddr_type_connected(device, bearer->type)) {
		if (msg)
			return btd_error_not_connected(msg);
		return NULL;
	}

	/* org.bluez.Device1.Disconnect() is in progress. Since it tears down
	 * both LE and BR/EDR bearers, it takes precedence over bearer-level
	 * disconnects. Ignore any bearer-specific disconnect requests here.
	 */
	if (device_is_disconnecting(device)) {
		if (msg)
			return btd_error_in_progress(msg);
		return NULL;
	}

	/* Auto-connect is only done over LE */
	if (bearer->type != BDADDR_BREDR)
		device_pause_auto_connect(device);

	if (msg)
		queue_push_tail(bearer->disconnects, dbus_message_ref(msg));

	device_cancel_bonding(device, MGMT_STATUS_DISCONNECTED);

	device_cancel_browse(device, bearer->type);

	btd_device_foreach_service(device, bearer_disconnect_service,
							&bearer->type);

	device_remove_pending_services(device, bearer->type);

	if (bearer->disconn_timer)
		return NULL;

	bearer->disconn_timer = timeout_add_seconds(DISCONNECT_TIMER,
							bearer_disconnect_link,
							bearer, NULL);

	return NULL;
}

static DBusMessage *rssi_reply(struct btd_bearer *bearer, DBusMessage *msg,
					uint8_t status, uint16_t length,
					const struct mgmt_rp_get_conn_info *rp)
{
	dbus_int16_t rssi;

	/* The kernel reports the connection as soon as it is established, but
	 * only answers once it has set it up, e.g. read the remote features.
	 */
	if (status == MGMT_STATUS_NOT_CONNECTED) {
		if (btd_device_bdaddr_type_connected(bearer->device,
							bearer->type))
			return btd_error_not_ready(msg);

		return btd_error_not_connected(msg);
	}

	if (status != MGMT_STATUS_SUCCESS)
		return btd_error_failed(msg, mgmt_errstr(status));

	if (length < sizeof(*rp))
		return btd_error_failed(msg, "Invalid response");

	/* 127 means the controller has no RSSI for the connection */
	if (rp->rssi == 127)
		return btd_error_not_available(msg);

	rssi = rp->rssi;

	return g_dbus_create_reply(msg, DBUS_TYPE_INT16, &rssi,
							DBUS_TYPE_INVALID);
}

static void conn_info_complete(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct btd_bearer *bearer = user_data;
	DBusMessage *msg;

	bearer->conn_info_id = 0;

	while ((msg = queue_pop_head(bearer->rssi_reads))) {
		g_dbus_send_message(btd_get_dbus_connection(),
				rssi_reply(bearer, msg, status, length, param));
		dbus_message_unref(msg);
	}
}

static DBusMessage *bearer_read_rssi(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct btd_bearer *bearer = user_data;
	struct btd_device *device = bearer->device;

	if (!btd_device_bdaddr_type_connected(device, bearer->type))
		return btd_error_not_connected(msg);

	/* Calls made while a read is pending get the same result */
	if (!bearer->conn_info_id) {
		bearer->conn_info_id = btd_adapter_get_conn_info(
					device_get_adapter(device),
					device_get_address(device),
					device_get_le_address_type(device),
					conn_info_complete, bearer);
		if (!bearer->conn_info_id)
			return btd_error_failed(msg, "Unable to read RSSI");
	}

	queue_push_tail(bearer->rssi_reads, dbus_message_ref(msg));

	return NULL;
}

static const GDBusMethodTable bearer_bredr_methods[] = {
	{ GDBUS_ASYNC_METHOD("Connect", NULL, NULL, bearer_connect) },
	{ GDBUS_ASYNC_METHOD("Disconnect", NULL, NULL,
						bearer_disconnect) },
	{}
};

static const GDBusMethodTable bearer_le_methods[] = {
	{ GDBUS_ASYNC_METHOD("Connect", NULL, NULL, bearer_connect) },
	{ GDBUS_ASYNC_METHOD("Disconnect", NULL, NULL,
						bearer_disconnect) },
	{ GDBUS_TESTING_ASYNC_METHOD("ReadRSSI", NULL,
					GDBUS_ARGS({ "rssi", "n" }),
					bearer_read_rssi) },
	{}
};

static gboolean bearer_get_adapter(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_bearer *bearer = data;
	struct btd_adapter *adapter = device_get_adapter(bearer->device);
	const char *path = adapter_get_path(adapter);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);

	return TRUE;
}

static gboolean bearer_get_paired(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_bearer *bearer = data;
	dbus_bool_t paired = device_is_paired(bearer->device, bearer->type);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &paired);

	return TRUE;
}

static gboolean bearer_get_bonded(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_bearer *bearer = data;
	dbus_bool_t bonded = device_is_bonded(bearer->device, bearer->type);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &bonded);

	return TRUE;
}

static gboolean bearer_get_connected(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_bearer *bearer = data;
	dbus_bool_t connected = btd_device_bdaddr_type_connected(bearer->device,
								bearer->type);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &connected);

	return TRUE;
}

static gboolean bearer_get_connectable(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_bearer *bearer = data;
	dbus_bool_t connectable;

	connectable = btd_device_bdaddr_type_connectable(bearer->device,
								bearer->type);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &connectable);

	return TRUE;
}

static gboolean bearer_connectable_exists(const GDBusPropertyTable *property,
								void *data)
{
	struct btd_bearer *bearer = data;

	if (bearer->type == BDADDR_BREDR)
		return TRUE;

	return btd_device_bdaddr_type_seen(bearer->device, bearer->type);
}

static gboolean bearer_get_role(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_bearer *bearer = data;
	const char *role;

	/* The initiator of an LE connection is always the central */
	if (btd_device_bdaddr_type_initiator(bearer->device, bearer->type))
		role = "peripheral";
	else
		role = "central";

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &role);

	return TRUE;
}

static gboolean bearer_role_exists(const GDBusPropertyTable *property,
								void *data)
{
	struct btd_bearer *bearer = data;

	if (bearer->type == BDADDR_BREDR)
		return FALSE;

	return btd_device_bdaddr_type_connected(bearer->device, bearer->type);
}

static gboolean bearer_get_interval(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_bearer *bearer = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32,
							&bearer->interval);

	return TRUE;
}

static gboolean bearer_get_latency(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_bearer *bearer = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16,
							&bearer->latency);

	return TRUE;
}

static gboolean bearer_get_supv_timeout(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_bearer *bearer = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16,
							&bearer->supv_timeout);

	return TRUE;
}

static gboolean bearer_get_subrate(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_bearer *bearer = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16,
							&bearer->subrate);

	return TRUE;
}

static gboolean bearer_conn_params_exists(const GDBusPropertyTable *property,
								void *data)
{
	struct btd_bearer *bearer = data;

	return bearer->conn_params;
}

static const GDBusSignalTable bearer_signals[] = {
	{ GDBUS_SIGNAL("Disconnected",
			GDBUS_ARGS({ "name", "s" }, { "message", "s" })) },
	{ }
};

static const GDBusPropertyTable bearer_properties[] = {
	{ "Adapter", "o", bearer_get_adapter },
	{ "Paired", "b", bearer_get_paired },
	{ "Bonded", "b", bearer_get_bonded },
	{ "Connected", "b", bearer_get_connected },
	{ "Connectable", "b", bearer_get_connectable, NULL,
					bearer_connectable_exists },
	{ "Role", "s", bearer_get_role, NULL, bearer_role_exists },
	{ "Interval", "u", bearer_get_interval, NULL,
					bearer_conn_params_exists },
	{ "Latency", "q", bearer_get_latency, NULL,
					bearer_conn_params_exists },
	{ "SupervisionTimeout", "q", bearer_get_supv_timeout, NULL,
					bearer_conn_params_exists },
	{ "Subrate", "q", bearer_get_subrate, NULL,
					bearer_conn_params_exists },
	{}
};

static const char *bearer_interface(uint8_t type)
{
	if (type == BDADDR_BREDR)
		return BTD_BEARER_BREDR_INTERFACE;
	else
		return BTD_BEARER_LE_INTERFACE;
}

static const GDBusMethodTable *bearer_methods(uint8_t type)
{
	if (type == BDADDR_BREDR)
		return bearer_bredr_methods;
	else
		return bearer_le_methods;
}

struct btd_bearer *btd_bearer_new(struct btd_device *device, uint8_t type)
{
	struct btd_bearer *bearer;

	switch (btd_opts.mode) {
	case BT_MODE_LE:
		if (type == BDADDR_BREDR)
			return NULL;
		break;
	case BT_MODE_BREDR:
		if (type != BDADDR_BREDR)
			return NULL;
		break;
	case BT_MODE_DUAL:
		break;
	}

	bearer = new0(struct btd_bearer, 1);
	bearer->device = device;
	bearer->type = type;
	bearer->path = device_get_path(device);
	bearer->disconnects = queue_new();
	bearer->rssi_reads = queue_new();

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
					bearer->path, bearer_interface(type),
					bearer_methods(type), bearer_signals,
					bearer_properties,
					bearer, bearer_free)) {
		error("Unable to register BREDR interface");
		bearer->path = NULL;
	}

	return bearer;
}

void btd_bearer_destroy(struct btd_bearer *bearer)
{
	if (!bearer)
		return;

	if (!bearer->path) {
		bearer_free(bearer);
		return;
	}

	if (bearer->disconnects) {
		queue_destroy(bearer->disconnects, bearer_free_dbus_message);
		bearer->disconnects = NULL;
	}

	if (bearer->connect) {
		dbus_message_unref(bearer->connect);
		bearer->connect = NULL;
	}

	if (bearer->conn_info_id) {
		btd_adapter_cancel_request(device_get_adapter(bearer->device),
							bearer->conn_info_id);
		bearer->conn_info_id = 0;
	}

	if (bearer->rssi_reads) {
		queue_destroy(bearer->rssi_reads, bearer_free_dbus_message);
		bearer->rssi_reads = NULL;
	}

	g_dbus_unregister_interface(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type));
}

void btd_bearer_paired(struct btd_bearer *bearer)
{
	if (!bearer || !bearer->path)
		return;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type),
					"Paired");
}

void btd_bearer_bonded(struct btd_bearer *bearer)
{
	if (!bearer || !bearer->path)
		return;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type),
					"Bonded");
}

void btd_bearer_connectable(struct btd_bearer *bearer)
{
	if (!bearer || !bearer->path)
		return;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type),
					"Connectable");
}

static void bearer_conn_param_changed(struct btd_bearer *bearer,
							const char *name)
{
	g_dbus_emit_property_changed(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type), name);
}

void btd_bearer_conn_params(struct btd_bearer *bearer, uint32_t interval,
				uint16_t latency, uint16_t supv_timeout,
				uint16_t subrate)
{
	bool added;

	if (!bearer || !bearer->path)
		return;

	added = !bearer->conn_params;
	bearer->conn_params = true;

	if (added || bearer->interval != interval) {
		bearer->interval = interval;
		bearer_conn_param_changed(bearer, "Interval");
	}

	if (added || bearer->latency != latency) {
		bearer->latency = latency;
		bearer_conn_param_changed(bearer, "Latency");
	}

	if (added || bearer->supv_timeout != supv_timeout) {
		bearer->supv_timeout = supv_timeout;
		bearer_conn_param_changed(bearer, "SupervisionTimeout");
	}

	if (added || bearer->subrate != subrate) {
		bearer->subrate = subrate;
		bearer_conn_param_changed(bearer, "Subrate");
	}
}

static void bearer_clear_conn_params(struct btd_bearer *bearer)
{
	if (!bearer->conn_params)
		return;

	bearer->conn_params = false;

	bearer_conn_param_changed(bearer, "Interval");
	bearer_conn_param_changed(bearer, "Latency");
	bearer_conn_param_changed(bearer, "SupervisionTimeout");
	bearer_conn_param_changed(bearer, "Subrate");
}

void btd_bearer_connected(struct btd_bearer *bearer, int err)
{
	DBusMessage *reply;

	if (!bearer || !bearer->path)
		return;

	if (bearer->connect) {
		if (err)
			reply = bearer->type == BDADDR_BREDR ?
				btd_error_bredr_errno(bearer->connect, err) :
				btd_error_le_errno(bearer->connect, err);
		else
			reply = dbus_message_new_method_return(
							bearer->connect);

		g_dbus_send_message(btd_get_dbus_connection(), reply);
		dbus_message_unref(bearer->connect);
		bearer->connect = NULL;
	}

	g_dbus_emit_property_changed(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type),
					"Connected");

	if (!err && bearer->type != BDADDR_BREDR)
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
					bearer->path,
					bearer_interface(bearer->type),
					"Role");
}

void btd_bearer_disconnected(struct btd_bearer *bearer, uint8_t reason)
{
	const char *name;
	const char *message;
	DBusMessage *msg;
	const struct queue_entry *entry;

	if (!bearer || !bearer->path)
		return;

	/* cancel disconnect timer if ACL link has already dropped */
	if (bearer->disconn_timer) {
		timeout_remove(bearer->disconn_timer);
		bearer->disconn_timer = 0;
	}

	if (!btd_device_is_connected(bearer->device))
		device_disconnect_watches_callback(bearer->device);

	while (!queue_isempty(bearer->disconnects)) {
		entry = queue_get_entries(bearer->disconnects);
		msg = entry->data;
		g_dbus_send_reply(btd_get_dbus_connection(), msg,
						DBUS_TYPE_INVALID);
		queue_remove(bearer->disconnects, msg);
		dbus_message_unref(msg);
	}

	g_dbus_emit_property_changed(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type),
					"Connected");

	if (bearer->type != BDADDR_BREDR)
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
					bearer->path,
					bearer_interface(bearer->type),
					"Role");

	bearer_clear_conn_params(bearer);

	switch (reason) {
	case MGMT_DEV_DISCONN_UNKNOWN:
		name = "org.bluez.Reason.Unknown";
		message = "Unspecified";
		break;
	case MGMT_DEV_DISCONN_TIMEOUT:
		name = "org.bluez.Reason.Timeout";
		message = "Connection timeout";
		break;
	case MGMT_DEV_DISCONN_LOCAL_HOST:
		name = "org.bluez.Reason.Local";
		message = "Connection terminated by local host";
		break;
	case MGMT_DEV_DISCONN_REMOTE:
		name = "org.bluez.Reason.Remote";
		message = "Connection terminated by remote user";
		break;
	case MGMT_DEV_DISCONN_AUTH_FAILURE:
		name = "org.bluez.Reason.Authentication";
		message = "Connection terminated due to authentication failure";
		break;
	case MGMT_DEV_DISCONN_LOCAL_HOST_SUSPEND:
		name = "org.bluez.Reason.Suspend";
		message = "Connection terminated by local host for suspend";
		break;
	default:
		warn("Unknown disconnection value: %u", reason);
		name = "org.bluez.Reason.Unknown";
		message = "Unspecified";
	}

	g_dbus_emit_signal(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type),
					"Disconnected",
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_STRING, &message,
					DBUS_TYPE_INVALID);
}
