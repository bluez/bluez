/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus-helper.h"
#include "dbus.h"
#include "logging.h"
#include "textfile.h"
#include "ipc.h"
#include "device.h"
#include "error.h"
#include "avdtp.h"
#include "a2dp.h"
#include "headset.h"
#include "gateway.h"
#include "sink.h"
#include "control.h"
#include "manager.h"

typedef enum {
	HEADSET	= 1 << 0,
	GATEWAY	= 1 << 1,
	SINK	= 1 << 2,
	SOURCE	= 1 << 3,
	CONTROL	= 1 << 4,
	TARGET	= 1 << 5,
	INVALID	= 1 << 6
} audio_service_type;

typedef enum {
		GENERIC_AUDIO = 0,
		ADVANCED_AUDIO,
		AV_REMOTE,
		GET_RECORDS
} audio_sdp_state_t;

struct audio_sdp_data {
	struct device *device;

	DBusMessage *msg;	/* Method call or NULL */

	GSList *handles;	/* uint32_t * */
	GSList *records;	/* sdp_record_t * */

	audio_sdp_state_t state;

	create_dev_cb_t cb;
	void *cb_data;
};

static DBusConnection *connection = NULL;

static struct device *default_hs = NULL;
static struct device *default_dev = NULL;

static GSList *devices = NULL;

static uint32_t hs_record_id = 0;
static uint32_t hf_record_id = 0;

static GIOChannel *hs_server = NULL;
static GIOChannel *hf_server = NULL;

static const struct enabled_interfaces *enabled;

static void get_next_record(struct audio_sdp_data *data);
static DBusHandlerResult get_handles(const char *uuid,
					struct audio_sdp_data *data);

static struct device *create_device(bdaddr_t *bda)
{
	static int device_id = 0;
	char path[128];

	snprintf(path, sizeof(path) - 1,
			"%s/device%d", AUDIO_MANAGER_PATH, device_id++);

	return device_register(connection, path, bda);
}

static void destroy_device(struct device *device)
{
	dbus_connection_destroy_object_path(connection, device->path);
}

static void remove_device(struct device *device)
{
	if (device == default_dev) {
		debug("Removing default device");
		default_dev = NULL;
	}

	if (device == default_hs) {
		debug("Removing default headset");
		default_hs = NULL;
	}

	devices = g_slist_remove(devices, device);

	destroy_device(device);
}

static gboolean add_device(struct device *device, gboolean send_signals)
{
	if (!send_signals)
		goto add;

	dbus_connection_emit_signal(connection, AUDIO_MANAGER_PATH,
					AUDIO_MANAGER_INTERFACE,
					"DeviceCreated",
					DBUS_TYPE_STRING, &device->path,
					DBUS_TYPE_INVALID);

	if (device->headset)
		dbus_connection_emit_signal(connection,
				AUDIO_MANAGER_PATH,
				AUDIO_MANAGER_INTERFACE,
				"HeadsetCreated",
				DBUS_TYPE_STRING, &device->path,
				DBUS_TYPE_INVALID);
add:

	if (default_dev == NULL && g_slist_length(devices) == 0) {
		debug("Selecting default device");
		default_dev = device;
	}

	if (!default_hs && device->headset && !devices)
		default_hs = device;

	devices = g_slist_append(devices, device);

	return TRUE;
}

static uint16_t get_service_uuid(const sdp_record_t *record)
{
	sdp_list_t *classes;
	uuid_t uuid;
	uint16_t uuid16 = 0;

	if (sdp_get_service_classes(record, &classes) < 0) {
		error("Unable to get service classes from record");
		return 0;
	}

	memcpy(&uuid, classes->data, sizeof(uuid));

	if (!sdp_uuid128_to_uuid(&uuid)) {
		error("Not a 16 bit UUID");
		sdp_list_free(classes, free);
		return 0;
	}

	if (uuid.type == SDP_UUID32) {
		if (uuid.value.uuid32 > 0xFFFF) {
			error("Not a 16 bit UUID");
			goto done;
		}
		uuid16 = (uint16_t) uuid.value.uuid32;
	} else
		uuid16 = uuid.value.uuid16;

done:
	sdp_list_free(classes, free);

	return uuid16;
}

static gboolean server_is_enabled(uint16_t svc)
{
	gboolean ret;

	switch (svc) {
	case HEADSET_SVCLASS_ID:
		ret = (hs_server != NULL);
		break;
	case HANDSFREE_SVCLASS_ID:
		ret = (hf_server != NULL);
		break;
	case AUDIO_SINK_SVCLASS_ID:
		return enabled->sink;
	case AV_REMOTE_TARGET_SVCLASS_ID:
	case AV_REMOTE_SVCLASS_ID:
		return enabled->control;
	default:
		ret = FALSE;
		break;
	}

	return ret;
}

static void handle_record(sdp_record_t *record, struct device *device)
{
	gboolean is_default;
	uint16_t uuid16;

	uuid16 = get_service_uuid(record);

	if (!server_is_enabled(uuid16))
		return;

	switch (uuid16) {
	case HEADSET_SVCLASS_ID:
		debug("Found Headset record");
		if (device->headset)
			headset_update(device, record, uuid16);
		else
			device->headset = headset_init(device,
							record, uuid16);
		break;
	case HEADSET_AGW_SVCLASS_ID:
		debug("Found Headset AG record");
		break;
	case HANDSFREE_SVCLASS_ID:
		debug("Found Hansfree record");
		if (device->headset)
			headset_update(device, record, uuid16);
		else
			device->headset = headset_init(device,
							record, uuid16);
		break;
	case HANDSFREE_AGW_SVCLASS_ID:
		debug("Found Handsfree AG record");
		break;
	case AUDIO_SINK_SVCLASS_ID:
		debug("Found Audio Sink");
		if (device->sink == NULL)
			device->sink = sink_init(device);
		break;
	case AUDIO_SOURCE_SVCLASS_ID:
		debug("Found Audio Source");
		break;
	case AV_REMOTE_SVCLASS_ID:
		debug("Found AV Remote");
		if (device->control == NULL)
			device->control = control_init(device);
		if (device->sink && sink_is_active(device))
			avrcp_connect(device);
		break;
	case AV_REMOTE_TARGET_SVCLASS_ID:
		debug("Found AV Target");
		if (device->control == NULL)
			device->control = control_init(device);
		if (device->sink && sink_is_active(device))
			avrcp_connect(device);
		break;
	default:
		debug("Unrecognized UUID: 0x%04X", uuid16);
		break;
	}

	is_default = (default_dev == device) ? TRUE : FALSE;

	device_store(device, is_default);
}

static void finish_sdp(struct audio_sdp_data *data, gboolean success)
{
	const char *addr;
	DBusMessage *reply = NULL;
	DBusError derr;

	debug("Audio service discovery completed with %s",
			success ? "success" : "failure");

	device_finish_sdp_transaction(data->device);

	if (!success)
		goto done;

	if (!data->msg)
		goto update;

	dbus_error_init(&derr);
	dbus_message_get_args(data->msg, &derr,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&derr)) {
		error("Unable to get message args");
		success = FALSE;
		err_failed(connection, data->msg, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	/* Return error if no audio related service records were found */
	if (!data->records) {
		debug("No audio audio related service records were found");
		success = FALSE;
		err_not_supported(connection, data->msg);
		goto done;
	}

	reply = dbus_message_new_method_return(data->msg);
	if (!reply) {
		success = FALSE;
		err_failed(connection, data->msg, "Out of memory");
		goto done;
	}

update:
	g_slist_foreach(data->records, (GFunc) handle_record, data->device);

	if (!g_slist_find(devices, data->device))
		add_device(data->device, TRUE);

	if (reply) {
		dbus_message_append_args(reply, DBUS_TYPE_STRING,
					&data->device->path,
					DBUS_TYPE_INVALID);
		send_message_and_unref(connection, reply);
	}

done:
	if (success) {
		if (data->cb)
			data->cb(data->device, data->cb_data);
	} else {
		if (data->cb)
			data->cb(NULL, data->cb_data);
		if (!g_slist_find(devices, data->device))
			destroy_device(data->device);
	}
	if (data->msg)
		dbus_message_unref(data->msg);
	g_slist_foreach(data->handles, (GFunc) g_free, NULL);
	g_slist_free(data->handles);
	g_slist_foreach(data->records, (GFunc) sdp_record_free, NULL);
	g_slist_free(data->records);
	g_free(data);
}

static void get_record_reply(DBusPendingCall *call,
				struct audio_sdp_data *data)
{
	DBusMessage *reply;
	DBusError derr;
	uint8_t *array;
	int array_len, record_len;
	sdp_record_t *record;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetRemoteServiceRecord failed: %s", derr.message);
		if (dbus_error_has_name(&derr,
					"org.bluez.Error.ConnectionAttemptFailed"))
			err_connect_failed(connection, data->msg,
				strerror(EHOSTDOWN));
		else
			err_failed(connection, data->msg, derr.message);
		dbus_error_free(&derr);
		goto failed;
	}

	if (!dbus_message_get_args(reply, NULL,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &array, &array_len,
				DBUS_TYPE_INVALID)) {
		err_failed(connection, data->msg,
				"Unable to get args from GetRecordReply");
		goto failed;
	}

	record = sdp_extract_pdu(array, &record_len);
	if (!record) {
		error("Unable to extract service record from reply");
		goto done;
	}

	if (record_len != array_len)
		debug("warning: array len (%d) != record len (%d)",
				array_len, record_len);

	data->records = g_slist_append(data->records, record);

done:
	dbus_message_unref(reply);

	if (data->handles)
		get_next_record(data);
	else
		finish_sdp(data, TRUE);

	return;

failed:
	if (reply)
		dbus_message_unref(reply);
	finish_sdp(data, FALSE);
}

static void get_next_record(struct audio_sdp_data *data)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	char address[18], *ptr = address;
	dbus_uint32_t *handle;

	msg = dbus_message_new_method_call("org.bluez",
						data->device->adapter_path,
						"org.bluez.Adapter",
						"GetRemoteServiceRecord");
	if (!msg) {
		error("Unable to allocate new method call");
		err_connect_failed(connection, data->msg, strerror(ENOMEM));
		finish_sdp(data, FALSE);
		return;
	}

	handle = data->handles->data;

	data->handles = g_slist_remove(data->handles, data->handles->data);

	ba2str(&data->device->dst, address);

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &ptr,
					DBUS_TYPE_UINT32, handle,
					DBUS_TYPE_INVALID);

	g_free(handle);

	if (!dbus_connection_send_with_reply(connection, msg, &pending, -1)) {
		error("Sending GetRemoteServiceRecord failed");
		err_connect_failed(connection, data->msg, strerror(EIO));
		finish_sdp(data, FALSE);
		return;
	}

	dbus_pending_call_set_notify(pending,
			(DBusPendingCallNotifyFunction) get_record_reply,
			data, NULL);
	dbus_pending_call_unref(pending);
	dbus_message_unref(msg);
}

static GSList *find_handle(GSList *handles, dbus_uint32_t handle)
{
	while (handles) {
		if (*(dbus_uint32_t *) handles->data == handle)
			return handles;
		handles = handles->next;
	}

	return NULL;
}

static void get_handles_reply(DBusPendingCall *call,
				struct audio_sdp_data *data)
{
	DBusMessage *reply;
	DBusError derr;
	dbus_uint32_t *array = NULL;
	int array_len, i;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetRemoteServiceHandles failed: %s", derr.message);
		if (dbus_error_has_name(&derr,
					"org.bluez.Error.ConnectionAttemptFailed"))
			err_connect_failed(connection, data->msg, strerror(EHOSTDOWN));
		else
			err_failed(connection, data->msg, derr.message);
		dbus_error_free(&derr);
		goto failed;
	}

	if (!dbus_message_get_args(reply, NULL,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
				&array, &array_len,
				DBUS_TYPE_INVALID)) {
		err_failed(connection, data->msg,
				"Unable to get args from reply");
		goto failed;
	}

	for (i = 0; i < array_len; i++) {
		if (!find_handle(data->handles, array[i])) {
			dbus_uint32_t *handle = g_new(dbus_uint32_t, 1);
			*handle = array[i];
			data->handles = g_slist_append(data->handles, handle);
		}
	}

	data->state++;

	switch (data->state) {
	case ADVANCED_AUDIO:
		get_handles(ADVANCED_AUDIO_UUID, data);
		break;
	case AV_REMOTE:
		get_handles(AVRCP_REMOTE_UUID, data);
		break;
	default:
		if (data->handles)
			get_next_record(data);
		else
			finish_sdp(data, TRUE);
	}

	dbus_message_unref(reply);

	return;

failed:
	dbus_message_unref(reply);
	finish_sdp(data, FALSE);
}

static DBusHandlerResult get_handles(const char *uuid,
					struct audio_sdp_data *data)
{
	DBusPendingCall *pending;
	char address[18];
	const char *ptr = address;
	DBusMessage *msg;

	msg = dbus_message_new_method_call("org.bluez",
						data->device->adapter_path,
						"org.bluez.Adapter",
						"GetRemoteServiceHandles");
	if (!msg) {
		err_failed(connection, data->msg,
				"Could not create a new dbus message");
		goto failed;
	}

	ba2str(&data->device->dst, address);

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &ptr,
					DBUS_TYPE_STRING, &uuid,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(connection, msg, &pending, -1)) {
		err_failed(connection, data->msg,
				"Sending GetRemoteServiceHandles failed");
		goto failed;
	}

	dbus_pending_call_set_notify(pending,
			(DBusPendingCallNotifyFunction) get_handles_reply,
			data, NULL);
	dbus_pending_call_unref(pending);
	dbus_message_unref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;

failed:
	if (msg)
		dbus_message_unref(msg);
	finish_sdp(data, FALSE);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult resolve_services(DBusMessage *msg,
						struct device *device,
						create_dev_cb_t cb,
						void *user_data)
{
	struct audio_sdp_data *sdp_data;

	sdp_data = g_new0(struct audio_sdp_data, 1);
	if (msg)
		sdp_data->msg = dbus_message_ref(msg);
	sdp_data->device = device;
	sdp_data->cb = cb;
	sdp_data->cb_data = user_data;

	return get_handles(GENERIC_AUDIO_UUID, sdp_data);
}

struct device *manager_device_connected(bdaddr_t *bda, const char *uuid)
{
	struct device *device;
	const char *path;
	gboolean headset = FALSE, created = FALSE;

	device = manager_find_device(bda, NULL, FALSE);
	if (!device) {
		device = create_device(bda);
		if (!device)
			return NULL;
		if (!add_device(device, TRUE)) {
			destroy_device(device);
			return NULL;
		}
		created = TRUE;
	}

	if (!strcmp(uuid, HSP_AG_UUID) || !strcmp(uuid, HFP_AG_UUID)) {
		if (device->headset)
			return device;

		device->headset = headset_init(device, NULL, 0);

		if (!device->headset)
			return NULL;

		headset = TRUE;
	} else if (!strcmp(uuid, A2DP_SOURCE_UUID)) {
		if (device->sink)
			return device;

		device->sink = sink_init(device);

		if (!device->sink)
			return NULL;
	} else if (!strcmp(uuid, AVRCP_TARGET_UUID)) {
		if (device->control)
			return device;

		device->control = control_init(device);

		if (!device->control)
			return NULL;
	} else
		return NULL;

	path = device->path;

	if (created) {
		dbus_connection_emit_signal(connection, AUDIO_MANAGER_PATH,
						AUDIO_MANAGER_INTERFACE,
						"DeviceCreated",
						DBUS_TYPE_STRING, &path,
						DBUS_TYPE_INVALID);
		resolve_services(NULL, device, NULL, NULL);
	}

	if (headset)
		dbus_connection_emit_signal(connection, AUDIO_MANAGER_PATH,
						AUDIO_MANAGER_INTERFACE,
						"HeadsetCreated",
						DBUS_TYPE_STRING, &path,
						DBUS_TYPE_INVALID);

	if (headset && !default_hs) {
		default_hs = device;
		dbus_connection_emit_signal(connection, AUDIO_MANAGER_PATH,
						AUDIO_MANAGER_INTERFACE,
						"DefaultHeadsetChanged",
						DBUS_TYPE_STRING, &path,
						DBUS_TYPE_INVALID);
	}

	if (!default_dev) {
		default_dev = device;
		dbus_connection_emit_signal(connection, AUDIO_MANAGER_PATH,
						AUDIO_MANAGER_INTERFACE,
						"DefaultDeviceChanged",
						DBUS_TYPE_STRING, &path,
						DBUS_TYPE_INVALID);
	}

	return device;
}

gboolean manager_create_device(bdaddr_t *bda, create_dev_cb_t cb,
				void *user_data)
{
	struct device *dev;

	dev = create_device(bda);
	if (!dev)
		return FALSE;

	resolve_services(NULL, dev, cb, user_data);

	return TRUE;
}

static DBusHandlerResult am_create_device(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	const char *address, *path;
	bdaddr_t bda;
	struct device *device;
	DBusMessage *reply;
	DBusError derr;

	dbus_error_init(&derr);
	dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&derr)) {
		err_invalid_args(connection, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	str2ba(address, &bda);

	device = manager_find_device(&bda, NULL, FALSE);
	if (!device) {
		device = create_device(&bda);
		return resolve_services(msg, device, NULL, NULL);
	}

	path = device->path;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult am_list_devices(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	DBusMessageIter iter, array_iter;
	DBusMessage *reply;
	DBusError derr;
	GSList *l;
	gboolean hs_only = FALSE;


	dbus_error_init(&derr);

	if (dbus_message_is_method_call(msg, AUDIO_MANAGER_INTERFACE,
					"ListHeadsets"))
		hs_only = TRUE;
	else
		hs_only = FALSE;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	for (l = devices; l != NULL; l = l->next) {
		struct device *device = l->data;

		if (hs_only && !device->headset)
			continue;

		dbus_message_iter_append_basic(&array_iter,
						DBUS_TYPE_STRING, &device->path);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(connection, reply);
}

static gint device_path_cmp(gconstpointer a, gconstpointer b)
{
	const struct device *device = a;
	const char *path = b;

	return strcmp(device->path, path);
}

static DBusHandlerResult am_remove_device(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	DBusError derr;
	DBusMessage *reply;
	GSList *match;
	const char *path;
	struct device *device;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
					DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID)) {
		err_invalid_args(connection, msg, derr.message);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	if (dbus_error_is_set(&derr)) {
		err_invalid_args(connection, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	match = g_slist_find_custom(devices, path, device_path_cmp);
	if (!match)
		return err_does_not_exist(connection, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	device = match->data;
	device_remove_stored(device);
	remove_device(device);

	/* Fallback to a valid default */
	if (default_dev == NULL) {
		const char *param;
		GSList *l;

		default_dev = manager_find_device(BDADDR_ANY, NULL, TRUE);

		if (!default_dev && devices) {
			l = devices;
			default_dev = (g_slist_last(l))->data;
		}

		param = default_dev ? default_dev->path : "";

		dbus_connection_emit_signal(conn, AUDIO_MANAGER_PATH,
						AUDIO_MANAGER_INTERFACE,
						"DefaultHeadsetChanged",
						DBUS_TYPE_STRING, &param,
						DBUS_TYPE_INVALID);

		dbus_connection_emit_signal(conn, AUDIO_MANAGER_PATH,
						AUDIO_MANAGER_INTERFACE,
						"DefaultDeviceChanged",
						DBUS_TYPE_STRING, &param,
						DBUS_TYPE_INVALID);

		if (default_dev)
			device_store(default_dev, TRUE);
	}

	dbus_connection_emit_signal(conn, AUDIO_MANAGER_PATH,
					AUDIO_MANAGER_INTERFACE,
					"HeadsetRemoved",
					DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID);

	dbus_connection_emit_signal(conn, AUDIO_MANAGER_PATH,
					AUDIO_MANAGER_INTERFACE,
					"DeviceRemoved",
					DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(connection, reply);
}

static DBusHandlerResult am_find_by_addr(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	const char *address;
	DBusMessage *reply;
	DBusError derr;
	struct device *device;
	bdaddr_t bda;

	dbus_error_init(&derr);
	dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_INVALID);
	if (dbus_error_is_set(&derr)) {
		err_invalid_args(connection, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	str2ba(address, &bda);
	device = manager_find_device(&bda, NULL, FALSE);

	if (!device)
		return err_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &device->path,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult am_default_device(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	DBusMessage *reply;

	if (!default_dev)
		return err_does_not_exist(connection, msg);

	if (default_dev->headset == NULL &&
		dbus_message_is_method_call(msg, AUDIO_MANAGER_INTERFACE,
							"DefaultHeadset"))
		return err_does_not_exist(connection, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &default_dev->path,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(connection, reply);
}

static DBusHandlerResult am_change_default_device(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	DBusError derr;
	DBusMessage *reply;
	GSList *match;
	const char *path;
	struct device *device;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
					DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID)) {
		err_invalid_args(connection, msg, derr.message);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	if (dbus_error_is_set(&derr)) {
		err_invalid_args(connection, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	match = g_slist_find_custom(devices, path, device_path_cmp);
	if (!match)
		return err_does_not_exist(connection, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	device = match->data;

	if (!dbus_message_is_method_call(msg, AUDIO_MANAGER_INTERFACE,
		"ChangeDefaultHeadset"))
		dbus_connection_emit_signal(conn, AUDIO_MANAGER_PATH,
						AUDIO_MANAGER_INTERFACE,
						"DefaultDeviceChanged",
						DBUS_TYPE_STRING, &device->path,
						DBUS_TYPE_INVALID);
	else if (device->headset)
		dbus_connection_emit_signal(conn, AUDIO_MANAGER_PATH,
						AUDIO_MANAGER_INTERFACE,
						"DefaultHeadsetChanged",
						DBUS_TYPE_STRING, &device->path,
						DBUS_TYPE_INVALID);
	else
		return err_does_not_exist(connection, msg);

	default_dev = device;
	device_store(device, TRUE);
	return send_message_and_unref(connection, reply);
}

static DBusMethodVTable manager_methods[] = {
	{ "CreateDevice",		am_create_device,
		"s",	"s"		},
	{ "RemoveDevice",		am_remove_device,
		"s",	""		},
	{ "ListDevices",		am_list_devices,
		"",	"as"		},
	{ "DefaultDevice",		am_default_device,
		"",	"s"		},
	{ "ChangeDefaultDevice",	am_change_default_device,
		"s",	""		},
	{ "CreateHeadset",		am_create_device,
		"s",	"s"		},
	{ "RemoveHeadset",		am_remove_device,
		"s",	""		},
	{ "ListHeadsets",		am_list_devices,
		"",	"as"		},
	{ "FindDeviceByAddress",	am_find_by_addr,
		"s",	"s"		},
	{ "DefaultHeadset",		am_default_device,
		"",	"s"		},
	{ "ChangeDefaultHeadset",	am_change_default_device,
		"s",	""		},
	{ NULL, NULL, NULL, NULL },
};

static DBusSignalVTable manager_signals[] = {
	{ "DeviceCreated",		"s"	},
	{ "DeviceRemoved",		"s"	},
	{ "HeadsetCreated",		"s"	},
	{ "HeadsetRemoved",		"s"	},
	{ "DefaultDeviceChanged",	"s"	},
	{ "DefaultHeadsetChanged",	"s"	},
	{ NULL, NULL }
};

static void parse_stored_devices(char *key, char *value, void *data)
{
	bdaddr_t *src = data;
	struct device *device;
	bdaddr_t dst;

	if (!key || !value || strcmp(key, "default") == 0)
		return;

	str2ba(key, &dst);
	device = manager_find_device(&dst, NULL, FALSE);

	if (device)
		return;

	info("Loading device %s (%s)", key, value);

	device = create_device(&dst);
	if (!device)
		return;

	/* Change storage to source adapter */
	bacpy(&device->store, src);

	if (enabled->headset && strstr(value, "headset"))
		device->headset = headset_init(device, NULL, 0);
	if (enabled->sink && strstr(value, "sink"))
		device->sink = sink_init(device);
	if (enabled->control && strstr(value, "control"))
		device->control = control_init(device);
	add_device(device, FALSE);
}

static void register_devices_stored(const char *adapter)
{
	char filename[PATH_MAX + 1];
	struct stat st;
	struct device *device;
	bdaddr_t default_src;
	bdaddr_t dst;
	bdaddr_t src;
	char *addr;
	int dev_id;

	create_name(filename, PATH_MAX, STORAGEDIR, adapter, "audio");

	str2ba(adapter, &src);

	if (stat(filename, &st) < 0)
		return;

	if (!(st.st_mode & __S_IFREG))
		return;

	textfile_foreach(filename, parse_stored_devices, &src);

	bacpy(&default_src, BDADDR_ANY);
	dev_id = hci_get_route(&default_src);
	if (dev_id < 0 || hci_devba(dev_id, &default_src) < 0)
		return;

	if (bacmp(&default_src, &src) != 0)
		return;

	addr = textfile_get(filename, "default");
	if (!addr)
		return;

	str2ba(addr, &dst);
	device = manager_find_device(&dst, NULL, FALSE);

	if (device) {
		info("Setting %s as default device", addr);
		default_dev = device;
	}

	free(addr);
}

static void register_stored(void)
{
	char dirname[PATH_MAX + 1];
	struct dirent *de;
	DIR *dir;

	snprintf(dirname, PATH_MAX, "%s", STORAGEDIR);

	dir = opendir(dirname);
	if (!dir)
		return;

	while ((de = readdir(dir)) != NULL) {
		if (!isdigit(de->d_name[0]))
			continue;

		/* Device objects */
		register_devices_stored(de->d_name);
	}

	closedir(dir);
}

static void manager_unregister(DBusConnection *conn, void *data)
{
	info("Unregistered manager path");

	if (devices) {
		g_slist_foreach(devices, (GFunc) remove_device, NULL);
		g_slist_free(devices);
		devices = NULL;
	}
}

static int hsp_ag_record(sdp_buf_t *buf, uint8_t ch)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid;
	uuid_t l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	sdp_data_t *channel;
	int ret;

	memset(&record, 0, sizeof(sdp_record_t));

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&svclass_uuid, HEADSET_AGW_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HEADSET_PROFILE_ID);
	profile.version = 0x0100;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &ch);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Headset Audio Gateway", 0, 0);

	if (sdp_gen_record_pdu(&record, buf) < 0)
		ret = -1;
	else
		ret = 0;

	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);
	sdp_list_free(record.attrlist, (sdp_free_func_t) sdp_data_free);
	sdp_list_free(record.pattern, free);

	return ret;
}

static int hfp_ag_record(sdp_buf_t *buf, uint8_t ch)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid;
	uuid_t l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	uint16_t u16 = 0x0009;
	sdp_data_t *channel, *features;
	uint8_t netid = 0x01;
	sdp_data_t *network = sdp_data_alloc(SDP_UINT8, &netid);
	int ret;

	memset(&record, 0, sizeof(sdp_record_t));

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&svclass_uuid, HANDSFREE_AGW_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HANDSFREE_PROFILE_ID);
	profile.version = 0x0105;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &ch);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	features = sdp_data_alloc(SDP_UINT16, &u16);
	sdp_attr_add(&record, SDP_ATTR_SUPPORTED_FEATURES, features);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Hands-Free Audio Gateway", 0, 0);

	sdp_attr_add(&record, SDP_ATTR_EXTERNAL_NETWORK, network);

	if (sdp_gen_record_pdu(&record, buf) < 0)
		ret = -1;
	else
		ret = 0;

	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);
	sdp_list_free(record.attrlist, (sdp_free_func_t) sdp_data_free);
	sdp_list_free(record.pattern, free);

	return ret;
}

uint32_t add_service_record(DBusConnection *conn, sdp_buf_t *buf)
{
	DBusMessage *msg, *reply;
	DBusError derr;
	dbus_uint32_t rec_id;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
						"org.bluez.Database",
						"AddServiceRecord");
	if (!msg) {
		error("Can't allocate new method call");
		return 0;
	}

	dbus_message_append_args(msg, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
						&buf->data, buf->data_size,
							DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(connection,
							msg, -1, &derr);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr) ||
			dbus_set_error_from_message(&derr, reply)) {
		error("Adding service record failed: %s", derr.message);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_get_args(reply, &derr, DBUS_TYPE_UINT32, &rec_id,
							DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&derr)) {
		error("Invalid arguments to AddServiceRecord reply: %s",
								derr.message);
		dbus_message_unref(reply);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_unref(reply);

	debug("add_service_record: got record id 0x%x", rec_id);

	return rec_id;
}

int remove_service_record(DBusConnection *conn, uint32_t rec_id)
{
	DBusMessage *msg, *reply;
	DBusError derr;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
						"org.bluez.Database",
						"RemoveServiceRecord");
	if (!msg) {
		error("Can't allocate new method call");
		return 0;
	}

	dbus_message_append_args(msg, DBUS_TYPE_UINT32, &rec_id,
							DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(connection,
							msg, -1, &derr);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr)) {
		error("Removing service record 0x%x failed: %s",
						rec_id, derr.message);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_unref(reply);

	return 0;
}

static void auth_cb(DBusPendingCall *call, void *data)
{
	struct device *device = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError err;
	const char *uuid;

	if (headset_get_type(device) == SVC_HEADSET)
		uuid = HSP_AG_UUID;
	else
		uuid = HFP_AG_UUID;

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("Access denied: %s", err.message);
		if (dbus_error_has_name(&err, DBUS_ERROR_NO_REPLY)) {
			debug("Canceling authorization request");
			manager_cancel_authorize(&device->dst, uuid, NULL);
		}
		dbus_error_free(&err);

		headset_set_state(device, HEADSET_STATE_DISCONNECTED);
	} else {
		char hs_address[18];

		headset_set_state(device, HEADSET_STATE_CONNECTED);

		ba2str(&device->dst, hs_address);

		debug("Accepted headset connection from %s for %s",
						hs_address, device->path);
	}

	dbus_message_unref(reply);
}

static gboolean ag_io_cb(GIOChannel *chan, GIOCondition cond, void *data)
{
	int srv_sk, cli_sk;
	struct sockaddr_rc addr;
	socklen_t size;
	const char *uuid;
	struct device *device;
	headset_type_t type;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		error("Hangup or error on rfcomm server socket");
		g_io_channel_close(chan);
		raise(SIGTERM);
		return FALSE;
	}

	srv_sk = g_io_channel_unix_get_fd(chan);

	size = sizeof(struct sockaddr_rc);
	cli_sk = accept(srv_sk, (struct sockaddr *) &addr, &size);
	if (cli_sk < 0) {
		error("accept: %s (%d)", strerror(errno), errno);
		return TRUE;
	}

	if (chan == hs_server) {
		type = SVC_HEADSET;
		uuid = HSP_AG_UUID;
	} else {
		type = SVC_HANDSFREE;
		uuid = HFP_AG_UUID;
	}

	device = manager_device_connected(&addr.rc_bdaddr, uuid);
	if (!device) {
		close(cli_sk);
		return TRUE;
	}

	if (headset_get_state(device) > HEADSET_STATE_DISCONNECTED) {
		debug("Refusing new connection since one already exists");
		close(cli_sk);
		return TRUE;
	}

	if (headset_connect_rfcomm(device, cli_sk) < 0) {
		error("Allocating new GIOChannel failed!");
		close(cli_sk);
		return TRUE;
	}

	headset_set_type(device, type);

	if (!manager_authorize(&device->dst, uuid, auth_cb, device, NULL))
		goto failed;

	headset_set_state(device, HEADSET_STATE_CONNECT_IN_PROGRESS);

	return TRUE;

failed:
	headset_close_rfcomm(device);

	return TRUE;
}

static GIOChannel *server_socket(uint8_t *channel)
{
	int sock, lm;
	struct sockaddr_rc addr;
	socklen_t sa_len;
	GIOChannel *io;

	sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sock < 0) {
		error("server socket: %s (%d)", strerror(errno), errno);
		return NULL;
	}

	lm = RFCOMM_LM_SECURE;
	if (setsockopt(sock, SOL_RFCOMM, RFCOMM_LM, &lm, sizeof(lm)) < 0) {
		error("server setsockopt: %s (%d)", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, BDADDR_ANY);
	addr.rc_channel = channel ? *channel : 0;

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		error("server bind: %s", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	if (listen(sock, 1) < 0) {
		error("server listen: %s", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	sa_len = sizeof(struct sockaddr_rc);
	getsockname(sock, (struct sockaddr *) &addr, &sa_len);
	*channel = addr.rc_channel;

	io = g_io_channel_unix_new(sock);
	if (!io) {
		error("Unable to allocate new io channel");
		close(sock);
		return NULL;
	}

	return io;
}

static int headset_server_init(DBusConnection *conn, gboolean no_hfp)
{
	uint8_t chan = DEFAULT_HS_AG_CHANNEL;
	sdp_buf_t buf;

	if (!(enabled->headset || enabled->gateway))
		return 0;

	hs_server = server_socket(&chan);
	if (!hs_server)
		return -1;

	if (hsp_ag_record(&buf, chan) < 0) {
		error("Unable to allocate new service record");
		return -1;
	}

	hs_record_id = add_service_record(conn, &buf);
	free(buf.data);
	if (!hs_record_id) {
		error("Unable to register HS AG service record");
		g_io_channel_unref(hs_server);
		hs_server = NULL;
		return -1;
	}

	g_io_add_watch(hs_server, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
						(GIOFunc) ag_io_cb, NULL);

	if (no_hfp)
		return 0;

	chan = DEFAULT_HF_AG_CHANNEL;

	hf_server = server_socket(&chan);
	if (!hf_server)
		return -1;

	if (hfp_ag_record(&buf, chan) < 0) {
		error("Unable to allocate new service record");
		return -1;
	}

	hf_record_id = add_service_record(conn, &buf);
	free(buf.data);
	if (!hf_record_id) {
		error("Unable to register HS AG service record");
		g_io_channel_unref(hf_server);
		hs_server = NULL;
		return -1;
	}

	g_io_add_watch(hf_server, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
						(GIOFunc) ag_io_cb, NULL);

	return 0;
}

static void server_exit(void)
{
	if (hs_record_id) {
		remove_service_record(connection, hs_record_id);
		hs_record_id = 0;
	}

	if (hs_server) {
		g_io_channel_unref(hs_server);
		hs_server = NULL;
	}

	if (hf_record_id) {
		remove_service_record(connection, hf_record_id);
		hf_record_id = 0;
	}

	if (hf_server) {
		g_io_channel_unref(hf_server);
		hf_server = NULL;
	}
}

int audio_init(DBusConnection *conn, struct enabled_interfaces *enable,
		gboolean no_hfp, gboolean sco_hci, int source_count)
{
	int sinks, sources;

	connection = dbus_connection_ref(conn);

	enabled = enable;

	if (!dbus_connection_create_object_path(conn, AUDIO_MANAGER_PATH,
						NULL, manager_unregister)) {
		error("D-Bus failed to register %s path", AUDIO_MANAGER_PATH);
		goto failed;
	}

	if (headset_server_init(conn, no_hfp) < 0)
		goto failed;

	if (enable->sink)
		sources = source_count;
	else
		sources = 0;

	if (enable->source)
		sinks = 1;
	else
		sinks = 0;

	if (a2dp_init(conn, sources, sinks) < 0)
		goto failed;

	if (enable->control && avrcp_init(conn) < 0)
		goto failed;

	if (!dbus_connection_register_interface(conn, AUDIO_MANAGER_PATH,
						AUDIO_MANAGER_INTERFACE,
						manager_methods,
						manager_signals, NULL)) {
		error("Failed to register %s interface to %s",
				AUDIO_MANAGER_INTERFACE, AUDIO_MANAGER_PATH);
		goto failed;
	}

	info("Registered manager path:%s", AUDIO_MANAGER_PATH);

	register_stored();

	return 0;
failed:
	audio_exit();
	return -1;
}

void audio_exit(void)
{
	server_exit();

	dbus_connection_destroy_object_path(connection, AUDIO_MANAGER_PATH);

	dbus_connection_unref(connection);

	connection = NULL;
}

struct device *manager_default_device(void)
{
	return default_dev;
}

struct device *manager_get_connected_device(void)
{
	GSList *l;

	for (l = devices; l != NULL; l = g_slist_next(l)) {
		struct device *device = l->data;

		if ((device->sink || device->source) &&
				avdtp_is_connected(&device->src, &device->dst))
			return device;

		if (device->headset && headset_is_active(device))
			return device;
	}

	return NULL;
}

void manager_cancel_authorize(bdaddr_t *dba, const char *uuid,
				DBusPendingCall *pending)
{
	DBusMessage *cancel;
	char addr[18], *address = addr;

	if (pending)
		dbus_pending_call_cancel(pending);

	cancel = dbus_message_new_method_call("org.bluez", "/org/bluez",
						"org.bluez.Database",
						"CancelAuthorizationRequest");
	if (!cancel) {
		error("Unable to allocate new method call");
		return;
	}

	ba2str(dba, addr);

	dbus_message_append_args(cancel, DBUS_TYPE_STRING, &address,
					DBUS_TYPE_STRING, &uuid,
					DBUS_TYPE_INVALID);

	send_message_and_unref(connection, cancel);
}

gboolean manager_authorize(bdaddr_t *dba, const char *uuid,
				DBusPendingCallNotifyFunction cb,
				void *user_data,
				DBusPendingCall **pending)
{
	DBusMessage *auth;
	char address[18], *addr_ptr = address;
	DBusPendingCall *p;

	ba2str(dba, address);

	debug("Requesting authorization for device %s, UUID %s",
			address, uuid);

	auth = dbus_message_new_method_call("org.bluez", "/org/bluez",
						"org.bluez.Database",
						"RequestAuthorization");
	if (!auth) {
		error("Unable to allocate RequestAuthorization method call");
		return FALSE;
	}

	dbus_message_append_args(auth, DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_STRING, &uuid,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(connection, auth, &p, -1)) {
		error("Sending of authorization request failed");
		dbus_message_unref(auth);
		return FALSE;
	}

	dbus_pending_call_set_notify(p, cb, user_data, NULL);
	if (pending)
		*pending = p;
	else
		dbus_pending_call_unref(p);

	dbus_message_unref(auth);

	return TRUE;
}

struct device *manager_find_device(bdaddr_t *bda, const char *interface,
					gboolean connected)
{
	GSList *l;

	if (!bacmp(bda, BDADDR_ANY) && !interface && !connected)
		return default_dev;

	for (l = devices; l != NULL; l = l->next) {
		struct device *dev = l->data;

		if (bacmp(bda, BDADDR_ANY) && bacmp(&dev->dst, bda))
			continue;

		if (interface && !strcmp(AUDIO_HEADSET_INTERFACE, interface)
				&& !dev->headset)
			continue;

		if (interface && !strcmp(AUDIO_SINK_INTERFACE, interface)
				&& !dev->sink)
			continue;

		if (interface && !strcmp(AUDIO_SOURCE_INTERFACE, interface)
				&& !dev->source)
			continue;

		if (interface && !strcmp(AUDIO_CONTROL_INTERFACE, interface)
				&& !dev->control)
			continue;

		if (connected && !device_is_connected(dev, interface))
			continue;

		return dev;
	}

	return NULL;
}
