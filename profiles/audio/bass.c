// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright 2023 NXP
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <glib.h>

#include "gdbus/gdbus.h"

#include "lib/bluetooth.h"
#include "lib/uuid.h"

#include "src/dbus-common.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gatt-server.h"
#include "src/adapter.h"
#include "src/shared/bass.h"
#include "src/shared/bap.h"

#include "src/plugin.h"
#include "src/gatt-database.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/log.h"
#include "src/error.h"

#include "bass.h"
#include "bap.h"

#define BASS_UUID_STR "0000184f-0000-1000-8000-00805f9b34fb"

#define MEDIA_ASSISTANT_INTERFACE "org.bluez.MediaAssistant1"

enum assistant_state {
	ASSISTANT_STATE_IDLE,		/* Assistant object was created for
					 * the stream
					 */
	ASSISTANT_STATE_PENDING,	/* Assistant object was pushed */
	ASSISTANT_STATE_REQUESTING,	/* Remote device requires
					 * Broadcast_Code
					 */
	ASSISTANT_STATE_ACTIVE,		/* Remote device started receiving
					 * stream
					 */
};

struct bass_data {
	struct btd_device *device;
	struct btd_service *service;
	struct bt_bass *bass;
};

struct bass_assistant {
	struct btd_device *device;	/* Broadcast source device */
	struct bass_data *data;		/* BASS session with peer device */
	uint8_t sgrp;
	uint8_t bis;
	struct bt_iso_qos qos;
	struct iovec *meta;
	struct iovec *caps;
	enum assistant_state state;
	char *path;
};

static struct queue *sessions;
static struct queue *assistants;

static void bass_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static DBusMessage *push(DBusConnection *conn, DBusMessage *msg,
							  void *user_data)
{
	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable assistant_methods[] = {
	{GDBUS_EXPERIMENTAL_ASYNC_METHOD("Push",
					GDBUS_ARGS({ "Props", "a{sv}" }),
					NULL, push)},
	{},
};

static const char *state2str(enum assistant_state state)
{
	switch (state) {
	case ASSISTANT_STATE_IDLE:
		return "idle";
	case ASSISTANT_STATE_PENDING:
		return "pending";
	case ASSISTANT_STATE_REQUESTING:
		return "requesting";
	case ASSISTANT_STATE_ACTIVE:
		return "active";
	}

	return NULL;
}

static gboolean get_state(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bass_assistant *assistant = data;
	const char *state = state2str(assistant->state);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &state);

	return TRUE;
}

static gboolean get_metadata(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bass_assistant *assistant = data;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	if (assistant->meta)
		dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&assistant->meta->iov_base,
						assistant->meta->iov_len);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean get_qos(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bass_assistant *assistant = data;
	DBusMessageIter dict;
	uint8_t *bcode = assistant->qos.bcast.bcode;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	dict_append_entry(&dict, "Encryption", DBUS_TYPE_BYTE,
				&assistant->qos.bcast.encryption);
	dict_append_array(&dict, "BCode", DBUS_TYPE_BYTE,
				&bcode, BT_BASS_BCAST_CODE_SIZE);

	dbus_message_iter_close_container(iter, &dict);

	return TRUE;
}

static const GDBusPropertyTable assistant_properties[] = {
	{ "State", "s", get_state },
	{ "Metadata", "ay", get_metadata, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "QoS", "a{sv}", get_qos, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};

static void assistant_free(void *data)
{
	struct bass_assistant *assistant = data;

	g_free(assistant->path);
	util_iov_free(assistant->meta, 1);
	util_iov_free(assistant->caps, 1);

	free(assistant);
}

static struct bass_assistant *assistant_new(struct btd_adapter *adapter,
		struct btd_device *device, struct bass_data *data,
		uint8_t sgrp, uint8_t bis, struct bt_iso_qos *qos,
		struct iovec *meta, struct iovec *caps)
{
	struct bass_assistant *assistant;
	char src_addr[18];
	char dev_addr[18];

	assistant = new0(struct bass_assistant, 1);
	if (!assistant)
		return NULL;

	DBG("assistant %p", assistant);

	assistant->device = device;
	assistant->data = data;
	assistant->sgrp = sgrp;
	assistant->bis = bis;
	assistant->qos = *qos;
	assistant->meta = util_iov_dup(meta, 1);
	assistant->caps = util_iov_dup(caps, 1);

	ba2str(device_get_address(device), src_addr);
	ba2str(device_get_address(data->device), dev_addr);

	assistant->path = g_strdup_printf("%s/src_%s/dev_%s/bis%d",
		adapter_get_path(adapter), src_addr, dev_addr, bis);

	g_strdelimit(assistant->path, ":", '_');

	if (!assistants)
		assistants = queue_new();

	queue_push_tail(assistants, assistant);

	return assistant;
}

void bass_add_stream(struct btd_device *device, struct iovec *meta,
			struct iovec *caps, struct bt_iso_qos *qos,
			uint8_t sgrp, uint8_t bis)
{
	const struct queue_entry *entry;
	struct bt_bap *bap;
	struct bt_bap_pac *pac;
	struct bass_assistant *assistant;
	char addr[18];

	for (entry = queue_get_entries(sessions); entry; entry = entry->next) {
		struct bass_data *data = entry->data;
		struct btd_adapter *adapter = device_get_adapter(data->device);

		if (!bt_bass_get_client(data->bass))
			/* Only client sessions must be handled */
			continue;

		bap = bap_get_session(data->device);
		if (!bap)
			continue;

		/* Check stream capabilities against peer caps. */
		bt_bap_verify_bis(bap, bis, caps, &pac);

		if (!pac)
			/* Capabilities did not match. */
			continue;

		ba2str(device_get_address(device), addr);

		DBG("%s data %p BIS %d", addr, data, bis);

		assistant = assistant_new(adapter, device, data, sgrp,
							bis, qos, meta, caps);

		if (g_dbus_register_interface(btd_get_dbus_connection(),
						assistant->path,
						MEDIA_ASSISTANT_INTERFACE,
						assistant_methods, NULL,
						assistant_properties,
						assistant,
						assistant_free) == FALSE)
			DBG("Could not register path %s", assistant->path);
	}
}

static bool assistant_match_device(const void *data, const void *match_data)
{
	const struct bass_assistant *assistant = data;
	const struct btd_device *device = match_data;

	return (assistant->device == device);
}

static void unregister_assistant(void *data)
{
	struct bass_assistant *assistant = data;

	DBG("%p", assistant);

	g_dbus_unregister_interface(btd_get_dbus_connection(),
				assistant->path, MEDIA_ASSISTANT_INTERFACE);
}

void bass_remove_stream(struct btd_device *device)
{
	queue_remove_all(assistants, assistant_match_device,
		device, unregister_assistant);
}

static struct bass_data *bass_data_new(struct btd_device *device)
{
	struct bass_data *data;

	data = new0(struct bass_data, 1);
	data->device = device;

	return data;
}

static void bass_data_add(struct bass_data *data)
{
	DBG("data %p", data);

	if (queue_find(sessions, NULL, data)) {
		error("data %p already added", data);
		return;
	}

	bt_bass_set_debug(data->bass, bass_debug, NULL, NULL);

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, data);

	if (data->service)
		btd_service_set_user_data(data->service, data);
}

static bool match_data(const void *data, const void *match_data)
{
	const struct bass_data *bdata = data;
	const struct bt_bass *bass = match_data;

	return bdata->bass == bass;
}

static bool assistant_match_data(const void *data, const void *match_data)
{
	const struct bass_assistant *assistant = data;
	const struct bass_data *bdata = match_data;

	return (assistant->data == bdata);
}

static void bass_data_free(struct bass_data *data)
{
	if (data->service) {
		btd_service_set_user_data(data->service, NULL);
		bt_bass_set_user_data(data->bass, NULL);
	}

	bt_bass_unref(data->bass);

	queue_remove_all(assistants, assistant_match_data,
		data, unregister_assistant);

	free(data);
}

static void bass_data_remove(struct bass_data *data)
{
	DBG("data %p", data);

	if (!queue_remove(sessions, data))
		return;

	bass_data_free(data);

	if (queue_isempty(sessions)) {
		queue_destroy(sessions, NULL);
		sessions = NULL;
	}
}

static void bass_detached(struct bt_bass *bass, void *user_data)
{
	struct bass_data *data;

	DBG("%p", bass);

	data = queue_find(sessions, match_data, bass);
	if (!data) {
		error("Unable to find bass session");
		return;
	}

	/* If there is a service it means there is BASS thus we can keep
	 * instance allocated.
	 */
	if (data->service)
		return;

	bass_data_remove(data);
}

static void bass_attached(struct bt_bass *bass, void *user_data)
{
	struct bass_data *data;
	struct bt_att *att;
	struct btd_device *device;

	DBG("%p", bass);

	data = queue_find(sessions, match_data, bass);
	if (data)
		return;

	att = bt_bass_get_att(bass);
	if (!att)
		return;

	device = btd_adapter_find_device_by_fd(bt_att_get_fd(att));
	if (!device) {
		error("Unable to find device");
		return;
	}

	data = bass_data_new(device);
	data->bass = bass;

	bass_data_add(data);
}

static int bass_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct btd_adapter *adapter = device_get_adapter(device);
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct bass_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	/* Ignore, if we were probed for this device already */
	if (data) {
		error("Profile probed twice for the same device!");
		return -EINVAL;
	}

	data = bass_data_new(device);
	data->service = service;

	data->bass = bt_bass_new(btd_gatt_database_get_db(database),
					btd_device_get_gatt_db(device),
					btd_adapter_get_address(adapter));
	if (!data->bass) {
		error("Unable to create BASS instance");
		free(data);
		return -EINVAL;
	}

	bass_data_add(data);
	bt_bass_set_user_data(data->bass, service);

	return 0;
}

static void bass_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bass_data *data;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	data = btd_service_get_user_data(service);
	if (!data) {
		error("BASS service not handled by profile");
		return;
	}

	bass_data_remove(data);
}
static int bass_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct bass_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	if (!data) {
		error("BASS service not handled by profile");
		return -EINVAL;
	}

	if (!bt_bass_attach(data->bass, client)) {
		error("BASS unable to attach");
		return -EINVAL;
	}

	btd_service_connecting_complete(service, 0);

	return 0;
}

static int bass_disconnect(struct btd_service *service)
{
	struct bass_data *data = btd_service_get_user_data(service);
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	bt_bass_detach(data->bass);

	btd_service_disconnecting_complete(service, 0);

	return 0;
}

static int bass_server_probe(struct btd_profile *p,
				struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);

	DBG("BASS path %s", adapter_get_path(adapter));

	bt_bass_add_db(btd_gatt_database_get_db(database),
				btd_adapter_get_address(adapter));

	return 0;
}

static void bass_server_remove(struct btd_profile *p,
					struct btd_adapter *adapter)
{
	DBG("BASS remove Adapter");
}

static struct btd_profile bass_service = {
	.name		= "bass",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.remote_uuid	= BASS_UUID_STR,
	.device_probe	= bass_probe,
	.device_remove	= bass_remove,
	.accept		= bass_accept,
	.disconnect	= bass_disconnect,
	.adapter_probe	= bass_server_probe,
	.adapter_remove	= bass_server_remove,
	.experimental	= true,
};

static unsigned int bass_id;

static int bass_init(void)
{
	int err;

	err = btd_profile_register(&bass_service);
	if (err)
		return err;

	bass_id = bt_bass_register(bass_attached, bass_detached, NULL);

	return 0;
}

static void bass_exit(void)
{
	btd_profile_unregister(&bass_service);
	bt_bass_unregister(bass_id);
}

BLUETOOTH_PLUGIN_DEFINE(bass, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							bass_init, bass_exit)
