// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright 2023-2024 NXP
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
#include "src/shared/ad.h"

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
#define BCAAS_UUID_STR "00001852-0000-1000-8000-00805f9b34fb"

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

static const char *const str_state[] = {
	"ASSISTANT_STATE_IDLE",
	"ASSISTANT_STATE_PENDING",
	"ASSISTANT_STATE_REQUESTING",
	"ASSISTANT_STATE_ACTIVE",
};

struct bass_data {
	struct btd_device *device;
	struct btd_service *service;
	struct bt_bass *bass;
	unsigned int src_id;
	unsigned int cp_id;
};

struct bass_assistant {
	struct btd_device *device;	/* Broadcast source device */
	struct bass_data *data;		/* BASS session with peer device */
	uint8_t sgrp;
	uint8_t bis;
	uint32_t bid;
	struct bt_iso_qos qos;
	struct iovec *meta;
	struct iovec *caps;
	enum assistant_state state;
	char *path;
};

struct bass_delegator {
	struct btd_device *device;	/* Broadcast source device */
	struct bt_bcast_src *src;
};

static struct queue *sessions;
static struct queue *assistants;
static struct queue *delegators;

static const char *state2str(enum assistant_state state);

static void bass_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static void assistant_set_state(struct bass_assistant *assistant,
					enum assistant_state state)
{
	enum assistant_state old_state = assistant->state;
	const char *str;

	if (old_state == state)
		return;

	assistant->state = state;

	DBG("State changed %s: %s -> %s", assistant->path, str_state[old_state],
							str_state[state]);

	str = state2str(state);

	if (g_strcmp0(str, state2str(old_state)) != 0)
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
						assistant->path,
						MEDIA_ASSISTANT_INTERFACE,
						"State");
}

static int assistant_parse_qos(struct bass_assistant *assistant,
						DBusMessageIter *iter)
{
	DBusMessageIter dict;
	const char *key;

	dbus_message_iter_recurse(iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter value, entry;
		int var;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		var = dbus_message_iter_get_arg_type(&value);

		if (!strcasecmp(key, "BCode")) {
			DBusMessageIter array;
			struct iovec iov = {0};

			if (var != DBUS_TYPE_ARRAY)
				return -EINVAL;

			dbus_message_iter_recurse(&value, &array);
			dbus_message_iter_get_fixed_array(&array,
							&iov.iov_base,
							(int *)&iov.iov_len);

			if (iov.iov_len != BT_BASS_BCAST_CODE_SIZE) {
				error("Invalid size for BCode: %zu != 16",
								iov.iov_len);
				return -EINVAL;
			}

			memcpy(assistant->qos.bcast.bcode, iov.iov_base,
								iov.iov_len);

			return 0;
		}

		dbus_message_iter_next(&dict);
	}

	return 0;
}

static int assistant_parse_props(struct bass_assistant *assistant,
					DBusMessageIter *props)
{
	DBusMessageIter value, entry, array;
	const char *key;

	while (dbus_message_iter_get_arg_type(props) == DBUS_TYPE_DICT_ENTRY) {
		dbus_message_iter_recurse(props, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (!strcasecmp(key, "Metadata")) {
			struct iovec iov;

			if (dbus_message_iter_get_arg_type(&value) !=
							DBUS_TYPE_ARRAY)
				goto fail;

			dbus_message_iter_recurse(&value, &array);
			dbus_message_iter_get_fixed_array(&array,
							&iov.iov_base,
							(int *)&iov.iov_len);

			util_iov_free(assistant->meta, 1);
			assistant->meta = util_iov_dup(&iov, 1);
			DBG("Parsed Metadata");
		} else if (!strcasecmp(key, "QoS")) {
			if (dbus_message_iter_get_arg_type(&value) !=
							DBUS_TYPE_ARRAY)
				goto fail;

			if (assistant_parse_qos(assistant, &value))
				goto fail;

			DBG("Parsed QoS");
		}

		dbus_message_iter_next(props);
	}

	return 0;

fail:
	DBG("Failed parsing %s", key);

	return -EINVAL;
}

static DBusMessage *push(DBusConnection *conn, DBusMessage *msg,
							  void *user_data)
{
	struct bass_assistant *assistant = user_data;
	struct bt_bass_bcast_audio_scan_cp_hdr hdr;
	struct bt_bass_add_src_params params;
	struct iovec iov = {0};
	uint32_t bis_sync = 0;
	uint8_t meta_len = 0;
	int err;
	DBusMessageIter props, dict;

	DBG("");

	dbus_message_iter_init(msg, &props);

	if (dbus_message_iter_get_arg_type(&props) != DBUS_TYPE_ARRAY) {
		DBG("Unable to parse properties");
		return btd_error_invalid_args(msg);
	}

	dbus_message_iter_recurse(&props, &dict);

	if (assistant_parse_props(assistant, &dict)) {
		DBG("Unable to parse properties");
		return btd_error_invalid_args(msg);
	}

	hdr.op = BT_BASS_ADD_SRC;

	if (device_get_le_address_type(assistant->device) == BDADDR_LE_PUBLIC)
		params.addr_type = BT_BASS_ADDR_PUBLIC;
	else
		params.addr_type = BT_BASS_ADDR_RANDOM;

	bacpy(&params.addr, device_get_address(assistant->device));
	put_le24(assistant->bid, params.bid);
	params.pa_sync = PA_SYNC_NO_PAST;
	params.pa_interval = PA_INTERVAL_UNKNOWN;
	params.num_subgroups = assistant->sgrp + 1;

	util_iov_append(&iov, &params, sizeof(params));

	/* Metadata and the BIS index associated with the MediaAssistant
	 * object will be set in the subgroup they belong to. For the other
	 * subgroups, no metadata and no BIS index will be provided.
	 */
	for (uint8_t sgrp = 0; sgrp < assistant->sgrp; sgrp++) {
		util_iov_append(&iov, &bis_sync, sizeof(bis_sync));
		util_iov_append(&iov, &meta_len, sizeof(meta_len));
	}

	bis_sync = (1 << (assistant->bis - 1));
	meta_len = assistant->meta->iov_len;

	util_iov_append(&iov, &bis_sync, sizeof(bis_sync));
	util_iov_append(&iov, &meta_len, sizeof(meta_len));
	util_iov_append(&iov, assistant->meta->iov_base,
				assistant->meta->iov_len);

	err = bt_bass_send(assistant->data->bass, &hdr, &iov);
	if (err) {
		DBG("Unable to send BASS Write Command");
		return btd_error_failed(msg, strerror(-err));
	}

	free(iov.iov_base);

	assistant_set_state(assistant, ASSISTANT_STATE_PENDING);

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

static void src_ad_search_bid(void *data, void *user_data)
{
	struct bt_ad_service_data *sd = data;
	struct bass_assistant *assistant = user_data;
	struct iovec iov;

	if (sd->uuid.type != BT_UUID16 || sd->uuid.value.u16 != BCAA_SERVICE)
		return;

	iov.iov_base = sd->data;
	iov.iov_len = sd->len;

	util_iov_pull_le24(&iov, &assistant->bid);
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

	btd_device_foreach_service_data(assistant->device, src_ad_search_bid,
							assistant);

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

	bt_bass_src_unregister(data->bass, data->src_id);
	bt_bass_cp_handler_unregister(data->bass, data->cp_id);

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

static int handle_add_src_req(struct bt_bcast_src *bcast_src,
			struct bt_bass_add_src_params *params,
			struct bass_data *data)
{
	struct btd_adapter *adapter = device_get_adapter(data->device);
	struct btd_device *device;
	struct bass_delegator *dg;

	/* Create device for Broadcast Source using the parameters
	 * provided by Broadcast Assistant.
	 */
	device = btd_adapter_get_device(adapter, &params->addr,
						params->addr_type);
	if (!device) {
		DBG("Unable to get device");
		return -EINVAL;
	}

	DBG("device %p", device);

	/* Probe Broadcast Source, if it has not already been
	 * autonomously probed inside BAP.
	 */
	if (!btd_device_get_service(device, BCAAS_UUID_STR))
		goto probe;

	return 0;

probe:
	dg = new0(struct bass_delegator, 1);
	if (!dg)
		return -ENOMEM;

	dg->device = device;
	dg->src = bcast_src;

	if (!delegators)
		delegators = queue_new();

	queue_push_tail(delegators, dg);

	DBG("delegator %p", dg);

	/* Probe device with BAP. */
	bap_scan_delegator_probe(device);

	return 0;
}

static int cp_handler(struct bt_bcast_src *bcast_src, uint8_t op, void *params,
		void *user_data)
{
	struct bass_data *data = user_data;
	int err = 0;

	switch (op) {
	case BT_BASS_ADD_SRC:
		err = handle_add_src_req(bcast_src, params, data);
		break;
	}

	return err;
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

	data->cp_id = bt_bass_cp_handler_register(data->bass,
			cp_handler, NULL, data);

	bass_data_add(data);
}

static void bass_handle_bcode_req(struct bass_assistant *assistant, int id)
{
	struct bt_bass_bcast_audio_scan_cp_hdr hdr;
	struct bt_bass_set_bcast_code_params params;
	struct iovec iov = {0};
	int err;

	assistant_set_state(assistant, ASSISTANT_STATE_REQUESTING);

	hdr.op = BT_BASS_SET_BCAST_CODE;

	params.id = id;
	memcpy(params.bcast_code, assistant->qos.bcast.bcode,
					BT_BASS_BCAST_CODE_SIZE);

	iov.iov_base = malloc0(sizeof(params));
	if (!iov.iov_base)
		return;

	util_iov_push_mem(&iov, sizeof(params), &params);

	err = bt_bass_send(assistant->data->bass, &hdr, &iov);
	if (err) {
		DBG("Unable to send BASS Write Command");
		return;
	}

	free(iov.iov_base);
}

static void bass_src_changed(uint8_t id, uint32_t bid, uint8_t enc,
					uint32_t bis_sync, void *user_data)
{
	const struct queue_entry *entry;

	for (entry = queue_get_entries(assistants); entry;
						entry = entry->next) {
		struct bass_assistant *assistant = entry->data;
		uint32_t bis = 1 << (assistant->bis - 1);

		if (assistant->bid != bid)
			/* Only handle assistant objects
			 * that match the source
			 */
			continue;

		switch (enc) {
		case BT_BASS_BIG_ENC_STATE_BCODE_REQ:
			if (assistant->state != ASSISTANT_STATE_PENDING)
				/* Only handle assistant objects that
				 * have been pushed by the user
				 */
				break;

			/* Provide Broadcast Code to peer */
			bass_handle_bcode_req(assistant, id);
			break;
		case BT_BASS_BIG_ENC_STATE_NO_ENC:
			if (assistant->state != ASSISTANT_STATE_PENDING)
				/* Only handle assistant objects that
				 * have been pushed by the user
				 */
				break;

			/* Match BIS index */
			if (bis & bis_sync)
				assistant_set_state(assistant,
						ASSISTANT_STATE_ACTIVE);
			break;
		case BT_BASS_BIG_ENC_STATE_DEC:
			/* Only handle assistant objects that
			 * have requested a Broadcast Code
			 */
			if (assistant->state != ASSISTANT_STATE_REQUESTING)
				break;

			/* Match BIS index */
			if (bis & bis_sync)
				assistant_set_state(assistant,
						ASSISTANT_STATE_ACTIVE);
			break;
		default:
			continue;
		}
	}
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

	/* Register callback to be called when notifications for
	 * Broadcast Receive State characteristics are received.
	 */
	data->src_id = bt_bass_src_register(data->bass, bass_src_changed,
						data, NULL);

	data->cp_id = bt_bass_cp_handler_register(data->bass,
			cp_handler, NULL, data);

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
