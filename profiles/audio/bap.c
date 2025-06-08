// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation. All rights reserved.
 *  Copyright 2023-2025 NXP
 *
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
#include <poll.h>
#include <errno.h>

#include <glib.h>

#include "gdbus/gdbus.h"

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/sdp.h"
#include "lib/uuid.h"
#include "lib/iso.h"

#include "src/btd.h"
#include "src/dbus-common.h"
#include "src/shared/util.h"
#include "src/shared/io.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gatt-server.h"
#include "src/shared/bap.h"

#include "btio/btio.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/gatt-database.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/log.h"
#include "src/error.h"

#define ISO_SOCKET_UUID "6fbaf188-05e0-496a-9885-d6ddfdb4e03e"
#define PACS_UUID_STR "00001850-0000-1000-8000-00805f9b34fb"
#define BCAAS_UUID_STR "00001852-0000-1000-8000-00805f9b34fb"
#define MEDIA_ENDPOINT_INTERFACE "org.bluez.MediaEndpoint1"
#define MEDIA_INTERFACE "org.bluez.Media1"

struct bap_setup {
	struct bap_ep *ep;
	struct bap_data *data;
	struct bt_bap_stream *stream;
	struct bt_bap_qos qos;
	int (*qos_parser)(struct bap_setup *setup, const char *key, int var,
							DBusMessageIter *iter);
	GIOChannel *io;
	unsigned int io_id;
	bool recreate;
	bool cig_active;
	uint8_t sid;
	bool config_pending;
	struct iovec *caps;
	struct iovec *metadata;
	unsigned int id;
	struct iovec *base;
	DBusMessage *msg;
	void (*destroy)(struct bap_setup *setup);
};

struct bap_ep {
	char *path;
	struct bap_data *data;
	struct bt_bap_pac *lpac;
	struct bt_bap_pac *rpac;
	uint32_t locations;
	uint16_t supported_context;
	uint16_t context;
	struct queue *setups;
};

struct bap_data {
	struct btd_device *device;
	struct btd_adapter *adapter;
	struct btd_service *service;
	struct bt_bap *bap;
	unsigned int ready_id;
	unsigned int state_id;
	unsigned int pac_id;
	struct queue *srcs;
	struct queue *snks;
	struct queue *bcast;
	struct queue *bcast_snks;
	struct queue *server_streams;
	GIOChannel *listen_io;
	unsigned int io_id;
	int selecting;
	void *user_data;
};

static struct queue *sessions;

static bool bap_data_set_user_data(struct bap_data *data, void *user_data)
{
	if (!data)
		return false;

	data->user_data = user_data;

	return true;
}

static void bap_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static void ep_unregister(void *data)
{
	struct bap_ep *ep = data;

	DBG("ep %p path %s", ep, ep->path);

	g_dbus_unregister_interface(btd_get_dbus_connection(), ep->path,
						MEDIA_ENDPOINT_INTERFACE);
}

static void setup_free(void *data);

static void bap_data_free(struct bap_data *data)
{
	if (data->listen_io) {
		g_io_channel_shutdown(data->listen_io, TRUE, NULL);
		g_io_channel_unref(data->listen_io);
	}

	if (data->io_id)
		g_source_remove(data->io_id);

	if (data->service && btd_service_get_user_data(data->service) == data)
		btd_service_set_user_data(data->service, NULL);

	queue_destroy(data->snks, ep_unregister);
	queue_destroy(data->srcs, ep_unregister);
	queue_destroy(data->bcast, ep_unregister);
	queue_destroy(data->server_streams, NULL);
	queue_destroy(data->bcast_snks, setup_free);
	bt_bap_ready_unregister(data->bap, data->ready_id);
	bt_bap_state_unregister(data->bap, data->state_id);
	bt_bap_pac_unregister(data->bap, data->pac_id);
	bt_bap_unref(data->bap);
	free(data);
}

static void bap_data_remove(struct bap_data *data)
{
	DBG("data %p", data);

	if (!queue_remove(sessions, data))
		return;

	bap_data_free(data);

	if (queue_isempty(sessions)) {
		queue_destroy(sessions, NULL);
		sessions = NULL;
	}
}

static void bap_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bap_data *data;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	data = btd_service_get_user_data(service);
	if (!data) {
		error("BAP service not handled by profile");
		return;
	}

	bap_data_remove(data);
}

static gboolean get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bap_ep *ep = data;
	const char *uuid;

	if (queue_find(ep->data->snks, NULL, ep))
		uuid = PAC_SINK_UUID;
	else if (queue_find(ep->data->srcs, NULL, ep))
		uuid = PAC_SOURCE_UUID;
	else if ((queue_find(ep->data->bcast, NULL, ep)
		&& (bt_bap_pac_get_type(ep->lpac) == BT_BAP_BCAST_SINK)))
		uuid = BCAA_SERVICE_UUID;
	else
		uuid = BAA_SERVICE_UUID;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &uuid);

	return TRUE;
}

static gboolean get_codec(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bap_ep *ep = data;
	uint8_t codec;

	/* For broadcast source, rpac is null so the codec
	 * is retrieved from the lpac
	 */
	if (ep->rpac == NULL)
		bt_bap_pac_get_codec(ep->lpac, &codec, NULL, NULL);
	else
		bt_bap_pac_get_codec(ep->rpac, &codec, NULL, NULL);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &codec);

	return TRUE;
}

static gboolean has_capabilities(const GDBusPropertyTable *property, void *data)
{
	struct bap_ep *ep = data;
	struct iovec *d = NULL;

	bt_bap_pac_get_codec(ep->rpac, NULL, &d, NULL);

	if (d)
		return TRUE;

	return FALSE;
}

static gboolean get_capabilities(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bap_ep *ep = data;
	DBusMessageIter array;
	struct iovec *d;

	bt_bap_pac_get_codec(ep->rpac, NULL, &d, NULL);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&d->iov_base, d->iov_len);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean has_metadata(const GDBusPropertyTable *property, void *data)
{
	struct bap_ep *ep = data;
	struct iovec *d = NULL;

	bt_bap_pac_get_codec(ep->rpac, NULL, NULL, &d);

	if (d)
		return TRUE;

	return FALSE;
}

static gboolean get_metadata(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bap_ep *ep = data;
	DBusMessageIter array;
	struct iovec *d;

	bt_bap_pac_get_codec(ep->rpac, NULL, NULL, &d);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&d->iov_base, d->iov_len);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean get_device(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bap_ep *ep = data;
	const char *path;

	if (bt_bap_pac_get_type(ep->lpac) == BT_BAP_BCAST_SOURCE)
		path = adapter_get_path(ep->data->adapter);
	else
		path = device_get_path(ep->data->device);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);

	return TRUE;
}

static gboolean get_locations(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bap_ep *ep = data;

	ep->locations = bt_bap_pac_get_locations(ep->rpac);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &ep->locations);

	return TRUE;
}

static gboolean get_supported_context(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bap_ep *ep = data;

	ep->supported_context = bt_bap_pac_get_supported_context(ep->rpac);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16,
					&ep->supported_context);

	return TRUE;
}

static gboolean get_context(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bap_ep *ep = data;

	ep->context = bt_bap_pac_get_context(ep->rpac);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &ep->context);

	return TRUE;
}

static gboolean qos_exists(const GDBusPropertyTable *property, void *data)
{
	struct bap_ep *ep = data;
	struct bt_bap_pac_qos *qos;

	qos = bt_bap_pac_get_qos(ep->rpac);
	if (!qos)
		return FALSE;

	return TRUE;
}

static gboolean get_qos(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bap_ep *ep = data;
	struct bt_bap_pac_qos *qos;
	DBusMessageIter dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	qos = bt_bap_pac_get_qos(ep->rpac);
	if (!qos)
		return FALSE;

	dict_append_entry(&dict, "Framing", DBUS_TYPE_BYTE, &qos->framing);
	dict_append_entry(&dict, "PHY", DBUS_TYPE_BYTE, &qos->phy);
	dict_append_entry(&dict, "Retransmissions", DBUS_TYPE_BYTE, &qos->rtn);
	dict_append_entry(&dict, "MaximumLatency", DBUS_TYPE_UINT16,
					&qos->latency);
	dict_append_entry(&dict, "MimimumDelay", DBUS_TYPE_UINT32,
					&qos->pd_min);
	dict_append_entry(&dict, "MaximumDelay", DBUS_TYPE_UINT32,
					&qos->pd_max);
	dict_append_entry(&dict, "PreferredMimimumDelay", DBUS_TYPE_UINT32,
					&qos->ppd_min);
	dict_append_entry(&dict, "PreferredMaximumDelay", DBUS_TYPE_UINT32,
					&qos->ppd_max);

	dbus_message_iter_close_container(iter, &dict);

	return TRUE;
}

static const GDBusPropertyTable ep_properties[] = {
	{ "UUID", "s", get_uuid, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Codec", "y", get_codec, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Capabilities", "ay", get_capabilities, NULL, has_capabilities,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Metadata", "ay", get_metadata, NULL, has_metadata,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Device", "o", get_device, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Locations", "u", get_locations, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "SupportedContext", "q", get_supported_context, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Context", "q", get_context, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "QoS", "a{sv}", get_qos, NULL, qos_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};

static int parse_array(DBusMessageIter *iter, struct iovec *iov)
{
	DBusMessageIter array;

	if (!iov)
		return 0;

	dbus_message_iter_recurse(iter, &array);
	dbus_message_iter_get_fixed_array(&array, &iov->iov_base,
						(int *)&iov->iov_len);

	return 0;
}

static int parse_io_qos(const char *key, int var, DBusMessageIter *iter,
				struct bt_bap_io_qos *qos)
{
	if (!strcasecmp(key, "Interval")) {
		if (var != DBUS_TYPE_UINT32)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->interval);
	} else if (!strcasecmp(key, "PHY")) {
		if (var != DBUS_TYPE_BYTE)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->phy);
	} else if (!strcasecmp(key, "SDU")) {
		if (var != DBUS_TYPE_UINT16)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->sdu);
	} else if (!strcasecmp(key, "Retransmissions")) {
		if (var != DBUS_TYPE_BYTE)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->rtn);
	} else if (!strcasecmp(key, "Latency")) {
		if (var != DBUS_TYPE_UINT16)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->latency);
	}

	return 0;
}

static int setup_parse_ucast_qos(struct bap_setup *setup, const char *key,
					int var, DBusMessageIter *iter)
{
	struct bt_bap_qos *qos = &setup->qos;

	if (!strcasecmp(key, "CIG")) {
		if (var != DBUS_TYPE_BYTE)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->ucast.cig_id);
	} else if (!strcasecmp(key, "CIS")) {
		if (var != DBUS_TYPE_BYTE)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->ucast.cis_id);
	} else if (!strcasecmp(key, "Framing")) {
		if (var != DBUS_TYPE_BYTE)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->ucast.framing);
	} else if (!strcasecmp(key, "PresentationDelay")) {
		if (var != DBUS_TYPE_UINT32)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->ucast.delay);
	} else if (!strcasecmp(key, "TargetLatency")) {
		if (var != DBUS_TYPE_BYTE)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->ucast.target_latency);
	} else {
		int err;

		err = parse_io_qos(key, var, iter, &qos->ucast.io_qos);
		if (err)
			return err;
	}

	return 0;
}

static void setup_bcast_destroy(struct bap_setup *setup)
{
	struct bt_bap_qos *qos = &setup->qos;

	util_iov_free(qos->bcast.bcode, 1);
}

static int setup_parse_bcast_qos(struct bap_setup *setup, const char *key,
					int var, DBusMessageIter *iter)
{
	struct bt_bap_qos *qos = &setup->qos;

	if (!strcasecmp(key, "Encryption")) {
		if (var != DBUS_TYPE_BYTE)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->bcast.encryption);
	} else if (!strcasecmp(key, "BIG")) {
		if (var != DBUS_TYPE_BYTE)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->bcast.big);
	} else if (!strcasecmp(key, "Options")) {
		if (var != DBUS_TYPE_BYTE)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->bcast.options);
	} else if (!strcasecmp(key, "Skip")) {
		if (var != DBUS_TYPE_UINT16)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->bcast.skip);
	} else if (!strcasecmp(key, "SyncTimeout")) {
		if (var != DBUS_TYPE_UINT16)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->bcast.sync_timeout);
	} else if (!strcasecmp(key, "SyncType")) {
		if (var != DBUS_TYPE_BYTE)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->bcast.sync_cte_type);
	} else if (!strcasecmp(key, "SyncFactor")) {
		if (var != DBUS_TYPE_BYTE)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->bcast.sync_factor);
	} else if (!strcasecmp(key, "MSE")) {
		if (var != DBUS_TYPE_BYTE)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->bcast.mse);
	} else if (!strcasecmp(key, "Timeout")) {
		if (var != DBUS_TYPE_UINT16)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->bcast.timeout);
	} else if (!strcasecmp(key, "PresentationDelay")) {
		if (var != DBUS_TYPE_UINT32)
			return -EINVAL;

		dbus_message_iter_get_basic(iter, &qos->bcast.delay);
	} else if (!strcasecmp(key, "BCode")) {
		struct iovec iov;

		if (var != DBUS_TYPE_ARRAY)
			return -EINVAL;

		memset(&iov, 0, sizeof(iov));

		parse_array(iter, &iov);

		if (iov.iov_len != 16) {
			error("Invalid size for BCode: %zu != 16", iov.iov_len);
			return -EINVAL;
		}

		util_iov_free(qos->bcast.bcode, 1);
		qos->bcast.bcode = util_iov_dup(&iov, 1);
	} else {
		int err;

		err = parse_io_qos(key, var, iter, &qos->bcast.io_qos);
		if (err)
			return err;
	}

	return 0;
}

static int setup_parse_qos(struct bap_setup *setup, DBusMessageIter *iter)
{
	DBusMessageIter array;
	const char *key;

	dbus_message_iter_recurse(iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter value, entry;
		int var, err;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		var = dbus_message_iter_get_arg_type(&value);

		err = setup->qos_parser(setup, key, var, &value);
		if (err) {
			DBG("Failed parsing %s", key);
			return err;
		}

		dbus_message_iter_next(&array);
	}

	return 0;
}

static int setup_parse_configuration(struct bap_setup *setup,
					DBusMessageIter *props)
{
	const char *key;
	struct iovec iov;

	memset(&iov, 0, sizeof(iov));

	while (dbus_message_iter_get_arg_type(props) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter value, entry;
		int var;

		dbus_message_iter_recurse(props, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		var = dbus_message_iter_get_arg_type(&value);

		if (!strcasecmp(key, "Capabilities")) {
			if (var != DBUS_TYPE_ARRAY)
				goto fail;

			if (parse_array(&value, &iov))
				goto fail;

			util_iov_free(setup->caps, 1);
			setup->caps = util_iov_dup(&iov, 1);
		} else if (!strcasecmp(key, "Metadata")) {
			if (var != DBUS_TYPE_ARRAY)
				goto fail;

			if (parse_array(&value, &iov))
				goto fail;

			util_iov_free(setup->metadata, 1);
			setup->metadata = util_iov_dup(&iov, 1);
		} else if (!strcasecmp(key, "QoS")) {
			if (var != DBUS_TYPE_ARRAY)
				goto fail;

			if (setup_parse_qos(setup, &value))
				goto fail;
		}

		dbus_message_iter_next(props);
	}

	return 0;

fail:
	DBG("Failed parsing %s", key);

	return -EINVAL;
}

static void qos_cb(struct bt_bap_stream *stream, uint8_t code, uint8_t reason,
					void *user_data)
{
	struct bap_setup *setup = user_data;
	DBusMessage *reply;

	DBG("stream %p code 0x%02x reason 0x%02x", stream, code, reason);

	setup->id = 0;

	if (!setup->msg)
		return;

	if (!code)
		reply = dbus_message_new_method_return(setup->msg);
	else
		reply = btd_error_failed(setup->msg, "Unable to configure");

	g_dbus_send_message(btd_get_dbus_connection(), reply);

	dbus_message_unref(setup->msg);
	setup->msg = NULL;
}

static void setup_create_io(struct bap_data *data, struct bap_setup *setup,
				struct bt_bap_stream *stream, int defer);

static int setup_qos(struct bap_setup *setup)
{
	struct bap_data *data = setup->ep->data;
	struct bt_bap_stream *stream = setup->stream;

	if (!stream)
		return -EINVAL;
	if (bt_bap_stream_get_state(stream) != BT_BAP_STREAM_STATE_CONFIG)
		goto error;
	if (setup->id)
		goto error;

	setup_create_io(data, setup, stream, true);
	if (!setup->io) {
		error("Unable to create io");
		goto error;
	}

	/* Wait QoS response to respond */
	setup->id = bt_bap_stream_qos(stream, &setup->qos, qos_cb, setup);
	if (!setup->id) {
		error("Failed to Configure QoS");
		goto error;
	}

	/* Bcast does not call the callback */
	if (bt_bap_stream_get_type(setup->stream) == BT_BAP_STREAM_TYPE_BCAST)
		setup->id = 0;

	return 0;

error:
	if (bt_bap_stream_get_state(stream) != BT_BAP_STREAM_STATE_RELEASING)
		bt_bap_stream_release(stream, NULL, NULL);
	return -EIO;
}

static void config_cb(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	struct bap_setup *setup = user_data;
	DBusMessage *reply;

	DBG("stream %p code 0x%02x reason 0x%02x", stream, code, reason);

	setup->id = 0;

	if (!code) {
		if (!setup->config_pending)
			setup_qos(setup);
		return;
	}

	if (!setup->msg)
		return;

	reply = btd_error_failed(setup->msg, "Unable to configure");
	g_dbus_send_message(btd_get_dbus_connection(), reply);

	dbus_message_unref(setup->msg);
	setup->msg = NULL;
}

static void setup_io_close(void *data, void *user_data)
{
	struct bap_setup *setup = data;
	int fd;

	if (setup->io_id) {
		g_source_remove(setup->io_id);
		setup->io_id = 0;
	}

	if (!setup->io)
		return;


	DBG("setup %p", setup);

	fd = g_io_channel_unix_get_fd(setup->io);
	close(fd);

	g_io_channel_unref(setup->io);
	setup->io = NULL;
	setup->cig_active = false;

	bt_bap_stream_io_connecting(setup->stream, -1);
}

static void ep_close(struct bap_ep *ep)
{
	if (!ep)
		return;

	queue_foreach(ep->setups, setup_io_close, NULL);
}

static struct bap_setup *setup_new(struct bap_ep *ep)
{
	struct bap_setup *setup;

	setup = new0(struct bap_setup, 1);
	setup->ep = ep;

	/* Broadcast Source has endpoints in bcast list, Broadcast Sink
	 * does not have endpoints
	 */
	if (((ep != NULL) && queue_find(ep->data->bcast, NULL, ep)) ||
			(ep == NULL)) {
		/* Mark BIG and BIS to be auto assigned */
		setup->qos.bcast.big = BT_ISO_QOS_BIG_UNSET;
		setup->qos.bcast.bis = BT_ISO_QOS_BIS_UNSET;
		setup->qos.bcast.sync_factor = BT_ISO_SYNC_FACTOR;
		setup->qos.bcast.sync_timeout = BT_ISO_SYNC_TIMEOUT;
		setup->qos.bcast.timeout = BT_ISO_SYNC_TIMEOUT;
		setup->qos_parser = setup_parse_bcast_qos;
		setup->destroy = setup_bcast_destroy;
	} else {
		/* Mark CIG and CIS to be auto assigned */
		setup->qos.ucast.cig_id = BT_ISO_QOS_CIG_UNSET;
		setup->qos.ucast.cis_id = BT_ISO_QOS_CIS_UNSET;
		setup->qos_parser = setup_parse_ucast_qos;
	}

	if (ep) {
		if (!ep->setups)
			ep->setups = queue_new();

		queue_push_tail(ep->setups, setup);

		DBG("ep %p setup %p", ep, setup);
	}

	return setup;
}

static void release_stream(struct bt_bap_stream *stream)
{
	switch (bt_bap_stream_get_state(stream)) {
	case BT_BAP_STREAM_STATE_IDLE:
	case BT_BAP_STREAM_STATE_RELEASING:
		break;
	default:
		bt_bap_stream_release(stream, NULL, NULL);
	}
}

static void setup_free(void *data)
{
	struct bap_setup *setup = data;
	DBusMessage *reply;

	DBG("%p", setup);

	if (setup->stream && setup->id) {
		bt_bap_stream_cancel(setup->stream, setup->id);
		setup->id = 0;
	}

	if (setup->msg) {
		reply = btd_error_failed(setup->msg, "Canceled");
		g_dbus_send_message(btd_get_dbus_connection(), reply);
		dbus_message_unref(setup->msg);
		setup->msg = NULL;
	}

	if (setup->ep)
		queue_remove(setup->ep->setups, setup);

	setup_io_close(setup, NULL);

	util_iov_free(setup->caps, 1);
	util_iov_free(setup->metadata, 1);
	util_iov_free(setup->base, 1);

	if (setup->destroy)
		setup->destroy(setup);

	bt_bap_stream_unlock(setup->stream);

	release_stream(setup->stream);

	free(setup);
}

static bool match_io_qos(const struct bt_bap_io_qos *io_qos,
		const struct bt_bap_io_qos *match)
{
	if (io_qos->interval != match->interval)
		return false;

	if (io_qos->latency != match->latency)
		return false;

	if (io_qos->sdu != match->sdu)
		return false;

	if (io_qos->phy != match->phy)
		return false;

	if (io_qos->rtn != match->rtn)
		return false;

	return true;
}

static bool match_bcast_qos(const struct bt_bap_bcast_qos *qos,
		const struct bt_bap_bcast_qos *match)
{
	if (qos->sync_factor != match->sync_factor)
		return false;

	if (qos->packing != match->packing)
		return false;

	if (qos->framing != match->framing)
		return false;

	if (qos->encryption != match->encryption)
		return false;

	if (qos->encryption && util_iov_memcmp(qos->bcode, match->bcode))
		return false;

	if (qos->options != match->options)
		return false;

	if (qos->skip != match->skip)
		return false;

	if (qos->sync_timeout != match->sync_timeout)
		return false;

	if (qos->sync_cte_type != match->sync_cte_type)
		return false;

	if (qos->mse != match->mse)
		return false;

	if (qos->timeout != match->timeout)
		return false;

	if (qos->pa_sync != match->pa_sync)
		return false;

	return match_io_qos(&qos->io_qos, &match->io_qos);
}

static bool setup_mismatch_qos(const void *data, const void *user_data)
{
	const struct bap_setup *setup = data;
	const struct bap_setup *match = user_data;

	/* Match setups that are part of the same BIG */
	if (setup == match ||
		setup->qos.bcast.big == BT_ISO_QOS_BIG_UNSET ||
		setup->qos.bcast.big != match->qos.bcast.big)
		return false;

	return !match_bcast_qos(&setup->qos.bcast, &match->qos.bcast);
}

static DBusMessage *set_configuration(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct bap_ep *ep = data;
	struct bap_setup *setup;
	const char *path;
	DBusMessageIter args, props;

	dbus_message_iter_init(msg, &args);

	dbus_message_iter_get_basic(&args, &path);
	dbus_message_iter_next(&args);

	dbus_message_iter_recurse(&args, &props);
	if (dbus_message_iter_get_arg_type(&props) != DBUS_TYPE_DICT_ENTRY)
		return btd_error_invalid_args(msg);

	/* Broadcast source supports multiple setups, each setup will be BIS
	 * and will be configured with the set_configuration command
	 * TO DO reconfiguration of a BIS.
	 */
	if (bt_bap_pac_get_type(ep->lpac) != BT_BAP_BCAST_SOURCE)
		ep_close(ep);

	setup = setup_new(ep);

	if (setup_parse_configuration(setup, &props) < 0) {
		DBG("Unable to parse configuration");
		setup_free(setup);
		return btd_error_invalid_args(msg);
	}

	if (bt_bap_pac_get_type(ep->lpac) == BT_BAP_BCAST_SOURCE)
		/* All streams in a BIG should have the same QoS.
		 * Check that the new configuration matches previous ones.
		 */
		if (queue_find(setup->ep->setups, setup_mismatch_qos, setup)) {
			setup_free(setup);
			return btd_error_invalid_args(msg);
		}

	setup->stream = bt_bap_stream_new(ep->data->bap, ep->lpac, ep->rpac,
						&setup->qos, setup->caps);
	bt_bap_stream_lock(setup->stream);
	bt_bap_stream_set_user_data(setup->stream, ep->path);
	setup->config_pending = true;
	setup->id = bt_bap_stream_config(setup->stream, &setup->qos,
						setup->caps, config_cb, setup);
	if (!setup->id) {
		DBG("Unable to config stream");
		setup_free(setup);
		return btd_error_invalid_args(msg);
	}

	if (setup->metadata && setup->metadata->iov_len)
		bt_bap_stream_metadata(setup->stream, setup->metadata, NULL,
								NULL);

	switch (bt_bap_stream_get_type(setup->stream)) {
	case BT_BAP_STREAM_TYPE_UCAST:
		setup->msg = dbus_message_ref(msg);
		break;
	case BT_BAP_STREAM_TYPE_BCAST:
		/* No message sent over the air for broadcast */
		setup->id = 0;
		setup->config_pending = false;

		if (ep->data->service)
			service_set_connecting(ep->data->service);

		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	}

	return NULL;
}

static bool stream_io_unset(const void *data, const void *user_data)
{
	struct bt_bap_stream *stream = (struct bt_bap_stream *)data;

	return !bt_bap_stream_get_io(stream);
}

static void iso_bcast_confirm_cb(GIOChannel *io, GError *err, void *user_data)
{
	struct bap_setup *setup = user_data;
	struct bt_bap_stream *stream = setup->stream;
	int fd;
	struct bap_data *bap_data = setup->data;

	DBG("BIG Sync completed");

	/* The order of the BIS fds notified from kernel corresponds
	 * to the order of the BISes that were enqueued before
	 * calling bt_io_bcast_accept.
	 */
	if (bt_bap_stream_get_io(stream))
		stream = queue_find(bt_bap_stream_io_get_links(stream),
				stream_io_unset, NULL);

	fd = g_io_channel_unix_get_fd(io);

	if (bt_bap_stream_set_io(stream, fd))
		g_io_channel_set_close_on_unref(io, FALSE);

	if (!queue_find(bt_bap_stream_io_get_links(stream),
				stream_io_unset, NULL)) {
		/* All fds have been notified. Mark service as connected. */
		btd_service_connecting_complete(bap_data->service, 0);

		g_io_channel_unref(bap_data->listen_io);
		g_io_channel_shutdown(bap_data->listen_io, TRUE, NULL);
		bap_data->listen_io = NULL;
	}
}

static void create_stream_for_bis(struct bap_data *bap_data,
				struct bt_bap_pac *lpac, uint8_t sid,
				struct bt_bap_qos *qos, struct iovec *caps,
				struct iovec *meta, char *path)
{
	struct bap_setup *setup;

	setup = setup_new(NULL);
	setup->qos = *qos;

	/* Create an internal copy for bcode */
	setup->qos.bcast.bcode = util_iov_dup(qos->bcast.bcode, 1);

	setup->data = bap_data;

	queue_push_tail(bap_data->bcast_snks, setup);

	/* Create and configure stream */
	setup->stream = bt_bap_stream_new(bap_data->bap,
			lpac, NULL, &setup->qos, caps);
	bt_bap_stream_lock(setup->stream);

	setup->sid = sid;
	bt_bap_stream_set_user_data(setup->stream, path);
	bt_bap_stream_config(setup->stream, &setup->qos,
			caps, NULL, NULL);
	bt_bap_stream_metadata(setup->stream, meta,
			NULL, NULL);
}

static void bis_handler(uint8_t sid, uint8_t bis, uint8_t sgrp,
			struct iovec *caps, struct iovec *meta,
			struct bt_bap_qos *qos, void *user_data)
{
	struct bap_data *data = user_data;
	struct bt_bap_pac *lpac;
	char *path;

	bt_bap_bis_probe(data->bap, sid, bis, sgrp, caps, meta, qos);

	/* Check if this BIS matches any local PAC */
	bt_bap_verify_bis(data->bap, bis, caps, &lpac);

	if (!lpac)
		return;

	if (asprintf(&path, "%s/sid%d/bis%d", device_get_path(data->device),
			sid, bis) < 0)
		return;

	create_stream_for_bis(data, lpac, sid, qos, caps, meta, path);
}

static gboolean big_info_report_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	GError *err = NULL;
	struct bap_data *data = user_data;
	struct bt_iso_base base;
	struct bt_iso_qos qos;
	struct iovec iov;
	struct bt_bap_qos bap_qos = {0};
	uint8_t sid;

	DBG("BIG Info received");

	bt_io_get(io, &err,
			BT_IO_OPT_BASE, &base,
			BT_IO_OPT_QOS, &qos,
			BT_IO_OPT_ISO_BC_SID, &sid,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		g_io_channel_shutdown(io, TRUE, NULL);
		data->io_id = 0;
		return FALSE;
	}

	/* Close the listen io */
	g_io_channel_shutdown(data->listen_io, TRUE, NULL);
	g_io_channel_unref(data->listen_io);
	data->listen_io = NULL;

	/* For short-lived PA, the sync is no longer needed at
	 * this point, so the io can be closed.
	 */
	g_io_channel_shutdown(io, TRUE, NULL);

	/* Analyze received BASE data and create remote media endpoints for each
	 * BIS matching our capabilities
	 */
	iov.iov_base = base.base;
	iov.iov_len = base.base_len;

	/* Create BAP QoS structure */
	bt_bap_iso_qos_to_bap_qos(&qos, &bap_qos);

	bt_bap_parse_base(sid, &iov, &bap_qos, bap_debug, bis_handler, data);

	util_iov_free(bap_qos.bcast.bcode, 1);

	service_set_connecting(data->service);

	data->io_id = 0;

	return FALSE;
}

static void iso_pa_sync_confirm_cb(GIOChannel *io, void *user_data)
{
	struct bap_data *data = user_data;
	/* PA Sync was established, wait for BIG Info report so that the
	 * encryption flag is also available.
	 */
	DBG("PA Sync done");
	data->io_id = g_io_add_watch(io, G_IO_OUT, big_info_report_cb,
								user_data);
}

static bool match_data_bap_data(const void *data, const void *match_data)
{
	const struct bap_data *bdata = data;
	const struct btd_adapter *adapter = match_data;

	return bdata->user_data == adapter;
}

static const GDBusMethodTable ep_methods[] = {
	{ GDBUS_EXPERIMENTAL_ASYNC_METHOD("SetConfiguration",
					GDBUS_ARGS({ "endpoint", "o" },
						{ "Configuration", "a{sv}" } ),
					NULL, set_configuration) },
	{ },
};

static void ep_cancel_select(struct bap_ep *ep);

static void ep_free(void *data)
{
	struct bap_ep *ep = data;
	struct queue *setups = ep->setups;

	ep_cancel_select(ep);

	ep->setups = NULL;
	queue_destroy(setups, setup_free);
	free(ep->path);
	free(ep);
}

struct match_ep {
	struct bt_bap_pac *lpac;
	struct bt_bap_pac *rpac;
};

static bool match_ep(const void *data, const void *user_data)
{
	const struct bap_ep *ep = data;
	const struct match_ep *match = user_data;

	if (ep->lpac != match->lpac)
		return false;

	return ep->rpac == match->rpac;
}

static struct bap_ep *ep_register_bcast(struct bap_data *data,
					struct bt_bap_pac *lpac,
					struct bt_bap_pac *rpac)
{
	struct btd_adapter *adapter = data->adapter;
	struct btd_device *device = data->device;
	struct bap_ep *ep;
	struct queue *queue;
	int i, err = 0;
	const char *suffix;
	struct match_ep match = { lpac, rpac };

	switch (bt_bap_pac_get_type(lpac)) {
	case BT_BAP_BCAST_SOURCE:
	case BT_BAP_BCAST_SINK:
		queue = data->bcast;
		i = queue_length(data->bcast);
		suffix = "bcast";
		break;
	default:
		return NULL;
	}

	ep = queue_find(queue, match_ep, &match);
	if (ep)
		return ep;

	ep = new0(struct bap_ep, 1);
	ep->data = data;
	ep->lpac = lpac;
	ep->rpac = rpac;

	if (device)
		ep->data->device = device;

	switch (bt_bap_pac_get_type(lpac)) {
	case BT_BAP_BCAST_SOURCE:
		err = asprintf(&ep->path, "%s/pac_%s%d",
				adapter_get_path(adapter), suffix, i);
		break;
	case BT_BAP_BCAST_SINK:
		err = asprintf(&ep->path, "%s/pac_%s%d",
				device_get_path(device), suffix, i);
		break;
	}

	if (err < 0) {
		error("Could not allocate path for remote pac %s/pac%d",
				adapter_get_path(adapter), i);
		free(ep);
		return NULL;
	}

	if (g_dbus_register_interface(btd_get_dbus_connection(),
			ep->path, MEDIA_ENDPOINT_INTERFACE,
			ep_methods, NULL, ep_properties,
			ep, ep_free) == FALSE) {
		error("Could not register remote ep %s", ep->path);
		ep_free(ep);
		return NULL;
	}

	/*
	 * The broadcast source local endpoint has only lpac and broadcast
	 * sink local endpoint has a rpac and a lpac
	 */
	if (rpac)
		bt_bap_pac_set_user_data(rpac, ep->path);

	DBG("ep %p lpac %p rpac %p path %s", ep, ep->lpac, ep->rpac, ep->path);

	queue_push_tail(queue, ep);

	return ep;
}

static void ep_update_properties(struct bap_ep *ep)
{
	if (!ep->rpac)
		return;

	if (ep->locations != bt_bap_pac_get_locations(ep->rpac))
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
						ep->path,
						MEDIA_ENDPOINT_INTERFACE,
						"Locations");

	if (ep->supported_context !=
				bt_bap_pac_get_supported_context(ep->rpac))
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
						ep->path,
						MEDIA_ENDPOINT_INTERFACE,
						"SupportedContext");

	if (ep->context != bt_bap_pac_get_context(ep->rpac))
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
						ep->path,
						MEDIA_ENDPOINT_INTERFACE,
						"Context");
}

static struct bap_ep *ep_register(struct btd_service *service,
					struct bt_bap_pac *lpac,
					struct bt_bap_pac *rpac)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bap_data *data = btd_service_get_user_data(service);
	struct bap_ep *ep;
	struct queue *queue;
	int i, err;
	const char *suffix;
	struct match_ep match = { lpac, rpac };

	switch (bt_bap_pac_get_type(rpac)) {
	case BT_BAP_SINK:
		queue = data->snks;
		i = queue_length(data->snks);
		suffix = "sink";
		break;
	case BT_BAP_SOURCE:
		queue = data->srcs;
		i = queue_length(data->srcs);
		suffix = "source";
		break;
	default:
		return NULL;
	}

	ep = queue_find(queue, match_ep, &match);
	if (ep) {
		ep_update_properties(ep);
		return ep;
	}

	ep = new0(struct bap_ep, 1);
	ep->data = data;
	ep->lpac = lpac;
	ep->rpac = rpac;

	err = asprintf(&ep->path, "%s/pac_%s%d", device_get_path(device),
		       suffix, i);
	if (err < 0) {
		error("Could not allocate path for remote pac %s/pac%d",
				device_get_path(device), i);
		free(ep);
		return NULL;
	}

	if (g_dbus_register_interface(btd_get_dbus_connection(),
				ep->path, MEDIA_ENDPOINT_INTERFACE,
				ep_methods, NULL, ep_properties,
				ep, ep_free) == FALSE) {
		error("Could not register remote ep %s", ep->path);
		ep_free(ep);
		return NULL;
	}

	bt_bap_pac_set_user_data(rpac, ep->path);

	DBG("ep %p lpac %p rpac %p path %s", ep, ep->lpac, ep->rpac, ep->path);

	queue_push_tail(queue, ep);

	return ep;
}

static void setup_config(void *data, void *user_data)
{
	struct bap_setup *setup = data;
	struct bap_ep *ep = setup->ep;

	DBG("setup %p caps %p metadata %p", setup, setup->caps,
						setup->metadata);

	/* TODO: Check if stream capabilities match add support for Latency
	 * and PHY.
	 */
	if (!setup->stream) {
		setup->stream = bt_bap_stream_new(ep->data->bap, ep->lpac,
						ep->rpac, &setup->qos,
						setup->caps);
		bt_bap_stream_lock(setup->stream);
	}

	setup->config_pending = true;
	setup->id = bt_bap_stream_config(setup->stream, &setup->qos,
						setup->caps, config_cb, setup);
	if (!setup->id) {
		DBG("Unable to config stream");
		setup_free(setup);
		return;
	}

	if (setup->metadata && setup->metadata->iov_len)
		bt_bap_stream_metadata(setup->stream, setup->metadata, NULL,
								NULL);

	bt_bap_stream_set_user_data(setup->stream, ep->path);
}

static void bap_config(void *data, void *user_data)
{
	struct bap_ep *ep = data;

	queue_foreach(ep->setups, setup_config, NULL);
}

static void select_cb(struct bt_bap_pac *pac, int err, struct iovec *caps,
				struct iovec *metadata, struct bt_bap_qos *qos,
				void *user_data)
{
	struct bap_ep *ep = user_data;
	struct bap_setup *setup;

	if (err) {
		error("err %d", err);
		ep->data->selecting--;
		goto done;
	}

	setup = setup_new(ep);
	setup->caps = util_iov_dup(caps, 1);
	setup->metadata = util_iov_dup(metadata, 1);
	setup->qos = *qos;

	DBG("selecting %d", ep->data->selecting);
	ep->data->selecting--;

done:
	if (ep->data->selecting)
		return;

	queue_foreach(ep->data->srcs, bap_config, NULL);
	queue_foreach(ep->data->snks, bap_config, NULL);
	queue_foreach(ep->data->bcast, bap_config, NULL);
}

static bool pac_register(struct bt_bap_pac *lpac, struct bt_bap_pac *rpac,
							void *user_data)
{
	struct btd_service *service = user_data;
	struct bap_ep *ep;

	DBG("lpac %p rpac %p", lpac, rpac);

	ep = ep_register(service, lpac, rpac);
	if (!ep)
		error("Unable to register endpoint for pac %p", rpac);

	return true;
}

static bool pac_select(struct bt_bap_pac *lpac, struct bt_bap_pac *rpac,
							void *user_data)
{
	struct btd_service *service = user_data;
	struct bap_data *data = btd_service_get_user_data(service);
	struct match_ep match = { lpac, rpac };
	struct queue *queue;
	struct bap_ep *ep;

	switch (bt_bap_pac_get_type(rpac)) {
	case BT_BAP_SINK:
		queue = data->snks;
		break;
	case BT_BAP_SOURCE:
		queue = data->srcs;
		break;
	default:
		return true;
	}

	ep = queue_find(queue, match_ep, &match);
	if (!ep) {
		error("Unable to find endpoint for pac %p", rpac);
		return true;
	}

	/* TODO: Cache LRU? */
	if (btd_service_is_initiator(service))
		bt_bap_select(lpac, rpac, &ep->data->selecting, select_cb, ep);

	return true;
}

static bool pac_cancel_select(struct bt_bap_pac *lpac, struct bt_bap_pac *rpac,
							void *user_data)
{
	struct bap_ep *ep = user_data;

	bt_bap_cancel_select(lpac, select_cb, ep);

	return true;
}

static void ep_cancel_select(struct bap_ep *ep)
{
	struct bt_bap *bap = ep->data->bap;

	bt_bap_foreach_pac(bap, BT_BAP_SOURCE, pac_cancel_select, ep);
	bt_bap_foreach_pac(bap, BT_BAP_SINK, pac_cancel_select, ep);
}

static bool pac_found_bcast(struct bt_bap_pac *lpac, struct bt_bap_pac *rpac,
							void *user_data)
{
	struct bap_data *data = user_data;
	struct bap_ep *ep;

	DBG("lpac %p rpac %p", lpac, rpac);

	ep = ep_register_bcast(user_data, lpac, rpac);
	if (!ep) {
		error("Unable to register endpoint for pac %p", rpac);
		return true;
	}

	/* Mark the device as connetable if an Endpoint is registered */
	if (data->device)
		btd_device_set_connectable(data->device, true);

	return true;
}

static void bap_ready(struct bt_bap *bap, void *user_data)
{
	struct btd_service *service = user_data;

	DBG("bap %p", bap);

	/* Register all ep before selecting, so that sound server
	 * knows all.
	 */
	bt_bap_foreach_pac(bap, BT_BAP_SOURCE, pac_register, service);
	bt_bap_foreach_pac(bap, BT_BAP_SINK, pac_register, service);

	bt_bap_foreach_pac(bap, BT_BAP_SOURCE, pac_select, service);
	bt_bap_foreach_pac(bap, BT_BAP_SINK, pac_select, service);
}

static bool match_setup_stream(const void *data, const void *user_data)
{
	const struct bap_setup *setup = data;
	const struct bt_bap_stream *stream = user_data;

	return setup->stream == stream;
}

static bool match_ep_stream(const void *data, const void *user_data)
{
	const struct bap_ep *ep = data;
	const struct bt_bap_stream *stream = user_data;

	return queue_find(ep->setups, match_setup_stream, stream);
}

static struct bap_setup *bap_find_setup_by_stream(struct bap_data *data,
					struct bt_bap_stream *stream)
{
	struct bap_ep *ep = NULL;
	struct queue *queue = NULL;

	switch (bt_bap_stream_get_type(stream)) {
	case BT_BAP_STREAM_TYPE_UCAST:
		ep = queue_find(data->snks, match_ep_stream, stream);
		if (!ep)
			ep = queue_find(data->srcs, match_ep_stream, stream);

		break;
	case BT_BAP_STREAM_TYPE_BCAST:
		ep = queue_find(data->bcast, match_ep_stream, stream);
		break;
	}

	if (ep)
		queue = ep->setups;
	else
		queue = data->bcast_snks;

	return queue_find(queue, match_setup_stream, stream);
}

static void iso_connect_bcast_cb(GIOChannel *chan, GError *err,
					gpointer user_data)
{
	struct bt_bap_stream *stream = user_data;
	int fd;

	if (err) {
		error("%s", err->message);
		bt_bap_stream_set_io(stream, -1);
		return;
	}

	DBG("ISO connected");

	fd = g_io_channel_unix_get_fd(chan);

	if (bt_bap_stream_set_io(stream, fd)) {
		bt_bap_stream_start(stream, NULL, NULL);
		g_io_channel_set_close_on_unref(chan, FALSE);
		return;
	}

	error("Unable to set IO");
	bt_bap_stream_set_io(stream, -1);
}

static void iso_connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct bt_bap_stream *stream = user_data;
	int fd;

	if (err) {
		error("%s", err->message);
		bt_bap_stream_set_io(stream, -1);
		return;
	}

	DBG("ISO connected");

	fd = g_io_channel_unix_get_fd(chan);

	if (bt_bap_stream_set_io(stream, fd)) {
		g_io_channel_set_close_on_unref(chan, FALSE);
		return;
	}

	error("Unable to set IO");
	bt_bap_stream_set_io(stream, -1);
}

static void bap_iso_qos(struct bt_bap_qos *qos, struct bt_iso_io_qos *io)
{
	if (!qos)
		return;

	io->interval = qos->ucast.io_qos.interval;
	io->latency = qos->ucast.io_qos.latency;
	io->sdu = qos->ucast.io_qos.sdu;
	io->phy = qos->ucast.io_qos.phy;
	io->rtn = qos->ucast.io_qos.rtn;
}

static bool match_stream_qos(const void *data, const void *user_data)
{
	const struct bt_bap_stream *stream = data;
	const struct bt_iso_qos *iso_qos = user_data;
	struct bt_bap_qos *qos;

	qos = bt_bap_stream_get_qos((void *)stream);

	if (iso_qos->ucast.cig != qos->ucast.cig_id)
		return false;

	return iso_qos->ucast.cis == qos->ucast.cis_id;
}

static void iso_confirm_cb(GIOChannel *io, void *user_data)
{
	struct bap_data *data = user_data;
	struct bt_bap_stream *stream;
	struct bt_iso_qos qos;
	char address[18];
	GError *err = NULL;

	bt_io_get(io, &err,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_QOS, &qos,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	DBG("ISO: incoming connect from %s (CIG 0x%02x CIS 0x%02x)",
					address, qos.ucast.cig, qos.ucast.cis);

	stream = queue_remove_if(data->server_streams, match_stream_qos, &qos);
	if (!stream) {
		error("No matching stream found");
		goto drop;
	}

	if (!bt_io_accept(io, iso_connect_cb, stream, NULL, &err)) {
		error("bt_io_accept: %s", err->message);
		g_error_free(err);
		goto drop;
	}

	return;

drop:
	g_io_channel_shutdown(io, TRUE, NULL);
}

static void setup_accept_io(struct bap_setup *setup,
				struct bt_bap_stream *stream,
				int fd, int defer)
{
	char c;
	struct pollfd pfd;
	socklen_t len;

	if (fd < 0 || defer)
		return;

	/* Check if socket has DEFER_SETUP set */
	len = sizeof(defer);
	if (getsockopt(fd, SOL_BLUETOOTH, BT_DEFER_SETUP, &defer, &len) < 0)
		/* Ignore errors since the fd may be connected already */
		return;

	if (!defer)
		return;

	DBG("stream %p fd %d defer %s", stream, fd, defer ? "true" : "false");

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLOUT;

	if (poll(&pfd, 1, 0) < 0) {
		error("poll: %s (%d)", strerror(errno), errno);
		goto fail;
	}

	if (!(pfd.revents & POLLOUT)) {
		if (read(fd, &c, 1) < 0) {
			error("read: %s (%d)", strerror(errno), errno);
			goto fail;
		}
	}

	setup->cig_active = true;

	return;

fail:
	close(fd);
}

struct cig_busy_data {
	struct btd_adapter *adapter;
	uint8_t cig;
};

static bool match_cig_active(const void *data, const void *match_data)
{
	const struct bap_setup *setup = data;
	const struct cig_busy_data *info = match_data;

	return (setup->qos.ucast.cig_id == info->cig) && setup->cig_active;
}

static bool cig_busy_ep(const void *data, const void *match_data)
{
	const struct bap_ep *ep = data;
	const struct cig_busy_data *info = match_data;

	return queue_find(ep->setups, match_cig_active, info);
}

static bool cig_busy_session(const void *data, const void *match_data)
{
	const struct bap_data *session = data;
	const struct cig_busy_data *info = match_data;

	if (device_get_adapter(session->device) != info->adapter)
		return false;

	return queue_find(session->snks, cig_busy_ep, match_data) ||
			queue_find(session->srcs, cig_busy_ep, match_data);
}

static bool is_cig_busy(struct bap_data *data, uint8_t cig)
{
	struct cig_busy_data info;

	if (cig == BT_ISO_QOS_CIG_UNSET)
		return false;

	info.adapter = device_get_adapter(data->device);
	info.cig = cig;

	return queue_find(sessions, cig_busy_session, &info);
}

static gboolean setup_io_recreate(void *user_data)
{
	struct bap_setup *setup = user_data;

	DBG("%p", setup);

	setup->io_id = 0;

	setup_create_io(setup->ep->data, setup, setup->stream, true);

	return FALSE;
}

static void setup_recreate(void *data, void *match_data)
{
	struct bap_setup *setup = data;
	struct cig_busy_data *info = match_data;

	if (setup->qos.ucast.cig_id != info->cig || !setup->recreate ||
						setup->io_id)
		return;

	setup->recreate = false;
	setup->io_id = g_idle_add(setup_io_recreate, setup);
}

static void recreate_cig_ep(void *data, void *match_data)
{
	struct bap_ep *ep = data;

	queue_foreach(ep->setups, setup_recreate, match_data);
}

static void recreate_cig_session(void *data, void *match_data)
{
	struct bap_data *session = data;
	struct cig_busy_data *info = match_data;

	if (device_get_adapter(session->device) != info->adapter)
		return;

	queue_foreach(session->snks, recreate_cig_ep, match_data);
	queue_foreach(session->srcs, recreate_cig_ep, match_data);
}

static void recreate_cig(struct bap_setup *setup)
{
	struct bap_data *data = setup->ep->data;
	struct cig_busy_data info;

	info.adapter = device_get_adapter(data->device);
	info.cig = setup->qos.ucast.cig_id;

	DBG("adapter %p setup %p recreate CIG %d", info.adapter, setup,
							info.cig);

	if (setup->qos.ucast.cig_id == BT_ISO_QOS_CIG_UNSET) {
		recreate_cig_ep(setup->ep, &info);
		return;
	}

	queue_foreach(sessions, recreate_cig_session, &info);
}

static void setup_io_disconnected(int cond, void *user_data)
{
	struct bap_setup *setup = user_data;

	DBG("%p recreate %s", setup, setup->recreate ? "true" : "false");

	setup->io_id = 0;

	setup_io_close(setup, NULL);

	/* Check if connecting recreate IO */
	if (!is_cig_busy(setup->ep->data, setup->qos.ucast.cig_id))
		recreate_cig(setup);
}

static void bap_connect_bcast_io_cb(GIOChannel *chan, GError *err,
					gpointer user_data)
{
	struct bap_setup *setup = user_data;

	if (!setup->stream)
		return;

	iso_connect_bcast_cb(chan, err, setup->stream);
}

static void bap_connect_io_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct bap_setup *setup = user_data;

	if (!setup->stream)
		return;

	iso_connect_cb(chan, err, setup->stream);
}

static void setup_connect_io(struct bap_data *data, struct bap_setup *setup,
				struct bt_bap_stream *stream,
				struct bt_iso_qos *qos, int defer)
{
	struct btd_adapter *adapter = device_get_adapter(data->device);
	GIOChannel *io;
	GError *err = NULL;
	int fd;

	/* If IO already set skip creating it again */
	if (bt_bap_stream_get_io(stream)) {
		DBG("setup %p stream %p has existing io", setup, stream);
		return;
	}

	if (bt_bap_stream_io_is_connecting(stream, &fd)) {
		setup_accept_io(setup, stream, fd, defer);
		return;
	}

	/* If IO channel still up or CIG is busy, wait for it to be
	 * disconnected and then recreate.
	 */
	if (setup->io || is_cig_busy(data, setup->qos.ucast.cig_id)) {
		DBG("setup %p stream %p defer %s wait recreate", setup, stream,
						defer ? "true" : "false");
		setup->recreate = true;
		return;
	}

	if (setup->io_id) {
		g_source_remove(setup->io_id);
		setup->io_id = 0;
	}

	DBG("setup %p stream %p defer %s", setup, stream,
				defer ? "true" : "false");

	io = bt_io_connect(bap_connect_io_cb, setup, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR,
				btd_adapter_get_address(adapter),
				BT_IO_OPT_SOURCE_TYPE,
				btd_adapter_get_address_type(adapter),
				BT_IO_OPT_DEST_BDADDR,
				device_get_address(data->device),
				BT_IO_OPT_DEST_TYPE,
				device_get_le_address_type(data->device),
				BT_IO_OPT_MODE, BT_IO_MODE_ISO,
				BT_IO_OPT_QOS, qos,
				BT_IO_OPT_DEFER_TIMEOUT, defer,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("%s", err->message);
		g_error_free(err);
		return;
	}

	setup->io_id = io_glib_add_err_watch(io, setup_io_disconnected, setup);

	setup->io = io;
	setup->cig_active = !defer;

	bt_bap_stream_io_connecting(stream, g_io_channel_unix_get_fd(io));
}

static void setup_connect_io_broadcast(struct bap_data *data,
					struct bap_setup *setup,
					struct bt_bap_stream *stream,
					struct bt_iso_qos *qos, int defer)
{
	struct btd_adapter *adapter = data->user_data;
	GIOChannel *io = NULL;
	GError *err = NULL;
	bdaddr_t dst_addr = {0};
	char addr[18];
	struct bt_iso_base base;

	/* If IO already set and we are in the creation step,
	 * skip creating it again
	 */
	if (bt_bap_stream_get_io(stream))
		return;

	if (setup->io_id) {
		g_source_remove(setup->io_id);
		setup->io_id = 0;
	}
	base.base_len = setup->base->iov_len;

	memset(base.base, 0, 248);
	memcpy(base.base, setup->base->iov_base, setup->base->iov_len);
	ba2str(btd_adapter_get_address(adapter), addr);

	DBG("setup %p stream %p", setup, stream);

	io = bt_io_connect(bap_connect_bcast_io_cb, setup, NULL, &err,
			BT_IO_OPT_SOURCE_BDADDR,
			btd_adapter_get_address(adapter),
			BT_IO_OPT_SOURCE_TYPE,
			btd_adapter_get_address_type(adapter),
			BT_IO_OPT_DEST_BDADDR,
			&dst_addr,
			BT_IO_OPT_DEST_TYPE,
			BDADDR_LE_PUBLIC,
			BT_IO_OPT_MODE, BT_IO_MODE_ISO,
			BT_IO_OPT_QOS, qos,
			BT_IO_OPT_BASE, &base,
			BT_IO_OPT_DEFER_TIMEOUT, defer,
			BT_IO_OPT_INVALID);

	if (!io) {
		error("%s", err->message);
		g_error_free(err);
		return;
	}

	setup->io_id = io_glib_add_err_watch(io, setup_io_disconnected, setup);

	setup->io = io;

	bt_bap_stream_io_connecting(stream, g_io_channel_unix_get_fd(io));
}

static void setup_listen_io(struct bap_data *data, struct bt_bap_stream *stream,
						struct bt_iso_qos *qos)
{
	struct btd_adapter *adapter = device_get_adapter(data->device);
	GIOChannel *io;
	GError *err = NULL;

	DBG("stream %p", stream);

	if (!data->server_streams)
		data->server_streams = queue_new();

	if (!queue_find(data->server_streams, NULL, stream))
		queue_push_tail(data->server_streams, stream);

	/* If IO already set skip creating it again */
	if (bt_bap_stream_get_io(stream) || data->listen_io)
		return;

	io = bt_io_listen(NULL, iso_confirm_cb, data, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR,
				btd_adapter_get_address(adapter),
				BT_IO_OPT_SOURCE_TYPE,
				btd_adapter_get_address_type(adapter),
				BT_IO_OPT_DEST_BDADDR,
				BDADDR_ANY,
				BT_IO_OPT_DEST_TYPE,
				BDADDR_LE_PUBLIC,
				BT_IO_OPT_MODE, BT_IO_MODE_ISO,
				BT_IO_OPT_QOS, qos,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("%s", err->message);
		g_error_free(err);
		return;
	}

	data->listen_io = io;
}

static int pa_sync(struct bap_data *data);
static void pa_and_big_sync(struct bap_setup *setup);

static void setup_accept_io_broadcast(struct bap_data *data,
					struct bap_setup *setup)
{
	pa_and_big_sync(setup);
}

static void setup_create_ucast_io(struct bap_data *data,
					struct bap_setup *setup,
					struct bt_bap_stream *stream,
					int defer)
{
	struct bt_bap_qos *qos[2] = {};
	struct bt_iso_qos iso_qos;

	if (!bt_bap_stream_io_get_qos(stream, &qos[0], &qos[1])) {
		error("bt_bap_stream_get_qos_links: failed");
		return;
	}

	memset(&iso_qos, 0, sizeof(iso_qos));

	iso_qos.ucast.cig = qos[0] ? qos[0]->ucast.cig_id :
						qos[1]->ucast.cig_id;
	iso_qos.ucast.cis = qos[0] ? qos[0]->ucast.cis_id :
						qos[1]->ucast.cis_id;

	bap_iso_qos(qos[0], &iso_qos.ucast.in);
	bap_iso_qos(qos[1], &iso_qos.ucast.out);

	if (setup)
		setup_connect_io(data, setup, stream, &iso_qos, defer);
	else
		setup_listen_io(data, stream, &iso_qos);
}

static void setup_create_bcast_io(struct bap_data *data,
					struct bap_setup *setup,
					struct bt_bap_stream *stream, int defer)
{
	struct bt_bap_qos *qos = &setup->qos;
	struct iovec *bcode = qos->bcast.bcode;
	struct bt_iso_qos iso_qos;

	memset(&iso_qos, 0, sizeof(iso_qos));

	iso_qos.bcast.big = setup->qos.bcast.big;
	iso_qos.bcast.bis = setup->qos.bcast.bis;
	iso_qos.bcast.sync_factor = setup->qos.bcast.sync_factor;
	iso_qos.bcast.packing = setup->qos.bcast.packing;
	iso_qos.bcast.framing = setup->qos.bcast.framing;
	iso_qos.bcast.encryption = setup->qos.bcast.encryption;
	if (bcode && bcode->iov_base)
		memcpy(iso_qos.bcast.bcode, bcode->iov_base, bcode->iov_len);
	iso_qos.bcast.options = setup->qos.bcast.options;
	iso_qos.bcast.skip = setup->qos.bcast.skip;
	iso_qos.bcast.sync_timeout = setup->qos.bcast.sync_timeout;
	iso_qos.bcast.sync_cte_type = setup->qos.bcast.sync_cte_type;
	iso_qos.bcast.mse = setup->qos.bcast.mse;
	iso_qos.bcast.timeout = setup->qos.bcast.timeout;
	memcpy(&iso_qos.bcast.out, &setup->qos.bcast.io_qos,
				sizeof(struct bt_iso_io_qos));

	if (bt_bap_stream_get_dir(stream) == BT_BAP_BCAST_SINK)
		setup_connect_io_broadcast(data, setup, stream, &iso_qos,
			defer);
	else
		setup_accept_io_broadcast(data, setup);
}

static void setup_create_io(struct bap_data *data, struct bap_setup *setup,
				struct bt_bap_stream *stream, int defer)
{
	DBG("setup %p stream %p defer %s", setup, stream,
				defer ? "true" : "false");

	switch (bt_bap_stream_get_type(stream)) {
	case BT_BAP_STREAM_TYPE_UCAST:
		setup_create_ucast_io(data, setup, stream, defer);
		break;
	case BT_BAP_STREAM_TYPE_BCAST:
		setup_create_bcast_io(data, setup, stream, defer);
		break;
	}
}

static void bap_state(struct bt_bap_stream *stream, uint8_t old_state,
				uint8_t new_state, void *user_data)
{
	struct bap_data *data = user_data;
	struct bap_setup *setup;

	DBG("stream %p: %s(%u) -> %s(%u)", stream,
			bt_bap_stream_statestr(old_state), old_state,
			bt_bap_stream_statestr(new_state), new_state);

	/* Ignore transitions back to same state (ASCS allows some of these).
	 * Of these we need to handle only the config->config case, which will
	 * occur when reconfiguring the codec from initial config state.
	 */
	if (new_state == old_state && new_state != BT_BAP_STREAM_STATE_CONFIG)
		return;

	setup = bap_find_setup_by_stream(data, stream);

	switch (new_state) {
	case BT_BAP_STREAM_STATE_IDLE:
		/* Release stream if idle */
		if (setup)
			setup_free(setup);
		else
			queue_remove(data->server_streams, stream);
		break;
	case BT_BAP_STREAM_STATE_CONFIG:
		if (setup) {
			setup->config_pending = false;
			setup_qos(setup);
		}
		break;
	case BT_BAP_STREAM_STATE_QOS:
			setup_create_io(data, setup, stream, true);
		break;
	case BT_BAP_STREAM_STATE_ENABLING:
		if (setup)
			setup_create_io(data, setup, stream, false);
		break;
	case BT_BAP_STREAM_STATE_STREAMING:
		break;
	}
}

/* This function will call setup_create_io on all BISes from a BIG.
 * The defer parameter will be set on true on all but the last one.
 * This is done to inform the kernel when to when to start the BIG.
 */
static bool create_io_bises(struct bap_setup *setup,
				uint8_t nb_bises, struct bap_data *data)
{
	const struct queue_entry *entry;
	struct bap_setup *ent_setup;
	bool defer = true;
	uint8_t active_bis_cnt = 1;

	for (entry = queue_get_entries(setup->ep->setups);
				entry; entry = entry->next) {
		ent_setup = entry->data;

		if (bt_bap_stream_get_qos(ent_setup->stream)->bcast.big !=
				bt_bap_stream_get_qos(setup->stream)->bcast.big)
			continue;

		if (active_bis_cnt == nb_bises)
			defer = false;

		setup_create_io(data, ent_setup, ent_setup->stream, defer);
		if (!ent_setup->io) {
			error("Unable to create io");
			goto fail;
		}

		active_bis_cnt++;
	}

	return true;

fail:
	/* Clear the io of the created sockets if one
	 * socket creation fails.
	 */
	for (entry = queue_get_entries(setup->ep->setups);
				entry; entry = entry->next) {
		ent_setup = entry->data;

		if (bt_bap_stream_get_qos(ent_setup->stream)->bcast.big !=
				bt_bap_stream_get_qos(setup->stream)->bcast.big)
			continue;

		if (setup->io)
			g_io_channel_unref(setup->io);
	}
	return false;
}

static void iterate_setup_update_base(void *data, void *user_data)
{
	struct bap_setup *setup = data;
	struct bap_setup *data_setup = user_data;

	if ((setup->stream != data_setup->stream) &&
		(setup->qos.bcast.big == data_setup->qos.bcast.big)) {

		if (setup->base)
			util_iov_free(setup->base, 1);

		setup->base = util_iov_dup(data_setup->base, 1);
	}
}

/* Function checks the state of all streams in the same BIG
 * as the parameter stream, so it can decide if any sockets need
 * to be created. Returns he number of streams that need a socket
 * from that BIG.
 */
static uint8_t get_streams_nb_by_state(struct bap_setup *setup)
{
	const struct queue_entry *entry;
	struct bap_setup *ent_setup;
	uint8_t stream_cnt = 0;

	if (setup->qos.bcast.big == BT_ISO_QOS_BIG_UNSET)
		/* If BIG ID is unset this is a single BIS BIG.
		 * return 1 as create one socket only for this BIS
		 */
		return 1;

	for (entry = queue_get_entries(setup->ep->setups);
				entry; entry = entry->next) {
		ent_setup = entry->data;

		/* Skip the curent stream form testing */
		if (ent_setup == setup) {
			stream_cnt++;
			continue;
		}

		/* Test only BISes for the same BIG */
		if (bt_bap_stream_get_qos(ent_setup->stream)->bcast.big !=
				bt_bap_stream_get_qos(setup->stream)->bcast.big)
			continue;

		if (bt_bap_stream_get_state(ent_setup->stream) ==
				BT_BAP_STREAM_STATE_STREAMING)
			/* If one stream in a multiple BIS BIG is in
			 * streaming state this means that just the current
			 * stream must have is socket created so return 1.
			 */
			return 1;
		else if (bt_bap_stream_get_state(ent_setup->stream) !=
				BT_BAP_STREAM_STATE_ENABLING)
			/* Not all streams form a BIG have received transport
			 * acquire, so wait for the other streams to.
			 */
			return 0;

		stream_cnt++;
	}

	/* Return the number of streams for the BIG
	 * as all are ready to create sockets
	 */
	return stream_cnt;
}

static void bap_state_bcast_src(struct bt_bap_stream *stream, uint8_t old_state,
				uint8_t new_state, void *user_data)
{
	struct bap_data *data = user_data;
	struct bap_setup *setup;
	bool defer = false;
	uint8_t nb_bises = 0;

	DBG("stream %p: %s(%u) -> %s(%u)", stream,
			bt_bap_stream_statestr(old_state), old_state,
			bt_bap_stream_statestr(new_state), new_state);

	/* Ignore transitions back to same state */
	if (new_state == old_state)
		return;

	setup = bap_find_setup_by_stream(data, stream);

	switch (new_state) {
	case BT_BAP_STREAM_STATE_IDLE:
		/* Release stream if idle */
		if (setup)
			setup_free(setup);
		break;
	case BT_BAP_STREAM_STATE_CONFIG:
		// TO DO Reconfiguration
		break;
	/* Use the ENABLING state to know when a transport
	 * linked to a stream has been acquired by a process
	 * and in the case of a BIG with one BIS stream goes
	 * in the ENABLING state waiting for the response
	 * from the kernel that the BIG has been created
	 * so it can go to the streaming state.
	 * For the case of a BIG with multiple BISes,
	 * the BIG is created when all BISes are acquired.
	 * So we use the ENABLING state to  verify that all
	 * transports attached to that streams form BIG have
	 * been acquired so we can create the BIG.
	 */
	case BT_BAP_STREAM_STATE_ENABLING:
		/* If the stream attached to a broadcast
		 * source endpoint generate the base.
		 */
		if (setup->base == NULL) {
			setup->base = bt_bap_stream_get_base(
					setup->stream);
			/* Set the generated BASE on all setups
			 * from the same BIG.
			 */
			queue_foreach(setup->ep->setups,
				iterate_setup_update_base, setup);
		}
		/* The kernel has 2 requirements when handling
		 * multiple BIS connections for the same BIG:
		 * 1 - setup_create_io for all but the last BIS
		 * must be with defer true so we can inform the
		 * kernel when to start the BIG.
		 * 2 - The order in which the setup_create_io
		 * are called must be in the order of BIS
		 * indexes in BASE from first to last.
		 * To address this requirement we will call
		 * setup_create_io on all BISes only when all
		 * transport acquire have been received and will
		 * send it in the order of the BIS index
		 * from BASE.
		 */
		nb_bises = get_streams_nb_by_state(setup);

		if (nb_bises == 1) {
			setup_create_io(data, setup,
			stream, defer);
			if (!setup->io) {
				error("Unable to create io");
				if (old_state !=
					BT_BAP_STREAM_STATE_RELEASING)
					bt_bap_stream_release(stream,
							NULL, NULL);
			}
			break;
		} else if (nb_bises == 0)
			break;

		if (!create_io_bises(setup, nb_bises, data)) {
			if (old_state !=
				BT_BAP_STREAM_STATE_RELEASING)
				bt_bap_stream_release(stream,
					NULL, NULL);
		}
		break;
	}
}

static bool link_enabled(const void *data, const void *match_data)
{
	struct bt_bap_stream *stream = (struct bt_bap_stream *)data;
	uint8_t state = bt_bap_stream_get_state(stream);

	return ((state == BT_BAP_STREAM_STATE_ENABLING) ||
			bt_bap_stream_get_io(stream));
}

static void bap_state_bcast_sink(struct bt_bap_stream *stream,
				uint8_t old_state, uint8_t new_state,
				void *user_data)
{
	struct bap_data *data = user_data;
	struct bap_setup *setup;
	bool defer = false;

	DBG("stream %p: %s(%u) -> %s(%u)", stream,
			bt_bap_stream_statestr(old_state), old_state,
			bt_bap_stream_statestr(new_state), new_state);

	if (new_state == old_state && new_state != BT_BAP_STREAM_STATE_CONFIG)
		return;

	setup = bap_find_setup_by_stream(data, stream);
	if (!setup)
		return;

	switch (new_state) {
	case BT_BAP_STREAM_STATE_IDLE:
		/* Release stream if idle */
		if (setup)
			setup_free(setup);
		break;
	case BT_BAP_STREAM_STATE_CONFIG:
		if (!setup)
			break;
		if (old_state ==
				BT_BAP_STREAM_STATE_STREAMING)
			setup_io_close(setup, NULL);
		break;
	case BT_BAP_STREAM_STATE_ENABLING:
		/* For a Broadcast Sink, the ENABLING state suggests that
		 * the upper layer process requires the stream to start
		 * receiving audio. This state is used to differentiate
		 * between all configured streams and the ones that have
		 * been enabled by the upper layer.
		 *
		 * Create stream io if not already created and if no
		 * link has been enabled or started.
		 *
		 * The first enabled link will create and set fds for
		 * all links.
		 */
		if (!bt_bap_stream_get_io(stream) &&
			!queue_find(bt_bap_stream_io_get_links(stream),
							link_enabled, NULL))
			setup_create_io(data, setup, stream, defer);

		break;
	}
}

static void pac_added(struct bt_bap_pac *pac, void *user_data)
{
	struct btd_service *service = user_data;
	struct bap_data *data;

	DBG("pac %p", pac);

	if (btd_service_get_state(service) != BTD_SERVICE_STATE_CONNECTED)
		return;

	data = btd_service_get_user_data(service);

	bt_bap_foreach_pac(data->bap, BT_BAP_SOURCE, pac_register, service);
	bt_bap_foreach_pac(data->bap, BT_BAP_SINK, pac_register, service);

	bt_bap_foreach_pac(data->bap, BT_BAP_SOURCE, pac_select, service);
	bt_bap_foreach_pac(data->bap, BT_BAP_SINK, pac_select, service);
}

static void pac_added_broadcast(struct bt_bap_pac *pac, void *user_data)
{
	struct bap_data *data = user_data;

	/*
	 * If pac type is BT_BAP_BCAST_SOURCE locally create an endpoint
	 * without a remote pac.
	 * If pac type is BT_BAP_BCAST_SOURCE and remote then look for a
	 * local broadcast sink pac locally before creating an endpoint.
	 */
	if (bt_bap_pac_bcast_is_local(data->bap, pac) &&
		(bt_bap_pac_get_type(pac) == BT_BAP_BCAST_SOURCE))
		pac_found_bcast(pac, NULL, user_data);
	else
		bt_bap_foreach_pac(data->bap, bt_bap_pac_get_type(pac),
					pac_found_bcast, data);
}

static bool ep_match_pac(const void *data, const void *match_data)
{
	const struct bap_ep *ep = data;
	const struct bt_bap_pac *pac = match_data;

	return ep->rpac == pac || ep->lpac == pac;
}

static void pac_removed(struct bt_bap_pac *pac, void *user_data)
{
	struct btd_service *service = user_data;
	struct bap_data *data;
	struct queue *queue;
	struct bap_ep *ep;

	DBG("pac %p", pac);

	if (btd_service_get_state(service) != BTD_SERVICE_STATE_CONNECTED)
		return;

	data = btd_service_get_user_data(service);

	switch (bt_bap_pac_get_type(pac)) {
	case BT_BAP_SINK:
		queue = data->srcs;
		break;
	case BT_BAP_SOURCE:
		queue = data->snks;
		break;
	default:
		return;
	}

	ep = queue_remove_if(queue, ep_match_pac, pac);
	if (!ep)
		return;

	ep_unregister(ep);
}

static void pac_removed_broadcast(struct bt_bap_pac *pac, void *user_data)
{
	struct bap_data *data = user_data;
	struct queue *queue;
	struct bap_ep *ep;

	DBG("pac %p", pac);

	switch (bt_bap_pac_get_type(pac)) {
	case BT_BAP_SINK:
		queue = data->srcs;
		break;
	case BT_BAP_SOURCE:
		queue = data->snks;
		break;
	case BT_BAP_BCAST_SOURCE:
		queue = data->bcast;
		break;
	default:
		return;
	}

	ep = queue_remove_if(queue, ep_match_pac, pac);
	if (!ep)
		return;

	ep_unregister(ep);
}

static bool match_device(const void *data, const void *match_data)
{
	const struct bap_data *bdata = data;
	const struct btd_device *device = match_data;

	return bdata->device == device;
}

static struct bap_data *bap_data_new(struct btd_device *device)
{
	struct bap_data *data;

	data = new0(struct bap_data, 1);
	data->device = device;
	data->srcs = queue_new();
	data->snks = queue_new();
	data->bcast = queue_new();

	return data;
}

static void bap_data_add(struct bap_data *data)
{
	DBG("data %p", data);

	if (queue_find(sessions, NULL, data)) {
		error("data %p already added", data);
		return;
	}

	bt_bap_set_debug(data->bap, bap_debug, NULL, NULL);

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, data);

	if (data->service && !btd_service_get_user_data(data->service))
		btd_service_set_user_data(data->service, data);
}

static bool match_data(const void *data, const void *match_data)
{
	const struct bap_data *bdata = data;
	const struct bt_bap *bap = match_data;

	return bdata->bap == bap;
}

static bool io_get_qos(GIOChannel *io, struct bt_iso_qos *qos)
{
	GError *err = NULL;
	bool ret;

	ret = bt_io_get(io, &err, BT_IO_OPT_QOS, qos, BT_IO_OPT_INVALID);
	if (!ret) {
		error("%s", err->message);
		g_error_free(err);
	}

	return ret;
}

static void bap_connecting(struct bt_bap_stream *stream, bool state, int fd,
							void *user_data)
{
	struct bap_data *data = user_data;
	struct bap_setup *setup;
	struct bt_bap_qos *qos;
	GIOChannel *io;

	if (!state)
		return;

	setup = bap_find_setup_by_stream(data, stream);
	if (!setup)
		return;

	setup->recreate = false;
	qos = &setup->qos;

	if (!setup->io) {
		io = g_io_channel_unix_new(fd);
		setup->io_id = io_glib_add_err_watch(io, setup_io_disconnected,
									setup);
		setup->io = io;
	} else
		io = setup->io;

	g_io_channel_set_close_on_unref(io, FALSE);

	/* Attempt to get CIG/CIS if they have not been set */
	if (qos->ucast.cig_id == BT_ISO_QOS_CIG_UNSET ||
			qos->ucast.cis_id == BT_ISO_QOS_CIS_UNSET) {
		struct bt_iso_qos iso_qos;

		if (!io_get_qos(io, &iso_qos)) {
			g_io_channel_unref(io);
			return;
		}

		qos->ucast.cig_id = iso_qos.ucast.cig;
		qos->ucast.cis_id = iso_qos.ucast.cis;
	}

	DBG("stream %p fd %d: CIG 0x%02x CIS 0x%02x", stream, fd,
			qos->ucast.cig_id, qos->ucast.cis_id);
}

static void bap_connecting_bcast(struct bt_bap_stream *stream, bool state,
							int fd, void *user_data)
{
	struct bap_data *data = user_data;
	struct bap_setup *setup;
	GIOChannel *io;

	if (!state)
		return;

	setup = bap_find_setup_by_stream(data, stream);
	if (!setup)
		return;

	setup->recreate = false;

	if (!setup->io) {
		io = g_io_channel_unix_new(fd);
		setup->io_id = io_glib_add_err_watch(io, setup_io_disconnected,
									setup);
		setup->io = io;
	} else
		io = setup->io;

	g_io_channel_set_close_on_unref(io, FALSE);

	/* Attempt to get BIG/BIS if they have not been set */
	if (setup->qos.bcast.big == BT_ISO_QOS_BIG_UNSET ||
			setup->qos.bcast.bis == BT_ISO_QOS_BIS_UNSET) {
		struct bt_iso_qos iso_qos;

		if (!io_get_qos(io, &iso_qos)) {
			g_io_channel_unref(io);
			return;
		}

		setup->qos.bcast.big = iso_qos.bcast.big;
		setup->qos.bcast.bis = iso_qos.bcast.bis;
		bt_bap_stream_qos(setup->stream, &setup->qos, NULL, NULL);
	}

	DBG("stream %p fd %d: BIG 0x%02x BIS 0x%02x", stream, fd,
			setup->qos.bcast.big, setup->qos.bcast.bis);
}

static void bap_attached(struct bt_bap *bap, void *user_data)
{
	struct bap_data *data;
	struct bt_att *att;
	struct btd_device *device;

	DBG("%p", bap);

	data = queue_find(sessions, match_data, bap);
	if (data)
		return;

	att = bt_bap_get_att(bap);
	if (!att)
		return;

	device = btd_adapter_find_device_by_fd(bt_att_get_fd(att));
	if (!device) {
		error("Unable to find device");
		return;
	}

	data = bap_data_new(device);
	data->bap = bap;

	bap_data_add(data);

	data->state_id = bt_bap_state_register(data->bap, bap_state,
						bap_connecting, data, NULL);
}

static void bap_detached(struct bt_bap *bap, void *user_data)
{
	struct bap_data *data;

	DBG("%p", bap);

	data = queue_find(sessions, match_data, bap);
	if (!data) {
		error("Unable to find bap session");
		return;
	}

	/* If there is a service it means there is PACS thus we can keep
	 * instance allocated.
	 */
	if (data->service)
		return;

	bap_data_remove(data);
}

static int pa_sync(struct bap_data *data)
{
	GError *err = NULL;
	uint8_t sid = 0xff;

	if (data->listen_io) {
		DBG("Already probed");
		return -1;
	}

	DBG("Create PA sync with this source");

	data->listen_io = bt_io_listen(NULL, iso_pa_sync_confirm_cb, data,
		NULL, &err,
		BT_IO_OPT_SOURCE_BDADDR,
		btd_adapter_get_address(data->adapter),
		BT_IO_OPT_SOURCE_TYPE,
		btd_adapter_get_address_type(data->adapter),
		BT_IO_OPT_DEST_BDADDR,
		device_get_address(data->device),
		BT_IO_OPT_DEST_TYPE,
		btd_device_get_bdaddr_type(data->device),
		BT_IO_OPT_MODE, BT_IO_MODE_ISO,
		BT_IO_OPT_QOS, &bap_sink_pa_qos,
		BT_IO_OPT_ISO_BC_SID, sid,
		BT_IO_OPT_INVALID);
	if (!data->listen_io) {
		error("%s", err->message);
		g_error_free(err);
	}

	return 0;
}

static void append_setup(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	struct sockaddr_iso_bc *addr = user_data;
	char *path = bt_bap_stream_get_user_data(stream);
	int bis = 1;
	int s_err;
	const char *strbis = NULL;

	strbis = strstr(path, "/bis");
	if (!strbis) {
		DBG("bis index cannot be found");
		return;
	}

	s_err = sscanf(strbis, "/bis%d", &bis);
	if (s_err == -1) {
		DBG("sscanf error");
		return;
	}

	DBG("Do BIG Sync with BIS %d", bis);

	addr->bc_bis[addr->bc_num_bis] = bis;
	addr->bc_num_bis++;
}

static void setup_refresh_qos(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	struct bap_data *bap_data = user_data;
	struct bap_setup *setup = bap_find_setup_by_stream(bap_data, stream);

	setup->qos = *bt_bap_stream_get_qos(stream);
}

static void iso_do_big_sync(GIOChannel *io, void *user_data)
{
	GError *err = NULL;
	struct bap_setup *setup = user_data;
	struct bap_data *data = setup->data;
	struct sockaddr_iso_bc iso_bc_addr = {0};
	struct bt_iso_qos qos;
	struct queue *links = bt_bap_stream_io_get_links(setup->stream);

	DBG("PA Sync done");

	g_io_channel_unref(data->listen_io);
	g_io_channel_shutdown(data->listen_io, TRUE, NULL);
	data->listen_io = io;
	g_io_channel_ref(data->listen_io);

	/* Append each linked BIS to the BIG sync request */
	append_setup(setup->stream, &iso_bc_addr);
	queue_foreach(links, append_setup, &iso_bc_addr);

	/* Refresh qos stored in setups */
	setup->qos = *bt_bap_stream_get_qos(setup->stream);
	queue_foreach(links, setup_refresh_qos, data);

	/* Set the user requested QOS */
	bt_bap_qos_to_iso_qos(&setup->qos, &qos);

	if (!bt_io_set(io, &err,
			BT_IO_OPT_QOS, &qos,
			BT_IO_OPT_INVALID)) {
		error("bt_io_set: %s", err->message);
		g_error_free(err);
	}

	if (!bt_io_bcast_accept(io,
			iso_bcast_confirm_cb,
			setup, NULL, &err,
			BT_IO_OPT_ISO_BC_NUM_BIS,
			iso_bc_addr.bc_num_bis, BT_IO_OPT_ISO_BC_BIS,
			iso_bc_addr.bc_bis, BT_IO_OPT_INVALID)) {
		error("bt_io_bcast_accept: %s", err->message);
		g_error_free(err);
	}
}

static void pa_and_big_sync(struct bap_setup *setup)
{
	GError *err = NULL;
	struct bap_data *bap_data = setup->data;

	DBG("Create PA sync with this source");
	bap_data->listen_io = bt_io_listen(NULL, iso_do_big_sync, setup,
			NULL, &err,
			BT_IO_OPT_SOURCE_BDADDR,
			btd_adapter_get_address(bap_data->adapter),
			BT_IO_OPT_DEST_BDADDR,
			device_get_address(bap_data->device),
			BT_IO_OPT_DEST_TYPE,
			btd_device_get_bdaddr_type(bap_data->device),
			BT_IO_OPT_MODE, BT_IO_MODE_ISO,
			BT_IO_OPT_QOS, &bap_sink_pa_qos,
			BT_IO_OPT_ISO_BC_SID, setup->sid,
			BT_IO_OPT_INVALID);
	if (!bap_data->listen_io) {
		error("%s", err->message);
		g_error_free(err);
	}
}

static int bap_bcast_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct btd_adapter *adapter = device_get_adapter(device);
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct bap_data *data;

	if (!btd_adapter_has_exp_feature(adapter, EXP_FEAT_ISO_SOCKET)) {
		error("BAP requires ISO Socket which is not enabled");
		return -ENOTSUP;
	}

	data = bap_data_new(device);
	data->service = service;
	data->adapter = adapter;
	data->device = device;
	data->bap = bt_bap_new(btd_gatt_database_get_db(database),
			btd_gatt_database_get_db(database));
	if (!data->bap) {
		error("Unable to create BAP instance");
		free(data);
		return -EINVAL;
	}
	data->bcast_snks = queue_new();

	bt_bap_set_user_data(data->bap, service);

	if (!bt_bap_attach(data->bap, NULL)) {
		error("BAP unable to attach");
		return -EINVAL;
	}

	bap_data_add(data);

	data->ready_id = bt_bap_ready_register(data->bap, bap_ready, service,
								NULL);
	data->state_id = bt_bap_state_register(data->bap, bap_state_bcast_sink,
					bap_connecting_bcast, data, NULL);
	data->pac_id = bt_bap_pac_register(data->bap, pac_added_broadcast,
				pac_removed_broadcast, data, NULL);

	if (btd_service_get_user_data(service) == data)
		/* If the reference to the bap session has been set as service
		 * user data, it means the broadcaster was autonomously probed.
		 * Thus, the Broadcast Sink needs to create short lived PA sync
		 * to discover streams.
		 *
		 * If the service user data does not match the bap session, it
		 * means that the broadcaster was probed via a Broadcast
		 * Assistant from the BASS plugin, where stream discovery and
		 * configuration will also be handled.
		 */
		pa_sync(data);

	return 0;
}

static void bap_bcast_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bap_data *data;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	data = queue_find(sessions, match_device, device);
	if (!data) {
		error("BAP service not handled by profile");
		return;
	}

	bt_bap_bis_remove(data->bap);

	bap_data_remove(data);
}

static int bap_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct btd_adapter *adapter = device_get_adapter(device);
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct bap_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	if (!btd_adapter_has_exp_feature(adapter, EXP_FEAT_ISO_SOCKET)) {
		error("BAP requires ISO Socket which is not enabled");
		return -ENOTSUP;
	}

	/* Ignore, if we were probed for this device already */
	if (data) {
		error("Profile probed twice for the same device!");
		return -EINVAL;
	}

	data = bap_data_new(device);
	data->service = service;

	data->bap = bt_bap_new(btd_gatt_database_get_db(database),
					btd_device_get_gatt_db(device));
	if (!data->bap) {
		error("Unable to create BAP instance");
		free(data);
		return -EINVAL;
	}

	bap_data_add(data);

	data->ready_id = bt_bap_ready_register(data->bap, bap_ready, service,
								NULL);
	data->state_id = bt_bap_state_register(data->bap, bap_state,
						bap_connecting, data, NULL);
	data->pac_id = bt_bap_pac_register(data->bap, pac_added, pac_removed,
						service, NULL);

	bt_bap_set_user_data(data->bap, service);

	return 0;
}

static int bap_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct bap_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	if (!data) {
		error("BAP service not handled by profile");
		return -EINVAL;
	}

	if (!bt_bap_attach(data->bap, client)) {
		error("BAP unable to attach");
		return -EINVAL;
	}

	btd_service_connecting_complete(service, 0);

	return 0;
}

static bool ep_remove(const void *data, const void *match_data)
{
	ep_unregister((void *)data);

	return true;
}

static int bap_disconnect(struct btd_service *service)
{
	struct bap_data *data = btd_service_get_user_data(service);

	queue_remove_all(data->snks, ep_remove, NULL, NULL);
	queue_remove_all(data->srcs, ep_remove, NULL, NULL);

	bt_bap_detach(data->bap);

	btd_service_disconnecting_complete(service, 0);

	return 0;
}

static int bap_bcast_disconnect(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bap_data *data;

	data = queue_find(sessions, match_device, device);
	if (!data) {
		error("BAP service not handled by profile");
		return -EINVAL;
	}

	bt_bap_detach(data->bap);

	btd_service_disconnecting_complete(service, 0);

	return 0;
}

static int bap_adapter_probe(struct btd_profile *p, struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct bap_data *data;
	char addr[18];

	ba2str(btd_adapter_get_address(adapter), addr);
	DBG("%s", addr);

	if (!btd_kernel_experimental_enabled(ISO_SOCKET_UUID)) {
		error("BAP requires ISO Socket which is not enabled");
		return -ENOTSUP;
	}

	data = bap_data_new(NULL);

	data->bap = bt_bap_new(btd_gatt_database_get_db(database),
					btd_gatt_database_get_db(database));
	if (!data->bap) {
		error("Unable to create BAP instance");
		free(data);
		return -EINVAL;
	}

	bap_data_add(data);

	if (!bt_bap_attach_broadcast(data->bap)) {
		error("BAP unable to attach");
		return -EINVAL;
	}

	data->state_id = bt_bap_state_register(data->bap, bap_state_bcast_src,
					bap_connecting_bcast, data, NULL);
	data->pac_id = bt_bap_pac_register(data->bap, pac_added_broadcast,
					pac_removed_broadcast, data, NULL);

	bap_data_set_user_data(data, adapter);

	data->adapter = adapter;

	return 0;
}

static void bap_adapter_remove(struct btd_profile *p,
					struct btd_adapter *adapter)
{
	struct bap_data *data = queue_find(sessions, match_data_bap_data,
						adapter);
	char addr[18];

	ba2str(btd_adapter_get_address(adapter), addr);
	DBG("%s", addr);

	if (!data) {
		error("BAP service not handled by profile");
		return;
	}

	bap_data_remove(data);
}

static struct btd_profile bap_profile = {
	.name		= "bap",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.remote_uuid	= PACS_UUID_STR,
	.device_probe	= bap_probe,
	.device_remove	= bap_remove,
	.accept		= bap_accept,
	.disconnect	= bap_disconnect,
	.adapter_probe	= bap_adapter_probe,
	.adapter_remove	= bap_adapter_remove,
	.auto_connect	= true,
	.experimental	= true,
};

static struct btd_profile bap_bcast_profile = {
	.name		= "bcaa",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.remote_uuid	= BCAAS_UUID_STR,
	.device_probe	= bap_bcast_probe,
	.device_remove	= bap_bcast_remove,
	.disconnect	= bap_bcast_disconnect,
	.auto_connect	= false,
	.experimental	= true,
};

static unsigned int bap_id = 0;

static int bap_init(void)
{
	int err;

	err = btd_profile_register(&bap_profile);
	if (err)
		return err;

	err = btd_profile_register(&bap_bcast_profile);
	if (err)
		return err;

	bap_id = bt_bap_register(bap_attached, bap_detached, NULL);

	return 0;
}

static void bap_exit(void)
{
	btd_profile_unregister(&bap_profile);
	bt_bap_unregister(bap_id);
}

BLUETOOTH_PLUGIN_DEFINE(bap, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							bap_init, bap_exit)
