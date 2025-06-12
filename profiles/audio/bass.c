// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright 2023-2025 NXP
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
#include "lib/iso.h"

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

#include "btio/btio.h"
#include "src/plugin.h"
#include "src/gatt-database.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/log.h"
#include "src/error.h"

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
	unsigned int bis_id;
};

struct bass_assistant {
	struct btd_device *device;	/* Broadcast source device */
	struct bass_data *data;		/* BASS session with peer device */
	uint8_t sgrp;
	uint8_t sid;
	uint8_t bis;
	uint32_t bid;
	struct bt_bap_qos qos;
	struct iovec *meta;
	struct iovec *caps;
	enum assistant_state state;
	char *path;
};

struct bass_delegator {
	struct btd_device *device;	/* Broadcast source device */
	struct btd_service *service;
	struct bt_bcast_src *src;
	struct bt_bap *bap;
	unsigned int state_id;
	unsigned int bcode_id;
	uint8_t sid;
	uint8_t *bcode;
	unsigned int timeout;
	struct queue *bcode_reqs;
	struct queue *setups;
	unsigned int io_id;
	GIOChannel *io;
};

struct bass_setup {
	struct bass_delegator *dg;
	char *path;
	struct bt_bap_stream *stream;
	uint8_t bis;
	struct bt_bap_qos qos;
	struct iovec *meta;
	struct iovec *config;
	struct bt_bap_pac *lpac;
};

struct bass_bcode_req {
	struct bass_setup *setup;
	bt_bap_bcode_reply_t cb;
	void *user_data;
};

static struct queue *sessions;
static struct queue *assistants;
static struct queue *delegators;

static const char *state2str(enum assistant_state state);

static struct bass_data *bass_data_new(struct btd_device *device);
static void bass_data_add(struct bass_data *data);
static void bass_data_remove(struct bass_data *data);

static void bis_probe(uint8_t sid, uint8_t bis, uint8_t sgrp,
			struct iovec *caps, struct iovec *meta,
			struct bt_bap_qos *qos, void *user_data);
static void bis_remove(struct bt_bap *bap, void *user_data);


static void bass_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static gboolean req_timeout(gpointer user_data)
{
	struct bass_delegator *dg = user_data;
	struct bass_bcode_req *req;

	DBG("delegator %p", dg);

	dg->timeout = 0;

	while ((req = queue_pop_head(dg->bcode_reqs))) {
		if (req->cb)
			req->cb(req->user_data, -ETIMEDOUT);

		free(req);
	}

	return FALSE;
}

static bool delegator_match_bap(const void *data, const void *match_data)
{
	const struct bass_delegator *dg = data;
	const struct bt_bap *bap = match_data;

	return dg->bap == bap;
}

static void setup_set_bcode(uint8_t *bcode, struct bass_setup *setup,
				bt_bap_bcode_reply_t cb, void *user_data)
{
	struct bt_bap_qos *qos = bt_bap_stream_get_qos(setup->stream);

	/* Allocate Broadcast Code inside setup QoS */
	util_iov_free(setup->qos.bcast.bcode, 1);
	setup->qos.bcast.bcode = util_iov_new(bcode, BT_BASS_BCAST_CODE_SIZE);

	/* Refresh stream bcode */
	qos->bcast.bcode = setup->qos.bcast.bcode;

	if (cb)
		cb(user_data, 0);
}

static bool match_setup_stream(const void *data, const void *user_data)
{
	const struct bass_setup *setup = data;
	const struct bt_bap_stream *stream = user_data;

	return setup->stream == stream;
}

static void bass_req_bcode(struct bt_bap_stream *stream,
	bt_bap_bcode_reply_t reply, void *reply_data,
	void *user_data)
{
	struct bt_bap *bap = bt_bap_stream_get_session(stream);
	struct bass_delegator *dg;
	struct bass_bcode_req *req;
	struct bass_setup *setup;

	dg = queue_find(delegators, delegator_match_bap, bap);
	if (!dg) {
		reply(reply_data, -EINVAL);
		return;
	}

	setup = queue_find(dg->setups, match_setup_stream, stream);
	if (!setup) {
		reply(reply_data, -EINVAL);
		return;
	}

	if (dg->bcode) {
		/* Broadcast Code has already been received before. */
		setup_set_bcode(dg->bcode, setup, reply, reply_data);
		return;
	}

	/* Create a request for the Broadcast Code. The request
	 * will be considered handled when the Broadcast Code is
	 * received from a Broadcast Assistant.
	 */
	req = new0(struct bass_bcode_req, 1);
	if (!req)
		return;

	req->setup = setup;
	req->cb = reply;
	req->user_data = reply_data;

	queue_push_tail(dg->bcode_reqs, req);

	/* Mark the encryption status as "Broadcast Code Required"
	 * in the Broadcast Receive State characteristic and notify
	 * Broadcast Assistants.
	 */
	bt_bass_set_enc(dg->src, BT_BASS_BIG_ENC_STATE_BCODE_REQ);

	/* Add timeout for Broadcast Assistants to provide the Code. */
	if (!dg->timeout)
		dg->timeout = g_timeout_add_seconds(10, req_timeout, dg);
}

static bool delegator_match_device(const void *data, const void *match_data)
{
	const struct bass_delegator *dg = data;
	const struct btd_device *device = match_data;

	return dg->device == device;
}

static int stream_get_bis(struct bt_bap_stream *stream)
{
	char *path = bt_bap_stream_get_user_data(stream);
	const char *strbis;
	int bis;

	strbis = strstr(path, "/bis");
	if (!strbis)
		return 0;

	if (sscanf(strbis, "/bis%d", &bis) < 0)
		return 0;

	return bis;
}

static void append_stream(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	struct sockaddr_iso_bc *addr = user_data;
	uint8_t bis = stream_get_bis(stream);

	DBG("%d", bis);

	addr->bc_bis[addr->bc_num_bis] = bis;
	addr->bc_num_bis++;
}

static bool link_io_unset(const void *data, const void *match_data)
{
	struct bt_bap_stream *link = (struct bt_bap_stream *)data;

	return !bt_bap_stream_get_io(link);
}

static void connect_cb(GIOChannel *io, GError *err, void *user_data)
{
	struct bass_setup *setup = user_data;
	struct bt_bap_stream *stream;
	struct queue *links;
	int fd;

	DBG("");

	if (!setup || !setup->stream)
		return;

	stream = setup->stream;
	links = bt_bap_stream_io_get_links(stream);

	/* Set fds for the stream and all its links. */
	if (bt_bap_stream_get_io(stream))
		stream = queue_find(links, link_io_unset, NULL);

	fd = g_io_channel_unix_get_fd(io);

	if (bt_bap_stream_set_io(stream, fd)) {
		g_io_channel_set_close_on_unref(io, FALSE);
	}
}

static bool link_enabled(const void *data, const void *match_data)
{
	struct bt_bap_stream *stream = (struct bt_bap_stream *)data;
	uint8_t state = bt_bap_stream_get_state(stream);

	return ((state == BT_BAP_STREAM_STATE_ENABLING) ||
			bt_bap_stream_get_io(stream));
}

static void bap_state_changed(struct bt_bap_stream *stream, uint8_t old_state,
				uint8_t new_state, void *user_data)
{
	struct bass_delegator *dg = user_data;
	int bis;
	struct bt_bap *bap = bt_bap_stream_get_session(stream);
	struct sockaddr_iso_bc iso_bc_addr = {0};
	struct queue *links;
	GError *gerr = NULL;
	struct bt_bap_qos *bap_qos = bt_bap_stream_get_qos(stream);
	struct bt_iso_qos qos;
	struct bass_setup *setup = queue_find(dg->setups,
				match_setup_stream, stream);

	if (dg->bap != bap)
		return;

	bis = stream_get_bis(stream);

	DBG("stream %p: %s(%u) -> %s(%u)", stream,
			bt_bap_stream_statestr(old_state), old_state,
			bt_bap_stream_statestr(new_state), new_state);

	switch (new_state) {
	case BT_BAP_STREAM_STATE_ENABLING:
		links = bt_bap_stream_io_get_links(stream);

		if (bt_bap_stream_get_io(stream) ||
			queue_find(links, link_enabled, NULL))
			/* The first enabled link will create and set fds
			 * for all links.
			 *
			 * If the stream io has already been set, the stream
			 * will automatically be started once all state_changed
			 * callbacks are notified.
			 *
			 * If there is any other linked stream that has already
			 * been enabled, the stream fd will be set once it is
			 * notified from kernel and the stream will be started.
			 */
			break;

		iso_bc_addr.bc_bdaddr_type =
				btd_device_get_bdaddr_type(dg->device);
		memcpy(&iso_bc_addr.bc_bdaddr, device_get_address(dg->device),
				sizeof(bdaddr_t));

		append_stream(stream, &iso_bc_addr);

		queue_foreach(links, append_stream, &iso_bc_addr);

		bt_bap_qos_to_iso_qos(bap_qos, &qos);

		if (!bt_io_set(dg->io, &gerr,
				BT_IO_OPT_QOS, &qos,
				BT_IO_OPT_INVALID)) {
			error("bt_io_set: %s", gerr->message);
			g_error_free(gerr);
			break;
		}

		if (!bt_io_bcast_accept(dg->io,
				connect_cb, setup, NULL, &gerr,
				BT_IO_OPT_ISO_BC_NUM_BIS,
				iso_bc_addr.bc_num_bis, BT_IO_OPT_ISO_BC_BIS,
				iso_bc_addr.bc_bis, BT_IO_OPT_INVALID)) {
			error("bt_io_bcast_accept: %s", gerr->message);
			g_error_free(gerr);
		}
		break;
	case BT_BAP_STREAM_STATE_STREAMING:
		/* BAP stream was started. Mark BIS index as synced inside the
		 * Broadcast Receive State characteristic and notify peers about
		 * the update.
		 */
		bt_bass_set_bis_sync(dg->src, bis);
		break;
	case BT_BAP_STREAM_STATE_CONFIG:
		if (old_state == BT_BAP_STREAM_STATE_STREAMING)
			/* BAP stream was disabled. Clear BIS index from the
			 * bitmask inside the Broadcast Receive State
			 * characteristic and notify peers about the update.
			 */
			bt_bass_clear_bis_sync(dg->src, bis);
		break;
	case BT_BAP_STREAM_STATE_IDLE:
		bt_bass_clear_bis_sync(dg->src, bis);
		setup->stream = NULL;
		break;
	}
}

static void bass_req_bcode_cb(void *user_data, int err)
{
	struct bass_setup *setup = user_data;

	if (!err) {
		if (asprintf(&setup->path, "%s/bis%d",
			device_get_path(setup->dg->device),
			setup->bis) < 0)
			return;

		bt_bap_stream_set_user_data(setup->stream, setup->path);

		bt_bap_stream_config(setup->stream, &setup->qos,
				setup->config, NULL, NULL);
		bt_bap_stream_metadata(setup->stream, setup->meta,
				NULL, NULL);
	}
}

static void setup_configure_stream(struct bass_setup *setup)
{
	uint8_t empty_bcode[BT_BASS_BCAST_CODE_SIZE] = {0};

	setup->stream = bt_bap_stream_new(setup->dg->bap, setup->lpac, NULL,
					&setup->qos, setup->config);
	if (!setup->stream)
		return;

	/* Before configuring the stream, check whether it is encrypted.
	 * If so, request the broadcast code from the client.
	 */
	if ((setup->qos.bcast.encryption) &&
	    (!memcmp(setup->qos.bcast.bcode->iov_base,
		     empty_bcode,
		     sizeof(empty_bcode)))) {
		bass_req_bcode(setup->stream, bass_req_bcode_cb, setup, NULL);
		return;
	}

	if (asprintf(&setup->path, "%s/bis%d",
			device_get_path(setup->dg->device),
			setup->bis) < 0)
		return;

	bt_bap_stream_set_user_data(setup->stream, setup->path);

	bt_bap_stream_config(setup->stream, &setup->qos,
			setup->config, NULL, NULL);
	bt_bap_stream_metadata(setup->stream, setup->meta,
			NULL, NULL);
}

static void stream_unlink(void *data, void *user_data)
{
	struct bt_bap_stream *link = data;
	struct bt_bap_stream *stream = user_data;

	bt_bap_stream_io_unlink(link, stream);
}

static void bass_remove_bis(struct bass_setup *setup)
{
	struct queue *links = bt_bap_stream_io_get_links(setup->stream);

	queue_foreach(links, stream_unlink, setup->stream);
	bt_bap_stream_release(setup->stream, NULL, NULL);
}

static void setup_disable_streaming(void *data, void *user_data)
{
	struct bass_setup *setup = data;
	struct queue *links = bt_bap_stream_io_get_links(setup->stream);

	if (!setup->stream)
		return;

	if (bt_bap_stream_get_state(setup->stream) !=
				BT_BAP_STREAM_STATE_STREAMING)
		return;

	queue_foreach(links, stream_unlink, setup->stream);
	bt_bap_stream_disable(setup->stream, false, NULL, NULL);
}

static void bass_add_bis(struct bass_setup *setup)
{
	queue_foreach(setup->dg->setups, setup_disable_streaming, NULL);
	setup_configure_stream(setup);
}

static void bis_handler(uint8_t sid, uint8_t bis, uint8_t sgrp,
			struct iovec *caps, struct iovec *meta,
			struct bt_bap_qos *qos, void *user_data)
{
	struct bass_delegator *dg = user_data;
	struct bt_bap_pac *lpac;
	struct bass_setup *setup;

	/* Check if this stream caps match any local PAC */
	bt_bap_verify_bis(dg->bap, bis, caps, &lpac);
	if (!lpac)
		return;

	setup = new0(struct bass_setup, 1);
	if (!setup)
		return;

	setup->dg = dg;
	setup->bis = bis;
	setup->lpac = lpac;

	setup->qos = *qos;
	setup->qos.bcast.bcode = util_iov_dup(qos->bcast.bcode, 1);

	setup->meta = util_iov_dup(meta, 1);
	setup->config = util_iov_dup(caps, 1);

	queue_push_tail(setup->dg->setups, setup);

	/* Only handle streams required by the Brodcast Assistant. */
	if (!bt_bass_check_bis(dg->src, bis))
		return;

	setup_configure_stream(setup);
}

static gboolean big_info_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct bass_delegator *dg = user_data;
	GError *err = NULL;
	struct bt_iso_base base;
	struct bt_iso_qos qos;
	struct iovec iov;
	struct bt_bap_qos bap_qos = {0};
	uint8_t sid;

	dg->io_id = 0;

	bt_io_get(io, &err,
			BT_IO_OPT_BASE, &base,
			BT_IO_OPT_QOS, &qos,
			BT_IO_OPT_ISO_BC_SID, &sid,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		return FALSE;
	}

	iov.iov_base = base.base;
	iov.iov_len = base.base_len;

	/* Create BAP QoS structure */
	bt_bap_iso_qos_to_bap_qos(&qos, &bap_qos);

	bt_bap_parse_base(sid, &iov, &bap_qos, bass_debug, bis_handler, dg);

	util_iov_free(bap_qos.bcast.bcode, 1);

	return FALSE;
}

static void confirm_cb(GIOChannel *io, void *user_data)
{
	struct bass_delegator *dg = user_data;

	DBG("");

	/* Close the listen io */
	g_io_channel_shutdown(dg->io, TRUE, NULL);
	g_io_channel_unref(dg->io);

	g_io_channel_ref(io);
	dg->io = io;

	/* Update Broadcast Receive State characteristic value and notify
	 * peers.
	 */
	if (bt_bass_set_pa_sync(dg->src, BT_BASS_SYNCHRONIZED_TO_PA))
		DBG("Failed to update Broadcast Receive State characteristic");

	/* Register BAP stream state changed callback. */
	dg->state_id = bt_bap_state_register(dg->bap, bap_state_changed,
			NULL, dg, NULL);

	/* Register callback to handle Broadcast Code requests from
	 * upper layers.
	 */
	dg->bcode_id = bt_bap_bcode_cb_register(dg->bap, bass_req_bcode,
							NULL, NULL);

	dg->io_id = g_io_add_watch(io, G_IO_OUT, big_info_cb, dg);
}

static void bap_attached(struct bt_bap *bap, void *user_data)
{
	struct btd_service *service;
	struct btd_profile *p;
	struct btd_device *device;
	struct btd_adapter *adapter;
	struct bass_delegator *dg;
	struct bass_data *data;
	GError *err = NULL;

	DBG("%p", bap);

	service = bt_bap_get_user_data(bap);
	if (!service)
		return;

	p = btd_service_get_profile(service);
	if (!p)
		return;

	/* Only handle sessions with Broadcast Sources */
	if (!g_str_equal(p->remote_uuid, BCAAS_UUID_STR))
		return;

	device = btd_service_get_device(service);
	adapter = device_get_adapter(device);

	/* Create BASS session with the Broadcast Source */
	data = bass_data_new(device);
	data->bis_id = bt_bap_bis_cb_register(bap, bis_probe,
					bis_remove, device, NULL);

	bass_data_add(data);

	dg = queue_find(delegators, delegator_match_device, device);
	if (!dg)
		/* Only probe devices added via Broadcast Assistants */
		return;

	if (dg->service)
		/* Service has already been probed */
		return;

	dg->service = service;
	dg->bap = bap;

	dg->io = bt_io_listen(NULL, confirm_cb, dg,
		NULL, &err,
		BT_IO_OPT_SOURCE_BDADDR,
		btd_adapter_get_address(adapter),
		BT_IO_OPT_SOURCE_TYPE,
		btd_adapter_get_address_type(adapter),
		BT_IO_OPT_DEST_BDADDR,
		device_get_address(device),
		BT_IO_OPT_DEST_TYPE,
		btd_device_get_bdaddr_type(device),
		BT_IO_OPT_MODE, BT_IO_MODE_ISO,
		BT_IO_OPT_QOS, &bap_sink_pa_qos,
		BT_IO_OPT_ISO_BC_SID, dg->sid,
		BT_IO_OPT_INVALID);
	if (!dg->io) {
		error("%s", err->message);
		g_error_free(err);
		return;
	}

	/* Take ownership for the service by setting the user data. */
	btd_service_set_user_data(service, dg);
}

static void setup_free(void *data)
{
	struct bass_setup *setup = data;

	DBG("setup %p", setup);

	util_iov_free(setup->qos.bcast.bcode, 1);
	util_iov_free(setup->meta, 1);
	util_iov_free(setup->config, 1);
	free(setup->path);

	/* Clear bis index from the bis sync bitmask, if it
	 * has been previously set.
	 */
	bt_bass_clear_bis_sync(setup->dg->src, setup->bis);
}

static bool match_device(const void *data, const void *match_data)
{
	const struct bass_data *bdata = data;
	const struct btd_device *device = match_data;

	return bdata->device == device;
}

static void bap_detached(struct bt_bap *bap, void *user_data)
{
	struct btd_service *service;
	struct btd_profile *p;
	struct btd_device *device;
	struct bass_delegator *dg;
	struct bass_data *data;

	DBG("%p", bap);

	service = bt_bap_get_user_data(bap);
	if (!service)
		return;

	p = btd_service_get_profile(service);
	if (!p)
		return;

	/* Only handle sessions with Broadcast Sources */
	if (!g_str_equal(p->remote_uuid, BCAAS_UUID_STR))
		return;

	device = btd_service_get_device(service);

	/* Remove BASS session with the Broadcast Source device */
	data = queue_find(sessions, match_device, device);
	if (data) {
		bt_bap_bis_cb_unregister(bap, data->bis_id);
		bass_data_remove(data);
	}

	dg = queue_remove_if(delegators, delegator_match_device, device);
	if (!dg)
		return;

	DBG("%p", dg);

	if (dg->io_id)
		g_source_remove(dg->io_id);

	if (dg->io) {
		g_io_channel_shutdown(dg->io, TRUE, NULL);
		g_io_channel_unref(dg->io);
	}

	queue_destroy(dg->setups, setup_free);

	/* Update Broadcast Receive State characteristic value and notify
	 * peers.
	 */
	if (bt_bass_set_pa_sync(dg->src, BT_BASS_NOT_SYNCHRONIZED_TO_PA))
		DBG("Failed to update Broadcast Receive State characteristic");

	/* Unregister BAP stream state changed callback. */
	bt_bap_state_unregister(dg->bap, dg->state_id);

	bt_bap_bcode_cb_unregister(dg->bap, dg->bcode_id);

	if (dg->timeout)
		g_source_remove(dg->timeout);

	queue_destroy(dg->bcode_reqs, free);

	free(dg->bcode);

	free(dg);

	btd_service_set_user_data(service, NULL);
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

			util_iov_free(assistant->qos.bcast.bcode, 1);
			assistant->qos.bcast.bcode = util_iov_dup(&iov, 1);

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
	params.sid = assistant->sid;
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
	uint8_t arr[BT_BASS_BCAST_CODE_SIZE] = {0};
	uint8_t *bcode = arr;

	if (assistant->qos.bcast.bcode)
		memcpy(arr, assistant->qos.bcast.bcode->iov_base,
						BT_BASS_BCAST_CODE_SIZE);

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
		uint8_t sgrp, uint8_t sid, uint8_t bis, struct bt_bap_qos *qos,
		struct iovec *meta, struct iovec *caps)
{
	struct bass_assistant *assistant;
	char src_addr[18];

	assistant = new0(struct bass_assistant, 1);
	if (!assistant)
		return NULL;

	DBG("assistant %p", assistant);

	assistant->device = device;
	assistant->data = data;
	assistant->sgrp = sgrp;
	assistant->sid = sid;
	assistant->bis = bis;
	assistant->qos = *qos;

	/* Create an internal copy for bcode */
	assistant->qos.bcast.bcode = util_iov_dup(qos->bcast.bcode, 1);

	assistant->meta = util_iov_dup(meta, 1);
	assistant->caps = util_iov_dup(caps, 1);

	btd_device_foreach_service_data(assistant->device, src_ad_search_bid,
							assistant);

	ba2str(device_get_address(device), src_addr);

	assistant->path = g_strdup_printf("%s/src_%s/sid%d/bis%d",
					device_get_path(data->device), src_addr,
					sid, bis);

	g_strdelimit(assistant->path, ":", '_');

	if (!assistants)
		assistants = queue_new();

	queue_push_tail(assistants, assistant);

	return assistant;
}

static void bis_probe(uint8_t sid, uint8_t bis, uint8_t sgrp,
			struct iovec *caps, struct iovec *meta,
			struct bt_bap_qos *qos, void *user_data)
{
	struct btd_device *device = user_data;
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

		bap = bt_bap_get_session(bt_bass_get_att(data->bass), NULL);
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
						sid, bis, qos, meta, caps);

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

static void bis_remove(struct bt_bap *bap, void *user_data)
{
	struct btd_device *device = user_data;

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
	dg->sid = params->sid;
	dg->bcode_reqs = queue_new();
	dg->setups = queue_new();

	if (!delegators)
		delegators = queue_new();

	queue_push_tail(delegators, dg);

	DBG("delegator %p", dg);

	/* Add Broadcast Audio Announcement Service UUID
	 * to device and probe service.
	 */
	btd_device_add_uuid(device, BCAAS_UUID_STR);

	return 0;
}

static bool delegator_match_src(const void *data, const void *match_data)
{
	const struct bass_delegator *dg = data;
	const struct bt_bcast_src *src = match_data;

	return dg->src == src;
}

static int handle_set_bcode_req(struct bt_bcast_src *bcast_src,
			struct bt_bass_set_bcast_code_params *params,
			struct bass_data *data)
{
	struct bass_delegator *dg;
	struct bass_bcode_req *req;

	dg = queue_find(delegators, delegator_match_src, bcast_src);
	if (!dg)
		return -EINVAL;

	dg->bcode = new0(uint8_t, BT_BASS_BCAST_CODE_SIZE);
	memcpy(dg->bcode, params->bcast_code, BT_BASS_BCAST_CODE_SIZE);

	if (dg->timeout) {
		g_source_remove(dg->timeout);
		dg->timeout = 0;
	}

	/* Set the Broadcast Code for each stream that required it. */
	while ((req = queue_pop_head(dg->bcode_reqs))) {
		setup_set_bcode(dg->bcode, req->setup, req->cb,
							req->user_data);
		free(req);
	}

	return 0;
}

static bool setup_match_bis(const void *data, const void *match_data)
{
	const struct bass_setup *setup = data;
	const int bis =  PTR_TO_INT(match_data);

	return setup->bis == bis;
}

static void bass_update_bis_sync(struct bass_delegator *dg,
				struct bt_bcast_src *bcast_src)
{
	for (int bis = 1; bis < ISO_MAX_NUM_BIS; bis++) {
		struct bass_setup *setup = queue_find(dg->setups,
				setup_match_bis, INT_TO_PTR(bis));
		uint8_t state;

		if (!setup)
			continue;

		state = bt_bap_stream_get_state(setup->stream);

		if (!setup->stream && bt_bass_check_bis(bcast_src, bis))
			bass_add_bis(setup);
		else if (setup->stream &&
				state == BT_BAP_STREAM_STATE_STREAMING &&
				!bt_bass_check_bis(bcast_src, bis))
			bass_remove_bis(setup);
	}
}

static int handle_mod_src_req(struct bt_bcast_src *bcast_src,
			struct bt_bass_mod_src_params *params,
			struct bass_data *data)
{
	struct bass_delegator *dg;
	uint8_t sync_state;
	int err = 0;

	DBG("");

	dg = queue_find(delegators, delegator_match_src, bcast_src);
	if (!dg)
		return -EINVAL;

	err = bt_bass_get_pa_sync(bcast_src, &sync_state);
	if (err)
		return err;

	switch (sync_state) {
	case BT_BASS_SYNCHRONIZED_TO_PA:
		if (params->pa_sync == PA_SYNC_NO_SYNC) {
			struct btd_adapter *adapter =
					device_get_adapter(dg->device);

			g_io_channel_shutdown(dg->io, TRUE, NULL);
			g_io_channel_unref(dg->io);
			dg->io = NULL;

			bt_bass_set_pa_sync(dg->src,
				BT_BASS_NOT_SYNCHRONIZED_TO_PA);

			/* Remove device of BIS source*/
			btd_adapter_remove_device(adapter, dg->device);
		} else {
			bass_update_bis_sync(dg, bcast_src);
		}
		break;
	case BT_BASS_NOT_SYNCHRONIZED_TO_PA:
		if (params->pa_sync == PA_SYNC_NO_PAST) {
			struct btd_adapter *adapter =
					device_get_adapter(dg->device);
			GError *err = NULL;

			dg->io = bt_io_listen(NULL, confirm_cb, dg,
				NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR,
				btd_adapter_get_address(adapter),
				BT_IO_OPT_SOURCE_TYPE,
				btd_adapter_get_address_type(adapter),
				BT_IO_OPT_DEST_BDADDR,
				device_get_address(dg->device),
				BT_IO_OPT_DEST_TYPE,
				btd_device_get_bdaddr_type(dg->device),
				BT_IO_OPT_MODE, BT_IO_MODE_ISO,
				BT_IO_OPT_QOS, &bap_sink_pa_qos,
				BT_IO_OPT_ISO_BC_SID, dg->sid,
				BT_IO_OPT_INVALID);
			if (!dg->io) {
				error("%s", err->message);
				g_error_free(err);
			}
		}

		break;
	}

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
	case BT_BASS_SET_BCAST_CODE:
		err = handle_set_bcode_req(bcast_src, params, data);
		break;
	case BT_BASS_MOD_SRC:
		err = handle_mod_src_req(bcast_src, params, data);
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
	struct bt_bass_set_bcast_code_params params = {0};
	struct iovec iov = {0};
	int err;

	assistant_set_state(assistant, ASSISTANT_STATE_REQUESTING);

	hdr.op = BT_BASS_SET_BCAST_CODE;

	params.id = id;

	if (assistant->qos.bcast.bcode)
		memcpy(params.bcast_code,
			assistant->qos.bcast.bcode->iov_base,
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
static unsigned int bap_id;

static int bass_init(void)
{
	int err;

	err = btd_profile_register(&bass_service);
	if (err)
		return err;

	bass_id = bt_bass_register(bass_attached, bass_detached, NULL);
	bap_id = bt_bap_register(bap_attached, bap_detached, NULL);

	return 0;
}

static void bass_exit(void)
{
	btd_profile_unregister(&bass_service);
	bt_bass_unregister(bass_id);
	bt_bap_unregister(bap_id);
}

BLUETOOTH_PLUGIN_DEFINE(bass, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							bass_init, bass_exit)
