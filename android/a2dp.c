/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib.h>

#include "btio/btio.h"
#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "profiles/audio/a2dp-codecs.h"
#include "log.h"
#include "a2dp.h"
#include "hal-msg.h"
#include "ipc.h"
#include "utils.h"
#include "bluetooth.h"
#include "avdtp.h"
#include "audio-msg.h"
#include "audio-ipc.h"

#define L2CAP_PSM_AVDTP 0x19
#define SVC_HINT_CAPTURING 0x08

static GIOChannel *server = NULL;
static GSList *devices = NULL;
static GSList *endpoints = NULL;
static GSList *setups = NULL;
static bdaddr_t adapter_addr;
static uint32_t record_id = 0;

struct a2dp_preset {
	void *data;
	int8_t len;
};

struct a2dp_endpoint {
	uint8_t id;
	uint8_t codec;
	struct avdtp_local_sep *sep;
	struct a2dp_preset *caps;
	GSList *presets;
};

struct a2dp_device {
	bdaddr_t	dst;
	uint8_t		state;
	GIOChannel	*io;
	struct avdtp	*session;
};

struct a2dp_setup {
	struct a2dp_device *dev;
	struct a2dp_endpoint *endpoint;
	struct a2dp_preset *preset;
	struct avdtp_stream *stream;
};

static int device_cmp(gconstpointer s, gconstpointer user_data)
{
	const struct a2dp_device *dev = s;
	const bdaddr_t *dst = user_data;

	return bacmp(&dev->dst, dst);
}

static void preset_free(void *data)
{
	struct a2dp_preset *preset = data;

	g_free(preset->data);
	g_free(preset);
}

static void unregister_endpoint(void *data)
{
	struct a2dp_endpoint *endpoint = data;

	if (endpoint->sep)
		avdtp_unregister_sep(endpoint->sep);

	if (endpoint->caps)
		preset_free(endpoint->caps);

	g_slist_free_full(endpoint->presets, preset_free);

	g_free(endpoint);
}

static void a2dp_device_free(struct a2dp_device *dev)
{
	if (dev->session)
		avdtp_unref(dev->session);

	if (dev->io) {
		g_io_channel_shutdown(dev->io, FALSE, NULL);
		g_io_channel_unref(dev->io);
	}

	devices = g_slist_remove(devices, dev);
	g_free(dev);
}

static struct a2dp_device *a2dp_device_new(const bdaddr_t *dst)
{
	struct a2dp_device *dev;

	dev = g_new0(struct a2dp_device, 1);
	bacpy(&dev->dst, dst);
	devices = g_slist_prepend(devices, dev);

	return dev;
}

static void bt_a2dp_notify_state(struct a2dp_device *dev, uint8_t state)
{
	struct hal_ev_a2dp_conn_state ev;
	char address[18];

	if (dev->state == state)
		return;

	dev->state = state;

	ba2str(&dev->dst, address);
	DBG("device %s state %u", address, state);

	bdaddr2android(&dev->dst, ev.bdaddr);
	ev.state = state;

	ipc_send_notif(HAL_SERVICE_ID_A2DP, HAL_EV_A2DP_CONN_STATE, sizeof(ev),
									&ev);

	if (state != HAL_A2DP_STATE_DISCONNECTED)
		return;

	a2dp_device_free(dev);
}

static void disconnect_cb(void *user_data)
{
	struct a2dp_device *dev = user_data;

	bt_a2dp_notify_state(dev, HAL_A2DP_STATE_DISCONNECTED);
}

static void signaling_connect_cb(GIOChannel *chan, GError *err,
							gpointer user_data)
{
	struct a2dp_device *dev = user_data;
	uint16_t imtu, omtu;
	GError *gerr = NULL;
	int fd;

	if (err) {
		bt_a2dp_notify_state(dev, HAL_A2DP_STATE_DISCONNECTED);
		error("%s", err->message);
		return;
	}

	bt_io_get(chan, &gerr,
			BT_IO_OPT_IMTU, &imtu,
			BT_IO_OPT_OMTU, &omtu,
			BT_IO_OPT_INVALID);
	if (gerr) {
		bt_a2dp_notify_state(dev, HAL_A2DP_STATE_DISCONNECTED);
		error("%s", gerr->message);
		g_error_free(gerr);
		return;
	}

	fd = g_io_channel_unix_get_fd(chan);

	/* FIXME: Add proper version */
	dev->session = avdtp_new(fd, imtu, omtu, 0x0100);
	if (!dev->session) {
		bt_a2dp_notify_state(dev, HAL_A2DP_STATE_DISCONNECTED);
		return;
	}

	avdtp_add_disconnect_cb(dev->session, disconnect_cb, dev);

	if (dev->io) {
		g_io_channel_unref(dev->io);
		dev->io = NULL;
	}

	bt_a2dp_notify_state(dev, HAL_A2DP_STATE_CONNECTED);
}

static void bt_a2dp_connect(const void *buf, uint16_t len)
{
	const struct hal_cmd_a2dp_connect *cmd = buf;
	struct a2dp_device *dev;
	uint8_t status;
	char addr[18];
	bdaddr_t dst;
	GSList *l;
	GError *err = NULL;

	DBG("");

	android2bdaddr(&cmd->bdaddr, &dst);

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (l) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	dev = a2dp_device_new(&dst);
	dev->io = bt_io_connect(signaling_connect_cb, dev, NULL, &err,
					BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
					BT_IO_OPT_DEST_BDADDR, &dev->dst,
					BT_IO_OPT_PSM, L2CAP_PSM_AVDTP,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
					BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		a2dp_device_free(dev);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	ba2str(&dev->dst, addr);
	DBG("connecting to %s", addr);

	bt_a2dp_notify_state(dev, HAL_A2DP_STATE_CONNECTING);

	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(HAL_SERVICE_ID_A2DP, HAL_OP_A2DP_CONNECT, status);
}

static void bt_a2dp_disconnect(const void *buf, uint16_t len)
{
	const struct hal_cmd_a2dp_connect *cmd = buf;
	uint8_t status;
	struct a2dp_device *dev;
	GSList *l;
	bdaddr_t dst;

	DBG("");

	android2bdaddr(&cmd->bdaddr, &dst);

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (!l) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	dev = l->data;
	status = HAL_STATUS_SUCCESS;

	if (dev->io) {
		bt_a2dp_notify_state(dev, HAL_A2DP_STATE_DISCONNECTED);
		goto failed;
	}

	/* Wait AVDTP session to shutdown */
	avdtp_shutdown(dev->session);
	bt_a2dp_notify_state(dev, HAL_A2DP_STATE_DISCONNECTING);

failed:
	ipc_send_rsp(HAL_SERVICE_ID_A2DP, HAL_OP_A2DP_DISCONNECT, status);
}

static const struct ipc_handler cmd_handlers[] = {
	/* HAL_OP_A2DP_CONNECT */
	{ bt_a2dp_connect, false, sizeof(struct hal_cmd_a2dp_connect) },
	/* HAL_OP_A2DP_DISCONNECT */
	{ bt_a2dp_disconnect, false, sizeof(struct hal_cmd_a2dp_disconnect) },
};

static void connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct a2dp_device *dev;
	bdaddr_t src, dst;
	char address[18];
	GError *gerr = NULL;
	GSList *l;

	if (err) {
		error("%s", err->message);
		return;
	}

	bt_io_get(chan, &gerr,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_INVALID);
	if (gerr) {
		error("%s", gerr->message);
		g_error_free(gerr);
		g_io_channel_shutdown(chan, TRUE, NULL);
		return;
	}

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (l)
		return;

	ba2str(&dst, address);
	DBG("Incoming connection from %s", address);

	dev = a2dp_device_new(&dst);
	signaling_connect_cb(chan, err, dev);
}

static sdp_record_t *a2dp_record(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap_uuid, avdtp_uuid, a2dp_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVDTP_UUID;
	uint16_t a2dp_ver = 0x0103, avdtp_ver = 0x0103, feat = 0x000f;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&a2dp_uuid, AUDIO_SOURCE_SVCLASS_ID);
	svclass_id = sdp_list_append(NULL, &a2dp_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, ADVANCED_AUDIO_PROFILE_ID);
	profile[0].version = a2dp_ver;
	pfseq = sdp_list_append(NULL, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap_uuid);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&avdtp_uuid, AVDTP_UUID);
	proto[1] = sdp_list_append(NULL, &avdtp_uuid);
	version = sdp_data_alloc(SDP_UINT16, &avdtp_ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(record, "Audio Source", NULL, NULL);

	sdp_data_free(psm);
	sdp_data_free(version);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(pfseq, NULL);
	sdp_list_free(aproto, NULL);
	sdp_list_free(root, NULL);
	sdp_list_free(svclass_id, NULL);

	return record;
}

static gboolean sep_getcap_ind(struct avdtp *session,
					struct avdtp_local_sep *sep,
					GSList **caps, uint8_t *err,
					void *user_data)
{
	struct a2dp_endpoint *endpoint = user_data;
	struct a2dp_preset *cap = endpoint->caps;
	struct avdtp_service_capability *service;
	struct avdtp_media_codec_capability *codec;

	*caps = NULL;

	service = avdtp_service_cap_new(AVDTP_MEDIA_TRANSPORT, NULL, 0);
	*caps = g_slist_append(*caps, service);

	codec = g_malloc0(sizeof(*codec) + sizeof(cap->len));
	codec->media_type = AVDTP_MEDIA_TYPE_AUDIO;
	codec->media_codec_type = endpoint->codec;
	memcpy(codec->data, cap->data, cap->len);

	service = avdtp_service_cap_new(AVDTP_MEDIA_CODEC, codec,
						sizeof(*codec) + cap->len);
	*caps = g_slist_append(*caps, service);
	g_free(codec);

	return TRUE;
}

static int sbc_check_config(struct a2dp_endpoint *endpoint,
						struct a2dp_preset *conf)
{
	a2dp_sbc_t *caps, *config;

	if (conf->len != sizeof(a2dp_sbc_t)) {
		error("SBC: Invalid configuration size (%u)", conf->len);
		return -EINVAL;
	}

	caps = endpoint->caps->data;
	config = conf->data;

	if (!(caps->frequency & config->frequency)) {
		error("SBC: Unsupported frequency (%u) by endpoint",
							config->frequency);
		return -EINVAL;
	}

	if (!(caps->channel_mode & config->channel_mode)) {
		error("SBC: Unsupported channel mode (%u) by endpoint",
							config->channel_mode);
		return -EINVAL;
	}

	if (!(caps->block_length & config->block_length)) {
		error("SBC: Unsupported block length (%u) by endpoint",
							config->block_length);
		return -EINVAL;
	}

	if (!(caps->allocation_method & config->allocation_method)) {
		error("SBC: Unsupported allocation method (%u) by endpoint",
							config->block_length);
		return -EINVAL;
	}

	return 0;
}

static int check_config(struct a2dp_endpoint *endpoint,
						struct a2dp_preset *config)
{
	GSList *l;

	for (l = endpoint->presets; l; l = g_slist_next(l)) {
		struct a2dp_preset *preset = l->data;

		if (preset->len != config->len)
			continue;

		if (memcmp(preset->data, config->data, preset->len) == 0)
			return 0;
	}

	/* Codec specific */
	switch (endpoint->codec) {
	case A2DP_CODEC_SBC:
		return sbc_check_config(endpoint, config);
	default:
		return -EINVAL;
	}
}

static struct a2dp_device *find_device_by_session(struct avdtp *session)
{
	GSList *l;

	for (l = devices; l; l = g_slist_next(l)) {
		struct a2dp_device *dev = l->data;

		if (dev->session == session)
			return dev;
	}

	return NULL;
}

static void setup_free(void *data)
{
	struct a2dp_setup *setup = data;

	preset_free(setup->preset);
	g_free(setup);
}

static void setup_add(struct a2dp_device *dev, struct a2dp_endpoint *endpoint,
			struct a2dp_preset *preset, struct avdtp_stream *stream)
{
	struct a2dp_setup *setup;

	setup = g_new0(struct a2dp_setup, 1);
	setup->dev = dev;
	setup->endpoint = endpoint;
	setup->preset = preset;
	setup->stream = stream;
	setups = g_slist_append(setups, setup);
}

static gboolean sep_setconf_ind(struct avdtp *session,
						struct avdtp_local_sep *sep,
						struct avdtp_stream *stream,
						GSList *caps,
						avdtp_set_configuration_cb cb,
						void *user_data)
{
	struct a2dp_endpoint *endpoint = user_data;
	struct a2dp_device *dev;
	struct a2dp_preset *preset = NULL;

	DBG("");

	dev = find_device_by_session(session);
	if (!dev) {
		error("Unable to find device for session %p", session);
		return FALSE;
	}

	for (; caps != NULL; caps = g_slist_next(caps)) {
		struct avdtp_service_capability *cap = caps->data;
		struct avdtp_media_codec_capability *codec;

		if (cap->category == AVDTP_DELAY_REPORTING)
			return FALSE;

		if (cap->category != AVDTP_MEDIA_CODEC)
			continue;

		codec = (struct avdtp_media_codec_capability *) cap->data;

		if (codec->media_codec_type != endpoint->codec)
			return FALSE;

		preset = g_new0(struct a2dp_preset, 1);
		preset->len = cap->length - sizeof(*codec);
		preset->data = g_memdup(codec->data, preset->len);

		if (check_config(endpoint, preset) < 0) {
			preset_free(preset);
			return FALSE;
		}
	}

	if (!preset)
		return FALSE;

	setup_add(dev, endpoint, preset, stream);

	cb(session, stream, NULL);

	return TRUE;
}

static struct avdtp_sep_ind sep_ind = {
	.get_capability		= sep_getcap_ind,
	.set_configuration	= sep_setconf_ind,
};

static uint8_t register_endpoint(const uint8_t *uuid, uint8_t codec,
							GSList *presets)
{
	struct a2dp_endpoint *endpoint;

	/* FIXME: Add proper check for uuid */

	endpoint = g_new0(struct a2dp_endpoint, 1);
	endpoint->id = g_slist_length(endpoints) + 1;
	endpoint->codec = codec;
	endpoint->sep = avdtp_register_sep(AVDTP_SEP_TYPE_SOURCE,
						AVDTP_MEDIA_TYPE_AUDIO,
						codec, FALSE, &sep_ind, NULL,
						endpoint);
	endpoint->caps = presets->data;
	endpoint->presets = g_slist_copy(g_slist_nth(presets, 1));

	endpoints = g_slist_append(endpoints, endpoint);

	return endpoint->id;
}

static GSList *parse_presets(const struct audio_preset *p, uint8_t count,
								uint16_t len)
{
	GSList *l = NULL;
	uint8_t i;

	for (i = 0; count > i; i++) {
		const uint8_t *ptr = (const uint8_t *) p;
		struct a2dp_preset *preset;

		if (len < sizeof(struct audio_preset)) {
			DBG("Invalid preset index %u", i);
			g_slist_free_full(l, preset_free);
			return NULL;
		}

		len -= sizeof(struct audio_preset);
		if (len == 0 || len < p->len) {
			DBG("Invalid preset size of %u for index %u", len, i);
			g_slist_free_full(l, preset_free);
			return NULL;
		}

		preset = g_new0(struct a2dp_preset, 1);
		preset->len = p->len;
		preset->data = g_memdup(p->data, preset->len);
		l = g_slist_append(l, preset);

		len -= preset->len;
		ptr += sizeof(*p) + preset->len;
		p = (const struct audio_preset *) ptr;
	}

	return l;
}

static void bt_audio_open(const void *buf, uint16_t len)
{
	const struct audio_cmd_open *cmd = buf;
	struct audio_rsp_open rsp;
	GSList *presets;

	DBG("");

	if (cmd->presets == 0) {
		error("No audio presets found");
		goto failed;
	}

	presets = parse_presets(cmd->preset, cmd->presets, len - sizeof(*cmd));
	if (!presets) {
		error("No audio presets found");
		goto failed;
	}

	rsp.id = register_endpoint(cmd->uuid, cmd->codec, presets);
	if (rsp.id == 0) {
		g_slist_free_full(presets, preset_free);
		error("Unable to register endpoint");
		goto failed;
	}

	g_slist_free(presets);

	audio_ipc_send_rsp_full(AUDIO_OP_OPEN, sizeof(rsp), &rsp, -1);

	return;

failed:
	audio_ipc_send_rsp(AUDIO_OP_OPEN, AUDIO_STATUS_FAILED);
}

static struct a2dp_endpoint *find_endpoint(uint8_t id)
{
	GSList *l;

	for (l = endpoints; l; l = g_slist_next(l)) {
		struct a2dp_endpoint *endpoint = l->data;

		if (endpoint->id == id)
			return endpoint;
	}

	return NULL;
}

static void bt_audio_close(const void *buf, uint16_t len)
{
	const struct audio_cmd_close *cmd = buf;
	struct a2dp_endpoint *endpoint;

	DBG("");

	endpoint = find_endpoint(cmd->id);
	if (!endpoint) {
		error("Unable to find endpoint %u", cmd->id);
		audio_ipc_send_rsp(AUDIO_OP_CLOSE, AUDIO_STATUS_FAILED);
		return;
	}

	unregister_endpoint(endpoint);

	audio_ipc_send_rsp(AUDIO_OP_CLOSE, AUDIO_STATUS_SUCCESS);
}

static struct a2dp_setup *find_setup(uint8_t id)
{
	GSList *l;

	for (l = setups; l; l = g_slist_next(l)) {
		struct a2dp_setup *setup = l->data;

		if (setup->endpoint->id == id)
			return setup;
	}

	return NULL;
}

static void bt_stream_open(const void *buf, uint16_t len)
{
	const struct audio_cmd_open_stream *cmd = buf;
	struct audio_rsp_open_stream *rsp;
	struct a2dp_setup *setup;

	DBG("");

	setup = find_setup(cmd->id);
	if (!setup) {
		error("Unable to find stream for endpoint %u", cmd->id);
		audio_ipc_send_rsp(AUDIO_OP_OPEN_STREAM, AUDIO_STATUS_FAILED);
		return;
	}

	len = sizeof(*rsp) + setup->preset->len;
	rsp = g_malloc0(sizeof(*rsp) + setup->preset->len);
	rsp->preset->len = setup->preset->len;
	memcpy(rsp->preset->data, setup->preset->data, setup->preset->len);

	audio_ipc_send_rsp_full(AUDIO_OP_OPEN_STREAM, len, rsp, -1);
}

static void bt_stream_close(const void *buf, uint16_t len)
{
	DBG("Not Implemented");

	audio_ipc_send_rsp(AUDIO_OP_CLOSE_STREAM, AUDIO_STATUS_FAILED);
}

static void bt_stream_resume(const void *buf, uint16_t len)
{
	DBG("Not Implemented");

	audio_ipc_send_rsp(AUDIO_OP_RESUME_STREAM, AUDIO_STATUS_FAILED);
}

static void bt_stream_suspend(const void *buf, uint16_t len)
{
	DBG("Not Implemented");

	audio_ipc_send_rsp(AUDIO_OP_SUSPEND_STREAM, AUDIO_STATUS_FAILED);
}

static const struct ipc_handler audio_handlers[] = {
	/* AUDIO_OP_OPEN */
	{ bt_audio_open, true, sizeof(struct audio_cmd_open) },
	/* AUDIO_OP_CLOSE */
	{ bt_audio_close, false, sizeof(struct audio_cmd_close) },
	/* AUDIO_OP_OPEN_STREAM */
	{ bt_stream_open, false, sizeof(struct audio_cmd_open_stream) },
	/* AUDIO_OP_CLOSE_STREAM */
	{ bt_stream_close, false, sizeof(struct audio_cmd_close_stream) },
	/* AUDIO_OP_RESUME_STREAM */
	{ bt_stream_resume, false, sizeof(struct audio_cmd_resume_stream) },
	/* AUDIO_OP_SUSPEND_STREAM */
	{ bt_stream_suspend, false, sizeof(struct audio_cmd_suspend_stream) },
};

bool bt_a2dp_register(const bdaddr_t *addr)
{
	GError *err = NULL;
	sdp_record_t *rec;

	DBG("");

	audio_ipc_init();

	bacpy(&adapter_addr, addr);

	server = bt_io_listen(connect_cb, NULL, NULL, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
				BT_IO_OPT_PSM, L2CAP_PSM_AVDTP,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_INVALID);
	if (!server) {
		error("Failed to listen on AVDTP channel: %s", err->message);
		g_error_free(err);
		return false;
	}

	rec = a2dp_record();
	if (!rec) {
		error("Failed to allocate A2DP record");
		goto fail;
	}

	if (bt_adapter_add_record(rec, SVC_HINT_CAPTURING) < 0) {
		error("Failed to register A2DP record");
		sdp_record_free(rec);
		goto fail;
	}
	record_id = rec->handle;

	ipc_register(HAL_SERVICE_ID_A2DP, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	audio_ipc_register(audio_handlers, G_N_ELEMENTS(audio_handlers));

	return true;

fail:
	g_io_channel_shutdown(server, TRUE, NULL);
	g_io_channel_unref(server);
	server = NULL;
	return false;
}

static void a2dp_device_disconnected(gpointer data, gpointer user_data)
{
	struct a2dp_device *dev = data;

	bt_a2dp_notify_state(dev, HAL_A2DP_STATE_DISCONNECTED);
}

void bt_a2dp_unregister(void)
{
	DBG("");

	g_slist_free_full(setups, setup_free);
	setups = NULL;

	g_slist_free_full(endpoints, unregister_endpoint);
	endpoints = NULL;

	g_slist_foreach(devices, a2dp_device_disconnected, NULL);
	devices = NULL;

	ipc_unregister(HAL_SERVICE_ID_A2DP);
	audio_ipc_unregister();

	bt_adapter_remove_record(record_id);
	record_id = 0;

	if (server) {
		g_io_channel_shutdown(server, TRUE, NULL);
		g_io_channel_unref(server);
		server = NULL;
	}

	audio_ipc_cleanup();
}
