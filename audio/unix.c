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
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <dbus/dbus.h>
#include <glib.h>

#include "log.h"
#include "ipc.h"
#include "device.h"
#include "manager.h"
#include "avdtp.h"
#include "a2dp.h"
#include "headset.h"
#include "sink.h"
#include "gateway.h"
#include "unix.h"
#include "glib-helper.h"

#define check_nul(str) (str[sizeof(str) - 1] == '\0')

typedef enum {
	TYPE_NONE,
	TYPE_HEADSET,
	TYPE_GATEWAY,
	TYPE_SINK,
	TYPE_SOURCE
} service_type_t;

typedef void (*notify_cb_t) (struct audio_device *dev, void *data);

struct a2dp_data {
	struct avdtp *session;
	struct avdtp_stream *stream;
	struct a2dp_sep *sep;
};

struct headset_data {
	gboolean locked;
};

struct unix_client {
	struct audio_device *dev;
	GSList *caps;
	service_type_t type;
	char *interface;
	uint8_t seid;
	union {
		struct a2dp_data a2dp;
		struct headset_data hs;
	} d;
	int sock;
	int lock;
	int data_fd; /* To be deleted once two phase configuration is fully implemented */
	unsigned int req_id;
	unsigned int cb_id;
	gboolean (*cancel) (struct audio_device *dev, unsigned int id);
};

static GSList *clients = NULL;

static int unix_sock = -1;

static void client_free(struct unix_client *client)
{
	DBG("client_free(%p)", client);

	if (client->cancel && client->dev && client->req_id > 0)
		client->cancel(client->dev, client->req_id);

	if (client->sock >= 0)
		close(client->sock);

	if (client->caps) {
		g_slist_foreach(client->caps, (GFunc) g_free, NULL);
		g_slist_free(client->caps);
	}

	g_free(client->interface);
	g_free(client);
}

/* Pass file descriptor through local domain sockets (AF_LOCAL, formerly
 * AF_UNIX) and the sendmsg() system call with the cmsg_type field of a "struct
 * cmsghdr" set to SCM_RIGHTS and the data being an integer value equal to the
 * handle of the file descriptor to be passed. */
static int unix_sendmsg_fd(int sock, int fd)
{
	char cmsg_b[CMSG_SPACE(sizeof(int))], m = 'm';
	struct cmsghdr *cmsg;
	struct iovec iov = { &m, sizeof(m) };
	struct msghdr msgh;

	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = &cmsg_b;
	msgh.msg_controllen = CMSG_LEN(sizeof(int));

	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	/* Initialize the payload */
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	return sendmsg(sock, &msgh, MSG_NOSIGNAL);
}

static void unix_ipc_sendmsg(struct unix_client *client,
					const bt_audio_msg_header_t *msg)
{
	const char *type = bt_audio_strtype(msg->type);
	const char *name = bt_audio_strname(msg->name);

	DBG("Audio API: %s -> %s", type, name);

	if (send(client->sock, msg, msg->length, 0) < 0)
		error("Error %s(%d)", strerror(errno), errno);
}

static void unix_ipc_error(struct unix_client *client, uint8_t name, int err)
{
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	bt_audio_error_t *rsp = (void *) buf;

	if (!g_slist_find(clients, client))
		return;

	memset(buf, 0, sizeof(buf));
	rsp->h.type = BT_ERROR;
	rsp->h.name = name;
	rsp->h.length = sizeof(*rsp);

	rsp->posix_errno = err;

	DBG("sending error %s(%d)", strerror(err), err);
	unix_ipc_sendmsg(client, &rsp->h);
}

static service_type_t select_service(struct audio_device *dev, const char *interface)
{
	if (!interface) {
		if (dev->sink && avdtp_is_connected(&dev->src, &dev->dst))
			return TYPE_SINK;
		else if (dev->source && avdtp_is_connected(&dev->src,
								&dev->dst))
			return TYPE_SOURCE;
		else if (dev->headset && headset_is_active(dev))
			return TYPE_HEADSET;
		else if (dev->sink)
			return TYPE_SINK;
		else if (dev->source)
			return TYPE_SOURCE;
		else if (dev->headset)
			return TYPE_HEADSET;
	} else if (!strcmp(interface, AUDIO_SOURCE_INTERFACE) && dev->source)
		return TYPE_SOURCE;
	else if (!strcmp(interface, AUDIO_SINK_INTERFACE) && dev->sink)
		return TYPE_SINK;
	else if (!strcmp(interface, AUDIO_HEADSET_INTERFACE) && dev->headset)
		return TYPE_HEADSET;
	else if (!strcmp(interface, AUDIO_GATEWAY_INTERFACE) && dev->gateway)
		return TYPE_GATEWAY;

	return TYPE_NONE;
}

static void stream_state_changed(struct avdtp_stream *stream,
					avdtp_state_t old_state,
					avdtp_state_t new_state,
					struct avdtp_error *err,
					void *user_data)
{
	struct unix_client *client = user_data;
	struct a2dp_data *a2dp = &client->d.a2dp;

	switch (new_state) {
	case AVDTP_STATE_IDLE:
		if (a2dp->sep) {
			a2dp_sep_unlock(a2dp->sep, a2dp->session);
			a2dp->sep = NULL;
		}
		if (a2dp->session) {
			avdtp_unref(a2dp->session);
			a2dp->session = NULL;
		}
		a2dp->stream = NULL;
		client->cb_id = 0;
		break;
	default:
		break;
	}
}

static uint8_t headset_generate_capability(struct audio_device *dev,
						codec_capabilities_t *codec)
{
	pcm_capabilities_t *pcm;

	codec->seid = BT_A2DP_SEID_RANGE + 1;
	codec->transport = BT_CAPABILITIES_TRANSPORT_SCO;
	codec->type = BT_HFP_CODEC_PCM;
	codec->length = sizeof(*pcm);

	pcm = (void *) codec;
	pcm->sampling_rate = 8000;
	if (dev->headset) {
		if (headset_get_nrec(dev))
			pcm->flags |= BT_PCM_FLAG_NREC;
		if (!headset_get_sco_hci(dev))
			pcm->flags |= BT_PCM_FLAG_PCM_ROUTING;
		codec->configured = headset_is_active(dev);
		codec->lock = headset_get_lock(dev);
	} else {
		pcm->flags |= BT_PCM_FLAG_NREC;
		codec->configured = TRUE;
		codec->lock = 0;
	}

	return codec->length;
}

static void headset_discovery_complete(struct audio_device *dev, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_get_capabilities_rsp *rsp = (void *) buf;
	uint8_t length;

	client->req_id = 0;

	if (!dev)
		goto failed;

	memset(buf, 0, sizeof(buf));

	length = headset_generate_capability(dev, (void *) rsp->data);

	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_GET_CAPABILITIES;
	rsp->h.length = sizeof(*rsp) + length;

	ba2str(&dev->src, rsp->source);
	ba2str(&dev->dst, rsp->destination);
	strncpy(rsp->object, dev->path, sizeof(rsp->object));

	unix_ipc_sendmsg(client, &rsp->h);

	return;

failed:
	error("discovery failed");
	unix_ipc_error(client, BT_SET_CONFIGURATION, EIO);
}

static void headset_setup_complete(struct audio_device *dev, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_set_configuration_rsp *rsp = (void *) buf;

	client->req_id = 0;

	if (!dev)
		goto failed;

	memset(buf, 0, sizeof(buf));

	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_SET_CONFIGURATION;
	rsp->h.length = sizeof(*rsp);

	rsp->link_mtu = 48;

	client->data_fd = headset_get_sco_fd(dev);

	unix_ipc_sendmsg(client, &rsp->h);

	return;

failed:
	error("config failed");
	unix_ipc_error(client, BT_SET_CONFIGURATION, EIO);
}

static void gateway_setup_complete(struct audio_device *dev, GError *err, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_set_configuration_rsp *rsp = (void *) buf;

	if (err) {
		unix_ipc_error(client, BT_SET_CONFIGURATION, err->code);
		return;
	}

	client->req_id = 0;

	memset(buf, 0, sizeof(buf));

	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_SET_CONFIGURATION;
	rsp->h.length = sizeof(*rsp);

	rsp->link_mtu = 48;

	client->data_fd = gateway_get_sco_fd(dev);

	unix_ipc_sendmsg(client, &rsp->h);
}

static void headset_resume_complete(struct audio_device *dev, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_start_stream_rsp *rsp = (void *) buf;
	struct bt_new_stream_ind *ind = (void *) buf;

	client->req_id = 0;

	if (!dev)
		goto failed;

	client->data_fd = headset_get_sco_fd(dev);
	if (client->data_fd < 0) {
		error("Unable to get a SCO fd");
		goto failed;
	}

	memset(buf, 0, sizeof(buf));
	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_START_STREAM;
	rsp->h.length = sizeof(*rsp);

	unix_ipc_sendmsg(client, &rsp->h);

	memset(buf, 0, sizeof(buf));
	ind->h.type = BT_INDICATION;
	ind->h.name = BT_NEW_STREAM;
	ind->h.length = sizeof(*ind);

	unix_ipc_sendmsg(client, &ind->h);

	if (unix_sendmsg_fd(client->sock, client->data_fd) < 0) {
		error("unix_sendmsg_fd: %s(%d)", strerror(errno), errno);
		goto failed;
	}

	return;

failed:
	error("headset_resume_complete: resume failed");
	unix_ipc_error(client, BT_START_STREAM, EIO);
}

static void gateway_resume_complete(struct audio_device *dev, GError *err, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_start_stream_rsp *rsp = (void *) buf;
	struct bt_new_stream_ind *ind = (void *) buf;

	if (err) {
		unix_ipc_error(client, BT_START_STREAM, err->code);
		return;
	}

	memset(buf, 0, sizeof(buf));
	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_START_STREAM;
	rsp->h.length = sizeof(*rsp);

	unix_ipc_sendmsg(client, &rsp->h);

	memset(buf, 0, sizeof(buf));
	ind->h.type = BT_INDICATION;
	ind->h.name = BT_NEW_STREAM;
	ind->h.length = sizeof(*ind);

	unix_ipc_sendmsg(client, &ind->h);

	client->data_fd = gateway_get_sco_fd(dev);
	if (unix_sendmsg_fd(client->sock, client->data_fd) < 0) {
		error("unix_sendmsg_fd: %s(%d)", strerror(errno), errno);
		unix_ipc_error(client, BT_START_STREAM, EIO);
	}

	client->req_id = 0;
}

static void headset_suspend_complete(struct audio_device *dev, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_stop_stream_rsp *rsp = (void *) buf;

	if (!dev)
		goto failed;

	memset(buf, 0, sizeof(buf));
	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_STOP_STREAM;
	rsp->h.length = sizeof(*rsp);

	unix_ipc_sendmsg(client, &rsp->h);

	return;

failed:
	error("suspend failed");
	unix_ipc_error(client, BT_STOP_STREAM, EIO);
}

static void print_mpeg12(struct mpeg_codec_cap *mpeg)
{
	DBG("Media Codec: MPEG12"
		" Channel Modes: %s%s%s%s"
		" Frequencies: %s%s%s%s%s%s"
		" Layers: %s%s%s"
		" CRC: %s",
		mpeg->channel_mode & MPEG_CHANNEL_MODE_MONO ? "Mono " : "",
		mpeg->channel_mode & MPEG_CHANNEL_MODE_DUAL_CHANNEL ?
		"DualChannel " : "",
		mpeg->channel_mode & MPEG_CHANNEL_MODE_STEREO ? "Stereo " : "",
		mpeg->channel_mode & MPEG_CHANNEL_MODE_JOINT_STEREO ?
		"JointStereo " : "",
		mpeg->frequency & MPEG_SAMPLING_FREQ_16000 ? "16Khz " : "",
		mpeg->frequency & MPEG_SAMPLING_FREQ_22050 ? "22.05Khz " : "",
		mpeg->frequency & MPEG_SAMPLING_FREQ_24000 ? "24Khz " : "",
		mpeg->frequency & MPEG_SAMPLING_FREQ_32000 ? "32Khz " : "",
		mpeg->frequency & MPEG_SAMPLING_FREQ_44100 ? "44.1Khz " : "",
		mpeg->frequency & MPEG_SAMPLING_FREQ_48000 ? "48Khz " : "",
		mpeg->layer & MPEG_LAYER_MP1 ? "1 " : "",
		mpeg->layer & MPEG_LAYER_MP2 ? "2 " : "",
		mpeg->layer & MPEG_LAYER_MP3 ? "3 " : "",
		mpeg->crc ? "Yes" : "No");
}

static void print_sbc(struct sbc_codec_cap *sbc)
{
	DBG("Media Codec: SBC"
		" Channel Modes: %s%s%s%s"
		" Frequencies: %s%s%s%s"
		" Subbands: %s%s"
		" Blocks: %s%s%s%s"
		" Bitpool: %d-%d",
		sbc->channel_mode & SBC_CHANNEL_MODE_MONO ? "Mono " : "",
		sbc->channel_mode & SBC_CHANNEL_MODE_DUAL_CHANNEL ?
		"DualChannel " : "",
		sbc->channel_mode & SBC_CHANNEL_MODE_STEREO ? "Stereo " : "",
		sbc->channel_mode & SBC_CHANNEL_MODE_JOINT_STEREO ? "JointStereo" : "",
		sbc->frequency & SBC_SAMPLING_FREQ_16000 ? "16Khz " : "",
		sbc->frequency & SBC_SAMPLING_FREQ_32000 ? "32Khz " : "",
		sbc->frequency & SBC_SAMPLING_FREQ_44100 ? "44.1Khz " : "",
		sbc->frequency & SBC_SAMPLING_FREQ_48000 ? "48Khz " : "",
		sbc->subbands & SBC_SUBBANDS_4 ? "4 " : "",
		sbc->subbands & SBC_SUBBANDS_8 ? "8 " : "",
		sbc->block_length & SBC_BLOCK_LENGTH_4 ? "4 " : "",
		sbc->block_length & SBC_BLOCK_LENGTH_8 ? "8 " : "",
		sbc->block_length & SBC_BLOCK_LENGTH_12 ? "12 " : "",
		sbc->block_length & SBC_BLOCK_LENGTH_16 ? "16 " : "",
		sbc->min_bitpool, sbc->max_bitpool);
}

static int a2dp_append_codec(struct bt_get_capabilities_rsp *rsp,
				struct avdtp_service_capability *cap,
				uint8_t seid,
				uint8_t type,
				uint8_t configured,
				uint8_t lock)
{
	struct avdtp_media_codec_capability *codec_cap = (void *) cap->data;
	codec_capabilities_t *codec = (void *) rsp + rsp->h.length;
	size_t space_left;

	if (rsp->h.length > BT_SUGGESTED_BUFFER_SIZE)
		return -ENOMEM;

	space_left = BT_SUGGESTED_BUFFER_SIZE - rsp->h.length;

	/* endianess prevent direct cast */
	if (codec_cap->media_codec_type == A2DP_CODEC_SBC) {
		struct sbc_codec_cap *sbc_cap = (void *) codec_cap;
		sbc_capabilities_t *sbc = (void *) codec;

		if (space_left < sizeof(sbc_capabilities_t))
			return -ENOMEM;

		if (type == AVDTP_SEP_TYPE_SINK)
			codec->type = BT_A2DP_SBC_SINK;
		else if (type == AVDTP_SEP_TYPE_SOURCE)
			codec->type = BT_A2DP_SBC_SOURCE;
		else
			return -EINVAL;

		codec->length = sizeof(sbc_capabilities_t);

		sbc->channel_mode = sbc_cap->channel_mode;
		sbc->frequency = sbc_cap->frequency;
		sbc->allocation_method = sbc_cap->allocation_method;
		sbc->subbands = sbc_cap->subbands;
		sbc->block_length = sbc_cap->block_length;
		sbc->min_bitpool = sbc_cap->min_bitpool;
		sbc->max_bitpool = sbc_cap->max_bitpool;

		print_sbc(sbc_cap);
	} else if (codec_cap->media_codec_type == A2DP_CODEC_MPEG12) {
		struct mpeg_codec_cap *mpeg_cap = (void *) codec_cap;
		mpeg_capabilities_t *mpeg = (void *) codec;

		if (space_left < sizeof(mpeg_capabilities_t))
			return -ENOMEM;

		if (type == AVDTP_SEP_TYPE_SINK)
			codec->type = BT_A2DP_MPEG12_SINK;
		else if (type == AVDTP_SEP_TYPE_SOURCE)
			codec->type = BT_A2DP_MPEG12_SOURCE;
		else
			return -EINVAL;

		codec->length = sizeof(mpeg_capabilities_t);

		mpeg->channel_mode = mpeg_cap->channel_mode;
		mpeg->crc = mpeg_cap->crc;
		mpeg->layer = mpeg_cap->layer;
		mpeg->frequency = mpeg_cap->frequency;
		mpeg->mpf = mpeg_cap->mpf;
		mpeg->bitrate = mpeg_cap->bitrate;

		print_mpeg12(mpeg_cap);
	} else {
		size_t codec_length, type_length, total_length;

		codec_length = cap->length - (sizeof(struct avdtp_service_capability)
				+ sizeof(struct avdtp_media_codec_capability));
		type_length = sizeof(codec_cap->media_codec_type);
		total_length = type_length + codec_length +
				sizeof(codec_capabilities_t);

		if (space_left < total_length)
			return -ENOMEM;

		if (type == AVDTP_SEP_TYPE_SINK)
			codec->type = BT_A2DP_UNKNOWN_SINK;
		else if (type == AVDTP_SEP_TYPE_SOURCE)
			codec->type = BT_A2DP_UNKNOWN_SOURCE;
		else
			return -EINVAL;

		codec->length = total_length;
		memcpy(codec->data, &codec_cap->media_codec_type, type_length);
		memcpy(codec->data + type_length, codec_cap->data,
			codec_length);
	}

	codec->seid = seid;
	codec->configured = configured;
	codec->lock = lock;
	rsp->h.length += codec->length;

	DBG("Append %s seid %d - length %d - total %d",
		configured ? "configured" : "", seid, codec->length,
		rsp->h.length);

	return 0;
}

static void a2dp_discovery_complete(struct avdtp *session, GSList *seps,
					struct avdtp_error *err,
					void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_get_capabilities_rsp *rsp = (void *) buf;
	struct a2dp_data *a2dp = &client->d.a2dp;
	GSList *l;

	if (!g_slist_find(clients, client)) {
		DBG("Client disconnected during discovery");
		return;
	}

	if (err)
		goto failed;

	memset(buf, 0, sizeof(buf));
	client->req_id = 0;

	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_GET_CAPABILITIES;
	rsp->h.length = sizeof(*rsp);
	ba2str(&client->dev->src, rsp->source);
	ba2str(&client->dev->dst, rsp->destination);
	strncpy(rsp->object, client->dev->path, sizeof(rsp->object));

	for (l = seps; l; l = g_slist_next(l)) {
		struct avdtp_remote_sep *rsep = l->data;
		struct a2dp_sep *sep;
		struct avdtp_service_capability *cap;
		struct avdtp_stream *stream;
		uint8_t type, seid, configured = 0, lock = 0;
		GSList *cl;

		type = avdtp_get_type(rsep);

		if (type != AVDTP_SEP_TYPE_SINK &&
						type != AVDTP_SEP_TYPE_SOURCE)
			continue;

		cap = avdtp_get_codec(rsep);

		if (cap->category != AVDTP_MEDIA_CODEC)
			continue;

		seid = avdtp_get_seid(rsep);

		if (client->seid != 0 && client->seid != seid)
			continue;

		stream = avdtp_get_stream(rsep);
		if (stream) {
			configured = 1;
			if (client->seid == seid)
				cap = avdtp_stream_get_codec(stream);
		}

		for (cl = clients; cl; cl = cl->next) {
			struct unix_client *c = cl->data;
			struct a2dp_data *ca2dp = &c->d.a2dp;

			if (ca2dp->session == session && c->seid == seid) {
				lock = c->lock;
				break;
			}
		}

		sep = a2dp_get_sep(session, stream);
		if (sep && a2dp_sep_get_lock(sep))
			lock = BT_WRITE_LOCK;

		a2dp_append_codec(rsp, cap, seid, type, configured, lock);
	}

	unix_ipc_sendmsg(client, &rsp->h);

	return;

failed:
	error("discovery failed");
	unix_ipc_error(client, BT_GET_CAPABILITIES, EIO);

	if (a2dp->sep) {
		a2dp_sep_unlock(a2dp->sep, a2dp->session);
		a2dp->sep = NULL;
	}

	avdtp_unref(a2dp->session);
	a2dp->session = NULL;
	a2dp->stream = NULL;
}

static void a2dp_config_complete(struct avdtp *session, struct a2dp_sep *sep,
					struct avdtp_stream *stream,
					struct avdtp_error *err,
					void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_set_configuration_rsp *rsp = (void *) buf;
	struct a2dp_data *a2dp = &client->d.a2dp;
	uint16_t imtu, omtu;
	GSList *caps;

	client->req_id = 0;

	if (err)
		goto failed;

	memset(buf, 0, sizeof(buf));

	if (!stream)
		goto failed;

	if (client->cb_id > 0)
		avdtp_stream_remove_cb(a2dp->session, a2dp->stream,
								client->cb_id);

	a2dp->sep = sep;
	a2dp->stream = stream;

	if (!avdtp_stream_get_transport(stream, &client->data_fd, &imtu, &omtu,
					&caps)) {
		error("Unable to get stream transport");
		goto failed;
	}

	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_SET_CONFIGURATION;
	rsp->h.length = sizeof(*rsp);

	/* FIXME: Use imtu when fd_opt is CFG_FD_OPT_READ */
	rsp->link_mtu = omtu;

	unix_ipc_sendmsg(client, &rsp->h);

	client->cb_id = avdtp_stream_add_cb(session, stream,
						stream_state_changed, client);

	return;

failed:
	error("config failed");

	unix_ipc_error(client, BT_SET_CONFIGURATION, EIO);

	avdtp_unref(a2dp->session);

	a2dp->session = NULL;
	a2dp->stream = NULL;
	a2dp->sep = NULL;
}

static void a2dp_resume_complete(struct avdtp *session,
				struct avdtp_error *err, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_start_stream_rsp *rsp = (void *) buf;
	struct bt_new_stream_ind *ind = (void *) buf;
	struct a2dp_data *a2dp = &client->d.a2dp;

	if (err)
		goto failed;

	memset(buf, 0, sizeof(buf));
	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_START_STREAM;
	rsp->h.length = sizeof(*rsp);

	unix_ipc_sendmsg(client, &rsp->h);

	memset(buf, 0, sizeof(buf));
	ind->h.type = BT_RESPONSE;
	ind->h.name = BT_NEW_STREAM;
	rsp->h.length = sizeof(*ind);

	unix_ipc_sendmsg(client, &ind->h);

	if (unix_sendmsg_fd(client->sock, client->data_fd) < 0) {
		error("unix_sendmsg_fd: %s(%d)", strerror(errno), errno);
		goto failed;
	}

	return;

failed:
	error("resume failed");

	unix_ipc_error(client, BT_START_STREAM, EIO);

	if (client->cb_id > 0) {
		avdtp_stream_remove_cb(a2dp->session, a2dp->stream,
					client->cb_id);
		client->cb_id = 0;
	}

	if (a2dp->sep) {
		a2dp_sep_unlock(a2dp->sep, a2dp->session);
		a2dp->sep = NULL;
	}

	avdtp_unref(a2dp->session);
	a2dp->session = NULL;
	a2dp->stream = NULL;
}

static void a2dp_suspend_complete(struct avdtp *session,
				struct avdtp_error *err, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_stop_stream_rsp *rsp = (void *) buf;
	struct a2dp_data *a2dp = &client->d.a2dp;

	if (err)
		goto failed;

	memset(buf, 0, sizeof(buf));
	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_STOP_STREAM;
	rsp->h.length = sizeof(*rsp);

	unix_ipc_sendmsg(client, &rsp->h);

	return;

failed:
	error("suspend failed");

	unix_ipc_error(client, BT_STOP_STREAM, EIO);

	if (a2dp->sep) {
		a2dp_sep_unlock(a2dp->sep, a2dp->session);
		a2dp->sep = NULL;
	}

	avdtp_unref(a2dp->session);
	a2dp->session = NULL;
	a2dp->stream = NULL;
}

static void start_discovery(struct audio_device *dev, struct unix_client *client)
{
	struct a2dp_data *a2dp;
	int err = 0;

	switch (client->type) {
	case TYPE_SINK:
	case TYPE_SOURCE:
		a2dp = &client->d.a2dp;

		if (!a2dp->session)
			a2dp->session = avdtp_get(&dev->src, &dev->dst);

		if (!a2dp->session) {
			error("Unable to get a session");
			goto failed;
		}

		err = avdtp_discover(a2dp->session, a2dp_discovery_complete,
					client);
		if (err) {
			if (a2dp->session) {
				avdtp_unref(a2dp->session);
				a2dp->session = NULL;
			}
			goto failed;
		}
		break;

	case TYPE_HEADSET:
	case TYPE_GATEWAY:
		headset_discovery_complete(dev, client);
		break;

	default:
		error("No known services for device");
		goto failed;
	}

	client->dev = dev;

	return;

failed:
	unix_ipc_error(client, BT_GET_CAPABILITIES, err ? : EIO);
}

static void open_complete(struct audio_device *dev, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_open_rsp *rsp = (void *) buf;

	memset(buf, 0, sizeof(buf));

	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_OPEN;
	rsp->h.length = sizeof(*rsp);

	ba2str(&dev->src, rsp->source);
	ba2str(&dev->dst, rsp->destination);
	strncpy(rsp->object, dev->path, sizeof(rsp->object));

	unix_ipc_sendmsg(client, &rsp->h);
}

static void start_open(struct audio_device *dev, struct unix_client *client)
{
	struct a2dp_data *a2dp;
	struct headset_data *hs;
	struct avdtp_remote_sep *rsep;
	gboolean unref_avdtp_on_fail = FALSE;

	switch (client->type) {
	case TYPE_SINK:
	case TYPE_SOURCE:
		a2dp = &client->d.a2dp;

		if (!a2dp->session) {
			a2dp->session = avdtp_get(&dev->src, &dev->dst);
			unref_avdtp_on_fail = TRUE;
		}

		if (!a2dp->session) {
			error("Unable to get a session");
			goto failed;
		}

		if (a2dp->sep) {
			error("Client already has an opened session");
			goto failed;
		}

		rsep = avdtp_get_remote_sep(a2dp->session, client->seid);
		if (!rsep) {
			error("Invalid seid %d", client->seid);
			goto failed;
		}

		a2dp->sep = a2dp_get(a2dp->session, rsep);
		if (!a2dp->sep) {
			error("seid %d not available or locked", client->seid);
			goto failed;
		}

		if (!a2dp_sep_lock(a2dp->sep, a2dp->session)) {
			error("Unable to open seid %d", client->seid);
			a2dp->sep = NULL;
			goto failed;
		}

		break;

	case TYPE_HEADSET:
		hs = &client->d.hs;

		if (hs->locked) {
			error("Client already has an opened session");
			goto failed;
		}

		hs->locked = headset_lock(dev, client->lock);
		if (!hs->locked) {
			error("Unable to open seid %d", client->seid);
			goto failed;
		}
		break;

        case TYPE_GATEWAY:
                break;
	default:
		error("No known services for device");
		goto failed;
	}

	client->dev = dev;

	open_complete(dev, client);

	return;

failed:
	if (unref_avdtp_on_fail && a2dp->session) {
		avdtp_unref(a2dp->session);
		a2dp->session = NULL;
	}
	unix_ipc_error(client, BT_OPEN, EINVAL);
}

static void start_config(struct audio_device *dev, struct unix_client *client)
{
	struct a2dp_data *a2dp;
	struct headset_data *hs;
	unsigned int id;

	switch (client->type) {
	case TYPE_SINK:
	case TYPE_SOURCE:
		a2dp = &client->d.a2dp;

		if (!a2dp->session)
			a2dp->session = avdtp_get(&dev->src, &dev->dst);

		if (!a2dp->session) {
			error("Unable to get a session");
			goto failed;
		}

		if (!a2dp->sep) {
			error("seid %d not opened", client->seid);
			goto failed;
		}

		id = a2dp_config(a2dp->session, a2dp->sep, a2dp_config_complete,
					client->caps, client);
		client->cancel = a2dp_cancel;
		break;

	case TYPE_HEADSET:
		hs = &client->d.hs;

		if (!hs->locked) {
			error("seid %d not opened", client->seid);
			goto failed;
		}

		id = headset_config_stream(dev, TRUE, headset_setup_complete,
						client);
		client->cancel = headset_cancel_stream;
		break;
	case TYPE_GATEWAY:
		if (gateway_config_stream(dev, gateway_setup_complete, client) >= 0) {
			client->cancel = gateway_cancel_stream;
			id = 1;
		} else
			id = 0;
		break;

	default:
		error("No known services for device");
		goto failed;
	}

	if (id == 0) {
		error("config failed");
		goto failed;
	}

	client->req_id = id;

	return;

failed:
	unix_ipc_error(client, BT_SET_CONFIGURATION, EIO);
}

static void start_resume(struct audio_device *dev, struct unix_client *client)
{
	struct a2dp_data *a2dp;
	struct headset_data *hs;
	unsigned int id;
	gboolean unref_avdtp_on_fail = FALSE;

	switch (client->type) {
	case TYPE_SINK:
	case TYPE_SOURCE:
		a2dp = &client->d.a2dp;

		if (!a2dp->session) {
			a2dp->session = avdtp_get(&dev->src, &dev->dst);
			unref_avdtp_on_fail = TRUE;
		}

		if (!a2dp->session) {
			error("Unable to get a session");
			goto failed;
		}

		if (!a2dp->sep) {
			error("seid not opened");
			goto failed;
		}

		id = a2dp_resume(a2dp->session, a2dp->sep, a2dp_resume_complete,
					client);
		client->cancel = a2dp_cancel;

		break;

	case TYPE_HEADSET:
		hs = &client->d.hs;

		if (!hs->locked) {
			error("seid not opened");
			goto failed;
		}

		id = headset_request_stream(dev, headset_resume_complete,
						client);
		client->cancel = headset_cancel_stream;
		break;

	case TYPE_GATEWAY:
		if (gateway_request_stream(dev, gateway_resume_complete, client))
			id = 1;
		else
			id = 0;
		client->cancel = gateway_cancel_stream;
		break;

	default:
		error("No known services for device");
		goto failed;
	}

	if (id == 0) {
		error("start_resume: resume failed");
		goto failed;
	}

	client->req_id = id;

	return;

failed:
	if (unref_avdtp_on_fail && a2dp->session) {
		avdtp_unref(a2dp->session);
		a2dp->session = NULL;
	}
	unix_ipc_error(client, BT_START_STREAM, EIO);
}

static void start_suspend(struct audio_device *dev, struct unix_client *client)
{
	struct a2dp_data *a2dp;
	struct headset_data *hs;
	unsigned int id;
	gboolean unref_avdtp_on_fail = FALSE;

	switch (client->type) {
	case TYPE_SINK:
	case TYPE_SOURCE:
		a2dp = &client->d.a2dp;

		if (!a2dp->session) {
			a2dp->session = avdtp_get(&dev->src, &dev->dst);
			unref_avdtp_on_fail = TRUE;
		}

		if (!a2dp->session) {
			error("Unable to get a session");
			goto failed;
		}

		if (!a2dp->sep) {
			error("Unable to get a sep");
			goto failed;
		}

		id = a2dp_suspend(a2dp->session, a2dp->sep,
					a2dp_suspend_complete, client);
		client->cancel = a2dp_cancel;
		break;

	case TYPE_HEADSET:
		hs = &client->d.hs;

		if (!hs->locked) {
			error("seid not opened");
			goto failed;
		}

		id = headset_suspend_stream(dev, headset_suspend_complete,
						client);
		client->cancel = headset_cancel_stream;
		break;

	case TYPE_GATEWAY:
		gateway_suspend_stream(dev);
		client->cancel = gateway_cancel_stream;
		headset_suspend_complete(dev, client);
		id = 1;
		break;

	default:
		error("No known services for device");
		goto failed;
	}

	if (id == 0) {
		error("suspend failed");
		goto failed;
	}

	return;

failed:
	if (unref_avdtp_on_fail && a2dp->session) {
		avdtp_unref(a2dp->session);
		a2dp->session = NULL;
	}
	unix_ipc_error(client, BT_STOP_STREAM, EIO);
}

static void close_complete(struct audio_device *dev, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_close_rsp *rsp = (void *) buf;

	memset(buf, 0, sizeof(buf));

	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_CLOSE;
	rsp->h.length = sizeof(*rsp);

	unix_ipc_sendmsg(client, &rsp->h);

	return;
}

static void start_close(struct audio_device *dev, struct unix_client *client,
			gboolean reply)
{
	struct a2dp_data *a2dp;
	struct headset_data *hs;

	if (!client->dev)
		goto failed;

	switch (client->type) {
	case TYPE_HEADSET:
		hs = &client->d.hs;

		if (client->dev && hs->locked) {
			headset_unlock(client->dev, client->lock);
			hs->locked = FALSE;
		}
		break;
        case TYPE_GATEWAY:
                break;
	case TYPE_SOURCE:
	case TYPE_SINK:
		a2dp = &client->d.a2dp;

		if (client->cb_id > 0)
			avdtp_stream_remove_cb(a2dp->session, a2dp->stream,
								client->cb_id);
		if (a2dp->sep) {
			a2dp_sep_unlock(a2dp->sep, a2dp->session);
			a2dp->sep = NULL;
		}
		if (a2dp->session) {
			avdtp_unref(a2dp->session);
			a2dp->session = NULL;
		}
		break;
	default:
		error("No known services for device");
		goto failed;
	}

	if (!reply)
		return;

	close_complete(dev, client);
	client->dev = NULL;

	return;

failed:
	if (reply)
		unix_ipc_error(client, BT_STOP_STREAM, EINVAL);
}

static void handle_getcapabilities_req(struct unix_client *client,
					struct bt_get_capabilities_req *req)
{
	struct audio_device *dev;
	bdaddr_t src, dst;
	int err = EIO;
	const char *interface;

	if (!check_nul(req->source) || !check_nul(req->destination) ||
			!check_nul(req->object)) {
		err = EINVAL;
		goto failed;
	}

	str2ba(req->source, &src);
	str2ba(req->destination, &dst);

	if (!manager_find_device(req->object, &src, &dst, NULL, FALSE))
		goto failed;

	if (req->transport == BT_CAPABILITIES_TRANSPORT_SCO)
		interface = AUDIO_HEADSET_INTERFACE;
	else if (req->transport == BT_CAPABILITIES_TRANSPORT_A2DP)
		interface = AUDIO_SINK_INTERFACE;
	else
		interface = client->interface;

	dev = manager_find_device(req->object, &src, &dst, interface, TRUE);
	if (!dev && (req->flags & BT_FLAG_AUTOCONNECT))
		dev = manager_find_device(req->object, &src, &dst,
							interface, FALSE);

	if (!dev) {
		if (req->transport == BT_CAPABILITIES_TRANSPORT_SCO)
			interface = AUDIO_GATEWAY_INTERFACE;
		else if (req->transport == BT_CAPABILITIES_TRANSPORT_A2DP)
			interface = AUDIO_SOURCE_INTERFACE;
		else
			interface = NULL;
		dev = manager_find_device(req->object, &src, &dst,
							interface, TRUE);
		if (!dev && (req->flags & BT_FLAG_AUTOCONNECT))
			dev = manager_find_device(req->object, &src, &dst,
							interface, FALSE);
	}

	if (!dev) {
		error("Unable to find a matching device");
		goto failed;
	}

	client->type = select_service(dev, interface);
	if (client->type == TYPE_NONE) {
		error("No matching service found");
		goto failed;
	}

	if (g_strcmp0(interface, client->interface) != 0) {
		g_free(client->interface);
		client->interface = g_strdup(interface);
	}

	client->seid = req->seid;

	start_discovery(dev, client);

	return;

failed:
	unix_ipc_error(client, BT_GET_CAPABILITIES, err);
}

static int handle_sco_open(struct unix_client *client, struct bt_open_req *req)
{
	if (!client->interface)
		client->interface = g_strdup(AUDIO_HEADSET_INTERFACE);
	else if (!g_str_equal(client->interface, AUDIO_HEADSET_INTERFACE) &&
		!g_str_equal(client->interface, AUDIO_GATEWAY_INTERFACE))
		return -EIO;

	DBG("open sco - object=%s source=%s destination=%s lock=%s%s",
			strcmp(req->object, "") ? req->object : "ANY",
			strcmp(req->source, "") ? req->source : "ANY",
			strcmp(req->destination, "") ? req->destination : "ANY",
			req->lock & BT_READ_LOCK ? "read" : "",
			req->lock & BT_WRITE_LOCK ? "write" : "");

	return 0;
}

static int handle_a2dp_open(struct unix_client *client, struct bt_open_req *req)
{
	if (!client->interface)
		/* FIXME: are we treating a sink or a source? */
		client->interface = g_strdup(AUDIO_SINK_INTERFACE);
	else if (!g_str_equal(client->interface, AUDIO_SINK_INTERFACE) &&
			!g_str_equal(client->interface, AUDIO_SOURCE_INTERFACE))
		return -EIO;

	DBG("open a2dp - object=%s source=%s destination=%s lock=%s%s",
			strcmp(req->object, "") ? req->object : "ANY",
			strcmp(req->source, "") ? req->source : "ANY",
			strcmp(req->destination, "") ? req->destination : "ANY",
			req->lock & BT_READ_LOCK ? "read" : "",
			req->lock & BT_WRITE_LOCK ? "write" : "");

	return 0;
}

static void handle_open_req(struct unix_client *client, struct bt_open_req *req)
{
	struct audio_device *dev;
	bdaddr_t src, dst;
	int err = 0;

	if (!check_nul(req->source) || !check_nul(req->destination) ||
			!check_nul(req->object)) {
		err = EINVAL;
		goto failed;
	}

	str2ba(req->source, &src);
	str2ba(req->destination, &dst);

	if (req->seid > BT_A2DP_SEID_RANGE) {
		err = handle_sco_open(client, req);
		if (err < 0) {
			err = -err;
			goto failed;
		}
	} else {
		err = handle_a2dp_open(client, req);
		if (err < 0) {
			err = -err;
			goto failed;
		}
	}

	if (!manager_find_device(req->object, &src, &dst, NULL, FALSE))
		goto failed;

	dev = manager_find_device(req->object, &src, &dst, client->interface,
				TRUE);
	if (!dev)
		dev = manager_find_device(req->object, &src, &dst,
					client->interface, FALSE);

	if (!dev)
		goto failed;

	client->seid = req->seid;
	client->lock = req->lock;

	start_open(dev, client);

	return;

failed:
	unix_ipc_error(client, BT_OPEN, err ? : EIO);
}

static int handle_sco_transport(struct unix_client *client,
				struct bt_set_configuration_req *req)
{
	struct audio_device *dev = client->dev;

	if (!client->interface) {
		if (dev->headset)
			client->interface = g_strdup(AUDIO_HEADSET_INTERFACE);
		else if (dev->gateway)
			client->interface = g_strdup(AUDIO_GATEWAY_INTERFACE);
		else
			return -EIO;
	} else if (!g_str_equal(client->interface, AUDIO_HEADSET_INTERFACE) &&
			!g_str_equal(client->interface, AUDIO_GATEWAY_INTERFACE))
		return -EIO;

	return 0;
}

static int handle_a2dp_transport(struct unix_client *client,
				struct bt_set_configuration_req *req)
{
	struct avdtp_service_capability *media_transport, *media_codec;
	struct sbc_codec_cap sbc_cap;
	struct mpeg_codec_cap mpeg_cap;

	if (!client->interface)
		/* FIXME: are we treating a sink or a source? */
		client->interface = g_strdup(AUDIO_SINK_INTERFACE);
	else if (!g_str_equal(client->interface, AUDIO_SINK_INTERFACE) &&
			!g_str_equal(client->interface, AUDIO_SOURCE_INTERFACE))
		return -EIO;

	if (client->caps) {
		g_slist_foreach(client->caps, (GFunc) g_free, NULL);
		g_slist_free(client->caps);
		client->caps = NULL;
	}

	media_transport = avdtp_service_cap_new(AVDTP_MEDIA_TRANSPORT,
						NULL, 0);

	client->caps = g_slist_append(client->caps, media_transport);

	if (req->codec.type == BT_A2DP_MPEG12_SINK ||
		req->codec.type == BT_A2DP_MPEG12_SOURCE) {
		mpeg_capabilities_t *mpeg = (void *) &req->codec;

		memset(&mpeg_cap, 0, sizeof(mpeg_cap));

		mpeg_cap.cap.media_type = AVDTP_MEDIA_TYPE_AUDIO;
		mpeg_cap.cap.media_codec_type = A2DP_CODEC_MPEG12;
		mpeg_cap.channel_mode = mpeg->channel_mode;
		mpeg_cap.crc = mpeg->crc;
		mpeg_cap.layer = mpeg->layer;
		mpeg_cap.frequency = mpeg->frequency;
		mpeg_cap.mpf = mpeg->mpf;
		mpeg_cap.bitrate = mpeg->bitrate;

		media_codec = avdtp_service_cap_new(AVDTP_MEDIA_CODEC, &mpeg_cap,
							sizeof(mpeg_cap));

		print_mpeg12(&mpeg_cap);
	} else if (req->codec.type == BT_A2DP_SBC_SINK ||
			req->codec.type == BT_A2DP_SBC_SOURCE) {
		sbc_capabilities_t *sbc = (void *) &req->codec;

		memset(&sbc_cap, 0, sizeof(sbc_cap));

		sbc_cap.cap.media_type = AVDTP_MEDIA_TYPE_AUDIO;
		sbc_cap.cap.media_codec_type = A2DP_CODEC_SBC;
		sbc_cap.channel_mode = sbc->channel_mode;
		sbc_cap.frequency = sbc->frequency;
		sbc_cap.allocation_method = sbc->allocation_method;
		sbc_cap.subbands = sbc->subbands;
		sbc_cap.block_length = sbc->block_length;
		sbc_cap.min_bitpool = sbc->min_bitpool;
		sbc_cap.max_bitpool = sbc->max_bitpool;

		media_codec = avdtp_service_cap_new(AVDTP_MEDIA_CODEC, &sbc_cap,
							sizeof(sbc_cap));

		print_sbc(&sbc_cap);
	} else
		return -EINVAL;

	client->caps = g_slist_append(client->caps, media_codec);

	return 0;
}

static void handle_setconfiguration_req(struct unix_client *client,
					struct bt_set_configuration_req *req)
{
	int err = 0;

	if (req->codec.seid != client->seid) {
		error("Unable to set configuration: seid %d not opened",
				req->codec.seid);
		goto failed;
	}

	if (!client->dev)
		goto failed;

	if (req->codec.transport == BT_CAPABILITIES_TRANSPORT_SCO) {
		err = handle_sco_transport(client, req);
		if (err < 0) {
			err = -err;
			goto failed;
		}
	} else if (req->codec.transport == BT_CAPABILITIES_TRANSPORT_A2DP) {
		err = handle_a2dp_transport(client, req);
		if (err < 0) {
			err = -err;
			goto failed;
		}
	}

	start_config(client->dev, client);

	return;

failed:
	unix_ipc_error(client, BT_SET_CONFIGURATION, err ? : EIO);
}

static void handle_streamstart_req(struct unix_client *client,
					struct bt_start_stream_req *req)
{
	if (!client->dev)
		goto failed;

	start_resume(client->dev, client);

	return;

failed:
	unix_ipc_error(client, BT_START_STREAM, EIO);
}

static void handle_streamstop_req(struct unix_client *client,
					struct bt_stop_stream_req *req)
{
	if (!client->dev)
		goto failed;

	start_suspend(client->dev, client);

	return;

failed:
	unix_ipc_error(client, BT_STOP_STREAM, EIO);
}

static void handle_close_req(struct unix_client *client,
				struct bt_close_req *req)
{
	if (!client->dev)
		goto failed;

	start_close(client->dev, client, TRUE);

	return;

failed:
	unix_ipc_error(client, BT_CLOSE, EIO);
}

static void handle_control_req(struct unix_client *client,
					struct bt_control_req *req)
{
	/* FIXME: really implement that */
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_set_configuration_rsp *rsp = (void *) buf;

	memset(buf, 0, sizeof(buf));
	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_CONTROL;
	rsp->h.length = sizeof(*rsp);

	unix_ipc_sendmsg(client, &rsp->h);
}

static void handle_delay_report_req(struct unix_client *client,
					struct bt_delay_report_req *req)
{
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_set_configuration_rsp *rsp = (void *) buf;
	struct a2dp_data *a2dp;
	int err;

	if (!client->dev) {
		err = -ENODEV;
		goto failed;
	}

	switch (client->type) {
	case TYPE_HEADSET:
        case TYPE_GATEWAY:
		err = -EINVAL;
		goto failed;
	case TYPE_SOURCE:
	case TYPE_SINK:
		a2dp = &client->d.a2dp;
		if (a2dp->session && a2dp->stream) {
			err = avdtp_delay_report(a2dp->session, a2dp->stream,
								req->delay);
			if (err < 0)
				goto failed;
		} else {
			err = -EINVAL;
			goto failed;
		}
		break;
	default:
		error("No known services for device");
		err = -EINVAL;
		goto failed;
	}

	memset(buf, 0, sizeof(buf));
	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_DELAY_REPORT;
	rsp->h.length = sizeof(*rsp);

	unix_ipc_sendmsg(client, &rsp->h);

	return;

failed:
	unix_ipc_error(client, BT_DELAY_REPORT, -err);
}

static gboolean client_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	bt_audio_msg_header_t *msghdr = (void *) buf;
	struct unix_client *client = data;
	int len;
	const char *type, *name;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		DBG("Unix client disconnected (fd=%d)", client->sock);

		goto failed;
	}

	memset(buf, 0, sizeof(buf));

	len = recv(client->sock, buf, sizeof(buf), 0);
	if (len < 0) {
		error("recv: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	type = bt_audio_strtype(msghdr->type);
	name = bt_audio_strname(msghdr->name);

	DBG("Audio API: %s <- %s", type, name);

	if (msghdr->length != len) {
		error("Invalid message: length mismatch");
		goto failed;
	}

	switch (msghdr->name) {
	case BT_GET_CAPABILITIES:
		handle_getcapabilities_req(client,
				(struct bt_get_capabilities_req *) msghdr);
		break;
	case BT_OPEN:
		handle_open_req(client,
				(struct bt_open_req *) msghdr);
		break;
	case BT_SET_CONFIGURATION:
		handle_setconfiguration_req(client,
				(struct bt_set_configuration_req *) msghdr);
		break;
	case BT_START_STREAM:
		handle_streamstart_req(client,
				(struct bt_start_stream_req *) msghdr);
		break;
	case BT_STOP_STREAM:
		handle_streamstop_req(client,
				(struct bt_stop_stream_req *) msghdr);
		break;
	case BT_CLOSE:
		handle_close_req(client,
				(struct bt_close_req *) msghdr);
		break;
	case BT_CONTROL:
		handle_control_req(client,
				(struct bt_control_req *) msghdr);
		break;
	case BT_DELAY_REPORT:
		handle_delay_report_req(client,
				(struct bt_delay_report_req *) msghdr);
		break;
	default:
		error("Audio API: received unexpected message name %d",
				msghdr->name);
	}

	return TRUE;

failed:
	clients = g_slist_remove(clients, client);
	start_close(client->dev, client, FALSE);
	client_free(client);
	return FALSE;
}

static gboolean server_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int sk, cli_sk;
	struct unix_client *client;
	GIOChannel *io;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		g_io_channel_close(chan);
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(chan);

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	cli_sk = accept(sk, (struct sockaddr *) &addr, &addrlen);
	if (cli_sk < 0) {
		error("accept: %s (%d)", strerror(errno), errno);
		return TRUE;
	}

	DBG("Accepted new client connection on unix socket (fd=%d)", cli_sk);
	set_nonblocking(cli_sk);

	client = g_new0(struct unix_client, 1);
	client->sock = cli_sk;
	clients = g_slist_append(clients, client);

	io = g_io_channel_unix_new(cli_sk);
	g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
							client_cb, client);
	g_io_channel_unref(io);

	return TRUE;
}

void unix_device_removed(struct audio_device *dev)
{
	GSList *l;

	DBG("unix_device_removed(%p)", dev);

	l = clients;
	while (l) {
		struct unix_client *client = l->data;

		l = l->next;

		if (client->dev == dev) {
			clients = g_slist_remove(clients, client);
			start_close(client->dev, client, FALSE);
			client_free(client);
		}
	}
}

void unix_delay_report(struct audio_device *dev, uint8_t seid, uint16_t delay)
{
	GSList *l;
	struct bt_delay_report_ind ind;

	DBG("unix_delay_report(%p): %u.%ums", dev, delay / 10, delay % 10);

	memset(&ind, 0, sizeof(ind));
	ind.h.type = BT_INDICATION;
	ind.h.name = BT_DELAY_REPORT;
	ind.h.length = sizeof(ind);
	ind.delay = delay;

	for (l = clients; l != NULL; l = g_slist_next(l)) {
		struct unix_client *client = l->data;

		if (client->dev != dev || client->seid != seid)
			continue;

		unix_ipc_sendmsg(client, (void *) &ind);
	}
}

int unix_init(void)
{
	GIOChannel *io;
	struct sockaddr_un addr = {
		AF_UNIX, BT_IPC_SOCKET_NAME
	};

	int sk, err;

	sk = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sk < 0) {
		err = errno;
		error("Can't create unix socket: %s (%d)", strerror(err), err);
		return -err;
	}

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		error("Can't bind unix socket: %s (%d)", strerror(errno),
				errno);
		close(sk);
		return -1;
	}

	set_nonblocking(sk);

	if (listen(sk, 1) < 0) {
		error("Can't listen on unix socket: %s (%d)",
						strerror(errno), errno);
		close(sk);
		return -1;
	}

	unix_sock = sk;

	io = g_io_channel_unix_new(sk);
	g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
							server_cb, NULL);
	g_io_channel_unref(io);

	DBG("Unix socket created: %d", sk);

	return 0;
}

void unix_exit(void)
{
	g_slist_foreach(clients, (GFunc) client_free, NULL);
	g_slist_free(clients);
	if (unix_sock >= 0) {
		close(unix_sock);
		unix_sock = -1;
	}
}
