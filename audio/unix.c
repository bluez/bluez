/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
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

#include "logging.h"
#include "ipc.h"
#include "device.h"
#include "manager.h"
#include "avdtp.h"
#include "a2dp.h"
#include "headset.h"
#include "sink.h"
#include "unix.h"
#include "glib-helper.h"

typedef enum {
	TYPE_NONE,
	TYPE_HEADSET,
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
	headset_lock_t lock;
};

struct unix_client {
	struct audio_device *dev;
	GSList *caps;
	service_type_t type;
	char *interface;
	union {
		struct a2dp_data a2dp;
		struct headset_data hs;
	} d;
	int sock;
	int access_mode;
	int data_fd; /* To be deleted once two phase configuration is fully implemented */
	unsigned int req_id;
	unsigned int cb_id;
	gboolean (*cancel) (struct audio_device *dev, unsigned int id);
};

static GSList *clients = NULL;

static int unix_sock = -1;

static void client_free(struct unix_client *client)
{
	struct a2dp_data *a2dp;

	switch (client->type) {
	case TYPE_SINK:
	case TYPE_SOURCE:
		a2dp = &client->d.a2dp;
		if (client->cb_id > 0)
			avdtp_stream_remove_cb(a2dp->session, a2dp->stream,
								client->cb_id);
		if (a2dp->sep)
			a2dp_sep_unlock(a2dp->sep, a2dp->session);
		if (a2dp->session)
			avdtp_unref(a2dp->session);
		break;
	default:
		break;
	}

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
	(*(int *) CMSG_DATA(cmsg)) = fd;

	return sendmsg(sock, &msgh, MSG_NOSIGNAL);
}

static void unix_ipc_sendmsg(struct unix_client *client,
					const bt_audio_msg_header_t *msg)
{
	const char *type = bt_audio_strtype(msg->type);
	const char *name = bt_audio_strname(msg->name);

	debug("Audio API: %s -> %s", type, name);

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

	unix_ipc_sendmsg(client, &rsp->h);
}

static service_type_t select_service(struct audio_device *dev, const char *interface)
{
	if (!interface) {
		if (dev->sink && avdtp_is_connected(&dev->src, &dev->dst))
			return TYPE_SINK;
		else if (dev->headset && headset_is_active(dev))
			return TYPE_HEADSET;
		else if (dev->sink)
			return TYPE_SINK;
		else if (dev->headset)
			return TYPE_HEADSET;
	} else if (!strcmp(interface, AUDIO_SINK_INTERFACE) && dev->sink)
		return TYPE_SINK;
	else if (!strcmp(interface, AUDIO_HEADSET_INTERFACE) && dev->headset)
		return TYPE_HEADSET;

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
		client->dev = NULL;
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

static void headset_discovery_complete(struct audio_device *dev, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_get_capabilities_rsp *rsp = (void *) buf;
	codec_capabilities_t *codec;
	pcm_capabilities_t *pcm;

	client->req_id = 0;

	if (!dev)
		goto failed;

	memset(buf, 0, sizeof(buf));

	codec = (void *) rsp->data;
	codec->transport = BT_CAPABILITIES_TRANSPORT_SCO;
	codec->type = BT_HFP_CODEC_PCM;
	codec->length = sizeof(*pcm);

	pcm = (void *) codec;
	pcm->sampling_rate = 8000;
	if (headset_get_nrec(dev))
		pcm->flags |= BT_PCM_FLAG_NREC;

	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_GET_CAPABILITIES;
	rsp->h.length = sizeof(*rsp) + codec->length;

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

	rsp->transport = BT_CAPABILITIES_TRANSPORT_SCO;
	rsp->access_mode = client->access_mode;
	rsp->link_mtu = 48;

	client->data_fd = headset_get_sco_fd(dev);

	unix_ipc_sendmsg(client, &rsp->h);

	return;

failed:
	error("config failed");
	unix_ipc_error(client, BT_SET_CONFIGURATION, EIO);
}

static void headset_resume_complete(struct audio_device *dev, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_start_stream_rsp *rsp = (void *) buf;
	struct bt_new_stream_ind *ind = (void *) buf;
	struct headset_data *hs = &client->d.hs;

	client->req_id = 0;

	if (!dev)
		goto failed;

	if (!headset_lock(dev, hs->lock)) {
		error("Unable to lock headset");
		goto failed;
	}

	client->data_fd = headset_get_sco_fd(dev);
	if (client->data_fd < 0) {
		error("Unable to get a SCO fd");
		headset_unlock(dev, hs->lock);
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
		headset_unlock(client->dev, hs->lock);
		goto failed;
	}

	return;

failed:
	error("headset_resume_complete: resume failed");
	unix_ipc_error(client, BT_START_STREAM, EIO);
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
	client->dev = NULL;
}

static int a2dp_append_codec(struct bt_get_capabilities_rsp *rsp,
				struct avdtp_service_capability *cap)
{
	struct avdtp_media_codec_capability *codec_cap = (void *) cap->data;
	codec_capabilities_t *codec = (void *) rsp + rsp->h.length;
	int space_left = BT_SUGGESTED_BUFFER_SIZE - rsp->h.length;

	if (space_left <= 0)
		return -ENOMEM;

	/* endianess prevent direct cast */
	if (codec_cap->media_codec_type == A2DP_CODEC_SBC) {
		struct sbc_codec_cap *sbc_cap = (void *) codec_cap;
		sbc_capabilities_t *sbc = (void *) codec;

		if ((space_left - (int) sizeof(sbc_capabilities_t)) < 0)
			return -ENOMEM;

		codec->length = sizeof(sbc_capabilities_t);

		sbc->channel_mode = sbc_cap->channel_mode;
		sbc->frequency = sbc_cap->frequency;
		sbc->allocation_method = sbc_cap->allocation_method;
		sbc->subbands = sbc_cap->subbands;
		sbc->block_length = sbc_cap->block_length;
		sbc->min_bitpool = sbc_cap->min_bitpool;
		sbc->max_bitpool = sbc_cap->max_bitpool;
	} else if (codec_cap->media_codec_type == A2DP_CODEC_MPEG12) {
		struct mpeg_codec_cap *mpeg_cap = (void *) codec_cap;
		mpeg_capabilities_t *mpeg = (void *) codec;

		if ((space_left - (int) sizeof(mpeg_capabilities_t)) < 0)
			return -ENOMEM;

		codec->length = sizeof(mpeg_capabilities_t);

		mpeg->channel_mode = mpeg_cap->channel_mode;
		mpeg->crc = mpeg_cap->crc;
		mpeg->layer = mpeg_cap->layer;
		mpeg->frequency = mpeg_cap->frequency;
		mpeg->mpf = mpeg_cap->mpf;
		mpeg->bitrate = mpeg_cap->bitrate;
	} else {
		int codec_length;

		codec_length = cap->length - (sizeof(struct avdtp_service_capability)
				+ sizeof(struct avdtp_media_codec_capability));

		if ((space_left - codec_length - (int) sizeof(codec_capabilities_t)) < 0)
			return -ENOMEM;

		codec->length = codec_length + sizeof(codec_capabilities_t);
		memcpy(codec->data, codec_cap->data, codec_length);
	}

	codec->type = codec_cap->media_codec_type;
	rsp->h.length += codec->length;

	debug("Append codec %d - length %d - total %d", codec->type,
			codec->length, rsp->h.length);

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
		debug("Client disconnected during discovery");
		return;
	}

	if (err)
		goto failed;

	memset(buf, 0, sizeof(buf));
	client->req_id = 0;

	rsp->h.type = BT_RESPONSE;
	rsp->h.name = BT_GET_CAPABILITIES;
	rsp->h.length = sizeof(*rsp);

	for (l = seps; l; l = g_slist_next(l)) {
		struct avdtp_remote_sep *rsep = l->data;
		struct avdtp_service_capability *cap;

		cap = avdtp_get_codec(rsep);

		if (cap->category != AVDTP_MEDIA_CODEC)
			continue;

		a2dp_append_codec(rsp, cap);
	}

	unix_ipc_sendmsg(client, &rsp->h);

	return;

failed:
	error("discovery failed");
	unix_ipc_error(client, BT_GET_CAPABILITIES, EIO);

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

	if (err)
		goto failed;

	memset(buf, 0, sizeof(buf));
	client->req_id = 0;

	if (!stream)
		goto failed;

	if (!a2dp_sep_lock(sep, session)) {
		error("Unable to lock A2DP source SEP");
		goto failed;
	}

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

	rsp->transport = BT_CAPABILITIES_TRANSPORT_A2DP;
	client->access_mode = BT_CAPABILITIES_ACCESS_MODE_WRITE;
	rsp->access_mode = client->access_mode;
	/* FIXME: Use imtu when fd_opt is CFG_FD_OPT_READ */
	rsp->link_mtu = omtu;

	unix_ipc_sendmsg(client, &rsp->h);

	client->cb_id = avdtp_stream_add_cb(session, stream,
						stream_state_changed, client);

	return;

failed:
	error("config failed");

	if (a2dp->sep) {
		a2dp_sep_unlock(a2dp->sep, a2dp->session);
		a2dp->sep = NULL;
	}
	unix_ipc_error(client, BT_SET_CONFIGURATION, EIO);

	avdtp_unref(a2dp->session);

	a2dp->session = NULL;
	a2dp->stream = NULL;
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

	if (a2dp->sep) {
		a2dp_sep_unlock(a2dp->sep, a2dp->session);
		a2dp->sep = NULL;
	}
	unix_ipc_error(client, BT_START_STREAM, EIO);

	if (client->cb_id > 0) {
		avdtp_stream_remove_cb(a2dp->session, a2dp->stream,
					client->cb_id);
		client->cb_id = 0;
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

	if (a2dp->sep) {
		a2dp_sep_unlock(a2dp->sep, a2dp->session);
		a2dp->sep = NULL;
	}
	unix_ipc_error(client, BT_STOP_STREAM, EIO);

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
		a2dp = &client->d.a2dp;

		if (!a2dp->session)
			a2dp->session = avdtp_get(&dev->src, &dev->dst);

		if (!a2dp->session) {
			error("Unable to get a session");
			goto failed;
		}

		err = avdtp_discover(a2dp->session, a2dp_discovery_complete,
					client);
		if (err)
			goto failed;
		break;

	case TYPE_HEADSET:
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

static void start_config(struct audio_device *dev, struct unix_client *client)
{
	struct a2dp_data *a2dp;
	struct headset_data *hs;
	unsigned int id;

	switch (client->type) {
	case TYPE_SINK:
		a2dp = &client->d.a2dp;

		if (!a2dp->session)
			a2dp->session = avdtp_get(&dev->src, &dev->dst);

		if (!a2dp->session) {
			error("Unable to get a session");
			goto failed;
		}

		id = a2dp_source_config(a2dp->session, a2dp_config_complete,
					client->caps, client);
		client->cancel = a2dp_source_cancel;
		break;

	case TYPE_HEADSET:
		hs = &client->d.hs;

		switch (client->access_mode) {
		case BT_CAPABILITIES_ACCESS_MODE_READ:
			hs->lock = HEADSET_LOCK_READ;
			break;
		case BT_CAPABILITIES_ACCESS_MODE_WRITE:
			hs->lock = HEADSET_LOCK_WRITE;
			break;
		case BT_CAPABILITIES_ACCESS_MODE_READWRITE:
			hs->lock = HEADSET_LOCK_READ | HEADSET_LOCK_WRITE;
			break;
		default:
			hs->lock = 0;
			break;
		}

		id = headset_config_stream(dev, headset_setup_complete,
					hs->lock, client);
		client->cancel = headset_cancel_stream;
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
	client->dev = dev;

	return;

failed:
	unix_ipc_error(client, BT_SET_CONFIGURATION, EIO);
}

static void start_resume(struct audio_device *dev, struct unix_client *client)
{
	struct a2dp_data *a2dp;
	struct headset_data *hs;
	unsigned int id;

	switch (client->type) {
	case TYPE_SINK:
		a2dp = &client->d.a2dp;

		if (!a2dp->session)
			a2dp->session = avdtp_get(&dev->src, &dev->dst);

		if (!a2dp->session) {
			error("Unable to get a session");
			goto failed;
		}

		if (!a2dp->sep) {
			error("Unable to get a sep");
			goto failed;
		}

		id = a2dp_source_resume(a2dp->session, a2dp->sep,
					a2dp_resume_complete, client);
		client->cancel = a2dp_source_cancel;

		break;

	case TYPE_HEADSET:
		hs = &client->d.hs;

		id = headset_request_stream(dev, headset_resume_complete,
					hs->lock, client);
		client->cancel = headset_cancel_stream;
		break;

	default:
		error("No known services for device");
		goto failed;
	}

	if (id == 0) {
		error("start_resume: resume failed");
		goto failed;
	}

	return;

failed:
	unix_ipc_error(client, BT_START_STREAM, EIO);
}

static void start_suspend(struct audio_device *dev, struct unix_client *client)
{
	struct a2dp_data *a2dp;
	struct headset_data *hs;
	unsigned int id;

	switch (client->type) {
	case TYPE_SINK:
		a2dp = &client->d.a2dp;

		if (!a2dp->session)
			a2dp->session = avdtp_get(&dev->src, &dev->dst);

		if (!a2dp->session) {
			error("Unable to get a session");
			goto failed;
		}

		if (!a2dp->sep) {
			error("Unable to get a sep");
			goto failed;
		}

		id = a2dp_source_suspend(a2dp->session, a2dp->sep,
					a2dp_suspend_complete, client);
		client->cancel = a2dp_source_cancel;
		break;

	case TYPE_HEADSET:
		hs = &client->d.hs;

		id = headset_suspend_stream(dev, headset_suspend_complete,
					hs->lock, client);
		client->cancel = headset_cancel_stream;
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
	unix_ipc_error(client, BT_STOP_STREAM, EIO);
}

static void handle_getcapabilities_req(struct unix_client *client,
					struct bt_get_capabilities_req *req)
{
	struct audio_device *dev;
	bdaddr_t bdaddr;

	str2ba(req->device, &bdaddr);

	if (client->interface) {
		error("Got GET_CAPABILITIES for an initialized client");
		goto failed;
	}

	if (req->transport == BT_CAPABILITIES_TRANSPORT_SCO)
		client->interface = g_strdup(AUDIO_HEADSET_INTERFACE);
	else if (req->transport == BT_CAPABILITIES_TRANSPORT_A2DP)
		client->interface = g_strdup(AUDIO_SINK_INTERFACE);

	if (!manager_find_device(&bdaddr, NULL, FALSE))
		goto failed;

	dev = manager_find_device(&bdaddr, client->interface, TRUE);
	if (!dev && (req->flags & BT_FLAG_AUTOCONNECT))
		dev = manager_find_device(&bdaddr, client->interface, FALSE);

	if (!dev) {
		error("Unable to find a matching device");
		goto failed;
	}

	client->type = select_service(dev, client->interface);
	if (client->type == TYPE_NONE) {
		error("No matching service found");
		goto failed;
	}

	start_discovery(dev, client);

	return;

failed:
	unix_ipc_error(client, BT_GET_CAPABILITIES, EIO);
}

static int handle_sco_transport(struct unix_client *client,
				struct bt_set_configuration_req *req)
{
	if (!client->interface)
		client->interface = g_strdup(AUDIO_HEADSET_INTERFACE);
	else if (!g_str_equal(client->interface, AUDIO_HEADSET_INTERFACE))
		return -EIO;

	debug("config sco - device = %s access_mode = %u", req->device,
			req->access_mode);

	return 0;
}

static int handle_a2dp_transport(struct unix_client *client,
				struct bt_set_configuration_req *req)
{
	struct avdtp_service_capability *media_transport, *media_codec;
	struct sbc_codec_cap sbc_cap;
	struct mpeg_codec_cap mpeg_cap;

	if (!client->interface)
		client->interface = g_strdup(AUDIO_SINK_INTERFACE);
	else if (!g_str_equal(client->interface, AUDIO_SINK_INTERFACE))
		return -EIO;

	if (client->caps) {
		g_slist_foreach(client->caps, (GFunc) g_free, NULL);
		g_slist_free(client->caps);
		client->caps = NULL;
	}

	media_transport = avdtp_service_cap_new(AVDTP_MEDIA_TRANSPORT,
						NULL, 0);

	client->caps = g_slist_append(client->caps, media_transport);

	debug("config a2dp - device = %s access_mode = %u", req->device,
			req->access_mode);

	if (req->codec.type == BT_A2DP_CODEC_MPEG12) {
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

		debug("codec mpeg12 - frequency = %u channel_mode = %u "
			"layer = %u crc = %u mpf = %u bitrate = %u",
			mpeg_cap.frequency, mpeg_cap.channel_mode,
			mpeg_cap.layer, mpeg_cap.crc, mpeg_cap.mpf,
			mpeg_cap.bitrate);
	} else if (req->codec.type == BT_A2DP_CODEC_SBC) {
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

		debug("codec sbc - frequency = %u channel_mode = %u "
			"allocation = %u subbands = %u blocks = %u "
			"bitpool = %u", sbc_cap.frequency,
			sbc_cap.channel_mode, sbc_cap.allocation_method,
			sbc_cap.subbands, sbc_cap.block_length,
			sbc_cap.max_bitpool);
	} else
		return -EINVAL;

	client->caps = g_slist_append(client->caps, media_codec);

	return 0;
}

static void handle_setconfiguration_req(struct unix_client *client,
					struct bt_set_configuration_req *req)
{
	struct audio_device *dev;
	bdaddr_t bdaddr;
	int err = 0;

	if (!req->access_mode) {
		err = EINVAL;
		goto failed;
	}

	str2ba(req->device, &bdaddr);

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

	if (!manager_find_device(&bdaddr, NULL, FALSE))
		goto failed;

	dev = manager_find_device(&bdaddr, client->interface, TRUE);
	if (!dev)
		dev = manager_find_device(&bdaddr, client->interface, FALSE);

	if (!dev)
		goto failed;

	client->access_mode = req->access_mode;

	start_config(dev, client);

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

static gboolean client_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	bt_audio_msg_header_t *msghdr = (void *) buf;
	struct unix_client *client = data;
	int len;
	struct a2dp_data *a2dp = &client->d.a2dp;
	struct headset_data *hs = &client->d.hs;
	const char *type, *name;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		debug("Unix client disconnected (fd=%d)", client->sock);
		switch (client->type) {
		case TYPE_HEADSET:
			if (client->dev)
				headset_unlock(client->dev, hs->lock);
			break;
		case TYPE_SOURCE:
		case TYPE_SINK:
			if (a2dp->sep) {
				a2dp_sep_unlock(a2dp->sep, a2dp->session);
				a2dp->sep = NULL;
			}
			break;
		default:
			break;
		}

		if (client->cancel && client->req_id > 0)
			client->cancel(client->dev, client->req_id);
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

	debug("Audio API: %s <- %s", type, name);

	if (msghdr->length != len) {
		error("Invalid message: length mismatch");
		goto failed;
	}

	switch (msghdr->name) {
	case BT_GET_CAPABILITIES:
		handle_getcapabilities_req(client,
				(struct bt_get_capabilities_req *) msghdr);
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
	case BT_CONTROL:
		handle_control_req(client,
				(struct bt_control_req *) msghdr);
		break;
	default:
		error("Audio API: received unexpected message name %d",
				msghdr->name);
	}

	return TRUE;

failed:
	clients = g_slist_remove(clients, client);
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

	debug("Accepted new client connection on unix socket (fd=%d)", cli_sk);
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

	unix_sock = sk;

	listen(sk, 1);

	io = g_io_channel_unix_new(sk);
	g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
							server_cb, NULL);
	g_io_channel_unref(io);

	debug("Unix socket created: %d", sk);

	return 0;
}

void unix_exit(void)
{
	g_slist_foreach(clients, (GFunc) client_free, NULL);
	g_slist_free(clients);
	close(unix_sock);
	unix_sock = -1;
}
