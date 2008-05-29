/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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
	info("Audio API: sending %s", bt_audio_strmsg(msg->msg_type));

	if (send(client->sock, msg, BT_AUDIO_IPC_PACKET_SIZE, 0) < 0)
		error("Error %s(%d)", strerror(errno), errno);
}

static void unix_ipc_error(struct unix_client *client, int type, int err)
{
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	bt_audio_rsp_msg_header_t *rsp_hdr = (void *) buf;

	if (!g_slist_find(clients, client))
		return;

	memset(buf, 0, sizeof(buf));
	rsp_hdr->msg_h.msg_type = type;
	rsp_hdr->posix_errno = err;

	unix_ipc_sendmsg(client, &rsp_hdr->msg_h);
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
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_getcapabilities_rsp *rsp = (void *) buf;

	client->req_id = 0;

	if (!dev)
		goto failed;

	memset(buf, 0, sizeof(buf));

	rsp->rsp_h.msg_h.msg_type = BT_GETCAPABILITIES_RSP;
	rsp->transport  = BT_CAPABILITIES_TRANSPORT_SCO;
	rsp->sampling_rate = 8000;

	unix_ipc_sendmsg(client, &rsp->rsp_h.msg_h);

	return;

failed:
	error("discovery failed");
	unix_ipc_error(client, BT_SETCONFIGURATION_RSP, EIO);
	client->dev = NULL;
}

static void headset_setup_complete(struct audio_device *dev, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_setconfiguration_rsp *rsp = (void *) buf;
	struct headset_data *hs = &client->d.hs;

	client->req_id = 0;

	if (!dev)
		goto failed;

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

	if (!headset_lock(dev, hs->lock)) {
		error("Unable to lock headset");
		goto failed;
	}

	memset(buf, 0, sizeof(buf));

	rsp->rsp_h.msg_h.msg_type = BT_SETCONFIGURATION_RSP;
	rsp->transport  = BT_CAPABILITIES_TRANSPORT_SCO;
	rsp->access_mode = client->access_mode;
	rsp->link_mtu = 48;

	client->data_fd = headset_get_sco_fd(dev);

	unix_ipc_sendmsg(client, &rsp->rsp_h.msg_h);

	return;

failed:
	error("config failed");
	unix_ipc_error(client, BT_SETCONFIGURATION_RSP, EIO);
	client->dev = NULL;
}

static void headset_resume_complete(struct audio_device *dev, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_streamstart_rsp *rsp = (void *) buf;
	struct bt_streamfd_ind *ind = (void *) buf;

	client->req_id = 0;

	if (!dev)
		goto failed;

	memset(buf, 0, sizeof(buf));

	rsp->rsp_h.msg_h.msg_type = BT_STREAMSTART_RSP;

	unix_ipc_sendmsg(client, &rsp->rsp_h.msg_h);

	memset(buf, 0, sizeof(buf));
	ind->h.msg_type = BT_STREAMFD_IND;
	unix_ipc_sendmsg(client, &ind->h);

	client->data_fd = headset_get_sco_fd(dev);

	if (unix_sendmsg_fd(client->sock, client->data_fd) < 0) {
		error("unix_sendmsg_fd: %s(%d)", strerror(errno), errno);
		goto failed;
	}

	return;

failed:
	error("resume failed");
	unix_ipc_error(client, BT_STREAMSTART_RSP, EIO);
	client->dev = NULL;
}

static void a2dp_discovery_complete(struct avdtp *session, GSList *seps,
					struct avdtp_error *err,
					void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_getcapabilities_rsp *rsp = (void *) buf;
	struct a2dp_data *a2dp = &client->d.a2dp;
	struct sbc_codec_cap *sbc_cap = NULL;
	struct mpeg_codec_cap *mpeg_cap = NULL;
	GSList *l;

	if (!g_slist_find(clients, client)) {
		debug("Client disconnected during discovery");
		return;
	}

	if (err)
		goto failed;

	memset(buf, 0, sizeof(buf));
	client->req_id = 0;

	rsp->rsp_h.msg_h.msg_type = BT_GETCAPABILITIES_RSP;
	rsp->transport = BT_CAPABILITIES_TRANSPORT_A2DP;

	for (l = seps; l; l = g_slist_next(l)) {
		struct avdtp_remote_sep *rsep = l->data;
		struct avdtp_service_capability *cap;
		struct avdtp_media_codec_capability *codec_cap;

		cap = avdtp_get_codec(rsep);

		if (cap->category != AVDTP_MEDIA_CODEC)
			continue;

		codec_cap = (void *) cap->data;

		if (codec_cap->media_codec_type == A2DP_CODEC_SBC && !sbc_cap)
			sbc_cap = (void *) codec_cap;

		if (codec_cap->media_codec_type == A2DP_CODEC_MPEG12 && !mpeg_cap)
			mpeg_cap = (void *) codec_cap;
	}

	/* endianess prevent direct cast */
	if (sbc_cap) {
		rsp->sbc_capabilities.channel_mode = sbc_cap->channel_mode;
		rsp->sbc_capabilities.frequency = sbc_cap->frequency;
		rsp->sbc_capabilities.allocation_method = sbc_cap->allocation_method;
		rsp->sbc_capabilities.subbands = sbc_cap->subbands;
		rsp->sbc_capabilities.block_length = sbc_cap->block_length;
		rsp->sbc_capabilities.min_bitpool = sbc_cap->min_bitpool;
		rsp->sbc_capabilities.max_bitpool = sbc_cap->max_bitpool;
	}

	if (mpeg_cap) {
		rsp->mpeg_capabilities.channel_mode = mpeg_cap->channel_mode;
		rsp->mpeg_capabilities.crc = mpeg_cap->crc;
		rsp->mpeg_capabilities.layer = mpeg_cap->layer;
		rsp->mpeg_capabilities.frequency = mpeg_cap->frequency;
		rsp->mpeg_capabilities.mpf = mpeg_cap->mpf;
		rsp->mpeg_capabilities.bitrate = mpeg_cap->bitrate;
	}

	unix_ipc_sendmsg(client, &rsp->rsp_h.msg_h);

	return;

failed:
	error("discovery failed");
	unix_ipc_error(client, BT_GETCAPABILITIES_RSP, EIO);

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
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_setconfiguration_rsp *rsp = (void *) buf;
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

	rsp->rsp_h.msg_h.msg_type = BT_SETCONFIGURATION_RSP;
	rsp->transport = BT_CAPABILITIES_TRANSPORT_A2DP;
	client->access_mode = BT_CAPABILITIES_ACCESS_MODE_WRITE;
	rsp->access_mode = client->access_mode;
	/* FIXME: Use imtu when fd_opt is CFG_FD_OPT_READ */
	rsp->link_mtu = omtu;

	unix_ipc_sendmsg(client, &rsp->rsp_h.msg_h);

	client->cb_id = avdtp_stream_add_cb(session, stream,
						stream_state_changed, client);

	return;

failed:
	error("config failed");

	if (a2dp->sep) {
		a2dp_sep_unlock(a2dp->sep, a2dp->session);
		a2dp->sep = NULL;
	}
	unix_ipc_error(client, BT_SETCONFIGURATION_RSP, EIO);

	avdtp_unref(a2dp->session);

	a2dp->session = NULL;
	a2dp->stream = NULL;
}

static void a2dp_resume_complete(struct avdtp *session,
				struct avdtp_error *err, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_streamstart_rsp *rsp = (void *) buf;
	struct bt_streamfd_ind *ind = (void *) buf;
	struct a2dp_data *a2dp = &client->d.a2dp;

	if (err)
		goto failed;

	memset(buf, 0, sizeof(buf));
	rsp->rsp_h.msg_h.msg_type = BT_STREAMSTART_RSP;
	rsp->rsp_h.posix_errno = 0;
	unix_ipc_sendmsg(client, &rsp->rsp_h.msg_h);

	memset(buf, 0, sizeof(buf));
	ind->h.msg_type = BT_STREAMFD_IND;
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
	unix_ipc_error(client, BT_STREAMSTART_RSP, EIO);

	avdtp_unref(a2dp->session);

	a2dp->session = NULL;
	a2dp->stream = NULL;
}

static void a2dp_suspend_complete(struct avdtp *session,
				struct avdtp_error *err, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_streamstart_rsp *rsp = (void *) buf;
	struct a2dp_data *a2dp = &client->d.a2dp;

	if (err)
		goto failed;

	memset(buf, 0, sizeof(buf));
	rsp->rsp_h.msg_h.msg_type = BT_STREAMSTOP_RSP;
	rsp->rsp_h.posix_errno = 0;
	unix_ipc_sendmsg(client, &rsp->rsp_h.msg_h);

	return;

failed:
	error("suspend failed");

	if (a2dp->sep) {
		a2dp_sep_unlock(a2dp->sep, a2dp->session);
		a2dp->sep = NULL;
	}
	unix_ipc_error(client, BT_STREAMSTOP_RSP, EIO);

	avdtp_unref(a2dp->session);

	a2dp->session = NULL;
	a2dp->stream = NULL;
}

static void start_discovery(struct audio_device *dev, struct unix_client *client)
{
	struct a2dp_data *a2dp;
	int err = 0;

	client->type = select_service(dev, client->interface);

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
	unix_ipc_error(client, BT_GETCAPABILITIES_RSP, err ? : EIO);
}

static void start_config(struct audio_device *dev, struct unix_client *client)
{
	struct a2dp_data *a2dp;
	unsigned int id;

	client->type = select_service(dev, client->interface);

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
		id = headset_request_stream(dev, headset_setup_complete, client);
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
	unix_ipc_error(client, BT_SETCONFIGURATION_RSP, EIO);
}

static void start_resume(struct audio_device *dev, struct unix_client *client)
{
	struct a2dp_data *a2dp;
	unsigned int id;

	client->type = select_service(dev, client->interface);

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

		if (id == 0) {
			error("resume failed");
			goto failed;
		}

		break;

	case TYPE_HEADSET:
		headset_resume_complete(dev, client);
		break;

	default:
		error("No known services for device");
		goto failed;
	}

	return;

failed:
	unix_ipc_error(client, BT_STREAMSTART_RSP, EIO);
}

static void start_suspend(struct audio_device *dev, struct unix_client *client)
{
	struct a2dp_data *a2dp;
	unsigned int id;

	client->type = select_service(dev, client->interface);

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
		id = headset_request_stream(dev, headset_setup_complete, client);
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
	unix_ipc_error(client, BT_STREAMSTOP_RSP, EIO);
}

static void create_cb(struct audio_device *dev, void *user_data)
{
	struct unix_client *client = user_data;

	if (!dev)
		unix_ipc_error(client, BT_GETCAPABILITIES_RSP, EIO);
	else
		start_discovery(dev, client);
}

static void handle_getcapabilities_req(struct unix_client *client,
					struct bt_getcapabilities_req *req)
{
	struct audio_device *dev;
	bdaddr_t bdaddr;

	str2ba(req->device, &bdaddr);

	if (client->interface) {
		g_free(client->interface);
		client->interface = NULL;
	}

	if (req->transport == BT_CAPABILITIES_TRANSPORT_SCO)
		client->interface = g_strdup(AUDIO_HEADSET_INTERFACE);
	else if (req->transport == BT_CAPABILITIES_TRANSPORT_A2DP)
		client->interface = g_strdup(AUDIO_SINK_INTERFACE);

	if (!manager_find_device(&bdaddr, NULL, FALSE)) {
		if (!(req->flags & BT_FLAG_AUTOCONNECT))
			goto failed;
		if (!bacmp(&bdaddr, BDADDR_ANY))
			goto failed;
		if (!manager_create_device(&bdaddr, create_cb, client))
			goto failed;
		return;
	}

	dev = manager_find_device(&bdaddr, client->interface, TRUE);
	if (!dev) {
		if (req->flags & BT_FLAG_AUTOCONNECT)
			dev = manager_find_device(&bdaddr, client->interface, FALSE);
		else
			goto failed;
	}

	if (!dev)
		goto failed;

	start_discovery(dev, client);

	return;

failed:
	unix_ipc_error(client, BT_GETCAPABILITIES_RSP, EIO);
}

static int handle_sco_transport(struct unix_client *client,
				struct bt_setconfiguration_req *req)
{
	client->interface = g_strdup(AUDIO_HEADSET_INTERFACE);

	info("config sco - device = %s access_mode = %u", req->device,
			req->access_mode);

	return 0;
}

static int handle_a2dp_transport(struct unix_client *client,
				struct bt_setconfiguration_req *req)
{
	struct avdtp_service_capability *media_transport, *media_codec;
	struct sbc_codec_cap sbc_cap;
	struct mpeg_codec_cap mpeg_cap;

	client->interface = g_strdup(AUDIO_SINK_INTERFACE);

	if (client->caps) {
		g_slist_foreach(client->caps, (GFunc) g_free, NULL);
		g_slist_free(client->caps);
	}

	media_transport = avdtp_service_cap_new(AVDTP_MEDIA_TRANSPORT,
						NULL, 0);

	client->caps = g_slist_append(client->caps, media_transport);

	info("config a2dp - device = %s access_mode = %u", req->device,
			req->access_mode);

	if (req->mpeg_capabilities.frequency) {

		memset(&mpeg_cap, 0, sizeof(mpeg_cap));

		mpeg_cap.cap.media_type = AVDTP_MEDIA_TYPE_AUDIO;
		mpeg_cap.cap.media_codec_type = A2DP_CODEC_MPEG12;
		mpeg_cap.channel_mode = req->mpeg_capabilities.channel_mode;
		mpeg_cap.crc = req->mpeg_capabilities.crc;
		mpeg_cap.layer = req->mpeg_capabilities.layer;
		mpeg_cap.frequency = req->mpeg_capabilities.frequency;
		mpeg_cap.mpf = req->mpeg_capabilities.mpf;
		mpeg_cap.bitrate = req->mpeg_capabilities.bitrate;

		media_codec = avdtp_service_cap_new(AVDTP_MEDIA_CODEC, &mpeg_cap,
							sizeof(mpeg_cap));

		info("codec mpeg12 - frequency = %u channel_mode = %u "
			"layer = %u crc = %u mpf = %u bitrate = %u",
			mpeg_cap.frequency, mpeg_cap.channel_mode,
			mpeg_cap.layer, mpeg_cap.crc, mpeg_cap.mpf,
			mpeg_cap.bitrate);
	} else if (req->sbc_capabilities.frequency) {
		memset(&sbc_cap, 0, sizeof(sbc_cap));

		sbc_cap.cap.media_type = AVDTP_MEDIA_TYPE_AUDIO;
		sbc_cap.cap.media_codec_type = A2DP_CODEC_SBC;
		sbc_cap.channel_mode = req->sbc_capabilities.channel_mode;
		sbc_cap.frequency = req->sbc_capabilities.frequency;
		sbc_cap.allocation_method = req->sbc_capabilities.allocation_method;
		sbc_cap.subbands = req->sbc_capabilities.subbands;
		sbc_cap.block_length = req->sbc_capabilities.block_length;
		sbc_cap.min_bitpool = req->sbc_capabilities.min_bitpool;
		sbc_cap.max_bitpool = req->sbc_capabilities.max_bitpool;

		media_codec = avdtp_service_cap_new(AVDTP_MEDIA_CODEC, &sbc_cap,
							sizeof(sbc_cap));

		info("codec sbc - frequency = %u channel_mode = %u "
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
					struct bt_setconfiguration_req *req)
{
	struct audio_device *dev;
	bdaddr_t bdaddr;
	int err = 0;

	if (!req->access_mode) {
		err = EINVAL;
		goto failed;
	}

	str2ba(req->device, &bdaddr);

	if (client->interface) {
		g_free(client->interface);
		client->interface = NULL;
	}

	if (req->transport == BT_CAPABILITIES_TRANSPORT_SCO) {
		err = handle_sco_transport(client, req);
		if (err < 0) {
			err = -err;
			goto failed;
		}
	} else if (req->transport == BT_CAPABILITIES_TRANSPORT_A2DP) {
		err = handle_a2dp_transport(client, req);
		if (err < 0) {
			err = -err;
			goto failed;
		}
	}

	if (!manager_find_device(&bdaddr, NULL, FALSE)) {
		if (!bacmp(&bdaddr, BDADDR_ANY))
			goto failed;
		if (!manager_create_device(&bdaddr, create_cb, client))
			goto failed;
		return;
	}

	dev = manager_find_device(&bdaddr, client->interface, TRUE);
	if (!dev)
		dev = manager_find_device(&bdaddr, client->interface, FALSE);

	if (!dev)
		goto failed;

	client->access_mode = req->access_mode;

	start_config(dev, client);

	return;

failed:
	unix_ipc_error(client, BT_SETCONFIGURATION_RSP, err ? : EIO);
}

static void handle_streamstart_req(struct unix_client *client,
					struct bt_streamstart_req *req)
{
	if (!client->dev)
		goto failed;

	start_resume(client->dev, client);

	return;

failed:
	unix_ipc_error(client, BT_STREAMSTART_REQ, EIO);
}

static void handle_streamstop_req(struct unix_client *client,
					struct bt_streamstop_req *req)
{
	if (!client->dev)
		goto failed;

	start_suspend(client->dev, client);

	return;

failed:
	unix_ipc_error(client, BT_STREAMSTOP_REQ, EIO);
}

static void handle_control_req(struct unix_client *client,
					struct bt_control_req *req)
{
	/* FIXME: really implement that */
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_setconfiguration_rsp *rsp = (void *) buf;

	memset(buf, 0, sizeof(buf));
	rsp->rsp_h.msg_h.msg_type = BT_CONTROL_RSP;
	rsp->rsp_h.posix_errno = 0;

	unix_ipc_sendmsg(client, &rsp->rsp_h.msg_h);
}

static gboolean client_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	bt_audio_msg_header_t *msghdr = (void *) buf;
	struct unix_client *client = data;
	int len;
	struct a2dp_data *a2dp = &client->d.a2dp;
	struct headset_data *hs = &client->d.hs;
	const char *type;

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

	len = recv(client->sock, buf, sizeof(buf), MSG_WAITALL);
	if (len < 0) {
		error("recv: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	if ((type = bt_audio_strmsg(msghdr->msg_type)))
		info("Audio API: received %s", type);

	switch (msghdr->msg_type) {
	case BT_GETCAPABILITIES_REQ:
		handle_getcapabilities_req(client,
				(struct bt_getcapabilities_req *) msghdr);
		break;
	case BT_SETCONFIGURATION_REQ:
		handle_setconfiguration_req(client,
				(struct bt_setconfiguration_req *) msghdr);
		break;
	case BT_STREAMSTART_REQ:
		handle_streamstart_req(client,
				(struct bt_streamstart_req *) msghdr);
		break;
	case BT_STREAMSTOP_REQ:
		handle_streamstop_req(client,
				(struct bt_streamstop_req *) msghdr);
		break;
	case BT_CONTROL_REQ:
		handle_control_req(client,
				(struct bt_control_req *) msghdr);
		break;
	default:
		error("Audio API: received unexpected packet type %d",
				msghdr->msg_type);
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

	info("Unix socket created: %d", sk);

	return 0;
}

void unix_exit(void)
{
	g_slist_foreach(clients, (GFunc) client_free, NULL);
	g_slist_free(clients);
	close(unix_sock);
	unix_sock = -1;
}
