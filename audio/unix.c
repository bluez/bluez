/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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
#include "dbus.h"
#include "ipc.h"
#include "device.h"
#include "manager.h"
#include "avdtp.h"
#include "a2dp.h"
#include "headset.h"
#include "sink.h"
#include "unix.h"

typedef enum {
	TYPE_NONE,
	TYPE_HEADSET,
	TYPE_SINK,
	TYPE_SOURCE
} service_type_t;

typedef void (*notify_cb_t) (struct device *dev, void *data);

struct a2dp_data {
	struct avdtp *session;
	struct avdtp_stream *stream;
	struct a2dp_sep *sep;
};

struct headset_data {
	headset_lock_t lock;
};

struct unix_client {
	struct device *dev;
	struct avdtp_service_capability *media_codec;
	service_type_t type;
	char *interface;
	union {
		struct a2dp_data a2dp;
		struct headset_data hs;
	} d;
	int sock;
	int fd_opt;
	unsigned int req_id;
	unsigned int cb_id;
	gboolean (*cancel_stream) (struct device *dev, unsigned int id);
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

	if (client->media_codec)
		g_free(client->media_codec);

	g_free(client->interface);
	g_free(client);
}

/* Pass file descriptor through local domain sockets (AF_LOCAL, formerly AF_UNIX)
and the sendmsg() system call with the cmsg_type field of a "struct cmsghdr" set
to SCM_RIGHTS and the data being an integer value equal to the handle of the 
file descriptor to be passed.*/
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

static service_type_t select_service(struct device *dev, const char *interface)
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

static int unix_send_cfg(int sock, struct ipc_data_cfg *cfg, int fd)
{
	char buf[IPC_MTU];
	struct ipc_packet *pkt = (void *) buf;
	int len, codec_len;

	memset(buf, 0, sizeof(buf));

	pkt->type = PKT_TYPE_CFG_RSP;

	if (!cfg) {
		pkt->error = EINVAL;
		len = send(sock, pkt, sizeof(struct ipc_packet), 0);
		if (len < 0)
			error("send: %s (%d)", strerror(errno), errno);
		return len;
	}

	debug("fd=%d, fd_opt=%u, pkt_len=%u, sample_size=%u, rate=%u",
						fd, cfg->fd_opt, cfg->pkt_len,
						cfg->sample_size, cfg->rate);

	if (cfg->codec == CFG_CODEC_SBC)
		codec_len = sizeof(struct ipc_codec_sbc);
	else
		codec_len = 0;

	pkt->error = PKT_ERROR_NONE;
	pkt->length = sizeof(struct ipc_data_cfg) + codec_len;
	memcpy(pkt->data, cfg, pkt->length);

	len = sizeof(struct ipc_packet) + pkt->length;
	len = send(sock, pkt, len, 0);
	if (len < 0)
		error("Error %s(%d)", strerror(errno), errno);

	debug("%d bytes sent", len);

	if (fd != -1) {
		len = unix_sendmsg_fd(sock, fd);
		if (len < 0)
			error("Error %s(%d)", strerror(errno), errno);
		debug("%d bytes sent", len);
	}

	return 0;
}

static void headset_setup_complete(struct device *dev, void *user_data)
{
	struct unix_client *client = user_data;
	struct ipc_data_cfg cfg;
	struct headset_data *hs = &client->d.hs;
	int fd;

	client->req_id = 0;

	if (!dev) {
		unix_send_cfg(client->sock, NULL, -1);
		client->dev = NULL;
		return;
	}

	switch (client->fd_opt) {
	case CFG_FD_OPT_READ:
		hs->lock = HEADSET_LOCK_READ;
		break;
	case CFG_FD_OPT_WRITE:
		hs->lock = HEADSET_LOCK_WRITE;
		break;
	case CFG_FD_OPT_READWRITE:
		hs->lock = HEADSET_LOCK_READ | HEADSET_LOCK_WRITE;
		break;
	default:
		hs->lock = 0;
		break;
	}

	if (!headset_lock(dev, hs->lock)) {
		error("Unable to lock headset");
		unix_send_cfg(client->sock, NULL, -1);
		client->dev = NULL;
		return;
	}

	memset(&cfg, 0, sizeof(cfg));

	cfg.fd_opt = client->fd_opt;
	cfg.codec = CFG_CODEC_SCO;
	cfg.mode = CFG_MODE_MONO;
	cfg.pkt_len = 48;
	cfg.sample_size = 2;
	cfg.rate = 8000;

	fd = headset_get_sco_fd(dev);

	unix_send_cfg(client->sock, &cfg, fd);
}

static void a2dp_setup_complete(struct avdtp *session, struct a2dp_sep *sep,
					struct avdtp_stream *stream,
					void *user_data, struct avdtp_error *err)
{
	struct unix_client *client = user_data;
	char buf[sizeof(struct ipc_data_cfg) + sizeof(struct ipc_codec_sbc)];
	struct ipc_data_cfg *cfg = (void *) buf;
	struct avdtp_service_capability *cap;
	struct avdtp_media_codec_capability *codec_cap;
	struct sbc_codec_cap *sbc_cap;
	struct ipc_codec_sbc *sbc = (void *) cfg->data;
	struct a2dp_data *a2dp = &client->d.a2dp;
	int fd;
	uint16_t mtu;
	GSList *caps;

	client->req_id = 0;

	if (!stream)
		goto failed;

	if (!a2dp_sep_lock(sep, session)) {
		error("Unable to lock A2DP source SEP");
		goto failed;
	}

	a2dp->sep = sep;
	a2dp->stream = stream;

	if (!avdtp_stream_get_transport(stream, &fd, &mtu, &caps)) {
		error("Unable to get stream transport");
		goto failed;
	}

	cfg->pkt_len = mtu;

	for (codec_cap = NULL; caps; caps = g_slist_next(caps)) {
		cap = caps->data;
		if (cap->category == AVDTP_MEDIA_CODEC) {
			codec_cap = (void *) cap->data;
			break;
		}
	}

	if (codec_cap == NULL ||
			codec_cap->media_codec_type != A2DP_CODEC_SBC) {
		error("Unable to find matching codec capability");
		goto failed;
	}

	cfg->fd_opt = CFG_FD_OPT_WRITE;

	sbc_cap = (void *) codec_cap;
	cfg->sample_size = 2;

	switch (sbc_cap->channel_mode) {
	case A2DP_CHANNEL_MODE_MONO:
		cfg->mode = CFG_MODE_MONO;
		break;
	case A2DP_CHANNEL_MODE_DUAL_CHANNEL:
		cfg->mode = CFG_MODE_DUAL_CHANNEL;
		break;
	case A2DP_CHANNEL_MODE_STEREO:
		cfg->mode = CFG_MODE_STEREO;
		break;
	case A2DP_CHANNEL_MODE_JOINT_STEREO:
		cfg->mode = CFG_MODE_JOINT_STEREO;
		break;
	}

	switch (sbc_cap->frequency) {
	case A2DP_SAMPLING_FREQ_16000:
		cfg->rate = 16000;
		break;
	case A2DP_SAMPLING_FREQ_32000:
		cfg->rate = 32000;
		break;
	case A2DP_SAMPLING_FREQ_44100:
		cfg->rate = 44100;
		break;
	case A2DP_SAMPLING_FREQ_48000:
		cfg->rate = 48000;
		break;
	}

	cfg->codec = CFG_CODEC_SBC;
	sbc->allocation = sbc_cap->allocation_method == A2DP_ALLOCATION_SNR ?
								0x01 : 0x00;
	sbc->subbands = sbc_cap->subbands == A2DP_SUBBANDS_4 ? 4 : 8;

	switch (sbc_cap->block_length) {
	case A2DP_BLOCK_LENGTH_4:
		sbc->blocks = 4;
		break;
	case A2DP_BLOCK_LENGTH_8:
		sbc->blocks = 8;
		break;
	case A2DP_BLOCK_LENGTH_12:
		sbc->blocks = 12;
		break;
	case A2DP_BLOCK_LENGTH_16:
		sbc->blocks = 16;
		break;
	}

	sbc->bitpool = sbc_cap->max_bitpool;

	unix_send_cfg(client->sock, cfg, fd);

	client->cb_id = avdtp_stream_add_cb(session, stream,
						stream_state_changed, client);

	return;

failed:
	error("stream setup failed");
	if (a2dp->sep) {
		a2dp_sep_unlock(a2dp->sep, a2dp->session);
		a2dp->sep = NULL;
	}
	unix_send_cfg(client->sock, NULL, -1);

	avdtp_unref(a2dp->session);

	a2dp->session = NULL;
	a2dp->stream = NULL;
}

static void create_stream(struct device *dev, struct unix_client *client)
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

		/* FIXME: The provided media_codec breaks bitpool
                   selection. So disable it. This needs fixing */
		id = a2dp_source_request_stream(a2dp->session,
						TRUE, a2dp_setup_complete,
						client,
						NULL/*client->media_codec*/);
		client->cancel_stream = a2dp_source_cancel_stream;
		break;

	case TYPE_HEADSET:
		id = headset_request_stream(dev, headset_setup_complete, client);
		client->cancel_stream = headset_cancel_stream;
		break;

	default:
		error("No known services for device");
		goto failed;
	}

	if (id == 0) {
		error("request_stream failed");
		goto failed;
	}

	client->req_id = id;
	client->dev = dev;

	return;

failed:
	unix_send_cfg(client->sock, NULL, -1);
}

static void create_cb(struct device *dev, void *user_data)
{
	struct unix_client *client = user_data;

	if (!dev)
		unix_send_cfg(client->sock, NULL, -1);
	else
		create_stream(dev, client);
}

static int cfg_to_caps(struct ipc_data_cfg *cfg, struct sbc_codec_cap *sbc_cap)
{
	struct ipc_codec_sbc *sbc = (void *) cfg->data;

	memset(sbc_cap, 0, sizeof(struct sbc_codec_cap));

	sbc_cap->cap.media_type = AVDTP_MEDIA_TYPE_AUDIO;
	sbc_cap->cap.media_codec_type = A2DP_CODEC_SBC;

	switch (cfg->rate) {
	case 48000:
		sbc_cap->frequency = A2DP_SAMPLING_FREQ_48000;
		break;
	case 44100:
		sbc_cap->frequency = A2DP_SAMPLING_FREQ_44100;
		break;
	case 32000:
		sbc_cap->frequency = A2DP_SAMPLING_FREQ_32000;
		break;
	case 16000:
		sbc_cap->frequency = A2DP_SAMPLING_FREQ_16000;
		break;
	default:
		sbc_cap->frequency = A2DP_SAMPLING_FREQ_44100;
		break;
	}

	switch (cfg->mode) {
	case CFG_MODE_MONO:
		sbc_cap->channel_mode = A2DP_CHANNEL_MODE_MONO;
		break;
	case CFG_MODE_DUAL_CHANNEL:
		sbc_cap->channel_mode = A2DP_CHANNEL_MODE_DUAL_CHANNEL;
		break;
	case CFG_MODE_STEREO:
		sbc_cap->channel_mode = A2DP_CHANNEL_MODE_STEREO;
		break;
	case CFG_MODE_JOINT_STEREO:
		sbc_cap->channel_mode = A2DP_CHANNEL_MODE_JOINT_STEREO;
		break;
	default:
		sbc_cap->channel_mode = A2DP_CHANNEL_MODE_JOINT_STEREO;
		break;
	}

	switch (sbc->allocation) {
	case CFG_ALLOCATION_LOUDNESS:
		sbc_cap->allocation_method = A2DP_ALLOCATION_LOUDNESS;
		break;
	case CFG_ALLOCATION_SNR:
		sbc_cap->allocation_method = A2DP_ALLOCATION_LOUDNESS;
		break;
	default:
		sbc_cap->allocation_method = A2DP_ALLOCATION_LOUDNESS;
		break;
	}

	switch (sbc->subbands) {
	case 8:
		sbc_cap->subbands = A2DP_SUBBANDS_8;
		break;
	case 4:
		sbc_cap->subbands = A2DP_SUBBANDS_4;
		break;
	default:
		sbc_cap->subbands = A2DP_SUBBANDS_8;
		break;
	}

	switch (sbc->blocks) {
	case 16:
		sbc_cap->block_length = A2DP_BLOCK_LENGTH_16;
		break;
	case 12:
		sbc_cap->block_length = A2DP_BLOCK_LENGTH_12;
		break;
	case 8:
		sbc_cap->block_length = A2DP_BLOCK_LENGTH_8;
		break;
	case 4:
		sbc_cap->block_length = A2DP_BLOCK_LENGTH_4;
		break;
	default:
		sbc_cap->block_length = A2DP_BLOCK_LENGTH_16;
		break;
	}

	if (sbc->bitpool != 0) {
		if (sbc->bitpool > 250)
			return -EINVAL;

		sbc_cap->min_bitpool = sbc->bitpool;
		sbc_cap->max_bitpool = sbc->bitpool;
	}

	return 0;
}

static void cfg_event(struct unix_client *client, struct ipc_packet *pkt, int len)
{
	struct device *dev;
	bdaddr_t bdaddr;
	struct ipc_data_cfg *cfg = (void *) pkt->data;
	struct sbc_codec_cap sbc_cap;

	str2ba(pkt->device, &bdaddr);

	client->fd_opt = cfg->fd_opt;

	if (client->interface) {
		g_free(client->interface);
		client->interface = NULL;
	}

	if (pkt->role == PKT_ROLE_VOICE)
		client->interface = g_strdup(AUDIO_HEADSET_INTERFACE);
	else if (pkt->role == PKT_ROLE_HIFI)
		client->interface = g_strdup(AUDIO_SINK_INTERFACE);

	if (cfg_to_caps(cfg, &sbc_cap) < 0)
		goto failed;

	client->media_codec = avdtp_service_cap_new(AVDTP_MEDIA_CODEC,
						&sbc_cap, sizeof(sbc_cap));

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

	create_stream(dev, client);

	return;

failed:
	unix_send_cfg(client->sock, NULL, -1);
}

static void ctl_event(struct unix_client *client,
					struct ipc_packet *pkt, int len)
{
}

static int reply_state(int sock, struct ipc_packet *pkt)
{
	struct ipc_data_state *state = (struct ipc_data_state *) pkt->data;
	int len;

	info("status=%u", state->state);

	pkt->type = PKT_TYPE_STATE_RSP;
	pkt->length = sizeof(struct ipc_data_state);
	pkt->error = PKT_ERROR_NONE;

	len = sizeof(struct ipc_packet) + sizeof(struct ipc_data_state);
	len = send(sock, pkt, len, 0);
	if (len < 0)
		error("Error %s(%d)", strerror(errno), errno);

	debug("%d bytes sent", len);

	return 0;
}

static void state_event(struct unix_client *client,
					struct ipc_packet *pkt, int len)
{
#if 0
	struct ipc_data_state *state = (struct ipc_data_state *) pkt->data;
	struct device *dev = client->dev;

	if (len > sizeof(struct ipc_packet))
		device_set_state(dev, state->state);
	else
		state->state = device_get_state(dev);
#endif

	reply_state(client->sock, pkt);
}

static gboolean client_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	char buf[IPC_MTU];
	struct ipc_packet *pkt = (void *) buf;
	struct unix_client *client = data;
	int len, len_check;
	struct a2dp_data *a2dp = &client->d.a2dp;
	struct headset_data *hs = &client->d.hs;

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

		if (client->cancel_stream && client->req_id > 0)
			client->cancel_stream(client->dev, client->req_id);
		goto failed;
	}

	memset(buf, 0, sizeof(buf));

	len = recv(client->sock, buf, sizeof(buf), 0);
	if (len < 0) {
		error("recv: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	len_check = pkt->length + sizeof(struct ipc_packet);
	if (len != len_check) {
		error("Packet lenght doesn't match");
		goto failed;
	}

	switch (pkt->type) {
	case PKT_TYPE_CFG_REQ:
		info("Package PKT_TYPE_CFG_REQ:%u", pkt->role);
		cfg_event(client, pkt, len);
		break;
	case PKT_TYPE_STATE_REQ:
		info("Package PKT_TYPE_STATE_REQ");
		state_event(client, pkt, len);
		break;
	case PKT_TYPE_CTL_REQ:
		info("Package PKT_TYPE_CTL_REQ");
		ctl_event(client, pkt, len);
		break;
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
		AF_UNIX, IPC_SOCKET_NAME
	};

	int sk, err;

	sk = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sk < 0) {
		err = errno;
		error("Can't create unix socket: %s (%d)", strerror(err), err);
		return -err;
	}

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		error("Can't bind unix socket: %s (%d)", strerror(errno), errno);
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

