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

struct unix_client {
	struct device *dev;
	service_type_t type;
	union {
		struct avdtp *session;
		void *data;
	} data;
	int sock;
	int req_id;
	notify_cb_t disconnect;
	notify_cb_t suspend;
	notify_cb_t play;
};

static GSList *clients = NULL;

static int unix_sock = -1;

static void client_free(struct unix_client *client)
{
	switch (client->type) {
	case TYPE_SINK:
	case TYPE_SOURCE:
		if (client->data.session)
			avdtp_unref(client->data.session);
		break;
	default:
		break;
	}

	if (client->sock >= 0)
		close(client->sock);
	g_free(client);
}

/* Pass file descriptor through local domain sockets (AF_LOCAL, formerly AF_UNIX)
and the sendmsg() system call with the cmsg_type field of a "struct cmsghdr" set
to SCM_RIGHTS and the data being an integer value equal to the handle of the 
file descriptor to be passed.*/
static int unix_sendmsg_fd(int sock, int fd, struct ipc_packet *pkt)
{
	char cmsg_b[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct iovec iov =  {
		.iov_base = pkt,
		.iov_len  = sizeof(struct ipc_packet)
        };

	struct msghdr msgh = {
		.msg_name       = 0,
		.msg_namelen    = 0,
		.msg_iov        = &iov,
		.msg_iovlen     = 1,
		.msg_control    = &cmsg_b,
		.msg_controllen = CMSG_LEN(sizeof(int)),
		.msg_flags      = 0
	};

	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	/* Initialize the payload */
	(*(int *) CMSG_DATA(cmsg)) = fd;

	return sendmsg(sock, &msgh, MSG_NOSIGNAL);
}

static service_type_t select_service(struct device *dev)
{
	if (dev->sink && avdtp_is_connected(&dev->src, &dev->dst))
		return TYPE_SINK;
	else if (dev->headset && headset_is_active(dev))
		return TYPE_HEADSET;
	else if (dev->sink)
		return TYPE_SINK;
	else if (dev->headset)
		return TYPE_HEADSET;
	else
		return TYPE_NONE;
}

static void a2dp_setup_complete(struct avdtp *session, struct device *dev,
					struct avdtp_stream *stream,
					void *user_data)
{
	struct unix_client *client = user_data;
	char buf[sizeof(struct ipc_data_cfg) + sizeof(struct ipc_codec_sbc)];
	struct ipc_data_cfg *cfg = (void *) buf;
	struct avdtp_service_capability *cap;
	struct avdtp_media_codec_capability *codec_cap;
	struct sbc_codec_cap *sbc_cap;
	struct ipc_codec_sbc *sbc = (void *) cfg->data;
	int fd;
	GSList *caps;

	if (!stream)
		goto failed;

	if (!avdtp_stream_get_transport(stream, &fd, &cfg->pkt_len, &caps)) {
		error("Unable to get stream transport");
		goto failed;
	}

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
	cfg->channels = sbc_cap->channel_mode == A2DP_CHANNEL_MODE_MONO ?
				1 : 2;
	cfg->channel_mode = sbc_cap->channel_mode;
	cfg->sample_size = 2;

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

	return;

failed:
	unix_send_cfg(client->sock, NULL, -1);
	a2dp_source_unlock(dev, session);
}

static void cfg_event(struct unix_client *client, struct ipc_packet *pkt,
			int len)
{
	struct ipc_data_cfg *rsp;
	struct device *dev;
	int ret, fd, id;

	dev = manager_get_connected_device();
	if (dev)
		goto proceed;

	dev = manager_default_device();
	if (!dev)
		goto failed;

proceed:
	client->type = select_service(dev);

	switch (client->type) {
	case TYPE_SINK:
		if (!client->data.session)
			client->data.session = avdtp_get(&dev->src, &dev->dst);

		if (!a2dp_source_lock(dev, client->data.session)) {
			error("Unable to lock A2DP source SEP");
			goto failed;
		}

		id = a2dp_source_request_stream(client->data.session, dev,
						TRUE, a2dp_setup_complete,
						client);
		if (id < 0) {
			error("request_stream failed");
			goto failed;
		}

		client->req_id = id;
		client->disconnect = (notify_cb_t) a2dp_source_unlock;
		client->suspend = (notify_cb_t) a2dp_source_suspend;
		client->play = (notify_cb_t) a2dp_source_start_stream;

		break;
	case TYPE_HEADSET:
		if (!headset_lock(dev, client->data.data)) {
			error("Unable to lock headset");
			goto failed;
		}

		ret = headset_get_config(dev, client->sock, pkt, len, &rsp,
						&fd);
		client->disconnect = (notify_cb_t) headset_unlock;
		client->suspend = (notify_cb_t) headset_suspend;
		client->play = (notify_cb_t) headset_play;
		break;
	default:
		error("No known services for device");
		goto failed;
	}

	client->dev = dev;
	return;

failed:
	unix_send_cfg(client->sock, NULL, -1);
}

static void ctl_event(struct unix_client *client, struct ipc_packet *pkt,
			int len)
{
}

static void state_event(struct unix_client *client, struct ipc_packet *pkt,
				int len)
{
#if 0
	struct ipc_data_state *state = (struct ipc_data_state *) pkt->data;
	struct device *dev = client->dev;

	if (len > sizeof(struct ipc_packet))
		device_set_state(dev, state->state);
	else
		state->state = device_get_state(dev);

	unix_send_state(client->sock, pkt);
#endif
}

static gboolean client_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	char buf[IPC_MTU];
	struct ipc_packet *pkt = (void *) buf;
	struct unix_client *client = data;
	int len, len_check;
	void *cb_data;

	if (cond & G_IO_NVAL)
		return FALSE;

	switch (client->type) {
	case TYPE_HEADSET:
		cb_data = client->data.data;
		break;
	case TYPE_SINK:
	case TYPE_SOURCE:
		cb_data = client->data.session;
		break;
	default:
		cb_data = NULL;
		break;
	}

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		debug("Unix client disconnected");
		if (client->disconnect)
			client->disconnect(client->dev, cb_data);
		if (client->type == TYPE_SINK && client->req_id >= 0)
			a2dp_source_cancel_stream(client->req_id);
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

	debug("Accepted new client connection on unix socket");

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

int unix_send_cfg(int sock, struct ipc_data_cfg *cfg, int fd)
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

	debug("fd=%d, fd_opt=%u, channels=%u, pkt_len=%u,"
		"sample_size=%u, rate=%u", fd, cfg->fd_opt, cfg->channels,
		cfg->pkt_len, cfg->sample_size, cfg->rate);

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
		len = unix_sendmsg_fd(sock, fd, pkt);
		if (len < 0)
			error("Error %s(%d)", strerror(errno), errno);
		debug("%d bytes sent", len);
	}

	return 0;
}

#if 0
static int unix_send_state(int sock, struct ipc_packet *pkt)
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
#endif
