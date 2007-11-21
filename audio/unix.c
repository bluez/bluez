/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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
	int access_mode;
	int data_fd; /* To be deleted once two phase configuration is fully implemented */
	unsigned int req_id;
	unsigned int cb_id;
	gboolean (*cancel_stream) (struct device *dev, unsigned int id);
};

static GSList *clients = NULL;

static int unix_sock = -1;

static void unix_ipc_sendmsg(struct unix_client *client,
					const bt_audio_msg_header_t *msg);

static void send_getcapabilities_rsp_error(struct unix_client *client, int err);

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

static void headset_setup_complete(struct device *dev, void *user_data)
{
	struct unix_client *client = user_data;
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_getcapabilities_rsp *rsp = (void *) buf;
	struct headset_data *hs = &client->d.hs;

	client->req_id = 0;

	if (!dev) {
		send_getcapabilities_rsp_error(client, EIO);
		client->dev = NULL;
		return;
	}

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
		send_getcapabilities_rsp_error(client, EIO);
		client->dev = NULL;
		return;
	}

	memset(buf, 0, sizeof(buf));

	rsp->h.msg_type = BT_GETCAPABILITIES_RSP;
	rsp->transport  = BT_CAPABILITIES_TRANSPORT_SCO;
	rsp->access_mode = client->access_mode;
	rsp->link_mtu = 48;
	rsp->sampling_rate = 8000;

	client->data_fd = headset_get_sco_fd(dev);

	unix_ipc_sendmsg(client, &rsp->h);
}

static void a2dp_setup_complete(struct avdtp *session, struct a2dp_sep *sep,
					struct avdtp_stream *stream,
					void *user_data, struct avdtp_error *err)
{
	struct unix_client *client = user_data;
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_getcapabilities_rsp *rsp = (void *) buf;
	struct avdtp_service_capability *cap;
	struct avdtp_media_codec_capability *codec_cap;
	struct sbc_codec_cap *sbc_cap;
	struct a2dp_data *a2dp = &client->d.a2dp;
	uint16_t imtu, omtu;
	GSList *caps;

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

	if (!avdtp_stream_get_transport(stream, &client->data_fd, &imtu, &omtu, &caps)) {
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

	rsp->h.msg_type = BT_GETCAPABILITIES_RSP;
	rsp->transport = BT_CAPABILITIES_TRANSPORT_A2DP;
	client->access_mode = BT_CAPABILITIES_ACCESS_MODE_WRITE;
	rsp->access_mode = client->access_mode;
	/* FIXME: Use imtu when fd_opt is CFG_FD_OPT_READ */
	rsp->link_mtu = omtu;

	sbc_cap = (void *) codec_cap;

	/* assignations below are ok as soon as newipc.h and a2dp.h are kept */
	/* in sync. However it is not possible to cast a struct to another   */
	/* dues to endianess issues */
	rsp->sbc_capabilities.channel_mode = sbc_cap->channel_mode;
	rsp->sbc_capabilities.frequency = sbc_cap->frequency;
	rsp->sbc_capabilities.allocation_method = sbc_cap->allocation_method;
	rsp->sbc_capabilities.subbands = sbc_cap->subbands;
	rsp->sbc_capabilities.block_length = sbc_cap->block_length;
	rsp->sbc_capabilities.min_bitpool = sbc_cap->min_bitpool;
	rsp->sbc_capabilities.max_bitpool = sbc_cap->max_bitpool;

	unix_ipc_sendmsg(client, &rsp->h);

	client->cb_id = avdtp_stream_add_cb(session, stream,
						stream_state_changed, client);

	return;

failed:
	error("stream setup failed");
	if (a2dp->sep) {
		a2dp_sep_unlock(a2dp->sep, a2dp->session);
		a2dp->sep = NULL;
	}
	send_getcapabilities_rsp_error(client, EIO);

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
	send_getcapabilities_rsp_error(client, EIO);
}

static void create_cb(struct device *dev, void *user_data)
{
	struct unix_client *client = user_data;

	if (!dev)
		send_getcapabilities_rsp_error(client, EIO);
	else
		create_stream(dev, client);
}

static void unix_ipc_sendmsg(struct unix_client *client,
					const bt_audio_msg_header_t *msg)
{
	info("Audio API: sending %s", bt_audio_strmsg(msg->msg_type));
	if (send(client->sock, msg, BT_AUDIO_IPC_PACKET_SIZE, 0) < 0)
		error("Error %s(%d)", strerror(errno), errno);
}

static void send_getcapabilities_rsp_error(struct unix_client *client, int err)
{
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_getcapabilities_rsp *rsp = (void *) buf;

	memset(buf, 0, sizeof(buf));
	rsp->h.msg_type = BT_GETCAPABILITIES_RSP;
	rsp->posix_errno = err;

	unix_ipc_sendmsg(client, &rsp->h);
}

static void handle_getcapabilities_req(struct unix_client *client,
					struct bt_getcapabilities_req *req)
{
	struct device *dev;
	bdaddr_t bdaddr;

	str2ba(req->device, &bdaddr);

	if (!req->access_mode) {
		send_getcapabilities_rsp_error(client, EINVAL);
		return;
	}

	client->access_mode = req->access_mode;

	if (client->interface) {
		g_free(client->interface);
		client->interface = NULL;
	}

	if (req->transport == BT_CAPABILITIES_TRANSPORT_SCO)
		client->interface = g_strdup(AUDIO_HEADSET_INTERFACE);
	else if (req->transport == BT_CAPABILITIES_TRANSPORT_A2DP)
		client->interface = g_strdup(AUDIO_SINK_INTERFACE);

	client->media_codec = 0;

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
	send_getcapabilities_rsp_error(client, EIO);
}

static void handle_setconfiguration_req(struct unix_client *client,
					struct bt_setconfiguration_req *req)
{
	/* FIXME: for now we just blindly assume that we receive is the
	   only valid configuration sent.*/
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_setconfiguration_rsp *rsp = (void *) buf;

	memset(buf, 0, sizeof(buf));
	rsp->h.msg_type = BT_SETCONFIGURATION_RSP;
	rsp->posix_errno = 0;

	unix_ipc_sendmsg(client, &rsp->h);
}

static void handle_streamstart_req(struct unix_client *client,
					struct bt_streamstart_req *req)
{
	/* FIXME : to be really implemented */
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_streamstart_rsp *rsp = (void *) buf;
	struct bt_datafd_ind *ind = (void *) buf;

	memset(buf, 0, sizeof(buf));
	rsp->h.msg_type = BT_STREAMSTART_RSP;
	rsp->posix_errno = 0;
	unix_ipc_sendmsg(client, &rsp->h);

	memset(buf, 0, sizeof(buf));
	ind->h.msg_type = BT_STREAMFD_IND;
	unix_ipc_sendmsg(client, &ind->h);

	if (unix_sendmsg_fd(client->sock, client->data_fd) < 0)
		error("unix_sendmsg_fd: %s(%d)", strerror(errno), errno);

}

static void handle_streamstop_req(struct unix_client *client,
					struct bt_streamstop_req *req)
{
	/* FIXME : to be implemented */
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_streamstop_rsp *rsp = (void *) buf;

	memset(buf, 0, sizeof(buf));
	rsp->h.msg_type = BT_STREAMSTOP_RSP;
	rsp->posix_errno = 0;

	unix_ipc_sendmsg(client, &rsp->h);
}

static void handle_control_req(struct unix_client *client,
					struct bt_control_req *req)
{
	/* FIXME: really implement that */
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_setconfiguration_rsp *rsp = (void *) buf;

	memset(buf, 0, sizeof(buf));
	rsp->h.msg_type = BT_CONTROL_RSP;
	rsp->posix_errno = 0;

	unix_ipc_sendmsg(client, &rsp->h);
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

		if (client->cancel_stream && client->req_id > 0)
			client->cancel_stream(client->dev, client->req_id);
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
