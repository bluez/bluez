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

#include <glib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#include "lib/bluetooth.h"
#include "btio/btio.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "src/sdp-client.h"

#include "log.h"
#include "hal-msg.h"
#include "hal-ipc.h"
#include "ipc.h"
#include "utils.h"
#include "socket.h"

#define OPP_DEFAULT_CHANNEL	9
#define PBAP_DEFAULT_CHANNEL	15

static bdaddr_t adapter_addr;

/* Simple list of RFCOMM server sockets */
GList *servers = NULL;

/* Simple list of RFCOMM connected sockets */
GList *connections = NULL;

struct rfcomm_sock {
	int fd;		/* descriptor for communication with Java framework */
	int real_sock;	/* real RFCOMM socket */
	int channel;	/* RFCOMM channel */

	guint rfcomm_watch;
	guint stack_watch;

	bdaddr_t dst;
};

static struct rfcomm_sock *create_rfsock(int sock, int *hal_fd)
{
	int fds[2] = {-1, -1};
	struct rfcomm_sock *rfsock;

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) < 0) {
		error("socketpair(): %s", strerror(errno));
		*hal_fd = -1;
		return NULL;
	}

	rfsock = g_new0(struct rfcomm_sock, 1);
	rfsock->fd = fds[0];
	*hal_fd = fds[1];
	rfsock->real_sock = sock;

	return rfsock;
}

static void cleanup_rfsock(struct rfcomm_sock *rfsock)
{
	DBG("rfsock: %p fd %d real_sock %d chan %u",
		rfsock, rfsock->fd, rfsock->real_sock, rfsock->channel);

	if (rfsock->fd > 0)
		close(rfsock->fd);
	if (rfsock->real_sock > 0)
		close(rfsock->real_sock);

	if (rfsock->rfcomm_watch > 0)
		if (!g_source_remove(rfsock->rfcomm_watch))
			error("rfcomm_watch source was not found");

	if (rfsock->stack_watch > 0)
		if (!g_source_remove(rfsock->stack_watch))
			error("stack_watch source was not found");

	g_free(rfsock);
}

static struct profile_info {
	uint8_t		uuid[16];
	uint8_t		channel;
	uint8_t		svc_hint;
	BtIOSecLevel	sec_level;
	sdp_record_t *	(*create_record)(uint8_t chan);
} profiles[] = {
	{
		.uuid = {
			0x00, 0x00, 0x11, 0x2F, 0x00, 0x00, 0x10, 0x00,
			0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
		},
		.channel = PBAP_DEFAULT_CHANNEL
	}, {
		.uuid = {
			0x00, 0x00, 0x11, 0x05, 0x00, 0x00, 0x10, 0x00,
			0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
		  },
		.channel = OPP_DEFAULT_CHANNEL
	}
};

static int bt_sock_send_fd(int sock_fd, const void *buf, int len, int send_fd)
{
	ssize_t ret;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iv;
	char msgbuf[CMSG_SPACE(1)];

	DBG("len %d sock_fd %d send_fd %d", len, sock_fd, send_fd);

	if (sock_fd == -1 || send_fd == -1)
		return -1;

	memset(&msg, 0, sizeof(msg));

	msg.msg_control = msgbuf;
	msg.msg_controllen = sizeof(msgbuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(send_fd));
	memcpy(CMSG_DATA(cmsg), &send_fd, sizeof(send_fd));

	iv.iov_base = (unsigned char *) buf;
	iv.iov_len = len;

	msg.msg_iov = &iv;
	msg.msg_iovlen = 1;

	ret = sendmsg(sock_fd, &msg, MSG_NOSIGNAL);
	if (ret < 0) {
		error("sendmsg(): sock_fd %d send_fd %d: %s",
					sock_fd, send_fd, strerror(errno));
		return ret;
	}

	return ret;
}

static struct profile_info *get_profile_by_uuid(const uint8_t *uuid)
{
	unsigned int i;

	for (i = 0; i < G_N_ELEMENTS(profiles); i++) {
		if (!memcmp(profiles[i].uuid, uuid, 16))
			return &profiles[i];
	}

	return NULL;
}

static int try_write_all(int fd, unsigned char *buf, int len)
{
	int sent = 0;

	while (len > 0) {
		int written;

		written = write(fd, buf, len);
		if (written < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}

		if (!written)
			return 0;

		len -= written; buf += written; sent += written;
	}

	return sent;
}

static gboolean sock_stack_event_cb(GIOChannel *io, GIOCondition cond,
								gpointer data)
{
	struct rfcomm_sock *rfsock = data;
	unsigned char buf[1024];
	int len, sent;

	DBG("rfsock: fd %d real_sock %d chan %u sock %d",
		rfsock->fd, rfsock->real_sock, rfsock->channel,
		g_io_channel_unix_get_fd(io));

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		error("Socket error: sock %d cond %d",
					g_io_channel_unix_get_fd(io), cond);
		goto fail;
	}

	len = read(rfsock->fd, buf, sizeof(buf));
	if (len <= 0) {
		error("read(): %s", strerror(errno));
		/* Read again */
		return TRUE;
	}

	DBG("read %d bytes write to %d", len, rfsock->real_sock);

	sent = try_write_all(rfsock->real_sock, buf, len);
	if (sent < 0) {
		error("write(): %s", strerror(errno));
		goto fail;
	}

	DBG("Written %d bytes", sent);

	return TRUE;
fail:
	connections = g_list_remove(connections, rfsock);
	cleanup_rfsock(rfsock);

	return FALSE;
}

static gboolean sock_rfcomm_event_cb(GIOChannel *io, GIOCondition cond,
								gpointer data)
{
	struct rfcomm_sock *rfsock = data;
	unsigned char buf[1024];
	int len, sent;

	DBG("rfsock: fd %d real_sock %d chan %u sock %d",
		rfsock->fd, rfsock->real_sock, rfsock->channel,
		g_io_channel_unix_get_fd(io));

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		error("Socket error: sock %d cond %d",
					g_io_channel_unix_get_fd(io), cond);
		goto fail;
	}

	len = read(rfsock->real_sock, buf, sizeof(buf));
	if (len <= 0) {
		error("read(): %s", strerror(errno));
		/* Read again */
		return TRUE;
	}

	DBG("read %d bytes, write to fd %d", len, rfsock->fd);

	sent = try_write_all(rfsock->fd, buf, len);
	if (sent < 0) {
		error("write(): %s", strerror(errno));
		goto fail;
	}

	DBG("Written %d bytes", sent);

	return TRUE;
fail:
	connections = g_list_remove(connections, rfsock);
	cleanup_rfsock(rfsock);

	return FALSE;
}

static bool sock_send_accept(struct rfcomm_sock *rfsock, bdaddr_t *bdaddr,
							int fd_accepted)
{
	struct hal_sock_connect_signal cmd;
	int len;

	DBG("");

	cmd.size = sizeof(cmd);
	bdaddr2android(bdaddr, cmd.bdaddr);
	cmd.channel = rfsock->channel;
	cmd.status = 0;

	len = bt_sock_send_fd(rfsock->fd, &cmd, sizeof(cmd), fd_accepted);
	if (len != sizeof(cmd)) {
		error("Error sending accept signal");
		return false;
	}

	return true;
}

static void accept_cb(GIOChannel *io, GError *err, gpointer user_data)
{
	struct rfcomm_sock *rfsock = user_data;
	struct rfcomm_sock *rfsock_acc;
	GIOChannel *io_stack;
	GError *gerr = NULL;
	bdaddr_t dst;
	char address[18];
	int sock_acc;
	int hal_fd;
	guint id;
	GIOCondition cond;

	if (err) {
		error("%s", err->message);
		return;
	}

	bt_io_get(io, &gerr,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_INVALID);
	if (gerr) {
		error("%s", gerr->message);
		g_error_free(gerr);
		g_io_channel_shutdown(io, TRUE, NULL);
		return;
	}

	ba2str(&dst, address);
	DBG("Incoming connection from %s rfsock %p", address, rfsock);

	sock_acc = g_io_channel_unix_get_fd(io);
	rfsock_acc = create_rfsock(sock_acc, &hal_fd);
	connections = g_list_append(connections, rfsock_acc);

	DBG("rfsock: fd %d real_sock %d chan %u sock %d",
		rfsock->fd, rfsock->real_sock, rfsock->channel,
		sock_acc);

	if (!sock_send_accept(rfsock, &dst, hal_fd)) {
		cleanup_rfsock(rfsock_acc);
		return;
	}

	/* Handle events from Android */
	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	io_stack = g_io_channel_unix_new(rfsock_acc->fd);
	id = g_io_add_watch(io_stack, cond, sock_stack_event_cb, rfsock_acc);
	g_io_channel_unref(io_stack);

	rfsock_acc->stack_watch = id;

	/* Handle rfcomm events */
	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	id = g_io_add_watch(io, cond, sock_rfcomm_event_cb, rfsock_acc);

	rfsock_acc->rfcomm_watch = id;

	DBG("rfsock %p rfsock_acc %p stack_watch %d rfcomm_watch %d",
		rfsock, rfsock_acc, rfsock_acc->stack_watch,
		rfsock_acc->rfcomm_watch);
}

static int handle_listen(void *buf)
{
	struct hal_cmd_sock_listen *cmd = buf;
	struct profile_info *profile;
	struct rfcomm_sock *rfsock;
	GIOChannel *io;
	GError *err = NULL;
	int hal_fd;
	int chan;

	DBG("");

	profile = get_profile_by_uuid(cmd->uuid);
	if (!profile)
		return -1;

	chan = profile->channel;

	DBG("rfcomm channel %d", chan);

	rfsock = create_rfsock(-1, &hal_fd);
	if (!rfsock)
		return -1;

	io = bt_io_listen(accept_cb, NULL, rfsock, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
				BT_IO_OPT_CHANNEL, chan,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("Failed listen: %s", err->message);
		g_error_free(err);
		cleanup_rfsock(rfsock);
		return -1;
	}

	rfsock->real_sock = g_io_channel_unix_get_fd(io);
	servers = g_list_append(servers, rfsock);

	/* TODO: Add server watch */
	g_io_channel_set_close_on_unref(io, TRUE);
	g_io_channel_unref(io);

	DBG("real_sock %d fd %d hal_fd %d", rfsock->real_sock, rfsock->fd,
								hal_fd);

	if (write(rfsock->fd, &chan, sizeof(chan)) != sizeof(chan)) {
		error("Error sending RFCOMM channel");
		cleanup_rfsock(rfsock);
		return -1;
	}

	return hal_fd;
}

static void connect_cb(GIOChannel *io, GError *err, gpointer user_data)
{
	struct rfcomm_sock *rfsock = user_data;
	bdaddr_t *dst = &rfsock->dst;
	GIOChannel *io_stack;
	char address[18];
	guint id;
	GIOCondition cond;

	if (err) {
		error("%s", err->message);
		goto fail;
	}

	ba2str(dst, address);
	DBG("Connected to %s", address);

	DBG("rfsock: fd %d real_sock %d chan %u sock %d",
		rfsock->fd, rfsock->real_sock, rfsock->channel,
		g_io_channel_unix_get_fd(io));

	/* Handle events from Android */
	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	io_stack = g_io_channel_unix_new(rfsock->fd);
	id = g_io_add_watch(io_stack, cond, sock_stack_event_cb, rfsock);
	g_io_channel_unref(io_stack);

	rfsock->stack_watch = id;

	/* Handle rfcomm events */
	cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	id = g_io_add_watch(io, cond, sock_rfcomm_event_cb, rfsock);

	rfsock->rfcomm_watch = id;

	return;
fail:
	cleanup_rfsock(rfsock);
}

static void sdp_search_cb(sdp_list_t *recs, int err, gpointer data)
{
	struct rfcomm_sock *rfsock = data;
	GError *gerr = NULL;
	sdp_list_t *list;
	GIOChannel *io;
	int chan;

	DBG("");

	if (err < 0) {
		error("Unable to get SDP record: %s", strerror(-err));
		goto fail;
	}

	if (!recs || !recs->data) {
		error("No SDP records found");
		goto fail;
	}

	for (list = recs; list != NULL; list = list->next) {
		sdp_record_t *rec = list->data;
		sdp_list_t *protos;

		if (sdp_get_access_protos(rec, &protos) < 0) {
			error("Unable to get proto list");
			goto fail;
		}

		chan = sdp_get_proto_port(protos, RFCOMM_UUID);

		sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free,
									NULL);
		sdp_list_free(protos, NULL);

		if (chan)
			break;
	}

	if (chan <= 0) {
		error("Could not get RFCOMM channel %d", chan);
		goto fail;
	}

	DBG("Got RFCOMM channel %d", chan);

	io = bt_io_connect(connect_cb, rfsock, NULL, &gerr,
				BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
				BT_IO_OPT_DEST_BDADDR, &rfsock->dst,
				BT_IO_OPT_CHANNEL, chan,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("Failed connect: %s", gerr->message);
		g_error_free(gerr);
		goto fail;
	}

	rfsock->real_sock = g_io_channel_unix_get_fd(io);
	rfsock->channel = chan;
	connections = g_list_append(connections, rfsock);

	g_io_channel_unref(io);

	return;
fail:
	cleanup_rfsock(rfsock);
}

static int handle_connect(void *buf)
{
	struct hal_cmd_sock_connect *cmd = buf;
	struct rfcomm_sock *rfsock;
	bdaddr_t dst;
	uuid_t uuid;
	int hal_fd = -1;

	DBG("");

	android2bdaddr(cmd->bdaddr, &dst);
	rfsock = create_rfsock(-1, &hal_fd);
	bacpy(&rfsock->dst, &dst);

	memset(&uuid, 0, sizeof(uuid));
	uuid.type = SDP_UUID128;
	memcpy(&uuid.value.uuid128, cmd->uuid, sizeof(uint128_t));

	if (bt_search_service(&adapter_addr, &dst, &uuid, sdp_search_cb, rfsock,
								NULL) < 0) {
		error("Failed to search SDP records");
		cleanup_rfsock(rfsock);
		return -1;
	}

	return hal_fd;
}

void bt_sock_handle_cmd(int sk, uint8_t opcode, void *buf, uint16_t len)
{
	int fd;

	switch (opcode) {
	case HAL_OP_SOCK_LISTEN:
		fd = handle_listen(buf);
		if (fd < 0)
			break;

		ipc_send(sk, HAL_SERVICE_ID_SOCK, opcode, 0, NULL, fd);
		return;
	case HAL_OP_SOCK_CONNECT:
		fd = handle_connect(buf);
		if (fd < 0)
			break;

		ipc_send(sk, HAL_SERVICE_ID_SOCK, opcode, 0, NULL, fd);
		return;
	default:
		DBG("Unhandled command, opcode 0x%x", opcode);
		break;
	}

	ipc_send_rsp(sk, HAL_SERVICE_ID_SOCK, opcode, HAL_STATUS_FAILED);
}

bool bt_socket_register(int sk, const bdaddr_t *addr)
{
	DBG("");

	bacpy(&adapter_addr, addr);

	return true;
}

void bt_socket_unregister(void)
{
	DBG("");
}
