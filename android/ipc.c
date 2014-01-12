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

#include <stddef.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <glib.h>

#include "hal-msg.h"
#include "ipc.h"
#include "log.h"

static struct service_handler services[HAL_SERVICE_ID_MAX + 1];

static GIOChannel *cmd_io = NULL;
static GIOChannel *notif_io = NULL;

int ipc_handle_msg(struct service_handler *handlers, size_t max_index,
						const void *buf, ssize_t len)
{
	const struct hal_hdr *msg = buf;
	const struct ipc_handler *handler;

	if (len < (ssize_t) sizeof(*msg)) {
		DBG("message too small (%zd bytes)", len);
		return -EBADMSG;
	}

	if (len != (ssize_t) (sizeof(*msg) + msg->len)) {
		DBG("message malformed (%zd bytes)", len);
		return -EBADMSG;
	}

	/* if service is valid */
	if (msg->service_id > max_index) {
		DBG("unknown service (0x%x)", msg->service_id);
		return -EOPNOTSUPP;
	}

	/* if service is registered */
	if (!handlers[msg->service_id].handler) {
		DBG("service not registered (0x%x)", msg->service_id);
		return -EOPNOTSUPP;
	}

	/* if opcode is valid */
	if (msg->opcode == HAL_OP_STATUS ||
			msg->opcode > handlers[msg->service_id].size) {
		DBG("invalid opcode 0x%x for service 0x%x", msg->opcode,
							msg->service_id);
		return -EOPNOTSUPP;
	}

	/* opcode is table offset + 1 */
	handler = &handlers[msg->service_id].handler[msg->opcode - 1];

	/* if payload size is valid */
	if ((handler->var_len && handler->data_len > msg->len) ||
			(!handler->var_len && handler->data_len != msg->len)) {
		DBG("invalid size for opcode 0x%x service 0x%x",
						msg->opcode, msg->service_id);
		return -EMSGSIZE;
	}

	handler->handler(msg->payload, msg->len);

	return 0;
}

static gboolean cmd_watch_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	char buf[BLUEZ_HAL_MTU];
	ssize_t ret;
	int fd, err;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		info("IPC: command socket closed, terminating");
		goto fail;
	}

	fd = g_io_channel_unix_get_fd(io);

	ret = read(fd, buf, sizeof(buf));
	if (ret < 0) {
		error("IPC: command read failed, terminating (%s)",
							strerror(errno));
		goto fail;
	}

	err = ipc_handle_msg(services, HAL_SERVICE_ID_MAX, buf, ret);
	if (err < 0) {
		error("IPC: failed to handle message, terminating (%s)",
							strerror(-err));
		goto fail;
	}

	return TRUE;

fail:
	raise(SIGTERM);
	return FALSE;
}

static gboolean notif_watch_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	info("IPC: notification socket closed, terminating");
	raise(SIGTERM);

	return FALSE;
}

GIOChannel *ipc_connect(const char *path, size_t size, GIOFunc connect_cb)
{
	struct sockaddr_un addr;
	GIOCondition cond;
	GIOChannel *io;
	int sk;

	sk = socket(PF_LOCAL, SOCK_SEQPACKET, 0);
	if (sk < 0) {
		error("IPC: failed to create socket: %d (%s)", errno,
							strerror(errno));
		return NULL;
	}

	io = g_io_channel_unix_new(sk);

	g_io_channel_set_close_on_unref(io, TRUE);
	g_io_channel_set_flags(io, G_IO_FLAG_NONBLOCK, NULL);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	memcpy(addr.sun_path, path, size);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		error("IPC: failed to connect HAL socket %s: %d (%s)", &path[1],
							errno, strerror(errno));
		g_io_channel_unref(io);
		return NULL;
	}

	cond = G_IO_OUT | G_IO_ERR | G_IO_HUP | G_IO_NVAL;

	g_io_add_watch(io, cond, connect_cb, NULL);

	return io;
}

static gboolean notif_connect_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	DBG("");

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		error("IPC: notification socket connect failed, terminating");
		raise(SIGTERM);
		return FALSE;
	}

	cond = G_IO_ERR | G_IO_HUP | G_IO_NVAL;

	g_io_add_watch(io, cond, notif_watch_cb, NULL);

	cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;

	g_io_add_watch(cmd_io, cond, cmd_watch_cb, NULL);

	info("IPC: successfully connected");

	return FALSE;
}

static gboolean cmd_connect_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	DBG("");

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		error("IPC: command socket connect failed, terminating");
		raise(SIGTERM);
		return FALSE;
	}

	notif_io = ipc_connect(BLUEZ_HAL_SK_PATH, sizeof(BLUEZ_HAL_SK_PATH),
							notif_connect_cb);
	if (!notif_io)
		raise(SIGTERM);

	return FALSE;
}

void ipc_init(void)
{
	cmd_io = ipc_connect(BLUEZ_HAL_SK_PATH, sizeof(BLUEZ_HAL_SK_PATH),
							cmd_connect_cb);
	if (!cmd_io)
		raise(SIGTERM);
}

void ipc_cleanup(void)
{
	if (cmd_io) {
		g_io_channel_shutdown(cmd_io, TRUE, NULL);
		g_io_channel_unref(cmd_io);
		cmd_io = NULL;
	}

	if (notif_io) {
		g_io_channel_shutdown(notif_io, TRUE, NULL);
		g_io_channel_unref(notif_io);
		notif_io = NULL;
	}
}

void ipc_send(int sk, uint8_t service_id, uint8_t opcode, uint16_t len,
							void *param, int fd)
{
	struct msghdr msg;
	struct iovec iv[2];
	struct hal_hdr m;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;

	memset(&msg, 0, sizeof(msg));
	memset(&m, 0, sizeof(m));
	memset(cmsgbuf, 0, sizeof(cmsgbuf));

	m.service_id = service_id;
	m.opcode = opcode;
	m.len = len;

	iv[0].iov_base = &m;
	iv[0].iov_len = sizeof(m);

	iv[1].iov_base = param;
	iv[1].iov_len = len;

	msg.msg_iov = iv;
	msg.msg_iovlen = 2;

	if (fd >= 0) {
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));

		/* Initialize the payload */
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	}

	if (sendmsg(sk, &msg, 0) < 0) {
		error("IPC send failed, terminating :%s", strerror(errno));
		raise(SIGTERM);
	}
}

void ipc_send_rsp(uint8_t service_id, uint8_t opcode, uint8_t status)
{
	struct hal_status s;
	int sk;

	sk = g_io_channel_unix_get_fd(cmd_io);

	if (status == HAL_STATUS_SUCCESS) {
		ipc_send(sk, service_id, opcode, 0, NULL, -1);
		return;
	}

	s.code = status;

	ipc_send(sk, service_id, HAL_OP_STATUS, sizeof(s), &s, -1);
}

void ipc_send_rsp_full(uint8_t service_id, uint8_t opcode, uint16_t len,
							void *param, int fd)
{
	ipc_send(g_io_channel_unix_get_fd(cmd_io), service_id, opcode, len,
								param, fd);
}

void ipc_send_notif(uint8_t service_id, uint8_t opcode,  uint16_t len,
								void *param)
{
	if (!notif_io)
		return;

	ipc_send(g_io_channel_unix_get_fd(notif_io), service_id, opcode, len,
								param, -1);
}

void ipc_register(uint8_t service, const struct ipc_handler *handlers,
								uint8_t size)
{
	services[service].handler = handlers;
	services[service].size = size;
}

void ipc_unregister(uint8_t service)
{
	services[service].handler = NULL;
	services[service].size = 0;
}
