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
#include <assert.h>

#include <glib.h>

#include "logging.h"
#include "dbus.h"

#include "manager.h"

static int unix_sock = -1;

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

static gboolean unix_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	struct ipc_packet *pkt;
	struct ipc_data_cfg *cfg;
	int sk, clisk, len;

	debug("chan %p cond %td data %p", chan, cond, data);

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		g_io_channel_close(chan);
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(chan);

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	clisk = accept(sk, (struct sockaddr *) &addr, &addrlen);
	if (clisk < 0) {
		error("accept: %s (%d)", strerror(errno), errno);
		return TRUE;
	}

	len = sizeof(struct ipc_packet) + sizeof(struct ipc_data_cfg);
	pkt = g_malloc0(len);
	len = recv(clisk, pkt, len, 0);

	debug("path %s len %d", addr.sun_path + 1, len);

	switch (pkt->type) {
	case PKT_TYPE_CFG_REQ:
		info("Package PKT_TYPE_CFG_REQ:%u", pkt->role);

		cfg = (struct ipc_data_cfg *) pkt->data;

		memset(cfg, 0, sizeof(struct ipc_data_cfg));
		if (manager_get_device(clisk, pkt->role, cfg) == 0)
			unix_send_cfg(clisk, pkt);

		break;
	case PKT_TYPE_STATUS_REQ:
		info("Package PKT_TYPE_STATUS_REQ");
		break;
	case PKT_TYPE_CTL_REQ:
		info("Package PKT_TYPE_CTL_REQ");
		break;
	}

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
							unix_event, NULL);

	g_io_channel_unref(io);

	info("Unix socket created: %d", sk);

	return 0;
}

void unix_exit(void)
{
	close(unix_sock);
	unix_sock = -1;
}

int unix_send_cfg(int sock, struct ipc_packet *pkt)
{
	struct ipc_data_cfg *cfg = (struct ipc_data_cfg *) pkt->data;
	int len;

	info("fd=%d, fd_opt=%u, channels=%u, pkt_len=%u, sample_size=%u,"
		"rate=%u", cfg->fd, cfg->fd_opt, cfg->channels,
		cfg->pkt_len, cfg->sample_size, cfg->rate);

	pkt->type = PKT_TYPE_CFG_RSP;
	pkt->length = sizeof(struct ipc_data_cfg);
	pkt->error = PKT_ERROR_NONE;

	len = sizeof(struct ipc_packet) + sizeof(struct ipc_data_cfg);
	len = send(sock, pkt, len, 0);
	if (len < 0)
		info("Error %s(%d)", strerror(errno), errno);

	info("%d bytes sent", len);

	if (cfg->fd != -1) {
		len = unix_sendmsg_fd(sock, cfg->fd, pkt);
		if (len < 0)
			info("Error %s(%d)", strerror(errno), errno);
		info("%d bytes sent", len);
	}

	g_free(pkt);
	close(sock);
	return 0;
}
