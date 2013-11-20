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
#include "log.h"
#include "hal-msg.h"
#include "hal-ipc.h"
#include "ipc.h"
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

static struct profile_info *get_profile_by_uuid(const uint8_t *uuid)
{
	unsigned int i;

	for (i = 0; i < G_N_ELEMENTS(profiles); i++) {
		if (!memcmp(profiles[i].uuid, uuid, 16))
			return &profiles[i];
	}

	return NULL;
}

static void accept_cb(GIOChannel *io, GError *err, gpointer user_data)
{
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

	return hal_fd;
}

static int handle_connect(void *buf)
{
	DBG("Not implemented");

	return -1;
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
