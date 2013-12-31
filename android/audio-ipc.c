/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
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
#include <unistd.h>
#include <glib.h>

#include "ipc.h"
#include "log.h"
#include "audio-msg.h"
#include "audio-ipc.h"

static GIOChannel *audio_io = NULL;

static struct service_handler service;

static gboolean audio_watch_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	char buf[BLUEZ_AUDIO_MTU];
	ssize_t ret;
	int fd, err;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		info("Audio IPC: command socket closed");
		goto fail;
	}

	fd = g_io_channel_unix_get_fd(io);

	ret = read(fd, buf, sizeof(buf));
	if (ret < 0) {
		error("Audio IPC: command read failed (%s)", strerror(errno));
		goto fail;
	}

	err = ipc_handle_msg(&service, AUDIO_SERVICE_ID, buf, ret);
	if (err < 0) {
		error("Audio IPC: failed to handle message (%s)",
							strerror(-err));
		goto fail;
	}

	return TRUE;

fail:
	audio_ipc_cleanup();
	return FALSE;
}

static gboolean audio_connect_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	DBG("");

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		error("Audio IPC: socket connect failed");
		audio_ipc_cleanup();
		return FALSE;
	}

	cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;

	g_io_add_watch(audio_io, cond, audio_watch_cb, NULL);

	info("Audio IPC: successfully connected");

	return FALSE;
}

void audio_ipc_init(void)
{
	audio_io = ipc_connect(BLUEZ_AUDIO_SK_PATH, sizeof(BLUEZ_AUDIO_SK_PATH),
							audio_connect_cb);
}

void audio_ipc_cleanup(void)
{
	if (audio_io) {
		g_io_channel_shutdown(audio_io, TRUE, NULL);
		g_io_channel_unref(audio_io);
		audio_io = NULL;
	}
}

void audio_ipc_register(const struct ipc_handler *handlers, uint8_t size)
{
	service.handler = handlers;
	service.size = size;
}

void audio_ipc_unregister(void)
{
	service.handler = NULL;
	service.size = 0;
}

void audio_ipc_send_rsp(uint8_t opcode, uint8_t status)
{
	struct audio_status s;
	int sk;

	sk = g_io_channel_unix_get_fd(audio_io);

	if (status == AUDIO_STATUS_SUCCESS) {
		ipc_send(sk, AUDIO_SERVICE_ID, opcode, 0, NULL, -1);
		return;
	}

	s.code = status;

	ipc_send(sk, AUDIO_SERVICE_ID, AUDIO_OP_STATUS, sizeof(s), &s, -1);
}

void audio_ipc_send_rsp_full(uint8_t opcode, uint16_t len, void *param, int fd)
{
	ipc_send(g_io_channel_unix_get_fd(audio_io), AUDIO_SERVICE_ID, opcode,
							len, param, fd);
}
