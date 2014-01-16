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
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/signalfd.h>

#include <glib.h>
#include "src/shared/util.h"
#include "src/log.h"
#include "android/hal-msg.h"
#include "android/ipc.h"

struct test_data {
	uint32_t expected_signal;
	const struct hal_hdr *cmd;
	uint16_t cmd_size;
	uint8_t service;
	const struct ipc_handler *handlers;
	uint8_t handlers_size;
};

struct context {
	GMainLoop *main_loop;

	int sk;

	guint source;
	guint cmd_source;
	guint notif_source;

	GIOChannel *cmd_io;
	GIOChannel *notif_io;
	GIOChannel *signal_io;

	guint signal_source;

	const struct test_data *data;
};

static void context_quit(struct context *context)
{
	g_main_loop_quit(context->main_loop);
}

static gboolean cmd_watch(GIOChannel *io, GIOCondition cond,
						gpointer user_data)
{
	struct context *context = user_data;
	const struct test_data *test_data = context->data;
	uint8_t buf[128];
	int sk;

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		g_assert(FALSE);
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(io);

	g_assert(read(sk, buf, sizeof(buf)) == test_data->cmd_size);
	g_assert(!memcmp(test_data->cmd, buf, test_data->cmd_size));

	context_quit(context);

	return TRUE;
}

static gboolean notif_watch(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		g_assert(FALSE);
		return FALSE;
	}

	return TRUE;
}

static gboolean connect_handler(GIOChannel *io, GIOCondition cond,
						gpointer user_data)
{
	struct context *context = user_data;
	const struct test_data *test_data = context->data;
	GIOChannel *new_io;
	GIOCondition watch_cond;
	int sk;

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		g_assert(FALSE);
		return FALSE;
	}

	g_assert(!context->cmd_source || !context->notif_source);

	sk = accept(context->sk, NULL, NULL);
	g_assert(sk >= 0);

	new_io = g_io_channel_unix_new(sk);

	watch_cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;

	if (context->cmd_source && !context->notif_source) {
		context->notif_source = g_io_add_watch(new_io, watch_cond,
							notif_watch, context);
		g_assert(context->notif_source > 0);
		context->notif_io = new_io;
	}

	if (!context->cmd_source) {
		context->cmd_source = g_io_add_watch(new_io, watch_cond,
							cmd_watch, context);
		context->cmd_io = new_io;
	}

	if (context->cmd_source && context->notif_source && !test_data->cmd)
		context_quit(context);

	return TRUE;
}

static gboolean signal_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct context *context = user_data;
	const struct test_data *test_data = context->data;
	struct signalfd_siginfo si;
	ssize_t result;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, &si, sizeof(si));
	if (result != sizeof(si))
		return FALSE;

	g_assert(test_data->expected_signal == si.ssi_signo);
	context_quit(context);
	return TRUE;
}

static guint setup_signalfd(gpointer user_data)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int ret;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	ret = sigprocmask(SIG_BLOCK, &mask, NULL);
	g_assert(ret == 0);

	fd = signalfd(-1, &mask, 0);
	g_assert(fd >= 0);

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, user_data);

	g_io_channel_unref(channel);

	return source;
}

static struct context *create_context(gconstpointer data)
{
	struct context *context = g_new0(struct context, 1);
	struct sockaddr_un addr;
	GIOChannel *io;
	int ret, sk;

	context->main_loop = g_main_loop_new(NULL, FALSE);
	g_assert(context->main_loop);

	context->signal_source = setup_signalfd(context);
	g_assert(context->signal_source);

	sk = socket(AF_LOCAL, SOCK_SEQPACKET, 0);
	g_assert(sk >= 0);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	memcpy(addr.sun_path, BLUEZ_HAL_SK_PATH, sizeof(BLUEZ_HAL_SK_PATH));

	ret = bind(sk, (struct sockaddr *) &addr, sizeof(addr));
	g_assert(ret == 0);

	ret = listen(sk, 5);
	g_assert(ret == 0);

	io = g_io_channel_unix_new(sk);

	g_io_channel_set_close_on_unref(io, TRUE);

	context->source = g_io_add_watch(io,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				connect_handler, context);
	g_assert(context->source > 0);

	g_io_channel_unref(io);

	context->sk = sk;
	context->data = data;

	return context;
}

static void execute_context(struct context *context)
{
	g_main_loop_run(context->main_loop);

	g_io_channel_shutdown(context->notif_io, true, NULL);
	g_io_channel_shutdown(context->cmd_io, true, NULL);
	g_io_channel_unref(context->cmd_io);
	g_io_channel_unref(context->notif_io);

	g_source_remove(context->notif_source);
	g_source_remove(context->signal_source);
	g_source_remove(context->cmd_source);
	g_source_remove(context->source);

	g_main_loop_unref(context->main_loop);

	g_free(context);
}

static void test_init(gconstpointer data)
{
	struct context *context = create_context(data);

	ipc_init();

	execute_context(context);

	ipc_cleanup();
}

static gboolean send_cmd(gpointer user_data)
{
	struct context *context = user_data;
	const struct test_data *test_data = context->data;
	int sk;

	sk = g_io_channel_unix_get_fd(context->cmd_io);
	g_assert(sk >= 0);

	g_assert(write(sk, test_data->cmd, test_data->cmd_size) ==
						test_data->cmd_size);

	return FALSE;
}

static gboolean register_service(gpointer user_data)
{
	struct context *context = user_data;
	const struct test_data *test_data = context->data;

	ipc_register(test_data->service, test_data->handlers,
						test_data->handlers_size);

	return FALSE;
}

static gboolean unregister_service(gpointer user_data)
{
	struct context *context = user_data;
	const struct test_data *test_data = context->data;

	ipc_unregister(test_data->service);

	return FALSE;
}

static void test_cmd(gconstpointer data)
{
	struct context *context = create_context(data);

	ipc_init();

	g_idle_add(send_cmd, context);

	execute_context(context);

	ipc_cleanup();
}

static void test_cmd_reg(gconstpointer data)
{
	struct context *context = create_context(data);
	const struct test_data *test_data = context->data;

	ipc_init();

	g_idle_add(register_service, context);
	g_idle_add(send_cmd, context);

	execute_context(context);

	ipc_unregister(test_data->service);

	ipc_cleanup();
}

static void test_cmd_reg_1(gconstpointer data)
{
	struct context *context = create_context(data);

	ipc_init();

	g_idle_add(register_service, context);
	g_idle_add(unregister_service, context);
	g_idle_add(send_cmd, context);

	execute_context(context);

	ipc_cleanup();
}

static void test_cmd_handler(const void *buf, uint16_t len)
{
	ipc_send_rsp(0, 1, 0);
}

static const struct test_data test_init_1 = {};

static const struct hal_hdr test_cmd_1_hdr = {
	.service_id = 0,
	.opcode = 1,
	.len = 0
};

static const struct test_data test_cmd_1 = {
	.cmd = &test_cmd_1_hdr,
	.cmd_size = sizeof(test_cmd_1_hdr),
	.expected_signal = SIGTERM
};

static const struct ipc_handler cmd_handlers[] = {
	{ test_cmd_handler, false, 0 }
};

static const struct test_data test_cmd_2 = {
	.cmd = &test_cmd_1_hdr,
	.cmd_size = sizeof(test_cmd_1_hdr),
	.service = 0,
	.handlers = cmd_handlers,
	.handlers_size = 1
};

static const struct test_data test_cmd_3 = {
	.cmd = &test_cmd_1_hdr,
	.cmd_size = sizeof(test_cmd_1_hdr),
	.service = 0,
	.handlers = cmd_handlers,
	.handlers_size = 1,
	.expected_signal = SIGTERM
};

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	if (g_test_verbose())
		__btd_log_init("*", 0);

	g_test_add_data_func("/android_ipc/init", &test_init_1, test_init);
	g_test_add_data_func("/android_ipc/send_cmd_1", &test_cmd_1, test_cmd);
	g_test_add_data_func("/android_ipc/send_cmd_2", &test_cmd_2,
							test_cmd_reg);
	g_test_add_data_func("/android_ipc/send_cmd_3", &test_cmd_3,
							test_cmd_reg_1);

	return g_test_run();
}
