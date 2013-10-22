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

#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <glib.h>

#include "log.h"
#include "src/sdpd.h"

#include "lib/bluetooth.h"
#include "lib/mgmt.h"
#include "src/shared/mgmt.h"

#include "adapter.h"
#include "hal-msg.h"
#include "ipc.h"

static GMainLoop *event_loop;
static struct mgmt *mgmt_if = NULL;

static uint8_t mgmt_version = 0;
static uint8_t mgmt_revision = 0;

static uint16_t adapter_index = MGMT_INDEX_NONE;

static GIOChannel *hal_cmd_io = NULL;
static GIOChannel *hal_notif_io = NULL;

static volatile sig_atomic_t __terminated = 0;

static bool services[HAL_SERVICE_ID_MAX + 1] = { false };

static void service_register(void *buf, uint16_t len)
{
	struct hal_msg_cmd_register_module *m = buf;

	if (m->service_id > HAL_SERVICE_ID_MAX || services[m->service_id]) {
		ipc_send_error(hal_cmd_io, HAL_SERVICE_ID_CORE,
							HAL_ERROR_FAILED);
		return;
	}

	services[m->service_id] = true;

	ipc_send(hal_cmd_io, HAL_SERVICE_ID_CORE, HAL_MSG_OP_REGISTER_MODULE, 0,
								NULL, -1);

	info("Service ID=%u registered", m->service_id);
}

static void service_unregister(void *buf, uint16_t len)
{
	struct hal_msg_cmd_unregister_module *m = buf;

	if (m->service_id > HAL_SERVICE_ID_MAX || !services[m->service_id]) {
		ipc_send_error(hal_cmd_io, HAL_SERVICE_ID_CORE,
							HAL_ERROR_FAILED);
		return;
	}

	services[m->service_id] = false;

	ipc_send(hal_cmd_io, HAL_SERVICE_ID_CORE, HAL_MSG_OP_UNREGISTER_MODULE,
								0, NULL, -1);

	info("Service ID=%u unregistered", m->service_id);
}

static void handle_service_core(uint8_t opcode, void *buf, uint16_t len)
{
	switch (opcode) {
	case HAL_MSG_OP_REGISTER_MODULE:
		service_register(buf, len);
		break;
	case HAL_MSG_OP_UNREGISTER_MODULE:
		service_unregister(buf, len);
		break;
	default:
		ipc_send_error(hal_cmd_io, HAL_SERVICE_ID_CORE,
							HAL_ERROR_FAILED);
		break;
	}
}

static gboolean cmd_watch_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	char buf[BLUEZ_HAL_MTU];
	struct hal_msg_hdr *msg = (void *) buf;
	ssize_t ret;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		info("HAL command socket closed, terminating");
		goto fail;
	}

	fd = g_io_channel_unix_get_fd(io);

	ret = read(fd, buf, sizeof(buf));
	if (ret < 0) {
		error("HAL command read failed, terminating (%s)",
							strerror(errno));
		goto fail;
	}

	if (ret < (ssize_t) sizeof(*msg)) {
		error("HAL command too small, terminating (%zd)", ret);
		goto fail;
	}

	if (ret != (ssize_t) (sizeof(*msg) + msg->len)) {
		error("Malformed HAL command (%zd bytes), terminating", ret);
		goto fail;
	}

	switch (msg->service_id) {
	case HAL_SERVICE_ID_CORE:
		handle_service_core(msg->opcode, buf + sizeof(*msg), msg->len);
		break;
	default:
		ipc_send_error(hal_cmd_io, msg->service_id, HAL_ERROR_FAILED);
		break;
	}

	return TRUE;

fail:
	g_main_loop_quit(event_loop);
	return FALSE;
}

static gboolean notif_watch_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	info("HAL notification socket closed, terminating");
	g_main_loop_quit(event_loop);

	return FALSE;
}

static GIOChannel *connect_hal(GIOFunc connect_cb)
{
	struct sockaddr_un addr;
	GIOCondition cond;
	GIOChannel *io;
	int err, sk;

	sk = socket(PF_LOCAL, SOCK_SEQPACKET, 0);
	if (sk < 0) {
		err = errno;
		error("Failed to create socket: %d (%s)", err, strerror(err));
		return NULL;
	}

	io = g_io_channel_unix_new(sk);

	g_io_channel_set_close_on_unref(io, TRUE);
	g_io_channel_set_flags(io, G_IO_FLAG_NONBLOCK, NULL);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	memcpy(addr.sun_path, BLUEZ_HAL_SK_PATH, sizeof(BLUEZ_HAL_SK_PATH));

	err = connect(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		err = -errno;
		error("Failed to connect HAL socket: %d (%s)", errno,
							strerror(errno));
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
		g_main_loop_quit(event_loop);
		return FALSE;
	}

	cond = G_IO_ERR | G_IO_HUP | G_IO_NVAL;

	g_io_add_watch(io, cond, notif_watch_cb, NULL);

	info("Successfully connected to HAL");

	/* TODO start handling commands */

	return FALSE;
}

static gboolean cmd_connect_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	DBG("");

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		g_main_loop_quit(event_loop);
		return FALSE;
	}

	cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;

	g_io_add_watch(io, cond, cmd_watch_cb, NULL);

	hal_notif_io = connect_hal(notif_connect_cb);
	if (!hal_notif_io) {
		error("Cannot connect to HAL, terminating");
		g_main_loop_quit(event_loop);
	}

	return FALSE;
}

static gboolean signal_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct signalfd_siginfo si;
	ssize_t result;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, &si, sizeof(si));
	if (result != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		if (__terminated == 0) {
			info("Terminating");
			g_main_loop_quit(event_loop);
		}

		__terminated = 1;
		break;
	}

	return TRUE;
}

static guint setup_signalfd(void)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("Failed to set signal mask");
		return 0;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		perror("Failed to create signal descriptor");
		return 0;
	}

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

static gboolean option_version = FALSE;

static GOptionEntry options[] = {
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit", NULL },
	{ NULL }
};

static void adapter_ready(struct bt_adapter *adapter, int err)
{
	if (err) {
		error("Adapter initialization failed: %s", strerror(err));
		exit(EXIT_FAILURE);
	}

	info("Adapter initialized");

	hal_cmd_io = connect_hal(cmd_connect_cb);
	if (!hal_cmd_io) {
		error("Cannot connect to HAL, terminating");
		g_main_loop_quit(event_loop);
	}
}

static void mgmt_index_added_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	DBG("index %u", index);

	if (adapter_index != MGMT_INDEX_NONE) {
		DBG("skip event for index %u", index);
		return;
	}

	adapter_index = index;
	bt_adapter_init(index, mgmt_if, adapter_ready);
}

static void mgmt_index_removed_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	DBG("index %u", index);
}

static void read_index_list_complete(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_index_list *rp = param;
	uint16_t num;
	int i;

	DBG("");

	if (status) {
		error("%s: Failed to read index list: %s (0x%02x)",
					__func__, mgmt_errstr(status), status);
		return;
	}

	if (length < sizeof(*rp)) {
		error("%s: Wrong size of read index list response", __func__);
		return;
	}

	num = btohs(rp->num_controllers);

	DBG("Number of controllers: %u", num);

	if (num * sizeof(uint16_t) + sizeof(*rp) != length) {
		error("%s: Incorrect pkt size for index list rsp", __func__);
		return;
	}

	for (i = 0; i < num; i++) {
		uint16_t index;

		index = btohs(rp->index[i]);

		/**
		 * Use index added event notification.
		 */
		mgmt_index_added_event(index, 0, NULL, NULL);
	}
}

static void read_commands_complete(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_commands *rp = param;

	DBG("");

	if (status) {
		error("Failed to read supported commands: %s (0x%02x)",
						mgmt_errstr(status), status);
		return;
	}

	if (length < sizeof(*rp)) {
		error("Wrong size response");
		return;
	}
}

static void read_version_complete(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_version *rp = param;

	DBG("");

	if (status) {
		error("Failed to read version information: %s (0x%02x)",
						mgmt_errstr(status), status);
		return;
	}

	if (length < sizeof(*rp)) {
		error("Wrong size response");
		return;
	}

	mgmt_version = rp->version;
	mgmt_revision = btohs(rp->revision);

	info("Bluetooth management interface %u.%u initialized",
						mgmt_version, mgmt_revision);

	if (mgmt_version < 1) {
		error("Version 1.0 or later of management interface required");
		abort();
	}

	mgmt_send(mgmt_if, MGMT_OP_READ_COMMANDS, MGMT_INDEX_NONE, 0, NULL,
					read_commands_complete, NULL, NULL);

	mgmt_register(mgmt_if, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
					mgmt_index_added_event, NULL, NULL);
	mgmt_register(mgmt_if, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
					mgmt_index_removed_event, NULL, NULL);

	if (mgmt_send(mgmt_if, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0,
			NULL, read_index_list_complete, NULL, NULL) > 0)
		return;

	error("Failed to read controller index list");
}

static bool init_mgmt_interface(void)
{
	mgmt_if = mgmt_new_default();
	if (!mgmt_if) {
		error("Failed to access management interface");
		return false;
	}

	if (mgmt_send(mgmt_if, MGMT_OP_READ_VERSION, MGMT_INDEX_NONE, 0, NULL,
				read_version_complete, NULL, NULL) == 0) {
		error("Error sending READ_VERSION mgmt command");
		return false;
	}

	return true;
}

static void cleanup_mgmt_interface(void)
{
	mgmt_unref(mgmt_if);
	mgmt_if = NULL;
}

static void cleanup_hal_connection(void)
{
	if (hal_cmd_io) {
		g_io_channel_shutdown(hal_cmd_io, TRUE, NULL);
		g_io_channel_unref(hal_cmd_io);
		hal_cmd_io = NULL;
	}

	if (hal_notif_io) {
		g_io_channel_shutdown(hal_notif_io, TRUE, NULL);
		g_io_channel_unref(hal_notif_io);
		hal_notif_io = NULL;
	}
}

static bool set_capabilities(void)
{
#if defined(ANDROID)
	struct __user_cap_header_struct header;
	struct __user_cap_data_struct cap;

	header.version = _LINUX_CAPABILITY_VERSION;
	header.pid = 0;

	cap.effective = cap.permitted =
		CAP_TO_MASK(CAP_NET_ADMIN) |
		CAP_TO_MASK(CAP_NET_BIND_SERVICE);
	cap.inheritable = 0;

	/* TODO: Move to cap_set_proc once bionic support it */
	if (capset(&header, &cap) < 0) {
		error("%s: capset(): %s", __func__, strerror(errno));
		return false;
	}

	/* TODO: Move to cap_get_proc once bionic support it */
	if (capget(&header, &cap) < 0) {
		error("%s: capget(): %s", __func__, strerror(errno));
		return false;
	}

	DBG("Caps: eff: 0x%x, perm: 0x%x, inh: 0x%x", cap.effective,
					cap.permitted, cap.inheritable);

#endif
	return true;
}

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *err = NULL;
	guint signal;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (g_option_context_parse(context, &argc, &argv, &err) == FALSE) {
		if (err != NULL) {
			g_printerr("%s\n", err->message);
			g_error_free(err);
		} else
			g_printerr("An unknown error occurred\n");

		exit(EXIT_FAILURE);
	}

	g_option_context_free(context);

	if (option_version == TRUE) {
		printf("%s\n", VERSION);
		exit(EXIT_SUCCESS);
	}

	event_loop = g_main_loop_new(NULL, FALSE);
	signal = setup_signalfd();
	if (!signal)
		return EXIT_FAILURE;

	__btd_log_init("*", 0);

	if (!set_capabilities())
		return EXIT_FAILURE;

	if (!init_mgmt_interface())
		return EXIT_FAILURE;

	/* Use params: mtu = 0, flags = 0 */
	start_sdp_server(0, 0);

	DBG("Entering main loop");

	g_main_loop_run(event_loop);

	g_source_remove(signal);

	cleanup_hal_connection();
	stop_sdp_server();
	cleanup_mgmt_interface();
	g_main_loop_unref(event_loop);

	info("Exit");

	__btd_log_cleanup();

	return EXIT_SUCCESS;
}
