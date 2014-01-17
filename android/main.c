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
#if defined(ANDROID)
#include <sys/capability.h>
#include <linux/prctl.h>
#endif

#include <glib.h>

#include "log.h"
#include "src/sdpd.h"

#include "lib/bluetooth.h"

#include "bluetooth.h"
#include "socket.h"
#include "hidhost.h"
#include "hal-msg.h"
#include "ipc.h"
#include "a2dp.h"
#include "pan.h"

#define STARTUP_GRACE_SECONDS 5
#define SHUTDOWN_GRACE_SECONDS 10

static guint bluetooth_start_timeout = 0;

static bdaddr_t adapter_bdaddr;

static GMainLoop *event_loop;

static bool services[HAL_SERVICE_ID_MAX + 1] = { false };

static void service_register(const void *buf, uint16_t len)
{
	const struct hal_cmd_register_module *m = buf;
	uint8_t status;

	if (m->service_id > HAL_SERVICE_ID_MAX || services[m->service_id]) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	switch (m->service_id) {
	case HAL_SERVICE_ID_BLUETOOTH:
		bt_bluetooth_register();

		break;
	case HAL_SERVICE_ID_SOCK:
		bt_socket_register(&adapter_bdaddr);

		break;
	case HAL_SERVICE_ID_HIDHOST:
		if (!bt_hid_register(&adapter_bdaddr)) {
			status = HAL_STATUS_FAILED;
			goto failed;
		}

		break;
	case HAL_SERVICE_ID_A2DP:
		if (!bt_a2dp_register(&adapter_bdaddr)) {
			status = HAL_STATUS_FAILED;
			goto failed;
		}

		break;
	case HAL_SERVICE_ID_PAN:
		if (!bt_pan_register(&adapter_bdaddr)) {
			status = HAL_STATUS_FAILED;
			goto failed;
		}

		break;
	default:
		DBG("service %u not supported", m->service_id);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	services[m->service_id] = true;

	status = HAL_STATUS_SUCCESS;

	info("Service ID=%u registered", m->service_id);

failed:
	ipc_send_rsp(HAL_SERVICE_ID_CORE, HAL_OP_REGISTER_MODULE, status);
}

static void service_unregister(const void *buf, uint16_t len)
{
	const struct hal_cmd_unregister_module *m = buf;
	uint8_t status;

	if (m->service_id > HAL_SERVICE_ID_MAX || !services[m->service_id]) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	switch (m->service_id) {
	case HAL_SERVICE_ID_BLUETOOTH:
		bt_bluetooth_unregister();
		break;
	case HAL_SERVICE_ID_SOCK:
		bt_socket_unregister();
		break;
	case HAL_SERVICE_ID_HIDHOST:
		bt_hid_unregister();
		break;
	case HAL_SERVICE_ID_A2DP:
		bt_a2dp_unregister();
		break;
	case HAL_SERVICE_ID_PAN:
		bt_pan_unregister();
		break;
	default:
		/* This would indicate bug in HAL, as unregister should not be
		 * called in init failed */
		DBG("service %u not supported", m->service_id);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	services[m->service_id] = false;

	status = HAL_STATUS_SUCCESS;

	info("Service ID=%u unregistered", m->service_id);

failed:
	ipc_send_rsp(HAL_SERVICE_ID_CORE, HAL_OP_UNREGISTER_MODULE, status);
}

static const struct ipc_handler cmd_handlers[] = {
	/* HAL_OP_REGISTER_MODULE */
	{ service_register, false, sizeof(struct hal_cmd_register_module) },
	/* HAL_OP_UNREGISTER_MODULE */
	{ service_unregister, false, sizeof(struct hal_cmd_unregister_module) },
};

static void bluetooth_stopped(void)
{
	g_main_loop_quit(event_loop);
}

static gboolean quit_eventloop(gpointer user_data)
{
	g_main_loop_quit(event_loop);
	return FALSE;
}

static void stop_bluetooth(void)
{
	static bool __stop = false;

	if (__stop)
		return;

	__stop = true;

	if (!bt_bluetooth_stop(bluetooth_stopped)) {
		g_main_loop_quit(event_loop);
		return;
	}

	g_timeout_add_seconds(SHUTDOWN_GRACE_SECONDS, quit_eventloop, NULL);
}

static void adapter_ready(int err, const bdaddr_t *addr)
{
	if (err < 0) {
		error("Adapter initialization failed: %s", strerror(-err));
		exit(EXIT_FAILURE);
	}

	bacpy(&adapter_bdaddr, addr);

	if (bluetooth_start_timeout > 0) {
		g_source_remove(bluetooth_start_timeout);
		bluetooth_start_timeout = 0;
	}

	info("Adapter initialized");

	ipc_init();
}

static gboolean signal_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	static bool __terminated = false;
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
		if (!__terminated) {
			info("Terminating");
			stop_bluetooth();
		}

		__terminated = true;
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
static gint option_index = -1;

static GOptionEntry options[] = {
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit", NULL },
	{ "index", 'i', 0, G_OPTION_ARG_INT, &option_index,
				"Use specified controller", "INDEX"},
	{ NULL }
};

static void cleanup_services(void)
{
	int i;

	DBG("");

	for (i = HAL_SERVICE_ID_BLUETOOTH; i < HAL_SERVICE_ID_MAX; i++) {
		if (!services[i])
			continue;

		switch (i) {
		case HAL_SERVICE_ID_BLUETOOTH:
			bt_bluetooth_unregister();
			break;
		case HAL_SERVICE_ID_SOCK:
			bt_socket_unregister();
			break;
		case HAL_SERVICE_ID_HIDHOST:
			bt_hid_unregister();
			break;
		case HAL_SERVICE_ID_A2DP:
			bt_a2dp_unregister();
			break;
		case HAL_SERVICE_ID_PAN:
			bt_pan_unregister();
			break;
		}

		services[i] = false;
	}
}

static bool set_capabilities(void)
{
#if defined(ANDROID)
	struct __user_cap_header_struct header;
	struct __user_cap_data_struct cap;

	header.version = _LINUX_CAPABILITY_VERSION;
	header.pid = 0;

	/* CAP_NET_ADMIN: Allow use of MGMT interface
	 * CAP_NET_BIND_SERVICE: Allow use of privileged PSM
	 * CAP_NET_RAW: Allow use of bnep ioctl calls */
	cap.effective = cap.permitted =
		CAP_TO_MASK(CAP_NET_RAW) |
		CAP_TO_MASK(CAP_NET_ADMIN) |
		CAP_TO_MASK(CAP_NET_BIND_SERVICE);
	cap.inheritable = 0;

	/* don't clear capabilities when dropping root */
	if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
		error("%s: prctl(): %s", __func__,strerror(errno));
		return false;
	}

	/* Android bluetooth user UID=1002 */
	if (setuid(1002) < 0) {
		error("%s: setuid(): %s", __func__, strerror(errno));
		return false;
	}

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

	signal = setup_signalfd();
	if (!signal)
		return EXIT_FAILURE;

	__btd_log_init("*", 0);

	if (!set_capabilities()) {
		__btd_log_cleanup();
		g_source_remove(signal);
		return EXIT_FAILURE;
	}

	bluetooth_start_timeout = g_timeout_add_seconds(STARTUP_GRACE_SECONDS,
							quit_eventloop, NULL);
	if (bluetooth_start_timeout == 0) {
		error("Failed to init startup timeout");
		__btd_log_cleanup();
		g_source_remove(signal);
		return EXIT_FAILURE;
	}

	if (!bt_bluetooth_start(option_index, adapter_ready)) {
		__btd_log_cleanup();
		g_source_remove(bluetooth_start_timeout);
		g_source_remove(signal);
		return EXIT_FAILURE;
	}

	/* Use params: mtu = 0, flags = 0 */
	start_sdp_server(0, 0);

	ipc_register(HAL_SERVICE_ID_CORE, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	DBG("Entering main loop");

	event_loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(event_loop);

	g_source_remove(signal);

	if (bluetooth_start_timeout > 0)
		g_source_remove(bluetooth_start_timeout);

	cleanup_services();

	ipc_cleanup();
	stop_sdp_server();
	bt_bluetooth_cleanup();
	g_main_loop_unref(event_loop);

	ipc_unregister(HAL_SERVICE_ID_CORE);

	info("Exit");

	__btd_log_cleanup();

	return EXIT_SUCCESS;
}
