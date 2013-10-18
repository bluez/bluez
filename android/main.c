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

#include <glib.h>

#include "log.h"
#include "src/sdpd.h"

#include "lib/bluetooth.h"
#include "lib/mgmt.h"
#include "src/shared/mgmt.h"

#include "adapter.h"

#define SHUTDOWN_GRACE_SECONDS 10

static GMainLoop *event_loop;
static struct mgmt *mgmt_if = NULL;

static uint8_t mgmt_version = 0;
static uint8_t mgmt_revision = 0;

static uint16_t adapter_index = MGMT_INDEX_NONE;

static gboolean quit_eventloop(gpointer user_data)
{
	g_main_loop_quit(event_loop);

	return FALSE;
}

static void sig_term(int sig)
{
	static bool __terminated = false;

	if (!__terminated) {
		g_timeout_add_seconds(SHUTDOWN_GRACE_SECONDS,
						quit_eventloop, NULL);
	}

	__terminated = true;
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

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *err = NULL;
	struct sigaction sa;

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

	__btd_log_init("*", 0);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (!init_mgmt_interface())
		return EXIT_FAILURE;

	/* Use params: mtu = 0, flags = 0 */
	start_sdp_server(0, 0);

	DBG("Entering main loop");

	g_main_loop_run(event_loop);

	stop_sdp_server();
	cleanup_mgmt_interface();
	g_main_loop_unref(event_loop);

	info("Exit");

	return EXIT_SUCCESS;
}
