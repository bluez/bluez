// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <ell/ell.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/mgmt.h"

#include "mesh/mesh.h"
#include "mesh/crypto.h"
#include "mesh/dbus.h"
#include "mesh/mesh-io.h"
#include "mesh/util.h"

static const char *storage_dir;
static const char *mesh_conf_fname;
static enum mesh_io_type io_type;
static void *io_opts;

static const struct option main_options[] = {
	{ "io",		required_argument,	NULL, 'i' },
	{ "storage",	required_argument,	NULL, 's' },
	{ "config",	required_argument,	NULL, 'c' },
	{ "nodetach",	no_argument,		NULL, 'n' },
	{ "debug",	no_argument,		NULL, 'd' },
	{ "dbus-debug",	no_argument,		NULL, 'b' },
	{ "help",	no_argument,		NULL, 'h' },
	{ }
};

static const char *io_usage =
	       "\t(auto | generic:[hci]<index> | unit:<fd_path>)\n"
	       "\t\tauto - Use first available controller (MGMT or raw HCI)\n"
	       "\t\tgeneric - Use raw HCI io on interface hci<index>\n"
	       "\t\tunit - Use test IO (for automatic testing only)\n";

static void usage(void)
{
	fprintf(stderr,
		"Usage:\n"
	       "\tbluetooth-meshd [options]\n");
	fprintf(stderr,
		"Options:\n"
	       "\t--io <io>         Use specified io (default: auto)\n"
	       "\t--config          Daemon configuration directory\n"
	       "\t--storage         Mesh node(s) configuration directory\n"
	       "\t--nodetach        Run in foreground\n"
	       "\t--debug           Enable debug output\n"
	       "\t--dbus-debug      Enable D-Bus debugging\n"
	       "\t--help            Show %s information\n", __func__);
	fprintf(stderr, "\n\t io: %s", io_usage);
}

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void mesh_ready_callback(void *user_data, bool success)
{
	struct l_dbus *dbus = user_data;

	l_info("mesh_ready_callback");
	if (!success) {
		l_error("Failed to start mesh");
		l_main_quit();
		return;
	}

	if (!dbus_init(dbus)) {
		l_error("Failed to initialize mesh D-Bus resources");
		l_main_quit();
	}
}

static void request_name_callback(struct l_dbus *dbus, bool success,
					bool queued, void *user_data)
{
	if (!success && io_type != MESH_IO_TYPE_UNIT_TEST) {
		l_info("Request name failed");
		l_main_quit();
		return;
	}

	if (!mesh_init(storage_dir, mesh_conf_fname, io_type, io_opts,
					mesh_ready_callback, dbus)) {
		l_error("Failed to initialize mesh");
		l_main_quit();
	}
}

static void ready_callback(void *user_data)
{
	struct l_dbus *dbus = user_data;

	l_info("D-Bus ready");
	l_dbus_name_acquire(dbus, BLUEZ_MESH_NAME, false, false, false,
						request_name_callback, NULL);
}

static void disconnect_callback(void *user_data)
{
	l_main_quit();
}

static void kill_to(struct l_timeout *timeout, void *user_data)
{
	l_timeout_remove(timeout);
	l_main_quit();
}

static void signal_handler(uint32_t signo, void *user_data)
{
	static bool terminated;

	if (terminated)
		return;

	l_info("Terminating");

	mesh_cleanup(true);

	if (io_type != MESH_IO_TYPE_UNIT_TEST)
		l_timeout_create(1, kill_to, NULL, NULL);
	else
		l_main_quit();

	terminated = true;
}

static bool parse_io(const char *optarg, enum mesh_io_type *type, void **opts)
{
	if (strstr(optarg, "auto") == optarg) {
		int *index = l_new(int, 1);

		*type = MESH_IO_TYPE_AUTO;
		*opts = index;

		optarg += strlen("auto");
		*index = MGMT_INDEX_NONE;
		return true;

		return false;
	} else if (strstr(optarg, "generic") == optarg) {
		int *index = l_new(int, 1);

		*type = MESH_IO_TYPE_GENERIC;
		*opts = index;

		optarg += strlen("generic");
		if (!*optarg || *optarg != ':')
			return false;

		optarg++;

		if (sscanf(optarg, "hci%d", index) == 1)
			return true;

		if (sscanf(optarg, "%d", index) == 1)
			return true;

		return false;

	} else if (strstr(optarg, "unit") == optarg) {
		char *test_path;

		*type = MESH_IO_TYPE_UNIT_TEST;

		optarg += strlen("unit");
		if (*optarg != ':')
			return false;

		optarg++;
		test_path = strdup(optarg);

		*opts = test_path;
		return true;
	}

	return false;
}

int main(int argc, char *argv[])
{
	int status;
	bool detached = true;
	bool dbus_debug = false;
	struct l_dbus *dbus = NULL;
	char *io = NULL;
	int hci_index;

	if (!l_main_init())
		return -1;

	l_log_set_stderr();

	if (!mesh_crypto_check_avail()) {
		l_error("Mesh Crypto functions unavailable");
		status = l_main_run_with_signal(signal_handler, NULL);
		goto done;
	}

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "u:i:s:c:ndbh", main_options,
									NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'u':
			if (sscanf(optarg, "%d", &hci_index) == 1 ||
					sscanf(optarg, "%d", &hci_index) == 1)
				io = l_strdup_printf("unit:%d", hci_index);
			else
				io = l_strdup(optarg);
			break;
		case 'i':
			if (sscanf(optarg, "hci%d", &hci_index) == 1 ||
					sscanf(optarg, "%d", &hci_index) == 1)
				io = l_strdup_printf("generic:%s", optarg);
			else
				io = l_strdup(optarg);
			break;
		case 'n':
			detached = false;
			break;
		case 'd':
			enable_debug();
			break;
		case 's':
			storage_dir = optarg;
			break;
		case 'c':
			mesh_conf_fname = optarg;
			break;
		case 'b':
			dbus_debug = true;
			break;
		case 'h':
			usage();
			status = EXIT_SUCCESS;
			goto done;
		default:
			usage();
			status = EXIT_FAILURE;
			goto done;
		}
	}

	if (!io)
		io = l_strdup_printf("auto");

	if (!parse_io(io, &io_type, &io_opts)) {
		l_error("Invalid io: %s\n%s", io, io_usage);
		status = EXIT_FAILURE;
		goto done;
	}

	l_free(io);
	io = NULL;

	if (!detached)
		umask(0077);

	if (io_type != MESH_IO_TYPE_UNIT_TEST)
		dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	else {
		dbus = l_dbus_new_default(L_DBUS_SESSION_BUS);
		prctl(PR_SET_PDEATHSIG, SIGSEGV);
	}

	if (!dbus) {
		l_error("unable to connect to D-Bus");
		status = EXIT_FAILURE;
		goto done;
	}

	if (dbus_debug)
		l_dbus_set_debug(dbus, do_debug, "[DBUS] ", NULL);
	l_dbus_set_ready_handler(dbus, ready_callback, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	if (!l_dbus_object_manager_enable(dbus, "/")) {
		l_error("Failed to enable Object Manager");
		status = EXIT_FAILURE;
		goto done;
	}

	status = l_main_run_with_signal(signal_handler, NULL);

done:
	l_free(io);
	l_free(io_opts);

	mesh_cleanup(false);
	l_dbus_destroy(dbus);
	l_main_exit();

	return status;
}
