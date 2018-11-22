/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017-2018  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>

#include <sys/stat.h>
#include <ell/ell.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "mesh/mesh.h"
#include "mesh/net.h"
#include "mesh/storage.h"

static const struct option main_options[] = {
	{ "index",	required_argument,	NULL, 'i' },
	{ "config",	optional_argument,	NULL, 'c' },
	{ "nodetach",	no_argument,		NULL, 'n' },
	{ "debug",	no_argument,		NULL, 'd' },
	{ "help",	no_argument,		NULL, 'h' },
	{ }
};

static void usage(void)
{
	l_info("");
	l_info("Usage:\n"
	       "\tmeshd [options]\n");
	l_info("Options:\n"
	       "\t--index <hcinum>  Use specified controller\n"
	       "\t--config          Configuration file\n"
	       "\t--nodetach        Run in foreground\n"
	       "\t--debug           Enable debug output\n"
	       "\t--help            Show %s information\n", __func__);
}

static void signal_handler(uint32_t signo, void *user_data)
{
	static bool terminated;

	if (terminated)
		return;

	l_info("Terminating");
	l_main_quit();
	terminated = true;
}

int main(int argc, char *argv[])
{
	int status;
	bool detached = true;
	struct bt_mesh *mesh = NULL;
	const char *config_file = NULL;
	int index = MGMT_INDEX_NONE;

	if (!l_main_init())
		return -1;

	l_log_set_stderr();

	for (;;) {
		int opt;
		const char *str;

		opt = getopt_long(argc, argv, "i:c:ndh", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'i':
			if (strlen(optarg) > 3 && !strncmp(optarg, "hci", 3))
				str = optarg + 3;
			else
				str = optarg;
			if (!isdigit(*str)) {
				l_error("Invalid controller index value");
				status = EXIT_FAILURE;
				goto done;
			}

			index = atoi(str);

			break;
		case 'n':
			detached = false;
			break;
		case 'd':
			l_debug_enable("*");
			break;
		case 'c':
			config_file = optarg;
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

	if (!mesh_new(index, config_file)) {
		l_error("Failed to initialize mesh");
		status = EXIT_FAILURE;
		goto done;
	}

	umask(0077);

	if (detached) {
		if (daemon(0, 0)) {
			perror("Failed to start meshd daemon");
			status = EXIT_FAILURE;
			goto done;
		}
	}

	status = l_main_run_with_signal(signal_handler, NULL);

done:
	mesh_unref(mesh);
	mesh_cleanup();
	l_main_exit();

	return status;
}
