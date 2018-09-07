/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

#include <ctype.h>
#include <stdio.h>
#include <unistd.h>

#include <ell/ell.h>

#include "src/shared/shell.h"
#include "src/shared/mainloop.h"

#include "mesh/mesh.h"
#include "mesh/net.h"

#define PROMPT COLOR_BLUE "[btmesh]" COLOR_OFF "# "

static struct bt_mesh *mesh;

static const struct option main_options[] = {
	{ "index",	1,	0, 'i' },
	{ "config",	1,	0, 'c' },
	{ "save",	1,	0, 's' },
	{ 0, 0, 0, 0 }
};

static const char *index_option;
static const char *config_option;
static const char *save_option;

static const char **optargs[] = {
	&index_option,
	&config_option,
	&save_option,
};

static const char *help[] = {
	"Specify adapter index",
	"Specify input configuration file",
	"Specify output configuration file"
};

static const struct bt_shell_opt opt = {
	.options = main_options,
	.optno = sizeof(main_options) / sizeof(struct option),
	.optstr = "i:c:s:",
	.optarg = optargs,
	.help = help,
};

static int get_arg_on_off(int argc, char *argv[])
{
	if (!strcmp(argv[1], "on") || !strcmp(argv[1], "yes"))
		return 1;

	if (!strcmp(argv[1], "off") || !strcmp(argv[1], "no"))
		return 0;

	bt_shell_printf("Invalid argument %s\n", argv[1]);
	return -1;
}

static void cmd_beacon(int argc, char *argv[])
{
	bool res;
	int enable;

	enable = get_arg_on_off(argc, argv);
	if (enable < 0)
		return;

	res = mesh_net_set_beacon_mode(mesh_get_net(mesh), enable);
	if (res)
		bt_shell_printf("Local beacon mode is %s\n",
				enable > 0 ? "enabled" : "disabled");
	else
		bt_shell_printf("Failed to set local beacon mode to %s\n",
				enable > 0 ? "enabled" : "disabled");
}

static const struct bt_shell_menu main_menu = {
	.name = "main",
	.entries = {
	{ "beacon",   "<enable>",  cmd_beacon, "Enable/disable beaconing"},
	{ } },
};

static int get_index(const char *arg)
{
	if (strlen(arg) > 3 && !strncasecmp(arg, "hci", 3))
		return atoi(&arg[3]);
	else
		return atoi(arg);
}

static void ell_event(int fd, uint32_t events, void *user_data)
{
	int timeout = l_main_prepare();

	l_main_iterate(timeout);
}

int main(int argc, char *argv[])
{
	int index;
	int fd;
	int status;

	l_log_set_stderr();
	l_debug_enable("*");

	if (!l_main_init())
		return -1;

	bt_shell_init(argc, argv, &opt);
	bt_shell_set_menu(&main_menu);

	if (!index_option) {
		l_info("Controller index is required");
		goto fail;
	}

	if (config_option)
		l_info("Reading local configuration from %s\n", config_option);

	if (save_option)
		l_info("Saving local configuration to %s\n", save_option);

	bt_shell_set_prompt(PROMPT);

	index = get_index(index_option);

	l_info("Starting mesh on hci%d\n", index);

	mesh = mesh_new(index, config_option);
	if (!mesh) {
		l_info("Failed to create mesh\n");
		goto fail;
	}

	if (save_option)
		mesh_set_output(mesh, save_option);

	fd = l_main_get_epoll_fd();
	mainloop_add_fd(fd, EPOLLIN, ell_event, NULL, NULL);

	status = bt_shell_attach(fileno(stdin));
	bt_shell_run();

	mesh_unref(mesh);
	mesh_cleanup();
	l_main_exit();
	return status;

fail:
	bt_shell_cleanup();
	return EXIT_FAILURE;
}
