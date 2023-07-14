// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>

#include "src/shared/shell.h"
#include "client/mgmt.h"

static const char *index_option;

static struct option main_options[] = {
	{ "index",	1, 0, 'i' },
	{ 0, 0, 0, 0 }
};

static const char **optargs[] = {
	&index_option
};

static const char *help[] = {
	"Specify adapter index\n"
};

static const struct bt_shell_opt opt = {
	.options = main_options,
	.optno = sizeof(main_options) / sizeof(struct option),
	.optstr = "i:V",
	.optarg = optargs,
	.help = help,
};

int main(int argc, char *argv[])
{
	int status;

	bt_shell_init(argc, argv, &opt);

	if (!mgmt_add_submenu()) {
		fprintf(stderr, "Unable to open mgmt_socket\n");
		return EXIT_FAILURE;
	}

	bt_shell_attach(fileno(stdin));
	mgmt_set_index(index_option);
	status = bt_shell_run();

	mgmt_remove_submenu();

	return status;
}
