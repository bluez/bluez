/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2015 Intel Corporation
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
#include <stdlib.h>
#include <getopt.h>

#include <glib.h>

#include "src/log.h"

static GMainLoop *mloop;

static void usage(void)
{
	printf("bneptest - BNEP testing ver %s\n", VERSION);
	printf("Usage:\n"
		"\tbneptest [options]\n");
}

static struct option main_options[] = {
	{ "help",		0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	int opt;

	DBG("");

	mloop = g_main_loop_new(NULL, FALSE);
	if (!mloop) {
		printf("cannot create main loop\n");

		exit(1);
	}

	while ((opt = getopt_long(argc, argv, "h", main_options, NULL))
								!= EOF) {
		switch (opt) {
		case 'h':
		default:
			usage();
			exit(0);
		}
	}

	return 0;
}
