/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include "mainloop.h"
#include "packet.h"
#include "control.h"
#include "hcidump.h"
#include "btsnoop.h"

static void signal_callback(int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		mainloop_quit();
		break;
	}
}

static const struct option main_options[] = {
	{ "btsnoop",	required_argument, NULL, 'b'	},
	{ }
};

int main(int argc, char *argv[])
{
	unsigned long filter_mask = 0;
	sigset_t mask;

	mainloop_init();

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "b", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'b':
			btsnoop_open(optarg);
			break;
		default:
			return EXIT_FAILURE;
		}
	}


	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	mainloop_set_signal(&mask, signal_callback, NULL, NULL);

	filter_mask |= PACKET_FILTER_SHOW_INDEX;
	filter_mask |= PACKET_FILTER_SHOW_TIME;
	filter_mask |= PACKET_FILTER_SHOW_ACL_DATA;

	packet_set_filter(filter_mask);

	printf("Bluetooth monitor ver %s\n", VERSION);

	if (control_tracing() < 0) {
		if (hcidump_tracing() < 0)
			return EXIT_FAILURE;
	}

	return mainloop_run();
}
