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

#include "mainloop.h"
#include "server.h"
#include "vhci.h"

static void signal_callback(int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		mainloop_quit();
		break;
	}
}

int main(int argc, char *argv[])
{
	struct vhci *vhci;
	struct server *server;
	sigset_t mask;

	mainloop_init();

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	mainloop_set_signal(&mask, signal_callback, NULL, NULL);

	vhci = vhci_open(VHCI_TYPE_BREDR, 0x23);
	if (!vhci) {
		fprintf(stderr, "Failed to open Virtual HCI device\n");
		return 1;
	}

	server = server_open_unix("/tmp/bt-server-bredr", 0x42);
	if (!server) {
		fprintf(stderr, "Failed to open server channel\n");
		vhci_close(vhci);
		return 1;
	}

	return mainloop_run();
}
