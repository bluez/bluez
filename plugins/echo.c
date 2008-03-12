/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <errno.h>

#include "plugin.h"
#include "server.h"
#include "logging.h"

static int echo_probe(const char *adapter)
{
	debug("echo probe adapter %s", adapter);

	return 0;
}

static void echo_remove(const char *adapter)
{
	debug("echo remove adapter %s", adapter);
}

static struct bt_server echo_server = {
	.uuid	= "00001101-0000-1000-8000-00805F9B34FB",
	.probe	= echo_probe,
	.remove	= echo_remove,
};

static int echo_init(void)
{
	debug("Setup echo plugin");

	return bt_register_server(&echo_server);
}

static void echo_exit(void)
{
	debug("Cleanup echo plugin");

	bt_unregister_server(&echo_server);
}

BLUETOOTH_PLUGIN_DEFINE("echo", echo_init, echo_exit)
