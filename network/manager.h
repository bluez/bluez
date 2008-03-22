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

#include "connection.h"
#include "server.h"

#define MAX_PATH_LENGTH 64 /* D-Bus path */
#define NETWORK_PATH "/org/bluez/network"

struct network_conf {
	gboolean connection_enabled;
	gboolean server_enabled;
	gboolean security;
	char *iface_prefix;
	char *panu_script;
	char *gn_script;
	char *nap_script;
	char *gn_iface;
	char *nap_iface;
};

int network_manager_init(DBusConnection *conn, struct network_conf *service_conf);
void network_manager_exit(void);
