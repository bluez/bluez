/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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
	char *iface_prefix;
	struct connection_conf conn;
	struct server_conf server;
};

int network_init(DBusConnection *conn);
void network_exit(void);

int network_del_stored_info(bdaddr_t *src, uint16_t uuid);
int network_store_info(bdaddr_t *src, uint16_t uuid, gboolean enable);
