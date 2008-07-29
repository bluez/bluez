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

#include <glib.h>

#include "server.h"

static GSList *servers = NULL;

int bt_register_server(struct bt_server *server)
{
	servers = g_slist_append(servers, server);

	return 0;
}

void bt_unregister_server(struct bt_server *server)
{
	servers = g_slist_remove(servers, server);
}

void __probe_servers(const char *adapter)
{
	GSList *list;

	for (list = servers; list; list = list->next) {
		struct bt_server *server = list->data;

		if (server->probe)
			server->probe(adapter);
	}
}

void __remove_servers(const char *adapter)
{
	GSList *list;

	for (list = servers; list; list = list->next) {
		struct bt_server *server = list->data;

		if (server->remove)
			server->remove(adapter);
	}
}
