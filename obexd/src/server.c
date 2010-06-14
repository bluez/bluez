/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Nokia Corporation
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <glib.h>

#include <openobex/obex.h>

#include "log.h"
#include "obex.h"
#include "obex-priv.h"
#include "server.h"
#include "dbus.h"
#include "service.h"
#include "transport.h"

static GSList *servers = NULL;

static void obex_server_free(struct obex_server *server)
{
	g_free(server->folder);
	g_free(server->capability);
	g_free(server);
}

int obex_server_init(uint16_t service, const char *folder,
				gboolean secure, gboolean auto_accept,
				gboolean symlinks, const char *capability)
{
	GSList *drivers;
	GSList *transports;
	GSList *l;

	drivers = obex_service_driver_list(service);
	if (drivers == NULL) {
		debug("No service driver registered");
		return -EINVAL;
	}

	transports = obex_transport_driver_list();
	if (transports == NULL) {
		debug("No transport driver registered");
		return -EINVAL;
	}

	for (l = transports; l; l = l->next) {
		struct obex_transport_driver *transport = l->data;
		struct obex_server *server;
		int err;

		if (transport->service != 0 &&
				(transport->service & service) == FALSE)
			continue;

		server = g_new0(struct obex_server, 1);
		server->transport = transport;
		server->drivers = drivers;
		server->folder = g_strdup(folder);
		server->auto_accept = auto_accept;
		server->symlinks = symlinks;
		server->capability = g_strdup(capability);
		server->secure = secure;

		server->transport_data = transport->start(server, &err);
		if (server->transport_data == NULL) {
			debug("Unable to start %s transport: %s (%d)",
					transport->name, strerror(err), err);
			obex_server_free(server);
			continue;
		}

		servers = g_slist_prepend(servers, server);
	}

	return 0;
}

void obex_server_exit(void)
{
	GSList *l;

	for (l = servers; l; l = l->next) {
		struct obex_server *server = l->data;

		server->transport->stop(server->transport_data);
		obex_server_free(server);
	}

	g_slist_free(servers);

	return;
}

struct obex_service_driver *obex_server_find_driver(
						struct obex_server *server,
						uint8_t channel)
{
	GSList *l;

	for (l = server->drivers; l; l = l->next) {
		struct obex_service_driver *driver = l->data;

		if (driver->channel == channel)
			return driver;
	}

	return NULL;
}

int obex_server_new_connection(struct obex_server *server, GIOChannel *io,
				uint16_t tx_mtu, uint16_t rx_mtu)
{
	return obex_session_start(io, tx_mtu, rx_mtu, server);
}
