/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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
#include <readline/readline.h>
#include <gdbus.h>

#include "display.h"
#include "agent.h"

#define AGENT_PATH "/org/bluez/agent"
#define AGENT_INTERFACE "org.bluez.Agent1"

static gboolean agent_registered = FALSE;

static DBusMessage *release_agent(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	agent_registered = FALSE;

	g_dbus_unregister_interface(conn, AGENT_PATH, AGENT_INTERFACE);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable methods[] = {
	{ GDBUS_METHOD("Release", NULL, NULL, release_agent) },
	{ }
};

void agent_register(DBusConnection *conn, GDBusProxy *manager)
{
	if (agent_registered == TRUE) {
		printf("Agent is already registered\n");
		return;
	}

	if (g_dbus_register_interface(conn, AGENT_PATH,
					AGENT_INTERFACE, methods,
					NULL, NULL, NULL, NULL) == FALSE) {
		printf("Failed to register agent object\n");
		return;
	}

	agent_registered = TRUE;
}

void agent_unregister(DBusConnection *conn, GDBusProxy *manager)
{
	if (agent_registered == FALSE) {
		printf("No agent is registered\n");
		return;
	}

	if (g_dbus_unregister_interface(conn, AGENT_PATH,
						AGENT_INTERFACE) == FALSE) {
		printf("Failed to unregister agent object\n");
		return;
	}

	agent_registered = FALSE;
}
