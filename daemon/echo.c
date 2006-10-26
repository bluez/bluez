/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2005-2006  Marcel Holtmann <marcel@holtmann.org>
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

#include <dbus/dbus-glib.h>

#define AGENT_PATH "/org/bluez/echo"

static DBusGConnection *conn;

typedef struct {
	GObject parent;
} ServiceAgent;

typedef struct {
	GObjectClass parent;
} ServiceAgentClass;

static GObjectClass *parent_class;

G_DEFINE_TYPE(ServiceAgent, service_agent, G_TYPE_OBJECT)

#define SERVICE_AGENT_OBJECT_TYPE (service_agent_get_type())

#define SERVICE_AGENT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			SERVICE_AGENT_OBJECT_TYPE, ServiceAgent))

static void service_agent_finalize(GObject *obj)
{
	parent_class->finalize(obj);
}

static void service_agent_init(ServiceAgent *obj)
{
}

static void service_agent_class_init(ServiceAgentClass *klass)
{
	GObjectClass *gobject_class;

	parent_class = g_type_class_peek_parent(klass);

	gobject_class = G_OBJECT_CLASS(klass);
	gobject_class->finalize = service_agent_finalize;
}

static ServiceAgent *service_agent_new(const char *path)
{
	ServiceAgent *agent;

	agent = g_object_new(SERVICE_AGENT_OBJECT_TYPE, NULL);

	dbus_g_connection_register_g_object(conn, path, G_OBJECT(agent));

	return agent;
}

static gboolean service_agent_interfaces(ServiceAgent *agent, GError **error)
{
	return FALSE;
}

static gboolean service_agent_start(ServiceAgent *agent,
					DBusGMethodInvocation *context)
{
	dbus_g_method_return(context, NULL);

	return TRUE;
}

static gboolean service_agent_stop(ServiceAgent *agent,
					DBusGMethodInvocation *context)
{
	dbus_g_method_return(context, NULL);

	return TRUE;
}

static gboolean service_agent_record(ServiceAgent *agent, GError **error)
{
	return FALSE;
}

static gboolean service_agent_release(ServiceAgent *agent, GError **error)
{
	return TRUE;
}

#include "service-agent-glue.h"

static int register_service_agent(void)
{
	DBusGProxy *object;
	GError *error = NULL;
	const char *name = "Echo service";
	const char *desc = "Simple serial port profile based echo service";
	void *agent;

	agent = service_agent_new(AGENT_PATH);
	if (!agent)
		return -1;

	object = dbus_g_proxy_new_for_name(conn, "org.bluez",
					"/org/bluez", "org.bluez.Manager");

	dbus_g_proxy_call(object, "RegisterService", &error,
				G_TYPE_STRING, AGENT_PATH,
				G_TYPE_STRING, name,
				G_TYPE_STRING, desc,
				G_TYPE_INVALID, G_TYPE_INVALID);

	if (error != NULL) {
		g_error_free(error);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	GMainLoop *mainloop;
	GError *error = NULL;

	g_type_init();

	mainloop = g_main_loop_new(NULL, FALSE);

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error != NULL) {
		g_printerr("Connecting to system bus failed: %s\n",
							error->message);
		g_error_free(error);
		exit(EXIT_FAILURE);
	}

	register_service_agent();

	g_main_loop_run(mainloop);

	dbus_g_connection_unref(conn);

	return 0;
}
