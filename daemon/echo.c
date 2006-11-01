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
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#include <dbus/dbus-glib.h>

#define AGENT_PATH "/org/bluez/echo"

static DBusGConnection *conn;

typedef struct {
	GObject parent;
	GIOChannel *server;
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
	obj->server = NULL;
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

static gboolean session_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	unsigned char buf[672];
	gsize len;
	GIOError err;
	int sk, ret;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len);
	if (err == G_IO_ERROR_AGAIN)
		return TRUE;

	sk = g_io_channel_unix_get_fd(chan);

	ret = write(sk, buf, len);

	return TRUE;
}

static gboolean connect_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	GIOChannel *io;
        struct sockaddr_rc addr;
        socklen_t optlen;
	int sk, nsk;

	sk = g_io_channel_unix_get_fd(chan);

	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);

	nsk = accept(sk, (struct sockaddr *) &addr, &optlen);
	if (nsk < 0)
		return TRUE;

	io = g_io_channel_unix_new(nsk);
	g_io_channel_set_close_on_unref(io, TRUE);

	g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR,
						session_event, NULL);

	return TRUE;
}

static gboolean service_agent_start(ServiceAgent *agent,
					DBusGMethodInvocation *context)
{
	struct sockaddr_rc addr;
	int sk;

	if (agent->server)
		return FALSE;

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0)
		return FALSE;

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, BDADDR_ANY);
	addr.rc_channel = 23;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return FALSE;
	}

	if (listen(sk, 10)) {
		close(sk);
		return FALSE;
	}

	agent->server = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(agent->server, TRUE);

	g_io_add_watch(agent->server, G_IO_IN, connect_event, NULL);

	dbus_g_method_return(context, NULL);

	return TRUE;
}

static gboolean service_agent_stop(ServiceAgent *agent,
					DBusGMethodInvocation *context)
{
	if (agent->server) {
		g_io_channel_close(agent->server);
		g_io_channel_unref(agent->server);
		agent->server = NULL;
	}

	dbus_g_method_return(context, NULL);

	return TRUE;
}

static gboolean service_agent_release(ServiceAgent *agent, GError **error)
{
	if (agent->server) {
		g_io_channel_close(agent->server);
		g_io_channel_unref(agent->server);
		agent->server = NULL;
	}

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

	dbus_g_object_type_install_info(SERVICE_AGENT_OBJECT_TYPE,
					&dbus_glib_service_agent_object_info);

	register_service_agent();

	g_main_loop_run(mainloop);

	dbus_g_connection_unref(conn);

	return 0;
}
