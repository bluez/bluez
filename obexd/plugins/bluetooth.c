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

#include <errno.h>
#include <string.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include <glib.h>
#include <gdbus.h>

#include "plugin.h"
#include "server.h"
#include "obex.h"
#include "transport.h"
#include "service.h"
#include "log.h"
#include "btio.h"

#define BT_RX_MTU 32767
#define BT_TX_MTU 32767

#define TIMEOUT 60*1000 /* Timeout for user response (miliseconds) */

struct pending_request {
	DBusPendingCall *call;
	struct bluetooth_service *service;
	char *adapter_path;
	char address[18];
	unsigned int watch;
	GIOChannel *io;
};

struct bluetooth_service {
	struct obex_server *server;
	struct obex_service_driver *driver;
	uint32_t handle;
};

struct adapter_any {
	char *path;		/* Adapter ANY path */
	GSList *services;	/* List of services to register records */
};

static DBusConnection *connection = NULL;
static struct adapter_any *any = NULL;

static void add_record_reply(DBusPendingCall *call, void *user_data)
{
	struct bluetooth_service *service = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;
	uint32_t handle;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("bluetooth: Replied with an error: %s, %s",
				derr.name, derr.message);
		dbus_error_free(&derr);
		handle = 0;
	} else {
		dbus_message_get_args(reply, NULL,
				DBUS_TYPE_UINT32, &handle,
				DBUS_TYPE_INVALID);

		service->handle = handle;

		DBG("Registered: %s, handle: 0x%x",
				service->driver->name, service->handle);
	}

	dbus_message_unref(reply);
}

static int add_record(const char *path, const char *xml,
			struct bluetooth_service *service)
{
	DBusMessage *msg;
	DBusPendingCall *call;
	int ret = 0;

	msg = dbus_message_new_method_call("org.bluez", path,
					"org.bluez.Service", "AddRecord");

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &xml,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection,
				msg, &call, -1) == FALSE) {
		ret = -1;
		goto failed;
	}

	dbus_pending_call_set_notify(call, add_record_reply, service, NULL);
	dbus_pending_call_unref(call);

failed:
	dbus_message_unref(msg);
	return ret;
}

static struct bluetooth_service *find_service(
					struct obex_service_driver *driver)
{
	GSList *l;

	for (l = any->services; l; l = l->next) {
		struct bluetooth_service *service = l->data;

		if (service->driver == driver)
			return service;
	}

	return NULL;
}

static void register_record(struct obex_server *server)
{
	const GSList *l;

	if (connection == NULL)
		return;

	for (l = server->drivers; l; l = l->next) {
		struct obex_service_driver *driver = l->data;
		struct bluetooth_service *service;
		char *xml;

		service = find_service(driver);
		if (service == NULL) {
			service = g_new0(struct bluetooth_service, 1);
			service->driver = driver;
			service->server = server;
			any->services = g_slist_append(any->services, service);
		}

		/* Service already has a record registered */
		if (service->handle != 0)
			continue;

		/* Adapter ANY is not available yet: Add record later */
		if (any->path == NULL)
			continue;

		xml = g_markup_printf_escaped(driver->record, driver->channel,
						driver->name);
		add_record(any->path, xml, service);
		g_free(xml);
	}
}

static void find_adapter_any_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	const char *path;
	GSList *l;
	DBusError derr;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("bluetooth: Replied with an error: %s, %s",
				derr.name, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	dbus_message_get_args(reply, NULL,
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);
	any->path = g_strdup(path);

	for (l = any->services; l; l = l->next) {
		struct bluetooth_service *service = l->data;
		char *xml;

		xml = g_markup_printf_escaped(service->driver->record,
						service->driver->channel,
						service->driver->name);
		add_record(any->path, xml, service);
		g_free(xml);
	}

done:
	dbus_message_unref(reply);
}

static DBusPendingCall *find_adapter(const char *pattern,
				DBusPendingCallNotifyFunction function,
				void *user_data)
{
	DBusMessage *msg;
	DBusPendingCall *call;

	DBG("FindAdapter(%s)", pattern);

	msg = dbus_message_new_method_call("org.bluez", "/",
					"org.bluez.Manager", "FindAdapter");
	if (!msg)
		return NULL;

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &pattern,
			DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(connection, msg, &call, -1)) {
		dbus_message_unref(msg);
		return NULL;
	}

	dbus_pending_call_set_notify(call, function, user_data, NULL);

	dbus_message_unref(msg);

	return call;
}

static void name_acquired(DBusConnection *conn, void *user_data)
{
	DBusPendingCall *call;

	call = find_adapter("any", find_adapter_any_reply, NULL);
	if (call)
		dbus_pending_call_unref(call);
}

static void name_released(DBusConnection *conn, void *user_data)
{
	GSList *l;

	/* reset handles so the services got register next time */
	for (l = any->services; l; l = l->next) {
		struct bluetooth_service *service = l->data;

		service->handle = 0;
	}

	g_free(any->path);
	any->path = NULL;

}

static void service_cancel(struct pending_request *pending)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call("org.bluez",
					pending->adapter_path,
					"org.bluez.Service",
					"CancelAuthorization");

	g_dbus_send_message(connection, msg);
}

static void pending_request_free(struct pending_request *pending)
{
	if (pending->call)
		dbus_pending_call_unref(pending->call);
	g_io_channel_unref(pending->io);
	g_free(pending->adapter_path);
	g_free(pending);
}

static void connect_event(GIOChannel *io, GError *err, void *user_data)
{
	struct bluetooth_service *service = user_data;
	struct obex_server *server = service->server;

	if (err)
		goto drop;

	if (obex_server_new_connection(server, io, BT_TX_MTU, BT_RX_MTU) < 0)
		g_io_channel_shutdown(io, TRUE, NULL);

	return;

drop:
	error("%s", err->message);
	g_io_channel_shutdown(io, TRUE, NULL);
	return;
}

static void service_reply(DBusPendingCall *call, void *user_data)
{
	struct pending_request *pending = user_data;
	GIOChannel *io = pending->io;
	struct bluetooth_service *service = pending->service;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;
	GError *err = NULL;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("bluetooth: RequestAuthorization error: %s, %s",
				derr.name, derr.message);

		if (dbus_error_has_name(&derr, DBUS_ERROR_NO_REPLY))
			service_cancel(pending);

		dbus_error_free(&derr);
		g_io_channel_shutdown(io, TRUE, NULL);
		goto done;
	}

	DBG("RequestAuthorization succeeded");

	if (!bt_io_accept(io, connect_event, service, NULL, &err)) {
		error("%s", err->message);
		g_error_free(err);
		g_io_channel_shutdown(io, TRUE, NULL);
	}

done:
	g_source_remove(pending->watch);
	pending_request_free(pending);
	dbus_message_unref(reply);
}

static gboolean service_error(GIOChannel *io, GIOCondition cond,
			void *user_data)
{
	struct pending_request *pending = user_data;

	service_cancel(pending);

	dbus_pending_call_cancel(pending->call);

	pending_request_free(pending);

	return FALSE;
}

static void find_adapter_reply(DBusPendingCall *call, void *user_data)
{
	struct pending_request *pending = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessage *msg;
	DBusPendingCall *pcall;
	const char *path, *paddr = pending->address;
	DBusError derr;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("Replied with an error: %s, %s",
				derr.name, derr.message);
		dbus_error_free(&derr);
		goto failed;
	}

	dbus_message_get_args(reply, NULL,
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);

	DBG("FindAdapter -> %s", path);
	pending->adapter_path = g_strdup(path);
	dbus_message_unref(reply);

	msg = dbus_message_new_method_call("org.bluez", path,
			"org.bluez.Service", "RequestAuthorization");

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &paddr,
			DBUS_TYPE_UINT32, &pending->service->handle,
			DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(connection,
					msg, &pcall, TIMEOUT)) {
		dbus_message_unref(msg);
		goto failed;
	}

	dbus_message_unref(msg);

	DBG("RequestAuthorization(%s, %x)", paddr,
			pending->service->handle);

	if (!dbus_pending_call_set_notify(pcall, service_reply, pending,
								NULL)) {
		dbus_pending_call_unref(pcall);
		goto failed;
	}

	dbus_pending_call_unref(pending->call);
	pending->call = pcall;

	/* Catches errors before authorization response comes */
	pending->watch = g_io_add_watch(pending->io,
					G_IO_HUP | G_IO_ERR | G_IO_NVAL,
					service_error, pending);

	return;

failed:
	g_io_channel_shutdown(pending->io, TRUE, NULL);
	pending_request_free(pending);
}

static int request_service_authorization(struct bluetooth_service *service,
					GIOChannel *io, const char *address)
{
	struct pending_request *pending;
	char source[18];
	GError *err = NULL;

	if (connection == NULL || any->path == NULL)
		return -1;

	bt_io_get(io, BT_IO_RFCOMM, &err,
			BT_IO_OPT_SOURCE, source,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		return -EINVAL;
	}

	pending = g_new0(struct pending_request, 1);
	pending->call = find_adapter(source, find_adapter_reply, pending);
	if (!pending->call) {
		g_free(pending);
		return -ENOMEM;
	}

	pending->service = service;
	pending->io = g_io_channel_ref(io);
	memcpy(pending->address, address, sizeof(pending->address));

	return 0;
}

static void confirm_event(GIOChannel *io, void *user_data)
{
	struct bluetooth_service *service;
	GError *err = NULL;
	char address[18];
	uint8_t channel;
	struct obex_service_driver *driver = user_data;

	bt_io_get(io, BT_IO_RFCOMM, &err,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_CHANNEL, &channel,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	info("bluetooth: New connection from: %s, channel %u", address,
			channel);

	service = find_service(driver);
	if (service == NULL) {
		error("bluetooth: Unable to find service");
		goto drop;
	}

	if (driver->service != OBEX_OPP) {
		if (request_service_authorization(service, io, address) < 0)
			goto drop;

		return;
	}

	if (!bt_io_accept(io, connect_event, service, NULL, &err)) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	return;

drop:
	g_io_channel_shutdown(io, TRUE, NULL);
}

static GIOChannel *start(struct obex_server *server,
				struct obex_service_driver *service,
				BtIOSecLevel sec_level)
{
	GIOChannel *io;
	GError *err = NULL;

	io = bt_io_listen(BT_IO_RFCOMM, NULL, confirm_event,
				service, NULL, &err,
				BT_IO_OPT_CHANNEL, service->channel,
				BT_IO_OPT_SEC_LEVEL, sec_level,
				BT_IO_OPT_INVALID);
	if (io == NULL) {
		error("bluetooth: unable to listen in channel %d: %s",
				service->channel, err->message);
		g_error_free(err);
	} else
		DBG("listening on channel %d", service->channel);

	return io;
}

static void *bluetooth_start(struct obex_server *server, int *err)
{
	BtIOSecLevel sec_level;
	GSList *ios = NULL;
	const GSList *l;

	if (server->secure == TRUE)
		sec_level = BT_IO_SEC_MEDIUM;
	else
		sec_level = BT_IO_SEC_LOW;

	for (l = server->drivers; l; l = l->next) {
		struct obex_service_driver *service = l->data;
		GIOChannel *io;

		io = start(server, service, sec_level);
		if (io == NULL)
			continue;

		ios = g_slist_prepend(ios, io);
	}

	register_record(server);

	return ios;
}

static void stop(gpointer data, gpointer user_data)
{
	GIOChannel *io = data;

	g_io_channel_shutdown(io, TRUE, NULL);
	g_io_channel_unref(io);
}

static void bluetooth_stop(void *data)
{
	GSList *ios = data;

	g_slist_foreach(ios, stop, NULL);
	g_slist_free(ios);
}

static struct obex_transport_driver driver = {
	.name = "bluetooth",
	.start = bluetooth_start,
	.stop = bluetooth_stop
};

static unsigned int listener_id = 0;

static int bluetooth_init(void)
{
	any = g_new0(struct adapter_any, 1);

	connection = g_dbus_setup_private(DBUS_BUS_SYSTEM, NULL, NULL);
	if (connection == NULL)
		return -EPERM;

	listener_id = g_dbus_add_service_watch(connection, "org.bluez",
				name_acquired, name_released, NULL, NULL);

	return obex_transport_driver_register(&driver);
}

static void bluetooth_exit(void)
{
	g_dbus_remove_watch(connection, listener_id);

	if (any) {
		g_slist_foreach(any->services, (GFunc) g_free, NULL);
		g_slist_free(any->services);
		g_free(any->path);
		g_free(any);
	}

	if (connection)
		dbus_connection_unref(connection);

	obex_transport_driver_unregister(&driver);
}

OBEX_PLUGIN_DEFINE(bluetooth, bluetooth_init, bluetooth_exit)
