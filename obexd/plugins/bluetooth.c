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
#include <unistd.h>
#include <inttypes.h>
#include <sys/socket.h>

#include <glib.h>
#include <gdbus.h>

#include "obexd.h"
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

		if (driver->port != 0)
			xml = g_markup_printf_escaped(driver->record,
							driver->channel,
							driver->name,
							driver->port);
		else
			xml = g_markup_printf_escaped(driver->record,
							driver->channel,
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
		struct obex_service_driver *driver = service->driver;
		char *xml;

		if (driver->port != 0)
			xml = g_markup_printf_escaped(driver->record,
							driver->channel,
							driver->name,
							driver->port);
		else
			xml = g_markup_printf_escaped(driver->record,
							driver->channel,
							driver->name);

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
	int sk = g_io_channel_unix_get_fd(io);
	struct bluetooth_service *service = user_data;
	struct obex_server *server = service->server;
	int type;
	int omtu = BT_TX_MTU;
	int imtu = BT_RX_MTU;
	gboolean stream = TRUE;
	socklen_t len = sizeof(int);

	if (err)
		goto drop;

	if (getsockopt(sk, SOL_SOCKET, SO_TYPE, &type, &len) < 0)
		goto done;

	if (type != SOCK_SEQPACKET)
		goto done;

	stream = FALSE;

	/* Read MTU if io is an L2CAP socket */
	bt_io_get(io, BT_IO_L2CAP, NULL, BT_IO_OPT_OMTU, &omtu,
						BT_IO_OPT_IMTU, &imtu,
						BT_IO_OPT_INVALID);

done:
	if (obex_server_new_connection(server, io, omtu, imtu, stream) < 0)
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
							GIOChannel *io,
							const char *source,
							const char *address)
{
	struct pending_request *pending;

	if (connection == NULL || any->path == NULL)
		return -1;

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

static void confirm_connection(GIOChannel *io, const char *source,
					const char *address, void *user_data)
{

	struct obex_service_driver *driver = user_data;
	struct bluetooth_service *service;
	GError *err = NULL;

	service = find_service(driver);
	if (service == NULL) {
		error("bluetooth: Unable to find service");
		goto drop;
	}

	if (driver->secure) {
		if (request_service_authorization(service, io, source,
								address) < 0)
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

static void confirm_rfcomm(GIOChannel *io, void *user_data)
{
	GError *err = NULL;
	char source[18];
	char address[18];
	uint8_t channel;

	bt_io_get(io, BT_IO_RFCOMM, &err,
			BT_IO_OPT_SOURCE, source,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_CHANNEL, &channel,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		g_io_channel_shutdown(io, TRUE, NULL);
		return;
	}

	info("bluetooth: New connection from: %s, channel %u", address,
								channel);

	confirm_connection(io, source, address, user_data);
}

static void confirm_l2cap(GIOChannel *io, void *user_data)
{
	GError *err = NULL;
	char source[18];
	char address[18];
	uint16_t psm;

	bt_io_get(io, BT_IO_L2CAP, &err,
			BT_IO_OPT_SOURCE, source,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_PSM, &psm,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		g_io_channel_shutdown(io, TRUE, NULL);
		return;
	}

	info("bluetooth: New connection from: %s, psm %u", address, psm);

	confirm_connection(io, source, address, user_data);
}

static GSList *start(struct obex_server *server,
				struct obex_service_driver *service)
{
	BtIOSecLevel sec_level;
	GSList *l = NULL;
	GIOChannel *io;
	GError *err = NULL;
	uint16_t psm;

	if (service->secure == TRUE)
		sec_level = BT_IO_SEC_MEDIUM;
	else
		sec_level = BT_IO_SEC_LOW;

	io = bt_io_listen(BT_IO_RFCOMM, NULL, confirm_rfcomm,
				service, NULL, &err,
				BT_IO_OPT_CHANNEL, service->channel,
				BT_IO_OPT_SEC_LEVEL, sec_level,
				BT_IO_OPT_INVALID);
	if (io == NULL) {
		error("bluetooth: unable to listen in channel %d: %s",
				service->channel, err->message);
		g_error_free(err);
	} else {
		l = g_slist_prepend(l, io);
		DBG("listening on channel %d", service->channel);
	}

	if (service->port == 0)
		return l;

	psm = service->port == OBEX_PORT_RANDOM ? 0 : service->port;

	io = bt_io_listen(BT_IO_L2CAP, NULL, confirm_l2cap,
			service, NULL, &err,
			BT_IO_OPT_PSM, psm,
			BT_IO_OPT_MODE, BT_IO_MODE_ERTM,
			BT_IO_OPT_OMTU, BT_TX_MTU,
			BT_IO_OPT_IMTU, BT_RX_MTU,
			BT_IO_OPT_SEC_LEVEL, sec_level,
			BT_IO_OPT_INVALID);
	if (io == NULL) {
		error("bluetooth: unable to listen in psm %d: %s",
				service->port, err->message);
		g_error_free(err);
		service->port = 0;
	} else {
		l = g_slist_prepend(l, io);
		bt_io_get(io, BT_IO_L2CAP, &err, BT_IO_OPT_PSM, &service->port,
							BT_IO_OPT_INVALID);
		DBG("listening on psm %d", service->port);
	}

	return l;
}

static void *bluetooth_start(struct obex_server *server, int *err)
{
	GSList *ios = NULL;
	const GSList *l;

	for (l = server->drivers; l; l = l->next) {
		struct obex_service_driver *service = l->data;
		GSList *l;

		l = start(server, service);
		if (l == NULL)
			continue;

		ios = g_slist_concat(ios, l);
	}

	register_record(server);

	return ios;
}

static void stop(gpointer data)
{
	GIOChannel *io = data;

	g_io_channel_shutdown(io, TRUE, NULL);
	g_io_channel_unref(io);
}

static void bluetooth_stop(void *data)
{
	GSList *ios = data;

	g_slist_free_full(ios, stop);
}

static int bluetooth_getpeername(GIOChannel *io, char **name)
{
	int sk = g_io_channel_unix_get_fd(io);
	GError *gerr = NULL;
	char address[18];
	int type;
	socklen_t len = sizeof(int);

	if (getsockopt(sk, SOL_SOCKET, SO_TYPE, &type, &len) < 0)
		return -errno;

	if (type == SOCK_STREAM)
		bt_io_get(io, BT_IO_RFCOMM, &gerr,
				BT_IO_OPT_DEST, address,
				BT_IO_OPT_INVALID);
	else
		bt_io_get(io, BT_IO_L2CAP, &gerr,
				BT_IO_OPT_DEST, address,
				BT_IO_OPT_INVALID);

	if (gerr) {
		error("%s", gerr->message);
		g_error_free(gerr);
		return -EINVAL;
	}

	*name = g_strdup(address);

	return 0;
}

static struct obex_transport_driver driver = {
	.name = "bluetooth",
	.start = bluetooth_start,
	.getpeername = bluetooth_getpeername,
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
		g_slist_free_full(any->services, g_free);
		g_free(any->path);
		g_free(any);
	}

	if (connection)
		dbus_connection_unref(connection);

	obex_transport_driver_unregister(&driver);
}

OBEX_PLUGIN_DEFINE(bluetooth, bluetooth_init, bluetooth_exit)
