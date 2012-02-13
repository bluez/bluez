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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <termios.h>
#include <inttypes.h>

#include <glib.h>
#include <gdbus.h>

#include "obexd.h"
#include "plugin.h"
#include "server.h"
#include "obex.h"
#include "transport.h"
#include "service.h"
#include "log.h"

static GIOChannel *usb_io = NULL;
static guint usb_reconnecting = 0;
static guint usb_watch = 0;
static DBusConnection *connection = NULL;

#define USB_RX_MTU 65535
#define USB_TX_MTU 65535
#define USB_DEVNODE "/dev/ttyGS0"

static int usb_connect(struct obex_server *server);

static void usb_disconnect(struct obex_server *server)
{
	if (usb_reconnecting > 0) {
		g_source_remove(usb_reconnecting);
		usb_reconnecting = 0;
	}

	if (usb_watch > 0) {
		g_source_remove(usb_watch);
		usb_watch = 0;
	}

	/* already disconnected */
	if (usb_io == NULL)
		return;

	g_io_channel_shutdown(usb_io, TRUE, NULL);
	g_io_channel_unref(usb_io);
	usb_io = NULL;
	DBG("disconnected");
}

static gboolean usb_reconnect(void *data)
{
	struct obex_server *server = data;

	DBG("reconnecting");
	usb_reconnecting = 0;
	usb_connect(server);

	return FALSE;
}

static gboolean usb_watchdog(GIOChannel *io, GIOCondition cond,
				void *user_data)
{
	struct obex_server *server = user_data;

	usb_watch = 0;
	usb_disconnect(server);

	if ((cond & G_IO_NVAL) == FALSE)
		usb_reconnecting = g_idle_add(usb_reconnect, server);

	return FALSE;
}

static int usb_connect(struct obex_server *server)
{
	struct termios options;
	int fd, err, arg;
	glong flags;

	if (usb_reconnecting > 0) {
		g_source_remove(usb_reconnecting);
		usb_reconnecting = 0;
	}

	/* already connected */
	if (usb_io != NULL)
		return 0;

	fd = open(USB_DEVNODE, O_RDWR | O_NOCTTY);
	if (fd < 0)
		return fd;

	flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

	tcgetattr(fd, &options);
	cfmakeraw(&options);
	options.c_oflag &= ~ONLCR;
	tcsetattr(fd, TCSANOW, &options);

	arg = fcntl(fd, F_GETFL);
	if (arg < 0) {
		err = -errno;
		goto failed;
	}

	arg |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, arg) < 0) {
		err = -errno;
		goto failed;
	}

	usb_io = g_io_channel_unix_new(fd);
	g_io_channel_set_close_on_unref(usb_io, TRUE);

	err = obex_server_new_connection(server, usb_io, USB_TX_MTU,
							USB_RX_MTU, TRUE);
	if (err < 0)
		goto failed;

	usb_watch = g_io_add_watch(usb_io, G_IO_HUP | G_IO_ERR | G_IO_NVAL,
					usb_watchdog, server);

	DBG("Successfully opened %s", USB_DEVNODE);

	return 0;

failed:
	error("usb: %s (%d)", strerror(-err), -err);
	if (usb_io == NULL)
		close(fd);
	else
		usb_disconnect(server);
	return err;
}

static void sig_usb(int sig)
{
}

static void usb_set_mode(struct obex_server *server, const char *mode)
{
	DBG("%s", mode);

	if (g_str_equal(mode, "ovi_suite") == TRUE)
		usb_connect(server);
	else if (g_str_equal(mode, "USB disconnected") == TRUE)
		usb_disconnect(server);
}

static gboolean handle_signal(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct obex_server *server = user_data;
	const char *mode;

	dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &mode,
				DBUS_TYPE_INVALID);

	usb_set_mode(server, mode);

	return TRUE;
}

static void usb_stop(void *data)
{
	guint id = GPOINTER_TO_UINT(data);
	g_dbus_remove_watch(connection, id);
}

static void mode_request_reply(DBusPendingCall *call, void *user_data)
{
	struct obex_server *server = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("usb: Replied with an error: %s, %s",
				derr.name, derr.message);
		dbus_error_free(&derr);
	} else {
		const char *mode;
		dbus_message_get_args(reply, NULL,
				DBUS_TYPE_STRING, &mode,
				DBUS_TYPE_INVALID);

		usb_set_mode(server, mode);
	}

	dbus_message_unref(reply);
}

static void *usb_start(struct obex_server *server, int *err)
{
	guint id;
	DBusMessage *msg;
	DBusPendingCall *call;

	msg = dbus_message_new_method_call("com.meego.usb_moded",
						"/com/meego/usb_moded",
						"com.meego.usb_moded",
						"mode_request");

	if (dbus_connection_send_with_reply(connection,
					msg, &call, -1) == FALSE) {
		error("usb: unable to send mode_request");
		dbus_message_unref(msg);
		goto fail;
	}

	dbus_pending_call_set_notify(call, mode_request_reply, server, NULL);
	dbus_pending_call_unref(call);
	dbus_message_unref(msg);

	id = g_dbus_add_signal_watch(connection, NULL, NULL,
					"com.meego.usb_moded",
					"sig_usb_state_ind",
					handle_signal, server, NULL);

	if (err != NULL)
		*err = 0;

	return GUINT_TO_POINTER(id);

fail:
	if (err != NULL)
		*err = -1;

	return NULL;
}

static struct obex_transport_driver driver = {
	.name = "usb",
	.service = OBEX_PCSUITE,
	.start = usb_start,
	.stop = usb_stop
};

static int usb_init(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_usb;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	connection = g_dbus_setup_private(DBUS_BUS_SYSTEM, NULL, NULL);
	if (connection == NULL)
		return -EPERM;

	return obex_transport_driver_register(&driver);
}

static void usb_exit(void)
{
	if (connection)
		dbus_connection_unref(connection);

	obex_transport_driver_unregister(&driver);
}

OBEX_PLUGIN_DEFINE(usb, usb_init, usb_exit)
