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

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include <glib.h>
#include <gdbus.h>

#include "plugin.h"
#include "server.h"
#include "obex.h"
#include "transport.h"
#include "service.h"
#include "logging.h"

static GIOChannel *usb_io = NULL;
static guint usb_reconnecting = 0;
static guint usb_watch = 0;
static int signal_pipe[2];

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
	debug("usb: disconnected");
}

static gboolean usb_reconnect(void *data)
{
	struct obex_server *server = data;

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

	err = obex_server_new_connection(server, usb_io,
					USB_TX_MTU, USB_RX_MTU);
	if (err < 0)
		goto failed;

	usb_watch = g_io_add_watch(usb_io, G_IO_HUP | G_IO_ERR | G_IO_NVAL,
					usb_watchdog, server);

	debug("usb: Successfully opened %s", USB_DEVNODE);

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
	if (write(signal_pipe[1], &sig, sizeof(sig)) != sizeof(sig))
		error("unable to write to signal pipe");
}

static gboolean handle_signal(GIOChannel *io, GIOCondition cond,
				void *user_data)
{
	struct obex_server *server = user_data;
	int sig, fd = g_io_channel_unix_get_fd(io);

	if (read(fd, &sig, sizeof(sig)) != sizeof(sig)) {
		error("handle_signal: unable to read signal from pipe");
		return TRUE;
	}

	switch (sig) {
	case SIGUSR1:
		debug("SIGUSR1");
		usb_connect(server);
		break;
	case SIGHUP:
		debug("SIGHUP");
		usb_disconnect(server);
		break;
	default:
		error("handle_signal: got unexpected signal %d", sig);
		break;
	}

	return TRUE;
}

static void usb_stop(void *data)
{
	guint id = GPOINTER_TO_UINT(data);
	g_source_remove(id);
}

static void *usb_start(struct obex_server *server, int *err)
{
	GIOChannel *io;
	guint id;

	io = g_io_channel_unix_new(signal_pipe[0]);
	id = g_io_add_watch(io, G_IO_IN, handle_signal, server);
	g_io_channel_unref(io);

	if (err != NULL)
		*err = 0;

	return GUINT_TO_POINTER(id);
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

	if (pipe(signal_pipe) < 0)
		return -errno;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_usb;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	return obex_transport_driver_register(&driver);
}

static void usb_exit(void)
{
	close(signal_pipe[0]);
	close(signal_pipe[1]);

	obex_transport_driver_unregister(&driver);
}

OBEX_PLUGIN_DEFINE(usb, usb_init, usb_exit)
