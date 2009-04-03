/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2008-2009  Leonid Movshovich <event.riga@gmail.org>
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

#include <stdint.h>
#include <errno.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include <bluetooth/bluetooth.h>

#include "device.h"
#include "gateway.h"

struct gateway {
	GIOChannel *rfcomm;
	guint rfcomm_watch_id;
	GIOChannel *sco;
	GIOChannel *sco_server;
	gateway_stream_cb_t sco_start_cb;
	void *sco_start_cb_data;
	DBusMessage *connect_message;
	guint ag_features;
	guint hold_multiparty_features;
	GSList *indies;
	gboolean is_dialing;
};

static GDBusMethodTable gateway_methods[] = {
	{ NULL, NULL, NULL, NULL }
};

static GDBusSignalTable gateway_signals[] = {
	{ NULL, NULL }
};

struct gateway *gateway_init(struct audio_device *dev)
{
	struct gateway *gw;

	if (!g_dbus_register_interface(dev->conn, dev->path,
					AUDIO_GATEWAY_INTERFACE,
					gateway_methods, gateway_signals,
					NULL, dev, NULL))
		return NULL;

	gw = g_new0(struct gateway, 1);
	gw->indies = NULL;
	gw->is_dialing = FALSE;
	return gw;

}

gboolean gateway_is_connected(struct audio_device *dev)
{
	return (dev && dev->gateway && dev->gateway->rfcomm);
}

int gateway_connect_rfcomm(struct audio_device *dev, GIOChannel *io)
{
	if (!io)
		return -EINVAL;

	dev->gateway->rfcomm = io;

	return 0;
}

void gateway_start_service(struct audio_device *device)
{
}
