/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sco.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "glib-helper.h"
#include "device.h"
#include "gateway.h"
#include "logging.h"
#include "error.h"
#include "btio.h"
#include "dbus-common.h"

#define RFCOMM_BUF_SIZE 256

struct gateway {
	gateway_state_t state;
	GIOChannel *rfcomm;
	guint rfcomm_watch_id;
	GIOChannel *sco;
	gateway_stream_cb_t sco_start_cb;
	void *sco_start_cb_data;
	DBusMessage *connect_message;
};

int gateway_close(struct audio_device *device);

static gboolean sco_io_cb(GIOChannel *chan, GIOCondition cond,
			struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		debug("sco connection is released");
		g_io_channel_shutdown(gw->sco, TRUE, NULL);
		g_io_channel_unref(gw->sco);
		gw->sco = NULL;
		return FALSE;
	}

	return TRUE;
}

static void sco_connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct audio_device *dev = (struct audio_device *) user_data;
	struct gateway *gw = dev->gateway;

	debug("at the begin of sco_connect_cb() in gateway.c");

	if (err) {
		error("sco_connect_cb(): %s", err->message);
		/* not sure, but from other point of view,
		 * what is the reason to have headset which
		 * cannot play audio? */
		if (gw->sco_start_cb)
			gw->sco_start_cb(NULL, gw->sco_start_cb_data);
		gateway_close(dev);
		return;
	}

	gw->sco = g_io_channel_ref(chan);
	if (gw->sco_start_cb)
		gw->sco_start_cb(dev, gw->sco_start_cb_data);

	/* why is this here? */
	fcntl(g_io_channel_unix_get_fd(chan), F_SETFL, 0);
	g_io_add_watch(gw->sco, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) sco_io_cb, dev);
}

static void rfcomm_connect_cb(GIOChannel *chan, GError *err,
				gpointer user_data)
{
	struct audio_device *dev = user_data;
	struct gateway *gw = dev->gateway;
	gchar gw_addr[18];
	GIOFlags flags;

	if (err) {
		error("connect(): %s", err->message);
		if (gw->sco_start_cb)
			gw->sco_start_cb(NULL, gw->sco_start_cb_data);
		return;
	}

	ba2str(&dev->dst, gw_addr);
	/* Blocking mode should be default, but just in case: */
	flags = g_io_channel_get_flags(chan);
	flags &= ~G_IO_FLAG_NONBLOCK;
	flags &= G_IO_FLAG_MASK;
	g_io_channel_set_flags(chan, flags, NULL);
	g_io_channel_set_encoding(chan, NULL, NULL);
	g_io_channel_set_buffered(chan, FALSE);
	if (!gw->rfcomm)
		gw->rfcomm = g_io_channel_ref(chan);

	if (NULL != gw->sco_start_cb)
		gw->sco_start_cb(NULL, gw->sco_start_cb_data);

	gateway_close(dev);
}

static void get_record_cb(sdp_list_t *recs, int perr, gpointer user_data)
{
	struct audio_device *dev = user_data;
	DBusMessage *msg = dev->gateway->connect_message;
	int ch = -1;
	sdp_list_t *protos, *classes;
	uuid_t uuid;
	gateway_stream_cb_t sco_cb;
	GIOChannel *io;
	GError *err = NULL;

	if (perr < 0) {
		error("Unable to get service record: %s (%d)", strerror(-perr),
					-perr);
		goto fail;
	}

	if (!recs || !recs->data) {
		error("No records found");
		goto fail;
	}

	if (sdp_get_service_classes(recs->data, &classes) < 0) {
		error("Unable to get service classes from record");
		goto fail;
	}

	if (sdp_get_access_protos(recs->data, &protos) < 0) {
		error("Unable to get access protocols from record");
		goto fail;
	}

	memcpy(&uuid, classes->data, sizeof(uuid));
	sdp_list_free(classes, free);

	if (!sdp_uuid128_to_uuid(&uuid) || uuid.type != SDP_UUID16 ||
			uuid.value.uuid16 != HANDSFREE_AGW_SVCLASS_ID) {
		sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free,
									NULL);
		sdp_list_free(protos, NULL);
		error("Invalid service record or not HFP");
		goto fail;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);
	if (ch <= 0) {
		error("Unable to extract RFCOMM channel from service record");
		goto fail;
	}

	io = bt_io_connect(BT_IO_RFCOMM, rfcomm_connect_cb, dev, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &dev->src,
				BT_IO_OPT_DEST_BDADDR, &dev->dst,
				BT_IO_OPT_CHANNEL, ch,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("Unable to connect: %s", err->message);
		if (msg) {
			error_common_reply(dev->conn, msg, ERROR_INTERFACE
						".ConnectionAttemptFailed",
						err->message);
			msg = NULL;
		}
		g_error_free(err);
		gateway_close(dev);
	}

	g_io_channel_unref(io);
	return;

fail:
	if (msg)
		error_common_reply(dev->conn, msg, ERROR_INTERFACE
					".NotSupported", "Not supported");

	dev->gateway->connect_message = NULL;

	sco_cb = dev->gateway->sco_start_cb;
	if (sco_cb)
		sco_cb(NULL, dev->gateway->sco_start_cb_data);
}

static int get_records(struct audio_device *device)
{
	uuid_t uuid;

	sdp_uuid16_create(&uuid, HANDSFREE_AGW_SVCLASS_ID);
	return bt_search_service(&device->src, &device->dst, &uuid,
				get_record_cb, device, NULL);
}

static DBusMessage *ag_connect(DBusConnection *conn, DBusMessage *msg,
				void *data)
{
	struct audio_device *au_dev = (struct audio_device *) data;
	struct gateway *gw = au_dev->gateway;

	debug("at the begin of ag_connect()");
	if (gw->rfcomm)
		return g_dbus_create_error(msg, ERROR_INTERFACE
					".AlreadyConnected",
					"Already Connected");

	gw->connect_message = dbus_message_ref(msg);
	if (get_records(au_dev) < 0) {
		dbus_message_unref(gw->connect_message);
		return g_dbus_create_error(msg, ERROR_INTERFACE
					".ConnectAttemptFailed",
					"Connect Attempt Failed");
	}
	debug("at the end of ag_connect()");
	return NULL;
}

static DBusMessage *ag_disconnect(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct gateway *gw = device->gateway;
	DBusMessage *reply = NULL;
	char gw_addr[18];

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	if (!gw->rfcomm)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotConnected",
						"Device not Connected");

	gateway_close(device);
	ba2str(&device->dst, gw_addr);
	debug("Disconnected from %s, %s", gw_addr, device->path);

	return reply;
}

static DBusMessage *ag_get_properties(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	return NULL;
}

static GDBusMethodTable gateway_methods[] = {
	{ "Connect", "", "", ag_connect, G_DBUS_METHOD_FLAG_ASYNC },
	{ "Disconnect", "", "", ag_disconnect },
	{ "GetProperties", "", "a{sv}", ag_get_properties },
	{ NULL, NULL, NULL, NULL }
};

static GDBusSignalTable gateway_signals[] = {
	{ "PropertyChanged", "sv" },
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

	debug("in gateway_init, dev is %p", dev);
	gw = g_new0(struct gateway, 1);
	gw->state = GATEWAY_STATE_DISCONNECTED;
	return gw;

}

gboolean gateway_is_connected(struct audio_device *dev)
{
	return (dev && dev->gateway &&
			dev->gateway->state == GATEWAY_STATE_CONNECTED);
}

int gateway_connect_rfcomm(struct audio_device *dev, GIOChannel *io)
{
	if (!io)
		return -EINVAL;

	g_io_channel_ref(io);
	dev->gateway->rfcomm = io;

	return 0;
}

int gateway_connect_sco(struct audio_device *dev, GIOChannel *io)
{
	struct gateway *gw = dev->gateway;

	if (gw->sco)
		return -EISCONN;

	gw->sco = g_io_channel_ref(io);

	g_io_add_watch(gw->sco, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
                                (GIOFunc) sco_io_cb, dev);
	return 0;
}

void gateway_start_service(struct audio_device *device)
{
	rfcomm_connect_cb(device->gateway->rfcomm, NULL, device);
}

int gateway_close(struct audio_device *device)
{
	struct gateway *gw = device->gateway;
	GIOChannel *rfcomm = gw->rfcomm;
	GIOChannel *sco = gw->sco;
	gboolean value = FALSE;

	if (rfcomm) {
		g_io_channel_shutdown(rfcomm, TRUE, NULL);
		g_io_channel_unref(rfcomm);
		gw->rfcomm = NULL;
	}

	if (sco) {
		g_io_channel_shutdown(sco, TRUE, NULL);
		g_io_channel_unref(sco);
		gw->sco = NULL;
		gw->sco_start_cb = NULL;
		gw->sco_start_cb_data = NULL;
	}

	gw->state = GATEWAY_STATE_DISCONNECTED;

	emit_property_changed(device->conn, device->path,
				AUDIO_GATEWAY_INTERFACE,
				"Connected", DBUS_TYPE_BOOLEAN, &value);
	return 0;
}

/* These are functions to be called from unix.c for audio system
 * ifaces (alsa, gstreamer, etc.) */
gboolean gateway_request_stream(struct audio_device *dev,
				gateway_stream_cb_t cb, void *user_data)
{
	struct gateway *gw = dev->gateway;
	GError *err = NULL;
	GIOChannel *io;

	if (!gw->rfcomm) {
		gw->sco_start_cb = cb;
		gw->sco_start_cb_data = user_data;
		get_records(dev);
	} else if (!gw->sco) {
		gw->sco_start_cb = cb;
		gw->sco_start_cb_data = user_data;
		io = bt_io_connect(BT_IO_SCO, sco_connect_cb, dev, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &dev->src,
				BT_IO_OPT_DEST_BDADDR, &dev->dst,
				BT_IO_OPT_INVALID);
		if (!io) {
			error("%s", err->message);
			g_error_free(err);
			return FALSE;
		}
	} else {
		if (cb)
			cb(dev, user_data);
	}

	return TRUE;
}

int gateway_config_stream(struct audio_device *dev, gateway_stream_cb_t sco_cb,
				void *user_data)
{
	struct gateway *gw = dev->gateway;

	if (!gw->rfcomm) {
		gw->sco_start_cb = sco_cb;
		gw->sco_start_cb_data = user_data;
		return get_records(dev);
	}

	if (sco_cb)
		sco_cb(dev, user_data);

	return 0;
}

gboolean gateway_cancel_stream(struct audio_device *dev, unsigned int id)
{
	gateway_close(dev);
	return TRUE;
}

int gateway_get_sco_fd(struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;

	if (!gw || !gw->sco)
		return -1;

	return g_io_channel_unix_get_fd(gw->sco);
}

void gateway_suspend_stream(struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;

	if (!gw || !gw->sco)
		return;

	g_io_channel_shutdown(gw->sco, TRUE, NULL);
	g_io_channel_unref(gw->sco);
	gw->sco = NULL;
	gw->sco_start_cb = NULL;
	gw->sco_start_cb_data = NULL;
}

