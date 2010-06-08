/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2008-2009  Leonid Movshovich <event.riga@gmail.org>
 *  Copyright (C) 2010  ProFUSION embedded systems
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
#include "log.h"
#include "error.h"
#include "btio.h"
#include "dbus-common.h"

#ifndef DBUS_TYPE_UNIX_FD
#define DBUS_TYPE_UNIX_FD -1
#endif

struct hf_agent {
	char *name;	/* Bus id */
	char *path;	/* D-Bus path */
	guint watch;	/* Disconnect watch */
};

struct gateway {
	gateway_state_t state;
	GIOChannel *rfcomm;
	GIOChannel *sco;
	gateway_stream_cb_t sco_start_cb;
	void *sco_start_cb_data;
	struct hf_agent *agent;
	DBusMessage *msg;
};

int gateway_close(struct audio_device *device);

static const char *state2str(gateway_state_t state)
{
	switch (state) {
	case GATEWAY_STATE_DISCONNECTED:
		return "disconnected";
	case GATEWAY_STATE_CONNECTING:
		return "connecting";
	case GATEWAY_STATE_CONNECTED:
		return "connected";
	case GATEWAY_STATE_PLAYING:
		return "playing";
	default:
		return "";
	}
}

static void agent_free(struct hf_agent *agent)
{
	if (!agent)
		return;

	g_free(agent->name);
	g_free(agent->path);
	g_free(agent);
}

static void change_state(struct audio_device *dev, gateway_state_t new_state)
{
	struct gateway *gw = dev->gateway;
	const char *val;

	if (gw->state == new_state)
		return;

	val = state2str(new_state);
	gw->state = new_state;

	emit_property_changed(dev->conn, dev->path,
			AUDIO_GATEWAY_INTERFACE, "State",
			DBUS_TYPE_STRING, &val);
}

static void agent_disconnect(struct audio_device *dev, struct hf_agent *agent)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(agent->name, agent->path,
			"org.bluez.HandsfreeAgent", "Release");

	g_dbus_send_message(dev->conn, msg);
}

static gboolean agent_sendfd(struct hf_agent *agent, int fd,
		DBusPendingCallNotifyFunction notify, void *data)
{
	struct audio_device *dev = data;
	DBusMessage *msg;
	DBusPendingCall *call;

	msg = dbus_message_new_method_call(agent->name, agent->path,
			"org.bluez.HandsfreeAgent", "NewConnection");

	dbus_message_append_args(msg, DBUS_TYPE_UNIX_FD, &fd,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(dev->conn, msg, &call, -1) == FALSE)
		return FALSE;

	dbus_pending_call_set_notify(call, notify, dev, NULL);
	dbus_pending_call_unref(call);

	return TRUE;
}

static gboolean sco_io_cb(GIOChannel *chan, GIOCondition cond,
			struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		DBG("sco connection is released");
		g_io_channel_shutdown(gw->sco, TRUE, NULL);
		g_io_channel_unref(gw->sco);
		gw->sco = NULL;
		change_state(dev, GATEWAY_STATE_CONNECTED);
		return FALSE;
	}

	return TRUE;
}

static void sco_connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct audio_device *dev = (struct audio_device *) user_data;
	struct gateway *gw = dev->gateway;

	DBG("at the begin of sco_connect_cb() in gateway.c");

	gw->sco = g_io_channel_ref(chan);

	if (gw->sco_start_cb)
		gw->sco_start_cb(dev, err, gw->sco_start_cb_data);

	if (err) {
		error("sco_connect_cb(): %s", err->message);
		gateway_close(dev);
		return;
	}

	g_io_add_watch(gw->sco, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) sco_io_cb, dev);
}

static void newconnection_reply(DBusPendingCall *call, void *data)
{
	struct audio_device *dev = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;

	if (!dev->gateway->rfcomm) {
		DBG("RFCOMM disconnected from server before agent reply");
		goto done;
	}

	dbus_error_init(&derr);
	if (!dbus_set_error_from_message(&derr, reply)) {
		DBG("Agent reply: file descriptor passed successfully");
		change_state(dev, GATEWAY_STATE_CONNECTED);
		goto done;
	}

	DBG("Agent reply: %s", derr.message);

	dbus_error_free(&derr);
	gateway_close(dev);

done:
	dbus_message_unref(reply);
}

static void rfcomm_connect_cb(GIOChannel *chan, GError *err,
				gpointer user_data)
{
	struct audio_device *dev = user_data;
	struct gateway *gw = dev->gateway;
	DBusMessage *reply;
	int sk, ret;

	if (err) {
		error("connect(): %s", err->message);
		if (gw->sco_start_cb)
			gw->sco_start_cb(dev, err, gw->sco_start_cb_data);
		goto fail;
	}

	if (!gw->agent) {
		error("Handsfree Agent not registered");
		goto fail;
	}

	sk = g_io_channel_unix_get_fd(chan);

	gw->rfcomm = g_io_channel_ref(chan);

	ret = agent_sendfd(gw->agent, sk, newconnection_reply, dev);

	if (!gw->msg)
		return;

	if (ret)
		reply = dbus_message_new_method_return(gw->msg);
	else
		reply = g_dbus_create_error(gw->msg, ERROR_INTERFACE ".Failed",
					"Can not pass file descriptor");

	g_dbus_send_message(dev->conn, reply);

	return;

fail:
	if (gw->msg)
		error_common_reply(dev->conn, gw->msg,
						ERROR_INTERFACE ".Failed",
						"Connection attempt failed");

	change_state(dev, GATEWAY_STATE_DISCONNECTED);
}

static void get_record_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct audio_device *dev = user_data;
	struct gateway *gw = dev->gateway;
	int ch;
	sdp_list_t *protos, *classes;
	uuid_t uuid;
	GIOChannel *io;
	GError *gerr = NULL;

	if (err < 0) {
		error("Unable to get service record: %s (%d)", strerror(-err),
					-err);
		goto fail;
	}

	if (!recs || !recs->data) {
		error("No records found");
		err = -EIO;
		goto fail;
	}

	if (sdp_get_service_classes(recs->data, &classes) < 0) {
		error("Unable to get service classes from record");
		err = -EINVAL;
		goto fail;
	}

	if (sdp_get_access_protos(recs->data, &protos) < 0) {
		error("Unable to get access protocols from record");
		err = -ENODATA;
		goto fail;
	}

	memcpy(&uuid, classes->data, sizeof(uuid));
	sdp_list_free(classes, free);

	if (!sdp_uuid128_to_uuid(&uuid) || uuid.type != SDP_UUID16 ||
			uuid.value.uuid16 != HANDSFREE_AGW_SVCLASS_ID) {
		sdp_list_free(protos, NULL);
		error("Invalid service record or not HFP");
		err = -EIO;
		goto fail;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);
	if (ch <= 0) {
		error("Unable to extract RFCOMM channel from service record");
		err = -EIO;
		goto fail;
	}

	io = bt_io_connect(BT_IO_RFCOMM, rfcomm_connect_cb, dev, NULL, &gerr,
				BT_IO_OPT_SOURCE_BDADDR, &dev->src,
				BT_IO_OPT_DEST_BDADDR, &dev->dst,
				BT_IO_OPT_CHANNEL, ch,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("Unable to connect: %s", gerr->message);
		gateway_close(dev);
		goto fail;
	}

	g_io_channel_unref(io);

	change_state(dev, GATEWAY_STATE_CONNECTING);
	return;

fail:
	if (gw->msg)
		error_common_reply(dev->conn, gw->msg,
					ERROR_INTERFACE ".NotSupported",
					"Not supported");

	change_state(dev, GATEWAY_STATE_DISCONNECTED);

	if (!gerr)
		g_set_error(&gerr, BT_IO_ERROR, BT_IO_ERROR_FAILED,
				"connect: %s (%d)", strerror(-err), -err);

	if (gw->sco_start_cb)
		gw->sco_start_cb(dev, gerr, gw->sco_start_cb_data);

	g_error_free(gerr);
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

	if (!gw->agent)
		return g_dbus_create_error(msg, ERROR_INTERFACE
				".Failed", "Agent not assigned");

	if (get_records(au_dev) < 0)
		return g_dbus_create_error(msg, ERROR_INTERFACE
					".ConnectAttemptFailed",
					"Connect Attempt Failed");

	gw->msg = dbus_message_ref(msg);

	return NULL;
}

int gateway_close(struct audio_device *device)
{
	struct gateway *gw = device->gateway;
	int sock;

	if (gw->rfcomm) {
		sock = g_io_channel_unix_get_fd(gw->rfcomm);
		shutdown(sock, SHUT_RDWR);

		g_io_channel_shutdown(gw->rfcomm, TRUE, NULL);
		g_io_channel_unref(gw->rfcomm);
		gw->rfcomm = NULL;
	}

	if (gw->sco) {
		g_io_channel_shutdown(gw->sco, TRUE, NULL);
		g_io_channel_unref(gw->sco);
		gw->sco = NULL;
		gw->sco_start_cb = NULL;
		gw->sco_start_cb_data = NULL;
	}

	change_state(device, GATEWAY_STATE_DISCONNECTED);

	return 0;
}

static DBusMessage *ag_disconnect(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct gateway *gw = device->gateway;
	DBusMessage *reply = NULL;
	char gw_addr[18];

	if (!device->conn)
		return NULL;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	if (!gw->rfcomm)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotConnected",
						"Device not Connected");

	gateway_close(device);
	ba2str(&device->dst, gw_addr);
	DBG("Disconnected from %s, %s", gw_addr, device->path);

	return reply;
}

static void agent_exited(DBusConnection *conn, void *data)
{
	struct gateway *gateway = data;
	struct hf_agent *agent = gateway->agent;

	DBG("Agent %s exited", agent->name);

	agent_free(agent);
	gateway->agent = NULL;
}

static DBusMessage *ag_get_properties(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct gateway *gw = device->gateway;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	const char *value;


	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	value = state2str(gw->state);
	dict_append_entry(&dict, "State",
			DBUS_TYPE_STRING, &value);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *register_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	struct gateway *gw = device->gateway;
	struct hf_agent *agent;
	const char *path, *name;

	if (gw->agent)
		return g_dbus_create_error(msg,
					ERROR_INTERFACE ".AlreadyExists",
					"Agent already exists");

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID))
		return g_dbus_create_error(msg,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid argument");

	name = dbus_message_get_sender(msg);
	agent = g_new0(struct hf_agent, 1);

	agent->name = g_strdup(name);
	agent->path = g_strdup(path);

	agent->watch = g_dbus_add_disconnect_watch(conn, name,
						agent_exited, gw, NULL);

	gw->agent = agent;

	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_agent(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	struct gateway *gw = device->gateway;
	const char *path;

	if (!gw->agent)
		goto done;

	if (strcmp(gw->agent->name, dbus_message_get_sender(msg)) != 0)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
							"Permission denied");

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID))
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".InvalidArguments",
				"Invalid argument");

	if (strcmp(gw->agent->path, path) != 0)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".Failed",
				"Unknown object path");

	g_dbus_remove_watch(device->conn, gw->agent->watch);

	agent_free(gw->agent);
	gw->agent = NULL;

done:
	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable gateway_methods[] = {
	{ "Connect", "", "", ag_connect, G_DBUS_METHOD_FLAG_ASYNC },
	{ "Disconnect", "", "", ag_disconnect, G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetProperties", "", "a{sv}", ag_get_properties },
	{ "RegisterAgent", "o", "", register_agent },
	{ "UnregisterAgent", "o", "", unregister_agent },
	{ NULL, NULL, NULL, NULL }
};

static GDBusSignalTable gateway_signals[] = {
	{ "PropertyChanged", "sv" },
	{ NULL, NULL }
};

static void path_unregister(void *data)
{
	struct audio_device *dev = data;

	DBG("Unregistered interface %s on path %s",
		AUDIO_GATEWAY_INTERFACE, dev->path);

	gateway_close(dev);

	g_free(dev->gateway);
	dev->gateway = NULL;
}

void gateway_unregister(struct audio_device *dev)
{
	if (dev->gateway->agent)
		agent_disconnect(dev, dev->gateway->agent);

	g_dbus_unregister_interface(dev->conn, dev->path,
						AUDIO_GATEWAY_INTERFACE);
}

struct gateway *gateway_init(struct audio_device *dev)
{
	if (DBUS_TYPE_UNIX_FD < 0)
		return NULL;

	if (!g_dbus_register_interface(dev->conn, dev->path,
					AUDIO_GATEWAY_INTERFACE,
					gateway_methods, gateway_signals,
					NULL, dev, path_unregister))
		return NULL;

	return g_new0(struct gateway, 1);

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

	dev->gateway->rfcomm = g_io_channel_ref(io);

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

	change_state(dev, GATEWAY_STATE_PLAYING);

	return 0;
}

void gateway_start_service(struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;
	GError *err = NULL;

	if (gw->rfcomm == NULL)
		return;

	if (!bt_io_accept(gw->rfcomm, rfcomm_connect_cb, dev, NULL, &err)) {
		error("bt_io_accept: %s", err->message);
		g_error_free(err);
	}
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
	} else if (cb)
		cb(dev, err, user_data);

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
		sco_cb(dev, NULL, user_data);

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
