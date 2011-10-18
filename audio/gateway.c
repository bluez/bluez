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
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "glib-compat.h"
#include "sdp-client.h"
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

struct connect_cb {
	unsigned int id;
	gateway_stream_cb_t cb;
	void *cb_data;
};

struct gateway {
	gateway_state_t state;
	GIOChannel *rfcomm;
	GIOChannel *sco;
	GIOChannel *incoming;
	GSList *callbacks;
	struct hf_agent *agent;
	DBusMessage *msg;
	int version;
	gateway_lock_t lock;
};

struct gateway_state_callback {
	gateway_state_cb cb;
	void *user_data;
	unsigned int id;
};

static GSList *gateway_callbacks = NULL;

int gateway_close(struct audio_device *device);

GQuark gateway_error_quark(void)
{
	return g_quark_from_static_string("gateway-error-quark");
}

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
	GSList *l;
	gateway_state_t old_state;

	if (gw->state == new_state)
		return;

	val = state2str(new_state);
	old_state = gw->state;
	gw->state = new_state;

	emit_property_changed(dev->conn, dev->path,
			AUDIO_GATEWAY_INTERFACE, "State",
			DBUS_TYPE_STRING, &val);

	for (l = gateway_callbacks; l != NULL; l = l->next) {
		struct gateway_state_callback *cb = l->data;
		cb->cb(dev, old_state, new_state, cb->user_data);
	}
}

void gateway_set_state(struct audio_device *dev, gateway_state_t new_state)
{
	switch (new_state) {
	case GATEWAY_STATE_DISCONNECTED:
		gateway_close(dev);
		break;
	case GATEWAY_STATE_CONNECTING:
	case GATEWAY_STATE_CONNECTED:
	case GATEWAY_STATE_PLAYING:
		break;
	}
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
	struct gateway *gw = dev->gateway;
	DBusMessage *msg;
	DBusPendingCall *call;

	msg = dbus_message_new_method_call(agent->name, agent->path,
			"org.bluez.HandsfreeAgent", "NewConnection");

	dbus_message_append_args(msg, DBUS_TYPE_UNIX_FD, &fd,
					DBUS_TYPE_UINT16, &gw->version,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(dev->conn, msg, &call, -1) == FALSE)
		return FALSE;

	dbus_pending_call_set_notify(call, notify, dev, NULL);
	dbus_pending_call_unref(call);
	dbus_message_unref(msg);

	return TRUE;
}

static unsigned int connect_cb_new(struct gateway *gw,
					gateway_stream_cb_t func,
					void *user_data)
{
	struct connect_cb *cb;
	static unsigned int free_cb_id = 1;

	if (!func)
		return 0;

	cb = g_new(struct connect_cb, 1);

	cb->cb = func;
	cb->cb_data = user_data;
	cb->id = free_cb_id++;

	gw->callbacks = g_slist_append(gw->callbacks, cb);

	return cb->id;
}

static void run_connect_cb(struct audio_device *dev, GError *err)
{
	struct gateway *gw = dev->gateway;
	GSList *l;

	for (l = gw->callbacks; l != NULL; l = l->next) {
		struct connect_cb *cb = l->data;
		cb->cb(dev, err, cb->cb_data);
	}

	g_slist_free_full(gw->callbacks, g_free);
	gw->callbacks = NULL;
}

static gboolean sco_io_cb(GIOChannel *chan, GIOCondition cond,
			struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;

	if (cond & G_IO_NVAL)
		return FALSE;

	DBG("sco connection is released");
	g_io_channel_shutdown(gw->sco, TRUE, NULL);
	g_io_channel_unref(gw->sco);
	gw->sco = NULL;
	change_state(dev, GATEWAY_STATE_CONNECTED);

	return FALSE;
}

static void sco_connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct audio_device *dev = (struct audio_device *) user_data;
	struct gateway *gw = dev->gateway;

	DBG("at the begin of sco_connect_cb() in gateway.c");

	gw->sco = g_io_channel_ref(chan);

	if (err) {
		error("sco_connect_cb(): %s", err->message);
		gateway_close(dev);
		return;
	}

	g_io_add_watch(gw->sco, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) sco_io_cb, dev);

	change_state(dev, GATEWAY_STATE_PLAYING);
	run_connect_cb(dev, NULL);
}

static gboolean rfcomm_disconnect_cb(GIOChannel *chan, GIOCondition cond,
			struct audio_device *dev)
{
	if (cond & G_IO_NVAL)
		return FALSE;

	gateway_close(dev);

	return FALSE;
}

static void newconnection_reply(DBusPendingCall *call, void *data)
{
	struct audio_device *dev = data;
	struct gateway *gw = dev->gateway;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;

	if (!dev->gateway->rfcomm) {
		DBG("RFCOMM disconnected from server before agent reply");
		goto done;
	}

	dbus_error_init(&derr);
	if (!dbus_set_error_from_message(&derr, reply)) {
		DBG("Agent reply: file descriptor passed successfully");
		g_io_add_watch(gw->rfcomm, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
					(GIOFunc) rfcomm_disconnect_cb, dev);
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
		goto fail;
	}

	if (!gw->agent) {
		error("Handsfree Agent not registered");
		goto fail;
	}

	sk = g_io_channel_unix_get_fd(chan);

	if (gw->rfcomm == NULL)
		gw->rfcomm = g_io_channel_ref(chan);

	ret = agent_sendfd(gw->agent, sk, newconnection_reply, dev);

	if (!gw->msg)
		return;

	if (ret)
		reply = dbus_message_new_method_return(gw->msg);
	else
		reply = btd_error_failed(gw->msg, "Can't pass file descriptor");

	g_dbus_send_message(dev->conn, reply);

	return;

fail:
	if (gw->msg) {
		DBusMessage *reply;
		reply = btd_error_failed(gw->msg, "Connect failed");
		g_dbus_send_message(dev->conn, reply);
	}

	gateway_close(dev);
}

static int get_remote_profile_version(sdp_record_t *rec)
{
	uuid_t uuid;
	sdp_list_t *profiles;
	sdp_profile_desc_t *desc;
	int ver = 0;

	sdp_uuid16_create(&uuid, HANDSFREE_PROFILE_ID);

	sdp_get_profile_descs(rec, &profiles);
	if (profiles == NULL)
		goto done;

	desc = profiles->data;

	if (sdp_uuid16_cmp(&desc->uuid, &uuid) == 0)
		ver = desc->version;

	sdp_list_free(profiles, free);

done:
	return ver;
}

static void get_incoming_record_cb(sdp_list_t *recs, int err,
					gpointer user_data)
{
	struct audio_device *dev = user_data;
	struct gateway *gw = dev->gateway;
	GError *gerr = NULL;

	if (err < 0) {
		error("Unable to get service record: %s (%d)", strerror(-err),
					-err);
		goto fail;
	}

	if (!recs || !recs->data) {
		error("No records found");
		goto fail;
	}

	gw->version = get_remote_profile_version(recs->data);
	if (gw->version == 0)
		goto fail;

	rfcomm_connect_cb(gw->incoming, gerr, dev);
	return;

fail:
	gateway_close(dev);
}

static void unregister_incoming(gpointer user_data)
{
	struct audio_device *dev = user_data;
	struct gateway *gw = dev->gateway;

	if (gw->incoming) {
		g_io_channel_unref(gw->incoming);
		gw->incoming = NULL;
	}
}

static void rfcomm_incoming_cb(GIOChannel *chan, GError *err,
				gpointer user_data)
{
	struct audio_device *dev = user_data;
	struct gateway *gw = dev->gateway;
	uuid_t uuid;

	gw->incoming = g_io_channel_ref(chan);

	sdp_uuid16_create(&uuid, HANDSFREE_AGW_SVCLASS_ID);
	if (bt_search_service(&dev->src, &dev->dst, &uuid,
						get_incoming_record_cb, dev,
						unregister_incoming) == 0)
		return;

	unregister_incoming(dev);
	gateway_close(dev);
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

	gw->version = get_remote_profile_version(recs->data);
	if (gw->version == 0) {
		error("Unable to get profile version from record");
		err = -EINVAL;
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
		goto fail;
	}

	g_io_channel_unref(io);
	return;

fail:
	if (gw->msg) {
		DBusMessage *reply = btd_error_failed(gw->msg,
					gerr ? gerr->message : strerror(-err));
		g_dbus_send_message(dev->conn, reply);
	}

	gateway_close(dev);

	if (gerr)
		g_error_free(gerr);
}

static int get_records(struct audio_device *device)
{
	uuid_t uuid;

	change_state(device, GATEWAY_STATE_CONNECTING);
	sdp_uuid16_create(&uuid, HANDSFREE_AGW_SVCLASS_ID);
	return bt_search_service(&device->src, &device->dst, &uuid,
				get_record_cb, device, NULL);
}

static DBusMessage *ag_connect(DBusConnection *conn, DBusMessage *msg,
				void *data)
{
	struct audio_device *au_dev = (struct audio_device *) data;
	struct gateway *gw = au_dev->gateway;
	int err;

	if (!gw->agent)
		return btd_error_agent_not_available(msg);

	err = get_records(au_dev);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	gw->msg = dbus_message_ref(msg);

	return NULL;
}

int gateway_close(struct audio_device *device)
{
	GError *gerr = NULL;
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
	}

	change_state(device, GATEWAY_STATE_DISCONNECTED);
	g_set_error(&gerr, GATEWAY_ERROR,
			GATEWAY_ERROR_DISCONNECTED, "Disconnected");
	run_connect_cb(device, gerr);
	g_error_free(gerr);

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
		return  btd_error_not_connected(msg);

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
		return btd_error_already_exists(msg);

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

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
		return btd_error_not_authorized(msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	if (strcmp(gw->agent->path, path) != 0)
		return btd_error_does_not_exist(msg);

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
	struct gateway *gw = dev->gateway;

	if (gw->state == GATEWAY_STATE_CONNECTED)
		return TRUE;

	return FALSE;
}

gboolean gateway_is_active(struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;

	if (gw->state != GATEWAY_STATE_DISCONNECTED)
		return TRUE;

	return FALSE;
}

int gateway_connect_rfcomm(struct audio_device *dev, GIOChannel *io)
{
	if (!io)
		return -EINVAL;

	dev->gateway->rfcomm = g_io_channel_ref(io);

	change_state(dev, GATEWAY_STATE_CONNECTING);

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

	if (!bt_io_accept(gw->rfcomm, rfcomm_incoming_cb, dev, NULL, &err)) {
		error("bt_io_accept: %s", err->message);
		g_error_free(err);
		gateway_close(dev);
	}
}

static gboolean request_stream_cb(gpointer data)
{
	run_connect_cb(data, NULL);
	return FALSE;
}

/* These are functions to be called from unix.c for audio system
 * ifaces (alsa, gstreamer, etc.) */
unsigned int gateway_request_stream(struct audio_device *dev,
				gateway_stream_cb_t cb, void *user_data)
{
	struct gateway *gw = dev->gateway;
	unsigned int id;
	GError *err = NULL;
	GIOChannel *io;

	id = connect_cb_new(gw, cb, user_data);

	if (!gw->rfcomm)
		get_records(dev);
	else if (!gw->sco) {
		io = bt_io_connect(BT_IO_SCO, sco_connect_cb, dev, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &dev->src,
				BT_IO_OPT_DEST_BDADDR, &dev->dst,
				BT_IO_OPT_INVALID);
		if (!io) {
			error("%s", err->message);
			g_error_free(err);
			return 0;
		}
	} else
		g_idle_add(request_stream_cb, dev);

	return id;
}

int gateway_config_stream(struct audio_device *dev, gateway_stream_cb_t cb,
				void *user_data)
{
	struct gateway *gw = dev->gateway;
	unsigned int id;

	id = connect_cb_new(gw, cb, user_data);

	if (!gw->rfcomm)
		get_records(dev);
	else if (cb)
		g_idle_add(request_stream_cb, dev);

	return id;
}

gboolean gateway_cancel_stream(struct audio_device *dev, unsigned int id)
{
	struct gateway *gw = dev->gateway;
	GSList *l;
	struct connect_cb *cb = NULL;

	for (l = gw->callbacks; l != NULL; l = l->next) {
		struct connect_cb *tmp = l->data;

		if (tmp->id == id) {
			cb = tmp;
			break;
		}
	}

	if (!cb)
		return FALSE;

	gw->callbacks = g_slist_remove(gw->callbacks, cb);
	g_free(cb);

	gateway_suspend_stream(dev);

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
	GError *gerr = NULL;
	struct gateway *gw = dev->gateway;

	if (!gw || !gw->sco)
		return;

	g_io_channel_shutdown(gw->sco, TRUE, NULL);
	g_io_channel_unref(gw->sco);
	gw->sco = NULL;
	g_set_error(&gerr, GATEWAY_ERROR, GATEWAY_ERROR_SUSPENDED, "Suspended");
	run_connect_cb(dev, gerr);
	g_error_free(gerr);
	change_state(dev, GATEWAY_STATE_CONNECTED);
}

unsigned int gateway_add_state_cb(gateway_state_cb cb, void *user_data)
{
	struct gateway_state_callback *state_cb;
	static unsigned int id = 0;

	state_cb = g_new(struct gateway_state_callback, 1);
	state_cb->cb = cb;
	state_cb->user_data = user_data;
	state_cb->id = ++id;

	gateway_callbacks = g_slist_append(gateway_callbacks, state_cb);

	return state_cb->id;
}

gboolean gateway_remove_state_cb(unsigned int id)
{
	GSList *l;

	for (l = gateway_callbacks; l != NULL; l = l->next) {
		struct gateway_state_callback *cb = l->data;
		if (cb && cb->id == id) {
			gateway_callbacks = g_slist_remove(gateway_callbacks,
									cb);
			g_free(cb);
			return TRUE;
		}
	}

	return FALSE;
}

gateway_lock_t gateway_get_lock(struct audio_device *dev)
{
	struct gateway *gw = dev->gateway;

	return gw->lock;
}

gboolean gateway_lock(struct audio_device *dev, gateway_lock_t lock)
{
	struct gateway *gw = dev->gateway;

	if (gw->lock & lock)
		return FALSE;

	gw->lock |= lock;

	return TRUE;
}

gboolean gateway_unlock(struct audio_device *dev, gateway_lock_t lock)
{
	struct gateway *gw = dev->gateway;

	if (!(gw->lock & lock))
		return FALSE;

	gw->lock &= ~lock;

	if (gw->lock)
		return TRUE;

	if (gw->state == GATEWAY_STATE_PLAYING)
		gateway_suspend_stream(dev);

	return TRUE;
}
