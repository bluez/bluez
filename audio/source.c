/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2009  Joao Paulo Rechi Vita
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

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "log.h"

#include "device.h"
#include "avdtp.h"
#include "media.h"
#include "a2dp.h"
#include "error.h"
#include "source.h"
#include "dbus-common.h"
#include "../src/adapter.h"
#include "../src/device.h"

#define STREAM_SETUP_RETRY_TIMER 2

struct pending_request {
	DBusConnection *conn;
	DBusMessage *msg;
	unsigned int id;
};

struct source {
	struct audio_device *dev;
	struct avdtp *session;
	struct avdtp_stream *stream;
	unsigned int cb_id;
	guint retry_id;
	avdtp_session_state_t session_state;
	avdtp_state_t stream_state;
	source_state_t state;
	struct pending_request *connect;
	struct pending_request *disconnect;
	DBusConnection *conn;
};

struct source_state_callback {
	source_state_cb cb;
	void *user_data;
	unsigned int id;
};

static GSList *source_callbacks = NULL;

static unsigned int avdtp_callback_id = 0;

static const char *state2str(source_state_t state)
{
	switch (state) {
	case SOURCE_STATE_DISCONNECTED:
		return "disconnected";
	case SOURCE_STATE_CONNECTING:
		return "connecting";
	case SOURCE_STATE_CONNECTED:
		return "connected";
	case SOURCE_STATE_PLAYING:
		return "playing";
	default:
		error("Invalid source state %d", state);
		return NULL;
	}
}

static void source_set_state(struct audio_device *dev, source_state_t new_state)
{
	struct source *source = dev->source;
	const char *state_str;
	source_state_t old_state = source->state;
	GSList *l;

	source->state = new_state;

	state_str = state2str(new_state);
	if (state_str)
		emit_property_changed(dev->conn, dev->path,
					AUDIO_SOURCE_INTERFACE, "State",
					DBUS_TYPE_STRING, &state_str);

	for (l = source_callbacks; l != NULL; l = l->next) {
		struct source_state_callback *cb = l->data;
		cb->cb(dev, old_state, new_state, cb->user_data);
	}
}

static void avdtp_state_callback(struct audio_device *dev,
					struct avdtp *session,
					avdtp_session_state_t old_state,
					avdtp_session_state_t new_state,
					void *user_data)
{
	struct source *source = dev->source;

	if (source == NULL)
		return;

	switch (new_state) {
	case AVDTP_SESSION_STATE_DISCONNECTED:
		source_set_state(dev, SOURCE_STATE_DISCONNECTED);
		break;
	case AVDTP_SESSION_STATE_CONNECTING:
		source_set_state(dev, SOURCE_STATE_CONNECTING);
		break;
	case AVDTP_SESSION_STATE_CONNECTED:
		break;
	}

	source->session_state = new_state;
}

static void pending_request_free(struct audio_device *dev,
					struct pending_request *pending)
{
	if (pending->conn)
		dbus_connection_unref(pending->conn);
	if (pending->msg)
		dbus_message_unref(pending->msg);
	if (pending->id)
		a2dp_cancel(dev, pending->id);

	g_free(pending);
}

static void stream_state_changed(struct avdtp_stream *stream,
					avdtp_state_t old_state,
					avdtp_state_t new_state,
					struct avdtp_error *err,
					void *user_data)
{
	struct audio_device *dev = user_data;
	struct source *source = dev->source;

	if (err)
		return;

	switch (new_state) {
	case AVDTP_STATE_IDLE:
		if (source->disconnect) {
			DBusMessage *reply;
			struct pending_request *p;

			p = source->disconnect;
			source->disconnect = NULL;

			reply = dbus_message_new_method_return(p->msg);
			g_dbus_send_message(p->conn, reply);
			pending_request_free(dev, p);
		}

		if (source->session) {
			avdtp_unref(source->session);
			source->session = NULL;
		}
		source->stream = NULL;
		source->cb_id = 0;
		break;
	case AVDTP_STATE_OPEN:
		source_set_state(dev, SOURCE_STATE_CONNECTED);
		break;
	case AVDTP_STATE_STREAMING:
		source_set_state(dev, SOURCE_STATE_PLAYING);
		break;
	case AVDTP_STATE_CONFIGURED:
	case AVDTP_STATE_CLOSING:
	case AVDTP_STATE_ABORTING:
	default:
		break;
	}

	source->stream_state = new_state;
}

static void error_failed(DBusConnection *conn, DBusMessage *msg,
							const char *desc)
{
	DBusMessage *reply = btd_error_failed(msg, desc);
	g_dbus_send_message(conn, reply);
}

static gboolean stream_setup_retry(gpointer user_data)
{
	struct source *source = user_data;
	struct pending_request *pending = source->connect;

	source->retry_id = 0;

	if (source->stream_state >= AVDTP_STATE_OPEN) {
		DBG("Stream successfully created, after XCASE connect:connect");
		if (pending->msg) {
			DBusMessage *reply;
			reply = dbus_message_new_method_return(pending->msg);
			g_dbus_send_message(pending->conn, reply);
		}
	} else {
		DBG("Stream setup failed, after XCASE connect:connect");
		if (pending->msg)
			error_failed(pending->conn, pending->msg, "Stream setup failed");
	}

	source->connect = NULL;
	pending_request_free(source->dev, pending);

	return FALSE;
}

static void stream_setup_complete(struct avdtp *session, struct a2dp_sep *sep,
					struct avdtp_stream *stream,
					struct avdtp_error *err, void *user_data)
{
	struct source *source = user_data;
	struct pending_request *pending;

	pending = source->connect;

	pending->id = 0;

	if (stream) {
		DBG("Stream successfully created");

		if (pending->msg) {
			DBusMessage *reply;
			reply = dbus_message_new_method_return(pending->msg);
			g_dbus_send_message(pending->conn, reply);
		}

		source->connect = NULL;
		pending_request_free(source->dev, pending);

		return;
	}

	avdtp_unref(source->session);
	source->session = NULL;
	if (avdtp_error_category(err) == AVDTP_ERRNO
			&& avdtp_error_posix_errno(err) != EHOSTDOWN) {
		DBG("connect:connect XCASE detected");
		source->retry_id = g_timeout_add_seconds(STREAM_SETUP_RETRY_TIMER,
							stream_setup_retry,
							source);
	} else {
		if (pending->msg)
			error_failed(pending->conn, pending->msg, "Stream setup failed");
		source->connect = NULL;
		pending_request_free(source->dev, pending);
		DBG("Stream setup failed : %s", avdtp_strerror(err));
	}
}

static void select_complete(struct avdtp *session, struct a2dp_sep *sep,
			GSList *caps, void *user_data)
{
	struct source *source = user_data;
	struct pending_request *pending;
	int id;

	pending = source->connect;

	pending->id = 0;

	if (caps == NULL)
		goto failed;

	id = a2dp_config(session, sep, stream_setup_complete, caps, source);
	if (id == 0)
		goto failed;

	pending->id = id;
	return;

failed:
	if (pending->msg)
		error_failed(pending->conn, pending->msg, "Stream setup failed");
	pending_request_free(source->dev, pending);
	source->connect = NULL;
	avdtp_unref(source->session);
	source->session = NULL;
}

static void discovery_complete(struct avdtp *session, GSList *seps, struct avdtp_error *err,
				void *user_data)
{
	struct source *source = user_data;
	struct pending_request *pending;
	int id;

	pending = source->connect;

	if (err) {
		avdtp_unref(source->session);
		source->session = NULL;
		if (avdtp_error_category(err) == AVDTP_ERRNO
				&& avdtp_error_posix_errno(err) != EHOSTDOWN) {
			DBG("connect:connect XCASE detected");
			source->retry_id =
				g_timeout_add_seconds(STREAM_SETUP_RETRY_TIMER,
							stream_setup_retry,
							source);
		} else
			goto failed;
		return;
	}

	DBG("Discovery complete");

	id = a2dp_select_capabilities(source->session, AVDTP_SEP_TYPE_SOURCE, NULL,
						select_complete, source);
	if (id == 0)
		goto failed;

	pending->id = id;
	return;

failed:
	if (pending->msg)
		error_failed(pending->conn, pending->msg, "Stream setup failed");
	pending_request_free(source->dev, pending);
	source->connect = NULL;
	avdtp_unref(source->session);
	source->session = NULL;
}

gboolean source_setup_stream(struct source *source, struct avdtp *session)
{
	if (source->connect || source->disconnect)
		return FALSE;

	if (session && !source->session)
		source->session = avdtp_ref(session);

	if (!source->session)
		return FALSE;

	avdtp_set_auto_disconnect(source->session, FALSE);

	if (avdtp_discover(source->session, discovery_complete, source) < 0)
		return FALSE;

	source->connect = g_new0(struct pending_request, 1);

	return TRUE;
}

static DBusMessage *source_connect(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct audio_device *dev = data;
	struct source *source = dev->source;
	struct pending_request *pending;

	if (!source->session)
		source->session = avdtp_get(&dev->src, &dev->dst);

	if (!source->session)
		return btd_error_failed(msg, "Unable to get a session");

	if (source->connect || source->disconnect)
		return btd_error_busy(msg);

	if (source->stream_state >= AVDTP_STATE_OPEN)
		return btd_error_already_connected(msg);

	if (!source_setup_stream(source, NULL))
		return btd_error_failed(msg, "Failed to create a stream");

	dev->auto_connect = FALSE;

	pending = source->connect;

	pending->conn = dbus_connection_ref(conn);
	pending->msg = dbus_message_ref(msg);

	DBG("stream creation in progress");

	return NULL;
}

static DBusMessage *source_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	struct source *source = device->source;
	struct pending_request *pending;
	int err;

	if (!source->session)
		return btd_error_not_connected(msg);

	if (source->connect || source->disconnect)
		return btd_error_busy(msg);

	if (source->stream_state < AVDTP_STATE_OPEN) {
		DBusMessage *reply = dbus_message_new_method_return(msg);
		if (!reply)
			return NULL;
		avdtp_unref(source->session);
		source->session = NULL;
		return reply;
	}

	err = avdtp_close(source->session, source->stream, FALSE);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	pending = g_new0(struct pending_request, 1);
	pending->conn = dbus_connection_ref(conn);
	pending->msg = dbus_message_ref(msg);
	source->disconnect = pending;

	return NULL;
}

static DBusMessage *source_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	struct source *source = device->source;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	const char *state;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* State */
	state = state2str(source->state);
	if (state)
		dict_append_entry(&dict, "State", DBUS_TYPE_STRING, &state);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static GDBusMethodTable source_methods[] = {
	{ "Connect",		"",	"",	source_connect,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "Disconnect",		"",	"",	source_disconnect,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetProperties",	"",	"a{sv}",source_get_properties },
	{ NULL, NULL, NULL, NULL }
};

static GDBusSignalTable source_signals[] = {
	{ "PropertyChanged",		"sv"	},
	{ NULL, NULL }
};

static void source_free(struct audio_device *dev)
{
	struct source *source = dev->source;

	if (source->cb_id)
		avdtp_stream_remove_cb(source->session, source->stream,
					source->cb_id);

	if (source->session)
		avdtp_unref(source->session);

	if (source->connect)
		pending_request_free(dev, source->connect);

	if (source->disconnect)
		pending_request_free(dev, source->disconnect);

	if (source->retry_id)
		g_source_remove(source->retry_id);

	g_free(source);
	dev->source = NULL;
}

static void path_unregister(void *data)
{
	struct audio_device *dev = data;

	DBG("Unregistered interface %s on path %s",
		AUDIO_SOURCE_INTERFACE, dev->path);

	source_free(dev);
}

void source_unregister(struct audio_device *dev)
{
	g_dbus_unregister_interface(dev->conn, dev->path,
		AUDIO_SOURCE_INTERFACE);
}

struct source *source_init(struct audio_device *dev)
{
	struct source *source;

	if (!g_dbus_register_interface(dev->conn, dev->path,
					AUDIO_SOURCE_INTERFACE,
					source_methods, source_signals, NULL,
					dev, path_unregister))
		return NULL;

	DBG("Registered interface %s on path %s",
		AUDIO_SOURCE_INTERFACE, dev->path);

	if (avdtp_callback_id == 0)
		avdtp_callback_id = avdtp_add_state_cb(avdtp_state_callback,
									NULL);

	source = g_new0(struct source, 1);

	source->dev = dev;

	return source;
}

gboolean source_is_active(struct audio_device *dev)
{
	struct source *source = dev->source;

	if (source->session)
		return TRUE;

	return FALSE;
}

avdtp_state_t source_get_state(struct audio_device *dev)
{
	struct source *source = dev->source;

	return source->stream_state;
}

gboolean source_new_stream(struct audio_device *dev, struct avdtp *session,
				struct avdtp_stream *stream)
{
	struct source *source = dev->source;

	if (source->stream)
		return FALSE;

	if (!source->session)
		source->session = avdtp_ref(session);

	source->stream = stream;

	source->cb_id = avdtp_stream_add_cb(session, stream,
						stream_state_changed, dev);

	return TRUE;
}

gboolean source_shutdown(struct source *source)
{
	if (!source->stream)
		return FALSE;

	if (avdtp_close(source->session, source->stream, FALSE) < 0)
		return FALSE;

	return TRUE;
}

unsigned int source_add_state_cb(source_state_cb cb, void *user_data)
{
	struct source_state_callback *state_cb;
	static unsigned int id = 0;

	state_cb = g_new(struct source_state_callback, 1);
	state_cb->cb = cb;
	state_cb->user_data = user_data;
	state_cb->id = ++id;

	source_callbacks = g_slist_append(source_callbacks, state_cb);

	return state_cb->id;
}

gboolean source_remove_state_cb(unsigned int id)
{
	GSList *l;

	for (l = source_callbacks; l != NULL; l = l->next) {
		struct source_state_callback *cb = l->data;
		if (cb && cb->id == id) {
			source_callbacks = g_slist_remove(source_callbacks, cb);
			g_free(cb);
			return TRUE;
		}
	}

	return FALSE;
}
