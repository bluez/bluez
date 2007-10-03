/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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

#include <bluetooth/bluetooth.h>

#include "dbus.h"
#include "dbus-helper.h"
#include "logging.h"

#include "avdtp.h"
#include "device.h"
#include "a2dp.h"
#include "error.h"
#include "sink.h"

struct pending_request {
	DBusConnection *conn;
	DBusMessage *msg;
	unsigned int id;
};

struct sink {
	struct avdtp *session;
	struct avdtp_stream *stream;
	unsigned int cb_id;
	uint8_t state;
	struct pending_request *connect;
	struct pending_request *disconnect;
	DBusConnection *conn;
};

static void pending_request_free(struct pending_request *pending)
{
	if (pending->conn)
		dbus_connection_unref(pending->conn);
	if (pending->msg)
		dbus_message_unref(pending->msg);
	g_free(pending);
}

static void stream_state_changed(struct avdtp_stream *stream,
					avdtp_state_t old_state,
					avdtp_state_t new_state,
					struct avdtp_error *err,
					void *user_data)
{
	struct device *dev = user_data;
	struct sink *sink = dev->sink;

	if (err)
		return;

	switch (new_state) {
	case AVDTP_STATE_IDLE:
		dbus_connection_emit_signal(dev->conn, dev->path,
						AUDIO_SINK_INTERFACE,
						"Disconnected",
						DBUS_TYPE_INVALID);
		if (sink->disconnect) {
			DBusMessage *reply;
			struct pending_request *p;

			p = sink->disconnect;
			sink->disconnect = NULL;

			reply = dbus_message_new_method_return(p->msg);
			send_message_and_unref(p->conn, reply);
			pending_request_free(p);
		}

		if (sink->session) {
			avdtp_unref(sink->session);
			sink->session = NULL;
		}
		sink->stream = NULL;
		sink->cb_id = 0;
		break;
	case AVDTP_STATE_OPEN:
		if (old_state == AVDTP_STATE_CONFIGURED)
			dbus_connection_emit_signal(dev->conn, dev->path,
							AUDIO_SINK_INTERFACE,
							"Connected",
							DBUS_TYPE_INVALID);
		else if (old_state == AVDTP_STATE_STREAMING)
			dbus_connection_emit_signal(dev->conn, dev->path,
							AUDIO_SINK_INTERFACE,
							"Stopped",
							DBUS_TYPE_INVALID);
		break;
	case AVDTP_STATE_STREAMING:
		dbus_connection_emit_signal(dev->conn, dev->path,
						AUDIO_SINK_INTERFACE,
						"Playing",
						DBUS_TYPE_INVALID);
		break;
	case AVDTP_STATE_CONFIGURED:
	case AVDTP_STATE_CLOSING:
	case AVDTP_STATE_ABORTING:
	default:
		break;
	}

	sink->state = new_state;
}

static void stream_setup_complete(struct avdtp *session, struct a2dp_sep *sep,
					struct avdtp_stream *stream,
					void *user_data, struct avdtp_error *err)
{
	struct sink *sink = user_data;
	struct pending_request *pending;

	pending = sink->connect;
	sink->connect = NULL;

	if (stream) {
		DBusMessage *reply;
		reply = dbus_message_new_method_return(pending->msg);
		send_message_and_unref(pending->conn, reply);
		debug("Stream successfully created");
	} else {
		err_failed(pending->conn, pending->msg, "Stream setup failed");
		avdtp_unref(sink->session);
		sink->session = NULL;
		debug("Stream setup failed : %s", avdtp_strerror(err));
	}

	pending_request_free(pending);
}

static DBusHandlerResult sink_connect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct device *dev = data;
	struct sink *sink = dev->sink;
	struct pending_request *pending;
	unsigned int id;

	if (!sink->session)
		sink->session = avdtp_get(&dev->src, &dev->dst);

	if (!sink->session)
		return err_connect_failed(conn, msg,
						"Unable to get a session");

	if (sink->connect || sink->disconnect)
		return err_connect_failed(conn, msg, "Connect in progress");

	if (sink->state >= AVDTP_STATE_OPEN)
		return err_already_connected(conn, msg);

	pending = g_new0(struct pending_request, 1);
	pending->conn = dbus_connection_ref(conn);
	pending->msg = dbus_message_ref(msg);
	sink->connect = pending;

	id = a2dp_source_request_stream(sink->session, FALSE,
					stream_setup_complete, sink,
					NULL);
	if (id == 0) {
		pending_request_free(pending);
		sink->connect = NULL;
		avdtp_unref(sink->session);
		sink->session = NULL;
		return err_connect_failed(conn, msg,
						"Failed to request a stream");
	}

	debug("stream creation in progress");

	pending->id = id;

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult sink_disconnect(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *device = data;
	struct sink *sink = device->sink;
	struct pending_request *pending;
	int err;

	if (!sink->session)
		return err_not_connected(conn, msg);

	if (sink->connect || sink->disconnect)
		return err_failed(conn, msg, strerror(EBUSY));

	if (sink->state < AVDTP_STATE_OPEN) {
		DBusMessage *reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		avdtp_unref(sink->session);
		sink->session = NULL;
		return send_message_and_unref(conn, reply);
	}

	err = avdtp_close(sink->session, sink->stream);
	if (err < 0)
		return err_failed(conn, msg, strerror(-err));

	pending = g_new0(struct pending_request, 1);
	pending->conn = dbus_connection_ref(conn);
	pending->msg = dbus_message_ref(msg);
	sink->disconnect = pending;

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult sink_is_connected(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct device *device = data;
	struct sink *sink = device->sink;
	DBusMessage *reply;
	dbus_bool_t connected;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	connected = (sink->state >= AVDTP_STATE_CONFIGURED);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connected,
					DBUS_TYPE_INVALID);

	send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusMethodVTable sink_methods[] = {
	{ "Connect",		sink_connect,		"",	""	},
	{ "Disconnect",		sink_disconnect,	"",	""	},
	{ "IsConnected",	sink_is_connected,	"",	"b"	},
	{ NULL, NULL, NULL, NULL }
};

static DBusSignalVTable sink_signals[] = {
	{ "Connected",			""	},
	{ "Disconnected",		""	},
	{ "Playing",			""	},
	{ "Stopped",			""	},
	{ NULL, NULL }
};

struct sink *sink_init(struct device *dev)
{
	if (!dbus_connection_register_interface(dev->conn, dev->path,
						AUDIO_SINK_INTERFACE,
						sink_methods,
						sink_signals, NULL))
		return NULL;

	return g_new0(struct sink, 1);
}

void sink_free(struct device *dev)
{
	struct sink *sink = dev->sink;

	if (sink->cb_id)
		avdtp_stream_remove_cb(sink->session, sink->stream,
					sink->cb_id);

	if (sink->session)
		avdtp_unref(sink->session);

	if (sink->connect)
		pending_request_free(sink->connect);

	if (sink->disconnect)
		pending_request_free(sink->disconnect);

	g_free(sink);
	dev->sink = NULL;
}

gboolean sink_is_active(struct device *dev)
{
	struct sink *sink = dev->sink;

	if (sink->session)
		return TRUE;

	return FALSE;
}

avdtp_state_t sink_get_state(struct device *dev)
{
	struct sink *sink = dev->sink;

	return sink->state;
}

gboolean sink_new_stream(struct device *dev, struct avdtp *session,
				struct avdtp_stream *stream)
{
	struct sink *sink = dev->sink;

	if (sink->stream)
		return FALSE;

	if (!sink->session)
		sink->session = avdtp_ref(session);

	sink->stream = stream;

	sink->cb_id = avdtp_stream_add_cb(session, stream,
						stream_state_changed, dev);

	return TRUE;
}

