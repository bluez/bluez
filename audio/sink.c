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
#include "ipc.h"
#include "device.h"
#include "a2dp.h"
#include "error.h"
#include "unix.h"
#include "sink.h"

struct pending_request {
	DBusMessage *msg;
	struct ipc_packet *pkt;
	int pkt_len;
	int sock;
};

struct sink {
	struct avdtp *session;
	struct avdtp_stream *stream;
	uint8_t state;
	struct pending_request *c;
	DBusConnection *conn;
	gboolean initiator;
};

static void pending_connect_free(struct pending_request *c)
{
	if (c->pkt)
		g_free(c->pkt);
	if (c->msg)
		dbus_message_unref(c->msg);
	g_free(c);
}

void stream_state_changed(struct avdtp_stream *stream, avdtp_state_t old_state,
				avdtp_state_t new_state,
				struct avdtp_error *err, void *user_data)
{
	struct device *dev = user_data;
	struct sink *sink = dev->sink;
	struct pending_request *c = NULL;
	DBusMessage *reply;
	int cmd_err;

	if (err)
		goto failed;

	switch (new_state) {
	case AVDTP_STATE_IDLE:
		dbus_connection_emit_signal(dev->conn, dev->path,
						AUDIO_SINK_INTERFACE,
						"Disconnected",
						DBUS_TYPE_INVALID);
		if (sink->session) {
			avdtp_unref(sink->session);
			sink->session = NULL;
		}
		sink->stream = NULL;
		c = sink->c;
		break;
	case AVDTP_STATE_CONFIGURED:
		if (!sink->initiator)
			break;

		cmd_err = avdtp_open(sink->session, stream);
		if (cmd_err < 0) {
			error("Error on avdtp_open %s (%d)", strerror(-cmd_err),
				cmd_err);
			goto failed;
		}
		break;
	case AVDTP_STATE_OPEN:
		if (old_state == AVDTP_STATE_CONFIGURED)
			dbus_connection_emit_signal(dev->conn, dev->path,
							AUDIO_SINK_INTERFACE,
							"Connected",
							DBUS_TYPE_INVALID);

		if (!sink->initiator)
			break;

		if (sink->c && sink->c->pkt) {
			cmd_err = avdtp_start(sink->session, stream);
			if (cmd_err < 0) {
				error("Error on avdtp_start %s (%d)",
					strerror(-cmd_err), cmd_err);
				goto failed;
			}
		}
		else
			c = sink->c;
		break;
	case AVDTP_STATE_STREAMING:
		c = sink->c;
		break;
	case AVDTP_STATE_CLOSING:
		break;
	case AVDTP_STATE_ABORTING:
		break;
	}

	sink->state = new_state;

	if (c) {
		if (c->msg) {
			reply = dbus_message_new_method_return(c->msg);
			send_message_and_unref(dev->conn, reply);
		}
		if (c->pkt) {
			struct ipc_data_cfg *rsp;
			int ret, fd;

			ret = sink_get_config(dev, c->sock, c->pkt,
						c->pkt_len, &rsp, &fd);
			if (ret == 0) {
				unix_send_cfg(c->sock, rsp, fd);
				g_free(rsp);
			}
			else
				unix_send_cfg(c->sock, NULL, -1);
		}

		pending_connect_free(c);
		sink->c = NULL;
	}

	return;

failed:
	if (sink->c) {
		if (sink->c->msg && err)
			err_failed(dev->conn, sink->c->msg,
					avdtp_strerror(err));

		pending_connect_free(sink->c);
		sink->c = NULL;
	}

	if (new_state == AVDTP_STATE_IDLE) {
		avdtp_unref(sink->session);
		sink->session = NULL;
		sink->stream = NULL;
	}
}

static void discovery_complete(struct avdtp *session, GSList *seps, int err,
				void *user_data)
{
	struct device *dev = user_data;
	struct sink *sink = dev->sink;
	struct avdtp_local_sep *lsep;
	struct avdtp_remote_sep *rsep;
	GSList *caps = NULL;
	const char *err_str = NULL;

	if (err < 0) {
		error("Discovery failed");
		err_str = strerror(-err);
		goto failed;
	}

	debug("Discovery complete");

	if (avdtp_get_seps(session, AVDTP_SEP_TYPE_SINK, AVDTP_MEDIA_TYPE_AUDIO,
				A2DP_CODEC_SBC, &lsep, &rsep) < 0) {
		err_str = "No matching ACP and INT SEPs found";
		goto failed;
	}

	if (!a2dp_select_capabilities(rsep, &caps)) {
		err_str = "Unable to select remote SEP capabilities";
		goto failed;
	}

	err = avdtp_set_configuration(session, rsep, lsep, caps,
					&sink->stream);
	if (err < 0) {
		error("avdtp_set_configuration: %s", strerror(-err));
		err_str = "Unable to set configuration";
		goto failed;
	}

	sink->initiator = TRUE;

	avdtp_stream_set_cb(session, sink->stream, stream_state_changed, dev);

	return;

failed:
	error("%s", err_str);
	if (sink->c) {
		if (sink->c->msg)
			err_failed(dev->conn, sink->c->msg, err_str);
		pending_connect_free(sink->c);
		sink->c = NULL;
	}
	if (sink->session) {
		avdtp_unref(sink->session);
		sink->session = NULL;
	}
}

static DBusHandlerResult sink_connect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct device *dev = data;
	struct sink *sink = dev->sink;
	struct pending_request *c;
	int err;

	if (!sink->session)
		sink->session = avdtp_get(&dev->src, &dev->dst);

	if (sink->c)
		return err_connect_failed(conn, msg, "Connect in progress");

	if (sink->state >= AVDTP_STATE_OPEN)
		return err_already_connected(conn, msg);

	c = g_new0(struct pending_request, 1);
	c->msg = dbus_message_ref(msg);
	sink->c = c;

	err = avdtp_discover(sink->session, discovery_complete, data);
	if (err < 0) {
		pending_connect_free(c);
		sink->c = NULL;
		avdtp_unref(sink->session);
		sink->session = NULL;
		return err_connect_failed(conn, msg, strerror(err));
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult sink_disconnect(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *device = data;
	struct sink *sink = device->sink;
	struct pending_request *c;
	int err;

	if (!sink->session)
		return err_not_connected(conn, msg);

	if (sink->c)
		return err_failed(conn, msg, strerror(EBUSY));

	if (sink->state < AVDTP_STATE_OPEN) {
		avdtp_unref(sink->session);
		sink->session = NULL;
	} else {
		err = avdtp_close(sink->session, sink->stream);
		if (err < 0)
			return err_failed(conn, msg, strerror(-err));
	}

	c = g_new0(struct pending_request, 1);
	c->msg = dbus_message_ref(msg);
	sink->c = c;

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

	if (sink->session)
		avdtp_unref(sink->session);

	if (sink->c)
		pending_connect_free(sink->c);

	g_free(sink);
	dev->sink = NULL;
}

int sink_get_config(struct device *dev, int sock, struct ipc_packet *req,
			int pkt_len, struct ipc_data_cfg **rsp, int *fd)
{
	struct sink *sink = dev->sink;
	int err;
	struct pending_request *c = NULL;

	if (sink->state == AVDTP_STATE_STREAMING)
		goto proceed;

	if (sink->c) {
		error("sink_get_config: another request already in progress");
		return -EBUSY;
	}

	if (!sink->session)
		sink->session = avdtp_get(&dev->src, &dev->dst);

	c = g_new0(struct pending_request, 1);
	c->sock = sock;
	c->pkt = g_malloc(pkt_len);
	memcpy(c->pkt, req, pkt_len);

	if (sink->state == AVDTP_STATE_IDLE)
		err = avdtp_discover(sink->session, discovery_complete, dev);
	else if (sink->state < AVDTP_STATE_STREAMING)
		err = avdtp_start(sink->session, sink->stream);
	else
		err = -EINVAL;

	if (err < 0)
		goto failed;

	sink->c = c;

	return 1;

proceed:
	if (!a2dp_get_config(sink->stream, rsp, fd)) {
		err = -EINVAL;
		goto failed;
	}

	return 0;

failed:
	if (c)
		pending_connect_free(c);
	return -err;
}

gboolean sink_is_active(struct device *dev)
{
	struct sink *sink = dev->sink;

	if (sink->session)
		return TRUE;

	return FALSE;
}

void sink_set_state(struct device *dev, avdtp_state_t state)
{
	struct sink *sink = dev->sink;
	int err = 0;

	if (sink->state == state)
		return;

	if (!sink->session || !sink->stream)
		goto failed;

	switch (sink->state) {
	case AVDTP_STATE_OPEN:
		if (state == AVDTP_STATE_STREAMING) {
			err = avdtp_start(sink->session, sink->stream);
			if (err == 0)
				return;
		}
		else if (state == AVDTP_STATE_IDLE) {
			err = avdtp_close(sink->session, sink->stream);
			if (err == 0)
				return;
		}
		break;
	case AVDTP_STATE_STREAMING:
		if (state == AVDTP_STATE_OPEN) {
			err = avdtp_suspend(sink->session, sink->stream);
			if (err == 0)
				return;
		}
		else if (state == AVDTP_STATE_IDLE) {
			err = avdtp_close(sink->session, sink->stream);
			if (err == 0)
				return;
		}
		break;
	default:
		goto failed;
	}

failed:
	error("%s: Error changing states", dev->path);
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
	sink->initiator = FALSE;

	avdtp_stream_set_cb(session, stream, stream_state_changed, dev);

	return TRUE;
}

