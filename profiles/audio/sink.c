/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdbool.h>
#include <errno.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "log.h"

#include "../src/adapter.h"
#include "../src/device.h"

#include "device.h"
#include "avdtp.h"
#include "media.h"
#include "a2dp.h"
#include "error.h"
#include "manager.h"
#include "sink.h"
#include "dbus-common.h"

#define STREAM_SETUP_RETRY_TIMER 2

struct sink {
	struct audio_device *dev;
	struct avdtp *session;
	struct avdtp_stream *stream;
	unsigned int cb_id;
	guint retry_id;
	avdtp_session_state_t session_state;
	avdtp_state_t stream_state;
	sink_state_t state;
	unsigned int connect_id;
	unsigned int disconnect_id;
	unsigned int avdtp_callback_id;
};

struct sink_state_callback {
	sink_state_cb cb;
	struct audio_device *dev;
	void *user_data;
	unsigned int id;
};

static GSList *sink_callbacks = NULL;

static char *str_state[] = {
	"SINK_STATE_DISCONNECTED",
	"SINK_STATE_CONNECTING",
	"SINK_STATE_CONNECTED",
	"SINK_STATE_PLAYING",
};

static void sink_set_state(struct audio_device *dev, sink_state_t new_state)
{
	struct sink *sink = dev->sink;
	sink_state_t old_state = sink->state;
	GSList *l;

	sink->state = new_state;

	DBG("State changed %s: %s -> %s", device_get_path(dev->btd_dev),
				str_state[old_state], str_state[new_state]);

	for (l = sink_callbacks; l != NULL; l = l->next) {
		struct sink_state_callback *cb = l->data;

		if (cb->dev != dev)
			continue;

		cb->cb(dev, old_state, new_state, cb->user_data);
	}

	if (new_state != SINK_STATE_DISCONNECTED)
		return;

	if (sink->session) {
		avdtp_unref(sink->session);
		sink->session = NULL;
	}
}

static void avdtp_state_callback(struct audio_device *dev,
					struct avdtp *session,
					avdtp_session_state_t old_state,
					avdtp_session_state_t new_state)
{
	struct sink *sink = dev->sink;

	switch (new_state) {
	case AVDTP_SESSION_STATE_DISCONNECTED:
		sink_set_state(dev, SINK_STATE_DISCONNECTED);
		break;
	case AVDTP_SESSION_STATE_CONNECTING:
		sink_set_state(dev, SINK_STATE_CONNECTING);
		break;
	case AVDTP_SESSION_STATE_CONNECTED:
		break;
	}

	sink->session_state = new_state;
}

static void stream_state_changed(struct avdtp_stream *stream,
					avdtp_state_t old_state,
					avdtp_state_t new_state,
					struct avdtp_error *err,
					void *user_data)
{
	struct audio_device *dev = user_data;
	struct sink *sink = dev->sink;

	if (err)
		return;

	switch (new_state) {
	case AVDTP_STATE_IDLE:
		audio_sink_disconnected(dev->btd_dev, 0);

		if (sink->disconnect_id > 0) {
			a2dp_cancel(dev, sink->disconnect_id);
			sink->disconnect_id = 0;
		}

		if (sink->session) {
			avdtp_unref(sink->session);
			sink->session = NULL;
		}
		sink->stream = NULL;
		sink->cb_id = 0;
		break;
	case AVDTP_STATE_OPEN:
		sink_set_state(dev, SINK_STATE_CONNECTED);
		break;
	case AVDTP_STATE_STREAMING:
		sink_set_state(dev, SINK_STATE_PLAYING);
		break;
	case AVDTP_STATE_CONFIGURED:
	case AVDTP_STATE_CLOSING:
	case AVDTP_STATE_ABORTING:
	default:
		break;
	}

	sink->stream_state = new_state;
}

static gboolean stream_setup_retry(gpointer user_data)
{
	struct sink *sink = user_data;
	int err;

	sink->retry_id = 0;

	if (sink->stream_state >= AVDTP_STATE_OPEN) {
		DBG("Stream successfully created, after XCASE connect:connect");
		err = 0;
	} else {
		DBG("Stream setup failed, after XCASE connect:connect");
		err = -EIO;
	}

	audio_sink_connected(sink->dev->btd_dev, err);

	if (sink->connect_id > 0) {
		a2dp_cancel(sink->dev, sink->connect_id);
		sink->connect_id = 0;
	}

	return FALSE;
}

static void stream_setup_complete(struct avdtp *session, struct a2dp_sep *sep,
					struct avdtp_stream *stream,
					struct avdtp_error *err, void *user_data)
{
	struct sink *sink = user_data;

	sink->connect_id = 0;

	if (stream) {
		DBG("Stream successfully created");
		audio_sink_connected(sink->dev->btd_dev, 0);
		return;
	}

	avdtp_unref(sink->session);
	sink->session = NULL;
	if (avdtp_error_category(err) == AVDTP_ERRNO
			&& avdtp_error_posix_errno(err) != EHOSTDOWN) {
		DBG("connect:connect XCASE detected");
		sink->retry_id = g_timeout_add_seconds(STREAM_SETUP_RETRY_TIMER,
							stream_setup_retry,
							sink);
	} else {
		DBG("Stream setup failed : %s", avdtp_strerror(err));
		audio_sink_connected(sink->dev->btd_dev, -EIO);
	}
}

static void select_complete(struct avdtp *session, struct a2dp_sep *sep,
			GSList *caps, void *user_data)
{
	struct sink *sink = user_data;
	int id;

	sink->connect_id = 0;

	id = a2dp_config(session, sep, stream_setup_complete, caps, sink);
	if (id == 0)
		goto failed;

	sink->connect_id = id;
	return;

failed:
	audio_sink_connected(sink->dev->btd_dev, -EIO);

	avdtp_unref(sink->session);
	sink->session = NULL;
}

static void discovery_complete(struct avdtp *session, GSList *seps, struct avdtp_error *err,
				void *user_data)
{
	struct sink *sink = user_data;
	int id;

	if (err) {
		avdtp_unref(sink->session);
		sink->session = NULL;
		if (avdtp_error_category(err) == AVDTP_ERRNO
				&& avdtp_error_posix_errno(err) != EHOSTDOWN) {
			DBG("connect:connect XCASE detected");
			sink->retry_id =
				g_timeout_add_seconds(STREAM_SETUP_RETRY_TIMER,
							stream_setup_retry,
							sink);
		} else
			goto failed;
		return;
	}

	DBG("Discovery complete");

	id = a2dp_select_capabilities(sink->session, AVDTP_SEP_TYPE_SINK, NULL,
						select_complete, sink);
	if (id == 0)
		goto failed;

	sink->connect_id = id;
	return;

failed:
	audio_sink_connected(sink->dev->btd_dev, -EIO);
	avdtp_unref(sink->session);
	sink->session = NULL;
}

gboolean sink_setup_stream(struct sink *sink, struct avdtp *session)
{
	if (sink->connect_id > 0 || sink->disconnect_id > 0)
		return FALSE;

	if (session && !sink->session)
		sink->session = avdtp_ref(session);

	if (!sink->session)
		return FALSE;

	if (avdtp_discover(sink->session, discovery_complete, sink) < 0)
		return FALSE;

	return TRUE;
}

int sink_connect(struct audio_device *dev)
{
	struct sink *sink = dev->sink;

	if (!sink->session)
		sink->session = avdtp_get(dev);

	if (!sink->session) {
		DBG("Unable to get a session");
		return -EIO;
	}

	if (sink->connect_id > 0 || sink->disconnect_id > 0)
		return -EBUSY;

	if (sink->stream_state >= AVDTP_STATE_OPEN)
		return -EALREADY;

	if (!sink_setup_stream(sink, NULL)) {
		DBG("Failed to create a stream");
		return -EIO;
	}

	DBG("stream creation in progress");

	return 0;
}

static void sink_free(struct audio_device *dev)
{
	struct sink *sink = dev->sink;

	if (sink->cb_id)
		avdtp_stream_remove_cb(sink->session, sink->stream,
					sink->cb_id);

	if (sink->session)
		avdtp_unref(sink->session);

	if (sink->connect_id > 0) {
		audio_sink_connected(dev->btd_dev, -ECANCELED);
		a2dp_cancel(dev, sink->connect_id);
		sink->connect_id = 0;
	}

	if (sink->disconnect_id > 0) {
		audio_sink_disconnected(dev->btd_dev, -ECANCELED);
		a2dp_cancel(dev, sink->disconnect_id);
		sink->disconnect_id = 0;
	}

	if (sink->retry_id)
		g_source_remove(sink->retry_id);

	avdtp_remove_state_cb(sink->avdtp_callback_id);

	g_free(sink);
	dev->sink = NULL;
}

void sink_unregister(struct audio_device *dev)
{
	DBG("%s", device_get_path(dev->btd_dev));
	sink_free(dev);
}

struct sink *sink_init(struct audio_device *dev)
{
	struct sink *sink;

	DBG("%s", device_get_path(dev->btd_dev));

	sink = g_new0(struct sink, 1);

	sink->dev = dev;

	sink->avdtp_callback_id = avdtp_add_state_cb(dev, avdtp_state_callback);

	return sink;
}

gboolean sink_is_active(struct audio_device *dev)
{
	struct sink *sink = dev->sink;

	if (sink->session)
		return TRUE;

	return FALSE;
}

gboolean sink_new_stream(struct audio_device *dev, struct avdtp *session,
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

int sink_disconnect(struct audio_device *dev, gboolean shutdown)
{
	struct sink *sink = dev->sink;

	if (!sink->session)
		return -ENOTCONN;

	if (shutdown)
		avdtp_set_device_disconnect(sink->session, TRUE);

	/* cancel pending connect */
	if (sink->connect_id > 0) {
		a2dp_cancel(dev, sink->connect_id);
		sink->connect_id = 0;
		audio_sink_connected(dev->btd_dev, -ECANCELED);

		avdtp_unref(sink->session);
		sink->session = NULL;

		return 0;
	}

	/* disconnect already ongoing */
	if (sink->disconnect_id > 0)
		return -EBUSY;

	if (!sink->stream)
		return -ENOTCONN;

	return avdtp_close(sink->session, sink->stream, FALSE);
}

unsigned int sink_add_state_cb(struct audio_device *dev, sink_state_cb cb,
								void *user_data)
{
	struct sink_state_callback *state_cb;
	static unsigned int id = 0;

	state_cb = g_new(struct sink_state_callback, 1);
	state_cb->cb = cb;
	state_cb->dev = dev;
	state_cb->user_data = user_data;
	state_cb->id = ++id;

	sink_callbacks = g_slist_append(sink_callbacks, state_cb);

	return state_cb->id;
}

gboolean sink_remove_state_cb(unsigned int id)
{
	GSList *l;

	for (l = sink_callbacks; l != NULL; l = l->next) {
		struct sink_state_callback *cb = l->data;
		if (cb && cb->id == id) {
			sink_callbacks = g_slist_remove(sink_callbacks, cb);
			g_free(cb);
			return TRUE;
		}
	}

	return FALSE;
}
