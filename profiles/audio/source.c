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
#include "source.h"
#include "dbus-common.h"

#define STREAM_SETUP_RETRY_TIMER 2

struct source {
	struct audio_device *dev;
	struct avdtp *session;
	struct avdtp_stream *stream;
	unsigned int cb_id;
	guint retry_id;
	avdtp_session_state_t session_state;
	avdtp_state_t stream_state;
	source_state_t state;
	unsigned int connect_id;
	unsigned int disconnect_id;
	unsigned int avdtp_callback_id;
};

struct source_state_callback {
	source_state_cb cb;
	struct audio_device *dev;
	void *user_data;
	unsigned int id;
};

static GSList *source_callbacks = NULL;

static char *str_state[] = {
	"SOURCE_STATE_DISCONNECTED",
	"SOURCE_STATE_CONNECTING",
	"SOURCE_STATE_CONNECTED",
	"SOURCE_STATE_PLAYING",
};

static void source_set_state(struct audio_device *dev, source_state_t new_state)
{
	struct source *source = dev->source;
	source_state_t old_state = source->state;
	GSList *l;

	source->state = new_state;

	DBG("State changed %s: %s -> %s", device_get_path(dev->btd_dev),
				str_state[old_state], str_state[new_state]);

	for (l = source_callbacks; l != NULL; l = l->next) {
		struct source_state_callback *cb = l->data;

		if (cb->dev != dev)
			continue;

		cb->cb(dev, old_state, new_state, cb->user_data);
	}

	if (new_state != SOURCE_STATE_DISCONNECTED)
		return;

	if (source->session) {
		avdtp_unref(source->session);
		source->session = NULL;
	}
}

static void avdtp_state_callback(struct audio_device *dev,
					struct avdtp *session,
					avdtp_session_state_t old_state,
					avdtp_session_state_t new_state)
{
	struct source *source = dev->source;

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
		audio_source_disconnected(dev->btd_dev, 0);

		if (source->disconnect_id > 0) {
			a2dp_cancel(dev, source->disconnect_id);
			source->disconnect_id = 0;
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

static gboolean stream_setup_retry(gpointer user_data)
{
	struct source *source = user_data;
	int err;

	source->retry_id = 0;

	if (source->stream_state >= AVDTP_STATE_OPEN) {
		DBG("Stream successfully created, after XCASE connect:connect");
		err = 0;
	} else {
		DBG("Stream setup failed, after XCASE connect:connect");
		err = -EIO;
	}

	audio_source_connected(source->dev->btd_dev, err);

	if (source->connect_id > 0) {
		a2dp_cancel(source->dev, source->connect_id);
		source->connect_id = 0;
	}

	return FALSE;
}

static void stream_setup_complete(struct avdtp *session, struct a2dp_sep *sep,
					struct avdtp_stream *stream,
					struct avdtp_error *err, void *user_data)
{
	struct source *source = user_data;

	source->connect_id = 0;

	if (stream) {
		DBG("Stream successfully created");
		audio_source_connected(source->dev->btd_dev, 0);
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
		DBG("Stream setup failed : %s", avdtp_strerror(err));
		audio_source_connected(source->dev->btd_dev, -EIO);
	}
}

static void select_complete(struct avdtp *session, struct a2dp_sep *sep,
			GSList *caps, void *user_data)
{
	struct source *source = user_data;
	int id;

	source->connect_id = 0;

	if (caps == NULL)
		goto failed;

	id = a2dp_config(session, sep, stream_setup_complete, caps, source);
	if (id == 0)
		goto failed;

	source->connect_id = id;
	return;

failed:
	audio_source_connected(source->dev->btd_dev, -EIO);

	avdtp_unref(source->session);
	source->session = NULL;
}

static void discovery_complete(struct avdtp *session, GSList *seps, struct avdtp_error *err,
				void *user_data)
{
	struct source *source = user_data;
	int id;

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

	source->connect_id = id;
	return;

failed:
	audio_source_connected(source->dev->btd_dev, -EIO);
	avdtp_unref(source->session);
	source->session = NULL;
}

gboolean source_setup_stream(struct source *source, struct avdtp *session)
{
	if (source->connect_id > 0 || source->disconnect_id > 0)
		return FALSE;

	if (session && !source->session)
		source->session = avdtp_ref(session);

	if (!source->session)
		return FALSE;

	if (avdtp_discover(source->session, discovery_complete, source) < 0)
		return FALSE;

	return TRUE;
}

int source_connect(struct audio_device *dev)
{
	struct source *source = dev->source;

	if (!source->session)
		source->session = avdtp_get(dev);

	if (!source->session) {
		DBG("Unable to get a session");
		return -EIO;
	}

	if (source->connect_id > 0 || source->disconnect_id > 0)
		return -EBUSY;

	if (source->stream_state >= AVDTP_STATE_OPEN)
		return -EALREADY;

	if (!source_setup_stream(source, NULL)) {
		DBG("Failed to create a stream");
		return -EIO;
	}

	DBG("stream creation in progress");

	return 0;
}

static void source_free(struct audio_device *dev)
{
	struct source *source = dev->source;

	if (source->cb_id)
		avdtp_stream_remove_cb(source->session, source->stream,
					source->cb_id);

	if (source->session)
		avdtp_unref(source->session);

	if (source->connect_id > 0) {
		audio_source_connected(dev->btd_dev, -ECANCELED);
		a2dp_cancel(dev, source->connect_id);
		source->connect_id = 0;
	}

	if (source->disconnect_id > 0) {
		audio_source_disconnected(dev->btd_dev, -ECANCELED);
		a2dp_cancel(dev, source->disconnect_id);
		source->disconnect_id = 0;
	}

	if (source->retry_id)
		g_source_remove(source->retry_id);

	avdtp_remove_state_cb(source->avdtp_callback_id);

	g_free(source);
	dev->source = NULL;
}

void source_unregister(struct audio_device *dev)
{
	DBG("%s", device_get_path(dev->btd_dev));

	source_free(dev);
}

struct source *source_init(struct audio_device *dev)
{
	struct source *source;

	DBG("%s", device_get_path(dev->btd_dev));

	source = g_new0(struct source, 1);

	source->dev = dev;

	source->avdtp_callback_id = avdtp_add_state_cb(dev,
							avdtp_state_callback);

	return source;
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

int source_disconnect(struct audio_device *dev, gboolean shutdown)
{
	struct source *source = dev->source;

	if (!source->session)
		return -ENOTCONN;

	if (shutdown)
		avdtp_set_device_disconnect(source->session, TRUE);

	/* cancel pending connect */
	if (source->connect_id > 0) {
		a2dp_cancel(dev, source->connect_id);
		source->connect_id = 0;
		audio_source_connected(dev->btd_dev, -ECANCELED);

		avdtp_unref(source->session);
		source->session = NULL;

		return 0;
	}

	/* disconnect already ongoing */
	if (source->disconnect_id > 0)
		return -EBUSY;

	if (!source->stream)
		return -ENOTCONN;

	return avdtp_close(source->session, source->stream, FALSE);
}

unsigned int source_add_state_cb(struct audio_device *dev, source_state_cb cb,
								void *user_data)
{
	struct source_state_callback *state_cb;
	static unsigned int id = 0;

	state_cb = g_new(struct source_state_callback, 1);
	state_cb->cb = cb;
	state_cb->dev = dev;
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
