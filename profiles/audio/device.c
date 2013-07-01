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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "lib/uuid.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/service.h"

#include "log.h"
#include "error.h"
#include "dbus-common.h"
#include "device.h"
#include "avdtp.h"
#include "control.h"
#include "avctp.h"
#include "avrcp.h"
#include "sink.h"
#include "source.h"

#define CONTROL_CONNECT_TIMEOUT 2
#define AVDTP_CONNECT_TIMEOUT 1
#define AVDTP_CONNECT_TIMEOUT_BOOST 1

struct dev_priv {
	btd_service_state_t sink_state;
	avctp_state_t avctp_state;

	guint control_timer;
	guint dc_id;

	gboolean disconnecting;

	unsigned int service_cb_id;
	unsigned int avdtp_callback_id;
	unsigned int avctp_callback_id;
};

static void device_free(struct audio_device *dev)
{
	struct dev_priv *priv = dev->priv;

	if (priv) {
		if (priv->control_timer)
			g_source_remove(priv->control_timer);
		if (priv->dc_id)
			device_remove_disconnect_watch(dev->btd_dev,
							priv->dc_id);

		avdtp_remove_state_cb(priv->avdtp_callback_id);
		avctp_remove_state_cb(priv->avctp_callback_id);
		btd_service_remove_state_cb(priv->service_cb_id);

		g_free(priv);
	}

	btd_device_unref(dev->btd_dev);

	g_free(dev);
}

static gboolean control_connect_timeout(gpointer user_data)
{
	struct audio_device *dev = user_data;

	dev->priv->control_timer = 0;

	if (dev->control)
		avrcp_connect(dev->btd_dev);

	return FALSE;
}

static gboolean device_set_control_timer(struct audio_device *dev)
{
	struct dev_priv *priv = dev->priv;

	if (!dev->control)
		return FALSE;

	if (priv->control_timer)
		return FALSE;

	priv->control_timer = g_timeout_add_seconds(CONTROL_CONNECT_TIMEOUT,
							control_connect_timeout,
							dev);

	return TRUE;
}

static void device_remove_control_timer(struct audio_device *dev)
{
	if (dev->priv->control_timer)
		g_source_remove(dev->priv->control_timer);
	dev->priv->control_timer = 0;
}

static void disconnect_cb(struct btd_device *btd_dev, gboolean removal,
				void *user_data)
{
	struct audio_device *dev = user_data;
	struct dev_priv *priv = dev->priv;
	struct btd_service *sink;

	if (priv->disconnecting)
		return;

	priv->disconnecting = TRUE;

	device_remove_control_timer(dev);

	if (dev->control && priv->avctp_state != AVCTP_STATE_DISCONNECTED)
		avrcp_disconnect(dev->btd_dev);

	sink = btd_device_get_service(btd_dev, A2DP_SINK_UUID);
	if (sink)
		sink_disconnect(sink, TRUE);
	else
		priv->disconnecting = FALSE;
}

static void device_avdtp_cb(struct btd_device *device, struct avdtp *session,
				avdtp_session_state_t old_state,
				avdtp_session_state_t new_state,
				void *user_data)
{
	struct audio_device *dev = user_data;

	if (!dev->control)
		return;

	if (new_state == AVDTP_SESSION_STATE_CONNECTED) {
		if (avdtp_stream_setup_active(session))
			device_set_control_timer(dev);
		else
			avrcp_connect(dev->btd_dev);
	}
}

static void device_sink_cb(struct audio_device *dev,
				btd_service_state_t old_state,
				btd_service_state_t new_state)
{
	struct dev_priv *priv = dev->priv;

	priv->sink_state = new_state;

	switch (new_state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
	case BTD_SERVICE_STATE_DISCONNECTED:
		if (dev->control) {
			device_remove_control_timer(dev);
			if (priv->avctp_state != AVCTP_STATE_DISCONNECTED)
				avrcp_disconnect(dev->btd_dev);
		}
		break;
	case BTD_SERVICE_STATE_CONNECTING:
	case BTD_SERVICE_STATE_CONNECTED:
	case BTD_SERVICE_STATE_DISCONNECTING:
		break;
	}
}

static void device_avctp_cb(struct btd_device *device, avctp_state_t old_state,
				avctp_state_t new_state, void *user_data)
{
	struct audio_device *dev = user_data;

	if (!dev->control)
		return;

	dev->priv->avctp_state = new_state;

	switch (new_state) {
	case AVCTP_STATE_DISCONNECTED:
		break;
	case AVCTP_STATE_CONNECTING:
		device_remove_control_timer(dev);
		break;
	case AVCTP_STATE_CONNECTED:
		break;
	case AVCTP_STATE_BROWSING_CONNECTING:
		break;
	case AVCTP_STATE_BROWSING_CONNECTED:
		break;
	}
}

static void service_cb(struct btd_service *service,
						btd_service_state_t old_state,
						btd_service_state_t new_state,
						void *user_data)
{
	struct audio_device *dev = user_data;

	if (dev->btd_dev != btd_service_get_device(service))
		return;

	if (service == dev->sink)
		device_sink_cb(dev, old_state, new_state);
}

struct audio_device *audio_device_register(struct btd_device *device)
{
	struct audio_device *dev;

	DBG("%s", device_get_path(device));

	dev = g_new0(struct audio_device, 1);

	dev->btd_dev = btd_device_ref(device);
	dev->priv = g_new0(struct dev_priv, 1);

	dev->priv->dc_id = device_add_disconnect_watch(dev->btd_dev,
							disconnect_cb, dev,
							NULL);
	dev->priv->service_cb_id = btd_service_add_state_cb(service_cb, dev);
	dev->priv->avdtp_callback_id = avdtp_add_state_cb(device,
							device_avdtp_cb, dev);
	dev->priv->avctp_callback_id = avctp_add_state_cb(device,
							device_avctp_cb, dev);

	return dev;
}

void audio_device_unregister(struct audio_device *device)
{
	DBG("%s", device_get_path(device->btd_dev));

	if (device->sink)
		sink_unregister(device->sink);

	if (device->source)
		source_unregister(device->source);

	if (device->control)
		control_unregister(device->control);

	device_free(device);
}
