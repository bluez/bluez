/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
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
#include <sys/stat.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "logging.h"
#include "textfile.h"

#include "error.h"
#include "ipc.h"
#include "device.h"
#include "avdtp.h"
#include "control.h"
#include "headset.h"
#include "sink.h"

#define CONTROL_CONNECT_TIMEOUT 2

static unsigned int avdtp_callback_id = 0;
static unsigned int avctp_callback_id = 0;

static void device_free(struct audio_device *dev)
{
	if (dev->conn)
		dbus_connection_unref(dev->conn);

	if (dev->control_timer)
		g_source_remove(dev->control_timer);

	g_free(dev->path);
	g_free(dev);
}

static gboolean control_connect_timeout(gpointer user_data)
{
	struct audio_device *dev = user_data;

	dev->control_timer = 0;

	if (dev->control)
		avrcp_connect(dev);

	return FALSE;
}

static gboolean device_set_control_timer(struct audio_device *dev)
{
	if (!dev->control)
		return FALSE;

	if (dev->control_timer)
		return FALSE;

	dev->control_timer = g_timeout_add_seconds(CONTROL_CONNECT_TIMEOUT,
							control_connect_timeout,
							dev);

	return TRUE;
}

static void device_remove_control_timer(struct audio_device *dev)
{
	if (dev->control_timer)
		g_source_remove(dev->control_timer);
	dev->control_timer = 0;
}

static void device_avdtp_cb(struct audio_device *dev,
				struct avdtp *session,
				avdtp_session_state_t old_state,
				avdtp_session_state_t new_state,
				void *user_data)
{
	if (!dev->control || !dev->sink)
		return;

	switch (new_state) {
	case AVDTP_SESSION_STATE_DISCONNECTED:
		device_remove_control_timer(dev);
		avrcp_disconnect(dev);
		break;
	case AVDTP_SESSION_STATE_CONNECTING:
		break;
	case AVDTP_SESSION_STATE_CONNECTED:
		if (avdtp_stream_setup_active(session))
			device_set_control_timer(dev);
		else
			avrcp_connect(dev);
		break;
	}
}

static void device_avctp_cb(struct audio_device *dev,
				avctp_state_t old_state,
				avctp_state_t new_state,
				void *user_data)
{
	if (!dev->control)
		return;

	switch (new_state) {
	case AVCTP_STATE_DISCONNECTED:
		break;
	case AVCTP_STATE_CONNECTING:
		device_remove_control_timer(dev);
		break;
	case AVCTP_STATE_CONNECTED:
		break;
	}
}

struct audio_device *audio_device_register(DBusConnection *conn,
					const char *path, const bdaddr_t *src,
					const bdaddr_t *dst)
{
	struct audio_device *dev;

	if (!conn || !path)
		return NULL;

	dev = g_new0(struct audio_device, 1);

	dev->path = g_strdup(path);
	bacpy(&dev->dst, dst);
	bacpy(&dev->src, src);
	dev->conn = dbus_connection_ref(conn);

	if (avdtp_callback_id == 0)
		avdtp_callback_id = avdtp_add_state_cb(device_avdtp_cb, NULL);

	if (avctp_callback_id == 0)
		avctp_callback_id = avctp_add_state_cb(device_avctp_cb, NULL);

	return dev;
}

gboolean audio_device_is_connected(struct audio_device *dev,
						const char *interface)
{
	if (!interface) {
		if ((dev->sink || dev->source) &&
			avdtp_is_connected(&dev->src, &dev->dst))
			return TRUE;

		if (dev->headset && headset_is_active(dev))
			return TRUE;
	}
	else if (!strcmp(interface, AUDIO_SINK_INTERFACE) && dev->sink &&
			avdtp_is_connected(&dev->src, &dev->dst))
		return TRUE;
	else if (!strcmp(interface, AUDIO_SOURCE_INTERFACE) && dev->source &&
			avdtp_is_connected(&dev->src, &dev->dst))
		return TRUE;
	else if (!strcmp(interface, AUDIO_HEADSET_INTERFACE) && dev->headset &&
			headset_is_active(dev))
		return TRUE;
	else if (!strcmp(interface, AUDIO_CONTROL_INTERFACE) && dev->control &&
			control_is_active(dev))
		return TRUE;

	return FALSE;
}

void audio_device_unregister(struct audio_device *device)
{
	if (device->headset)
		headset_unregister(device);

	if (device->sink)
		sink_unregister(device);

	if (device->control)
		control_unregister(device);

	device_free(device);
}
