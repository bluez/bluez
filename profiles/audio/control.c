/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2011  Texas Instruments, Inc.
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

#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "lib/uuid.h"
#include "../src/adapter.h"
#include "../src/device.h"
#include "../src/profile.h"
#include "../src/service.h"

#include "log.h"
#include "error.h"
#include "device.h"
#include "manager.h"
#include "avctp.h"
#include "control.h"
#include "sdpd.h"
#include "glib-helper.h"
#include "dbus-common.h"

struct control {
	struct avctp *session;
	struct btd_service *target;
	struct btd_service *remote;
	unsigned int avctp_id;
};

void control_target_connected(struct control *control, int err)
{
	btd_service_connecting_complete(control->target, err);
}

void control_target_disconnected(struct control *control, int err)
{
	btd_service_disconnecting_complete(control->target, err);
}

void control_remote_connected(struct control *control, int err)
{
	btd_service_connecting_complete(control->remote, err);
}

void control_remote_disconnected(struct control *control, int err)
{
	btd_service_disconnecting_complete(control->remote, err);
}

static void state_changed(struct audio_device *dev, avctp_state_t old_state,
							avctp_state_t new_state)
{
	DBusConnection *conn = btd_get_dbus_connection();
	struct control *control = dev->control;
	const char *path = device_get_path(dev->btd_dev);

	switch (new_state) {
	case AVCTP_STATE_DISCONNECTED:
		control->session = NULL;

		g_dbus_emit_property_changed(conn, path,
					AUDIO_CONTROL_INTERFACE, "Connected");

		break;
	case AVCTP_STATE_CONNECTING:
		if (control->session)
			break;

		control->session = avctp_get(dev);

		break;
	case AVCTP_STATE_CONNECTED:
		g_dbus_emit_property_changed(conn, path,
					AUDIO_CONTROL_INTERFACE, "Connected");
		break;
	default:
		return;
	}
}

int control_connect(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (control->session)
		return -EALREADY;

	if (!control->target)
		return -ENOTSUP;

	control->session = avctp_connect(dev);
	if (!control->session)
		return -EIO;

	return 0;
}

int control_disconnect(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (!control->session)
		return -ENOTCONN;

	avctp_disconnect(control->session);

	return 0;
}

static DBusMessage *key_pressed(DBusConnection *conn, DBusMessage *msg,
						uint8_t op, void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	int err;

	if (!control->session)
		return btd_error_not_connected(msg);

	if (!control->target)
		return btd_error_not_supported(msg);

	err = avctp_send_passthrough(control->session, op);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return dbus_message_new_method_return(msg);
}

static DBusMessage *control_volume_up(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	return key_pressed(conn, msg, AVC_VOLUME_UP, data);
}

static DBusMessage *control_volume_down(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	return key_pressed(conn, msg, AVC_VOLUME_DOWN, data);
}

static DBusMessage *control_play(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	return key_pressed(conn, msg, AVC_PLAY, data);
}

static DBusMessage *control_pause(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	return key_pressed(conn, msg, AVC_PAUSE, data);
}

static DBusMessage *control_stop(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	return key_pressed(conn, msg, AVC_STOP, data);
}

static DBusMessage *control_next(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	return key_pressed(conn, msg, AVC_FORWARD, data);
}

static DBusMessage *control_previous(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	return key_pressed(conn, msg, AVC_BACKWARD, data);
}

static DBusMessage *control_fast_forward(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	return key_pressed(conn, msg, AVC_FAST_FORWARD, data);
}

static DBusMessage *control_rewind(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	return key_pressed(conn, msg, AVC_REWIND, data);
}

static gboolean control_property_get_connected(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct audio_device *device = data;
	dbus_bool_t value = (device->control->session != NULL);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &value);

	return TRUE;
}

static const GDBusMethodTable control_methods[] = {
	{ GDBUS_METHOD("Play", NULL, NULL, control_play) },
	{ GDBUS_METHOD("Pause", NULL, NULL, control_pause) },
	{ GDBUS_METHOD("Stop", NULL, NULL, control_stop) },
	{ GDBUS_METHOD("Next", NULL, NULL, control_next) },
	{ GDBUS_METHOD("Previous", NULL, NULL, control_previous) },
	{ GDBUS_METHOD("VolumeUp", NULL, NULL, control_volume_up) },
	{ GDBUS_METHOD("VolumeDown", NULL, NULL, control_volume_down) },
	{ GDBUS_METHOD("FastForward", NULL, NULL, control_fast_forward) },
	{ GDBUS_METHOD("Rewind", NULL, NULL, control_rewind) },
	{ }
};

static const GDBusPropertyTable control_properties[] = {
	{ "Connected", "b", control_property_get_connected },
	{ }
};

static void path_unregister(void *data)
{
	struct audio_device *dev = data;
	struct control *control = dev->control;

	DBG("Unregistered interface %s on path %s",
		AUDIO_CONTROL_INTERFACE, device_get_path(dev->btd_dev));

	if (control->session)
		avctp_disconnect(control->session);

	avctp_remove_state_cb(control->avctp_id);

	if (control->target)
		btd_service_unref(control->target);

	if (control->remote)
		btd_service_unref(control->remote);

	g_free(control);
	dev->control = NULL;
}

void control_unregister(struct audio_device *dev)
{
	g_dbus_unregister_interface(btd_get_dbus_connection(),
						device_get_path(dev->btd_dev),
						AUDIO_CONTROL_INTERFACE);
}

static struct control *control_init(struct audio_device *dev)
{
	struct control *control;

	if (dev->control != NULL)
		return dev->control;

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
					device_get_path(dev->btd_dev),
					AUDIO_CONTROL_INTERFACE,
					control_methods, NULL,
					control_properties, dev,
					path_unregister))
		return NULL;

	DBG("Registered interface %s on path %s",
		AUDIO_CONTROL_INTERFACE, device_get_path(dev->btd_dev));

	control = g_new0(struct control, 1);

	control->avctp_id = avctp_add_state_cb(dev, state_changed);

	return control;
}

struct control *control_init_target(struct audio_device *dev,
						struct btd_service *service)
{
	struct control *control;

	control = control_init(dev);
	if (control == NULL)
		return NULL;

	control->target = btd_service_ref(service);

	return control;
}

struct control *control_init_remote(struct audio_device *dev,
						struct btd_service *service)
{
	struct control *control;

	control = control_init(dev);
	if (control == NULL)
		return NULL;

	control->remote = btd_service_ref(service);

	return control;
}

gboolean control_is_active(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (control && control->session)
		return TRUE;

	return FALSE;
}
