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
#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"

#include "src/log.h"
#include "src/error.h"
#include "src/sdpd.h"
#include "src/uuid-helper.h"
#include "src/dbus-common.h"

#include "avctp.h"
#include "control.h"

static GSList *devices = NULL;

struct control {
	struct btd_device *dev;
	struct avctp *session;
	struct btd_service *target;
	struct btd_service *remote;
	unsigned int avctp_id;
};

static void state_changed(struct btd_device *dev, avctp_state_t old_state,
				avctp_state_t new_state, void *user_data)
{
	struct control *control = user_data;
	DBusConnection *conn = btd_get_dbus_connection();
	const char *path = device_get_path(dev);

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
	case AVCTP_STATE_BROWSING_CONNECTING:
	case AVCTP_STATE_BROWSING_CONNECTED:
	default:
		return;
	}
}

int control_connect(struct btd_service *service)
{
	struct control *control = btd_service_get_user_data(service);

	if (control->session)
		return -EALREADY;

	control->session = avctp_connect(control->dev);
	if (!control->session)
		return -EIO;

	return 0;
}

int control_disconnect(struct btd_service *service)
{
	struct control *control = btd_service_get_user_data(service);

	if (!control->session)
		return -ENOTCONN;

	avctp_disconnect(control->session);

	return 0;
}

static DBusMessage *key_pressed(DBusConnection *conn, DBusMessage *msg,
						uint8_t op, void *data)
{
	struct control *control = data;
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
	struct control *control = data;
	dbus_bool_t value = (control->session != NULL);

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
	struct control *control = data;

	DBG("Unregistered interface %s on path %s",  AUDIO_CONTROL_INTERFACE,
						device_get_path(control->dev));

	if (control->session)
		avctp_disconnect(control->session);

	avctp_remove_state_cb(control->avctp_id);

	if (control->target)
		btd_service_unref(control->target);

	if (control->remote)
		btd_service_unref(control->remote);

	devices = g_slist_remove(devices, control);
	g_free(control);
}

void control_unregister(struct btd_service *service)
{
	struct btd_device *dev = btd_service_get_device(service);

	g_dbus_unregister_interface(btd_get_dbus_connection(),
						device_get_path(dev),
						AUDIO_CONTROL_INTERFACE);
}

static struct control *find_control(struct btd_device *dev)
{
	GSList *l;

	for (l = devices; l; l = l->next) {
		struct control *control = l->data;

		if (control->dev == dev)
			return control;
	}

	return NULL;
}

static struct control *control_init(struct btd_service *service)
{
	struct control *control;
	struct btd_device *dev = btd_service_get_device(service);

	control = find_control(dev);
	if (control != NULL)
		return control;

	control = g_new0(struct control, 1);

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
					device_get_path(dev),
					AUDIO_CONTROL_INTERFACE,
					control_methods, NULL,
					control_properties, control,
					path_unregister)) {
		g_free(control);
		return NULL;
	}

	DBG("Registered interface %s on path %s", AUDIO_CONTROL_INTERFACE,
							device_get_path(dev));

	control->dev = dev;
	control->avctp_id = avctp_add_state_cb(dev, state_changed, control);
	devices = g_slist_prepend(devices, control);

	return control;
}

int control_init_target(struct btd_service *service)
{
	struct control *control;

	control = control_init(service);
	if (control == NULL)
		return -EINVAL;

	control->target = btd_service_ref(service);

	btd_service_set_user_data(service, control);

	return 0;
}

int control_init_remote(struct btd_service *service)
{
	struct control *control;

	control = control_init(service);
	if (control == NULL)
		return -EINVAL;

	control->remote = btd_service_ref(service);

	btd_service_set_user_data(service, control);

	return 0;
}

gboolean control_is_active(struct btd_service *service)
{
	struct control *control = btd_service_get_user_data(service);

	if (control && control->session)
		return TRUE;

	return FALSE;
}
