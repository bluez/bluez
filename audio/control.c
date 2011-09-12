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
#include <gdbus.h>

#include "log.h"
#include "error.h"
#include "device.h"
#include "manager.h"
#include "avctp.h"
#include "control.h"
#include "sdpd.h"
#include "glib-helper.h"
#include "dbus-common.h"

static unsigned int avctp_id = 0;

struct control {
	struct audio_device *dev;
	struct avctp *session;

	gboolean target;
};

static void state_changed(struct audio_device *dev, avctp_state_t old_state,
				avctp_state_t new_state, void *user_data)
{
	struct control *control = dev->control;
	gboolean value;

	switch (new_state) {
	case AVCTP_STATE_DISCONNECTED:
		control->session = NULL;

		if (old_state != AVCTP_STATE_CONNECTED)
			break;

		value = FALSE;
		g_dbus_emit_signal(dev->conn, dev->path,
					AUDIO_CONTROL_INTERFACE,
					"Disconnected", DBUS_TYPE_INVALID);
		emit_property_changed(dev->conn, dev->path,
					AUDIO_CONTROL_INTERFACE, "Connected",
					DBUS_TYPE_BOOLEAN, &value);

		break;
	case AVCTP_STATE_CONNECTING:
		if (control->session)
			break;

		control->session = avctp_get(&dev->src, &dev->dst);

		break;
	case AVCTP_STATE_CONNECTED:
		value = TRUE;
		g_dbus_emit_signal(dev->conn, dev->path,
				AUDIO_CONTROL_INTERFACE, "Connected",
				DBUS_TYPE_INVALID);
		emit_property_changed(dev->conn, dev->path,
				AUDIO_CONTROL_INTERFACE, "Connected",
				DBUS_TYPE_BOOLEAN, &value);
		break;
	default:
		return;
	}
}

static DBusMessage *control_is_connected(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	DBusMessage *reply;
	dbus_bool_t connected;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	connected = (control->session != NULL);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connected,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *volume_up(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	int err;

	if (!control->session)
		return btd_error_not_connected(msg);

	if (!control->target)
		return btd_error_not_supported(msg);

	err = avctp_send_passthrough(control->session, VOL_UP_OP);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return dbus_message_new_method_return(msg);
}

static DBusMessage *volume_down(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	int err;

	if (!control->session)
		return btd_error_not_connected(msg);

	if (!control->target)
		return btd_error_not_supported(msg);

	err = avctp_send_passthrough(control->session, VOL_DOWN_OP);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return dbus_message_new_method_return(msg);
}

static DBusMessage *control_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	gboolean value;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Connected */
	value = (device->control->session != NULL);
	dict_append_entry(&dict, "Connected", DBUS_TYPE_BOOLEAN, &value);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static GDBusMethodTable control_methods[] = {
	{ "IsConnected",	"",	"b",	control_is_connected,
						G_DBUS_METHOD_FLAG_DEPRECATED },
	{ "GetProperties",	"",	"a{sv}",control_get_properties },
	{ "VolumeUp",		"",	"",	volume_up },
	{ "VolumeDown",		"",	"",	volume_down },
	{ NULL, NULL, NULL, NULL }
};

static GDBusSignalTable control_signals[] = {
	{ "Connected",			"",	G_DBUS_SIGNAL_FLAG_DEPRECATED},
	{ "Disconnected",		"",	G_DBUS_SIGNAL_FLAG_DEPRECATED},
	{ "PropertyChanged",		"sv"	},
	{ NULL, NULL }
};

static void path_unregister(void *data)
{
	struct audio_device *dev = data;
	struct control *control = dev->control;

	DBG("Unregistered interface %s on path %s",
		AUDIO_CONTROL_INTERFACE, dev->path);

	if (control->session)
		avctp_disconnect(control->session);

	g_free(control);
	dev->control = NULL;
}

void control_unregister(struct audio_device *dev)
{
	g_dbus_unregister_interface(dev->conn, dev->path,
						AUDIO_CONTROL_INTERFACE);
}

void control_update(struct control *control, uint16_t uuid16)
{
	if (uuid16 == AV_REMOTE_TARGET_SVCLASS_ID)
		control->target = TRUE;
}

struct control *control_init(struct audio_device *dev, uint16_t uuid16)
{
	struct control *control;

	if (!g_dbus_register_interface(dev->conn, dev->path,
					AUDIO_CONTROL_INTERFACE,
					control_methods, control_signals, NULL,
					dev, path_unregister))
		return NULL;

	DBG("Registered interface %s on path %s",
		AUDIO_CONTROL_INTERFACE, dev->path);

	control = g_new0(struct control, 1);
	control->dev = dev;

	control_update(control, uuid16);

	if (!avctp_id)
		avctp_id = avctp_add_state_cb(state_changed, NULL);

	return control;
}

gboolean control_is_active(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (control && control->session)
		return TRUE;

	return FALSE;
}
