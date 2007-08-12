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

#include <bluetooth/sdp.h>
#include <dbus/dbus.h>

#include "device.h"

#define MAX_PATH_LENGTH 64 /* D-Bus path */
#define AUDIO_MANAGER_PATH "/org/bluez/audio"
#define AUDIO_MANAGER_INTERFACE "org.bluez.audio.Manager"

struct enabled_interfaces {
	gboolean headset;
	gboolean gateway;
	gboolean sink;
	gboolean source;
	gboolean control;
	gboolean target;
};

int audio_init(DBusConnection *conn, struct enabled_interfaces *enabled,
		gboolean no_hfp, gboolean sco_hci);

void audio_exit(void);

uint32_t add_service_record(DBusConnection *conn, sdp_buf_t *buf);
int remove_service_record(DBusConnection *conn, uint32_t rec_id);

struct device *manager_device_connected(bdaddr_t *bda, const char *uuid);

struct device *manager_default_device();

struct device *manager_get_connected_device(void);
