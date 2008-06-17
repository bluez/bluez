/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#define MAX_PATH_LENGTH 64 /* D-Bus path */
#define AUDIO_MANAGER_PATH "/org/bluez/audio"
#define AUDIO_MANAGER_INTERFACE "org.bluez.audio.Manager"

struct enabled_interfaces {
	gboolean headset;
	gboolean gateway;
	gboolean sink;
	gboolean source;
	gboolean control;
};

typedef void (*create_dev_cb_t) (struct audio_device *dev, void *user_data);

int audio_manager_init(DBusConnection *conn, GKeyFile *config);
void audio_manager_exit(void);

gboolean server_is_enabled(uint16_t svc);

struct audio_device *manager_find_device(const bdaddr_t *bda, const char *interface,
					gboolean connected);

struct audio_device *manager_device_connected(const bdaddr_t *bda, const char *uuid);

gboolean manager_create_device(bdaddr_t *bda, create_dev_cb_t cb,
				void *user_data);
