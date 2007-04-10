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
#ifndef __AUDIO_MANAGER_H
#define __AUDIO_MANAGER_H

#include <bluetooth/bluetooth.h>

#include <dbus/dbus.h>

struct manager;

#include "headset.h"

#define AUDIO_MANAGER_PATH "/org/bluez/audio"

#define AUDIO_HEADSET_PATH_BASE "/org/bluez/audio/headset"

void manager_add_headset(struct manager *manager, struct headset *hs);

struct headset *manager_find_headset_by_bda(struct manager *manager,
						bdaddr_t *bda);

DBusConnection *manager_get_dbus_conn(struct manager *manager);

int audio_init(DBusConnection *conn);

void audio_exit(void);

#endif /* __AUDIO_MANAGER_H_ */

