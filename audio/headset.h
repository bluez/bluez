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
#ifndef __AUDIO_HEADSET_H
#define __AUDIO_HEADSET_H

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <dbus/dbus.h>

#include "unix.h"

#define AUDIO_HEADSET_INTERFACE "org.bluez.audio.Headset"

typedef struct headset headset_t;

headset_t *headset_init(const char *object_path, sdp_record_t *record,
			uint16_t svc);

void headset_free(const char *object_path);

void headset_update(headset_t *headset, sdp_record_t *record, uint16_t svc);

gboolean headset_is_connected(headset_t *headset);

int headset_server_init(DBusConnection *conn, gboolean disable_hfp,
			gboolean sco_hci);

void headset_exit(void);

int headset_get_config(headset_t *headset, int sock, struct ipc_data_cfg *cfg);

#endif /* __AUDIO_HEADSET_H_ */
