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

#include <dbus/dbus.h>

#define BUF_SIZE 1024

char *headset_add(const bdaddr_t *bda);

void headset_remove(char *path);

uint32_t headset_add_ag_record(uint8_t channel);

int headset_remove_ag_record(uint32_t rec_id);

gboolean headset_server_io_cb(GIOChannel *chan, GIOCondition cond, void *data);

void headset_init(DBusConnection *conn);
void headset_exit(void);

#endif /* __AUDIO_HEADSET_H_ */
