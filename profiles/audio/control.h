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

#define AUDIO_CONTROL_INTERFACE "org.bluez.MediaControl1"

struct btd_service;

struct control *control_init_target(struct audio_device *dev,
						struct btd_service *service);
struct control *control_init_remote(struct audio_device *dev,
						struct btd_service *service);
void control_unregister(struct audio_device *dev);
gboolean control_is_active(struct audio_device *dev);

int control_connect(struct audio_device *dev);
int control_disconnect(struct audio_device *dev);

void control_target_connected(struct control *control, int err);
void control_target_disconnected(struct control *control, int err);
void control_remote_connected(struct control *control, int err);
void control_remote_disconnected(struct control *control, int err);
