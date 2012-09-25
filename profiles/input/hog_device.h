/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2012  Nordic Semiconductor Inc.
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia - INdT
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

#define HOG_UUID		"00001812-0000-1000-8000-00805f9b34fb"

struct hog_device;

struct hog_device *hog_device_register(struct btd_device *device,
						const char *path, int *perr);
int hog_device_unregister(struct hog_device *hogdev);
struct hog_device *hog_device_find(GSList *list, const char *path);
int hog_device_set_control_point(struct hog_device *hogdev, gboolean suspend);
