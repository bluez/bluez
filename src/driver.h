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

#define BTD_UUIDS(args...) ((const char *[]) { args, NULL } )

struct btd_device;

struct btd_device_driver {
	const char *name;
	const char **uuids;
	int (*probe) (struct btd_device_driver *driver,
			struct btd_device *device, GSList *records);
	void (*remove) (struct btd_device_driver *driver,
			struct btd_device *device);
};

int btd_register_device_driver(struct btd_device_driver *driver);
void btd_unregister_device_driver(struct btd_device_driver *driver);
GSList *btd_get_device_drivers(void);

struct btd_adapter;

struct btd_adapter_driver {
	const char *name;
	int (*probe) (struct btd_adapter_driver *driver,
			struct btd_adapter *adapter);
	void (*remove) (struct btd_adapter_driver *driver,
			struct btd_adapter *adapter);
};

int btd_register_adapter_driver(struct btd_adapter_driver *driver);
void btd_unregister_adapter_driver(struct btd_adapter_driver *driver);
GSList *btd_get_adapter_drivers(void);
