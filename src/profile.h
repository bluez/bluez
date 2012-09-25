/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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

struct btd_profile;

typedef void (*btd_profile_cb)(struct btd_profile *profile,
					struct btd_device *device, int err);

struct btd_profile {
	const char *name;

	const char *local_uuid;
	const char **remote_uuids;

	bool auto_connect;

	int (*device_probe) (struct btd_device *device, GSList *uuids);
	void (*device_remove) (struct btd_device *device);

	int (*connect) (struct btd_device *device, struct btd_profile *profile,
							btd_profile_cb cb);
	int (*disconnect) (struct btd_device *device, btd_profile_cb cb);

	int (*adapter_probe) (struct btd_adapter *adapter);
	void (*adapter_remove) (struct btd_adapter *adapter);
};

void btd_profile_foreach(void (*func)(struct btd_profile *p, void *data),
								void *data);

int btd_profile_register(struct btd_profile *profile);
void btd_profile_unregister(struct btd_profile *profile);
