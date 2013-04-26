/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2013  BMW Car IT GmbH. All rights reserved.
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

struct btd_service;
struct btd_device;
struct btd_profile;

struct btd_service *btd_service_ref(struct btd_service *service);
void btd_service_unref(struct btd_service *service);

/* Service management functions used by the core */
struct btd_service *service_create(struct btd_device *device,
						struct btd_profile *profile);

int service_probe(struct btd_service *service);
void service_shutdown(struct btd_service *service);

/* Connection control API */
int btd_service_connect(struct btd_service *service);
int btd_service_disconnect(struct btd_service *service);

/* Public member access */
struct btd_device *btd_service_get_device(const struct btd_service *service);
struct btd_profile *btd_service_get_profile(const struct btd_service *service);
