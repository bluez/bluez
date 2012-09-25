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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdint.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "adapter.h"
#include "device.h"
#include "profile.h"

static GSList *profiles = NULL;

void btd_profile_foreach(void (*func)(struct btd_profile *p, void *data),
								void *data)
{
	GSList *l, *next;

	for (l = profiles; l != NULL; l = next) {
		struct btd_profile *profile = l->data;

		next = g_slist_next(l);

		func(profile, data);
	}
}

int btd_profile_register(struct btd_profile *profile)
{
	profiles = g_slist_append(profiles, profile);
	return 0;
}

void btd_profile_unregister(struct btd_profile *profile)
{
	profiles = g_slist_remove(profiles, profile);
}
