/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012 Texas Instruments, Inc.
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

#include <glib.h>
#include <bluetooth/uuid.h>
#include "adapter.h"
#include "device.h"
#include "gattrib.h"
#include "attio.h"
#include "att.h"
#include "gattrib.h"
#include "gatt.h"
#include "deviceinfo.h"

struct deviceinfo {
	struct btd_device	*dev;		/* Device reference */
	GAttrib			*attrib;	/* GATT connection */
	guint			attioid;	/* Att watcher id */
};

static GSList *servers = NULL;

static void deviceinfo_free(gpointer user_data)
{
	struct deviceinfo *d = user_data;

	if (d->attioid > 0)
		btd_device_remove_attio_callback(d->dev, d->attioid);

	if (d->attrib != NULL)
		g_attrib_unref(d->attrib);

	btd_device_unref(d->dev);
	g_free(d);
}

static gint cmp_device(gconstpointer a, gconstpointer b)
{
	const struct deviceinfo *d = a;
	const struct btd_device *dev = b;

	if (dev == d->dev)
		return 0;

	return -1;
}

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct deviceinfo *d = user_data;

	d->attrib = g_attrib_ref(attrib);
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct deviceinfo *d = user_data;

	g_attrib_unref(d->attrib);
	d->attrib = NULL;
}

int deviceinfo_register(struct btd_device *device)
{
	struct deviceinfo *d;

	d = g_new0(struct deviceinfo, 1);
	d->dev = btd_device_ref(device);

	servers = g_slist_prepend(servers, d);

	d->attioid = btd_device_add_attio_callback(device, attio_connected_cb,
						attio_disconnected_cb, d);
	return 0;
}

void deviceinfo_unregister(struct btd_device *device)
{
	struct deviceinfo *d;
	GSList *l;

	l = g_slist_find_custom(servers, device, cmp_device);
	if (l == NULL)
		return;

	d = l->data;
	servers = g_slist_remove(servers, d);

	deviceinfo_free(d);
}
