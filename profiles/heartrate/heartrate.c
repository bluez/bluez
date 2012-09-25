/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012 Tieto Poland
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

#include <errno.h>
#include <stdbool.h>
#include <glib.h>
#include <bluetooth/uuid.h>

#include "adapter.h"
#include "device.h"
#include "heartrate.h"

struct heartrate_adapter {
	struct btd_adapter	*adapter;
	GSList			*devices;
};

struct heartrate {
	struct btd_device		*dev;
	struct heartrate_adapter	*hradapter;
};

static GSList *heartrate_adapters = NULL;

static gint cmp_adapter(gconstpointer a, gconstpointer b)
{
	const struct heartrate_adapter *hradapter = a;
	const struct btd_adapter *adapter = b;

	if (adapter == hradapter->adapter)
		return 0;

	return -1;
}

static gint cmp_device(gconstpointer a, gconstpointer b)
{
	const struct heartrate *hr = a;
	const struct btd_device *dev = b;

	if (dev == hr->dev)
		return 0;

	return -1;
}

static struct heartrate_adapter *
find_heartrate_adapter(struct btd_adapter *adapter)
{
	GSList *l = g_slist_find_custom(heartrate_adapters, adapter,
								cmp_adapter);
	if (!l)
		return NULL;

	return l->data;
}

static void destroy_heartrate(gpointer user_data)
{
	struct heartrate *hr = user_data;

	btd_device_unref(hr->dev);
	g_free(hr);
}

static void destroy_heartrate_adapter(gpointer user_data)
{
	struct heartrate_adapter *hradapter = user_data;

	g_free(hradapter);
}

int heartrate_adapter_register(struct btd_adapter *adapter)
{
	struct heartrate_adapter *hradapter;

	hradapter = g_new0(struct heartrate_adapter, 1);
	hradapter->adapter = adapter;

	heartrate_adapters = g_slist_prepend(heartrate_adapters, hradapter);

	return 0;
}

void heartrate_adapter_unregister(struct btd_adapter *adapter)
{
	struct heartrate_adapter *hradapter;

	hradapter = find_heartrate_adapter(adapter);
	if (hradapter == NULL)
		return;

	heartrate_adapters = g_slist_remove(heartrate_adapters, hradapter);

	destroy_heartrate_adapter(hradapter);
}

int heartrate_device_register(struct btd_device *device)
{
	struct btd_adapter *adapter;
	struct heartrate_adapter *hradapter;
	struct heartrate *hr;

	adapter = device_get_adapter(device);

	hradapter = find_heartrate_adapter(adapter);

	if (hradapter == NULL)
		return -1;

	hr = g_new0(struct heartrate, 1);
	hr->dev = btd_device_ref(device);
	hr->hradapter = hradapter;

	hradapter->devices = g_slist_prepend(hradapter->devices, hr);

	return 0;
}

void heartrate_device_unregister(struct btd_device *device)
{
	struct btd_adapter *adapter;
	struct heartrate_adapter *hradapter;
	struct heartrate *hr;
	GSList *l;

	adapter = device_get_adapter(device);

	hradapter = find_heartrate_adapter(adapter);
	if (hradapter == NULL)
		return;

	l = g_slist_find_custom(hradapter->devices, device, cmp_device);
	if (l == NULL)
		return;

	hr = l->data;

	hradapter->devices = g_slist_remove(hradapter->devices, hr);

	destroy_heartrate(hr);
}
