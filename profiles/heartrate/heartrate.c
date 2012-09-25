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
#include "gattrib.h"
#include "att.h"
#include "gatt.h"
#include "attio.h"
#include "log.h"
#include "heartrate.h"

struct heartrate_adapter {
	struct btd_adapter	*adapter;
	GSList			*devices;
};

struct heartrate {
	struct btd_device		*dev;
	struct heartrate_adapter	*hradapter;
	GAttrib				*attrib;
	guint				attioid;

	struct att_range		*svc_range;	/* primary svc range */

	uint16_t			measurement_val_handle;
	uint16_t			hrcp_val_handle;
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

	if (hr->attioid > 0)
		btd_device_remove_attio_callback(hr->dev, hr->attioid);

	if (hr->attrib != NULL)
		g_attrib_unref(hr->attrib);

	btd_device_unref(hr->dev);
	g_free(hr->svc_range);
	g_free(hr);
}

static void destroy_heartrate_adapter(gpointer user_data)
{
	struct heartrate_adapter *hradapter = user_data;

	g_free(hradapter);
}

static void discover_char_cb(GSList *chars, guint8 status, gpointer user_data)
{
	struct heartrate *hr = user_data;

	if (status) {
		error("Discover HRS characteristics failed: %s",
							att_ecode2str(status));
		return;
	}

	for (; chars; chars = chars->next) {
		struct gatt_char *c = chars->data;

		if (g_strcmp0(c->uuid, HEART_RATE_MEASUREMENT_UUID) == 0) {
			hr->measurement_val_handle = c->value_handle;
			/* TODO: discover CCC handle */
		} else if (g_strcmp0(c->uuid, BODY_SENSOR_LOCATION_UUID) == 0) {
			DBG("Body Sensor Location supported");
			/* TODO: read characterictic value */
		} else if (g_strcmp0(c->uuid,
					HEART_RATE_CONTROL_POINT_UUID) == 0) {
			DBG("Heart Rate Control Point supported");
			hr->hrcp_val_handle = c->value_handle;
		}
	}
}

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct heartrate *hr = user_data;

	DBG("");

	hr->attrib = g_attrib_ref(attrib);

	gatt_discover_char(hr->attrib, hr->svc_range->start, hr->svc_range->end,
						NULL, discover_char_cb, hr);
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct heartrate *hr = user_data;

	DBG("");

	g_attrib_unref(hr->attrib);
	hr->attrib = NULL;
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

int heartrate_device_register(struct btd_device *device,
						struct gatt_primary *prim)
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

	hr->svc_range = g_new0(struct att_range, 1);
	hr->svc_range->start = prim->range.start;
	hr->svc_range->end = prim->range.end;

	hradapter->devices = g_slist_prepend(hradapter->devices, hr);

	hr->attioid = btd_device_add_attio_callback(device, attio_connected_cb,
						attio_disconnected_cb, hr);

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
