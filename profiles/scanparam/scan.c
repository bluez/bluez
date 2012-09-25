/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/uuid.h>

#include "log.h"
#include "adapter.h"
#include "device.h"
#include "att.h"
#include "gattrib.h"
#include "gatt.h"
#include "attio.h"
#include "scan.h"

#define SCAN_INTERVAL_WIN_UUID		0x2A4F

#define SCAN_INTERVAL		0x0060
#define SCAN_WINDOW		0x0030

struct scan {
	struct btd_device *device;
	GAttrib *attrib;
	struct att_range range;
	guint attioid;
	uint16_t interval;
	uint16_t window;
};

GSList *servers = NULL;

static gint scan_device_cmp(gconstpointer a, gconstpointer b)
{
	const struct scan *scan = a;
	const struct btd_device *device = b;

	return (device == scan->device ? 0 : -1);
}

static void iwin_discovered_cb(GSList *chars, guint8 status,
						gpointer user_data)
{
	struct scan *scan = user_data;
	struct gatt_char *chr;
	uint8_t value[4];

	if (status) {
		error("Discover Scan Interval Window: %s",
						att_ecode2str(status));
		return;
	}

	chr = chars->data;

	DBG("Scan Interval Window handle: 0x%04x",
						chr->value_handle);

	att_put_u16(SCAN_INTERVAL, &value[0]);
	att_put_u16(SCAN_WINDOW, &value[2]);

	gatt_write_char(scan->attrib, chr->value_handle, value,
						sizeof(value), NULL, NULL);
}

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct scan *scan = user_data;
	bt_uuid_t iwin_uuid;

	bt_uuid16_create(&iwin_uuid, SCAN_INTERVAL_WIN_UUID);

	scan->attrib = g_attrib_ref(attrib);

	gatt_discover_char(scan->attrib, scan->range.start, scan->range.end,
					&iwin_uuid, iwin_discovered_cb, scan);
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct scan *scan = user_data;

	g_attrib_unref(scan->attrib);
	scan->attrib = NULL;
}

int scan_register(struct btd_device *device, struct gatt_primary *prim)
{
	struct scan *scan;

	scan = g_new0(struct scan, 1);
	scan->device = btd_device_ref(device);
	scan->range = prim->range;
	scan->attioid = btd_device_add_attio_callback(device,
							attio_connected_cb,
							attio_disconnected_cb,
							scan);

	servers = g_slist_prepend(servers, scan);

	return 0;
}

void scan_unregister(struct btd_device *device)
{
	struct scan *scan;
	GSList *l;

	l = g_slist_find_custom(servers, device, scan_device_cmp);
	if (l == NULL)
		return;

	scan = l->data;
	servers = g_slist_remove(servers, scan);

	btd_device_remove_attio_callback(scan->device, scan->attioid);
	btd_device_unref(scan->device);
	g_attrib_unref(scan->attrib);
	g_free(scan);
}
