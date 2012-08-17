/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia - INdT
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
#include "att.h"
#include "gattrib.h"
#include "attio.h"
#include "gatt.h"
#include "log.h"
#include "gas.h"

/* Generic Attribute/Access Service */
struct gas {
	struct btd_device *device;
	struct att_range gap;	/* GAP Primary service range */
	struct att_range gatt;	/* GATT Primary service range */
	GAttrib *attrib;
	guint attioid;
};

static GSList *devices = NULL;

static void gas_free(struct gas *gas)
{
	if (gas->attioid)
		btd_device_remove_attio_callback(gas->device, gas->attioid);

	btd_device_unref(gas->device);
	g_free(gas);
}

static gint cmp_device(gconstpointer a, gconstpointer b)
{
	const struct gas *gas = a;
	const struct btd_device *device = b;

	return (gas->device == device ? 0 : -1);
}

static void gap_appearance_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct gas *gas = user_data;
	struct att_data_list *list =  NULL;
	uint16_t app;
	uint8_t *atval;

	if (status != 0) {
		error("Read characteristics by UUID failed: %s",
				att_ecode2str(status));
		return;
	}

	list = dec_read_by_type_resp(pdu, plen);
	if (list == NULL)
		return;

	if (list->len != 4) {
		error("GAP Appearance value: invalid data");
		goto done;
	}

	atval = list->data[0] + 2; /* skip handle value */
	app = att_get_u16(atval);

	DBG("GAP Appearance: 0x%04x", app);

	device_set_appearance(gas->device, app);

done:
	att_data_list_free(list);
}

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct gas *gas = user_data;
	uint16_t app;

	gas->attrib = g_attrib_ref(attrib);

	if (device_get_appearance(gas->device, &app) < 0) {
		bt_uuid_t uuid;

		bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);

		gatt_read_char_by_uuid(gas->attrib, gas->gap.start,
						gas->gap.end, &uuid,
						gap_appearance_cb, gas);
	}

	/* TODO: Read other GAP characteristics - See Core spec page 1739 */
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct gas *gas = user_data;

	g_attrib_unref(gas->attrib);
	gas->attrib = NULL;
}

int gas_register(struct btd_device *device, struct att_range *gap,
						struct att_range *gatt)
{
	struct gas *gas;

	gas = g_new0(struct gas, 1);
	gas->gap.start = gap->start;
	gas->gap.end = gap->end;
	gas->gatt.start = gatt->start;
	gas->gatt.end = gatt->end;

	gas->device = btd_device_ref(device);

	devices = g_slist_append(devices, gas);

	gas->attioid = btd_device_add_attio_callback(device,
						attio_connected_cb,
						attio_disconnected_cb, gas);

	return 0;
}

void gas_unregister(struct btd_device *device)
{
	struct gas *gas;
	GSList *l;

	l = g_slist_find_custom(devices, device, cmp_device);
	if (l == NULL)
		return;

	gas = l->data;
	devices = g_slist_remove(devices, gas);
	gas_free(gas);
}
