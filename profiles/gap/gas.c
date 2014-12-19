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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <glib.h>

#include "btio/btio.h"
#include "lib/uuid.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/shared/util.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "src/attio.h"
#include "attrib/gatt.h"
#include "src/log.h"
#include "src/textfile.h"

/* Generic Attribute/Access Service */
struct gas {
	struct btd_device *device;
	struct att_range gap;	/* GAP Primary service range */
	GAttrib *attrib;
	guint attioid;
};

static GSList *devices;

static void gas_free(struct gas *gas)
{
	if (gas->attioid)
		btd_device_remove_attio_callback(gas->device, gas->attioid);

	g_attrib_unref(gas->attrib);
	btd_device_unref(gas->device);
	g_free(gas);
}

static int cmp_device(gconstpointer a, gconstpointer b)
{
	const struct gas *gas = a;
	const struct btd_device *device = b;

	return gas->device == device ? 0 : -1;
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
	app = get_le16(atval);

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

static int gas_register(struct btd_device *device, struct att_range *gap)
{
	struct gas *gas;

	gas = g_new0(struct gas, 1);
	gas->gap.start = gap->start;
	gas->gap.end = gap->end;

	gas->device = btd_device_ref(device);

	devices = g_slist_append(devices, gas);

	gas->attioid = btd_device_add_attio_callback(device,
						attio_connected_cb,
						attio_disconnected_cb, gas);

	return 0;
}

static void gas_unregister(struct btd_device *device)
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

static int gap_driver_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct gatt_primary *gap;

	gap = btd_device_get_primary(device, GAP_UUID);

	if (gap == NULL) {
		error("GAP service is mandatory");
		return -EINVAL;
	}

	return gas_register(device, &gap->range);
}

static void gap_driver_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);

	gas_unregister(device);
}

static struct btd_profile gap_profile = {
	.name		= "gap-profile",
	.remote_uuid	= GAP_UUID,
	.device_probe	= gap_driver_probe,
	.device_remove	= gap_driver_remove
};

static int gap_init(void)
{
	devices = NULL;

	btd_profile_register(&gap_profile);

	return 0;
}

static void gap_exit(void)
{
	btd_profile_unregister(&gap_profile);
}

BLUETOOTH_PLUGIN_DEFINE(gap, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							gap_init, gap_exit)
