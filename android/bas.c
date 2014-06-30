/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can rebastribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is bastributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <errno.h>

#include <glib.h>

#include "src/log.h"

#include "lib/uuid.h"
#include "src/shared/util.h"

#include "attrib/gattrib.h"
#include "attrib/att.h"
#include "attrib/gatt.h"

#include "android/bas.h"

#define ATT_NOTIFICATION_HEADER_SIZE 3

struct bt_bas {
	int ref_count;
	GAttrib *attrib;
	struct gatt_primary *primary;
	uint16_t handle;
	uint16_t ccc_handle;
	guint id;
};

static void bas_free(struct bt_bas *bas)
{
	bt_bas_detach(bas);

	g_free(bas->primary);
	g_free(bas);
}

struct bt_bas *bt_bas_new(void *primary)
{
	struct bt_bas *bas;

	bas = g_try_new0(struct bt_bas, 1);
	if (!bas)
		return NULL;

	if (primary)
		bas->primary = g_memdup(primary, sizeof(*bas->primary));

	return bt_bas_ref(bas);
}

struct bt_bas *bt_bas_ref(struct bt_bas *bas)
{
	if (!bas)
		return NULL;

	__sync_fetch_and_add(&bas->ref_count, 1);

	return bas;
}

void bt_bas_unref(struct bt_bas *bas)
{
	if (!bas)
		return;

	if (__sync_sub_and_fetch(&bas->ref_count, 1))
		return;

	bas_free(bas);
}

static void value_cb(const guint8 *pdu, guint16 len, gpointer user_data)
{
	DBG("Battery Level at %u", pdu[ATT_NOTIFICATION_HEADER_SIZE]);
}

static void ccc_written_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	struct bt_bas *bas = user_data;

	if (status != 0) {
		error("Write Scan Refresh CCC failed: %s",
						att_ecode2str(status));
		return;
	}

	DBG("Battery Level: notification enabled");

	bas->id = g_attrib_register(bas->attrib, ATT_OP_HANDLE_NOTIFY,
					bas->handle, value_cb, bas, NULL);
}

static void write_ccc(GAttrib *attrib, uint16_t handle, void *user_data)
{
	uint8_t value[2];

	put_le16(GATT_CLIENT_CHARAC_CFG_NOTIF_BIT, value);

	gatt_write_char(attrib, handle, value, sizeof(value), ccc_written_cb,
								user_data);
}


static void ccc_read_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct bt_bas *bas = user_data;

	if (status != 0) {
		error("Error reading CCC value: %s", att_ecode2str(status));
		return;
	}

	write_ccc(bas->attrib, bas->ccc_handle, bas);
}

static void discover_descriptor_cb(uint8_t status, GSList *descs,
								void *user_data)
{
	struct bt_bas *bas = user_data;
	struct gatt_desc *desc;

	if (status != 0) {
		error("Discover descriptors failed: %s", att_ecode2str(status));
		return;
	}

	/* There will be only one descriptor on list and it will be CCC */
	desc = descs->data;
	bas->ccc_handle = desc->handle;

	gatt_read_char(bas->attrib, desc->handle, ccc_read_cb, bas);
}

static void bas_discovered_cb(uint8_t status, GSList *chars, void *user_data)
{
	struct bt_bas *bas = user_data;
	struct gatt_char *chr;
	uint16_t start, end;
	bt_uuid_t uuid;

	if (status) {
		error("Battery: %s", att_ecode2str(status));
		return;
	}

	chr = chars->data;
	bas->handle = chr->value_handle;

	DBG("Battery handle: 0x%04x", bas->handle);

	start = chr->value_handle + 1;
	end = bas->primary->range.end;

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);

	gatt_discover_desc(bas->attrib, start, end, &uuid,
						discover_descriptor_cb, bas);
}

bool bt_bas_attach(struct bt_bas *bas, void *attrib)
{
	if (!bas || bas->attrib || !bas->primary)
		return false;

	bas->attrib = g_attrib_ref(attrib);

	if (bas->handle > 0)
		return true;

	gatt_discover_char(bas->attrib, bas->primary->range.start,
					bas->primary->range.end, NULL,
					bas_discovered_cb, bas);

	return true;
}

void bt_bas_detach(struct bt_bas *bas)
{
	if (!bas || !bas->attrib)
		return;

	if (bas->id > 0) {
		g_attrib_unregister(bas->attrib, bas->id);
		bas->id = 0;
	}

	g_attrib_unref(bas->attrib);
	bas->attrib = NULL;
}
