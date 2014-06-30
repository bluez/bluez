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
#include <errno.h>

#include <glib.h>

#include "src/log.h"

#include "lib/uuid.h"
#include "src/shared/util.h"

#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt.h"

#include "android/scpp.h"

#define SCAN_INTERVAL_WIN_UUID		0x2A4F
#define SCAN_REFRESH_UUID		0x2A31

#define SCAN_INTERVAL		0x0060
#define SCAN_WINDOW		0x0030
#define SERVER_REQUIRES_REFRESH	0x00

struct bt_scpp {
	int ref_count;
	GAttrib *attrib;
	struct gatt_primary *primary;
	uint16_t interval;
	uint16_t window;
	uint16_t iwhandle;
	uint16_t refresh_handle;
	guint refresh_cb_id;
};

static void scpp_free(struct bt_scpp *scan)
{
	bt_scpp_detach(scan);

	g_free(scan->primary);
	g_free(scan);
}

struct bt_scpp *bt_scpp_new(void *primary)
{
	struct bt_scpp *scan;

	scan = g_try_new0(struct bt_scpp, 1);
	if (!scan)
		return NULL;

	scan->interval = SCAN_INTERVAL;
	scan->window = SCAN_WINDOW;

	if (primary)
		scan->primary = g_memdup(primary, sizeof(*scan->primary));

	return bt_scpp_ref(scan);
}

struct bt_scpp *bt_scpp_ref(struct bt_scpp *scan)
{
	if (!scan)
		return NULL;

	__sync_fetch_and_add(&scan->ref_count, 1);

	return scan;
}

void bt_scpp_unref(struct bt_scpp *scan)
{
	if (!scan)
		return;

	if (__sync_sub_and_fetch(&scan->ref_count, 1))
		return;

	scpp_free(scan);
}

static void write_scan_params(GAttrib *attrib, uint16_t handle,
					uint16_t interval, uint16_t window)
{
	uint8_t value[4];

	put_le16(interval, &value[0]);
	put_le16(window, &value[2]);

	gatt_write_cmd(attrib, handle, value, sizeof(value), NULL, NULL);
}

static void refresh_value_cb(const uint8_t *pdu, uint16_t len,
						gpointer user_data)
{
	struct bt_scpp *scan = user_data;

	DBG("Server requires refresh: %d", pdu[3]);

	if (pdu[3] == SERVER_REQUIRES_REFRESH)
		write_scan_params(scan->attrib, scan->iwhandle, scan->interval,
								scan->window);
}

static void ccc_written_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	struct bt_scpp *scan = user_data;

	if (status != 0) {
		error("Write Scan Refresh CCC failed: %s",
						att_ecode2str(status));
		return;
	}

	DBG("Scan Refresh: notification enabled");

	scan->refresh_cb_id = g_attrib_register(scan->attrib,
				ATT_OP_HANDLE_NOTIFY, scan->refresh_handle,
				refresh_value_cb, scan, NULL);
}

static void write_ccc(GAttrib *attrib, uint16_t handle, void *user_data)
{
	uint8_t value[2];

	put_le16(GATT_CLIENT_CHARAC_CFG_NOTIF_BIT, value);

	gatt_write_char(attrib, handle, value, sizeof(value), ccc_written_cb,
								user_data);
}

static void discover_descriptor_cb(uint8_t status, GSList *descs,
								void *user_data)
{
	struct bt_scpp *scan = user_data;
	struct gatt_desc *desc;


	if (status != 0) {
		error("Discover descriptors failed: %s", att_ecode2str(status));
		return;
	}

	/* There will be only one descriptor on list and it will be CCC */
	desc = descs->data;

	write_ccc(scan->attrib, desc->handle, scan);
}

static void refresh_discovered_cb(uint8_t status, GSList *chars,
								void *user_data)
{
	struct bt_scpp *scan = user_data;
	struct gatt_char *chr;
	uint16_t start, end;
	bt_uuid_t uuid;

	if (status) {
		error("Scan Refresh %s", att_ecode2str(status));
		return;
	}

	if (!chars) {
		DBG("Scan Refresh not supported");
		return;
	}

	chr = chars->data;

	DBG("Scan Refresh handle: 0x%04x", chr->value_handle);

	start = chr->value_handle + 1;
	end = scan->primary->range.end;

	if (start > end)
		return;

	scan->refresh_handle = chr->value_handle;

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);

	gatt_discover_desc(scan->attrib, start, end, &uuid,
					discover_descriptor_cb, user_data);
}

static void iwin_discovered_cb(uint8_t status, GSList *chars, void *user_data)
{
	struct bt_scpp *scan = user_data;
	struct gatt_char *chr;

	if (status) {
		error("Discover Scan Interval Window: %s",
						att_ecode2str(status));
		return;
	}

	chr = chars->data;
	scan->iwhandle = chr->value_handle;

	DBG("Scan Interval Window handle: 0x%04x", scan->iwhandle);

	write_scan_params(scan->attrib, scan->iwhandle, scan->interval,
								scan->window);
}

bool bt_scpp_attach(struct bt_scpp *scan, void *attrib)
{
	bt_uuid_t iwin_uuid, refresh_uuid;

	if (!scan || scan->attrib || !scan->primary)
		return false;

	scan->attrib = g_attrib_ref(attrib);

	if (scan->iwhandle)
		write_scan_params(scan->attrib, scan->iwhandle, scan->interval,
								scan->window);
	else {
		bt_uuid16_create(&iwin_uuid, SCAN_INTERVAL_WIN_UUID);
		gatt_discover_char(scan->attrib, scan->primary->range.start,
					scan->primary->range.end, &iwin_uuid,
					iwin_discovered_cb, scan);
	}

	if (scan->refresh_handle)
		scan->refresh_cb_id = g_attrib_register(scan->attrib,
				ATT_OP_HANDLE_NOTIFY, scan->refresh_handle,
				refresh_value_cb, scan, NULL);
	else {
		bt_uuid16_create(&refresh_uuid, SCAN_REFRESH_UUID);
		gatt_discover_char(scan->attrib, scan->primary->range.start,
					scan->primary->range.end, &refresh_uuid,
					refresh_discovered_cb, scan);
	}

	return true;
}

void bt_scpp_detach(struct bt_scpp *scan)
{
	if (!scan || !scan->attrib)
		return;

	if (scan->refresh_cb_id > 0) {
		g_attrib_unregister(scan->attrib, scan->refresh_cb_id);
		scan->refresh_cb_id = 0;
	}

	g_attrib_unref(scan->attrib);
	scan->attrib = NULL;
}

bool bt_scpp_set_interval(struct bt_scpp *scan, uint16_t value)
{
	if (!scan)
		return false;

	/* TODO: Check valid range */

	scan->interval = value;

	return true;
}

bool bt_scpp_set_window(struct bt_scpp *scan, uint16_t value)
{
	if (!scan)
		return false;

	/* TODO: Check valid range */

	scan->window = value;

	return true;
}
