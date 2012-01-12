/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *  Copyright (C) 2011  Marcel Holtmann <marcel@holtmann.org>
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

#include <glib.h>
#include <bluetooth/uuid.h>
#include <adapter.h>

#include "log.h"

#include "hcid.h"
#include "att.h"
#include "gattrib.h"
#include "attrib-server.h"
#include "reporter.h"

#define IMMEDIATE_ALERT_SVC_UUID	0x1802
#define LINK_LOSS_SVC_UUID		0x1803
#define TX_POWER_SVC_UUID		0x1804
#define ALERT_LEVEL_CHR_UUID		0x2A06
#define POWER_LEVEL_CHR_UUID		0x2A07

enum {
	NO_ALERT = 0x00,
	MILD_ALERT = 0x01,
	HIGH_ALERT = 0x02,
};

static uint16_t tx_power_handle;

static void register_link_loss(void)
{
	uint16_t start_handle, h;
	const int svc_size = 3;
	uint8_t atval[256];
	bt_uuid_t uuid;

	/* FIXME: Provide the adapter in next function */
	start_handle = attrib_db_find_avail(NULL, svc_size);
	if (start_handle == 0) {
		error("Not enough free handles to register service");
		return;
	}

	DBG("start_handle=0x%04x", start_handle);

	h = start_handle;

	/* Primary service definition */
	bt_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	att_put_u16(LINK_LOSS_SVC_UUID, &atval[0]);
	/* FIXME: Provide the adapter in next function */
	attrib_db_add(NULL, h++, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 2);

	/* Alert level characteristic */
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	atval[0] = ATT_CHAR_PROPER_READ | ATT_CHAR_PROPER_WRITE;
	att_put_u16(h + 1, &atval[1]);
	att_put_u16(ALERT_LEVEL_CHR_UUID, &atval[3]);
	/* FIXME: Provide the adapter in next function */
	attrib_db_add(NULL, h++, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 5);

	/* Alert level value */
	bt_uuid16_create(&uuid, ALERT_LEVEL_CHR_UUID);
	att_put_u8(NO_ALERT, &atval[0]);
	/* FIXME: Provide the adapter in next function */
	attrib_db_add(NULL, h++, &uuid, ATT_NONE, ATT_NONE, atval, 1);

	g_assert(h - start_handle == svc_size);
}

static void register_tx_power(void)
{
	uint16_t start_handle, h;
	const int svc_size = 4;
	uint8_t atval[256];
	bt_uuid_t uuid;

	/* FIXME: Provide the adapter in next function */
	start_handle = attrib_db_find_avail(NULL, svc_size);
	if (start_handle == 0) {
		error("Not enough free handles to register service");
		return;
	}

	DBG("start_handle=0x%04x", start_handle);

	h = start_handle;

	/* Primary service definition */
	bt_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	att_put_u16(TX_POWER_SVC_UUID, &atval[0]);
	/* FIXME: Provide the adapter in next function */
	attrib_db_add(NULL, h++, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 2);

	/* Power level characteristic */
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	atval[0] = ATT_CHAR_PROPER_READ | ATT_CHAR_PROPER_NOTIFY;
	att_put_u16(h + 1, &atval[1]);
	att_put_u16(POWER_LEVEL_CHR_UUID, &atval[3]);
	/* FIXME: Provide the adapter in next function */
	attrib_db_add(NULL, h++, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 5);

	/* Power level value */
	bt_uuid16_create(&uuid, POWER_LEVEL_CHR_UUID);
	att_put_u8(0x00, &atval[0]);
	tx_power_handle = h;
	/* FIXME: Provide the adapter in next function */
	attrib_db_add(NULL, h++, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 1);

	/* Client characteristic configuration */
	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	atval[0] = 0x00;
	atval[1] = 0x00;
	/* FIXME: Provide the adapter in next function */
	attrib_db_add(NULL, h++, &uuid, ATT_NONE, ATT_NONE, atval, 2);

	g_assert(h - start_handle == svc_size);
}

static void register_immediate_alert(void)
{
	uint16_t start_handle, h;
	const int svc_size = 3;
	uint8_t atval[256];
	bt_uuid_t uuid;

	/* FIXME: Provide the adapter in next function */
	start_handle = attrib_db_find_avail(NULL, svc_size);
	if (start_handle == 0) {
		error("Not enough free handles to register service");
		return;
	}

	DBG("start_handle=0x%04x", start_handle);

	h = start_handle;

	/* Primary service definition */
	bt_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	att_put_u16(IMMEDIATE_ALERT_SVC_UUID, &atval[0]);
	/* FIXME: Provide the adapter in next function */
	attrib_db_add(NULL, h++, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 2);

	/* Alert level characteristic */
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	atval[0] = ATT_CHAR_PROPER_WRITE_WITHOUT_RESP;
	att_put_u16(h + 1, &atval[1]);
	att_put_u16(ALERT_LEVEL_CHR_UUID, &atval[3]);
	/* FIXME: Provide the adapter in next function */
	attrib_db_add(NULL, h++, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 5);

	/* Alert level value */
	bt_uuid16_create(&uuid, ALERT_LEVEL_CHR_UUID);
	att_put_u8(NO_ALERT, &atval[0]);
	/* FIXME: Provide the adapter in next function */
	attrib_db_add(NULL, h++, &uuid, ATT_NONE, ATT_NONE, atval, 1);

	g_assert(h - start_handle == svc_size);
}

int reporter_init(void)
{
	if (!main_opts.attrib_server) {
		DBG("Attribute server is disabled");
		return -1;
	}

	DBG("Proximity Reporter");

	register_link_loss();
	register_tx_power();
	register_immediate_alert();

	return 0;
}

void reporter_exit(void)
{
}
