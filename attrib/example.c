/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <arpa/inet.h>

#include <bluetooth/uuid.h>

#include <glib.h>

#include "log.h"
#include "attrib-server.h"

#include "att.h"
#include "example.h"

/* FIXME: Not defined by SIG? UUID128? */
#define OPCODES_SUPPORTED_UUID          0xA001
#define BATTERY_STATE_SVC_UUID		0xA002
#define BATTERY_STATE_UUID		0xA003
#define THERM_HUMIDITY_SVC_UUID		0xA004
#define MANUFACTURER_SVC_UUID		0xA005
#define TEMPERATURE_UUID		0xA006
#define FMT_CELSIUS_UUID		0xA007
#define FMT_OUTSIDE_UUID		0xA008
#define RELATIVE_HUMIDITY_UUID		0xA009
#define FMT_PERCENT_UUID		0xA00A
#define BLUETOOTH_SIG_UUID		0xA00B
#define MANUFACTURER_NAME_UUID		0xA00C
#define MANUFACTURER_SERIAL_UUID	0xA00D
#define VENDOR_SPECIFIC_SVC_UUID	0xA00E
#define VENDOR_SPECIFIC_TYPE_UUID	0xA00F
#define FMT_KILOGRAM_UUID		0xA010
#define FMT_HANGING_UUID		0xA011

static GSList *sdp_handles = NULL;

static int register_attributes(void)
{
	const char *desc_out_temp = "Outside Temperature";
	const char *desc_out_hum = "Outside Relative Humidity";
	const char *desc_weight = "Rucksack Weight";
	const char *manufacturer_name1 = "ACME Temperature Sensor";
	const char *manufacturer_name2 = "ACME Weighing Scales";
	const char *serial1 = "237495-3282-A";
	const char *serial2 = "11267-2327A00239";

	const uint128_t char_weight_uuid_btorder = {
		.data = { 0x80, 0x88, 0xF2, 0x18, 0x90, 0x2C, 0x45, 0x0B,
			  0xB6, 0xC4, 0x62, 0x89, 0x1E, 0x8C, 0x25, 0xE9 } };
	const uint128_t prim_weight_uuid_btorder = {
		.data = { 0x4F, 0x0A, 0xC0, 0x96, 0x35, 0xD4, 0x49, 0x11,
			  0x96, 0x31, 0xDE, 0xA8, 0xDC, 0x74, 0xEE, 0xFE } };

	uint128_t char_weight_uuid;
	uint8_t atval[256];
	uint32_t handle;
	bt_uuid_t uuid;
	int len;

	btoh128(&char_weight_uuid_btorder, &char_weight_uuid);

	/* Battery state service: primary service definition */
	bt_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	att_put_u16(BATTERY_STATE_SVC_UUID, &atval[0]);
	attrib_db_add(0x0100, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 2);

	/* Battery: battery state characteristic */
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	att_put_u16(0x0110, &atval[1]);
	att_put_u16(BATTERY_STATE_UUID, &atval[3]);
	attrib_db_add(0x0106, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 5);

	/* Battery: battery state attribute */
	bt_uuid16_create(&uuid, BATTERY_STATE_UUID);
	atval[0] = 0x04;
	attrib_db_add(0x0110, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 1);

	/* Battery: Client Characteristic Configuration */
	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	atval[0] = 0x00;
	atval[1] = 0x00;
	attrib_db_add(0x0111, &uuid, ATT_NONE, ATT_AUTHENTICATION, atval, 2);

	/* Add an SDP record for the above service */
	handle = attrib_create_sdp(0x0100, "Battery State Service");
	if (handle)
		sdp_handles = g_slist_prepend(sdp_handles, GUINT_TO_POINTER(handle));

	/* Thermometer: primary service definition */
	bt_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	att_put_u16(THERM_HUMIDITY_SVC_UUID, &atval[0]);
	attrib_db_add(0x0200, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 2);

	/* Thermometer: Include */
	bt_uuid16_create(&uuid, GATT_INCLUDE_UUID);
	att_put_u16(0x0500, &atval[0]);
	att_put_u16(0x0504, &atval[2]);
	att_put_u16(MANUFACTURER_SVC_UUID, &atval[4]);
	attrib_db_add(0x0201, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 6);

	/* Thermometer: Include */
	att_put_u16(0x0550, &atval[0]);
	att_put_u16(0x0568, &atval[2]);
	att_put_u16(VENDOR_SPECIFIC_SVC_UUID, &atval[4]);
	attrib_db_add(0x0202, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 6);

	/* Thermometer: temperature characteristic */
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	att_put_u16(0x0204, &atval[1]);
	att_put_u16(TEMPERATURE_UUID, &atval[3]);
	attrib_db_add(0x0203, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 5);

	/* Thermometer: temperature characteristic value */
	bt_uuid16_create(&uuid, TEMPERATURE_UUID);
	atval[0] = 0x8A;
	atval[1] = 0x02;
	attrib_db_add(0x0204, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 2);

	/* Thermometer: temperature characteristic format */
	bt_uuid16_create(&uuid, GATT_CHARAC_FMT_UUID);
	atval[0] = 0x0E;
	atval[1] = 0xFE;
	att_put_u16(FMT_CELSIUS_UUID, &atval[2]);
	atval[4] = 0x01;
	att_put_u16(FMT_OUTSIDE_UUID, &atval[5]);
	attrib_db_add(0x0205, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 7);

	/* Thermometer: characteristic user description */
	bt_uuid16_create(&uuid, GATT_CHARAC_USER_DESC_UUID);
	len = strlen(desc_out_temp);
	strncpy((char *) atval, desc_out_temp, len);
	attrib_db_add(0x0206, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, len);

	/* Thermometer: relative humidity characteristic */
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	att_put_u16(0x0212, &atval[1]);
	att_put_u16(RELATIVE_HUMIDITY_UUID, &atval[3]);
	attrib_db_add(0x0210, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 5);

	/* Thermometer: relative humidity value */
	bt_uuid16_create(&uuid, RELATIVE_HUMIDITY_UUID);
	atval[0] = 0x27;
	attrib_db_add(0x0212, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 1);

	/* Thermometer: relative humidity characteristic format */
	bt_uuid16_create(&uuid, GATT_CHARAC_FMT_UUID);
	atval[0] = 0x04;
	atval[1] = 0x00;
	att_put_u16(FMT_PERCENT_UUID, &atval[2]);
	att_put_u16(BLUETOOTH_SIG_UUID, &atval[4]);
	att_put_u16(FMT_OUTSIDE_UUID, &atval[6]);
	attrib_db_add(0x0213, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 8);

	/* Thermometer: characteristic user description */
	bt_uuid16_create(&uuid, GATT_CHARAC_USER_DESC_UUID);
	len = strlen(desc_out_hum);
	strncpy((char *) atval, desc_out_hum, len);
	attrib_db_add(0x0214, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, len);

	/* Add an SDP record for the above service */
	handle = attrib_create_sdp(0x0200, "Thermometer");
	if (handle)
		sdp_handles = g_slist_prepend(sdp_handles, GUINT_TO_POINTER(handle));

	/* Secondary Service: Manufacturer Service */
	bt_uuid16_create(&uuid, GATT_SND_SVC_UUID);
	att_put_u16(MANUFACTURER_SVC_UUID, &atval[0]);
	attrib_db_add(0x0500, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 2);

	/* Manufacturer name characteristic definition */
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	att_put_u16(0x0502, &atval[1]);
	att_put_u16(MANUFACTURER_NAME_UUID, &atval[3]);
	attrib_db_add(0x0501, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 5);

	/* Manufacturer name characteristic value */
	bt_uuid16_create(&uuid, MANUFACTURER_NAME_UUID);
	len = strlen(manufacturer_name1);
	strncpy((char *) atval, manufacturer_name1, len);
	attrib_db_add(0x0502, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, len);

	/* Manufacturer serial number characteristic */
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	att_put_u16(0x0504, &atval[1]);
	att_put_u16(MANUFACTURER_SERIAL_UUID, &atval[3]);
	attrib_db_add(0x0503, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 5);

	/* Manufacturer serial number characteristic value */
	bt_uuid16_create(&uuid, MANUFACTURER_SERIAL_UUID);
	len = strlen(serial1);
	strncpy((char *) atval, serial1, len);
	attrib_db_add(0x0504, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, len);

	/* Secondary Service: Manufacturer Service */
	bt_uuid16_create(&uuid, GATT_SND_SVC_UUID);
	att_put_u16(MANUFACTURER_SVC_UUID, &atval[0]);
	attrib_db_add(0x0505, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 2);

	/* Manufacturer name characteristic definition */
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	att_put_u16(0x0507, &atval[1]);
	att_put_u16(MANUFACTURER_NAME_UUID, &atval[3]);
	attrib_db_add(0x0506, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 5);

	/* Secondary Service: Vendor Specific Service */
	bt_uuid16_create(&uuid, GATT_SND_SVC_UUID);
	att_put_u16(VENDOR_SPECIFIC_SVC_UUID, &atval[0]);
	attrib_db_add(0x0550, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 2);

	/* Vendor Specific Type characteristic definition */
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	att_put_u16(0x0568, &atval[1]);
	att_put_u16(VENDOR_SPECIFIC_TYPE_UUID, &atval[3]);
	attrib_db_add(0x0560, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 5);

	/* Vendor Specific Type characteristic value */
	bt_uuid16_create(&uuid, VENDOR_SPECIFIC_TYPE_UUID);
	atval[0] = 0x56;
	atval[1] = 0x65;
	atval[2] = 0x6E;
	atval[3] = 0x64;
	atval[4] = 0x6F;
	atval[5] = 0x72;
	attrib_db_add(0x0568, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 6);

	/* Manufacturer name attribute */
	bt_uuid16_create(&uuid, MANUFACTURER_NAME_UUID);
	len = strlen(manufacturer_name2);
	strncpy((char *) atval, manufacturer_name2, len);
	attrib_db_add(0x0507, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, len);

	/* Characteristic: serial number */
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	att_put_u16(0x0509, &atval[1]);
	att_put_u16(MANUFACTURER_SERIAL_UUID, &atval[3]);
	attrib_db_add(0x0508, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 5);

	/* Serial number characteristic value */
	bt_uuid16_create(&uuid, MANUFACTURER_SERIAL_UUID);
	len = strlen(serial2);
	strncpy((char *) atval, serial2, len);
	attrib_db_add(0x0509, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, len);

	/* Weight service: primary service definition */
	bt_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	memcpy(atval, &prim_weight_uuid_btorder, 16);
	attrib_db_add(0x0680, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 16);

	/* Weight: include */
	bt_uuid16_create(&uuid, GATT_INCLUDE_UUID);
	att_put_u16(0x0505, &atval[0]);
	att_put_u16(0x0509, &atval[2]);
	att_put_u16(MANUFACTURER_SVC_UUID, &atval[4]);
	attrib_db_add(0x0681, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 6);

	/* Weight: characteristic */
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	att_put_u16(0x0683, &atval[1]);
	memcpy(&atval[3], &char_weight_uuid_btorder, 16);
	attrib_db_add(0x0682, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 19);

	/* Weight: characteristic value */
	bt_uuid128_create(&uuid, char_weight_uuid);
	atval[0] = 0x82;
	atval[1] = 0x55;
	atval[2] = 0x00;
	atval[3] = 0x00;
	attrib_db_add(0x0683, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 4);

	/* Weight: characteristic format */
	bt_uuid16_create(&uuid, GATT_CHARAC_FMT_UUID);
	atval[0] = 0x08;
	atval[1] = 0xFD;
	att_put_u16(FMT_KILOGRAM_UUID, &atval[2]);
	att_put_u16(BLUETOOTH_SIG_UUID, &atval[4]);
	att_put_u16(FMT_HANGING_UUID, &atval[6]);
	attrib_db_add(0x0684, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 8);

	/* Weight: characteristic user description */
	bt_uuid16_create(&uuid, GATT_CHARAC_USER_DESC_UUID);
	len = strlen(desc_weight);
	strncpy((char *) atval, desc_weight, len);
	attrib_db_add(0x0685, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, len);

	/* Add an SDP record for the above service */
	handle = attrib_create_sdp(0x0680, "Weight Service");
	if (handle)
		sdp_handles = g_slist_prepend(sdp_handles, GUINT_TO_POINTER(handle));

	return 0;
}

int server_example_init(void)
{
	return register_attributes();
}

void server_example_exit(void)
{
	while (sdp_handles) {
		uint32_t handle = GPOINTER_TO_UINT(sdp_handles->data);

		attrib_free_sdp(handle);
		sdp_handles = g_slist_remove(sdp_handles, sdp_handles->data);
	}
}
