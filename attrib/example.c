/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "sdpd.h"
#include "log.h"
#include "attrib-server.h"

#include "att.h"
#include "example.h"

#define ATT_PSM 27

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

static uint32_t handle = 0;

static sdp_record_t *server_record_new(void)
{
	sdp_list_t *svclass_id, *apseq, *proto[2], *profiles, *root, *aproto;
	uuid_t root_uuid, proto_uuid, gatt_uuid, l2cap;
	sdp_profile_desc_t profile;
	sdp_record_t *record;
	sdp_data_t *psm, *sh, *eh;
	uint16_t lp = ATT_PSM, start = 0x0001, end = 0x000f;

	record = sdp_record_alloc();
	if (record == NULL)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);
	sdp_list_free(root, NULL);

	sdp_uuid16_create(&gatt_uuid, GENERIC_ATTRIB_SVCLASS_ID);
	svclass_id = sdp_list_append(NULL, &gatt_uuid);
	sdp_set_service_classes(record, svclass_id);
	sdp_list_free(svclass_id, NULL);

	sdp_uuid16_create(&profile.uuid, GENERIC_ATTRIB_PROFILE_ID);
	profile.version = 0x0100;
	profiles = sdp_list_append(NULL, &profile);
	sdp_set_profile_descs(record, profiles);
	sdp_list_free(profiles, NULL);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&proto_uuid, ATT_UUID);
	proto[1] = sdp_list_append(NULL, &proto_uuid);
	sh = sdp_data_alloc(SDP_UINT16, &start);
	proto[1] = sdp_list_append(proto[1], sh);
	eh = sdp_data_alloc(SDP_UINT16, &end);
	proto[1] = sdp_list_append(proto[1], eh);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_set_info_attr(record, "Generic Attribute Profile", "BlueZ", NULL);

	sdp_set_url_attr(record, "http://www.bluez.org/",
			"http://www.bluez.org/", "http://www.bluez.org/");

	sdp_set_service_id(record, gatt_uuid);

	sdp_data_free(psm);
	sdp_data_free(sh);
	sdp_data_free(eh);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(aproto, NULL);

	return record;
}

static int register_attributes(void)
{
	const char *devname = "Example Device";
	const char *desc_out_temp = "Outside Temperature";
	const char *desc_out_hum = "Outside Relative Humidity";
	uint8_t atval[256];
	uuid_t uuid;
	int len;
	uint16_t u16;

	/* GAP service: primary service definition */
	sdp_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	u16 = htons(GENERIC_ACCESS_PROFILE_ID);
	atval[0] = u16 >> 8;
	atval[1] = u16;
	attrib_db_add(0x0001, &uuid, atval, 2);

	/* GAP service: device name characteristic */
	sdp_uuid16_create(&uuid, GATT_CHARAC_UUID);
	u16 = htons(GATT_CHARAC_DEVICE_NAME);
	atval[0] = ATT_CHAR_PROPER_READ;
	atval[1] = 0x00;
	atval[2] = 0x06;
	atval[3] = u16 >> 8;
	atval[4] = u16;
	attrib_db_add(0x0004, &uuid, atval, 5);

	/* GAP service: device name attribute */
	sdp_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	len = strlen(devname);
	strncpy((char *) atval, devname, len);
	attrib_db_add(0x0006, &uuid, atval, len);

	/* GATT service: primary service definition */
	sdp_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	u16 = htons(GENERIC_ATTRIB_PROFILE_ID);
	atval[0] = u16 >> 8;
	atval[1] = u16;
	attrib_db_add(0x0010, &uuid, atval, 2);

	/* GATT service: attributes opcodes characteristic */
	sdp_uuid16_create(&uuid, GATT_CHARAC_UUID);
	u16 = htons(OPCODES_SUPPORTED_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	atval[1] = 0x00;
	atval[2] = 0x12;
	atval[3] = u16 >> 8;
	atval[4] = u16;
	attrib_db_add(0x0011, &uuid, atval, 5);

	/* GATT service: attribute opcodes supported */
	sdp_uuid16_create(&uuid, OPCODES_SUPPORTED_UUID);
	atval[0] = 0x01;
	atval[1] = 0xFF;
	attrib_db_add(0x0012, &uuid, atval, 2);

	/* Battery state service: primary service definition */
	sdp_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	u16 = htons(BATTERY_STATE_SVC_UUID);
	atval[0] = u16 >> 8;
	atval[1] = u16;
	attrib_db_add(0x0100, &uuid, atval, 2);

	/* Battery: battery state characteristic */
	sdp_uuid16_create(&uuid, GATT_CHARAC_UUID);
	u16 = htons(BATTERY_STATE_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	atval[1] = 0x01;
	atval[2] = 0x10;
	atval[3] = u16 >> 8;
	atval[4] = u16;
	attrib_db_add(0x0106, &uuid, atval, 5);

	/* Battery: battery state attribute */
	sdp_uuid16_create(&uuid, BATTERY_STATE_UUID);
	u16 = htons(BATTERY_STATE_UUID);
	atval[0] = 0x04;
	attrib_db_add(0x0110, &uuid, atval, 1);

	/* Thermometer: primary service definition */
	sdp_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	u16 = htons(THERM_HUMIDITY_SVC_UUID);
	atval[0] = u16 >> 8;
	atval[1] = u16;
	attrib_db_add(0x0200, &uuid, atval, 2);

	/* Thermometer: Include */
	sdp_uuid16_create(&uuid, GATT_INCLUDE_UUID);
	u16 = htons(MANUFACTURER_SVC_UUID);
	atval[0] = 0x05;
	atval[1] = 0x00;
	atval[2] = 0x05;
	atval[3] = 0x04;
	atval[4] = u16 >> 8;
	atval[5] = u16;
	attrib_db_add(0x0201, &uuid, atval, 6);

	/* Thermometer: Include */
	atval[0] = 0x05;
	atval[1] = 0x50;
	atval[2] = 0x05;
	atval[3] = 0x68;
	attrib_db_add(0x0202, &uuid, atval, 4);

	/* Thermometer: temperature characteristic */
	sdp_uuid16_create(&uuid, GATT_CHARAC_UUID);
	u16 = htons(TEMPERATURE_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	atval[1] = 0x02;
	atval[2] = 0x04;
	atval[3] = u16 >> 8;
	atval[4] = u16;
	attrib_db_add(0x0203, &uuid, atval, 5);

	/* Thermometer: temperature characteristic value */
	sdp_uuid16_create(&uuid, TEMPERATURE_UUID);
	atval[0] = 0x02;
	atval[1] = 0x8A;
	attrib_db_add(0x0204, &uuid, atval, 2);

	/* Thermometer: temperature characteristic format */
	sdp_uuid16_create(&uuid, GATT_CHARAC_FMT_UUID);
	u16 = htons(FMT_CELSIUS_UUID);
	atval[0] = 0x0E;
	atval[1] = 0xFE;
	atval[2] = u16 >> 8;
	atval[3] = u16;
	atval[4] = 0x01;
	u16 = htons(FMT_OUTSIDE_UUID);
	atval[5] = u16 >> 8;
	atval[6] = u16;
	attrib_db_add(0x0205, &uuid, atval, 7);

	/* Thermometer: characteristic user description */
	sdp_uuid16_create(&uuid, GATT_CHARAC_USER_DESC_UUID);
	len = strlen(desc_out_temp);
	strncpy((char *) atval, desc_out_temp, len);
	attrib_db_add(0x0206, &uuid, atval, len);

	/* Thermometer: relative humidity characteristic */
	sdp_uuid16_create(&uuid, GATT_CHARAC_UUID);
	u16 = htons(RELATIVE_HUMIDITY_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	atval[1] = 0x02;
	atval[2] = 0x12;
	atval[3] = u16 >> 8;
	atval[4] = u16;
	attrib_db_add(0x0210, &uuid, atval, 5);

	/* Thermometer: relative humidity value */
	sdp_uuid16_create(&uuid, RELATIVE_HUMIDITY_UUID);
	atval[0] = 0x27;
	attrib_db_add(0x0212, &uuid, atval, 1);

	/* Thermometer: relative humidity characteristic format */
	sdp_uuid16_create(&uuid, GATT_CHARAC_FMT_UUID);
	u16 = htons(FMT_PERCENT_UUID);
	atval[0] = 0x04;
	atval[1] = 0x00;
	atval[2] = u16 >> 8;
	atval[3] = u16;
	u16 = htons(BLUETOOTH_SIG_UUID);
	atval[4] = u16 >> 8;
	atval[5] = u16;
	u16 = htons(FMT_OUTSIDE_UUID);
	atval[6] = u16 >> 8;
	atval[7] = u16;
	attrib_db_add(0x0213, &uuid, atval, 8);

	/* Thermometer: characteristic user description */
	sdp_uuid16_create(&uuid, GATT_CHARAC_USER_DESC_UUID);
	len = strlen(desc_out_hum);
	strncpy((char *) atval, desc_out_hum, len);
	attrib_db_add(0x0214, &uuid, atval, len);

	return 0;
}

int server_example_init(void)
{
	sdp_record_t *record;

	/*
	 * FIXME: Add BR/EDR service record and attributes into the GATT
	 * database. BlueZ gatt server will be automatically enabled if
	 * any plugin registers at least one primary service.
	 */

	record = server_record_new();
	if (record == NULL) {
		error("Unable to create GATT service record");
		return -1;
	}

	if (add_record_to_server(BDADDR_ANY, record) < 0) {
		error("Failed to register GATT service record");
		sdp_record_free(record);
		return -1;
	}

	handle = record->handle;

	return register_attributes();
}

void server_example_exit(void)
{
	if (handle)
		remove_record_from_server(handle);
}
