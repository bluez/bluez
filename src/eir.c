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
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/sdp.h>

#include "glib-helper.h"
#include "eir.h"

#define EIR_FLAGS                   0x01  /* flags */
#define EIR_UUID16_SOME             0x02  /* 16-bit UUID, more available */
#define EIR_UUID16_ALL              0x03  /* 16-bit UUID, all listed */
#define EIR_UUID32_SOME             0x04  /* 32-bit UUID, more available */
#define EIR_UUID32_ALL              0x05  /* 32-bit UUID, all listed */
#define EIR_UUID128_SOME            0x06  /* 128-bit UUID, more available */
#define EIR_UUID128_ALL             0x07  /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */
#define EIR_TX_POWER                0x0A  /* transmit power level */
#define EIR_DEVICE_ID               0x10  /* device ID */

void eir_data_free(struct eir_data *eir)
{
	g_slist_foreach(eir->services, (GFunc) g_free, NULL);
	g_slist_free(eir->services);
	g_free(eir->name);
}

int eir_parse(struct eir_data *eir, uint8_t *eir_data)
{
	uint16_t len = 0;
	size_t total;
	size_t uuid16_count = 0;
	size_t uuid32_count = 0;
	size_t uuid128_count = 0;
	uint8_t *uuid16 = NULL;
	uint8_t *uuid32 = NULL;
	uint8_t *uuid128 = NULL;
	uuid_t service;
	char *uuid_str;
	unsigned int i;

	eir->flags = -1;

	/* No EIR data to parse */
	if (eir_data == NULL)
		return 0;

	while (len < HCI_MAX_EIR_LENGTH - 1) {
		uint8_t field_len = eir_data[0];

		/* Check for the end of EIR */
		if (field_len == 0)
			break;

		switch (eir_data[1]) {
		case EIR_UUID16_SOME:
		case EIR_UUID16_ALL:
			uuid16_count = field_len / 2;
			uuid16 = &eir_data[2];
			break;
		case EIR_UUID32_SOME:
		case EIR_UUID32_ALL:
			uuid32_count = field_len / 4;
			uuid32 = &eir_data[2];
			break;
		case EIR_UUID128_SOME:
		case EIR_UUID128_ALL:
			uuid128_count = field_len / 16;
			uuid128 = &eir_data[2];
			break;
		case EIR_FLAGS:
			eir->flags = eir_data[2];
			break;
		case EIR_NAME_SHORT:
		case EIR_NAME_COMPLETE:
			if (g_utf8_validate((char *) &eir_data[2],
							field_len - 1, NULL))
				eir->name = g_strndup((char *) &eir_data[2],
								field_len - 1);
			else
				eir->name = g_strdup("");
			eir->name_complete = eir_data[1] == EIR_NAME_COMPLETE;
			break;
		}

		len += field_len + 1;
		eir_data += field_len + 1;
	}

	/* Bail out if got incorrect length */
	if (len > HCI_MAX_EIR_LENGTH)
		return -EINVAL;

	total = uuid16_count + uuid32_count + uuid128_count;

	/* No UUIDs were parsed, so skip code below */
	if (!total)
		return 0;

	/* Generate uuids in SDP format (EIR data is Little Endian) */
	service.type = SDP_UUID16;
	for (i = 0; i < uuid16_count; i++) {
		uint16_t val16 = uuid16[1];

		val16 = (val16 << 8) + uuid16[0];
		service.value.uuid16 = val16;
		uuid_str = bt_uuid2string(&service);
		eir->services = g_slist_append(eir->services, uuid_str);
		uuid16 += 2;
	}

	service.type = SDP_UUID32;
	for (i = uuid16_count; i < uuid32_count + uuid16_count; i++) {
		uint32_t val32 = uuid32[3];
		int k;

		for (k = 2; k >= 0; k--)
			val32 = (val32 << 8) + uuid32[k];

		service.value.uuid32 = val32;
		uuid_str = bt_uuid2string(&service);
		eir->services = g_slist_append(eir->services, uuid_str);
		uuid32 += 4;
	}

	service.type = SDP_UUID128;
	for (i = uuid32_count + uuid16_count; i < total; i++) {
		int k;

		for (k = 0; k < 16; k++)
			service.value.uuid128.data[k] = uuid128[16 - k - 1];

		uuid_str = bt_uuid2string(&service);
		eir->services = g_slist_append(eir->services, uuid_str);
		uuid128 += 16;
	}

	return 0;
}

#define SIZEOF_UUID128 16

static void eir_generate_uuid128(GSList *list, uint8_t *ptr, uint16_t *eir_len)
{
	int i, k, uuid_count = 0;
	uint16_t len = *eir_len;
	uint8_t *uuid128;
	gboolean truncated = FALSE;

	/* Store UUIDs in place, skip 2 bytes to write type and length later */
	uuid128 = ptr + 2;

	for (; list; list = list->next) {
		struct uuid_info *uuid = list->data;
		uint8_t *uuid128_data = uuid->uuid.value.uuid128.data;

		if (uuid->uuid.type != SDP_UUID128)
			continue;

		/* Stop if not enough space to put next UUID128 */
		if ((len + 2 + SIZEOF_UUID128) > HCI_MAX_EIR_LENGTH) {
			truncated = TRUE;
			break;
		}

		/* Check for duplicates, EIR data is Little Endian */
		for (i = 0; i < uuid_count; i++) {
			for (k = 0; k < SIZEOF_UUID128; k++) {
				if (uuid128[i * SIZEOF_UUID128 + k] !=
					uuid128_data[SIZEOF_UUID128 - 1 - k])
					break;
			}
			if (k == SIZEOF_UUID128)
				break;
		}

		if (i < uuid_count)
			continue;

		/* EIR data is Little Endian */
		for (k = 0; k < SIZEOF_UUID128; k++)
			uuid128[uuid_count * SIZEOF_UUID128 + k] =
				uuid128_data[SIZEOF_UUID128 - 1 - k];

		len += SIZEOF_UUID128;
		uuid_count++;
	}

	if (uuid_count > 0 || truncated) {
		/* EIR Data length */
		ptr[0] = (uuid_count * SIZEOF_UUID128) + 1;
		/* EIR Data type */
		ptr[1] = truncated ? EIR_UUID128_SOME : EIR_UUID128_ALL;
		len += 2;
		*eir_len = len;
	}
}

void eir_create(const char *name, int8_t tx_power, uint16_t did_vendor,
			uint16_t did_product, uint16_t did_version,
			GSList *uuids, uint8_t *data)
{
	GSList *l;
	uint8_t *ptr = data;
	uint16_t eir_len = 0;
	uint16_t uuid16[HCI_MAX_EIR_LENGTH / 2];
	int i, uuid_count = 0;
	gboolean truncated = FALSE;
	size_t name_len;

	name_len = strlen(name);

	if (name_len > 0) {
		/* EIR Data type */
		if (name_len > 48) {
			name_len = 48;
			ptr[1] = EIR_NAME_SHORT;
		} else
			ptr[1] = EIR_NAME_COMPLETE;

		/* EIR Data length */
		ptr[0] = name_len + 1;

		memcpy(ptr + 2, name, name_len);

		eir_len += (name_len + 2);
		ptr += (name_len + 2);
	}

	if (tx_power != 0) {
		*ptr++ = 2;
		*ptr++ = EIR_TX_POWER;
		*ptr++ = (uint8_t) tx_power;
		eir_len += 3;
	}

	if (did_vendor != 0x0000) {
		uint16_t source = 0x0002;
		*ptr++ = 9;
		*ptr++ = EIR_DEVICE_ID;
		*ptr++ = (source & 0x00ff);
		*ptr++ = (source & 0xff00) >> 8;
		*ptr++ = (did_vendor & 0x00ff);
		*ptr++ = (did_vendor & 0xff00) >> 8;
		*ptr++ = (did_product & 0x00ff);
		*ptr++ = (did_product & 0xff00) >> 8;
		*ptr++ = (did_version & 0x00ff);
		*ptr++ = (did_version & 0xff00) >> 8;
		eir_len += 10;
	}

	/* Group all UUID16 types */
	for (l = uuids; l != NULL; l = g_slist_next(l)) {
		struct uuid_info *uuid = l->data;

		if (uuid->uuid.type != SDP_UUID16)
			continue;

		if (uuid->uuid.value.uuid16 < 0x1100)
			continue;

		if (uuid->uuid.value.uuid16 == PNP_INFO_SVCLASS_ID)
			continue;

		/* Stop if not enough space to put next UUID16 */
		if ((eir_len + 2 + sizeof(uint16_t)) > HCI_MAX_EIR_LENGTH) {
			truncated = TRUE;
			break;
		}

		/* Check for duplicates */
		for (i = 0; i < uuid_count; i++)
			if (uuid16[i] == uuid->uuid.value.uuid16)
				break;

		if (i < uuid_count)
			continue;

		uuid16[uuid_count++] = uuid->uuid.value.uuid16;
		eir_len += sizeof(uint16_t);
	}

	if (uuid_count > 0) {
		/* EIR Data length */
		ptr[0] = (uuid_count * sizeof(uint16_t)) + 1;
		/* EIR Data type */
		ptr[1] = truncated ? EIR_UUID16_SOME : EIR_UUID16_ALL;

		ptr += 2;
		eir_len += 2;

		for (i = 0; i < uuid_count; i++) {
			*ptr++ = (uuid16[i] & 0x00ff);
			*ptr++ = (uuid16[i] & 0xff00) >> 8;
		}
	}

	/* Group all UUID128 types */
	if (eir_len <= HCI_MAX_EIR_LENGTH - 2)
		eir_generate_uuid128(uuids, ptr, &eir_len);
}
