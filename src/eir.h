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
#define EIR_CLASS_OF_DEV            0x0D  /* Class of Device */
#define EIR_DEVICE_ID               0x10  /* device ID */

struct uuid_info {
	uuid_t uuid;
	uint8_t svc_hint;
};

struct eir_data {
	GSList *services;
	int flags;
	char *name;
	uint8_t dev_class[3];
	gboolean name_complete;
};

void eir_data_free(struct eir_data *eir);
int eir_parse(struct eir_data *eir, uint8_t *eir_data, uint8_t eir_len);
void eir_create(const char *name, int8_t tx_power, uint16_t did_vendor,
			uint16_t did_product, uint16_t did_version,
			GSList *uuids, uint8_t *data);

gboolean eir_has_data_type(uint8_t *data, size_t len, uint8_t type);

size_t eir_append_data(uint8_t *eir, size_t eir_len, uint8_t type,
						uint8_t *data, size_t data_len);
size_t eir_length(uint8_t *eir, size_t maxlen);
