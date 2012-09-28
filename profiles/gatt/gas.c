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

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <glib.h>
#include <bluetooth/uuid.h>

#include "adapter.h"
#include "device.h"
#include "att.h"
#include "gattrib.h"
#include "attio.h"
#include "btio.h"
#include "gatt.h"
#include "log.h"
#include "textfile.h"
#include "gas.h"

/* Generic Attribute/Access Service */
struct gas {
	struct btd_device *device;
	struct att_range gap;	/* GAP Primary service range */
	struct att_range gatt;	/* GATT Primary service range */
	GAttrib *attrib;
	guint attioid;
	guint changed_ind;
	uint16_t changed_handle;
	uint16_t mtu;
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

static inline int create_filename(char *buf, size_t size,
				const bdaddr_t *bdaddr, const char *name)
{
	char addr[18];

	ba2str(bdaddr, addr);

	return create_name(buf, size, STORAGEDIR, addr, name);
}

static int write_ctp_handle(bdaddr_t *sba, bdaddr_t *dba, uint8_t bdaddr_type,
						uint16_t uuid, uint16_t handle)
{
	char filename[PATH_MAX + 1], addr[18], key[27], value[7];

	create_filename(filename, PATH_MAX, sba, "gatt");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(dba, addr);

	snprintf(key, sizeof(key), "%17s#%hhu#0x%4.4x", addr, bdaddr_type,
									uuid);
	snprintf(value, sizeof(value), "0x%4.4x", handle);

	return textfile_put(filename, key, value);
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

static void ccc_written_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct gas *gas = user_data;
	bdaddr_t sba, dba;
	uint8_t bdaddr_type;

	if (status) {
		error("Write Service Changed CCC failed: %s",
						att_ecode2str(status));
		return;
	}

	DBG("Service Changed indications enabled");

	adapter_get_address(device_get_adapter(gas->device), &sba);
	device_get_address(gas->device, &dba, &bdaddr_type);

	write_ctp_handle(&sba, &dba, bdaddr_type, GATT_CHARAC_SERVICE_CHANGED,
							gas->changed_handle);
}

static void write_ccc(GAttrib *attrib, uint16_t handle, gpointer user_data)
{
	uint8_t value[2];

	att_put_u16(GATT_CLIENT_CHARAC_CFG_IND_BIT, value);
	gatt_write_char(attrib, handle, value, sizeof(value), ccc_written_cb,
								user_data);
}

static void indication_cb(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	struct gas *gas = user_data;
	uint16_t handle, start, end, olen;
	size_t plen;
	uint8_t *opdu;

	if (len < 7) { /* 1-byte opcode + 2-byte handle + 4 range */
		error("Malformed ATT notification");
		return;
	}

	handle = att_get_u16(&pdu[1]);
	start = att_get_u16(&pdu[3]);
	end = att_get_u16(&pdu[5]);

	if (handle != gas->changed_handle)
		return;

	DBG("Service Changed start: 0x%04X end: 0x%04X", start, end);

	if (device_is_bonded(gas->device) == FALSE) {
		DBG("Ignoring Service Changed: device is not bonded");
		return;
	}

	/* Confirming indication received */
	opdu = g_attrib_get_buffer(gas->attrib, &plen);
	olen = enc_confirmation(opdu, plen);
	g_attrib_send(gas->attrib, 0, opdu[0], opdu, olen, NULL, NULL, NULL);

	btd_device_gatt_set_service_changed(gas->device, start, end);
}

static void gatt_descriptors_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct gas *gas = user_data;
	struct att_data_list *list;
	int i;
	uint8_t format;

	if (status) {
		error("Discover all GATT characteristic descriptors: %s",
							att_ecode2str(status));
		return;
	}

	list = dec_find_info_resp(pdu, len, &format);
	if (list == NULL)
		return;

	if (format != ATT_FIND_INFO_RESP_FMT_16BIT)
		goto done;

	for (i = 0; i < list->num; i++) {
		uint16_t uuid16, ccc;
		uint8_t *value;

		value = list->data[i];
		ccc = att_get_u16(value);
		uuid16 = att_get_u16(&value[2]);
		DBG("CCC: 0x%04x UUID: 0x%04x", ccc, uuid16);
		write_ccc(gas->attrib, ccc, user_data);
	}

done:
	att_data_list_free(list);
}

static void gatt_characteristic_cb(GSList *characteristics, guint8 status,
							gpointer user_data)
{
	struct gas *gas = user_data;
	struct gatt_char *chr;
	uint16_t start, end;

	if (status) {
		error("Discover Service Changed handle: %s", att_ecode2str(status));
		return;
	}

	chr = characteristics->data;

	start = chr->value_handle + 1;
	end = gas->gatt.end;

	if (start > end) {
		error("Inconsistent database: Service Changed CCC missing");
		return;
	}

	gas->changed_handle = chr->value_handle;
	gatt_find_info(gas->attrib, start, end, gatt_descriptors_cb, gas);
}

static void exchange_mtu_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct gas *gas = user_data;
	uint16_t rmtu;

	if (status) {
		error("MTU exchange: %s", att_ecode2str(status));
		return;
	}

	if (!dec_mtu_resp(pdu, plen, &rmtu)) {
		error("MTU exchange: protocol error");
		return;
	}

	gas->mtu = MIN(rmtu, gas->mtu);
	if (g_attrib_set_mtu(gas->attrib, gas->mtu))
		DBG("MTU exchange succeeded: %d", gas->mtu);
	else
		DBG("MTU exchange failed");
}

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct gas *gas = user_data;
	GIOChannel *io;
	GError *gerr = NULL;
	uint16_t cid, imtu;
	uint16_t app;

	gas->attrib = g_attrib_ref(attrib);
	io = g_attrib_get_channel(attrib);

	if (bt_io_get(io, &gerr, BT_IO_OPT_IMTU, &imtu,
				BT_IO_OPT_CID, &cid, BT_IO_OPT_INVALID)) {
		gatt_exchange_mtu(gas->attrib, imtu, exchange_mtu_cb, gas);
		gas->mtu = imtu;
		DBG("MTU Exchange: Requesting %d", imtu);
	}

	gas->changed_ind = g_attrib_register(gas->attrib, ATT_OP_HANDLE_IND,
						indication_cb, gas, NULL);

	if (device_get_appearance(gas->device, &app) < 0) {
		bt_uuid_t uuid;

		bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);

		gatt_read_char_by_uuid(gas->attrib, gas->gap.start,
						gas->gap.end, &uuid,
						gap_appearance_cb, gas);
	}

	/* TODO: Read other GAP characteristics - See Core spec page 1739 */

	/*
	 * When re-connecting <<Service Changed>> handle and characteristic
	 * value doesn't need to read again: known information from the
	 * previous interaction.
	 */
	if (gas->changed_handle == 0) {
		bt_uuid_t uuid;

		bt_uuid16_create(&uuid, GATT_CHARAC_SERVICE_CHANGED);

		gatt_discover_char(gas->attrib, gas->gatt.start, gas->gatt.end,
					&uuid, gatt_characteristic_cb, gas);
	}
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct gas *gas = user_data;

	g_attrib_unregister(gas->attrib, gas->changed_ind);
	gas->changed_ind = 0;

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
