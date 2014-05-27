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

	g_attrib_unref(gas->attrib);
	btd_device_unref(gas->device);
	g_free(gas);
}

static int cmp_device(gconstpointer a, gconstpointer b)
{
	const struct gas *gas = a;
	const struct btd_device *device = b;

	return (gas->device == device ? 0 : -1);
}

static void write_ctp_handle(struct btd_device *device, uint16_t uuid,
					uint16_t handle)
{
	char *filename, group[6], value[7];
	GKeyFile *key_file;
	char *data;
	gsize length = 0;

	filename = btd_device_get_storage_path(device, "gatt");
	if (!filename) {
		warn("Unable to get gatt storage path for device");
		return;
	}

	key_file = g_key_file_new();
	g_key_file_load_from_file(key_file, filename, 0, NULL);

	snprintf(group, sizeof(group), "%hu", uuid);
	snprintf(value, sizeof(value), "0x%4.4X", handle);
	g_key_file_set_string(key_file, group, "Value", value);

	data = g_key_file_to_data(key_file, &length, NULL);
	if (length > 0) {
		create_file(filename, S_IRUSR | S_IWUSR);
		g_file_set_contents(filename, data, length, NULL);
	}

	g_free(data);
	g_free(filename);
	g_key_file_free(key_file);
}

static int read_ctp_handle(struct btd_device *device, uint16_t uuid,
					uint16_t *value)
{
	char *filename, group[6];
	GKeyFile *key_file;
	char *str;
	int err = 0;

	filename = btd_device_get_storage_path(device, "gatt");
	if (!filename) {
		warn("Unable to get gatt storage path for device");
		return -ENOENT;
	}

	snprintf(group, sizeof(group), "%hu", uuid);

	key_file = g_key_file_new();
	g_key_file_load_from_file(key_file, filename, 0, NULL);

	str = g_key_file_get_string(key_file, group, "Value", NULL);
	if (str == NULL || sscanf(str, "%hx", value) != 1)
		err = -ENOENT;

	g_free(str);
	g_free(filename);
	g_key_file_free(key_file);

	return err;
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

static void indication_cb(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint8_t bdaddr_type;
	struct gas *gas = user_data;
	uint16_t start, end, olen;
	size_t plen;
	uint8_t *opdu;

	if (len < 7) { /* 1-byte opcode + 2-byte handle + 4 range */
		error("Malformed ATT notification");
		return;
	}

	start = get_le16(&pdu[3]);
	end = get_le16(&pdu[5]);

	DBG("Service Changed start: 0x%04X end: 0x%04X", start, end);

	/* Confirming indication received */
	opdu = g_attrib_get_buffer(gas->attrib, &plen);
	olen = enc_confirmation(opdu, plen);
	g_attrib_send(gas->attrib, 0, opdu, olen, NULL, NULL, NULL);

	bdaddr_type = btd_device_get_bdaddr_type(gas->device);
	if (!device_is_bonded(gas->device, bdaddr_type)) {
		DBG("Ignoring Service Changed: device is not bonded");
		return;
	}

	btd_device_gatt_set_service_changed(gas->device, start, end);
}

static void ccc_written_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct gas *gas = user_data;

	if (status) {
		error("Write Service Changed CCC failed: %s",
						att_ecode2str(status));
		return;
	}

	DBG("Service Changed indications enabled");

	gas->changed_ind = g_attrib_register(gas->attrib, ATT_OP_HANDLE_IND,
						gas->changed_handle,
						indication_cb, gas, NULL);

	write_ctp_handle(gas->device, GATT_CHARAC_SERVICE_CHANGED,
					gas->changed_handle);
}

static void write_ccc(GAttrib *attrib, uint16_t handle, gpointer user_data)
{
	uint8_t value[2];

	put_le16(GATT_CLIENT_CHARAC_CFG_IND_BIT, value);
	gatt_write_char(attrib, handle, value, sizeof(value), ccc_written_cb,
								user_data);
}

static void discover_ccc_cb(uint8_t status, GSList *descs, void *user_data)
{
	struct gas *gas = user_data;
	struct gatt_desc *desc;

	if (status != 0) {
		error("Discover Service Changed CCC failed: %s",
							att_ecode2str(status));
		return;
	}

	/* There will be only one descriptor on list and it will be CCC */
	desc = descs->data;

	DBG("CCC: 0x%04x", desc->handle);
	write_ccc(gas->attrib, desc->handle, user_data);
}

static void gatt_characteristic_cb(uint8_t status, GSList *characteristics,
								void *user_data)
{
	struct gas *gas = user_data;
	struct gatt_char *chr;
	uint16_t start, end;
	bt_uuid_t uuid;

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

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);

	gatt_discover_desc(gas->attrib, start, end, &uuid, discover_ccc_cb,
									gas);
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
				BT_IO_OPT_CID, &cid, BT_IO_OPT_INVALID) &&
							cid == ATT_CID) {
		gatt_exchange_mtu(gas->attrib, imtu, exchange_mtu_cb, gas);
		gas->mtu = imtu;
		DBG("MTU Exchange: Requesting %d", imtu);
	}

	if (gerr) {
		error("Could not acquire att imtu and cid: %s", gerr->message);
		g_error_free(gerr);
	}

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

static int gas_register(struct btd_device *device, struct att_range *gap,
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

	read_ctp_handle(gas->device, GATT_CHARAC_SERVICE_CHANGED,
					&gas->changed_handle);

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

static int gatt_driver_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct gatt_primary *gap, *gatt;

	gap = btd_device_get_primary(device, GAP_UUID);
	gatt = btd_device_get_primary(device, GATT_UUID);

	if (gap == NULL || gatt == NULL) {
		error("GAP and GATT are mandatory");
		return -EINVAL;
	}

	return gas_register(device, &gap->range, &gatt->range);
}

static void gatt_driver_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);

	gas_unregister(device);
}

static struct btd_profile gatt_profile = {
	.name		= "gap-gatt-profile",
	.remote_uuid	= GATT_UUID,
	.device_probe	= gatt_driver_probe,
	.device_remove	= gatt_driver_remove
};

static int gatt_init(void)
{
	btd_profile_register(&gatt_profile);

	return 0;
}

static void gatt_exit(void)
{
	btd_profile_unregister(&gatt_profile);
}

BLUETOOTH_PLUGIN_DEFINE(gatt, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
					gatt_init, gatt_exit)
