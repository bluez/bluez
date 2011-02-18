/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "log.h"
#include "textfile.h"

#include "hcid.h"
#include "adapter.h"
#include "manager.h"
#include "device.h"
#include "error.h"
#include "glib-helper.h"
#include "dbus-common.h"
#include "agent.h"
#include "storage.h"
#include "event.h"
#include "sdpd.h"

struct eir_data {
	GSList *services;
	int flags;
	char *name;
	gboolean name_complete;
};

static gboolean get_adapter_and_device(bdaddr_t *src, bdaddr_t *dst,
					struct btd_adapter **adapter,
					struct btd_device **device,
					gboolean create)
{
	DBusConnection *conn = get_dbus_connection();
	char peer_addr[18];

	*adapter = manager_find_adapter(src);
	if (!*adapter) {
		error("Unable to find matching adapter");
		return FALSE;
	}

	ba2str(dst, peer_addr);

	if (create)
		*device = adapter_get_device(conn, *adapter, peer_addr);
	else
		*device = adapter_find_device(*adapter, peer_addr);

	if (create && !*device) {
		error("Unable to get device object!");
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************
 *
 *  Section reserved to HCI commands confirmation handling and low
 *  level events(eg: device attached/dettached.
 *
 *****************************************************************/

static void pincode_cb(struct agent *agent, DBusError *derr,
				const char *pincode, struct btd_device *device)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	bdaddr_t sba, dba;
	int err;

	device_get_address(device, &dba);

	if (derr) {
		err = btd_adapter_pincode_reply(adapter, &dba, NULL);
		if (err < 0)
			goto fail;
		return;
	}

	err = btd_adapter_pincode_reply(adapter, &dba, pincode);
	if (err < 0)
		goto fail;

	adapter_get_address(adapter, &sba);

	return;

fail:
	error("Sending PIN code reply failed: %s (%d)", strerror(-err), -err);
}

int btd_event_request_pin(bdaddr_t *sba, bdaddr_t *dba)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	char pin[17];
	int pinlen;

	if (!get_adapter_and_device(sba, dba, &adapter, &device, TRUE))
		return -ENODEV;

	memset(pin, 0, sizeof(pin));
	pinlen = read_pin_code(sba, dba, pin);
	if (pinlen > 0) {
		btd_adapter_pincode_reply(adapter, dba, pin);
		return 0;
	}

	return device_request_authentication(device, AUTH_TYPE_PINCODE, 0,
								pincode_cb);
}

static int confirm_reply(struct btd_adapter *adapter,
				struct btd_device *device, gboolean success)
{
	bdaddr_t bdaddr;

	device_get_address(device, &bdaddr);

	return btd_adapter_confirm_reply(adapter, &bdaddr, success);
}

static void confirm_cb(struct agent *agent, DBusError *err, void *user_data)
{
	struct btd_device *device = user_data;
	struct btd_adapter *adapter = device_get_adapter(device);
	gboolean success = (err == NULL) ? TRUE : FALSE;

	confirm_reply(adapter, device, success);
}

static void passkey_cb(struct agent *agent, DBusError *err, uint32_t passkey,
			void *user_data)
{
	struct btd_device *device = user_data;
	struct btd_adapter *adapter = device_get_adapter(device);
	bdaddr_t bdaddr;

	device_get_address(device, &bdaddr);

	if (err)
		passkey = INVALID_PASSKEY;

	btd_adapter_passkey_reply(adapter, &bdaddr, passkey);
}

int btd_event_user_confirm(bdaddr_t *sba, bdaddr_t *dba, uint32_t passkey)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(sba, dba, &adapter, &device, TRUE))
		return -ENODEV;

	return device_request_authentication(device, AUTH_TYPE_CONFIRM,
							passkey, confirm_cb);
}

int btd_event_user_passkey(bdaddr_t *sba, bdaddr_t *dba)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(sba, dba, &adapter, &device, TRUE))
		return -ENODEV;

	return device_request_authentication(device, AUTH_TYPE_PASSKEY, 0,
								passkey_cb);
}

int btd_event_user_notify(bdaddr_t *sba, bdaddr_t *dba, uint32_t passkey)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(sba, dba, &adapter, &device, TRUE))
		return -ENODEV;

	return device_request_authentication(device, AUTH_TYPE_NOTIFY,
								passkey, NULL);
}

void btd_event_bonding_complete(bdaddr_t *local, bdaddr_t *peer,
							uint8_t status)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	gboolean create;

	DBG("status 0x%02x", status);

	create = status ? FALSE : TRUE;

	if (!get_adapter_and_device(local, peer, &adapter, &device, create))
		return;

	if (device)
		device_bonding_complete(device, status);
}

void btd_event_simple_pairing_complete(bdaddr_t *local, bdaddr_t *peer,
								uint8_t status)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	gboolean create;

	DBG("status=%02x", status);

	create = status ? FALSE : TRUE;

	if (!get_adapter_and_device(local, peer, &adapter, &device, create))
		return;

	if (!device)
		return;

	device_simple_pairing_complete(device, status);
}

static int parse_eir_data(struct eir_data *eir, uint8_t *eir_data,
							size_t eir_length)
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
	if (eir_data == NULL || eir_length == 0)
		return 0;

	while (len < eir_length - 1) {
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
	if (len > eir_length)
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

static void free_eir_data(struct eir_data *eir)
{
	g_slist_foreach(eir->services, (GFunc) g_free, NULL);
	g_slist_free(eir->services);
	g_free(eir->name);
}

void btd_event_advertising_report(bdaddr_t *local, le_advertising_info *info)
{
	struct btd_adapter *adapter;
	struct eir_data eir_data;
	int8_t rssi;
	int err;

	adapter = manager_find_adapter(local);
	if (adapter == NULL) {
		error("No matching adapter found");
		return;
	}

	memset(&eir_data, 0, sizeof(eir_data));
	err = parse_eir_data(&eir_data, info->data, info->length);
	if (err < 0)
		error("Error parsing advertising data: %s (%d)",
							strerror(-err), -err);

	rssi = *(info->data + info->length);

	adapter_update_device_from_info(adapter, info->bdaddr, rssi,
					info->evt_type, eir_data.name,
					eir_data.services, eir_data.flags);

	free_eir_data(&eir_data);
}

static void update_lastseen(bdaddr_t *sba, bdaddr_t *dba)
{
	time_t t;
	struct tm *tm;

	t = time(NULL);
	tm = gmtime(&t);

	write_lastseen_info(sba, dba, tm);
}

static void update_lastused(bdaddr_t *sba, bdaddr_t *dba)
{
	time_t t;
	struct tm *tm;

	t = time(NULL);
	tm = gmtime(&t);

	write_lastused_info(sba, dba, tm);
}

void btd_event_device_found(bdaddr_t *local, bdaddr_t *peer, uint32_t class,
				int8_t rssi, uint8_t *data)
{
	char filename[PATH_MAX + 1];
	struct btd_adapter *adapter;
	char local_addr[18], peer_addr[18], *alias, *name;
	name_status_t name_status;
	struct eir_data eir_data;
	int state, err;
	dbus_bool_t legacy;
	unsigned char features[8];
	const char *dev_name;

	ba2str(local, local_addr);
	ba2str(peer, peer_addr);

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	update_lastseen(local, peer);
	write_remote_class(local, peer, class);

	if (data)
		write_remote_eir(local, peer, data);

	/*
	 * Workaround to identify periodic inquiry: inquiry complete event is
	 * sent after each window, however there isn't an event to indicate the
	 * beginning of a new periodic inquiry window.
	 */
	state = adapter_get_state(adapter);
	if (!(state & (STATE_STDINQ | STATE_LE_SCAN | STATE_PINQ))) {
		state |= STATE_PINQ;
		adapter_set_state(adapter, state);
	}

	/* the inquiry result can be triggered by NON D-Bus client */
	if (adapter_get_discover_type(adapter) & DISC_RESOLVNAME &&
				adapter_has_discov_sessions(adapter))
		name_status = NAME_REQUIRED;
	else
		name_status = NAME_NOT_REQUIRED;

	create_name(filename, PATH_MAX, STORAGEDIR, local_addr, "aliases");
	alias = textfile_get(filename, peer_addr);

	create_name(filename, PATH_MAX, STORAGEDIR, local_addr, "names");
	name = textfile_get(filename, peer_addr);

	if (data)
		legacy = FALSE;
	else if (name == NULL)
		legacy = TRUE;
	else if (read_remote_features(local, peer, NULL, features) == 0) {
		if (features[0] & 0x01)
			legacy = FALSE;
		else
			legacy = TRUE;
	} else
		legacy = TRUE;

	memset(&eir_data, 0, sizeof(eir_data));
	err = parse_eir_data(&eir_data, data, EIR_DATA_LENGTH);
	if (err < 0)
		error("Error parsing EIR data: %s (%d)", strerror(-err), -err);

	/* Complete EIR names are always used. Shortened EIR names are only
	 * used if there is no name already in storage. */
	dev_name = name;
	if (eir_data.name != NULL) {
		if (eir_data.name_complete) {
			write_device_name(local, peer, eir_data.name);
			name_status = NAME_NOT_REQUIRED;
			dev_name = eir_data.name;
		} else if (name == NULL)
			dev_name = eir_data.name;
	}

	adapter_update_found_devices(adapter, peer, rssi, class, dev_name,
					alias, legacy, eir_data.services,
					name_status);

	free_eir_data(&eir_data);
	free(name);
	free(alias);
}

void btd_event_set_legacy_pairing(bdaddr_t *local, bdaddr_t *peer,
							gboolean legacy)
{
	struct btd_adapter *adapter;
	struct remote_dev_info *dev, match;

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	memset(&match, 0, sizeof(struct remote_dev_info));
	bacpy(&match.bdaddr, peer);
	match.name_status = NAME_ANY;

	dev = adapter_search_found_devices(adapter, &match);
	if (dev)
		dev->legacy = legacy;
}

void btd_event_remote_class(bdaddr_t *local, bdaddr_t *peer, uint32_t class)
{
	uint32_t old_class = 0;
	struct btd_adapter *adapter;
	struct btd_device *device;
	const gchar *dev_path;
	DBusConnection *conn = get_dbus_connection();

	read_remote_class(local, peer, &old_class);

	if (old_class == class)
		return;

	write_remote_class(local, peer, class);

	if (!get_adapter_and_device(local, peer, &adapter, &device, FALSE))
		return;

	if (!device)
		return;

	dev_path = device_get_path(device);

	emit_property_changed(conn, dev_path, DEVICE_INTERFACE, "Class",
				DBUS_TYPE_UINT32, &class);
}

void btd_event_remote_name(bdaddr_t *local, bdaddr_t *peer, uint8_t status,
				char *name)
{
	struct btd_adapter *adapter;
	char srcaddr[18], dstaddr[18];
	int state;
	struct btd_device *device;
	struct remote_dev_info match, *dev_info;

	if (status == 0) {
		char *end;

		/* It's ok to cast end between const and non-const since
		 * we know it points to inside of name which is non-const */
		if (!g_utf8_validate(name, -1, (const char **) &end))
			*end = '\0';

		write_device_name(local, peer, name);
	}

	if (!get_adapter_and_device(local, peer, &adapter, &device, FALSE))
		return;

	ba2str(local, srcaddr);
	ba2str(peer, dstaddr);

	if (status != 0)
		goto proceed;

	bacpy(&match.bdaddr, peer);
	match.name_status = NAME_ANY;

	dev_info = adapter_search_found_devices(adapter, &match);
	if (dev_info) {
		g_free(dev_info->name);
		dev_info->name = g_strdup(name);
		adapter_emit_device_found(adapter, dev_info);
	}

	if (device)
		device_set_name(device, name);

proceed:
	/* remove from remote name request list */
	adapter_remove_found_device(adapter, peer);

	/* check if there is more devices to request names */
	if (adapter_resolve_names(adapter) == 0)
		return;

	state = adapter_get_state(adapter);
	state &= ~STATE_RESOLVNAME;
	adapter_set_state(adapter, state);
}

int btd_event_link_key_notify(bdaddr_t *local, bdaddr_t *peer,
				uint8_t *key, uint8_t key_type,
				uint8_t pin_length)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	int ret;

	if (!get_adapter_and_device(local, peer, &adapter, &device, TRUE))
		return -ENODEV;

	DBG("storing link key of type 0x%02x", key_type);

	ret = write_link_key(local, peer, key, key_type, pin_length);

	if (ret == 0 && device_is_temporary(device))
		device_set_temporary(device, FALSE);

	return ret;
}

void btd_event_conn_complete(bdaddr_t *local, bdaddr_t *peer)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(local, peer, &adapter, &device, TRUE))
		return;

	update_lastused(local, peer);

	adapter_add_connection(adapter, device);
}

void btd_event_conn_failed(bdaddr_t *local, bdaddr_t *peer, uint8_t status)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	DBusConnection *conn = get_dbus_connection();

	DBG("status 0x%02x", status);

	if (!get_adapter_and_device(local, peer, &adapter, &device, FALSE))
		return;

	if (!device)
		return;

	if (device_is_temporary(device))
		adapter_remove_device(conn, adapter, device, TRUE);
}

void btd_event_disconn_complete(bdaddr_t *local, bdaddr_t *peer)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	DBG("");

	if (!get_adapter_and_device(local, peer, &adapter, &device, FALSE))
		return;

	if (!device)
		return;

	adapter_remove_connection(adapter, device);
}

/* Section reserved to device HCI callbacks */

void btd_event_le_set_scan_enable_complete(bdaddr_t *local, uint8_t status)
{
	struct btd_adapter *adapter;
	int state;

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	if (status) {
		error("Can't enable/disable LE scan");
		return;
	}

	state = adapter_get_state(adapter);

	/* Enabling or disabling ? */
	if (state & STATE_LE_SCAN)
		state &= ~STATE_LE_SCAN;
	else
		state |= STATE_LE_SCAN;

	adapter_set_state(adapter, state);
}

void btd_event_returned_link_key(bdaddr_t *local, bdaddr_t *peer)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(local, peer, &adapter, &device, TRUE))
		return;

	device_set_paired(device, TRUE);
}
