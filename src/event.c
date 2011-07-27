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
#include <ctype.h>
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
#include "eir.h"

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
	bdaddr_t dba;
	int err;

	device_get_address(device, &dba);

	if (derr) {
		err = btd_adapter_pincode_reply(adapter, &dba, NULL, 0);
		if (err < 0)
			goto fail;
		return;
	}

	err = btd_adapter_pincode_reply(adapter, &dba, pincode,
						pincode ? strlen(pincode) : 0);
	if (err < 0)
		goto fail;

	return;

fail:
	error("Sending PIN code reply failed: %s (%d)", strerror(-err), -err);
}

int btd_event_request_pin(bdaddr_t *sba, bdaddr_t *dba, gboolean secure)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	char pin[17];
	ssize_t pinlen;

	if (!get_adapter_and_device(sba, dba, &adapter, &device, TRUE))
		return -ENODEV;

	memset(pin, 0, sizeof(pin));
	pinlen = btd_adapter_get_pin(adapter, device, pin);
	if (pinlen > 0 && (!secure || pinlen == 16)) {
		btd_adapter_pincode_reply(adapter, dba, pin, pinlen);
		return 0;
	}

	return device_request_authentication(device, AUTH_TYPE_PINCODE, 0,
							secure, pincode_cb);
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
						passkey, FALSE, confirm_cb);
}

int btd_event_user_passkey(bdaddr_t *sba, bdaddr_t *dba)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(sba, dba, &adapter, &device, TRUE))
		return -ENODEV;

	return device_request_authentication(device, AUTH_TYPE_PASSKEY, 0,
							FALSE, passkey_cb);
}

int btd_event_user_notify(bdaddr_t *sba, bdaddr_t *dba, uint32_t passkey)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(sba, dba, &adapter, &device, TRUE))
		return -ENODEV;

	return device_request_authentication(device, AUTH_TYPE_NOTIFY, passkey,
								FALSE, NULL);
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
	struct btd_adapter *adapter;

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	update_lastseen(local, peer);
	write_remote_class(local, peer, class);

	if (data)
		write_remote_eir(local, peer, data);

	adapter_update_found_devices(adapter, peer, class, rssi, data);
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
	struct btd_adapter *adapter;
	struct btd_device *device;
	uint32_t old_class = 0;

	read_remote_class(local, peer, &old_class);

	if (old_class == class)
		return;

	write_remote_class(local, peer, class);

	if (!get_adapter_and_device(local, peer, &adapter, &device, FALSE))
		return;

	if (!device)
		return;

	device_set_class(device, class);
}

void btd_event_remote_name(bdaddr_t *local, bdaddr_t *peer, uint8_t status,
				char *name)
{
	struct btd_adapter *adapter;
	char srcaddr[18], dstaddr[18];
	struct btd_device *device;
	struct remote_dev_info match, *dev_info;

	if (status == 0) {
		if (!g_utf8_validate(name, -1, NULL)) {
			int i;

			/* Assume ASCII, and replace all non-ASCII with
			 * spaces */
			for (i = 0; name[i] != '\0'; i++) {
				if (!isascii(name[i]))
					name[i] = ' ';
			}
			/* Remove leading and trailing whitespace characters */
			g_strstrip(name);
		}

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

	adapter_set_state(adapter, STATE_IDLE);
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

	if (ret == 0) {
		device_set_bonded(device, TRUE);

		if (device_is_temporary(device))
			device_set_temporary(device, FALSE);
	}

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

	if (device_is_bonding(device, NULL))
		device_cancel_bonding(device, status);

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

void btd_event_returned_link_key(bdaddr_t *local, bdaddr_t *peer)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(local, peer, &adapter, &device, TRUE))
		return;

	device_set_paired(device, TRUE);
}
