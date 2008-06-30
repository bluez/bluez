/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "hcid.h"
#include "textfile.h"
#include "manager.h"
#include "adapter.h"
#include "device.h"
#include "error.h"
#include "glib-helper.h"
#include "dbus-common.h"
#include "dbus-error.h"
#include "dbus-service.h"
#include "dbus-security.h"
#include "agent.h"
#include "dbus-hci.h"

static DBusConnection *connection = NULL;

void bonding_request_free(struct bonding_request_info *bonding)
{
	struct device *device;
	char address[18];

	if (!bonding)
		return;

	if (bonding->msg)
		dbus_message_unref(bonding->msg);

	if (bonding->conn)
		dbus_connection_unref(bonding->conn);

	if (bonding->io)
		g_io_channel_unref(bonding->io);

	ba2str(&bonding->bdaddr, address);

	device = adapter_find_device(bonding->adapter, address);
	if (device && device->agent) {
		agent_destroy(device->agent, FALSE);
		device->agent = NULL;
	}

	g_free(bonding);
}

int found_device_cmp(const struct remote_dev_info *d1,
			const struct remote_dev_info *d2)
{
	int ret;

	if (bacmp(&d2->bdaddr, BDADDR_ANY)) {
		ret = bacmp(&d1->bdaddr, &d2->bdaddr);
		if (ret)
			return ret;
	}

	if (d2->name_status != NAME_ANY) {
		ret = (d1->name_status - d2->name_status);
		if (ret)
			return ret;
	}

	return 0;
}

int dev_rssi_cmp(struct remote_dev_info *d1, struct remote_dev_info *d2)
{
	int rssi1, rssi2;

	rssi1 = d1->rssi < 0 ? -d1->rssi : d1->rssi;
	rssi2 = d2->rssi < 0 ? -d2->rssi : d2->rssi;

	return rssi1 - rssi2;
}

int found_device_add(GSList **list, bdaddr_t *bdaddr, int8_t rssi,
			name_status_t name_status)
{
	struct remote_dev_info *dev, match;
	GSList *l;

	memset(&match, 0, sizeof(struct remote_dev_info));
	bacpy(&match.bdaddr, bdaddr);
	match.name_status = NAME_ANY;

	/* ignore repeated entries */
	l = g_slist_find_custom(*list, &match, (GCompareFunc) found_device_cmp);
	if (l) {
		/* device found, update the attributes */
		dev = l->data;

		if (rssi != 0)
			dev->rssi = rssi;

		 /* Get remote name can be received while inquiring.
		  * Keep in mind that multiple inquiry result events can
		  * be received from the same remote device.
		  */
		if (name_status != NAME_NOT_REQUIRED)
			dev->name_status = name_status;

		*list = g_slist_sort(*list, (GCompareFunc) dev_rssi_cmp);

		return -EALREADY;
	}

	dev = g_new0(struct remote_dev_info, 1);

	bacpy(&dev->bdaddr, bdaddr);
	dev->rssi = rssi;
	dev->name_status = name_status;

	*list = g_slist_insert_sorted(*list, dev, (GCompareFunc) dev_rssi_cmp);

	return 0;
}

static int found_device_remove(GSList **list, bdaddr_t *bdaddr)
{
	struct remote_dev_info *dev, match;
	GSList *l;

	memset(&match, 0, sizeof(struct remote_dev_info));
	bacpy(&match.bdaddr, bdaddr);

	l = g_slist_find_custom(*list, &match, (GCompareFunc) found_device_cmp);
	if (!l)
		return -1;

	dev = l->data;
	*list = g_slist_remove(*list, dev);
	g_free(dev);

	return 0;
}

int active_conn_find_by_bdaddr(const void *data, const void *user_data)
{
	const struct active_conn_info *con = data;
	const bdaddr_t *bdaddr = user_data;

	return bacmp(&con->bdaddr, bdaddr);
}

static int active_conn_find_by_handle(const void *data, const void *user_data)
{
	const struct active_conn_info *dev = data;
	const uint16_t *handle = user_data;

	if (dev->handle == *handle)
		return 0;

	return -1;
}

static int active_conn_append(GSList **list, bdaddr_t *bdaddr,
				uint16_t handle)
{
	struct active_conn_info *dev;

	dev = g_new0(struct active_conn_info, 1);

	bacpy(&dev->bdaddr, bdaddr);
	dev->handle = handle;

	*list = g_slist_append(*list, dev);
	return 0;
}

DBusMessage *new_authentication_return(DBusMessage *msg, uint8_t status)
{
	switch (status) {
	case 0x00: /* success */
		return dbus_message_new_method_return(msg);

	case 0x04: /* page timeout */
	case 0x08: /* connection timeout */
	case 0x10: /* connection accept timeout */
	case 0x22: /* LMP response timeout */
	case 0x28: /* instant passed - is this a timeout? */
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".AuthenticationTimeout",
					"Authentication Timeout");
	case 0x17: /* too frequent pairing attempts */
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".RepeatedAttempts",
					"Repeated Attempts");

	case 0x06:
	case 0x18: /* pairing not allowed (e.g. gw rejected attempt) */
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".AuthenticationRejected",
					"Authentication Rejected");

	case 0x07: /* memory capacity */
	case 0x09: /* connection limit */
	case 0x0a: /* synchronous connection limit */
	case 0x0d: /* limited resources */
	case 0x14: /* terminated due to low resources */
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".AuthenticationCanceled",
					"Authentication Canceled");

	case 0x05: /* authentication failure */
	case 0x0E: /* rejected due to security reasons - is this auth failure? */
	case 0x25: /* encryption mode not acceptable - is this auth failure? */
	case 0x26: /* link key cannot be changed - is this auth failure? */
	case 0x29: /* pairing with unit key unsupported - is this auth failure? */
	case 0x2f: /* insufficient security - is this auth failure? */
	default:
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".AuthenticationFailed",
					"Authentication Failed");
	}
}

static dbus_bool_t send_adapter_signal(DBusConnection *conn, int devid,
					const char *name, int first, ...)
{
	va_list var_args;
	dbus_bool_t ret;
	char path[MAX_PATH_LENGTH];

	snprintf(path, sizeof(path)-1, "%s/hci%d", BASE_PATH, devid);

	va_start(var_args, first);
	ret = g_dbus_emit_signal_valist(conn, path, ADAPTER_INTERFACE,
							name, first, var_args);
	va_end(var_args);

	return ret;
}

static void adapter_mode_changed(struct adapter *adapter, uint8_t scan_enable)
{
	const char *mode;

	adapter->scan_enable = scan_enable;

	switch (scan_enable) {
	case SCAN_DISABLED:
		mode = "off";
		adapter->mode = MODE_OFF;
		break;
	case SCAN_PAGE:
		mode = "connectable";
		adapter->mode = MODE_CONNECTABLE;
		break;
	case (SCAN_PAGE | SCAN_INQUIRY):

		if (adapter->discov_timeout != 0)
			adapter->timeout_id = g_timeout_add(adapter->discov_timeout * 1000,
					discov_timeout_handler, adapter);

		if (adapter->mode == MODE_LIMITED) {
			mode = "limited";
		} else {
			adapter->mode = MODE_DISCOVERABLE;
			mode = "discoverable";
		}
		break;
	case SCAN_INQUIRY:
		/* Address the scenario where another app changed the scan mode */
		if (adapter->discov_timeout != 0)
			adapter->timeout_id = g_timeout_add(adapter->discov_timeout * 1000,
					discov_timeout_handler, adapter);
		/* ignore, this event should not be sent*/
	default:
		/* ignore, reserved */
		return;
	}

	g_dbus_emit_signal(connection, adapter->path, ADAPTER_INTERFACE,
					"ModeChanged",
					DBUS_TYPE_STRING, &mode,
					DBUS_TYPE_INVALID);

	if (hcid_dbus_use_experimental()) {
		const char *ptr = adapter->path + ADAPTER_PATH_INDEX;
		dbus_connection_emit_property_changed(connection, ptr,
						ADAPTER_INTERFACE, "Mode",
						DBUS_TYPE_STRING, &mode);
	}
}

/*
 * HCI D-Bus services
 */
static void reply_pending_requests(const char *path, struct adapter *adapter)
{
	if (!path || !adapter)
		return;

	/* pending bonding */
	if (adapter->bonding) {
		error_authentication_canceled(connection, adapter->bonding->msg);

		remove_pending_device(adapter);

		g_dbus_remove_watch(adapter->bonding->conn,
					adapter->bonding->listener_id);

		if (adapter->bonding->io_id)
			g_source_remove(adapter->bonding->io_id);
		g_io_channel_close(adapter->bonding->io);
		bonding_request_free(adapter->bonding);
		adapter->bonding = NULL;
	}

	/* If there is a pending reply for discovery cancel */
	if (adapter->discovery_cancel) {
		DBusMessage *reply;
		reply = dbus_message_new_method_return(adapter->discovery_cancel);
		dbus_connection_send(connection, reply, NULL);
		dbus_message_unref(reply);
		dbus_message_unref(adapter->discovery_cancel);
		adapter->discovery_cancel = NULL;
	}

	if (adapter->discov_active) {
		/* Send discovery completed signal if there isn't name
		 * to resolve */
		if (hcid_dbus_use_experimental()) {
			const char *ptr = path + ADAPTER_PATH_INDEX;

			g_dbus_emit_signal(connection, ptr,
						ADAPTER_INTERFACE,
						"DiscoveryCompleted",
						DBUS_TYPE_INVALID);

		}

		g_dbus_emit_signal(connection, path,
						ADAPTER_INTERFACE,
						"DiscoveryCompleted",
						DBUS_TYPE_INVALID);

		/* Cancel inquiry initiated by D-Bus client */
		if (adapter->discov_requestor)
			cancel_discovery(adapter);
	}

	if (adapter->pdiscov_active) {
		/* Send periodic discovery stopped signal exit or stop
		 * the device */
		g_dbus_emit_signal(connection, path,
						ADAPTER_INTERFACE,
						"PeriodicDiscoveryStopped",
						DBUS_TYPE_INVALID);

		/* Stop periodic inquiry initiated by D-Bus client */
		if (adapter->pdiscov_requestor)
			cancel_periodic_discovery(adapter);
	}
}

static void do_unregister(gpointer data, gpointer user_data)
{
	DBusConnection *conn = user_data;
	struct device *device = data;

	device_remove(conn, device);
}

int unregister_adapter_path(const char *path)
{
	struct adapter *adapter;

	info("Unregister path: %s", path);

	__remove_servers(path);

	adapter = manager_find_adapter_by_path(path);
	if (!adapter)
		goto unreg;

	/* check pending requests */
	reply_pending_requests(path, adapter);

	cancel_passkey_agent_requests(adapter->passkey_agents, path, NULL);

	release_passkey_agents(adapter, NULL);

	if (adapter->agent) {
		agent_destroy(adapter->agent, FALSE);
		adapter->agent = NULL;
	}

	if (adapter->discov_requestor) {
		g_dbus_remove_watch(connection, adapter->discov_listener);
		adapter->discov_listener = 0;
		g_free(adapter->discov_requestor);
		adapter->discov_requestor = NULL;
	}

	if (adapter->pdiscov_requestor) {
		g_dbus_remove_watch(connection, adapter->pdiscov_listener);
		adapter->pdiscov_listener = 0;
		g_free(adapter->pdiscov_requestor);
		adapter->pdiscov_requestor = NULL;
	}

	if (adapter->found_devices) {
		g_slist_foreach(adapter->found_devices,
				(GFunc) g_free, NULL);
		g_slist_free(adapter->found_devices);
		adapter->found_devices = NULL;
	}

	if (adapter->oor_devices) {
		g_slist_foreach(adapter->oor_devices,
				(GFunc) free, NULL);
		g_slist_free(adapter->oor_devices);
		adapter->oor_devices = NULL;
	}

	if (adapter->auth_reqs) {
		g_slist_foreach(adapter->auth_reqs,
				(GFunc) g_free, NULL);
		g_slist_free(adapter->auth_reqs);
		adapter->auth_reqs = NULL;
	}

	if (adapter->active_conn) {
		g_slist_foreach(adapter->active_conn,
				(GFunc) free, NULL);
		g_slist_free(adapter->active_conn);
		adapter->active_conn = NULL;
	}

	/* Check if there is a pending RemoteDeviceDisconnect request */
	if (adapter->pending_dc) {
		error_no_such_adapter(adapter->pending_dc->conn,
				      adapter->pending_dc->msg);
		g_source_remove(adapter->pending_dc->timeout_id);
		dc_pending_timeout_cleanup(adapter);
	}

	if (adapter->devices) {
		g_slist_foreach(adapter->devices, do_unregister,
							connection);
		g_slist_free(adapter->devices);
	}

	manager_remove_adapter(adapter);

	g_free(adapter->path);
	g_free(adapter);

unreg:
	if (!adapter_cleanup(connection, path)) {
		error("Failed to unregister adapter interface on %s object",
			path);
		return -1;
	}

	if (!security_cleanup(connection, path)) {
		error("Failed to unregister security interface on %s object",
			path);
		return -1;
	}

	if (hcid_dbus_use_experimental()) {
		const char *ptr = path + ADAPTER_PATH_INDEX;

		adapter_cleanup(connection, ptr);
	}

	return 0;
}

/*****************************************************************
 *
 *  Section reserved to HCI commands confirmation handling and low
 *  level events(eg: device attached/dettached.
 *
 *****************************************************************/

int hcid_dbus_register_device(uint16_t id)
{
	char path[MAX_PATH_LENGTH];
	char *ptr = path + ADAPTER_PATH_INDEX;
	struct adapter *adapter;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	adapter = g_try_new0(struct adapter, 1);
	if (!adapter) {
		error("Failed to alloc memory to D-Bus path register data (%s)",
				path);
		return -1;
	}

	adapter->dev_id = id;
	adapter->pdiscov_resolve_names = 1;

	if (!adapter_init(connection, path, adapter)) {
		error("Adapter interface init failed on path %s", path);
		g_free(adapter);
		return -1;
	}

	adapter->path = g_strdup(path);

	if (!security_init(connection, path)) {
		error("Security interface init failed on path %s", path);
		goto failed;
	}

	__probe_servers(path);

	manager_add_adapter(adapter);

	return 0;

failed:
	if (hcid_dbus_use_experimental())
		g_dbus_unregister_interface(connection, ptr, ADAPTER_INTERFACE);

	g_dbus_unregister_interface(connection, path, ADAPTER_INTERFACE);

	g_free(adapter->path);
	g_free(adapter);

	return -1;
}

int hcid_dbus_unregister_device(uint16_t id)
{
	char path[MAX_PATH_LENGTH];

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	return unregister_adapter_path(path);
}

static void create_stored_device_from_profiles(char *key, char *value,
						void *user_data)
{
	struct adapter *adapter = user_data;
	GSList *uuids = bt_string2list(value);
	struct device *device;

	device = device_create(connection, adapter, key);
	if (device) {
		device->temporary = FALSE;
		adapter->devices = g_slist_append(adapter->devices, device);
		device_probe_drivers(device, uuids);
		g_slist_free(uuids);
	}
}

static void create_stored_device_from_linkkeys(char *key, char *value,
						void *user_data)
{
	struct adapter *adapter = user_data;
	struct device *device;

	if (g_slist_find_custom(adapter->devices,
				key, (GCompareFunc) device_address_cmp))
		return;

	device = device_create(connection, adapter, key);
	if (device) {
		device->temporary = FALSE;
		adapter->devices = g_slist_append(adapter->devices, device);
	}
}

static void register_devices(bdaddr_t *src, struct adapter *adapter)
{
	char filename[PATH_MAX + 1];
	char addr[18];

	ba2str(src, addr);

	create_name(filename, PATH_MAX, STORAGEDIR, addr, "profiles");
	textfile_foreach(filename, create_stored_device_from_profiles, adapter);

	create_name(filename, PATH_MAX, STORAGEDIR, addr, "linkkeys");
	textfile_foreach(filename, create_stored_device_from_linkkeys, adapter);
}

int hcid_dbus_start_device(uint16_t id)
{
	char path[MAX_PATH_LENGTH];
	char *ptr = path + ADAPTER_PATH_INDEX;
	struct hci_dev_info di;
	struct adapter* adapter;
	struct hci_conn_list_req *cl = NULL;
	struct hci_conn_info *ci;
	const char *mode;
	int i, err, dd = -1, ret = -1;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (hci_devinfo(id, &di) < 0) {
		error("Getting device info failed: hci%d", id);
		return -1;
	}

	if (hci_test_bit(HCI_RAW, &di.flags))
		return -1;

	adapter = manager_find_adapter_by_path(path);
	if (!adapter) {
		error("Getting %s path data failed!", path);
		return -1;
	}

	if (hci_test_bit(HCI_INQUIRY, &di.flags))
		adapter->discov_active = 1;
	else
		adapter->discov_active = 0;

	adapter->up = 1;
	adapter->discov_timeout = get_discoverable_timeout(id);
	adapter->discov_type = DISCOVER_TYPE_NONE;

	dd = hci_open_dev(id);
	if (dd < 0)
		goto failed;

	adapter->scan_enable = get_startup_scan(id);
	hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE,
					1, &adapter->scan_enable);
	/*
	 * Get the adapter Bluetooth address
	 */
	err = get_device_address(adapter->dev_id, adapter->address,
					sizeof(adapter->address));
	if (err < 0)
		goto failed;

	err = get_device_class(adapter->dev_id, adapter->class);
	if (err < 0)
		goto failed;

	adapter->mode = get_startup_mode(id);
	if (adapter->mode == MODE_LIMITED)
		set_limited_discoverable(dd, adapter->class, TRUE);

	/*
	 * retrieve the active connections: address the scenario where
	 * the are active connections before the daemon've started
	 */

	cl = g_malloc0(10 * sizeof(*ci) + sizeof(*cl));

	cl->dev_id = id;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(dd, HCIGETCONNLIST, cl) < 0)
		goto failed;

	for (i = 0; i < cl->conn_num; i++, ci++)
		active_conn_append(&adapter->active_conn,
					&ci->bdaddr, ci->handle);

	ret = 0;

	mode = mode2str(adapter->mode);
	g_dbus_emit_signal(connection, path, ADAPTER_INTERFACE,
					"ModeChanged",
					DBUS_TYPE_STRING, &mode,
					DBUS_TYPE_INVALID);

	if (hcid_dbus_use_experimental()) {
		dbus_connection_emit_property_changed(connection, ptr,
						ADAPTER_INTERFACE, "Mode",
						DBUS_TYPE_STRING, &mode);
	}

	if (manager_get_default_adapter() < 0)
		manager_set_default_adapter(id);

	if (hcid_dbus_use_experimental())
		register_devices(&di.bdaddr, adapter);

failed:
	if (dd >= 0)
		hci_close_dev(dd);

	g_free(cl);

	return ret;
}

static void send_dc_signal(struct active_conn_info *dev, const char *path)
{
	char addr[18];
	const char *paddr = addr;

	ba2str(&dev->bdaddr, addr);

	g_dbus_emit_signal(connection, path, ADAPTER_INTERFACE,
					"RemoteDeviceDisconnected",
					DBUS_TYPE_STRING, &paddr,
					DBUS_TYPE_INVALID);
}

int hcid_dbus_stop_device(uint16_t id)
{
	char path[MAX_PATH_LENGTH];
	struct adapter *adapter;
	const char *mode = "off";

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	adapter = manager_find_adapter_by_path(path);
	if (!adapter) {
		error("Getting %s path data failed!", path);
		return -1;
	}

	/* cancel pending timeout */
	if (adapter->timeout_id) {
		g_source_remove(adapter->timeout_id);
		adapter->timeout_id = 0;
	}

	/* check pending requests */
	reply_pending_requests(path, adapter);

	cancel_passkey_agent_requests(adapter->passkey_agents, path, NULL);

	release_passkey_agents(adapter, NULL);

	if (adapter->discov_requestor) {
		g_dbus_remove_watch(connection, adapter->discov_listener);
		adapter->discov_listener = 0;
		g_free(adapter->discov_requestor);
		adapter->discov_requestor = NULL;
	}

	if (adapter->pdiscov_requestor) {
		g_dbus_remove_watch(connection, adapter->pdiscov_listener);
		adapter->pdiscov_listener = 0;
		g_free(adapter->pdiscov_requestor);
		adapter->pdiscov_requestor = NULL;
	}

	if (adapter->found_devices) {
		g_slist_foreach(adapter->found_devices, (GFunc) g_free, NULL);
		g_slist_free(adapter->found_devices);
		adapter->found_devices = NULL;
	}

	if (adapter->oor_devices) {
		g_slist_foreach(adapter->oor_devices, (GFunc) free, NULL);
		g_slist_free(adapter->oor_devices);
		adapter->oor_devices = NULL;
	}

	if (adapter->auth_reqs) {
		g_slist_foreach(adapter->auth_reqs, (GFunc) g_free, NULL);
		g_slist_free(adapter->auth_reqs);
		adapter->auth_reqs = NULL;
	}

	if (adapter->active_conn) {
		g_slist_foreach(adapter->active_conn, (GFunc) send_dc_signal, path);
		g_slist_foreach(adapter->active_conn, (GFunc) g_free, NULL);
		g_slist_free(adapter->active_conn);
		adapter->active_conn = NULL;
	}

	send_adapter_signal(connection, adapter->dev_id, "ModeChanged",
				DBUS_TYPE_STRING, &mode,
				DBUS_TYPE_INVALID);

	if (hcid_dbus_use_experimental()) {
		const char *ptr = path + ADAPTER_PATH_INDEX;
		dbus_connection_emit_property_changed(connection, ptr,
						ADAPTER_INTERFACE, "Mode",
						DBUS_TYPE_STRING, &mode);
	}

	adapter->up = 0;
	adapter->scan_enable = SCAN_DISABLED;
	adapter->mode = MODE_OFF;
	adapter->discov_active = 0;
	adapter->pdiscov_active = 0;
	adapter->pinq_idle = 0;
	adapter->discov_type = DISCOVER_TYPE_NONE;

	return 0;
}

static void pincode_cb(struct agent *agent, DBusError *err, const char *pincode,
			struct device *device)
{
	struct adapter *adapter = device->adapter;
	pin_code_reply_cp pr;
	bdaddr_t sba, dba;
	size_t len;
	int dev;
	struct pending_auth_info *auth;

	/* No need to reply anything if the authentication already failed */
	if (adapter->bonding && adapter->bonding->hci_status)
		return;

	dev = hci_open_dev(adapter->dev_id);
	if (dev < 0) {
		error("hci_open_dev(%d): %s (%d)", adapter->dev_id,
				strerror(errno), errno);
		return;
	}

	str2ba(adapter->address, &sba);
	str2ba(device->address, &dba);

	auth = adapter_find_auth_request(adapter, &dba);

	if (err) {
		hci_send_cmd(dev, OGF_LINK_CTL,
				OCF_PIN_CODE_NEG_REPLY, 6, &dba);
		goto done;
	}

	len = strlen(pincode);

	set_pin_length(&sba, len);

	memset(&pr, 0, sizeof(pr));
	bacpy(&pr.bdaddr, &dba);
	memcpy(pr.pin_code, pincode, len);
	pr.pin_len = len;
	hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_REPLY, PIN_CODE_REPLY_CP_SIZE, &pr);

done:
	if (auth) {
		auth->replied = TRUE;
		auth->agent = NULL;
	}
	hci_close_dev(dev);
}

int hcid_dbus_request_pin(int dev, bdaddr_t *sba, struct hci_conn_info *ci)
{
	char addr[18];
	struct adapter *adapter;
	struct device *device;
	struct agent *agent;
	int ret;

	adapter = manager_find_adapter(sba);
	if (!adapter) {
		error("No matching adapter found");
		return -1;
	}

	if (!hcid_dbus_use_experimental())
		goto old_fallback;

	ba2str(&ci->bdaddr, addr);

	device = adapter_find_device(adapter, addr);
	agent = device && device->agent ? device->agent : adapter->agent;
	if (!agent)
		goto old_fallback;

	if (!device) {
		device = adapter_create_device(connection, adapter, addr);
		if (!device)
			return -ENODEV;
	}

	ret = agent_request_pincode(agent, device,
					(agent_pincode_cb) pincode_cb,
					device);
	if (ret == 0) {
		struct pending_auth_info *auth;
		auth = adapter_new_auth_request(adapter, &ci->bdaddr,
						AUTH_TYPE_PINCODE);
		auth->agent = agent;
	}


	return ret;

old_fallback:
	ret = handle_passkey_request_old(connection, dev, adapter, sba,
						&ci->bdaddr);
	if (ret == 0)
		adapter_new_auth_request(adapter, &ci->bdaddr,
						AUTH_TYPE_PINCODE);
	return ret;
}

static void confirm_cb(struct agent *agent, DBusError *err, void *user_data)
{
	struct device *device = user_data;
	struct adapter *adapter = device->adapter;
	user_confirm_reply_cp cp;
	int dd;
	struct pending_auth_info *auth;

	/* No need to reply anything if the authentication already failed */
	if (adapter->bonding && adapter->bonding->hci_status)
		return;

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0) {
		error("Unable to open hci%d", adapter->dev_id);
		return;
	}

	memset(&cp, 0, sizeof(cp));
	str2ba(device->address, &cp.bdaddr);

	auth = adapter_find_auth_request(adapter, &cp.bdaddr);

	if (err)
		hci_send_cmd(dd, OGF_LINK_CTL, OCF_USER_CONFIRM_NEG_REPLY,
					USER_CONFIRM_REPLY_CP_SIZE, &cp);
	else
		hci_send_cmd(dd, OGF_LINK_CTL, OCF_USER_CONFIRM_REPLY,
					USER_CONFIRM_REPLY_CP_SIZE, &cp);

	if (auth) {
		auth->replied = TRUE;
		auth->agent = FALSE;
	}

	hci_close_dev(dd);
}

static void passkey_cb(struct agent *agent, DBusError *err, uint32_t passkey,
			void *user_data)
{
	struct device *device = user_data;
	struct adapter *adapter = device->adapter;
	user_passkey_reply_cp cp;
	bdaddr_t dba;
	int dd;
	struct pending_auth_info *auth;

	/* No need to reply anything if the authentication already failed */
	if (adapter->bonding && adapter->bonding->hci_status)
		return;

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0) {
		error("Unable to open hci%d", adapter->dev_id);
		return;
	}

	str2ba(device->address, &dba);

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, &dba);
	cp.passkey = passkey;

	auth = adapter_find_auth_request(adapter, &dba);

	if (err)
		hci_send_cmd(dd, OGF_LINK_CTL,
				OCF_USER_PASSKEY_NEG_REPLY, 6, &dba);
	else
		hci_send_cmd(dd, OGF_LINK_CTL, OCF_USER_PASSKEY_REPLY,
					USER_PASSKEY_REPLY_CP_SIZE, &cp);

	if (auth) {
		auth->replied = TRUE;
		auth->agent = NULL;
	}

	hci_close_dev(dd);
}

static int get_auth_requirements(bdaddr_t *local, bdaddr_t *remote,
							uint8_t *auth)
{
	struct hci_auth_info_req req;
	char addr[18];
	int err, dd, dev_id;

	ba2str(local, addr);

	dev_id = hci_devid(addr);
	if (dev_id < 0)
		return dev_id;

	dd = hci_open_dev(dev_id);
	if (dd < 0)
		return dd;

	memset(&req, 0, sizeof(req));
	bacpy(&req.bdaddr, remote);

	err = ioctl(dd, HCIGETAUTHINFO, (unsigned long) &req);
	if (err < 0) {
		debug("HCIGETAUTHINFO failed: %s (%d)",
					strerror(errno), errno);
		hci_close_dev(dd);
		return err;
	}

	hci_close_dev(dd);

	if (auth)
		*auth = req.type;

	return 0;
}

int hcid_dbus_user_confirm(bdaddr_t *sba, bdaddr_t *dba, uint32_t passkey)
{
	struct adapter *adapter;
	struct device *device;
	struct agent *agent;
	char addr[18];
	uint8_t type;
	struct pending_auth_info *auth;

	adapter = manager_find_adapter(sba);
	if (!adapter) {
		error("No matching adapter found");
		return -1;
	}

	if (get_auth_requirements(sba, dba, &type) < 0) {
		int dd;

		dd = hci_open_dev(adapter->dev_id);
		if (dd < 0) {
			error("Unable to open hci%d", adapter->dev_id);
			return -1;
		}

		hci_send_cmd(dd, OGF_LINK_CTL,
					OCF_USER_CONFIRM_NEG_REPLY, 6, dba);

		hci_close_dev(dd);

		return 0;
	}

	ba2str(dba, addr);

	device = adapter_get_device(connection, adapter, addr);
	if (!device) {
		error("Device creation failed");
		return -1;
	}

	/* If no MITM protection required, auto-accept */
	if (!(device->auth & 0x01) && !(type & 0x01)) {
		int dd;

		dd = hci_open_dev(adapter->dev_id);
		if (dd < 0) {
			error("Unable to open hci%d", adapter->dev_id);
			return -1;
		}

		hci_send_cmd(dd, OGF_LINK_CTL,
					OCF_USER_CONFIRM_REPLY, 6, dba);

		hci_close_dev(dd);

		return 0;
	}

	if (device->agent)
		agent = device->agent;
	else
		agent = adapter->agent;

	if (!agent) {
		error("No agent available for user confirm request");
		return -1;
	}

	if (agent_request_confirmation(agent, device, passkey,
						confirm_cb, device) < 0) {
		error("Requesting passkey failed");
		return -1;
	}

	auth = adapter_new_auth_request(adapter, dba, AUTH_TYPE_CONFIRM);
	auth->agent = agent;

	return 0;
}

int hcid_dbus_user_passkey(bdaddr_t *sba, bdaddr_t *dba)
{
	struct adapter *adapter;
	struct device *device;
	struct agent *agent;
	char addr[18];
	struct pending_auth_info *auth;

	adapter = manager_find_adapter(sba);
	if (!adapter) {
		error("No matching adapter found");
		return -1;
	}

	ba2str(dba, addr);

	device = adapter_get_device(connection, adapter, addr);
	if (device && device->agent)
		agent = device->agent;
	else
		agent = adapter->agent;

	if (!agent) {
		error("No agent available for user confirm request");
		return -1;
	}

	if (agent_request_passkey(agent, device, passkey_cb, device) < 0) {
		error("Requesting passkey failed");
		return -1;
	}

	auth = adapter_new_auth_request(adapter, dba, AUTH_TYPE_PASSKEY);
	auth->agent = agent;

	return 0;
}

int hcid_dbus_user_notify(bdaddr_t *sba, bdaddr_t *dba, uint32_t passkey)
{
	struct adapter *adapter;
	struct device *device;
	struct agent *agent;
	char addr[18];
	struct pending_auth_info *auth;

	adapter = manager_find_adapter(sba);
	if (!adapter) {
		error("No matching adapter found");
		return -1;
	}

	ba2str(dba, addr);

	device = adapter_get_device(connection, adapter, addr);
	if (device && device->agent)
		agent = device->agent;
	else
		agent = adapter->agent;

	if (!agent) {
		error("No agent available for user confirm request");
		return -1;
	}

	if (agent_display_passkey(agent, device, passkey) < 0) {
		error("Displaying passkey failed");
		return -1;
	}

	auth = adapter_new_auth_request(adapter, dba, AUTH_TYPE_NOTIFY);
	auth->agent = agent;

	return 0;
}

void hcid_dbus_bonding_process_complete(bdaddr_t *local, bdaddr_t *peer,
					uint8_t status)
{
	struct adapter *adapter;
	char peer_addr[18];
	const char *paddr = peer_addr;
	DBusMessage *reply;
	struct device *device;
	struct bonding_request_info *bonding;
	gboolean paired = TRUE;
	struct pending_auth_info *auth;

	debug("hcid_dbus_bonding_process_complete: status=%02x", status);

	ba2str(peer, peer_addr);

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("Unable to find matching adapter");
		return;
	}

	if (status) {
		if (adapter->bonding)
			adapter->bonding->hci_status = status;
		cancel_passkey_agent_requests(adapter->passkey_agents,
						adapter->path, peer);
	}

	auth = adapter_find_auth_request(adapter, peer);
	if (!auth) {
		debug("hcid_dbus_bonding_process_complete: no pending auth request");
		goto proceed;
	}

	if (auth->agent)
		agent_cancel(auth->agent);

	adapter_remove_auth_request(adapter, peer);

	if (status)
		goto proceed;

	send_adapter_signal(connection, adapter->dev_id, "BondingCreated",
				DBUS_TYPE_STRING, &paddr, DBUS_TYPE_INVALID);

	device = adapter_get_device(connection, adapter, paddr);
	if (device) {
		char *ptr = adapter->path + ADAPTER_PATH_INDEX;

		debug("hcid_dbus_bonding_process_complete: removing temporary flag");

		device->temporary = FALSE;

		g_dbus_emit_signal(connection, ptr,
					ADAPTER_INTERFACE,
					"DeviceCreated",
					DBUS_TYPE_OBJECT_PATH,
					&device->path,
					DBUS_TYPE_INVALID);

		dbus_connection_emit_property_changed(connection, device->path,
					DEVICE_INTERFACE, "Paired",
					DBUS_TYPE_BOOLEAN, &paired);
	}

proceed:

	release_passkey_agents(adapter, peer);

	bonding = adapter->bonding;
	if (!bonding || bacmp(&bonding->bdaddr, peer))
		return; /* skip: no bonding req pending */

	if (bonding->cancel) {
		/* reply authentication canceled */
		error_authentication_canceled(connection, bonding->msg);
		goto cleanup;
	}

	/* reply authentication success or an error */
	if (dbus_message_is_method_call(bonding->msg, ADAPTER_INTERFACE,
					"CreateBonding")) {
		reply = new_authentication_return(bonding->msg, status);
		dbus_connection_send(connection, reply, NULL);
		dbus_message_unref(reply);
	} else if ((device = adapter_find_device(adapter, paddr))) {
		if (status) {
			reply = new_authentication_return(bonding->msg, status);
			dbus_connection_send(connection, reply, NULL);
			dbus_message_unref(reply);
		} else {
			device->temporary = FALSE;
			device_browse(device, bonding->conn,
					bonding->msg, NULL);
		}
	}

cleanup:
	g_dbus_remove_watch(connection, adapter->bonding->listener_id);

	if (adapter->bonding->io_id)
		g_source_remove(adapter->bonding->io_id);
	g_io_channel_close(adapter->bonding->io);
	bonding_request_free(adapter->bonding);
	adapter->bonding = NULL;
}

void hcid_dbus_inquiry_start(bdaddr_t *local)
{
	struct adapter *adapter;

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("Unable to find matching adapter");
		return;
	}

	adapter->discov_active = 1;
	/*
	 * Cancel pending remote name request and clean the device list
	 * when inquiry is supported in periodic inquiry idle state.
	 */
	if (adapter->pdiscov_active)
		pending_remote_name_cancel(adapter);

	/* Disable name resolution for non D-Bus clients */
	if (!adapter->discov_requestor)
		adapter->discov_type &= ~RESOLVE_NAME;

	if (hcid_dbus_use_experimental())
		dbus_connection_emit_property_changed(connection,
				adapter->path + ADAPTER_PATH_INDEX,
				ADAPTER_INTERFACE, "PeriodicDiscovery",
				DBUS_TYPE_BOOLEAN, &adapter->discov_active);

	send_adapter_signal(connection, adapter->dev_id, "DiscoveryStarted",
				DBUS_TYPE_INVALID);

	if (hcid_dbus_use_experimental())
		g_dbus_emit_signal(connection,
						adapter->path + ADAPTER_PATH_INDEX,
						ADAPTER_INTERFACE,
						"DiscoveryStarted",
						DBUS_TYPE_INVALID);
}

int found_device_req_name(struct adapter *adapter)
{
	struct hci_request rq;
	evt_cmd_status rp;
	remote_name_req_cp cp;
	struct remote_dev_info match;
	GSList *l;
	int dd, req_sent = 0;

	/* get the next remote address */
	if (!adapter->found_devices)
		return -ENODATA;

	memset(&match, 0, sizeof(struct remote_dev_info));
	bacpy(&match.bdaddr, BDADDR_ANY);
	match.name_status = NAME_REQUIRED;

	l = g_slist_find_custom(adapter->found_devices, &match,
					(GCompareFunc) found_device_cmp);
	if (!l)
		return -ENODATA;

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0)
		return -errno;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_REMOTE_NAME_REQ;
	rq.cparam = &cp;
	rq.clen   = REMOTE_NAME_REQ_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CMD_STATUS_SIZE;
	rq.event  = EVT_CMD_STATUS;

	/* send at least one request or return failed if the list is empty */
	do {
		struct remote_dev_info *dev = l->data;
		char peer_addr[18];
		const char *signal = NULL, *paddr = peer_addr;

		 /* flag to indicate the current remote name requested */
		dev->name_status = NAME_REQUESTED;

		memset(&rp, 0, sizeof(rp));
		memset(&cp, 0, sizeof(cp));
		bacpy(&cp.bdaddr, &dev->bdaddr);
		cp.pscan_rep_mode = 0x02;

		ba2str(&dev->bdaddr, peer_addr);

		if (hci_send_req(dd, &rq, 500) < 0) {
			error("Unable to send the HCI remote name request: %s (%d)",
						strerror(errno), errno);
			signal = "RemoteNameFailed";
		}

		if (rp.status) {
			error("Remote name request failed with status 0x%02x",
					rp.status);
			signal = "RemoteNameFailed";
		}

		if (!signal) {
			req_sent = 1;
			/* if we are in discovery, inform application of getting name */
			if (adapter->discov_type & (STD_INQUIRY | PERIODIC_INQUIRY))
				signal = "RemoteNameRequested";
		}

		if (signal)
			send_adapter_signal(connection, adapter->dev_id, signal,
						DBUS_TYPE_STRING, &paddr,
						DBUS_TYPE_INVALID);

		if (req_sent)
			break;

		/* if failed, request the next element */
		/* remove the element from the list */
		adapter->found_devices = g_slist_remove(adapter->found_devices, dev);
		g_free(dev);

		/* get the next element */
		l = g_slist_find_custom(adapter->found_devices, &match,
					(GCompareFunc) found_device_cmp);

	} while (l);

	hci_close_dev(dd);

	if (!req_sent)
		return -ENODATA;

	return 0;
}

static void send_out_of_range(const char *path, GSList *l)
{
	while (l) {
		const char *peer_addr = l->data;

		g_dbus_emit_signal(connection, path,
						ADAPTER_INTERFACE,
						"RemoteDeviceDisappeared",
						DBUS_TYPE_STRING, &peer_addr,
						DBUS_TYPE_INVALID);

		if (hcid_dbus_use_experimental()) {
			const char *ptr = path + ADAPTER_PATH_INDEX;
			g_dbus_emit_signal(connection, ptr,
						ADAPTER_INTERFACE,
						"DeviceDisappeared",
						DBUS_TYPE_STRING,
						&peer_addr,
						DBUS_TYPE_INVALID);
		}

		l = l->next;
	}
}

void hcid_dbus_inquiry_complete(bdaddr_t *local)
{
	struct adapter *adapter;
	struct remote_dev_info *dev;
	bdaddr_t tmp;

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("Unable to find matching adapter");
		return;
	}

	/* Out of range verification */
	if (adapter->pdiscov_active && !adapter->discov_active) {
		GSList *l;

		send_out_of_range(adapter->path, adapter->oor_devices);

		g_slist_foreach(adapter->oor_devices, (GFunc) free, NULL);
		g_slist_free(adapter->oor_devices);
		adapter->oor_devices = NULL;

		l = adapter->found_devices;
		while (l) {
			dev = l->data;
			baswap(&tmp, &dev->bdaddr);
			adapter->oor_devices = g_slist_append(adapter->oor_devices,
								batostr(&tmp));
			l = l->next;
		}
	}

	adapter->pinq_idle = 1;

	/*
	 * Enable resolution again: standard inquiry can be
	 * received in the periodic inquiry idle state.
	 */
	if (adapter->pdiscov_requestor && adapter->pdiscov_resolve_names)
		adapter->discov_type |= RESOLVE_NAME;

	/*
	 * The following scenarios can happen:
	 * 1. standard inquiry: always send discovery completed signal
	 * 2. standard inquiry + name resolving: send discovery completed
	 *    after name resolving
	 * 3. periodic inquiry: skip discovery completed signal
	 * 4. periodic inquiry + standard inquiry: always send discovery
	 *    completed signal
	 *
	 * Keep in mind that non D-Bus requests can arrive.
	 */

	if (!found_device_req_name(adapter))
		return;		/* skip - there is name to resolve */

	if (adapter->discov_active) {
		if (hcid_dbus_use_experimental()) {
			const char *ptr = adapter->path + ADAPTER_PATH_INDEX;
			g_dbus_emit_signal(connection, ptr,
						ADAPTER_INTERFACE,
						"DiscoveryCompleted",
						DBUS_TYPE_INVALID);

		}

		g_dbus_emit_signal(connection, adapter->path,
						ADAPTER_INTERFACE,
						"DiscoveryCompleted",
						DBUS_TYPE_INVALID);
		adapter->discov_active = 0;
	}

	/* free discovered devices list */
	g_slist_foreach(adapter->found_devices, (GFunc) g_free, NULL);
	g_slist_free(adapter->found_devices);
	adapter->found_devices = NULL;

	if (adapter->discov_requestor) {
		g_dbus_remove_watch(connection, adapter->discov_listener);
		adapter->discov_listener = 0;
		g_free(adapter->discov_requestor);
		adapter->discov_requestor = NULL;

		/* If there is a pending reply for discovery cancel */
		if (adapter->discovery_cancel) {
			DBusMessage *reply;
			reply = dbus_message_new_method_return(adapter->discovery_cancel);
			dbus_connection_send(connection, reply, NULL);
			dbus_message_unref(reply);
			dbus_message_unref(adapter->discovery_cancel);
			adapter->discovery_cancel = NULL;
		}

		/* reset the discover type for standard inquiry only */
		adapter->discov_type &= ~STD_INQUIRY;
	}
}

void hcid_dbus_periodic_inquiry_start(bdaddr_t *local, uint8_t status)
{
	struct adapter *adapter;

	/* Don't send the signal if the cmd failed */
	if (status)
		return;

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	adapter->pdiscov_active = 1;

	/* Disable name resolution for non D-Bus clients */
	if (!adapter->pdiscov_requestor)
		adapter->discov_type &= ~RESOLVE_NAME;

	if (hcid_dbus_use_experimental())
		dbus_connection_emit_property_changed(connection,
						adapter->path + ADAPTER_PATH_INDEX,
						ADAPTER_INTERFACE,
						"PeriodicDiscovery",
						DBUS_TYPE_BOOLEAN,
						&adapter->pdiscov_active);

	g_dbus_emit_signal(connection, adapter->path, ADAPTER_INTERFACE,
					"PeriodicDiscoveryStarted",
					DBUS_TYPE_INVALID);
}

void hcid_dbus_periodic_inquiry_exit(bdaddr_t *local, uint8_t status)
{
	struct adapter *adapter;
	char *ptr;

	/* Don't send the signal if the cmd failed */
	if (status)
		return;

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	ptr = adapter->path + ADAPTER_PATH_INDEX;

	/* reset the discover type to be able to handle D-Bus and non D-Bus
	 * requests */
	adapter->pdiscov_active = 0;
	adapter->discov_type &= ~(PERIODIC_INQUIRY | RESOLVE_NAME);

	/* free discovered devices list */
	g_slist_foreach(adapter->found_devices, (GFunc) g_free, NULL);
	g_slist_free(adapter->found_devices);
	adapter->found_devices = NULL;

	/* free out of range devices list */
	g_slist_foreach(adapter->oor_devices, (GFunc) free, NULL);
	g_slist_free(adapter->oor_devices);
	adapter->oor_devices = NULL;

	if (adapter->pdiscov_requestor) {
		g_dbus_remove_watch(connection, adapter->pdiscov_listener);
		adapter->pdiscov_listener = 0;
		g_free(adapter->pdiscov_requestor);
		adapter->pdiscov_requestor = NULL;
	}

	 /* workaround: inquiry completed is not sent when exiting from
	  * periodic inquiry */
	if (adapter->discov_active) {
		if (hcid_dbus_use_experimental())
			g_dbus_emit_signal(connection, ptr,
					ADAPTER_INTERFACE,
					"DiscoveryCompleted",
					DBUS_TYPE_INVALID);

		g_dbus_emit_signal(connection, adapter->path,
						ADAPTER_INTERFACE,
						"DiscoveryCompleted",
						DBUS_TYPE_INVALID);
		adapter->discov_active = 0;
	}

	/* Send discovery completed signal if there isn't name to resolve */
	g_dbus_emit_signal(connection, adapter->path,
					ADAPTER_INTERFACE,
					"PeriodicDiscoveryStopped",
					DBUS_TYPE_INVALID);

	if (hcid_dbus_use_experimental())
		dbus_connection_emit_property_changed(connection, ptr,
						ADAPTER_INTERFACE,
						"PeriodicDiscovery",
						DBUS_TYPE_BOOLEAN,
						&adapter->discov_active);
}

static char *extract_eir_name(uint8_t *data, uint8_t *type)
{
	if (!data || !type)
		return NULL;

	if (data[0] == 0)
		return NULL;

	*type = data[1];

	switch (*type) {
	case 0x08:
	case 0x09:
		return strndup((char *) (data + 2), data[0] - 1);
	}

	return NULL;
}

static void append_dict_valist(DBusMessageIter *iter,
					const char *first_key,
					va_list var_args)
{
	DBusMessageIter dict;
	const char *key;
	int type;
	void *val;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	key = first_key;
	while (key) {
		type = va_arg(var_args, int);
		val = va_arg(var_args, void *);
		dbus_message_iter_append_dict_entry(&dict, key, type, val);
		key = va_arg(var_args, char *);
	}

	dbus_message_iter_close_container(iter, &dict);
}

static void emit_device_found(const char *path, const char *address,
				const char *first_key, ...)
{
	DBusMessage *signal;
	DBusMessageIter iter;
	va_list var_args;

	signal = dbus_message_new_signal(path, ADAPTER_INTERFACE,
					"DeviceFound");
	if (!signal) {
		error("Unable to allocate new %s.DeviceFound signal",
				ADAPTER_INTERFACE);
		return;
	}
	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &address);

	va_start(var_args, first_key);
	append_dict_valist(&iter, first_key, var_args);
	va_end(var_args);

	dbus_connection_send(connection, signal, NULL);

	dbus_message_unref(signal);
}

void hcid_dbus_inquiry_result(bdaddr_t *local, bdaddr_t *peer, uint32_t class,
				int8_t rssi, uint8_t *data)
{
	char filename[PATH_MAX + 1];
	struct adapter *adapter;
	GSList *l;
	char local_addr[18], peer_addr[18], *name, *tmp_name;
	const char *paddr = peer_addr;
	struct remote_dev_info match;
	dbus_int16_t tmp_rssi = rssi;
	uint8_t name_type = 0x00;
	name_status_t name_status;

	ba2str(local, local_addr);
	ba2str(peer, peer_addr);

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	write_remote_class(local, peer, class);

	if (data)
		write_remote_eir(local, peer, data);

	/*
	 * workaround to identify situation when the daemon started and
	 * a standard inquiry or periodic inquiry was already running
	 */
	if (!adapter->discov_active && !adapter->pdiscov_active)
		adapter->pdiscov_active = 1;

	/* reset the idle flag when the inquiry complete event arrives */
	if (adapter->pdiscov_active) {
		adapter->pinq_idle = 0;

		/* Out of range list update */
		l = g_slist_find_custom(adapter->oor_devices, peer_addr,
				(GCompareFunc) strcmp);
		if (l) {
			char *dev = l->data;
			adapter->oor_devices = g_slist_remove(adapter->oor_devices,
								dev);
			g_free(dev);
		}
	}

	/* send the device found signal */
	g_dbus_emit_signal(connection, adapter->path,
					ADAPTER_INTERFACE,
					"RemoteDeviceFound",
					DBUS_TYPE_STRING, &paddr,
					DBUS_TYPE_UINT32, &class,
					DBUS_TYPE_INT16, &tmp_rssi,
					DBUS_TYPE_INVALID);

	memset(&match, 0, sizeof(struct remote_dev_info));
	bacpy(&match.bdaddr, peer);
	match.name_status = NAME_SENT;
	/* if found: don't send the name again */
	l = g_slist_find_custom(adapter->found_devices, &match,
			(GCompareFunc) found_device_cmp);
	if (l)
		return;

	/* the inquiry result can be triggered by NON D-Bus client */
	if (adapter->discov_type & RESOLVE_NAME)
		name_status = NAME_REQUIRED;
	else
		name_status = NAME_NOT_REQUIRED;

	create_name(filename, PATH_MAX, STORAGEDIR, local_addr, "names");
	name = textfile_get(filename, peer_addr);

	tmp_name = extract_eir_name(data, &name_type);
	if (tmp_name) {
		if (name_type == 0x09) {
			write_device_name(local, peer, tmp_name);
			name_status = NAME_NOT_REQUIRED;

			if (name)
				g_free(name);

			name = tmp_name;
		} else {
			if (name)
				free(tmp_name);
			else
				name = tmp_name;
		}
	}

	if (name) {
		g_dbus_emit_signal(connection, adapter->path,
						ADAPTER_INTERFACE,
						"RemoteNameUpdated",
						DBUS_TYPE_STRING, &paddr,
						DBUS_TYPE_STRING, &name,
						DBUS_TYPE_INVALID);

		if (name_type != 0x08)
			name_status = NAME_SENT;

		if (hcid_dbus_use_experimental()) {
			emit_device_found(adapter->path + ADAPTER_PATH_INDEX,
					paddr,
					"Address", DBUS_TYPE_STRING, &paddr,
					"Class", DBUS_TYPE_UINT32, &class,
					"RSSI", DBUS_TYPE_INT16, &tmp_rssi,
					"Name", DBUS_TYPE_STRING, &name,
					NULL);
		}

		g_free(name);
	} else if (hcid_dbus_use_experimental()) {
		emit_device_found(adapter->path + ADAPTER_PATH_INDEX,
				paddr,
				"Address", DBUS_TYPE_STRING, &paddr,
				"Class", DBUS_TYPE_UINT32, &class,
				"RSSI", DBUS_TYPE_INT16, &tmp_rssi,
				NULL);
	}

	/* add in the list to track name sent/pending */
	found_device_add(&adapter->found_devices, peer, rssi, name_status);
}

void hcid_dbus_remote_class(bdaddr_t *local, bdaddr_t *peer, uint32_t class)
{
	char peer_addr[18];
	const char *paddr = peer_addr;
	uint32_t old_class = 0;
	struct adapter *adapter;

	read_remote_class(local, peer, &old_class);

	if (old_class == class)
		return;

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	ba2str(peer, peer_addr);

	send_adapter_signal(connection, adapter->dev_id,
				"RemoteClassUpdated",
				DBUS_TYPE_STRING, &paddr,
				DBUS_TYPE_UINT32, &class,
				DBUS_TYPE_INVALID);

	if (hcid_dbus_use_experimental()) {
		GSList *l;
		struct device *device;

		l = g_slist_find_custom(adapter->devices, paddr,
				(GCompareFunc) device_address_cmp);
		if (!l)
			return;

		device = l->data;
		dbus_connection_emit_property_changed(connection,
					device->path, DEVICE_INTERFACE,
					"Class", DBUS_TYPE_UINT32, &class);
	}
}

void hcid_dbus_remote_name(bdaddr_t *local, bdaddr_t *peer, uint8_t status,
				char *name)
{
	struct adapter *adapter;
	char peer_addr[18];
	const char *paddr = peer_addr;

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	ba2str(peer, peer_addr);

	if (status)
		g_dbus_emit_signal(connection, adapter->path,
						ADAPTER_INTERFACE,
						"RemoteNameFailed",
						DBUS_TYPE_STRING, &paddr,
						DBUS_TYPE_INVALID);
	else {
		g_dbus_emit_signal(connection, adapter->path,
						ADAPTER_INTERFACE,
						"RemoteNameUpdated",
						DBUS_TYPE_STRING, &paddr,
						DBUS_TYPE_STRING, &name,
						DBUS_TYPE_INVALID);

		if (hcid_dbus_use_experimental()) {
			struct device *device;

			device = adapter_find_device(adapter, paddr);
			if (device) {
				dbus_connection_emit_property_changed(connection,
						device->path, DEVICE_INTERFACE,
						"Name", DBUS_TYPE_STRING, &name);
			}
		}
	}

	/* remove from remote name request list */
	found_device_remove(&adapter->found_devices, peer);

	/* check if there is more devices to request names */
	if (!found_device_req_name(adapter))
		return; /* skip if a new request has been sent */

	/* free discovered devices list */
	g_slist_foreach(adapter->found_devices, (GFunc) g_free, NULL);
	g_slist_free(adapter->found_devices);
	adapter->found_devices = NULL;

	/* The discovery completed signal must be sent only for discover
	 * devices request WITH name resolving */
	if (adapter->discov_requestor) {
		g_dbus_remove_watch(connection, adapter->discov_listener);
		adapter->discov_listener = 0;
		g_free(adapter->discov_requestor);
		adapter->discov_requestor = NULL;

		/* If there is a pending reply for discovery cancel */
		if (adapter->discovery_cancel) {
			DBusMessage *reply;
			reply = dbus_message_new_method_return(adapter->discovery_cancel);
			dbus_connection_send(connection, reply, NULL);
			dbus_message_unref(reply);
			dbus_message_unref(adapter->discovery_cancel);
			adapter->discovery_cancel = NULL;
		}

		/* Disable name resolution for non D-Bus clients */
		if (!adapter->pdiscov_requestor)
			adapter->discov_type &= ~RESOLVE_NAME;
	}

	if (adapter->discov_active) {
		if (hcid_dbus_use_experimental())
			g_dbus_emit_signal(connection,
					adapter->path + ADAPTER_PATH_INDEX,
					ADAPTER_INTERFACE,
					"DiscoveryCompleted",
					DBUS_TYPE_INVALID);

		g_dbus_emit_signal(connection, adapter->path,
						ADAPTER_INTERFACE,
						"DiscoveryCompleted",
						DBUS_TYPE_INVALID);
		adapter->discov_active = 0;
	}
}

void hcid_dbus_conn_complete(bdaddr_t *local, uint8_t status, uint16_t handle,
				bdaddr_t *peer)
{
	char peer_addr[18];
	const char *paddr = peer_addr;
	struct adapter *adapter;

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	ba2str(peer, peer_addr);

	if (status) {
		struct pending_auth_info *auth;

		cancel_passkey_agent_requests(adapter->passkey_agents,
						adapter->path, peer);
		release_passkey_agents(adapter, peer);

		auth = adapter_find_auth_request(adapter, peer);
		if (auth && auth->agent)
			agent_cancel(auth->agent);

		adapter_remove_auth_request(adapter, peer);

		if (adapter->bonding)
			adapter->bonding->hci_status = status;
	} else {
		/* Send the remote device connected signal */
		g_dbus_emit_signal(connection, adapter->path,
						ADAPTER_INTERFACE,
						"RemoteDeviceConnected",
						DBUS_TYPE_STRING, &paddr,
						DBUS_TYPE_INVALID);

		if (hcid_dbus_use_experimental()) {
			struct device *device;
			gboolean connected = TRUE;

			device = adapter_find_device(adapter, paddr);
			if (device) {
				dbus_connection_emit_property_changed(connection,
					device->path, DEVICE_INTERFACE,
					"Connected", DBUS_TYPE_BOOLEAN,
					&connected);
			}
		}

		/* add in the active connetions list */
		active_conn_append(&adapter->active_conn, peer, handle);
	}
}

void hcid_dbus_disconn_complete(bdaddr_t *local, uint8_t status,
				uint16_t handle, uint8_t reason)
{
	DBusMessage *reply;
	char peer_addr[18];
	const char *paddr = peer_addr;
	struct adapter *adapter;
	struct device *device;
	struct active_conn_info *dev;
	GSList *l;
	gboolean connected = FALSE;
	struct pending_auth_info *auth;

	if (status) {
		error("Disconnection failed: 0x%02x", status);
		return;
	}

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	l = g_slist_find_custom(adapter->active_conn, &handle,
				active_conn_find_by_handle);

	if (!l)
		return;

	dev = l->data;

	ba2str(&dev->bdaddr, peer_addr);

	/* clean pending HCI cmds */
	hci_req_queue_remove(adapter->dev_id, &dev->bdaddr);

	/* Cancel D-Bus/non D-Bus requests */
	cancel_passkey_agent_requests(adapter->passkey_agents, adapter->path,
					&dev->bdaddr);
	release_passkey_agents(adapter, &dev->bdaddr);

	auth = adapter_find_auth_request(adapter, &dev->bdaddr);
	if (auth && auth->agent)
		agent_cancel(auth->agent);

	adapter_remove_auth_request(adapter, &dev->bdaddr);

	/* Check if there is a pending CreateBonding request */
	if (adapter->bonding && (bacmp(&adapter->bonding->bdaddr, &dev->bdaddr) == 0)) {
		if (adapter->bonding->cancel) {
			/* reply authentication canceled */
			error_authentication_canceled(connection,
							adapter->bonding->msg);
		} else {
			reply = new_authentication_return(adapter->bonding->msg,
							HCI_AUTHENTICATION_FAILURE);
			dbus_connection_send(connection, reply, NULL);
			dbus_message_unref(reply);
		}

		g_dbus_remove_watch(adapter->bonding->conn,
					adapter->bonding->listener_id);

		if (adapter->bonding->io_id)
			g_source_remove(adapter->bonding->io_id);
		g_io_channel_close(adapter->bonding->io);
		bonding_request_free(adapter->bonding);
		adapter->bonding = NULL;
	}

	/* Check if there is a pending RemoteDeviceDisconnect request */
	if (adapter->pending_dc) {
		reply = dbus_message_new_method_return(adapter->pending_dc->msg);
		if (reply) {
			dbus_connection_send(connection, reply, NULL);
			dbus_message_unref(reply);
		} else
			error("Failed to allocate disconnect reply");

		g_source_remove(adapter->pending_dc->timeout_id);
		dc_pending_timeout_cleanup(adapter);
	}

	/* Send the remote device disconnected signal */
	g_dbus_emit_signal(connection, adapter->path,
					ADAPTER_INTERFACE,
					"RemoteDeviceDisconnected",
					DBUS_TYPE_STRING, &paddr,
					DBUS_TYPE_INVALID);

	adapter->active_conn = g_slist_remove(adapter->active_conn, dev);
	g_free(dev);

	device = adapter_find_device(adapter, paddr);
	if (device) {
		dbus_connection_emit_property_changed(connection,
					device->path, DEVICE_INTERFACE,
					"Connected", DBUS_TYPE_BOOLEAN,
					&connected);
		if (device->temporary) {
			debug("Removing temporary device %s", device->address);
			adapter_remove_device(connection, adapter, device);
		}
	}
}

int set_limited_discoverable(int dd, const uint8_t *cls, gboolean limited)
{
	uint32_t dev_class;
	int err;
	int num = (limited ? 2 : 1);
	uint8_t lap[] = { 0x33, 0x8b, 0x9e, 0x00, 0x8b, 0x9e };
	/*
	 * 1: giac
	 * 2: giac + liac
	 */
	if (hci_write_current_iac_lap(dd, num, lap, 1000) < 0) {
		err = errno;
		error("Can't write current IAC LAP: %s(%d)",
				strerror(err), err);
		return -err;
	}

	if (limited) {
		if (cls[1] & 0x20)
			return 0; /* Already limited */

		dev_class = (cls[2] << 16) | ((cls[1] | 0x20) << 8) | cls[0];
	} else {
		if (!(cls[1] & 0x20))
			return 0; /* Already clear */

		dev_class = (cls[2] << 16) | ((cls[1] & 0xdf) << 8) | cls[0];
	}

	if (hci_write_class_of_dev(dd, dev_class, 1000) < 0) {
		err = errno;
		error("Can't write class of device: %s (%d)",
							strerror(err), err);
		return -err;
	}

	return 0;
}

int set_service_classes(int dd, const uint8_t *cls, uint8_t value)
{
	uint32_t dev_class;
	int err;

	if (cls[2] == value)
		return 0; /* Already set */

	dev_class = (value << 16) | (cls[1] << 8) | cls[0];

	if (hci_write_class_of_dev(dd, dev_class, 1000) < 0) {
		err = errno;
		error("Can't write class of device: %s (%d)",
							strerror(err), err);
		return -err;
	}

	return 0;
}

gboolean discov_timeout_handler(void *data)
{
	struct adapter *adapter = data;
	struct hci_request rq;
	int dd;
	uint8_t scan_enable = adapter->scan_enable;
	uint8_t status = 0;
	gboolean retval = TRUE;

	scan_enable &= ~SCAN_INQUIRY;

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0) {
		error("HCI device open failed: hci%d", adapter->dev_id);
		return TRUE;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_SCAN_ENABLE;
	rq.cparam = &scan_enable;
	rq.clen   = sizeof(scan_enable);
	rq.rparam = &status;
	rq.rlen   = sizeof(status);
	rq.event  = EVT_CMD_COMPLETE;

	if (hci_send_req(dd, &rq, 1000) < 0) {
		error("Sending write scan enable command to hci%d failed: %s (%d)",
				adapter->dev_id, strerror(errno), errno);
		goto failed;
	}
	if (status) {
		error("Setting scan enable failed with status 0x%02x", status);
		goto failed;
	}

	set_limited_discoverable(dd, adapter->class, FALSE);

	adapter->timeout_id = 0;
	retval = FALSE;

failed:
	if (dd >= 0)
		hci_close_dev(dd);

	return retval;
}

/* Section reserved to device HCI callbacks */

void hcid_dbus_setname_complete(bdaddr_t *local)
{
	int id, dd = -1;
	read_local_name_rp rp;
	struct hci_request rq;
	const char *pname = (char *) rp.name;
	char local_addr[18], name[249];

	ba2str(local, local_addr);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		return;
	}

	dd = hci_open_dev(id);
	if (dd < 0) {
		error("HCI device open failed: hci%d", id);
		memset(&rp, 0, sizeof(rp));
	} else {
		memset(&rq, 0, sizeof(rq));
		rq.ogf    = OGF_HOST_CTL;
		rq.ocf    = OCF_READ_LOCAL_NAME;
		rq.rparam = &rp;
		rq.rlen   = READ_LOCAL_NAME_RP_SIZE;
		rq.event  = EVT_CMD_COMPLETE;

		if (hci_send_req(dd, &rq, 1000) < 0) {
			error("Sending getting name command failed: %s (%d)",
						strerror(errno), errno);
			rp.name[0] = '\0';
		} else if (rp.status) {
			error("Getting name failed with status 0x%02x",
					rp.status);
			rp.name[0] = '\0';
		}
		hci_close_dev(dd);
	}

	strncpy(name, pname, sizeof(name) - 1);
	name[248] = '\0';
	pname = name;

	send_adapter_signal(connection, id, "NameChanged",
				DBUS_TYPE_STRING, &pname, DBUS_TYPE_INVALID);
}

void hcid_dbus_setscan_enable_complete(bdaddr_t *local)
{
	struct adapter *adapter;
	read_scan_enable_rp rp;
	struct hci_request rq;
	int dd = -1;

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0) {
		error("HCI device open failed: hci%d", adapter->dev_id);
		return;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_SCAN_ENABLE;
	rq.rparam = &rp;
	rq.rlen   = READ_SCAN_ENABLE_RP_SIZE;
	rq.event  = EVT_CMD_COMPLETE;

	if (hci_send_req(dd, &rq, 1000) < 0) {
		error("Sending read scan enable command failed: %s (%d)",
				strerror(errno), errno);
		goto failed;
	}

	if (rp.status) {
		error("Getting scan enable failed with status 0x%02x",
				rp.status);
		goto failed;
	}

	if (adapter->timeout_id) {
		g_source_remove(adapter->timeout_id);
		adapter->timeout_id = 0;
	}

	if (adapter->scan_enable != rp.enable)
		adapter_mode_changed(adapter, rp.enable);

failed:
	if (dd >= 0)
		hci_close_dev(dd);
}

void hcid_dbus_write_class_complete(bdaddr_t *local)
{
	struct adapter *adapter;
	int dd;
	uint8_t cls[3];

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0) {
		error("HCI device open failed: hci%d", adapter->dev_id);
		return;
	}

	if (hci_read_class_of_dev(dd, cls, 1000) < 0) {
		error("Can't read class of device on hci%d: %s (%d)",
			adapter->dev_id, strerror(errno), errno);
		hci_close_dev(dd);
		return;
	}

	write_local_class(local, cls);
	set_device_class(adapter->dev_id, cls);
	memcpy(adapter->class, cls, 3);

	hci_close_dev(dd);
}

void hcid_dbus_write_simple_pairing_mode_complete(bdaddr_t *local)
{
	char addr[18];
	int dev_id, dd;
	uint8_t mode;

	ba2str(local, addr);

	dev_id = hci_devid(addr);
	if (dev_id < 0) {
		error("No matching device id for %s", addr);
		return;
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		error("HCI device open failed: hci%d", dev_id);
		return;
	}

	if (hci_read_simple_pairing_mode(dd, &mode, 1000) < 0) {
		error("Can't read class of device on hci%d: %s(%d)",
					dev_id, strerror(errno), errno);
		hci_close_dev(dd);
		return;
	}

	set_simple_pairing_mode(dev_id, mode);

	hci_close_dev(dd);
}

int hcid_dbus_get_io_cap(bdaddr_t *local, bdaddr_t *remote,
						uint8_t *cap, uint8_t *auth)
{
	struct adapter *adapter;
	struct device *device;
	struct agent *agent;
	char addr[18];

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return -1;
	}

	if (get_auth_requirements(local, remote, auth) < 0)
		return -1;

	ba2str(remote, addr);

	device = adapter_find_device(adapter, addr);
	if (device && device->agent) {
		agent = device->agent;
		*auth = 0x03;
	} else
		agent = adapter->agent;

	if (!agent) {
		if (!(*auth & 0x01)) {
			/* No input, no output */
			*cap = 0x03;
			return 0;
		}
		error("No agent available for IO capability");
		return -1;
	}

	*cap = agent_get_io_capability(agent);

	return 0;
}

int hcid_dbus_set_io_cap(bdaddr_t *local, bdaddr_t *remote,
                                                uint8_t cap, uint8_t auth)
{
	struct adapter *adapter;
	struct device *device;
	char addr[18];

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return -1;
	}

	ba2str(remote, addr);

	device = adapter_get_device(connection, adapter, addr);
	if (device) {
		device->cap = cap;
		device->auth = auth;
	}

	return 0;
}

static int inquiry_cancel(int dd, int to)
{
	struct hci_request rq;
	uint8_t status;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_INQUIRY_CANCEL;
	rq.rparam = &status;
	rq.rlen   = sizeof(status);
	rq.event = EVT_CMD_COMPLETE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = bt_error(status);
		return -1;
	}

	return 0;
}

static int remote_name_cancel(int dd, bdaddr_t *dba, int to)
{
	remote_name_req_cancel_cp cp;
	struct hci_request rq;
	uint8_t status;

	memset(&rq, 0, sizeof(rq));
	memset(&cp, 0, sizeof(cp));

	bacpy(&cp.bdaddr, dba);

	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_REMOTE_NAME_REQ_CANCEL;
	rq.cparam = &cp;
	rq.clen   = REMOTE_NAME_REQ_CANCEL_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = sizeof(status);
	rq.event = EVT_CMD_COMPLETE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = bt_error(status);
		return -1;
	}

	return 0;
}

int cancel_discovery(struct adapter *adapter)
{
	struct remote_dev_info *dev, match;
	GSList *l;
	int dd, err = 0;

	if (!adapter->discov_active)
		goto cleanup;

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0) {
		err = -ENODEV;
		goto cleanup;
	}

	/*
	 * If there is a pending read remote name request means
	 * that the inquiry complete event was already received
	 */
	memset(&match, 0, sizeof(struct remote_dev_info));
	bacpy(&match.bdaddr, BDADDR_ANY);
	match.name_status = NAME_REQUESTED;

	l = g_slist_find_custom(adapter->found_devices, &match,
				(GCompareFunc) found_device_cmp);
	if (l) {
		dev = l->data;
		if (remote_name_cancel(dd, &dev->bdaddr, 1000) < 0) {
			error("Read remote name cancel failed: %s, (%d)",
					strerror(errno), errno);
			err = -errno;
		}
	} else {
		if (inquiry_cancel(dd, 1000) < 0) {
			error("Inquiry cancel failed:%s (%d)",
					strerror(errno), errno);
			err = -errno;
		}
	}

	hci_close_dev(dd);

cleanup:
	/*
	 * Reset discov_requestor and discover_state in the remote name
	 * request event handler or in the inquiry complete handler.
	 */
	g_slist_foreach(adapter->found_devices, (GFunc) g_free, NULL);
	g_slist_free(adapter->found_devices);
	adapter->found_devices = NULL;

	/* Disable name resolution for non D-Bus clients */
	if (!adapter->pdiscov_requestor)
		adapter->discov_type &= ~RESOLVE_NAME;

	return err;
}

static int periodic_inquiry_exit(int dd, int to)
{
	struct hci_request rq;
	uint8_t status;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_EXIT_PERIODIC_INQUIRY;
	rq.rparam = &status;
	rq.rlen   = sizeof(status);
	rq.event = EVT_CMD_COMPLETE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = status;
		return -1;
	}

	return 0;
}

int cancel_periodic_discovery(struct adapter *adapter)
{
	struct remote_dev_info *dev, match;
	GSList *l;
	int dd, err = 0;

	if (!adapter->pdiscov_active)
		goto cleanup;

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0) {
		err = -ENODEV;
		goto cleanup;
	}
	/* find the pending remote name request */
	memset(&match, 0, sizeof(struct remote_dev_info));
	bacpy(&match.bdaddr, BDADDR_ANY);
	match.name_status = NAME_REQUESTED;

	l = g_slist_find_custom(adapter->found_devices, &match,
			(GCompareFunc) found_device_cmp);
	if (l) {
		dev = l->data;
		if (remote_name_cancel(dd, &dev->bdaddr, 1000) < 0) {
			error("Read remote name cancel failed: %s, (%d)",
					strerror(errno), errno);
			err = -errno;
		}
	}

	/* ovewrite err if necessary: stop periodic inquiry has higher
	 * priority */
	if (periodic_inquiry_exit(dd, 1000) < 0) {
		error("Periodic Inquiry exit failed:%s (%d)",
				strerror(errno), errno);
		err = -errno;
	}

	hci_close_dev(dd);

cleanup:
	/*
	 * Reset pdiscov_requestor and pdiscov_active is done when the
	 * cmd complete event for exit periodic inquiry mode cmd arrives.
	 */
	g_slist_foreach(adapter->found_devices, (GFunc) g_free, NULL);
	g_slist_free(adapter->found_devices);
	adapter->found_devices = NULL;

	return err;
}

/* Most of the functions in this module require easy access to a connection so
 * we keep it global here and provide these access functions the other (few)
 * modules that require access to it */

void set_dbus_connection(DBusConnection *conn)
{
	connection = conn;
}

DBusConnection *get_dbus_connection(void)
{
	return connection;
}
