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

#include "hcid.h"
#include "dbus.h"
#include "textfile.h"
#include "manager.h"
#include "adapter.h"
#include "error.h"
#include "dbus-helper.h"
#include "dbus-common.h"
#include "dbus-error.h"
#include "dbus-test.h"
#include "dbus-service.h"
#include "dbus-security.h"
#include "dbus-hci.h"

static DBusConnection *connection = NULL;

void bonding_request_free(struct bonding_request_info *bonding)
{
	if (!bonding)
		return;

	if (bonding->rq)
		dbus_message_unref(bonding->rq);

	if (bonding->conn)
		dbus_connection_unref(bonding->conn);

	if (bonding->io)
		g_io_channel_unref(bonding->io);

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
	ret = dbus_connection_emit_signal_valist(conn, path, ADAPTER_INTERFACE,
							name, first, var_args);
	va_end(var_args);

	return ret;
}

static void adapter_mode_changed(struct adapter *adapter,
			const char *path, uint8_t scan_enable)
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

	dbus_connection_emit_signal(connection, path, ADAPTER_INTERFACE,
					"ModeChanged",
					DBUS_TYPE_STRING, &mode,
					DBUS_TYPE_INVALID);
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
		error_authentication_canceled(connection, adapter->bonding->rq);
		name_listener_remove(connection,
					dbus_message_get_sender(adapter->bonding->rq),
					(name_cb_t) create_bond_req_exit,
					adapter);
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
		send_message_and_unref(connection, reply);
		dbus_message_unref(adapter->discovery_cancel);
		adapter->discovery_cancel = NULL;
	}

	if (adapter->discov_active) {
		/* Send discovery completed signal if there isn't name
		 * to resolve */
		dbus_connection_emit_signal(connection, path,
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
		dbus_connection_emit_signal(connection, path,
						ADAPTER_INTERFACE,
						"PeriodicDiscoveryStopped",
						DBUS_TYPE_INVALID);

		/* Stop periodic inquiry initiated by D-Bus client */
		if (adapter->pdiscov_requestor)
			cancel_periodic_discovery(adapter);
	}
}

int unregister_adapter_path(const char *path)
{
	struct adapter *adapter = NULL;

	info("Unregister path: %s", path);

	dbus_connection_get_object_user_data(connection, path,
						(void *) &adapter);

	if (!adapter)
		goto unreg;

	/* check pending requests */
	reply_pending_requests(path, adapter);

	cancel_passkey_agent_requests(adapter->passkey_agents, path, NULL);

	release_passkey_agents(adapter, NULL);

	if (adapter->discov_requestor) {
		name_listener_remove(connection,
				adapter->discov_requestor,
				(name_cb_t) discover_devices_req_exit, adapter);
		g_free(adapter->discov_requestor);
		adapter->discov_requestor = NULL;
	}

	if (adapter->pdiscov_requestor) {
		name_listener_remove(connection,
				adapter->pdiscov_requestor,
				(name_cb_t) periodic_discover_req_exit,
				adapter);
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

	if (adapter->pin_reqs) {
		g_slist_foreach(adapter->pin_reqs,
				(GFunc) g_free, NULL);
		g_slist_free(adapter->pin_reqs);
		adapter->pin_reqs = NULL;
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

	g_free(adapter);

unreg:
	if (!dbus_connection_destroy_object_path(connection, path)) {
		error("D-Bus failed to unregister %s object", path);
		return -1;
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
	char *pptr = path;
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

	if (!dbus_connection_create_object_path(connection, path, adapter,
						NULL)) {
		error("D-Bus failed to register %s object", path);
		g_free(adapter);
		return -1;
	}

	if (!adapter_init(connection, path)) {
		error("Adapter interface init failed");
		goto failed;
	}

	if (!security_init(connection, path)) {
		error("Security interface init failed");
		goto failed;
	}

	if (!test_init(connection, path)) {
		error("Test interface init failed");
		goto failed;
	}

	/*
	 * Send the adapter added signal
	 */
	dbus_connection_emit_signal(connection, BASE_PATH, MANAGER_INTERFACE,
					"AdapterAdded",
					DBUS_TYPE_STRING, &pptr,
					DBUS_TYPE_INVALID);

	return 0;

failed:
	dbus_connection_destroy_object_path(connection, path);
	g_free(adapter);

	return -1;
}

int hcid_dbus_unregister_device(uint16_t id)
{
	char path[MAX_PATH_LENGTH];
	char *pptr = path;
	int ret;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	dbus_connection_emit_signal(connection, BASE_PATH, MANAGER_INTERFACE,
					"AdapterRemoved",
					DBUS_TYPE_STRING, &pptr,
					DBUS_TYPE_INVALID);

	ret = unregister_adapter_path(path);

	if (ret == 0 && (get_default_adapter() == id || get_default_adapter() < 0)) {
		int new_default = hci_get_route(NULL);
		set_default_adapter(new_default);
		if (new_default >= 0) {
			snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH,
					new_default);
			dbus_connection_emit_signal(connection, BASE_PATH,
							MANAGER_INTERFACE,
							"DefaultAdapterChanged",
							DBUS_TYPE_STRING, &pptr,
							DBUS_TYPE_INVALID);
		} else {
			*path = '\0';
			dbus_connection_emit_signal(connection, BASE_PATH,
							MANAGER_INTERFACE,
							"DefaultAdapterChanged",
							DBUS_TYPE_STRING, &pptr,
							DBUS_TYPE_INVALID);
		}
	}

	return ret;
}

int hcid_dbus_start_device(uint16_t id)
{
	char path[MAX_PATH_LENGTH], *pptr;
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

	if (!dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
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
	dbus_connection_emit_signal(connection, path, ADAPTER_INTERFACE,
					"ModeChanged",
					DBUS_TYPE_STRING, &mode,
					DBUS_TYPE_INVALID);

	if (get_default_adapter() < 0) {
		set_default_adapter(id);
		pptr = path;
		dbus_connection_emit_signal(connection, BASE_PATH,
					    MANAGER_INTERFACE,
					    "DefaultAdapterChanged",
					    DBUS_TYPE_STRING, &pptr,
					    DBUS_TYPE_INVALID);
	}

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

	dbus_connection_emit_signal(connection, path, ADAPTER_INTERFACE,
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

	if (!dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
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
		name_listener_remove(connection, adapter->discov_requestor,
					(name_cb_t) discover_devices_req_exit,
					adapter);
		g_free(adapter->discov_requestor);
		adapter->discov_requestor = NULL;
	}

	if (adapter->pdiscov_requestor) {
		name_listener_remove(connection, adapter->pdiscov_requestor,
					(name_cb_t) periodic_discover_req_exit,
					adapter);
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

	if (adapter->pin_reqs) {
		g_slist_foreach(adapter->pin_reqs, (GFunc) g_free, NULL);
		g_slist_free(adapter->pin_reqs);
		adapter->pin_reqs = NULL;
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

	adapter->up = 0;
	adapter->scan_enable = SCAN_DISABLED;
	adapter->mode = MODE_OFF;
	adapter->discov_active = 0;
	adapter->pdiscov_active = 0;
	adapter->pinq_idle = 0;
	adapter->discov_type = DISCOVER_TYPE_NONE;

	return 0;
}

int pin_req_cmp(const void *p1, const void *p2)
{
	const struct pending_pin_info *pb1 = p1;
	const struct pending_pin_info *pb2 = p2;

	return p2 ? bacmp(&pb1->bdaddr, &pb2->bdaddr) : -1;
}

void hcid_dbus_pending_pin_req_add(bdaddr_t *sba, bdaddr_t *dba)
{
	char path[MAX_PATH_LENGTH], addr[18];
	struct adapter *adapter;
	struct pending_pin_info *info;
	int id;

	ba2str(sba, addr);

	id = hci_devid(addr);
	if (id < 0) {
		error("No matching device id for %s", addr);
		return;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
		error("Getting %s path data failed!", path);
		return;
	}

	info = g_new0(struct pending_pin_info, 1);

	bacpy(&info->bdaddr, dba);
	adapter->pin_reqs = g_slist_append(adapter->pin_reqs, info);

	if (adapter->bonding && !bacmp(dba, &adapter->bonding->bdaddr))
		adapter->bonding->auth_active = 1;
}

int hcid_dbus_request_pin(int dev, bdaddr_t *sba, struct hci_conn_info *ci)
{
	char path[MAX_PATH_LENGTH], addr[18];
	int id;

	ba2str(sba, addr);

	id = hci_devid(addr);
	if (id < 0) {
		error("No matching device id for %s", addr);
		return -1;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	return handle_passkey_request(connection, dev, path, sba, &ci->bdaddr);
}

int hcid_dbus_confirm_pin(int dev, bdaddr_t *sba, struct hci_conn_info *ci, char *pin)
{
	char path[MAX_PATH_LENGTH], addr[18];
	int id;

	ba2str(sba, addr);

	id = hci_devid(addr);
	if (id < 0) {
		error("No matching device id for %s", addr);
		return -1;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	return handle_confirm_request(connection, dev, path, sba, &ci->bdaddr, pin);
}

void hcid_dbus_bonding_process_complete(bdaddr_t *local, bdaddr_t *peer,
					uint8_t status)
{
	struct adapter *adapter;
	char path[MAX_PATH_LENGTH], local_addr[18], peer_addr[18];
	const char *paddr = peer_addr;
	GSList *l;
	int id;

	ba2str(local, local_addr);
	ba2str(peer, peer_addr);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		return;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	/* create the authentication reply */
	if (!dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
		error("Getting %s path data failed!", path);
		return;
	}

	if (status)
		cancel_passkey_agent_requests(adapter->passkey_agents, path,
						peer);

	l = g_slist_find_custom(adapter->pin_reqs, peer, pin_req_cmp);
	if (l) {
		void *d = l->data;
		adapter->pin_reqs = g_slist_remove(adapter->pin_reqs, l->data);
		g_free(d);

		if (!status)
			send_adapter_signal(connection, adapter->dev_id,
						"BondingCreated",
						DBUS_TYPE_STRING, &paddr,
						DBUS_TYPE_INVALID);
	}

	release_passkey_agents(adapter, peer);

	if (!adapter->bonding || bacmp(&adapter->bonding->bdaddr, peer))
		return; /* skip: no bonding req pending */

	if (adapter->bonding->cancel) {
		/* reply authentication canceled */
		error_authentication_canceled(connection, adapter->bonding->rq);
	} else {
		DBusMessage *reply;
		/* reply authentication success or an error */
		reply = new_authentication_return(adapter->bonding->rq,
							status);
		send_message_and_unref(connection, reply);
	}

	name_listener_remove(connection,
				dbus_message_get_sender(adapter->bonding->rq),
				(name_cb_t) create_bond_req_exit, adapter);

	if (adapter->bonding->io_id)
		g_source_remove(adapter->bonding->io_id);
	g_io_channel_close(adapter->bonding->io);
	bonding_request_free(adapter->bonding);
	adapter->bonding = NULL;
}

void hcid_dbus_inquiry_start(bdaddr_t *local)
{
	struct adapter *adapter;
	char path[MAX_PATH_LENGTH], local_addr[18];
	int id;

	ba2str(local, local_addr);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		return;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
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
	}

	send_adapter_signal(connection, adapter->dev_id, "DiscoveryStarted",
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

		dbus_connection_emit_signal(connection, path,
						ADAPTER_INTERFACE,
						"RemoteDeviceDisappeared",
						DBUS_TYPE_STRING, &peer_addr,
						DBUS_TYPE_INVALID);
		l = l->next;
	}
}

void hcid_dbus_inquiry_complete(bdaddr_t *local)
{
	struct adapter *adapter;
	GSList *l;
	char path[MAX_PATH_LENGTH], local_addr[18];
	struct remote_dev_info *dev;
	bdaddr_t tmp;
	int id;

	ba2str(local, local_addr);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		return;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
		error("Getting %s path data failed!", path);
		goto done;
	}

	/* Out of range verification */
	if (adapter->pdiscov_active && !adapter->discov_active) {
		send_out_of_range(path, adapter->oor_devices);

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
		goto done; /* skip - there is name to resolve */

	if (adapter->discov_active) {
		dbus_connection_emit_signal(connection, path,
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
		name_listener_remove(connection, adapter->discov_requestor,
				(name_cb_t) discover_devices_req_exit, adapter);
		g_free(adapter->discov_requestor);
		adapter->discov_requestor = NULL;

		/* If there is a pending reply for discovery cancel */
		if (adapter->discovery_cancel) {
			DBusMessage *reply;
			reply = dbus_message_new_method_return(adapter->discovery_cancel);
			send_message_and_unref(connection, reply);
			dbus_message_unref(adapter->discovery_cancel);
			adapter->discovery_cancel = NULL;
		}

		/* reset the discover type for standard inquiry only */
		adapter->discov_type &= ~STD_INQUIRY;
	}

done:
	/* Proceed with any queued up audits */
	process_audits_list(path);
}

void hcid_dbus_periodic_inquiry_start(bdaddr_t *local, uint8_t status)
{
	struct adapter *adapter;
	char path[MAX_PATH_LENGTH], local_addr[18];
	int id;

	/* Don't send the signal if the cmd failed */
	if (status)
		return;

	ba2str(local, local_addr);
	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		return;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
		adapter->pdiscov_active = 1;

		/* Disable name resolution for non D-Bus clients */
		if (!adapter->pdiscov_requestor)
			adapter->discov_type &= ~RESOLVE_NAME;
	}

	dbus_connection_emit_signal(connection, path, ADAPTER_INTERFACE,
					"PeriodicDiscoveryStarted",
					DBUS_TYPE_INVALID);
}

void hcid_dbus_periodic_inquiry_exit(bdaddr_t *local, uint8_t status)
{
	struct adapter *adapter;
	char path[MAX_PATH_LENGTH], local_addr[18];
	int id;

	/* Don't send the signal if the cmd failed */
	if (status)
		return;

	ba2str(local, local_addr);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		return;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
		error("Getting %s path data failed!", path);
		return;
	}

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
		name_listener_remove(connection, adapter->pdiscov_requestor,
					(name_cb_t) periodic_discover_req_exit,
					adapter);
		g_free(adapter->pdiscov_requestor);
		adapter->pdiscov_requestor = NULL;
	}

	 /* workaround: inquiry completed is not sent when exiting from
	  * periodic inquiry */
	if (adapter->discov_active) {
		dbus_connection_emit_signal(connection, path,
						ADAPTER_INTERFACE,
						"DiscoveryCompleted",
						DBUS_TYPE_INVALID);
		adapter->discov_active = 0;
	}

	/* Send discovery completed signal if there isn't name to resolve */
	dbus_connection_emit_signal(connection, path, ADAPTER_INTERFACE,
					"PeriodicDiscoveryStopped",
					DBUS_TYPE_INVALID);
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

void hcid_dbus_inquiry_result(bdaddr_t *local, bdaddr_t *peer, uint32_t class,
				int8_t rssi, uint8_t *data)
{
	char filename[PATH_MAX + 1], path[MAX_PATH_LENGTH];
	struct adapter *adapter;
	GSList *l;
	char local_addr[18], peer_addr[18], *name, *tmp_name;
	const char *paddr = peer_addr;
	struct remote_dev_info match;
	dbus_int16_t tmp_rssi = rssi;
	uint8_t name_type = 0x00;
	name_status_t name_status;
	int id;

	ba2str(local, local_addr);
	ba2str(peer, peer_addr);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		return;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
		error("Getting %s path data failed!", path);
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
	dbus_connection_emit_signal(connection, path, ADAPTER_INTERFACE,
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
		dbus_connection_emit_signal(connection, path,
						ADAPTER_INTERFACE,
						"RemoteNameUpdated",
						DBUS_TYPE_STRING, &paddr,
						DBUS_TYPE_STRING, &name,
						DBUS_TYPE_INVALID);
		g_free(name);

		if (name_type != 0x08)
			name_status = NAME_SENT;
	}

	/* add in the list to track name sent/pending */
	found_device_add(&adapter->found_devices, peer, rssi, name_status);
}

void hcid_dbus_remote_class(bdaddr_t *local, bdaddr_t *peer, uint32_t class)
{
	char local_addr[18], peer_addr[18];
	const char *paddr = peer_addr;
	uint32_t old_class = 0;
	int id;

	read_remote_class(local, peer, &old_class);

	if (old_class == class)
		return;

	ba2str(local, local_addr);
	ba2str(peer, peer_addr);
	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		return;
	}

	send_adapter_signal(connection, id, "RemoteClassUpdated",
				DBUS_TYPE_STRING, &paddr,
				DBUS_TYPE_UINT32, &class,
				DBUS_TYPE_INVALID);

}

void hcid_dbus_remote_name(bdaddr_t *local, bdaddr_t *peer, uint8_t status,
				char *name)
{
	struct adapter *adapter;
	char path[MAX_PATH_LENGTH], local_addr[18], peer_addr[18];
	const char *paddr = peer_addr;
	int id;

	ba2str(local, local_addr);
	ba2str(peer, peer_addr);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		return;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
		error("Getting %s path data failed!", path);
		return;
	}

	if (status)
		dbus_connection_emit_signal(connection, path,
						ADAPTER_INTERFACE,
						"RemoteNameFailed",
						DBUS_TYPE_STRING, &paddr,
						DBUS_TYPE_INVALID);
	else
		dbus_connection_emit_signal(connection, path,
						ADAPTER_INTERFACE,
						"RemoteNameUpdated",
						DBUS_TYPE_STRING, &paddr,
						DBUS_TYPE_STRING, &name,
						DBUS_TYPE_INVALID);

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
		name_listener_remove(connection, adapter->discov_requestor,
				(name_cb_t) discover_devices_req_exit, adapter);
		g_free(adapter->discov_requestor);
		adapter->discov_requestor = NULL;

		/* If there is a pending reply for discovery cancel */
		if (adapter->discovery_cancel) {
			DBusMessage *reply;
			reply = dbus_message_new_method_return(adapter->discovery_cancel);
			send_message_and_unref(connection, reply);
			dbus_message_unref(adapter->discovery_cancel);
			adapter->discovery_cancel = NULL;
		}

		/* Disable name resolution for non D-Bus clients */
		if (!adapter->pdiscov_requestor)
			adapter->discov_type &= ~RESOLVE_NAME;
	}

	if (adapter->discov_active) {
		dbus_connection_emit_signal(connection, path,
						ADAPTER_INTERFACE,
						"DiscoveryCompleted",
						DBUS_TYPE_INVALID);
		adapter->discov_active = 0;
	}
}

void hcid_dbus_conn_complete(bdaddr_t *local, uint8_t status, uint16_t handle,
				bdaddr_t *peer)
{
	char path[MAX_PATH_LENGTH], local_addr[18], peer_addr[18];
	const char *paddr = peer_addr;
	struct adapter *adapter;
	int id;

	ba2str(local, local_addr);
	ba2str(peer, peer_addr);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		return;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
		error("Getting %s path data failed!", path);
		return;
	}

	if (status) {
		GSList *l;

		cancel_passkey_agent_requests(adapter->passkey_agents, path,
						peer);
		release_passkey_agents(adapter, peer);

		l = g_slist_find_custom(adapter->pin_reqs, peer, pin_req_cmp);
		if (l) {
			struct pending_pin_req *p = l->data;
			adapter->pin_reqs = g_slist_remove(adapter->pin_reqs, p);
			g_free(p);
		}

		if (adapter->bonding)
			adapter->bonding->hci_status = status;
	} else {
		/* Send the remote device connected signal */
		dbus_connection_emit_signal(connection, path,
						ADAPTER_INTERFACE,
						"RemoteDeviceConnected",
						DBUS_TYPE_STRING, &paddr,
						DBUS_TYPE_INVALID);

		/* add in the active connetions list */
		active_conn_append(&adapter->active_conn, peer, handle);
	}
}

void hcid_dbus_disconn_complete(bdaddr_t *local, uint8_t status,
				uint16_t handle, uint8_t reason)
{
	DBusMessage *reply;
	char path[MAX_PATH_LENGTH], local_addr[18], peer_addr[18];
	const char *paddr = peer_addr;
	struct adapter *adapter;
	struct active_conn_info *dev;
	GSList *l;
	int id;

	if (status) {
		error("Disconnection failed: 0x%02x", status);
		return;
	}

	ba2str(local, local_addr);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		return;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
		error("Getting %s path data failed!", path);
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
	cancel_passkey_agent_requests(adapter->passkey_agents, path,
					&dev->bdaddr);
	release_passkey_agents(adapter, &dev->bdaddr);

	l = g_slist_find_custom(adapter->pin_reqs, &dev->bdaddr, pin_req_cmp);
	if (l) {
		struct pending_pin_req *p = l->data;
		adapter->pin_reqs = g_slist_remove(adapter->pin_reqs, p);
		g_free(p);
	}

	/* Check if there is a pending CreateBonding request */
	if (adapter->bonding && (bacmp(&adapter->bonding->bdaddr, &dev->bdaddr) == 0)) {
		if (adapter->bonding->cancel) {
			/* reply authentication canceled */
			error_authentication_canceled(connection,
							adapter->bonding->rq);
		} else {
			reply = new_authentication_return(adapter->bonding->rq,
							HCI_AUTHENTICATION_FAILURE);
			send_message_and_unref(connection, reply);
		}

		name_listener_remove(connection,
					dbus_message_get_sender(adapter->bonding->rq),
					(name_cb_t) create_bond_req_exit,
					adapter);
		if (adapter->bonding->io_id)
			g_source_remove(adapter->bonding->io_id);
		g_io_channel_close(adapter->bonding->io);
		bonding_request_free(adapter->bonding);
		adapter->bonding = NULL;
	}

	/* Check if there is a pending RemoteDeviceDisconnect request */
	if (adapter->pending_dc) {
		reply = dbus_message_new_method_return(adapter->pending_dc->msg);
		if (!reply)
			error("Failed to allocate disconnect reply");
		else
			send_message_and_unref(adapter->pending_dc->conn, reply);

		g_source_remove(adapter->pending_dc->timeout_id);
		dc_pending_timeout_cleanup(adapter);
	}

	/* Send the remote device disconnected signal */
	dbus_connection_emit_signal(connection, path, ADAPTER_INTERFACE,
					"RemoteDeviceDisconnected",
					DBUS_TYPE_STRING, &paddr,
					DBUS_TYPE_INVALID);

	adapter->active_conn = g_slist_remove(adapter->active_conn, dev);
	g_free(dev);

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
		}

		if (rp.status) {
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
	char path[MAX_PATH_LENGTH], local_addr[18];
	read_scan_enable_rp rp;
	struct hci_request rq;
	int id, dd = -1;

	ba2str(local, local_addr);
	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		return;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	dd = hci_open_dev(id);
	if (dd < 0) {
		error("HCI device open failed: hci%d", id);
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

	if (!dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
		error("Getting %s path data failed!", path);
		goto failed;
	}

	if (adapter->timeout_id) {
		g_source_remove(adapter->timeout_id);
		adapter->timeout_id = 0;
	}

	if (adapter->scan_enable != rp.enable)
		adapter_mode_changed(adapter, path, rp.enable);

failed:
	if (dd >= 0)
		hci_close_dev(dd);
}

void hcid_dbus_write_class_complete(bdaddr_t *local)
{
	struct adapter *adapter;
	char path[MAX_PATH_LENGTH], local_addr[18];
	int id, dd;
	uint8_t cls[3];

	ba2str(local, local_addr);
	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		return;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);
	if (!dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
		error("Getting %s path data failed!", path);
		return;
	}

	dd = hci_open_dev(id);
	if (dd < 0) {
		error("HCI device open failed: hci%d", id);
		return;
	}

	if (hci_read_class_of_dev(dd, cls, 1000) < 0) {
		error("Can't read class of device on hci%d: %s (%d)",
						id, strerror(errno), errno);
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

void hcid_dbus_pin_code_reply(bdaddr_t *local, void *ptr)
{

	typedef struct {
		uint8_t status;
		bdaddr_t bdaddr;
	} __attribute__ ((packed)) ret_pin_code_req_reply;

	struct adapter *adapter;
	ret_pin_code_req_reply *ret = ptr + EVT_CMD_COMPLETE_SIZE;
	GSList *l;
	char path[MAX_PATH_LENGTH], local_addr[18];
	int id;

	ba2str(local, local_addr);
	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		return;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_user_data(connection, path,
							(void *) &adapter)) {
		error("Getting %s path data failed!", path);
		return;
	}

	l = g_slist_find_custom(adapter->pin_reqs, &ret->bdaddr, pin_req_cmp);
	if (l) {
		struct pending_pin_info *p = l->data;
		p->replied = 1;
	}
}

void create_bond_req_exit(const char *name, struct adapter *adapter)
{
	char path[MAX_PATH_LENGTH];
	GSList *l;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, adapter->dev_id);

	debug("CreateConnection requestor (%s) exited before bonding was completed",
			name);

	cancel_passkey_agent_requests(adapter->passkey_agents, path,
					&adapter->bonding->bdaddr);
	release_passkey_agents(adapter, &adapter->bonding->bdaddr);

	l = g_slist_find_custom(adapter->pin_reqs, &adapter->bonding->bdaddr,
			pin_req_cmp);
	if (l) {
		struct pending_pin_info *p = l->data;

		if (!p->replied) {
			int dd;

			dd = hci_open_dev(adapter->dev_id);
			if (dd >= 0) {
				hci_send_cmd(dd, OGF_LINK_CTL,
						OCF_PIN_CODE_NEG_REPLY,
						6, &adapter->bonding->bdaddr);
				hci_close_dev(dd);
			}
		}

		adapter->pin_reqs = g_slist_remove(adapter->pin_reqs, p);
		g_free(p);
	}

	g_io_channel_close(adapter->bonding->io);
	if (adapter->bonding->io_id)
		g_source_remove(adapter->bonding->io_id);
	bonding_request_free(adapter->bonding);
	adapter->bonding = NULL;
}

void discover_devices_req_exit(const char *name, struct adapter *adapter)
{
	debug("DiscoverDevices requestor (%s) exited", name);

	/* Cleanup the discovered devices list and send the command to cancel
	 * inquiry or cancel remote name request. The return can be ignored. */
	cancel_discovery(adapter);
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

void periodic_discover_req_exit(const char *name, struct adapter *adapter)
{
	debug("PeriodicDiscovery requestor (%s) exited", name);

	/* Cleanup the discovered devices list and send the cmd to exit from
	 * periodic inquiry or cancel remote name request. The return value can
	 * be ignored. */

	cancel_periodic_discovery(adapter);
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
