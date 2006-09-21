/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <string.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <dbus/dbus.h>

#include "glib-ectomy.h"

#include "hcid.h"
#include "dbus.h"
#include "textfile.h"
#include "list.h"

static DBusConnection *connection;

static int default_dev = -1;

static int experimental = 0;

#define MAX_CONN_NUMBER			10
#define RECONNECT_RETRY_TIMEOUT		5000
#define DISPATCH_TIMEOUT		0

typedef struct {
	uint32_t id;
	DBusTimeout *timeout;
} timeout_handler_t;

struct watch_info {
	guint watch_id;
	GIOChannel *io;
};

void hcid_dbus_set_experimental(void)
{
	experimental = 1;
}

int hcid_dbus_use_experimental(void)
{
	return experimental;
}

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

	free(bonding);
}

int disc_device_find(const struct discovered_dev_info *d1, const struct discovered_dev_info *d2)
{
	int ret;

	if (bacmp(&d2->bdaddr, BDADDR_ANY)) {
		ret = bacmp(&d1->bdaddr, &d2->bdaddr);
		if (ret)
			return ret;
	}

	/* if not any */
	if (d2->name_status) {
		ret = (d1->name_status - d2->name_status);
		if (ret)
			return ret;
	}

	return 0;
}

int disc_device_append(struct slist **list, bdaddr_t *bdaddr, name_status_t name_status)
{
	struct discovered_dev_info *dev, match;
	struct slist *l;

	memset(&match, 0, sizeof(struct discovered_dev_info));
	bacpy(&match.bdaddr, bdaddr);
	match.name_status = NAME_ANY;

	/* ignore repeated entries */
	l = slist_find(*list, &match, (cmp_func_t) disc_device_find);
	if (l) {
		/* device found, update the attributes */
		dev = l->data;

		 /* Get remote name can be received while inquiring.
		  * Keep in mind that multiple inquiry result events can
		  * be received from the same remote device.
		  */
		if (name_status != NAME_NOT_REQUIRED)
			dev->name_status = name_status;
		return -EALREADY;
	}

	dev = malloc(sizeof(*dev));
	if (!dev)
		return -ENOMEM;

	memset(dev, 0, sizeof(*dev));
	bacpy(&dev->bdaddr, bdaddr);
	dev->name_status = name_status;

	*list = slist_append(*list, dev);

	return 0;
}

static int disc_device_remove(struct slist **list, bdaddr_t *bdaddr)
{
	struct discovered_dev_info *dev, match;
	struct slist *l;
	int ret_val = -1;

	memset(&match, 0, sizeof(struct discovered_dev_info));
	bacpy(&match.bdaddr, bdaddr);

	l = slist_find(*list, &match, (cmp_func_t) disc_device_find);

	if (l) {
		dev = l->data;
		*list = slist_remove(*list, dev);
		free(dev);
		ret_val = 0;
	}

	return ret_val;
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

static int active_conn_append(struct slist **list, bdaddr_t *bdaddr, uint16_t handle)
{
	struct active_conn_info *dev;

	dev = malloc(sizeof(*dev));
	if (!dev)
		return -1;

	memset(dev, 0 , sizeof(*dev));
	bacpy(&dev->bdaddr, bdaddr);
	dev->handle = handle;

	*list = slist_append(*list, dev);
	return 0;
}

static int active_conn_remove(struct slist **list, uint16_t *handle)
{
	struct active_conn_info *dev;
	struct slist *l;
	int ret_val = -1;

	l = slist_find(*list, handle, active_conn_find_by_handle);

	if (l) {
		dev = l->data;
		*list = slist_remove(*list, dev);
		free(dev);
		ret_val = 0;
	}

	return ret_val;
}

static DBusMessage *dbus_msg_new_authentication_return(DBusMessage *msg, uint8_t status)
{
	switch (status) {
	case 0x00: /* success */
		return dbus_message_new_method_return(msg);

	case 0x04: /* page timeout */
	case 0x08: /* connection timeout */
	case 0x10: /* connection accept timeout */
	case 0x22: /* LMP response timeout */
	case 0x28: /* instant passed - is this a timeout? */
		return dbus_message_new_error(msg, ERROR_INTERFACE".AuthenticationTimeout",
							"Authentication Timeout");
	case 0x17: /* too frequent pairing attempts */
		return dbus_message_new_error(msg, ERROR_INTERFACE".RepeatedAttemps",
							"Repeated Attempts");

	case 0x06:
	case 0x18: /* pairing not allowed (e.g. gw rejected attempt) */
		return dbus_message_new_error(msg, ERROR_INTERFACE".AuthenticationRejected",
							"Authentication Rejected");

	case 0x07: /* memory capacity */
	case 0x09: /* connection limit */
	case 0x0a: /* synchronous connection limit */
	case 0x0d: /* limited resources */
	case 0x14: /* terminated due to low resources */
		return dbus_message_new_error(msg, ERROR_INTERFACE".AuthenticationCanceled",
							"Authentication Canceled");

	case 0x05: /* authentication failure */
	case 0x0E: /* rejected due to security reasons - is this auth failure? */
	case 0x25: /* encryption mode not acceptable - is this auth failure? */
	case 0x26: /* link key cannot be changed - is this auth failure? */
	case 0x29: /* pairing with unit key unsupported - is this auth failure? */
	case 0x2f: /* insufficient security - is this auth failure? */
	default:
		return dbus_message_new_error(msg, ERROR_INTERFACE".AuthenticationFailed",
							"Authentication Failed");
	}
}

int get_default_dev_id(void)
{
	return default_dev;
}

static inline int dev_append_signal_args(DBusMessage *signal, int first, va_list var_args)
{
	void *value;
	DBusMessageIter iter;
	int type = first;

	dbus_message_iter_init_append(signal, &iter);

	while (type != DBUS_TYPE_INVALID) {
		value = va_arg(var_args, void *);

		if (!dbus_message_iter_append_basic(&iter, type, value)) {
			error("Append property argument error (type %d)", type);
			return -1;
		}

		type = va_arg(var_args, int);
	}

	return 0;
}

DBusMessage *dev_signal_factory(const int devid, const char *prop_name, const int first, ...)
{
	va_list var_args;
	DBusMessage *signal;
	char path[MAX_PATH_LENGTH];

	snprintf(path, sizeof(path)-1, "%s/hci%d", BASE_PATH, devid);

	signal = dbus_message_new_signal(path, ADAPTER_INTERFACE, prop_name);
	if (!signal) {
		error("Can't allocate D-BUS message");
		return NULL;
	}

	va_start(var_args, first);

	if (dev_append_signal_args(signal, first, var_args) < 0) {
		dbus_message_unref(signal);
		signal = NULL;
	}

	va_end(var_args);

	return signal;
}

/*
 * Virtual table that handle the object path hierarchy
 */

static const DBusObjectPathVTable obj_dev_vtable = {
	.message_function	= &msg_func_device,
	.unregister_function	= NULL
};

static const DBusObjectPathVTable obj_mgr_vtable = {
	.message_function	= &msg_func_manager,
	.unregister_function	= NULL
};

/*
 * HCI D-Bus services
 */
static DBusHandlerResult hci_dbus_signal_filter(DBusConnection *conn, DBusMessage *msg, void *data);

static int register_dbus_path(const char *path, uint16_t dev_id,
				const DBusObjectPathVTable *pvtable, gboolean fallback)
{
	struct hci_dbus_data *data;

	info("Register path:%s fallback:%d", path, fallback);

	data = malloc(sizeof(struct hci_dbus_data));
	if (!data) {
		error("Failed to alloc memory to DBUS path register data (%s)", path);
		return -1;
	}

	memset(data, 0, sizeof(struct hci_dbus_data));

	data->dev_id = dev_id;

	if (fallback) {
		if (!dbus_connection_register_fallback(connection, path, pvtable, data)) {
			error("D-Bus failed to register %s fallback", path);
			free(data);
			return -1;
		}
	} else {
		if (!dbus_connection_register_object_path(connection, path, pvtable, data)) {
			error("D-Bus failed to register %s object", path);
			free(data);
			return -1;
		}
	}

	return 0;
}

static void reply_pending_requests(const char *path, struct hci_dbus_data *pdata)
{
	DBusMessage *message = NULL;

	if (!path || !pdata)
		return;

	/* pending bonding */
	if (pdata->bonding) {
		error_authentication_canceled(connection, pdata->bonding->rq);
		name_listener_remove(connection, dbus_message_get_sender(pdata->bonding->rq),
				(name_cb_t) create_bond_req_exit, pdata);
		if (pdata->bonding->io_id)
			g_io_remove_watch(pdata->bonding->io_id);
		g_io_channel_close(pdata->bonding->io);
		bonding_request_free(pdata->bonding);
		pdata->bonding = NULL;
	}

	/* If there is a pending reply for discovery cancel */
	if (pdata->discovery_cancel) {
		message = dbus_message_new_method_return(pdata->discovery_cancel);
		send_reply_and_unref(connection, message);
		dbus_message_unref(pdata->discovery_cancel);
		pdata->discovery_cancel = NULL;
	}

	if (pdata->disc_active) {
		/* Send discovery completed signal if there isn't name
		 * to resolve */
		message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
							"DiscoveryCompleted");
		send_reply_and_unref(connection, message);

		/* Cancel inquiry initiated by D-Bus client */
		if (pdata->discovery_requestor)
			cancel_discovery(pdata);
	}

	if (pdata->pdisc_active) {
		/* Send periodic discovery stopped signal exit or stop
		 * the device */
		message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						"PeriodicDiscoveryStopped");
		send_reply_and_unref(connection, message);

		/* Stop periodic inquiry initiated by D-Bus client */
		if (pdata->pdiscovery_requestor)
			cancel_periodic_discovery(pdata);
	}
}

static int unregister_dbus_path(const char *path)
{
	struct hci_dbus_data *pdata;

	info("Unregister path:%s", path);

	if (dbus_connection_get_object_path_data(connection, path, (void *) &pdata) && pdata) {

		/* check pending requests */
		reply_pending_requests(path, pdata);

		cancel_passkey_agent_requests(pdata->passkey_agents, path, NULL);

		release_passkey_agents(pdata, NULL);

		if (pdata->discovery_requestor) {
			name_listener_remove(connection,
				pdata->discovery_requestor,
				(name_cb_t) discover_devices_req_exit, pdata);
			free(pdata->discovery_requestor);
			pdata->discovery_requestor = NULL;
		}

		if (pdata->pdiscovery_requestor) {
			name_listener_remove(connection,
				pdata->pdiscovery_requestor,
				(name_cb_t) periodic_discover_req_exit, pdata);
			free(pdata->pdiscovery_requestor);
			pdata->pdiscovery_requestor = NULL;
		}

		if (pdata->disc_devices) {
			slist_foreach(pdata->disc_devices,
					(slist_func_t) free, NULL);
			slist_free(pdata->disc_devices);
			pdata->disc_devices = NULL;
		}

		if (pdata->oor_devices) {
			slist_foreach(pdata->oor_devices,
					(slist_func_t) free, NULL);
			slist_free(pdata->oor_devices);
			pdata->oor_devices = NULL;
		}

		if (pdata->pin_reqs) {
			slist_foreach(pdata->pin_reqs,
					(slist_func_t) free, NULL);
			slist_free(pdata->pin_reqs);
			pdata->pin_reqs = NULL;
		}

		if (pdata->active_conn) {
			slist_foreach(pdata->active_conn,
					(slist_func_t) free, NULL);
			slist_free(pdata->active_conn);
			pdata->active_conn = NULL;
		}

		free (pdata);
	}

	if (!dbus_connection_unregister_object_path (connection, path)) {
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
	DBusMessage *message = NULL;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (register_dbus_path(path, id, &obj_dev_vtable, FALSE) < 0)
		return -1;

	/*
	 * Send the adapter added signal
	 */
	message = dbus_message_new_signal(BASE_PATH, MANAGER_INTERFACE,
							"AdapterAdded");
	if (message == NULL) {
		error("Can't allocate D-Bus message");
		dbus_connection_unregister_object_path(connection, path);
		return -1;
	}

	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &pptr,
					DBUS_TYPE_INVALID);

	send_reply_and_unref(connection, message);

	return 0;
}

int hcid_dbus_unregister_device(uint16_t id)
{
	DBusMessage *message;
	char path[MAX_PATH_LENGTH];
	char *pptr = path;
	int ret;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	message = dbus_message_new_signal(BASE_PATH, MANAGER_INTERFACE,
							"AdapterRemoved");
	if (message == NULL) {
		error("Can't allocate D-Bus message");
		goto failed;
	}

	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &pptr,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send(connection, message, NULL)) {
		error("Can't send D-Bus added device message");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	if (message)
		dbus_message_unref(message);

	ret = unregister_dbus_path(path);

	if (ret == 0 && default_dev == id)
		default_dev = hci_get_route(NULL);

	return ret;
}

int hcid_dbus_start_device(uint16_t id)
{
	char path[MAX_PATH_LENGTH];
	int i, err, dd = -1, ret = -1;
	read_scan_enable_rp rp;
	struct hci_dev_info di;
	struct hci_request rq;
	struct hci_dbus_data* pdata;
	struct hci_conn_list_req *cl = NULL;
	struct hci_conn_info *ci;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	/* FIXME: check dupplicated code - configure_device() */
	if (hci_devinfo(id, &di) < 0) {
		error("Getting device info failed: hci%d", id);
		return -1;
	}

	if (hci_test_bit(HCI_RAW, &di.flags))
		return -1;

	dd = hci_open_dev(id);
	if (dd < 0) {
		error("HCI device open failed: hci%d", id);
		rp.enable = SCAN_PAGE | SCAN_INQUIRY;
	} else {
		memset(&rq, 0, sizeof(rq));
		rq.ogf    = OGF_HOST_CTL;
		rq.ocf    = OCF_READ_SCAN_ENABLE;
		rq.rparam = &rp;
		rq.rlen   = READ_SCAN_ENABLE_RP_SIZE;

		if (hci_send_req(dd, &rq, 500) < 0) {
			error("Sending read scan enable command failed: %s (%d)",
								strerror(errno), errno);
			rp.enable = SCAN_PAGE | SCAN_INQUIRY;
		} else if (rp.status) {
			error("Getting scan enable failed with status 0x%02x",
										rp.status);
			rp.enable = SCAN_PAGE | SCAN_INQUIRY;
		}
	}

	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		error("Getting %s path data failed!", path);
		goto failed;
	}

	if (hci_test_bit(HCI_INQUIRY, &di.flags))
		pdata->disc_active = 1;
	else
		pdata->disc_active = 0;

	pdata->mode = rp.enable;	/* Keep the current scan status */
	pdata->up = 1;
	pdata->discoverable_timeout = get_discoverable_timeout(id);
	pdata->discover_type = DISCOVER_TYPE_NONE;

	/*
	 * Get the adapter Bluetooth address
	 */
	err = get_device_address(pdata->dev_id, pdata->address, sizeof(pdata->address));
	if (err < 0)
		goto failed;

	/* 
	 * retrieve the active connections: address the scenario where
	 * the are active connections before the daemon've started
	 */

	cl = malloc(10 * sizeof(*ci) + sizeof(*cl));
	if (!cl)
		goto failed;

	cl->dev_id = id;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(dd, HCIGETCONNLIST, (void *) cl) < 0) {
		free(cl);
		cl = NULL;
		goto failed;
	}

	for (i = 0; i < cl->conn_num; i++, ci++)
		active_conn_append(&pdata->active_conn,
					&ci->bdaddr, ci->handle);

	ret = 0;

failed:
	if (ret == 0 && default_dev < 0)
		default_dev = id;

	if (dd >= 0)
		close(dd);

	if (cl)
		free(cl);

	return ret;
}

int hcid_dbus_stop_device(uint16_t id)
{
	char path[MAX_PATH_LENGTH];
	struct hci_dbus_data *pdata;
	const char *scan_mode = MODE_OFF;
	DBusMessage *message;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		error("Getting %s path data failed!", path);
		return -1;
	}
	/* cancel pending timeout */
	if (pdata->timeout_id) {
		g_timeout_remove(pdata->timeout_id);
		pdata->timeout_id = 0;
	}

	/* check pending requests */
	reply_pending_requests(path, pdata);

	message = dev_signal_factory(pdata->dev_id, "ModeChanged",
						DBUS_TYPE_STRING, &scan_mode,
						DBUS_TYPE_INVALID);

	send_reply_and_unref(connection, message);


	cancel_passkey_agent_requests(pdata->passkey_agents, path, NULL);

	release_passkey_agents(pdata, NULL);

	if (pdata->discovery_requestor) {
		name_listener_remove(connection, pdata->discovery_requestor,
					(name_cb_t) discover_devices_req_exit, pdata);
		free(pdata->discovery_requestor);
		pdata->discovery_requestor = NULL;
	}

	if (pdata->pdiscovery_requestor) {
		name_listener_remove(connection, pdata->pdiscovery_requestor,
					(name_cb_t) periodic_discover_req_exit, pdata);
		free(pdata->pdiscovery_requestor);
		pdata->pdiscovery_requestor = NULL;
	}

	if (pdata->disc_devices) {
		slist_foreach(pdata->disc_devices, (slist_func_t) free, NULL);
		slist_free(pdata->disc_devices);
		pdata->disc_devices = NULL;
	}

	if (pdata->oor_devices) {
		slist_foreach(pdata->oor_devices, (slist_func_t) free, NULL);
		slist_free(pdata->oor_devices);
		pdata->oor_devices = NULL;
	}

	if (pdata->pin_reqs) {
		slist_foreach(pdata->pin_reqs, (slist_func_t) free, NULL);
		slist_free(pdata->pin_reqs);
		pdata->pin_reqs = NULL;
	}

	if (pdata->active_conn) {
		slist_foreach(pdata->active_conn, (slist_func_t) free, NULL);
		slist_free(pdata->active_conn);
		pdata->active_conn = NULL;
	}

	pdata->up = 0;
	pdata->mode = SCAN_DISABLED;
	pdata->disc_active = 0;
	pdata->pdisc_active = 0;
	pdata->pinq_idle = 0;
	pdata->discover_type = DISCOVER_TYPE_NONE;

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
	struct hci_dbus_data *pdata;
	struct pending_pin_info *info;

	ba2str(sba, addr);

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, hci_devid(addr));

	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		error("Getting %s path data failed!", path);
		return;
	}

	info = malloc(sizeof(struct pending_pin_info));
	if (!info) {
		error("Out of memory when adding new pin request");
		return;
	}

	memset(info, 0, sizeof(struct pending_pin_info));
	bacpy(&info->bdaddr, dba);
	pdata->pin_reqs = slist_append(pdata->pin_reqs, info);
}

int hcid_dbus_request_pin(int dev, bdaddr_t *sba, struct hci_conn_info *ci)
{
	char path[MAX_PATH_LENGTH], addr[18];

	ba2str(sba, addr);

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, hci_devid(addr));

	return handle_passkey_request(connection, dev, path, sba, &ci->bdaddr);
}

void hcid_dbus_bonding_process_complete(bdaddr_t *local, bdaddr_t *peer, uint8_t status)
{
	struct hci_dbus_data *pdata;
	DBusMessage *message;
	char *local_addr, *peer_addr;
	struct slist *l;
	bdaddr_t tmp;
	char path[MAX_PATH_LENGTH];
	int id;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, peer); peer_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	/* create the authentication reply */
	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		error("Getting %s path data failed!", path);
		goto failed;
	}

	if (status)
		cancel_passkey_agent_requests(pdata->passkey_agents, path, peer);

	l = slist_find(pdata->pin_reqs, peer, pin_req_cmp);
	if (l) {
		void *d = l->data;
		pdata->pin_reqs = slist_remove(pdata->pin_reqs, l->data);
		free(d);

		if (!status) {
			message = dev_signal_factory(pdata->dev_id, "BondingCreated",
							DBUS_TYPE_STRING, &peer_addr,
							DBUS_TYPE_INVALID);
			send_reply_and_unref(connection, message);
		}
	}

	release_passkey_agents(pdata, peer);

	if (!pdata->bonding || bacmp(&pdata->bonding->bdaddr, peer))
		goto failed; /* skip: no bonding req pending */

	if (pdata->bonding->cancel) {
		/* reply authentication canceled */
		error_authentication_canceled(connection, pdata->bonding->rq);
	} else {
		/* reply authentication success or an error */
		message = dbus_msg_new_authentication_return(pdata->bonding->rq, status);
		send_reply_and_unref(connection, message);
	}

	name_listener_remove(connection, dbus_message_get_sender(pdata->bonding->rq),
			(name_cb_t) create_bond_req_exit, pdata);

	g_io_channel_close(pdata->bonding->io);
	bonding_request_free(pdata->bonding);
	pdata->bonding = NULL;

failed:
	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_inquiry_start(bdaddr_t *local)
{
	struct hci_dbus_data *pdata;
	DBusMessage *message = NULL;
	char path[MAX_PATH_LENGTH];
	char *local_addr;
	bdaddr_t tmp;
	int id;

	baswap(&tmp, local); local_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		pdata->disc_active = 1;
		/* 
		 * Cancel pending remote name request and clean the device list
		 * when inquiry is supported in periodic inquiry idle state.
		 */
		if (pdata->pdisc_active)
			pending_remote_name_cancel(pdata);

		/* Disable name resolution for non D-Bus clients */
		if (!pdata->discovery_requestor)
			pdata->discover_type &= ~RESOLVE_NAME;
	}

	message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						"DiscoveryStarted");
	if (message == NULL) {
		error("Can't allocate D-Bus message");
		goto failed;
	}

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		error("Can't send D-Bus inquiry start message");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	if (message)
		dbus_message_unref(message);

	bt_free(local_addr);
}

int disc_device_req_name(struct hci_dbus_data *dbus_data)
{
	struct hci_request rq;
	evt_cmd_status rp;
	remote_name_req_cp cp;
	struct discovered_dev_info match;
	struct slist *l;
	int dd, req_sent = 0;

	/* get the next remote address */
	if (!dbus_data->disc_devices)
		return -ENODATA;

	memset(&match, 0, sizeof(struct discovered_dev_info));
	bacpy(&match.bdaddr, BDADDR_ANY);
	match.name_status = NAME_REQUIRED;

	l = slist_find(dbus_data->disc_devices, &match,
					(cmp_func_t) disc_device_find);
	if (!l)
		return -ENODATA;

	dd = hci_open_dev(dbus_data->dev_id);
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
		DBusMessage *failed_signal = NULL;
		struct discovered_dev_info *dev = l->data;
		char *peer_addr;
		bdaddr_t tmp;

		 /* flag to indicate the current remote name requested */ 
		dev->name_status = NAME_REQUESTED;

		memset(&cp, 0, sizeof(cp));
		bacpy(&cp.bdaddr, &dev->bdaddr);
		cp.pscan_rep_mode = 0x02;

		baswap(&tmp, &dev->bdaddr); peer_addr = batostr(&tmp);

		if (hci_send_req(dd, &rq, 100) < 0) {
			error("Unable to send the HCI remote name request: %s (%d)",
						strerror(errno), errno);
			failed_signal = dev_signal_factory(dbus_data->dev_id,
						"RemoteNameFailed",
						DBUS_TYPE_STRING, &peer_addr,
						DBUS_TYPE_INVALID);
		}

		if (rp.status) {
			error("Remote name request failed with status 0x%02x", rp.status);
			failed_signal = dev_signal_factory(dbus_data->dev_id,
						"RemoteNameFailed",
						DBUS_TYPE_STRING, &peer_addr,
						DBUS_TYPE_INVALID);
		}

		free(peer_addr);

		if (!failed_signal) {
			req_sent = 1;
			break;
		}

		send_reply_and_unref(connection, failed_signal);
		failed_signal = NULL;

		/* if failed, request the next element */
		/* remove the element from the list */
		dbus_data->disc_devices = slist_remove(dbus_data->disc_devices, dev);
		free(dev);

		/* get the next element */
		l = slist_find(dbus_data->disc_devices, &match,
					(cmp_func_t) disc_device_find);

	} while (l);

	hci_close_dev(dd);

	if (!req_sent)
		return -ENODATA;

	return 0;
}

static void send_out_of_range(const char *path, struct slist *l)
{
	DBusMessage *message;
	const char *peer_addr;

	while (l) {
		peer_addr = l->data;

		message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						"RemoteDeviceDisappeared");
		dbus_message_append_args(message,
				DBUS_TYPE_STRING, &peer_addr,
				DBUS_TYPE_INVALID);

		send_reply_and_unref(connection, message);
		l = l->next;
	}
}

void hcid_dbus_inquiry_complete(bdaddr_t *local)
{
	DBusMessage *message;
	struct hci_dbus_data *pdata;
	struct slist *l;
	char path[MAX_PATH_LENGTH];
	char *local_addr;
	struct discovered_dev_info *dev;
	bdaddr_t tmp;
	int id;

	baswap(&tmp, local); local_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto done;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		error("Getting %s path data failed!", path);
		goto done;
	}

	/* Out of range verification */
	if (pdata->pdisc_active && !pdata->disc_active) {
		send_out_of_range(path, pdata->oor_devices);

		slist_foreach(pdata->oor_devices, (slist_func_t) free, NULL);
		slist_free(pdata->oor_devices);
		pdata->oor_devices = NULL;

		l = pdata->disc_devices;
		while (l) {
			dev = l->data;
			baswap(&tmp, &dev->bdaddr);
			pdata->oor_devices = slist_append(pdata->oor_devices, batostr(&tmp));
			l = l->next;
		}
	}

	pdata->pinq_idle = 1;

	/* 
	 * Enable resolution again: standard inquiry can be 
	 * received in the periodic inquiry idle state.
	 */
	if (pdata->pdiscovery_requestor)
		pdata->discover_type |= RESOLVE_NAME;

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

	if (!disc_device_req_name(pdata))
		goto done; /* skip - there is name to resolve */

	if (pdata->disc_active) {
		message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
							"DiscoveryCompleted");
		send_reply_and_unref(connection, message);

		pdata->disc_active = 0;
	}

	/* free discovered devices list */
	slist_foreach(pdata->disc_devices, (slist_func_t) free, NULL);
	slist_free(pdata->disc_devices);
	pdata->disc_devices = NULL;

	if (pdata->discovery_requestor) { 
		name_listener_remove(connection, pdata->discovery_requestor,
				(name_cb_t) discover_devices_req_exit, pdata);
		free(pdata->discovery_requestor);
		pdata->discovery_requestor = NULL;

		/* If there is a pending reply for discovery cancel */
		if (pdata->discovery_cancel) {
			message = dbus_message_new_method_return(pdata->discovery_cancel);
			send_reply_and_unref(connection, message);
			dbus_message_unref(pdata->discovery_cancel);
			pdata->discovery_cancel = NULL;
		}

		/* reset the discover type for standard inquiry only */
		pdata->discover_type &= ~STD_INQUIRY; 
	}

done:
	bt_free(local_addr);
}

void hcid_dbus_periodic_inquiry_start(bdaddr_t *local, uint8_t status)
{
	struct hci_dbus_data *pdata;
	DBusMessage *message;
	char path[MAX_PATH_LENGTH];
	char *local_addr;
	bdaddr_t tmp;
	int id;

	/* Don't send the signal if the cmd failed */
	if (status)
		return;

	baswap(&tmp, local); local_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		pdata->pdisc_active = 1;

		/* Disable name resolution for non D-Bus clients */
		if (!pdata->pdiscovery_requestor)
			pdata->discover_type &= ~RESOLVE_NAME;
	}

	message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						"PeriodicDiscoveryStarted");
	send_reply_and_unref(connection, message);

failed:
	bt_free(local_addr);
}

void hcid_dbus_periodic_inquiry_exit(bdaddr_t *local, uint8_t status)
{
	DBusMessage *message;
	struct hci_dbus_data *pdata;
	char path[MAX_PATH_LENGTH];
	char *local_addr;
	bdaddr_t tmp;
	int id;

	/* Don't send the signal if the cmd failed */
	if (status)
		return;

	baswap(&tmp, local); local_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto done;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		error("Getting %s path data failed!", path);
		goto done;
	}

	/* reset the discover type to be able to handle D-Bus and non D-Bus requests */
	pdata->pdisc_active = 0;
	pdata->discover_type &= ~(PERIODIC_INQUIRY | RESOLVE_NAME);

	/* free discovered devices list */
	slist_foreach(pdata->disc_devices, (slist_func_t) free, NULL);
	slist_free(pdata->disc_devices);
	pdata->disc_devices = NULL;

	/* free out of range devices list */
	slist_foreach(pdata->oor_devices, (slist_func_t) free, NULL);
	slist_free(pdata->oor_devices);
	pdata->oor_devices = NULL;

	if (pdata->pdiscovery_requestor) {
		name_listener_remove(connection, pdata->pdiscovery_requestor,
					(name_cb_t) periodic_discover_req_exit, pdata);
		free(pdata->pdiscovery_requestor);
		pdata->pdiscovery_requestor = NULL;
	}

	 /* workaround: inquiry completed is not sent when exiting from periodic inquiry */
	if (pdata->disc_active) {
		message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
				"DiscoveryCompleted");
		send_reply_and_unref(connection, message);

		pdata->disc_active = 0;
	}

	/* Send discovery completed signal if there isn't name to resolve */
	message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						"PeriodicDiscoveryStopped");
	send_reply_and_unref(connection, message);
done:
	bt_free(local_addr);
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

void hcid_dbus_inquiry_result(bdaddr_t *local, bdaddr_t *peer, uint32_t class, int8_t rssi, uint8_t *data)
{
	char filename[PATH_MAX + 1];
	DBusMessage *signal_device;
	DBusMessage *signal_name;
	char path[MAX_PATH_LENGTH];
	struct hci_dbus_data *pdata;
	struct slist *l;
	struct discovered_dev_info match;
	char *local_addr, *peer_addr, *name, *tmp_name;
	const dbus_uint32_t tmp_class = class;
	const dbus_int16_t tmp_rssi = rssi;
	bdaddr_t tmp;
	uint8_t name_type = 0x00;
	name_status_t name_status;
	int id;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, peer); peer_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto done;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		error("Getting %s path data failed!", path);
		goto done;
	}

	write_remote_class(local, peer, class);

	/*
	 * workaround to identify situation when the daemon started and
	 * a standard inquiry or periodic inquiry was already running
	 */
	if (!pdata->disc_active && !pdata->pdisc_active)
		pdata->pdisc_active = 1;

	/* reset the idle flag when the inquiry complete event arrives */
	if (pdata->pdisc_active) {
		pdata->pinq_idle = 0;

		/* Out of range list update */
		l = slist_find(pdata->oor_devices, peer_addr, (cmp_func_t) strcmp);
		if (l)
			pdata->oor_devices = slist_remove(pdata->oor_devices, l->data);
	}

	/* send the device found signal */
	signal_device = dev_signal_factory(pdata->dev_id, "RemoteDeviceFound",
						DBUS_TYPE_STRING, &peer_addr,
						DBUS_TYPE_UINT32, &tmp_class,
						DBUS_TYPE_INT16, &tmp_rssi,
						DBUS_TYPE_INVALID);

	send_reply_and_unref(connection, signal_device);

	memset(&match, 0, sizeof(struct discovered_dev_info));
	bacpy(&match.bdaddr, peer);
	match.name_status = NAME_SENT;
	/* if found: don't sent the name again */
	l = slist_find(pdata->disc_devices, &match, (cmp_func_t) disc_device_find);
	if (l)
		goto done;

	/* the inquiry result can be triggered by NON D-Bus client */
	if (pdata->discover_type & RESOLVE_NAME)
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
				free(name);

			name = tmp_name;
		} else {
			if (name)
				free(tmp_name);
			else
				name = tmp_name;
		}
	}

	if (name) {
		signal_name = dev_signal_factory(pdata->dev_id, "RemoteNameUpdated",
							DBUS_TYPE_STRING, &peer_addr,
							DBUS_TYPE_STRING, &name,
							DBUS_TYPE_INVALID);
		send_reply_and_unref(connection, signal_name);

		free(name);

		if (name_type != 0x08)
			name_status = NAME_SENT;
	} 

	/* add in the list to track name sent/pending */
	disc_device_append(&pdata->disc_devices, peer, name_status);

done:
	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_remote_class(bdaddr_t *local, bdaddr_t *peer, uint32_t class)
{
	struct hci_dbus_data *pdata;
	DBusMessage *message;
	char path[MAX_PATH_LENGTH];
	char *local_addr, *peer_addr;
	bdaddr_t tmp;
	uint32_t old_class = 0;
	const dbus_uint32_t tmp_class = class;
	int id;

	read_remote_class(local, peer, &old_class);

	if (old_class == class)
		return;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, peer); peer_addr = batostr(&tmp);
	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (dbus_connection_get_object_path_data(connection, path, (void *) &pdata))
		goto failed;

	message = dev_signal_factory(pdata->dev_id, "RemoteClassUpdated",
						DBUS_TYPE_STRING, &peer_addr,
						DBUS_TYPE_UINT32, &tmp_class,
						DBUS_TYPE_INVALID);

	send_reply_and_unref(connection, message);

failed:
	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_remote_name(bdaddr_t *local, bdaddr_t *peer, uint8_t status, char *name)
{
	struct hci_dbus_data *pdata;
	DBusMessage *message;
	char path[MAX_PATH_LENGTH];
	char *local_addr, *peer_addr;
	bdaddr_t tmp;
	int id;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, peer); peer_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto done;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		error("Getting %s path data failed!", path);
		goto done;
	}

	if (status)
		message = dev_signal_factory(pdata->dev_id,
						"RemoteNameFailed",
						DBUS_TYPE_STRING, &peer_addr,
						DBUS_TYPE_INVALID);
	else 
		message = dev_signal_factory(pdata->dev_id,
						"RemoteNameUpdated",
						DBUS_TYPE_STRING, &peer_addr,
						DBUS_TYPE_STRING, &name,
						DBUS_TYPE_INVALID);

	send_reply_and_unref(connection, message);

	/* remove from remote name request list */
	disc_device_remove(&pdata->disc_devices, peer);

	/* check if there is more devices to request names */
	if (!disc_device_req_name(pdata))
		goto done; /* skip if a new request has been sent */

	/* free discovered devices list */
	slist_foreach(pdata->disc_devices, (slist_func_t) free, NULL);
	slist_free(pdata->disc_devices);
	pdata->disc_devices = NULL;

	/*
	 * The discovery completed signal must be sent only for discover 
	 * devices request WITH name resolving
	 */
	if (pdata->discovery_requestor) {
		name_listener_remove(connection, pdata->discovery_requestor,
				(name_cb_t) discover_devices_req_exit, pdata);
		free(pdata->discovery_requestor);
		pdata->discovery_requestor = NULL;

		/* If there is a pending reply for discovery cancel */
		if (pdata->discovery_cancel) {
			message = dbus_message_new_method_return(pdata->discovery_cancel);
			send_reply_and_unref(connection, message);
			dbus_message_unref(pdata->discovery_cancel);
			pdata->discovery_cancel = NULL;
		}

		if (pdata->discover_type & RESOLVE_NAME) {
			message = dbus_message_new_signal(path,
				ADAPTER_INTERFACE, "DiscoveryCompleted");
			send_reply_and_unref(connection, message);
		}

		/* Disable name resolution for non D-Bus clients */
		if (!pdata->pdiscovery_requestor)
			pdata->discover_type &= ~RESOLVE_NAME;
	}

	pdata->disc_active = 0;

done:
	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_conn_complete(bdaddr_t *local, uint8_t status, uint16_t handle, bdaddr_t *peer)
{
	char path[MAX_PATH_LENGTH];
	DBusMessage *message;
	struct hci_dbus_data *pdata;
	char *local_addr, *peer_addr;
	bdaddr_t tmp;
	int dd = -1, id;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, peer); peer_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto done;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		error("Getting %s path data failed!", path);
		goto done;
	}

	if (!status) {
		/* Sent the remote device connected signal */
		message = dbus_message_new_signal(path, ADAPTER_INTERFACE, "RemoteDeviceConnected");

		dbus_message_append_args(message,
					 	DBUS_TYPE_STRING, &peer_addr,
						DBUS_TYPE_INVALID);

		send_reply_and_unref(connection, message);

		/* add in the active connetions list */
		active_conn_append(&pdata->active_conn, peer, handle);
	}

done:
	if (dd >= 0)
		hci_close_dev(dd);

	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_disconn_complete(bdaddr_t *local, uint8_t status, uint16_t handle, uint8_t reason)
{
	char path[MAX_PATH_LENGTH];
	struct hci_dbus_data *pdata;
	struct active_conn_info *dev;
	DBusMessage *message;
	struct slist *l;
	char *local_addr, *peer_addr = NULL;
	bdaddr_t tmp;
	int id;

	if (status) {
		error("Disconnection failed: 0x%02x", status);
		return;
	}

	baswap(&tmp, local); local_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		error("Getting %s path data failed!", path);
		goto failed;
	}

	l = slist_find(pdata->active_conn, &handle, active_conn_find_by_handle);

	if (!l)
		goto failed;

	dev = l->data;

	baswap(&tmp, &dev->bdaddr); peer_addr = batostr(&tmp);

	/* clean pending HCI cmds */
	hci_req_queue_remove(pdata->dev_id, &dev->bdaddr);

	/* Cancel D-Bus/non D-Bus requests */
	cancel_passkey_agent_requests(pdata->passkey_agents, path, &dev->bdaddr);
	release_passkey_agents(pdata, &dev->bdaddr);

	l = slist_find(pdata->pin_reqs, &dev->bdaddr, pin_req_cmp);
	if (l) {
		struct pending_pin_req *p = l->data;
		pdata->pin_reqs = slist_remove(pdata->pin_reqs, p);
		free(p);
	}

	/* Check if there is a pending CreateBonding request */
	if (pdata->bonding && (bacmp(&pdata->bonding->bdaddr, &dev->bdaddr) == 0)) {
		if (pdata->bonding->cancel) {
			/* reply authentication canceled */
			error_authentication_canceled(connection, pdata->bonding->rq);
		} else {
			message = dbus_msg_new_authentication_return(pdata->bonding->rq, HCI_AUTHENTICATION_FAILURE);
			send_reply_and_unref(connection, message);
		}

		name_listener_remove(connection, dbus_message_get_sender(pdata->bonding->rq),
				(name_cb_t) create_bond_req_exit, pdata);
		g_io_channel_close(pdata->bonding->io);
		bonding_request_free(pdata->bonding);
		pdata->bonding = NULL;
	}
	/* Sent the remote device disconnected signal */
	message = dev_signal_factory(pdata->dev_id, "RemoteDeviceDisconnected",
					DBUS_TYPE_STRING, &peer_addr,
					DBUS_TYPE_INVALID);

	send_reply_and_unref(connection, message);
	active_conn_remove(&pdata->active_conn, &handle);

failed:
	if (peer_addr)
		free(peer_addr);

	free(local_addr);
}

/*****************************************************************
 *
 *  Section reserved to D-Bus watch functions
 *
 *****************************************************************/
static gboolean message_dispatch_cb(void *data)
{
	dbus_connection_ref(connection);

	/* Dispatch messages */
	while (dbus_connection_dispatch(connection) == DBUS_DISPATCH_DATA_REMAINS);

	dbus_connection_unref(connection);

	return FALSE;
}

static gboolean watch_func(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	DBusWatch *watch = data;
	int flags = 0;

	if (cond & G_IO_IN)  flags |= DBUS_WATCH_READABLE;
	if (cond & G_IO_OUT) flags |= DBUS_WATCH_WRITABLE;
	if (cond & G_IO_HUP) flags |= DBUS_WATCH_HANGUP;
	if (cond & G_IO_ERR) flags |= DBUS_WATCH_ERROR;

	dbus_watch_handle(watch, flags);

	if (dbus_connection_get_dispatch_status(connection) == DBUS_DISPATCH_DATA_REMAINS)
		g_timeout_add(DISPATCH_TIMEOUT, message_dispatch_cb, NULL);

	return TRUE;
}

static dbus_bool_t add_watch(DBusWatch *watch, void *data)
{
	GIOCondition cond = G_IO_HUP | G_IO_ERR;
	struct watch_info *info;
	int fd, flags;

	if (!dbus_watch_get_enabled(watch))
		return TRUE;

	info = malloc(sizeof(struct watch_info));
	if (info == NULL)
		return FALSE;

	fd = dbus_watch_get_fd(watch);
	info->io = g_io_channel_unix_new(fd);
	flags = dbus_watch_get_flags(watch);

	if (flags & DBUS_WATCH_READABLE) cond |= G_IO_IN;
	if (flags & DBUS_WATCH_WRITABLE) cond |= G_IO_OUT;

	info->watch_id = g_io_add_watch(info->io, cond, watch_func, watch);

	dbus_watch_set_data(watch, info, NULL);

	return TRUE;
}

static void remove_watch(DBusWatch *watch, void *data)
{
	struct watch_info *info = dbus_watch_get_data(watch);

	dbus_watch_set_data(watch, NULL, NULL);

	if (info) {
		g_io_remove_watch(info->watch_id);
		g_io_channel_unref(info->io);
		free(info);
	}
}

static void watch_toggled(DBusWatch *watch, void *data)
{
	/* Because we just exit on OOM, enable/disable is
	 * no different from add/remove */
	if (dbus_watch_get_enabled(watch))
		add_watch(watch, data);
	else
		remove_watch(watch, data);
}

static gboolean timeout_handler_dispatch(gpointer data)
{
	timeout_handler_t *handler = data;

	/* if not enabled should not be polled by the main loop */
	if (dbus_timeout_get_enabled(handler->timeout) != TRUE)
		return FALSE;

	dbus_timeout_handle(handler->timeout);

	return FALSE;
}

static void timeout_handler_free(void *data)
{
	timeout_handler_t *handler = data;
	if (!handler)
		return;

	g_timeout_remove(handler->id);
	free(handler);
}

static dbus_bool_t add_timeout(DBusTimeout *timeout, void *data)
{
	timeout_handler_t *handler;

	if (!dbus_timeout_get_enabled (timeout))
		return TRUE;

	handler = malloc(sizeof(timeout_handler_t));
	memset(handler, 0, sizeof(timeout_handler_t));

	handler->timeout = timeout;
	handler->id = g_timeout_add(dbus_timeout_get_interval(timeout),
					timeout_handler_dispatch, handler);

	dbus_timeout_set_data(timeout, handler, timeout_handler_free);

	return TRUE;
}

static void remove_timeout(DBusTimeout *timeout, void *data)
{

}

static void timeout_toggled(DBusTimeout *timeout, void *data)
{
	if (dbus_timeout_get_enabled(timeout))
		add_timeout(timeout, data);
	else
		remove_timeout(timeout, data);
}

static void dispatch_status_cb(DBusConnection *conn,
				DBusDispatchStatus new_status,
				void *data)
{
	if (!dbus_connection_get_is_connected(conn))
			return;

	if (new_status == DBUS_DISPATCH_DATA_REMAINS)
		g_timeout_add(DISPATCH_TIMEOUT, message_dispatch_cb, NULL);
}

int hcid_dbus_init(void)
{
	int ret_val;
	DBusError err;

	dbus_error_init(&err);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &err);

	if (dbus_error_is_set(&err)) {
		error("Can't open system message bus connection: %s", err.message);
		dbus_error_free(&err);
		return -1;
	}

	dbus_connection_set_exit_on_disconnect(connection, FALSE);

	ret_val = dbus_bus_request_name(connection, BASE_INTERFACE, 0, &err);

	if (ret_val != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER ) {
		error("Service could not become the primary owner.");
		return -1;
	}

	if (dbus_error_is_set(&err)) {
		error("Can't get system message bus name: %s", err.message);
		dbus_error_free(&err);
		return -1;
	}

	if (register_dbus_path(BASE_PATH, INVALID_DEV_ID, &obj_mgr_vtable, TRUE) < 0)
		return -1;

	if (!dbus_connection_add_filter(connection, hci_dbus_signal_filter, NULL, NULL)) {
		error("Can't add new HCI filter");
		return -1;
	}

	dbus_connection_set_watch_functions(connection,
			add_watch, remove_watch, watch_toggled, NULL, NULL);

	dbus_connection_set_timeout_functions(connection,
			add_timeout, remove_timeout, timeout_toggled, NULL, NULL);

	dbus_connection_set_dispatch_status_function(connection,
			dispatch_status_cb, NULL, NULL);

	return 0;
}

void hcid_dbus_exit(void)
{
	char **children = NULL;
	int i = 0;

	if (!dbus_connection_get_is_connected(connection))
		return;

	release_default_agent();

	/* Unregister all paths in Adapter path hierarchy */
	if (!dbus_connection_list_registered(connection, BASE_PATH, &children))
		goto done;

	for (; children[i]; i++) {
		char dev_path[MAX_PATH_LENGTH];

		snprintf(dev_path, sizeof(dev_path), "%s/%s", BASE_PATH, children[i]);

		unregister_dbus_path(dev_path);
	}

	dbus_free_string_array(children);

done:
	unregister_dbus_path(BASE_PATH);

	dbus_connection_close(connection);
}

/*****************************************************************
 *
 *  Section reserved to re-connection timer
 *
 *****************************************************************/

gboolean discoverable_timeout_handler(void *data)
{
	struct hci_dbus_data *dbus_data = data;
	struct hci_request rq;
	int dd = -1;
	uint8_t hci_mode = dbus_data->mode;
	uint8_t status = 0;
	gboolean retval = TRUE;

	hci_mode &= ~SCAN_INQUIRY;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		error("HCI device open failed: hci%d", dbus_data->dev_id);
		return TRUE;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_SCAN_ENABLE;
	rq.cparam = &hci_mode;
	rq.clen   = sizeof(hci_mode);
	rq.rparam = &status;
	rq.rlen   = sizeof(status);

	if (hci_send_req(dd, &rq, 100) < 0) {
		error("Sending write scan enable command to hci%d failed: %s (%d)",
				dbus_data->dev_id, strerror(errno), errno);
		goto failed;
	}
	if (status) {
		error("Setting scan enable failed with status 0x%02x", status);
		goto failed;
	}

	dbus_data->timeout_id = 0;
	retval = FALSE;

failed:
	if (dd >= 0)
		close(dd);

	return retval;
}

static gboolean system_bus_reconnect(void *data)
{
	struct hci_dev_list_req *dl = NULL;
	struct hci_dev_req *dr;
	int sk, i;
	gboolean ret_val = TRUE;

	if (dbus_connection_get_is_connected(connection))
		return FALSE;

	if (hcid_dbus_init() == FALSE)
		return TRUE;

	/* Create and bind HCI socket */
	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0) {
		error("Can't open HCI socket: %s (%d)",
							strerror(errno), errno);
		return TRUE;
	}

	dl = malloc(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));
	if (!dl) {
		error("Can't allocate memory");
		goto failed;
	}

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(sk, HCIGETDEVLIST, (void *) dl) < 0) {
		info("Can't get device list: %s (%d)",
			strerror(errno), errno);
		goto failed;
	}

	/* reset the default device */
	default_dev = -1;

	for (i = 0; i < dl->dev_num; i++, dr++)
		hcid_dbus_register_device(dr->dev_id);

	ret_val = FALSE;

failed:
	if (sk >= 0)
		close(sk);

	if (dl)
		free(dl);

	return ret_val;
}

/*****************************************************************
 *
 *  Section reserved to D-Bus signal/messages handling function
 *
 *****************************************************************/
static DBusHandlerResult hci_dbus_signal_filter(DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	const char *iface;
	const char *method;

	if (!msg || !conn)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_get_type (msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	iface = dbus_message_get_interface(msg);
	method = dbus_message_get_member(msg);

	if ((strcmp(iface, DBUS_INTERFACE_LOCAL) == 0) &&
			(strcmp(method, "Disconnected") == 0)) {
		error("Got disconnected from the system message bus");
		dbus_connection_unref(conn);
		g_timeout_add(RECONNECT_RETRY_TIMEOUT, system_bus_reconnect, NULL);
	}

	return ret;
}

/*****************************************************************
 *  
 *  Section reserved to device HCI callbacks
 *  
 *****************************************************************/
void hcid_dbus_setname_complete(bdaddr_t *local)
{
	DBusMessage *signal = NULL;
	char *local_addr;
	bdaddr_t tmp;
	int id;
	int dd = -1;
	read_local_name_rp rp;
	struct hci_request rq;
	const char *pname = (char *) rp.name;
	char name[249];

	baswap(&tmp, local); local_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto failed;
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

		if (hci_send_req(dd, &rq, 100) < 0) {
			error("Sending getting name command failed: %s (%d)",
						strerror(errno), errno);
			rp.name[0] = '\0';
		}

		if (rp.status) {
			error("Getting name failed with status 0x%02x", rp.status);
			rp.name[0] = '\0';
		}
	}

	strncpy(name, pname, sizeof(name) - 1);
	name[248] = '\0';
	pname = name;

	signal = dev_signal_factory(id, "NameChanged",
				DBUS_TYPE_STRING, &pname, DBUS_TYPE_INVALID);
	if (dbus_connection_send(connection, signal, NULL) == FALSE) {
		error("Can't send D-Bus name changed signal");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	if (signal)
		dbus_message_unref(signal);

	if (dd >= 0)
		close(dd);

	bt_free(local_addr);
}

void hcid_dbus_setscan_enable_complete(bdaddr_t *local)
{
	DBusMessage *message = NULL;
	struct hci_dbus_data *pdata;
	char *local_addr;
	char path[MAX_PATH_LENGTH];
	bdaddr_t tmp;
	read_scan_enable_rp rp;
	struct hci_request rq;
	int id;
	int dd = -1;
	const char *scan_mode;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	dd = hci_open_dev(id);
	if (dd < 0) {
		error("HCI device open failed: hci%d", id);
		goto failed;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_SCAN_ENABLE;
	rq.rparam = &rp;
	rq.rlen   = READ_SCAN_ENABLE_RP_SIZE;

	if (hci_send_req(dd, &rq, 100) < 0) {
		error("Sending read scan enable command failed: %s (%d)",
							strerror(errno), errno);
		goto failed;
	}

	if (rp.status) {
		error("Getting scan enable failed with status 0x%02x", rp.status);
		goto failed;
	}

	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		error("Getting %s path data failed!", path);
		goto failed;
	}
	
	/* update the current scan mode value */
	pdata->mode = rp.enable;

	if (pdata->timeout_id) {
		g_timeout_remove(pdata->timeout_id);
		pdata->timeout_id = 0;
	}

	switch (rp.enable) {
	case SCAN_DISABLED:
		scan_mode = MODE_OFF;
		break;
	case SCAN_PAGE:
		scan_mode = MODE_CONNECTABLE;
		break;
	case (SCAN_PAGE | SCAN_INQUIRY):
		scan_mode = MODE_DISCOVERABLE;
		if (pdata->discoverable_timeout != 0)
			pdata->timeout_id = g_timeout_add(pdata->discoverable_timeout * 1000,
							  discoverable_timeout_handler, pdata);
		break;
	case SCAN_INQUIRY:
		/* Address the scenario where another app changed the scan mode */
		if (pdata->discoverable_timeout != 0)
			pdata->timeout_id = g_timeout_add(pdata->discoverable_timeout * 1000,
							  discoverable_timeout_handler, pdata);
		/* ignore, this event should not be sent*/
	default:
		/* ignore, reserved */
		goto failed;
	}

	write_device_mode(local, scan_mode);

	message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						"ModeChanged");
	if (message == NULL) {
		error("Can't allocate D-Bus message");
		goto failed;
	}

	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &scan_mode,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		error("Can't send D-Bus mode changed signal");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	if (message)
		dbus_message_unref(message);

	if (dd >= 0)
		close(dd);

	bt_free(local_addr);
}

void hcid_dbus_pin_code_reply(bdaddr_t *local, void *ptr)
{

	typedef struct {
		uint8_t status;
		bdaddr_t bdaddr;
	} __attribute__ ((packed)) ret_pin_code_req_reply;

	struct hci_dbus_data *pdata;
	char *local_addr;
	ret_pin_code_req_reply *ret = ptr + EVT_CMD_COMPLETE_SIZE;
	struct slist *l;
	char path[MAX_PATH_LENGTH];
	bdaddr_t tmp;
	int id;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		error("Getting %s path data failed!", path);
		goto failed;
	}

	l = slist_find(pdata->pin_reqs, &ret->bdaddr, pin_req_cmp);
	if (l) {
		struct pending_pin_info *p = l->data;
		p->replied = 1;
	}

failed:
	bt_free(local_addr);
}

void create_bond_req_exit(const char *name, struct hci_dbus_data *pdata)
{
	char path[MAX_PATH_LENGTH];
	struct slist *l;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, pdata->dev_id);

	debug("CreateConnection requestor at %s exited before bonding was completed", name);

	cancel_passkey_agent_requests(pdata->passkey_agents, path, &pdata->bonding->bdaddr);
	release_passkey_agents(pdata, &pdata->bonding->bdaddr);

	l = slist_find(pdata->pin_reqs, &pdata->bonding->bdaddr, pin_req_cmp);
	if (l) {
		struct pending_pin_info *p = l->data;

		if (!p->replied) {
			int dd;

			dd = hci_open_dev(pdata->dev_id);
			if (dd >= 0) {
				hci_send_cmd(dd, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY,
						6, &pdata->bonding->bdaddr);
				hci_close_dev(dd);
			}
		}

		pdata->pin_reqs = slist_remove(pdata->pin_reqs, p);
		free(p);
	}

	g_io_channel_close(pdata->bonding->io);
	if (pdata->bonding->io_id)
		g_io_remove_watch(pdata->bonding->io_id);
	bonding_request_free(pdata->bonding);
	pdata->bonding = NULL;
}

void discover_devices_req_exit(const char *name, struct hci_dbus_data *pdata)
{
	debug("DiscoverDevices requestor at %s exited before the operation finished", name);

	/* 
	 * Cleanup the discovered devices list and send the command to
	 * cancel inquiry or cancel remote name request. The return
	 * can be ignored.
	 */
	cancel_discovery(pdata);
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

int cancel_discovery(struct hci_dbus_data *pdata)
{
	struct discovered_dev_info *dev, match;
	struct slist *l;
	int dd, err = 0;

	if (!pdata->disc_active)
		goto cleanup;

	dd = hci_open_dev(pdata->dev_id);
	if (dd < 0) {
		err = -ENODEV;
		goto cleanup;
	}

	/* 
	 * If there is a pending read remote name request means
	 * that the inquiry complete event was already received
	 */
	memset(&match, 0, sizeof(struct discovered_dev_info));
	bacpy(&match.bdaddr, BDADDR_ANY);
	match.name_status = NAME_REQUESTED;

	l = slist_find(pdata->disc_devices, &match,
				(cmp_func_t) disc_device_find);
	if (l) {
		dev = l->data;
		if (remote_name_cancel(dd, &dev->bdaddr, 100) < 0) {
			error("Read remote name cancel failed: %s, (%d)",
						strerror(errno), errno);
			err = -errno;
		}
	} else {
		if (inquiry_cancel(dd, 100) < 0) {
			error("Inquiry cancel failed:%s (%d)",
						strerror(errno), errno);
			err = -errno;
		}
	}

	hci_close_dev(dd);

cleanup:
	/*
	 * Reset discovery_requestor and discover_state in the remote name
	 * request event handler or in the inquiry complete handler.
	 */
	slist_foreach(pdata->disc_devices, (slist_func_t) free, NULL);
	slist_free(pdata->disc_devices);
	pdata->disc_devices = NULL;

	/* Disable name resolution for non D-Bus clients */
	if (!pdata->pdiscovery_requestor)
		pdata->discover_type &= ~RESOLVE_NAME;

	return err;
}

void periodic_discover_req_exit(const char *name, struct hci_dbus_data *pdata)
{
	debug("Periodic Discover  requestor at %s exited before the operation finishes", name);

	/* 
	 * Cleanup the discovered devices list and send the cmd to exit from periodic inquiry
	 * or cancel remote name request. The return value can be ignored.
	 */

	cancel_periodic_discovery(pdata);
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

int cancel_periodic_discovery(struct hci_dbus_data *pdata)
{
	struct discovered_dev_info *dev, match;
	struct slist *l;
	int dd, err = 0;
	
	if (!pdata->pdisc_active)
		goto cleanup;

	dd = hci_open_dev(pdata->dev_id);
	if (dd < 0) {
		err = -ENODEV;
		goto cleanup;
	}
	/* find the pending remote name request */
	memset(&match, 0, sizeof(struct discovered_dev_info));
	bacpy(&match.bdaddr, BDADDR_ANY);
	match.name_status = NAME_REQUESTED;

	l = slist_find(pdata->disc_devices, &match, (cmp_func_t) disc_device_find);
	if (l) {
		dev = l->data;
		if (remote_name_cancel(dd, &dev->bdaddr, 100) < 0) {
			error("Read remote name cancel failed: %s, (%d)", strerror(errno), errno);
			err = -errno;
		}
	}

	/* ovewrite err if necessary: stop periodic inquiry has higher priority */
	if (periodic_inquiry_exit(dd, 100) < 0) {
		error("Periodic Inquiry exit failed:%s (%d)", strerror(errno), errno);
		err = -errno;
	}

	hci_close_dev(dd);
cleanup:
	/*
	 * Reset pdiscovery_requestor and pdisc_active is done when the
	 * cmd complete event for exit periodic inquiry mode cmd arrives.
	 */
	slist_foreach(pdata->disc_devices, (slist_func_t) free, NULL);
	slist_free(pdata->disc_devices);
	pdata->disc_devices = NULL;

	return err;
}
