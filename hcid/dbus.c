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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
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

#define MAX_CONN_NUMBER			10
#define RECONNECT_RETRY_TIMEOUT		5000

void disc_device_info_free(void *data, void *user_data)
{
	struct discovered_dev_info *dev = data;

	if (dev)
		free(dev);
}

void bonding_request_free(struct bonding_request_info *dev )
{
	if (dev) {
		if (dev->rq)
			dbus_message_unref(dev->rq);
		if (dev->cancel)
			dbus_message_unref(dev->cancel);
		free(dev);
	}
}

static void active_conn_info_free(void *data, void *user_data)
{
	struct active_conn_info *dev = data;

	if (dev)
		free(dev);
}

static int disc_device_find_by_bdaddr(const void *data, const void *user_data)
{
	const struct discovered_dev_info *dev = data;
	const bdaddr_t *bdaddr = user_data;

	return bacmp(&dev->bdaddr, bdaddr);
}

static int disc_device_find_by_name_status(const void *data, const void *user_data)
{
	const struct discovered_dev_info *dev = data;
	const name_status_t *name_status = user_data;

	if (dev->name_status == *name_status)
		return 0;

	return -1;
}

int disc_device_append(struct slist **list, bdaddr_t *bdaddr, name_status_t name_status)
{
	struct discovered_dev_info *dev = NULL;
	struct slist *l;

	/* ignore repeated entries */
	l = slist_find(*list, bdaddr, disc_device_find_by_bdaddr);

	if (l) {
		/* device found, update the attributes */
		dev = l->data;
		dev->name_status = name_status;
		return -1;
	}

	dev = malloc(sizeof(*dev));
	if (!dev)
		return -1;

	memset(dev, 0, sizeof(*dev));
	bacpy(&dev->bdaddr, bdaddr);
	dev->name_status = name_status;

	*list = slist_append(*list, dev);

	return 0;
}

static int disc_device_remove(struct slist **list, bdaddr_t *bdaddr)
{
	struct discovered_dev_info *dev;
	struct slist *l;
	int ret_val = -1;

	l = slist_find(*list, bdaddr, disc_device_find_by_bdaddr);

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
	struct active_conn_info *dev = NULL;

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
	case 0x06: /* pin missing */
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

static gboolean register_dbus_path(const char *path, uint16_t dev_id,
				const DBusObjectPathVTable *pvtable, gboolean fallback)
{
	gboolean ret = FALSE;
	struct hci_dbus_data *data = NULL;

	info("Register path:%s fallback:%d", path, fallback);

	data = malloc(sizeof(struct hci_dbus_data));
	if (data == NULL) {
		error("Failed to alloc memory to DBUS path register data (%s)", path);
		goto failed;
	}

	memset(data, 0, sizeof(struct hci_dbus_data));

	data->dev_id = dev_id;
	data->mode = SCAN_DISABLED;
	data->discoverable_timeout = get_discoverable_timeout(dev_id);

	if (fallback) {
		if (!dbus_connection_register_fallback(connection, path, pvtable, data)) {
			error("D-Bus failed to register %s fallback", path);
			goto failed;
		}
	} else {
		if (!dbus_connection_register_object_path(connection, path, pvtable, data)) {
			error("D-Bus failed to register %s object", path);
			goto failed;
		}
	}

	ret = TRUE;

failed:
	if (!ret && data)
		free(data);

	return ret;
}

static gboolean unregister_dbus_path(const char *path)
{
	struct hci_dbus_data *pdata;

	info("Unregister path:%s", path);

	if (dbus_connection_get_object_path_data(connection, path, (void *) &pdata) && pdata) {
		if (pdata->requestor_name)
			free(pdata->requestor_name);

		if (pdata->disc_devices) {
			slist_foreach(pdata->disc_devices, disc_device_info_free, NULL);
			slist_free(pdata->disc_devices);
			pdata->disc_devices = NULL;
		}

		if (pdata->bonding) {
			bonding_request_free(pdata->bonding);
			pdata->bonding = NULL;
		}

		if (pdata->active_conn) {
			slist_foreach(pdata->active_conn, active_conn_info_free, NULL);
			slist_free(pdata->active_conn);
			pdata->active_conn = NULL;
		}

		free (pdata);
	}

	if (!dbus_connection_unregister_object_path (connection, path)) {
		error("D-Bus failed to unregister %s object", path);
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

gboolean hcid_dbus_register_device(uint16_t id)
{
	char path[MAX_PATH_LENGTH];
	char *pptr = path;
	gboolean ret = FALSE;
	DBusMessage *message = NULL;
	int i, err, dd = -1;
	read_scan_enable_rp rp;
	struct hci_request rq;
	struct hci_dbus_data* pdata;
	struct hci_conn_list_req *cl = NULL;
	struct hci_conn_info *ci = NULL;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);
	if (!register_dbus_path(path, id, &obj_dev_vtable, FALSE))
		return FALSE;

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

	pdata->mode = rp.enable;	/* Keep the current scan status */

	/*
	 * Get the adapter Bluetooth address
	 */
	err = get_device_address(pdata->dev_id, pdata->address, sizeof(pdata->address));
	if (err < 0)
		goto failed;

	/*
	 * Send the adapter added signal
	 */
	message = dbus_message_new_signal(BASE_PATH, MANAGER_INTERFACE,
							"AdapterAdded");
	if (message == NULL) {
		error("Can't allocate D-Bus message");
		goto failed;
	}

	/*FIXME: append a friendly name instead of device path */
	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &pptr,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send(connection, message, NULL)) {
		error("Can't send D-BUS adapter added message");
		goto failed;
	}

	dbus_connection_flush(connection);
	
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
		active_conn_append(&pdata->active_conn, &ci->bdaddr, ci->handle);

	ret = TRUE;

failed:
	if (!ret)
		dbus_connection_unregister_object_path(connection, path);

	if (message)
		dbus_message_unref(message);

	if (ret && default_dev < 0)
		default_dev = id;

	if (dd >= 0)
		close(dd);

	if (cl)
		free(cl);

	return ret;
}

gboolean hcid_dbus_unregister_device(uint16_t id)
{
	gboolean ret;
	DBusMessage *message = NULL;
	char path[MAX_PATH_LENGTH];
	char *pptr = path;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	message = dbus_message_new_signal(BASE_PATH, MANAGER_INTERFACE,
							"AdapterRemoved");
	if (message == NULL) {
		error("Can't allocate D-Bus message");
		goto failed;
	}

	/*FIXME: append a friendly name instead of device path */
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

	if (ret && default_dev == id)
		default_dev = hci_get_route(NULL);

	return ret;
}

void hcid_dbus_request_pin(int dev, bdaddr_t *sba, struct hci_conn_info *ci)
{
	char path[MAX_PATH_LENGTH], addr[18];

	ba2str(sba, addr);

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, hci_devid(addr));

	handle_passkey_request(connection, dev, path, sba, &ci->bdaddr);
}

void hcid_dbus_bonding_process_complete(bdaddr_t *local, bdaddr_t *peer, const uint8_t status)
{
	struct hci_dbus_data *pdata;
	DBusMessage *message = NULL;
	char *local_addr, *peer_addr;
	const char *name;
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

	/* Don't send any signals if a pairing process isn't active */
	if (!pdata->pairing_active)
		return;

	pdata->pairing_active = 0;

	/*
	 * 0x00: authentication request successfully completed
	 * 0x01-0x0F: authentication request failed
	 */
	name = status ? "BondingFailed" : "BondingCreated";
	/* authentication signal */
	message = dev_signal_factory(pdata->dev_id, name,
					DBUS_TYPE_STRING, &peer_addr,
					DBUS_TYPE_INVALID);

	send_reply_and_unref(connection, message);

	if (!pdata->bonding)
		goto failed; /* skip: no bonding req pending */

	if (pdata->bonding->disconnect) {
		struct slist *l;

		l = slist_find(pdata->active_conn, peer, active_conn_find_by_bdaddr);
		if (l) {
			struct active_conn_info *con = l->data;
			struct hci_req_data *data;
			disconnect_cp cp;
			memset(&cp, 0, sizeof(cp));

			cp.handle = con->handle;
			cp.reason = HCI_OE_USER_ENDED_CONNECTION;

			data = hci_req_data_new(pdata->dev_id, peer, OGF_LINK_CTL,
						OCF_DISCONNECT, EVT_DISCONN_COMPLETE,
						&cp, DISCONNECT_CP_SIZE);
			hci_req_queue_append(data);
		}
	}

	message = dbus_msg_new_authentication_return(pdata->bonding->rq, status);
	send_reply_and_unref(connection, message);

	bonding_request_free(pdata->bonding);
	pdata->bonding = NULL;

	free(pdata->requestor_name);
	pdata->requestor_name = NULL;

failed:
	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_create_conn_cancel(bdaddr_t *local, void *ptr)
{
	typedef struct {
		uint8_t status;
		bdaddr_t bdaddr;
	}__attribute__ ((packed)) ret_param_conn_cancel;

	char path[MAX_PATH_LENGTH];
	bdaddr_t tmp;
	ret_param_conn_cancel *ret = ptr + sizeof(evt_cmd_complete);
	DBusMessage *reply;
	char *local_addr, *peer_addr;
	struct hci_dbus_data *pdata;
	int id;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, &ret->bdaddr); peer_addr = batostr(&tmp);

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

	if (!pdata->bonding)
		goto failed;

	if (bacmp(&pdata->bonding->bdaddr, &ret->bdaddr))
		goto failed;
	
	if (!ret->status) {
		reply = dbus_message_new_method_return(pdata->bonding->cancel);
		send_reply_and_unref(connection, reply);
	} else
		error_failed(connection, pdata->bonding->cancel, bt_error(ret->status));	

	dbus_message_unref(pdata->bonding->cancel);
	pdata->bonding->cancel = NULL;

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

	if (dbus_connection_get_object_path_data(connection, path, (void *) &pdata))
		pdata->discover_state = STATE_DISCOVER;

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
	dbus_message_unref(message);
	bt_free(local_addr);
}

int disc_device_req_name(struct hci_dbus_data *dbus_data)
{
	struct hci_request rq;
	evt_cmd_status rp;
	remote_name_req_cp cp;
	bdaddr_t tmp;
	struct discovered_dev_info *dev;
	DBusMessage *message = NULL;
	struct slist *l = NULL;
	char *peer_addr = NULL;
	int dd, req_sent, ret_val = 0;
	name_status_t name_status = NAME_PENDING;

	/*get the next remote address */
	if (!dbus_data->disc_devices)
		return -1;

	l = slist_find(dbus_data->disc_devices, &name_status, disc_device_find_by_name_status);

	if (!l)
		return -1;

	dev = l->data;
	if (!dev)
		return -1;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0)
		return -1;

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
		req_sent = 1;

		memset(&cp, 0, sizeof(cp));
		bacpy(&cp.bdaddr, &dev->bdaddr);
		cp.pscan_rep_mode = 0x02;

		baswap(&tmp, &dev->bdaddr); peer_addr = batostr(&tmp);

		if (hci_send_req(dd, &rq, 100) < 0) {
			error("Unable to send the HCI remote name request: %s (%d)",
				strerror(errno), errno);
			message = dev_signal_factory(dbus_data->dev_id, "RemoteNameFailed",
							DBUS_TYPE_STRING, &peer_addr,
							DBUS_TYPE_INVALID);
			req_sent = 0;
		}

		if (rp.status) {
			error("Remote name request failed with status 0x%02x", rp.status);
			message = dev_signal_factory(dbus_data->dev_id, "RemoteNameFailed",
							DBUS_TYPE_STRING, &peer_addr,
							DBUS_TYPE_INVALID);
			req_sent = 0;
		}

		send_reply_and_unref(connection, message);

		free(peer_addr);

		/* if failed, request the next element */
		if (!req_sent) {
			/* remove the element from the list */
			dbus_data->disc_devices = slist_remove(dbus_data->disc_devices, dev);
			free(dev);

			/* get the next element */
			l = slist_find(dbus_data->disc_devices, &name_status, disc_device_find_by_name_status);

			if (!l) {
				/* no more devices: exit */
				ret_val = -1;
				goto failed;
			}

			dev = l->data;
		}
	} while (!req_sent);

failed:
	hci_close_dev(dd);

	return ret_val;
}

void hcid_dbus_inquiry_complete(bdaddr_t *local)
{
	DBusMessage *message = NULL;
	struct hci_dbus_data *pdata = NULL;
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

		if (pdata->discover_type == RESOLVE_NAMES) {
			if (!disc_device_req_name(pdata)) {
				pdata->discover_state = STATE_RESOLVING_NAMES;
				goto failed; /* skip - there is name to resolve */
			}
		}
		pdata->discover_state = STATE_IDLE;

		/* free discovered devices list */
		slist_foreach(pdata->disc_devices, disc_device_info_free, NULL);
		slist_free(pdata->disc_devices);
		pdata->disc_devices = NULL;

		if (pdata->requestor_name) {
			free(pdata->requestor_name);
			pdata->requestor_name = NULL;
		}
	}

	message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						"DiscoveryCompleted");
	if (message == NULL) {
		error("Can't allocate D-Bus message");
		goto failed;
	}

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		error("Can't send D-Bus inquiry complete message");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	if (message)
		dbus_message_unref(message);
	bt_free(local_addr);
}

static void append_class_string(const char *class, DBusMessageIter *iter)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &class);
}

void hcid_dbus_inquiry_result(bdaddr_t *local, bdaddr_t *peer, uint32_t class, int8_t rssi)
{
	char filename[PATH_MAX + 1];
	DBusMessage *signal_device = NULL;
	DBusMessage *signal_name = NULL;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	char path[MAX_PATH_LENGTH];
	struct hci_dbus_data *pdata = NULL;
	struct slist *l = NULL;
	struct discovered_dev_info *dev;
	char *local_addr, *peer_addr, *name = NULL;
	const char *major_ptr, *minor_ptr;
	struct slist *service_classes;
	const dbus_int16_t tmp_rssi = rssi;
	bdaddr_t tmp;
	int id;
	name_status_t name_status = NAME_PENDING;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, peer); peer_addr = batostr(&tmp);

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

	write_remote_class(local, peer, class);

	/* send the device found signal */
	signal_device = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						"RemoteDeviceFound");
	if (signal_device == NULL) {
		error("Can't allocate D-Bus message");
		goto failed;
	}

	major_ptr = major_class_str(class);
	minor_ptr = minor_class_str(class);

	dbus_message_iter_init_append(signal_device, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &peer_addr);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT16, &tmp_rssi);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &major_ptr);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &minor_ptr);

	service_classes = service_classes_str(class);

	/* add the service classes */
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
	 					DBUS_TYPE_STRING_AS_STRING, &array_iter);

	slist_foreach(service_classes, (slist_func_t)append_class_string, &array_iter);

	dbus_message_iter_close_container(&iter, &array_iter);

	slist_free(service_classes);

	if (dbus_connection_send(connection, signal_device, NULL) == FALSE) {
		error("Can't send D-Bus remote device found signal");
		goto failed;
	}

	/* send the remote name signal */
	l = slist_find(pdata->disc_devices, peer, disc_device_find_by_bdaddr);

	if (l) {
		dev = l->data;
		if (dev->name_status == NAME_SENT)
			goto failed; /* don't sent the name again */
	}

	snprintf(filename, PATH_MAX, "%s/%s/names", STORAGEDIR, local_addr);
	name = textfile_get(filename, peer_addr);

	if (name) {
		signal_name = dev_signal_factory(pdata->dev_id, "RemoteNameUpdated",
							DBUS_TYPE_STRING, &peer_addr,
							DBUS_TYPE_STRING, &name,
							DBUS_TYPE_INVALID);
		send_reply_and_unref(connection, signal_name);

		free(name);
		name_status = NAME_SENT;
	} 
	/* queue only results triggered by D-Bus clients */
	if (pdata->requestor_name)
		disc_device_append(&pdata->disc_devices, peer, name_status);


	disc_device_append(&pdata->disc_devices, peer, name_status);

failed:
	if (signal_device)
		dbus_message_unref(signal_device);

	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_remote_name(bdaddr_t *local, bdaddr_t *peer, uint8_t status, char *name)
{
	struct hci_dbus_data *pdata = NULL;
	DBusMessage *message = NULL;
	char path[MAX_PATH_LENGTH];
	char *local_addr, *peer_addr;
	bdaddr_t tmp;
	int id;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, peer); peer_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, id);

	/* remove from remote name request list */
	if (dbus_connection_get_object_path_data(connection, path, (void *) &pdata))
		disc_device_remove(&pdata->disc_devices, peer);

	/* if the requested name failed, don't send signal and request the next name */
	if (status)
		message = dev_signal_factory(pdata->dev_id, "RemoteNameFailed",
						DBUS_TYPE_STRING, &peer_addr,
						DBUS_TYPE_INVALID);
	else 
		message = dev_signal_factory(pdata->dev_id, "RemoteNameUpdated",
					     	DBUS_TYPE_STRING, &peer_addr,
						DBUS_TYPE_STRING, &name,
						DBUS_TYPE_INVALID);

	send_reply_and_unref(connection, message);

	/* check if there is more devices to request names */
	if (!disc_device_req_name(pdata))
		goto failed; /* skip if a new request has been sent */

	/* free discovered devices list */
	slist_foreach(pdata->disc_devices, disc_device_info_free, NULL);
	slist_free(pdata->disc_devices);
	pdata->disc_devices = NULL;

	if (pdata->discover_state == STATE_RESOLVING_NAMES ) {
		message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						  "DiscoveryCompleted");

		send_reply_and_unref(connection, message);

		if (pdata->requestor_name) {
			free(pdata->requestor_name);
			pdata->requestor_name = NULL;
		}
	}

	pdata->discover_state = STATE_IDLE;

failed:
	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_conn_complete(bdaddr_t *local, uint8_t status, uint16_t handle, bdaddr_t *peer)
{
	char path[MAX_PATH_LENGTH];
	DBusMessage *message = NULL;
	struct hci_request rq;
	evt_cmd_status rp;
	auth_requested_cp cp;
	struct hci_dbus_data *pdata = NULL;
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

	/* check if this connection request was requested by a bonding procedure */
	if (!pdata->bonding)
		goto done; /* skip */

	if (bacmp(&pdata->bonding->bdaddr, peer))
		goto done; /* skip */

	if (status) {
		error_connection_attempt_failed(connection, pdata->bonding->rq, bt_error(status));
		goto bonding_failed;
	}

	dd = hci_open_dev(pdata->dev_id);
	if (dd < 0) {
		error_no_such_adapter(connection, pdata->bonding->rq);
		goto bonding_failed;
	}

	/* request authentication */
	memset(&rq, 0, sizeof(rq));
	memset(&rp, 0, sizeof(rp));
	memset(&cp, 0, sizeof(cp));

	cp.handle = handle;

	rq.ogf    = OGF_LINK_CTL;
	rq.event  = EVT_CMD_STATUS;
	rq.rparam = &rp;
	rq.rlen   = EVT_CMD_STATUS_SIZE;
	rq.ocf    = OCF_AUTH_REQUESTED;
	rq.cparam = &cp;
	rq.clen   = AUTH_REQUESTED_CP_SIZE;

	if (hci_send_req(dd, &rq, 100) < 0) {
		error("Unable to send the HCI request: %s (%d)",
				strerror(errno), errno);
		error_failed(connection, pdata->bonding->rq, errno);
		goto bonding_failed;
	}

	if (rp.status) {
		error("Failed with status 0x%02x", rp.status);
		error_failed(connection, pdata->bonding->rq, bt_error(rp.status));
		goto bonding_failed;
	}

	goto done; /* skip: authentication requested */

bonding_failed:
	/* free bonding request if the HCI pairing request was not sent */
	bonding_request_free(pdata->bonding);
	pdata->bonding = NULL;
	free(pdata->requestor_name);
	pdata->requestor_name = NULL;

done:
	hci_close_dev(dd);

	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_disconn_complete(bdaddr_t *local, uint8_t status, uint16_t handle, uint8_t reason)
{
	char path[MAX_PATH_LENGTH];
	struct hci_dbus_data *pdata = NULL;
	struct active_conn_info *dev;
	DBusMessage *message;
	struct slist *l;
	char *local_addr, *peer_addr = NULL;
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

	l = slist_find(pdata->active_conn, &handle, active_conn_find_by_handle);

	if (!l)
		goto failed;

	dev = l->data;

	baswap(&tmp, &dev->bdaddr); peer_addr = batostr(&tmp);

	/* clean pending HCI cmds */
	hci_req_queue_remove(pdata->dev_id, &dev->bdaddr);

	/* Check if there is a pending Bonding */
	if (pdata->bonding) {
		message = dev_signal_factory(pdata->dev_id, "BondingFailed",
						DBUS_TYPE_STRING, &peer_addr,
						DBUS_TYPE_INVALID);

		send_reply_and_unref(connection, message);

		message = dbus_msg_new_authentication_return(pdata->bonding->rq, status);
		send_reply_and_unref(connection, message);

		bonding_request_free(pdata->bonding);
		pdata->bonding = NULL;

		free(pdata->requestor_name);
		pdata->requestor_name = NULL;
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
static gboolean watch_func(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	DBusWatch *watch = (DBusWatch *) data;
	int flags = 0;

	if (cond & G_IO_IN)  flags |= DBUS_WATCH_READABLE;
	if (cond & G_IO_OUT) flags |= DBUS_WATCH_WRITABLE;
	if (cond & G_IO_HUP) flags |= DBUS_WATCH_HANGUP;
	if (cond & G_IO_ERR) flags |= DBUS_WATCH_ERROR;

	dbus_watch_handle(watch, flags);

	dbus_connection_ref(connection);

	/* Dispatch messages */
	while (dbus_connection_dispatch(connection) == DBUS_DISPATCH_DATA_REMAINS);

	dbus_connection_unref(connection);

	return TRUE;
}

static dbus_bool_t add_watch(DBusWatch *watch, void *data)
{
	GIOCondition cond = G_IO_HUP | G_IO_ERR;
	GIOChannel *io;
	guint *id;
	int fd, flags;

	if (!dbus_watch_get_enabled(watch))
		return TRUE;

	id = malloc(sizeof(guint));
	if (id == NULL)
		return FALSE;

	fd = dbus_watch_get_fd(watch);
	io = g_io_channel_unix_new(fd);
	flags = dbus_watch_get_flags(watch);

	if (flags & DBUS_WATCH_READABLE) cond |= G_IO_IN;
	if (flags & DBUS_WATCH_WRITABLE) cond |= G_IO_OUT;

	*id = g_io_add_watch(io, cond, watch_func, watch);

	dbus_watch_set_data(watch, id, NULL);

	return TRUE;
}

static void remove_watch(DBusWatch *watch, void *data)
{
	guint *id = dbus_watch_get_data(watch);

	dbus_watch_set_data(watch, NULL, NULL);

	if (id) {
		g_io_remove_watch(*id);
		free(id);
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

gboolean hcid_dbus_init(void)
{
	int ret_val;
	DBusError err;

	dbus_error_init(&err);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &err);

	if (dbus_error_is_set(&err)) {
		error("Can't open system message bus connection: %s", err.message);
		dbus_error_free(&err);
		return FALSE;
	}

	dbus_connection_set_exit_on_disconnect(connection, FALSE);

	ret_val = dbus_bus_request_name(connection, BASE_INTERFACE, 0, &err);

	if (ret_val != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER ) {
		error("Service could not become the primary owner.");
		return FALSE;
	}

	if (dbus_error_is_set(&err)) {
		error("Can't get system message bus name: %s", err.message);
		dbus_error_free(&err);
		return FALSE;
	}

	if (!register_dbus_path(BASE_PATH, INVALID_DEV_ID, &obj_mgr_vtable, TRUE))
		return FALSE;

	if (!dbus_connection_add_filter(connection, hci_dbus_signal_filter, NULL, NULL)) {
		error("Can't add new HCI filter");
		return FALSE;
	}

	dbus_connection_set_watch_functions(connection,
			add_watch, remove_watch, watch_toggled, NULL, NULL);

	return TRUE;
}

void hcid_dbus_exit(void)
{
	char **children = NULL;
	int i = 0;

	if (!dbus_connection_get_is_connected(connection))
		return;

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

int discoverable_timeout_handler(void *data)
{
	struct hci_dbus_data *dbus_data = data;
	struct hci_request rq;
	int dd = -1;
	uint8_t hci_mode = dbus_data->mode;
	uint8_t status = 0;
	int8_t retval = 0;

	hci_mode &= ~SCAN_INQUIRY;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		error("HCI device open failed: hci%d", dbus_data->dev_id);
		return 0;
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
	retval = -1;

failed:
	if (dd >= 0)
		close(dd);

	return retval;
}

static int system_bus_reconnect(void *data)
{
	struct hci_dev_list_req *dl = NULL;
	struct hci_dev_req *dr;
	int sk, i, ret_val = 0;

	if (dbus_connection_get_is_connected(connection))
		return -1;

	if (hcid_dbus_init() == FALSE)
		return 0;

	/* Create and bind HCI socket */
	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0) {
		error("Can't open HCI socket: %s (%d)",
							strerror(errno), errno);
		return 0;
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

	ret_val = -1;

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
	const char *pname = (char*) rp.name;
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
	struct hci_dbus_data *pdata = NULL;
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
