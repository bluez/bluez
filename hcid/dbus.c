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
#include <signal.h>
#include <string.h>
#include <sys/time.h>
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
static volatile sig_atomic_t __timeout_active = 0;

#define MAX_CONN_NUMBER			10

static const char *services_cls[] = {
	"positioning",
	"networking",
	"rendering",
	"capturing",
	"object transfer",
	"audio",
	"telephony",
	"information"
};

static const char *major_cls[] = {
	"miscellaneous",
	"computer",
	"phone",
	"access point",
	"audio/video",
	"peripheral",
	"imaging",
	"wearable",
	"toy",
	"uncategorized"
};

static const char *computer_minor_cls[] = {
	"uncategorized",
	"desktop",
	"server",
	"laptop",
	"handheld",
	"palm",
	"wearable"
};

static const char *phone_minor_cls[] = {
	"uncategorized",
	"cellular",
	"cordless",
	"smart phone",
	"modem",
	"isdn"
};


void discovered_device_free(void *data, void *user_data)
{
	struct discovered_dev_info *dev = data;

	if (dev) {
		free(dev->bdaddr);
		free(dev);
	}
}

int bonding_requests_find(const void *data, const void *user_data)
{
	const struct bonding_request_info *dev = data;
	const bdaddr_t *bdaddr = user_data;

	if (memcmp(dev->bdaddr, bdaddr, sizeof(*bdaddr)) == 0)
		return 0;

	return -1;
}

int remote_name_find_by_bdaddr(const void *data, const void *user_data)
{
	const struct discovered_dev_info *dev = data;
	const bdaddr_t *bdaddr = user_data;

	if (memcmp(dev->bdaddr, bdaddr, sizeof(*bdaddr)) == 0)
		return 0;

	return -1;
}

static int remote_name_find_by_name_status(const void *data, const void *user_data)
{
	const struct discovered_dev_info *dev = data;
	const name_status_t *name_status = user_data;

	if (dev->name_status == *name_status)
		return 0;

	return -1;
}

int remote_name_append(struct slist **list, bdaddr_t *bdaddr, name_status_t name_status)
{
	struct discovered_dev_info *dev = NULL;
	struct slist *l;

	/* ignore repeated entries */
	l = slist_find(*list, bdaddr, remote_name_find_by_bdaddr);

	if (l) {
		/* device found, update the attributes */
		dev = l->data;
		dev->name_status = name_status;
		return -1;
	}

	dev = malloc(sizeof(*dev));
	if (!dev)
		return -1;

	dev->bdaddr = malloc(sizeof(*dev->bdaddr));
	bacpy(dev->bdaddr, bdaddr);
	dev->name_status = name_status;

	*list = slist_append(*list, dev);
	return 0;
}

static int remote_name_remove(struct slist **list, bdaddr_t *bdaddr)
{
	struct discovered_dev_info *dev;
	struct slist *l;
	int ret_val = -1;

	l = slist_find(*list, bdaddr, remote_name_find_by_bdaddr);

	if (l) {
		dev = l->data;
		*list = slist_remove(*list, dev);
		free(dev->bdaddr);
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

/*
 * Timeout functions Protypes
 */
static int discoverable_timeout_handler(void *data);

DBusConnection *get_dbus_connection(void)
{
	return connection;
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

	snprintf(path, sizeof(path)-1, "%s/hci%d", ADAPTER_PATH, devid);

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

static gboolean register_dbus_path(const char *path, uint16_t path_id, uint16_t dev_id,
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

	data->path_id = path_id;
	data->dev_id = dev_id;
	data->mode = SCAN_DISABLED;
	data->discoverable_timeout = DFT_DISCOVERABLE_TIMEOUT;

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
	struct hci_dbus_data *data;

	info("Unregister path:%s", path);

	if (dbus_connection_get_object_path_data(connection, path, (void *) &data) && data) {
		if (data->requestor_name)
			free(data->requestor_name);
		free(data);
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
	gboolean ret;
	DBusMessage *message = NULL;
	int dd = -1;
	read_scan_enable_rp rp;
	struct hci_request rq;
	struct hci_dbus_data* pdata;

	snprintf(path, sizeof(path), "%s/hci%d", ADAPTER_PATH, id);
	ret = register_dbus_path(path, ADAPTER_PATH_ID, id, &obj_dev_vtable, FALSE);

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

	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata))
		error("Getting path data failed!");
	else
		pdata->mode = rp.enable;	/* Keep the current scan status */

	/* 
	 * Enable timeout to address dbus daemon restart, where
	 * register the device paths is required due connection lost.
	 */
	if (pdata->mode & SCAN_INQUIRY)
		pdata->timeout_handler = &discoverable_timeout_handler;

	message = dbus_message_new_signal(MANAGER_PATH, MANAGER_INTERFACE,
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

failed:
	if (message)
		dbus_message_unref(message);

	if (ret && default_dev < 0)
		default_dev = id;

	if (dd >= 0)
		close(dd);

	return ret;
}

gboolean hcid_dbus_unregister_device(uint16_t id)
{
	gboolean ret;
	DBusMessage *message = NULL;
	char path[MAX_PATH_LENGTH];
	char *pptr = path;

	snprintf(path, sizeof(path), "%s/hci%d", ADAPTER_PATH, id);

	message = dbus_message_new_signal(MANAGER_PATH, MANAGER_INTERFACE,
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

	snprintf(path, sizeof(path), "%s/hci%d", ADAPTER_PATH, hci_devid(addr));

	handle_passkey_request(dev, path, sba, &ci->bdaddr);
}

void hcid_dbus_bonding_created_complete(bdaddr_t *local, bdaddr_t *peer, const uint8_t status)
{
	struct hci_dbus_data *pdata;
	DBusMessage *msg_reply = NULL;
	DBusMessage *msg_signal = NULL;
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

	snprintf(path, sizeof(path), "%s/hci%d", ADAPTER_PATH, id);

	/*
	 * 0x00: authentication request successfully completed
	 * 0x01-0x0F: authentication request failed
	 */
	name = status ? "BondingFailed" : "BondingCreated";
	/* authentication signal */
	msg_signal = dbus_message_new_signal(path, ADAPTER_INTERFACE, name);

	if (msg_signal == NULL) {
		error("Can't allocate D-Bus message");
		goto failed;
	}

	dbus_message_append_args(msg_signal,
					DBUS_TYPE_STRING, &peer_addr,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send(connection, msg_signal, NULL) == FALSE) {
		error("Can't send D-Bus bonding created signal");
		goto failed;
	}

	dbus_connection_flush(connection);

	/* create the authentication reply */
	if (dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		struct slist *l;

		l = slist_find(pdata->bonding_requests, peer, bonding_requests_find);

		if (l) {
			struct bonding_request_info *dev = l->data;

			msg_reply = dbus_msg_new_authentication_return(dev->msg, status);
			if (dbus_connection_send(connection, msg_reply, NULL) == FALSE) {
				error("Can't send D-Bus reply for create bonding request");
				goto failed;
			}

			dbus_message_unref(dev->msg);
			pdata->bonding_requests = slist_remove(pdata->bonding_requests, dev);
			free(dev->bdaddr);
			free(dev);
		}
	}

failed:
	if (msg_signal)
		dbus_message_unref(msg_signal);

	if (msg_reply)
		dbus_message_unref(msg_reply);

	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_inquiry_start(bdaddr_t *local)
{
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

	snprintf(path, sizeof(path), "%s/hci%d", ADAPTER_PATH, id);

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

int remote_name_resolve(struct hci_dbus_data *dbus_data)
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
	if (!dbus_data->discovered_devices)
		return -1;

	l = slist_find(dbus_data->discovered_devices, &name_status, remote_name_find_by_name_status);

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
		bacpy(&cp.bdaddr, dev->bdaddr);
		cp.pscan_rep_mode = 0x02;

		baswap(&tmp, dev->bdaddr); peer_addr = batostr(&tmp);

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
			dbus_data->discovered_devices = slist_remove(dbus_data->discovered_devices, dev);
			free(dev->bdaddr);
			free(dev);

			/* get the next element */
			l = slist_find(dbus_data->discovered_devices, &name_status, remote_name_find_by_name_status);

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

	snprintf(path, sizeof(path), "%s/hci%d", ADAPTER_PATH, id);

	if (dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		if (!remote_name_resolve(pdata)) {
			pdata->discover_state = RESOLVING_NAMES;
			goto failed; /* skip - there is name to resolve */
		}

		pdata->discover_state = DISCOVER_OFF;

		/* free discovered devices list */
		slist_foreach(pdata->discovered_devices, discovered_device_free, NULL);
		slist_free(pdata->discovered_devices);
		pdata->discovered_devices = NULL;

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
	const char *major_ptr;
	char invalid_minor_class[] = "";
	const char *minor_ptr = invalid_minor_class;
	const dbus_int16_t tmp_rssi = rssi;
	bdaddr_t tmp;
	int id, i;
	uint8_t service_index, major_index, minor_index;
	name_status_t name_status = NAME_PENDING;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, peer); peer_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d", ADAPTER_PATH, id);

	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata)) {
		error("Getting %s path data failed!", path);
		goto failed;
	}

	/* send the device found signal */
	signal_device = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						"RemoteDeviceFound");
	if (signal_device == NULL) {
		error("Can't allocate D-Bus message");
		goto failed;
	}

	/* get the major class */
	major_index = (class >> 8) & 0x1F;
	if (major_index > 8)
		major_ptr = major_cls[9]; /* set to uncategorized */
	else
		major_ptr = major_cls[major_index];

	/* get the minor class */
	minor_index = (class >> 2) & 0x3F;
	switch (major_index) {
	case 1: /* computer */
		minor_ptr = computer_minor_cls[minor_index];
		break;
	case 2: /* phone */
		minor_ptr = phone_minor_cls[minor_index];
		break;
	}

	dbus_message_iter_init_append(signal_device, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &peer_addr);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT16, &tmp_rssi);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &major_ptr);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &minor_ptr);

	/* add the service classes */
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
	 					DBUS_TYPE_STRING_AS_STRING, &array_iter);

	service_index = class >> 16;
	for (i = 0; i < (sizeof(services_cls) / sizeof(*services_cls)); i++)
		if (service_index & (1 << i))
			dbus_message_iter_append_basic(&array_iter, DBUS_TYPE_STRING, &services_cls[i]);

	dbus_message_iter_close_container(&iter, &array_iter);

	if (dbus_connection_send(connection, signal_device, NULL) == FALSE) {
		error("Can't send D-Bus remote device found signal");
		goto failed;
	}

	/* send the remote name signal */
	l = slist_find(pdata->discovered_devices, peer, remote_name_find_by_bdaddr);

	if (l) {
		dev = l->data;
		if (dev->name_status == NAME_SENT)
			goto failed; /* don't sent the name again */
	}

	snprintf(filename, PATH_MAX, "%s/%s/names", STORAGEDIR, local_addr);
	name = textfile_get(filename, peer_addr);

	if (name) {
		signal_name = dev_signal_factory(pdata->dev_id, "RemoteNameUpdate",
							DBUS_TYPE_STRING, &peer_addr,
							DBUS_TYPE_STRING, &name,
							DBUS_TYPE_INVALID);
		send_reply_and_unref(connection, signal_name);

		free(name);
		name_status = NAME_SENT;
	}

	/* handle only requests triggered by dbus applications */
	if ((pdata->discover_state == DISCOVER_RUNNING_WITH_NAMES) ||
		(pdata->discover_state == DISCOVER_RUNNING))
		remote_name_append(&pdata->discovered_devices, peer, name_status);

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

	snprintf(path, sizeof(path), "%s/hci%d", ADAPTER_PATH, id);

	/* remove from remote name request list */
	if (dbus_connection_get_object_path_data(connection, path, (void *) &pdata))
		remote_name_remove(&pdata->discovered_devices, peer);

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
	if (!remote_name_resolve(pdata))
		goto failed; /* skip if a new request has been sent */

	/* free discovered devices list */
	slist_foreach(pdata->discovered_devices, discovered_device_free, NULL);
	slist_free(pdata->discovered_devices);
	pdata->discovered_devices = NULL;

	if (pdata->discover_state != DISCOVER_OFF) {
		message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						  "DiscoveryCompleted");

		send_reply_and_unref(connection, message);

		if (pdata->requestor_name) {
			free(pdata->requestor_name);
			pdata->requestor_name = NULL;
		}

		pdata->discover_state = DISCOVER_OFF;
	}

failed:
	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_conn_complete(bdaddr_t *local, uint8_t status, uint16_t handle, bdaddr_t *peer)
{
	char path[MAX_PATH_LENGTH];
	struct hci_request rq;
	evt_cmd_status rp;
	auth_requested_cp cp;
	struct hci_dbus_data *pdata = NULL;
	const struct slist *l;
	struct bonding_request_info *dev = NULL;
	char *local_addr, *peer_addr;
	bdaddr_t tmp;
	int dd = -1, id;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, peer); peer_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d", ADAPTER_PATH, id);

	if (!dbus_connection_get_object_path_data(connection, path, (void *) &pdata))
		goto failed;

	l = slist_find(pdata->bonding_requests, peer, bonding_requests_find);

	/* 
	 * Connections can be requested by other applications,  profiles and bonding
	 * For now it's necessary check only if there a pending bonding request
	 */
	if (!l) 
		goto failed;

	dev = l->data;

	/* connection failed */	
	if (status) {
		error_connection_attempt_failed(connection, dev->msg, status);
		goto failed;
	}

	if (dev->bonding_state != CONNECTING)
		goto failed; /* FIXME: is it possible? */

	dd = hci_open_dev(pdata->dev_id);
	if (dd < 0) {
		error_no_such_adapter(connection, dev->msg);
		goto failed;
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
		error_failed(connection, dev->msg, errno);
		goto failed;
	}

	if (rp.status) {
		error("Failed with status 0x%02x", rp.status);
		error_failed(connection, dev->msg, rp.status);
		goto failed;
	}
	/* request sent properly */
	dev->bonding_state = PAIRING;

failed:
	/* remove from the list if the HCI pairing request was not sent */
	if (dev) {
		if (dev->bonding_state != PAIRING) {
			dbus_message_unref(dev->msg);
			pdata->bonding_requests = slist_remove(pdata->bonding_requests, dev);
			free(dev->bdaddr);
			free(dev);
		}
	}

	hci_close_dev(dd);

	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_disconn_complete(bdaddr_t *local, bdaddr_t *peer, uint8_t reason)
{
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

	ret_val = dbus_bus_request_name(connection, BASE_INTERFACE,
						0, &err);

	if (ret_val != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER ) {
		error("Service could not become the primary owner.");
		return FALSE;
	}

	if (dbus_error_is_set(&err)) {
		error("Can't get system message bus name: %s", err.message);
		dbus_error_free(&err);
		return FALSE;
	}

	if (!register_dbus_path(ADAPTER_PATH, ADAPTER_ROOT_ID, INVALID_DEV_ID,
				&obj_dev_vtable, TRUE))
		return FALSE;

	if (!register_dbus_path(MANAGER_PATH, MANAGER_ROOT_ID, INVALID_DEV_ID,
				&obj_mgr_vtable, FALSE))
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
	if (!dbus_connection_list_registered(connection, ADAPTER_PATH, &children))
		goto done;

	for (; children[i]; i++) {
		char dev_path[MAX_PATH_LENGTH];

		snprintf(dev_path, sizeof(dev_path), "%s/%s", ADAPTER_PATH, children[i]);

		unregister_dbus_path(dev_path);
	}

	dbus_free_string_array(children);

done:
	unregister_dbus_path(ADAPTER_PATH);
	unregister_dbus_path(MANAGER_PATH);

	dbus_connection_close(connection);
}

/*****************************************************************
 *
 *  Section reserved to re-connection timer
 *
 *****************************************************************/

static int discoverable_timeout_handler(void *data)
{
	const struct hci_dbus_data *dbus_data = data;
	struct hci_request rq;
	int dd = -1;
	uint8_t hci_mode = dbus_data->mode;
	uint8_t status = 0;
	int8_t retval = 0;

	hci_mode &= ~SCAN_INQUIRY;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		error("HCI device open failed: hci%d", dbus_data->dev_id);
		return -1;
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
		retval = -1;
		goto failed;
	}
	if (status) {
		error("Setting scan enable failed with status 0x%02x", status);
		retval = -1;
		goto failed;
	}

failed:
	if (dd >= 0)
		close(dd);

	return retval;
}

static void system_bus_reconnect(void)
{
	struct hci_dev_list_req *dl = NULL;
	struct hci_dev_req *dr;
	int sk;
	int i;

	if (hcid_dbus_init() == FALSE)
		return;

	/* Create and bind HCI socket */
	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0) {
		error("Can't open HCI socket: %s (%d)",
							strerror(errno), errno);
		return;
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

failed:
	if (sk >= 0)
		close(sk);

	if (dl)
		free(dl);
}

static void sigalarm_handler(int signum)
{
	struct hci_dbus_data *pdata = NULL;
	char device_path[MAX_PATH_LENGTH];
	char **device = NULL;
	int active_handlers = 0;
	int i = 0;

	if (!dbus_connection_get_is_connected(connection)) {
		/* it is not connected */
		system_bus_reconnect();
		return;
	}

	if (!dbus_connection_list_registered(connection, ADAPTER_PATH, &device))
		goto done;

	/* check the timer for each registered path */
	for (; device[i]; i++) {

		snprintf(device_path, sizeof(device_path), "%s/%s", ADAPTER_PATH, device[i]);

		if (!dbus_connection_get_object_path_data(connection, device_path, (void *) &pdata)){
			error("Getting %s path data failed!", device_path);
			continue;
		}

		if (pdata->timeout_handler == NULL)
			continue;

		if (!(pdata->mode & SCAN_INQUIRY)) {
			pdata->timeout_hits = 0;
			continue;
		}

		active_handlers++;

		if ((++(pdata->timeout_hits) % pdata->discoverable_timeout) != 0)
			continue;

		if (!pdata->timeout_handler(pdata)) {
			/* Remove from the timeout queue */
			pdata->timeout_handler = NULL;
			pdata->timeout_hits = 0;
			active_handlers--;
		}
	}

	dbus_free_string_array(device);

done:
	if (!active_handlers) {
		sigaction(SIGALRM, NULL, NULL);
		setitimer(ITIMER_REAL, NULL, NULL);
		__timeout_active = 0;
	}
}

static void bluez_timeout_start(void)
{
	struct sigaction sa;
	struct itimerval timer;

	if (__timeout_active)
		return;

	__timeout_active = 1;

	memset (&sa, 0, sizeof (sa));
	sa.sa_handler = &sigalarm_handler;
	sigaction(SIGALRM, &sa, NULL);

	/* expire after 1 sec... */
	timer.it_value.tv_sec = 1;
	timer.it_value.tv_usec = 0;

	/* ... and every 1 sec after that. */
	timer.it_interval.tv_sec = 1;
	timer.it_interval.tv_usec = 0;

	setitimer(ITIMER_REAL, &timer, NULL);
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
		bluez_timeout_start();
		ret = DBUS_HANDLER_RESULT_HANDLED;
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

	snprintf(path, sizeof(path), "%s/hci%d", ADAPTER_PATH, id);

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
		error("Getting path data failed!");
		goto failed;
	}

	/* update the current scan mode value */
	pdata->mode = rp.enable;

	switch (rp.enable) {
	case SCAN_DISABLED:
		scan_mode = MODE_OFF;
		break;
	case SCAN_PAGE:
		scan_mode = MODE_CONNECTABLE;
		break;
	case (SCAN_PAGE | SCAN_INQUIRY):
		scan_mode = MODE_DISCOVERABLE;
		pdata->timeout_handler = &discoverable_timeout_handler;
		bluez_timeout_start();
		break;
	case SCAN_INQUIRY:
		/* Address the scenario where another app changed the scan mode */
		pdata->timeout_handler = &discoverable_timeout_handler;
		bluez_timeout_start();
		/* ignore, this event should not be sent*/
	default:
		/* ignore, reserved */
		goto failed;
	}

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
