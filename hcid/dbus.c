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

#ifndef DBUS_NAME_FLAG_PROHIBIT_REPLACEMENT
#define DBUS_NAME_FLAG_PROHIBIT_REPLACEMENT	0x00
#endif

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

static bdaddr_t *remote_name_find(struct slist *list, bdaddr_t *addr)
{
	struct slist *current;

	for (current = list; current != NULL; current = current->next) {
		bdaddr_t *data = current->data;
		if (memcmp(data, addr, sizeof(*addr)) == 0) 
			return data;
	}

	return NULL;
}

static int remote_name_add(struct slist **list, bdaddr_t *addr)
{
	bdaddr_t *data;

	/* ignore repeated entries */
	data = remote_name_find(*list, addr);

	if (data)
		return -1;

	data = malloc(sizeof(bdaddr_t));
	if (!data)
		return -1;

	data = malloc(sizeof(bdaddr_t));
	memcpy(data, addr, sizeof(bdaddr_t));

	*list = slist_append(*list, data);

	return 0;
}

static int remote_name_remove(struct slist **list, bdaddr_t *addr)
{
	bdaddr_t *data;
	int ret_val = -1;

	data = remote_name_find(*list, addr);

	if (data) {
		*list = slist_remove(*list, data);
		free(data);
		ret_val = 0;
	}
	
	return ret_val;
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

static int dev_append_signal_args(DBusMessage *signal, int first, va_list var_args)
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
		error("Can't allocate D-BUS inquiry complete message");
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

	if (dbus_connection_get_object_path_data(connection, path, (void*)&data) && data) {
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

	if (!dbus_connection_get_object_path_data(connection, path, (void*) &pdata))
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
		error("Can't allocate D-BUS remote name message");
		goto failed;
	}

	/*FIXME: append a friendly name instead of device path */
	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &pptr,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send(connection, message, NULL)) {
		error("Can't send D-BUS added device message");
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
		error("Can't allocate D-Bus remote name message");
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

	snprintf(path, sizeof(path), "%s/hci%d", ADAPTER_PATH, id);

	/*
	 * 0x00: authentication request successfully completed
	 * 0x01-0x0F: authentication request failed
	 */
	name = status ? "BondingFailed" : "BondingCreated";

	message = dbus_message_new_signal(path, ADAPTER_INTERFACE, name);

	if (message == NULL) {
		error("Can't allocate D-Bus remote name message");
		goto failed;
	}

	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &peer_addr,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		error("Can't send D-Bus remote name message");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	if (message)
		dbus_message_unref(message);

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
		error("Can't allocate D-Bus inquiry start message");
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

static inline int remote_name_resolve(struct hci_dbus_data *dbus_data)
{
	bdaddr_t *bdaddr;
	remote_name_req_cp cp;
	int dd;

	/*get the next remote address */
	if (!dbus_data->discovered_devices)
		return -1;

	bdaddr = (bdaddr_t *) dbus_data->discovered_devices->data;
	if (!bdaddr)
		return -1;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0)
		return -1;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);
	cp.pscan_rep_mode = 0x02;

	hci_send_cmd(dd, OGF_LINK_CTL, OCF_REMOTE_NAME_REQ,
						REMOTE_NAME_REQ_CP_SIZE, &cp);

	hci_close_dev(dd);

	return 0;
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

	if (dbus_connection_get_object_path_data(connection, path, (void*) &pdata)) {
		if (pdata->resolve_name)
			if (!remote_name_resolve(pdata))
				goto failed; /* skip, send discovery complete after resolve all remote names */

		if (pdata->requestor_name) {
			free(pdata->requestor_name);
			pdata->requestor_name = NULL;
		}
	}

	message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						"DiscoveryCompleted");
	if (message == NULL) {
		error("Can't allocate D-Bus inquiry complete message");
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
	char *local_addr, *peer_addr, *name = NULL;
	const char *major_ptr;
	char invalid_minor_class[] = "";
	const char *minor_ptr = invalid_minor_class;
	const dbus_int16_t tmp_rssi = rssi;
	bdaddr_t tmp;
	int id, i;
	uint8_t service_index, major_index, minor_index;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, peer); peer_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		error("No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d", ADAPTER_PATH, id);

	signal_name = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						"RemoteNameUpdated");
	if (signal_name == NULL) {
		error("Can't allocate D-Bus inquiry result message");
		goto failed;
	}

	signal_device = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						"RemoteDeviceFound");
	if (signal_device == NULL) {
		error("Can't allocate D-Bus inquiry result message");
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
		error("Can't send D-Bus inquiry result message");
		goto failed;
	}

	snprintf(filename, PATH_MAX, "%s/%s/names", STORAGEDIR, local_addr);

	name = textfile_get(filename, peer_addr);

	if (!name) {
		/* FIXME: if necessary create a queue to resolve the name */

		if (!dbus_connection_get_object_path_data(connection, path, (void*) &pdata)) {
			error("Getting %s path data failed!", path);
			goto failed;
		}

		if (!pdata->resolve_name)
			goto failed; /* skip - it is a normal request */
		else
			remote_name_add(&pdata->discovered_devices, peer);

		goto failed;
	}


	dbus_message_append_args(signal_name,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send(connection, signal_name, NULL) == FALSE)
		error("Can't send D-Bus inquiry result message");

failed:
	if (signal_device)
		dbus_message_unref(signal_device);

	if (signal_name)
		dbus_message_unref(signal_name);

	bt_free(local_addr);
	bt_free(peer_addr);

	if (name)
		bt_free(name);

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
	if (dbus_connection_get_object_path_data(connection, path, (void*) &pdata))
		remote_name_remove(&pdata->discovered_devices, peer);
	
	if (!status)
		goto request_next;


	/* send the remote name update signal */
	message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						"RemoteNameUpdated");
	if (message == NULL) {
		error("Can't allocate D-Bus remote name message");
		goto failed;
	}

	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &peer_addr,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		error("Can't send D-Bus remote name message");
		goto failed;
	}

	dbus_connection_flush(connection);

request_next:
	if (!pdata->requestor_name)
		goto failed; /* handle requests from external app */

	if (!remote_name_resolve(pdata))
		goto failed; /* skip: there is more remote name to resolve */

	if (message)
		dbus_message_unref(message);
	
	message = dbus_message_new_signal(path, ADAPTER_INTERFACE,
						"DiscoveryCompleted");
	if (message == NULL) {
		error("Can't allocate D-Bus inquiry complete message");
		goto failed;
	}

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		error("Can't send D-Bus inquiry complete message");
		goto failed;
	}

	dbus_connection_flush(connection);

	free(pdata->requestor_name);
	pdata->requestor_name = NULL;

failed:
	if (message)
		dbus_message_unref(message);

	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_conn_complete(bdaddr_t *local, bdaddr_t *peer)
{
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
	DBusError err;

	dbus_error_init(&err);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &err);

	if (dbus_error_is_set(&err)) {
		error("Can't open system message bus connection: %s", err.message);
		dbus_error_free(&err);
		return FALSE;
	}

	dbus_connection_set_exit_on_disconnect(connection, FALSE);

	dbus_bus_request_name(connection, BASE_INTERFACE,
				DBUS_NAME_FLAG_PROHIBIT_REPLACEMENT, &err);

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

		if (!dbus_connection_get_object_path_data(connection, device_path, (void*) &pdata)){
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
		error("Can't send D-Bus signal");
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

	if (!dbus_connection_get_object_path_data(connection, path, (void*) &pdata)) {
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
		error("Can't allocate D-Bus inquiry complete message");
		goto failed;
	}

	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &scan_mode,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		error("Can't send D-Bus ModeChanged signal");
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
