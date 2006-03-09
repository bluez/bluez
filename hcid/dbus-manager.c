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
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "dbus.h"

static DBusMessage *handle_mgr_list_devices_req(DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessage *reply;
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i, sk;

	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0)
		return error_failed(msg, errno);

	dl = malloc(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));
	if (!dl) {
		close(sk);
		return error_out_of_memory(msg);
	}

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(sk, HCIGETDEVLIST, dl) < 0) {
		reply = error_failed(msg, errno);
		goto failed;
	}

	dr = dl->dev_req;

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		reply = error_out_of_memory(msg);
		goto failed;
	}

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	for (i = 0; i < dl->dev_num; i++, dr++) {
		char path[MAX_PATH_LENGTH], *path_ptr = path;
		struct hci_dev_info di;

		memset(&di, 0 , sizeof(struct hci_dev_info));
		di.dev_id = dr->dev_id;

		if (ioctl(sk, HCIGETDEVINFO, &di) < 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", ADAPTER_PATH, di.name);

		dbus_message_iter_append_basic(&array_iter,
						DBUS_TYPE_STRING, &path_ptr);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

failed:
	free(dl);

	close(sk);

	return reply;
}

static DBusMessage *handle_mgr_default_device_req(DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	char path[MAX_PATH_LENGTH], *path_ptr = path;
	int default_dev = get_default_dev_id();

	if (default_dev < 0)
		return error_no_such_adapter(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(msg);

	snprintf(path, sizeof(path), "%s/hci%d", ADAPTER_PATH, default_dev);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &path_ptr,
					DBUS_TYPE_INVALID);

	return reply;
}

static const struct service_data mgr_services[] = {
	{ MGR_LIST_ADAPTERS,	handle_mgr_list_devices_req,	MGR_LIST_ADAPTERS_SIGNATURE	},
	{ MGR_DEFAULT_ADAPTER,	handle_mgr_default_device_req,	MGR_DEFAULT_ADAPTER_SIGNATURE	},
	{ NULL, NULL, NULL }
};

DBusHandlerResult msg_func_manager(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct service_data *handlers;
	DBusMessage *reply = NULL;
	const char *iface;
	const char *method;
	const char *signature;
	uint32_t err = BLUEZ_EDBUS_UNKNOWN_METHOD;
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	iface = dbus_message_get_interface(msg);
	method = dbus_message_get_member(msg);
	signature = dbus_message_get_signature(msg);

	info("Manager path:%s method:%s", dbus_message_get_path(msg), method);

	if (strcmp(iface, MANAGER_INTERFACE))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	for (handlers = mgr_services; handlers->name != NULL; handlers++) {
		if (strcmp(handlers->name, method))
			continue;

		if (strcmp(handlers->signature, signature) != 0)
			err = BLUEZ_EDBUS_WRONG_SIGNATURE;
		else {
			reply = handlers->handler_func(msg, data);
			err = 0;
		}

		ret = DBUS_HANDLER_RESULT_HANDLED;
	}

	if (err)
		reply = bluez_new_failure_msg(msg, err);

	if (reply) {
		if (!dbus_connection_send (conn, reply, NULL))
			error("Can't send reply message");

		dbus_message_unref(reply);
	}

	return ret;
}
