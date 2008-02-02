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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "sdpd.h"
#include "adapter.h"
#include "dbus.h"
#include "dbus-helper.h"
#include "dbus-common.h"
#include "error.h"
#include "dbus-error.h"
#include "dbus-hci.h"
#include "dbus-service.h"
#include "dbus-database.h"
#include "dbus-security.h"
#include "sdp-xml.h"

#include "manager.h"

static int default_adapter_id = -1;

static DBusHandlerResult interface_version(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	dbus_uint32_t version = 0;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &version,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult default_adapter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	char path[MAX_PATH_LENGTH], *path_ptr = path;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	if (default_adapter_id < 0)
		return error_no_such_adapter(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, default_adapter_id);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &path_ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static int find_by_address(const char *str)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	bdaddr_t ba;
	int i, sk;
	int devid = -1;

	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0)
		return -1;

	dl = g_malloc0(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(sk, HCIGETDEVLIST, dl) < 0)
		goto out;

	dr = dl->dev_req;
	str2ba(str, &ba);

	for (i = 0; i < dl->dev_num; i++, dr++) {
		struct hci_dev_info di;

		if (hci_devinfo(dr->dev_id, &di) < 0)
			continue;

		if (hci_test_bit(HCI_RAW, &di.flags))
			continue;

		if (!bacmp(&ba, &di.bdaddr)) {
			devid = dr->dev_id;
			break;
		}
	}

out:
	g_free(dl);
	close(sk);
	return devid;
}

static DBusHandlerResult find_adapter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	char path[MAX_PATH_LENGTH], *path_ptr = path;
	struct hci_dev_info di;
	const char *pattern;
	int dev_id;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	/* hci_devid() would make sense to use here, except it
	   is restricted to devices which are up */
	if (!strncmp(pattern, "hci", 3) && strlen(pattern) >= 4)
		dev_id = atoi(pattern + 3);
	else
		dev_id = find_by_address(pattern);

	if (dev_id < 0)
		return error_no_such_adapter(conn, msg);

	if (hci_devinfo(dev_id, &di) < 0)
		return error_no_such_adapter(conn, msg);

	if (hci_test_bit(HCI_RAW, &di.flags))
		return error_no_such_adapter(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, dev_id);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &path_ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult list_adapters(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessage *reply;
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i, sk;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0)
		return error_failed_errno(conn, msg, errno);

	dl = g_malloc0(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(sk, HCIGETDEVLIST, dl) < 0) {
		int err = errno;
		close(sk);
		g_free(dl);
		return error_failed_errno(conn, msg, err);
	}

	dr = dl->dev_req;

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		close(sk);
		g_free(dl);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	for (i = 0; i < dl->dev_num; i++, dr++) {
		char path[MAX_PATH_LENGTH], *path_ptr = path;
		struct hci_dev_info di;

		if (hci_devinfo(dr->dev_id, &di) < 0)
			continue;

		if (hci_test_bit(HCI_RAW, &di.flags))
			continue;

		snprintf(path, sizeof(path), "%s/%s", BASE_PATH, di.name);

		dbus_message_iter_append_basic(&array_iter,
						DBUS_TYPE_STRING, &path_ptr);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	g_free(dl);

	close(sk);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult find_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *pattern;
	struct service *service;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	service = search_service(conn, pattern);
	if (!service)
		return error_no_such_service(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &service->object_path,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult list_services(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array_iter;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	append_available_services(&array_iter);

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult activate_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *pattern;
	struct service *service;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	service = search_service(conn, pattern);
	if (!service)
		return error_no_such_service(conn, msg);

	if (service->bus_name) {
		DBusMessage *reply;

		reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		dbus_message_append_args(reply,
					DBUS_TYPE_STRING, &service->bus_name,
					DBUS_TYPE_INVALID);

		return send_message_and_unref(conn, reply);
	}

	if (service->pid)
		return error_service_start_in_progress(conn, msg);

	if (service_start(service, conn) < 0)
		return error_failed_errno(conn, msg, ENOEXEC);

	service->action = dbus_message_ref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusMethodVTable manager_methods[] = {
	{ "InterfaceVersion",	interface_version,	"",	"u"	},
	{ "DefaultAdapter",	default_adapter,	"",	"s"	},
	{ "FindAdapter",	find_adapter,		"s",	"s"	},
	{ "ListAdapters",	list_adapters,		"",	"as"	},
	{ "FindService",	find_service,		"s",	"s"	},
	{ "ListServices",	list_services,		"",	"as"	},
	{ "ActivateService",	activate_service,	"s",	"s"	},
	{ NULL, NULL, NULL, NULL }
};

static DBusSignalVTable manager_signals[] = {
	{ "AdapterAdded",		"s"	},
	{ "AdapterRemoved",		"s"	},
	{ "DefaultAdapterChanged",	"s"	},
	{ "ServiceAdded",		"s"	},
	{ "ServiceRemoved",		"s"	},
	{ NULL, NULL }
};

dbus_bool_t manager_init(DBusConnection *conn, const char *path)
{
	return dbus_connection_register_interface(conn, path, MANAGER_INTERFACE,
							manager_methods,
							manager_signals, NULL);
}

int get_default_adapter(void)
{
	return default_adapter_id;
}

void set_default_adapter(int new_default)
{
	default_adapter_id = new_default;
}
