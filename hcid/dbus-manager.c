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
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "dbus.h"
#include "list.h"
#include "dbus-common.h"
#include "dbus-error.h"
#include "dbus-security.h"
#include "dbus-service.h"
#include "dbus-manager.h"

static int default_adapter_id = -1;

static DBusHandlerResult interface_version(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	dbus_uint32_t version = 0;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

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
		return error_invalid_arguments(conn, msg);

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

static DBusHandlerResult find_adapter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusError err;
	char path[MAX_PATH_LENGTH], *path_ptr = path;
	const char *pattern;
	int dev_id;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	dev_id = hci_devid(pattern);
	if (dev_id < 0)
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
		return error_invalid_arguments(conn, msg);

	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0)
		return error_failed(conn, msg, errno);

	dl = malloc(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));
	if (!dl) {
		close(sk);
		return error_out_of_memory(conn, msg);
	}

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(sk, HCIGETDEVLIST, dl) < 0) {
		int err = errno;
		close(sk);
		free(dl);
		return error_failed(conn, msg, err);
	}

	dr = dl->dev_req;

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		close(sk);
		free(dl);
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

		snprintf(path, sizeof(path), "%s/%s", BASE_PATH, di.name);

		dbus_message_iter_append_basic(&array_iter,
						DBUS_TYPE_STRING, &path_ptr);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	free(dl);

	close(sk);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult list_services(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array_iter;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

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

static DBusHandlerResult register_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *path, *name, *description;
	DBusMessage *message;
	DBusError err;
	int reg_err;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_STRING, &description,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	reg_err = register_service_agent(conn, dbus_message_get_sender(msg),
					path, name, description);

	if (reg_err < 0)
		return error_failed(conn, msg, -reg_err);

	/* Report that a new service was registered */
	message = dbus_message_new_signal(BASE_PATH, MANAGER_INTERFACE,
					"ServiceRegistered");
	dbus_message_append_args(message, DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID);
	send_message_and_unref(conn, message);

	return send_message_and_unref(conn, dbus_message_new_method_return(msg));
}

static DBusHandlerResult unregister_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *message;
	const char *path;
	DBusError err;
	int unreg_err;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	unreg_err = unregister_service_agent(conn,
					dbus_message_get_sender(msg), path);
	if (unreg_err < 0)
		return error_failed(conn, msg, -unreg_err);

	/* Report that the service was unregistered */
	message = dbus_message_new_signal(BASE_PATH, MANAGER_INTERFACE,
					"ServiceUnregistered");
	dbus_message_append_args(message, DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID);
	send_message_and_unref(conn, message);

	return send_message_and_unref(conn, dbus_message_new_method_return(msg));
}

static DBusHandlerResult register_shadow_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}


static DBusHandlerResult unregister_shadow_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static struct service_data methods[] = {
	{ "InterfaceVersion",	interface_version			},
	{ "DefaultAdapter",	default_adapter				},
	{ "FindAdapter",	find_adapter				},
	{ "ListAdapters",	list_adapters				},
	{ "ListServices",	list_services				},
	{ "RegisterService",	register_service			},
	{ "UnregisterService",	unregister_service			},
	{ "RegisterShadowService",	register_shadow_service		},
	{ "UnregistershadowService",	unregister_shadow_service	},

	{ NULL, NULL }
};

DBusHandlerResult handle_manager_method(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	service_handler_func_t handler;
	const char *iface, *path, *name;

	iface = dbus_message_get_interface(msg);
	path = dbus_message_get_path(msg);
	name = dbus_message_get_member(msg);

	if ((strcmp(BASE_PATH, path)) && !strcmp(iface, "org.bluez.ServiceAgent")) 
		return error_unknown_method(conn, msg);

	if (strcmp(BASE_PATH, path))
		return error_no_such_adapter(conn, msg);

	if (!strcmp(DBUS_INTERFACE_INTROSPECTABLE, iface) &&
					!strcmp("Introspect", name)) {
		return simple_introspect(conn, msg, data);
	} else if (!strcmp(iface, MANAGER_INTERFACE)) {
		handler = find_service_handler(methods, msg);
		if (handler)
			return handler(conn, msg, data);
		else
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (!strcmp(iface, SECURITY_INTERFACE))
		return handle_security_method(conn, msg, data);

	return error_unknown_method(conn, msg);
}

int get_default_adapter(void)
{
	return default_adapter_id;
}

void set_default_adapter(int new_default)
{
	default_adapter_id = new_default;
}
