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

#include <gdbus.h>

#include "hcid.h"
#include "sdpd.h"
#include "adapter.h"
#include "dbus-common.h"
#include "error.h"
#include "dbus-error.h"
#include "dbus-hci.h"
#include "dbus-service.h"
#include "dbus-database.h"
#include "dbus-security.h"
#include "sdp-xml.h"

#include "manager.h"

static DBusConnection *connection = NULL;
static int default_adapter_id = -1;
static GSList *adapters = NULL;

static inline DBusMessage *invalid_args(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".InvalidArguments",
			"Invalid arguments in method call");
}

static inline DBusMessage *no_such_adapter(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".NoSuchAdapter",
			"No such adapter");
}

static inline DBusMessage *no_such_service(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".NoSuchService",
			"No such service");
}

static inline DBusMessage *failed_strerror(DBusMessage *msg, int err)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".Failed",
			strerror(err));
}

static DBusMessage *interface_version(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	dbus_uint32_t version = 0;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return invalid_args(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &version,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *old_default_adapter(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	char path[MAX_PATH_LENGTH], *path_ptr = path;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return invalid_args(msg);

	if (default_adapter_id < 0)
		return no_such_adapter(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, default_adapter_id);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &path_ptr,
					DBUS_TYPE_INVALID);

	return reply;
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

static DBusMessage *old_find_adapter(DBusConnection *conn,
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
		return invalid_args(msg);

	/* hci_devid() would make sense to use here, except it
	   is restricted to devices which are up */
	if (!strncmp(pattern, "hci", 3) && strlen(pattern) >= 4)
		dev_id = atoi(pattern + 3);
	else
		dev_id = find_by_address(pattern);

	if (dev_id < 0)
		return no_such_adapter(msg);

	if (hci_devinfo(dev_id, &di) < 0)
		return no_such_adapter(msg);

	if (hci_test_bit(HCI_RAW, &di.flags))
		return no_such_adapter(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, dev_id);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &path_ptr,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *old_list_adapters(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessage *reply;
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i, sk;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return invalid_args(msg);

	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0)
		return failed_strerror(msg, errno);

	dl = g_malloc0(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(sk, HCIGETDEVLIST, dl) < 0) {
		int err = errno;
		close(sk);
		g_free(dl);
		return failed_strerror(msg, err);
	}

	dr = dl->dev_req;

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		close(sk);
		g_free(dl);
		return NULL;
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

	return reply;
}

static DBusMessage *find_service(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *pattern;
	struct service *service;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID))
		return invalid_args(msg);

	service = search_service(pattern);
	if (!service)
		return no_such_service(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &service->object_path,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *list_services(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array_iter;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return invalid_args(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	append_available_services(&array_iter);

	dbus_message_iter_close_container(&iter, &array_iter);

	return reply;
}

static DBusMessage *activate_service(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *pattern;
	struct service *service;
	const char *busname = "org.bluez";

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID))
		return invalid_args(msg);

	service = search_service(pattern);
	if (!service)
		return no_such_service(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &busname,
							DBUS_TYPE_INVALID);

	return reply;
}

static GDBusMethodTable old_manager_methods[] = {
	{ "InterfaceVersion",	"",	"u",	interface_version	},
	{ "DefaultAdapter",	"",	"s",	old_default_adapter	},
	{ "FindAdapter",	"s",	"s",	old_find_adapter	},
	{ "ListAdapters",	"",	"as",	old_list_adapters	},
	{ "FindService",	"s",	"s",	find_service		},
	{ "ListServices",	"",	"as",	list_services		},
	{ "ActivateService",	"s",	"s",	activate_service	},
	{ NULL, NULL, NULL, NULL }
};

static GDBusSignalTable old_manager_signals[] = {
	{ "AdapterAdded",		"s"	},
	{ "AdapterRemoved",		"s"	},
	{ "DefaultAdapterChanged",	"s"	},
	{ "ServiceAdded",		"s"	},
	{ "ServiceRemoved",		"s"	},
	{ NULL, NULL }
};

static DBusMessage *default_adapter(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	struct adapter *adapter;
	char *path;

	adapter = manager_find_adapter_by_id(default_adapter_id);
	if (!adapter)
		return no_such_adapter(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	path = adapter->path + ADAPTER_PATH_INDEX;

	dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *find_adapter(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	struct adapter *adapter;
	char *path;
	struct hci_dev_info di;
	const char *pattern;
	int dev_id;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pattern,
							DBUS_TYPE_INVALID))
		return NULL;

	/* hci_devid() would make sense to use here, except it
	   is restricted to devices which are up */
	if (!strncmp(pattern, "hci", 3) && strlen(pattern) >= 4)
		dev_id = atoi(pattern + 3);
	else
		dev_id = find_by_address(pattern);

	if (dev_id < 0)
		return no_such_adapter(msg);

	if (hci_devinfo(dev_id, &di) < 0)
		return no_such_adapter(msg);

	if (hci_test_bit(HCI_RAW, &di.flags))
		return no_such_adapter(msg);

	adapter = manager_find_adapter_by_id(dev_id);
	if (!adapter)
		return no_such_adapter(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	path = adapter->path + ADAPTER_PATH_INDEX;

	dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *list_adapters(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessage *reply;
	GSList *l;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &array_iter);

	for (l = adapters; l; l = l->next) {
		struct adapter *adapter = l->data;
		char *path;
		struct hci_dev_info di;

		if (hci_devinfo(adapter->dev_id, &di) < 0)
			continue;

		if (hci_test_bit(HCI_RAW, &di.flags))
			continue;

		path = adapter->path + ADAPTER_PATH_INDEX;

		dbus_message_iter_append_basic(&array_iter,
					DBUS_TYPE_OBJECT_PATH, &path);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return reply;
}

static GDBusMethodTable manager_methods[] = {
	{ "DefaultAdapter",	"",	"o",	default_adapter	},
	{ "FindAdapter",	"s",	"o",	find_adapter	},
	{ "ListAdapters",	"",	"ao",	list_adapters	},
	{ }
};

static GDBusSignalTable manager_signals[] = {
	{ "AdapterAdded",		"o"	},
	{ "AdapterRemoved",		"o"	},
	{ "DefaultAdapterChanged",	"o"	},
	{ }
};

dbus_bool_t manager_init(DBusConnection *conn, const char *path)
{
	connection = conn;

	if (hcid_dbus_use_experimental()) {
		debug("Registering experimental manager interface");
		g_dbus_register_interface(conn, "/", MANAGER_INTERFACE,
				manager_methods, manager_signals,
				NULL, NULL, NULL);
	}

	return g_dbus_register_interface(conn, path, MANAGER_INTERFACE,
			old_manager_methods, old_manager_signals,
			NULL, NULL, NULL);
}

void manager_cleanup(DBusConnection *conn, const char *path)
{
	g_dbus_unregister_interface(conn, path, MANAGER_INTERFACE);

	if (hcid_dbus_use_experimental())
		g_dbus_unregister_interface(conn, "/", MANAGER_INTERFACE);
}

static gint adapter_id_cmp(gconstpointer a, gconstpointer b)
{
	const struct adapter *adapter = a;
	uint16_t id = GPOINTER_TO_UINT(b);

	return adapter->dev_id == id ? 0 : -1;
}

static gint adapter_path_cmp(gconstpointer a, gconstpointer b)
{
	const struct adapter *adapter = a;
	const char *path = b;

	return strcmp(adapter->path, path);
}

static gint adapter_address_cmp(gconstpointer a, gconstpointer b)
{
	const struct adapter *adapter = a;
	const char *address = b;

	return strcmp(adapter->address, address);
}

struct adapter *manager_find_adapter(const bdaddr_t *sba)
{
	GSList *match;
	char address[18];

	ba2str(sba, address);

	match = g_slist_find_custom(adapters, address, adapter_address_cmp);
	if (!match)
		return NULL;

	return match->data;
}

struct adapter *manager_find_adapter_by_path(const char *path)
{
	GSList *match;

	match = g_slist_find_custom(adapters, path, adapter_path_cmp);
	if (!match)
		return NULL;

	return match->data;
}

struct adapter *manager_find_adapter_by_id(int id)
{
	GSList *match;

	match = g_slist_find_custom(adapters, GINT_TO_POINTER(id), adapter_id_cmp);
	if (!match)
		return NULL;

	return match->data;
}

void manager_add_adapter(struct adapter *adapter)
{
	const char *ptr = adapter->path + ADAPTER_PATH_INDEX;

	if (hcid_dbus_use_experimental()) {
		g_dbus_emit_signal(connection, "/",
				MANAGER_INTERFACE, "AdapterAdded",
				DBUS_TYPE_OBJECT_PATH, &ptr,
				DBUS_TYPE_INVALID);
	}

	g_dbus_emit_signal(connection, BASE_PATH,
			MANAGER_INTERFACE, "AdapterAdded",
			DBUS_TYPE_STRING, &adapter->path,
			DBUS_TYPE_INVALID);

	adapters = g_slist_append(adapters, adapter);
}

void manager_remove_adapter(struct adapter *adapter)
{
	const char *ptr = adapter->path + ADAPTER_PATH_INDEX;

	if (hcid_dbus_use_experimental()) {
		g_dbus_emit_signal(connection, "/",
				MANAGER_INTERFACE, "AdapterRemoved",
				DBUS_TYPE_OBJECT_PATH, &ptr,
				DBUS_TYPE_INVALID);
	}

	g_dbus_emit_signal(connection, BASE_PATH,
			MANAGER_INTERFACE, "AdapterRemoved",
			DBUS_TYPE_STRING, &adapter->path,
			DBUS_TYPE_INVALID);

	if ((default_adapter_id == adapter->dev_id || default_adapter_id < 0)) {
		int new_default = hci_get_route(NULL);

		default_adapter_id = new_default;
		if (new_default >= 0) {
			if (hcid_dbus_use_experimental()) {
				g_dbus_emit_signal(connection, "/",
						MANAGER_INTERFACE,
						"DefaultAdapterChanged",
						DBUS_TYPE_OBJECT_PATH, &ptr,
						DBUS_TYPE_INVALID);
			}
			g_dbus_emit_signal(connection, BASE_PATH,
					MANAGER_INTERFACE,
					"DefaultAdapterChanged",
					DBUS_TYPE_STRING, &adapter->path,
					DBUS_TYPE_INVALID);
		} else {
			g_dbus_emit_signal(connection, BASE_PATH,
					MANAGER_INTERFACE,
					"DefaultAdapterChanged",
					DBUS_TYPE_STRING, &adapter->path,
					DBUS_TYPE_INVALID);
		}
	}

	adapters = g_slist_remove(adapters, adapter);
}

int manager_get_default_adapter()
{
	return default_adapter_id;
}

void manager_set_default_adapter(int id)
{
	struct adapter *adapter = manager_find_adapter_by_id(id);
	const char *ptr = adapter->path + ADAPTER_PATH_INDEX;

	default_adapter_id = id;

	if (hcid_dbus_use_experimental())
		g_dbus_emit_signal(connection, "/",
				MANAGER_INTERFACE,
				"DefaultAdapterChanged",
				DBUS_TYPE_OBJECT_PATH, &ptr,
				DBUS_TYPE_INVALID);

	g_dbus_emit_signal(connection, BASE_PATH,
			MANAGER_INTERFACE,
			"DefaultAdapterChanged",
			DBUS_TYPE_STRING, &adapter->path,
			DBUS_TYPE_INVALID);
}
