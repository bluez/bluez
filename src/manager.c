/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include <gdbus.h>

#include "glib-helper.h"
#include "hcid.h"
#include "dbus-common.h"
#include "log.h"
#include "adapter.h"
#include "error.h"
#include "manager.h"

static char base_path[50] = "/org/bluez";

static DBusConnection *connection = NULL;
static int default_adapter_id = -1;
static GSList *adapters = NULL;

const char *manager_get_base_path(void)
{
	return base_path;
}

static DBusMessage *default_adapter(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	struct btd_adapter *adapter;
	const gchar *path;

	adapter = manager_find_adapter_by_id(default_adapter_id);
	if (!adapter)
		return btd_error_no_such_adapter(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	path = adapter_get_path(adapter);

	dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *find_adapter(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	struct btd_adapter *adapter;
	const char *pattern;
	int dev_id;
	const gchar *path;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pattern,
							DBUS_TYPE_INVALID))
		return NULL;

	/* hci_devid() would make sense to use here, except it is
	 * restricted to devices which are up */
	if (!strcmp(pattern, "any") || !strcmp(pattern, "00:00:00:00:00:00")) {
		path = adapter_any_get_path();
		if (path != NULL)
			goto done;
		return btd_error_no_such_adapter(msg);
	} else if (!strncmp(pattern, "hci", 3) && strlen(pattern) >= 4) {
		dev_id = atoi(pattern + 3);
		adapter = manager_find_adapter_by_id(dev_id);
	} else {
		bdaddr_t bdaddr;
		str2ba(pattern, &bdaddr);
		adapter = manager_find_adapter(&bdaddr);
	}

	if (!adapter)
		return btd_error_no_such_adapter(msg);

	path = adapter_get_path(adapter);

done:
	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

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
		struct btd_adapter *adapter = l->data;
		const gchar *path = adapter_get_path(adapter);

		dbus_message_iter_append_basic(&array_iter,
					DBUS_TYPE_OBJECT_PATH, &path);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return reply;
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	GSList *list;
	char **array;
	int i;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	array = g_new0(char *, g_slist_length(adapters) + 1);
	for (i = 0, list = adapters; list; list = list->next) {
		struct btd_adapter *adapter = list->data;

		array[i] = (char *) adapter_get_path(adapter);
		i++;
	}
	dict_append_array(&dict, "Adapters", DBUS_TYPE_OBJECT_PATH, &array, i);
	g_free(array);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static GDBusMethodTable manager_methods[] = {
	{ "GetProperties",	"",	"a{sv}",get_properties	},
	{ "DefaultAdapter",	"",	"o",	default_adapter	},
	{ "FindAdapter",	"s",	"o",	find_adapter	},
	{ "ListAdapters",	"",	"ao",	list_adapters,
						G_DBUS_METHOD_FLAG_DEPRECATED},
	{ }
};

static GDBusSignalTable manager_signals[] = {
	{ "PropertyChanged",		"sv"	},
	{ "AdapterAdded",		"o"	},
	{ "AdapterRemoved",		"o"	},
	{ "DefaultAdapterChanged",	"o"	},
	{ }
};

dbus_bool_t manager_init(DBusConnection *conn, const char *path)
{
	connection = conn;

	snprintf(base_path, sizeof(base_path), "/org/bluez/%d", getpid());

	return g_dbus_register_interface(conn, "/", MANAGER_INTERFACE,
					manager_methods, manager_signals,
					NULL, NULL, NULL);
}

static void manager_update_adapters(void)
{
	GSList *list;
	char **array;
	int i;

	array = g_new0(char *, g_slist_length(adapters) + 1);
	for (i = 0, list = adapters; list; list = list->next) {
		struct btd_adapter *adapter = list->data;

		array[i] = (char *) adapter_get_path(adapter);
		i++;
	}

	emit_array_property_changed(connection, "/",
					MANAGER_INTERFACE, "Adapters",
					DBUS_TYPE_OBJECT_PATH, &array, i);

	g_free(array);
}

static void manager_set_default_adapter(int id)
{
	struct btd_adapter *adapter;
	const gchar *path;

	default_adapter_id = id;

	adapter = manager_find_adapter_by_id(id);
	if (!adapter)
		return;

	path = adapter_get_path(adapter);

	g_dbus_emit_signal(connection, "/",
			MANAGER_INTERFACE,
			"DefaultAdapterChanged",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);
}

struct btd_adapter *manager_get_default_adapter(void)
{
	return manager_find_adapter_by_id(default_adapter_id);
}

static void manager_remove_adapter(struct btd_adapter *adapter)
{
	uint16_t dev_id = adapter_get_dev_id(adapter);
	const gchar *path = adapter_get_path(adapter);

	adapters = g_slist_remove(adapters, adapter);

	manager_update_adapters();

	if (default_adapter_id == dev_id || default_adapter_id < 0) {
		int new_default = hci_get_route(NULL);

		manager_set_default_adapter(new_default);
	}

	g_dbus_emit_signal(connection, "/",
			MANAGER_INTERFACE, "AdapterRemoved",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);

	adapter_remove(adapter);
	btd_adapter_unref(adapter);

	if (adapters == NULL)
		btd_start_exit_timer();
}

void manager_cleanup(DBusConnection *conn, const char *path)
{
	while (adapters) {
		struct btd_adapter *adapter = adapters->data;

		adapters = g_slist_remove(adapters, adapter);
		adapter_remove(adapter);
		btd_adapter_unref(adapter);
	}

	btd_start_exit_timer();

	g_dbus_unregister_interface(conn, "/", MANAGER_INTERFACE);
}

static gint adapter_id_cmp(gconstpointer a, gconstpointer b)
{
	struct btd_adapter *adapter = (struct btd_adapter *) a;
	uint16_t id = GPOINTER_TO_UINT(b);
	uint16_t dev_id = adapter_get_dev_id(adapter);

	return dev_id == id ? 0 : -1;
}

static gint adapter_cmp(gconstpointer a, gconstpointer b)
{
	struct btd_adapter *adapter = (struct btd_adapter *) a;
	const bdaddr_t *bdaddr = b;
	bdaddr_t src;

	adapter_get_address(adapter, &src);

	return bacmp(&src, bdaddr);
}

struct btd_adapter *manager_find_adapter(const bdaddr_t *sba)
{
	GSList *match;

	match = g_slist_find_custom(adapters, sba, adapter_cmp);
	if (!match)
		return NULL;

	return match->data;
}

struct btd_adapter *manager_find_adapter_by_id(int id)
{
	GSList *match;

	match = g_slist_find_custom(adapters, GINT_TO_POINTER(id),
							adapter_id_cmp);
	if (!match)
		return NULL;

	return match->data;
}

void manager_foreach_adapter(adapter_cb func, gpointer user_data)
{
	g_slist_foreach(adapters, (GFunc) func, user_data);
}

GSList *manager_get_adapters(void)
{
	return adapters;
}

void manager_add_adapter(const char *path)
{
	g_dbus_emit_signal(connection, "/",
				MANAGER_INTERFACE, "AdapterAdded",
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID);

	manager_update_adapters();

	btd_stop_exit_timer();
}

struct btd_adapter *btd_manager_register_adapter(int id)
{
	struct btd_adapter *adapter;
	const char *path;

	adapter = manager_find_adapter_by_id(id);
	if (adapter) {
		error("Unable to register adapter: hci%d already exist", id);
		return NULL;
	}

	adapter = adapter_create(connection, id);
	if (!adapter)
		return NULL;

	adapters = g_slist_append(adapters, adapter);

	if (!adapter_init(adapter)) {
		adapters = g_slist_remove(adapters, adapter);
		btd_adapter_unref(adapter);
		return NULL;
	}

	path = adapter_get_path(adapter);
	g_dbus_emit_signal(connection, "/",
				MANAGER_INTERFACE, "AdapterAdded",
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID);

	manager_update_adapters();

	btd_stop_exit_timer();

	if (default_adapter_id < 0)
		manager_set_default_adapter(id);

	DBG("Adapter %s registered", path);

	return btd_adapter_ref(adapter);
}

int btd_manager_unregister_adapter(int id)
{
	struct btd_adapter *adapter;
	const gchar *path;

	adapter = manager_find_adapter_by_id(id);
	if (!adapter)
		return -1;

	path = adapter_get_path(adapter);

	info("Unregister path: %s", path);

	manager_remove_adapter(adapter);

	return 0;
}

void btd_manager_set_did(uint16_t vendor, uint16_t product, uint16_t version)
{
	GSList *l;

	for (l = adapters; l != NULL; l = g_slist_next(l)) {
		struct btd_adapter *adapter = l->data;

		btd_adapter_set_did(adapter, vendor, product, version);
	}
}
