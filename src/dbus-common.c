/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2005-2007  Johan Hedberg <johan.hedberg@nokia.com>
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/l2cap.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "log.h"

#include "manager.h"
#include "adapter.h"
#include "dbus-hci.h"
#include "dbus-common.h"

#define BLUEZ_NAME "org.bluez"

#define RECONNECT_RETRY_TIMEOUT	5000

static gboolean system_bus_reconnect(void *data)
{
	DBusConnection *conn = get_dbus_connection();
	struct hci_dev_list_req *dl = NULL;
	struct hci_dev_req *dr;
	int sk, i;
	gboolean ret_val = TRUE;

	if (conn) {
		if (dbus_connection_get_is_connected(conn))
			return FALSE;
	}

	if (hcid_dbus_init() < 0)
		return TRUE;

	/* Create and bind HCI socket */
	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0) {
		error("Can't open HCI socket: %s (%d)",
				strerror(errno), errno);
		return TRUE;
	}

	dl = g_malloc0(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(sk, HCIGETDEVLIST, (void *) dl) < 0) {
		info("Can't get device list: %s (%d)",
			strerror(errno), errno);
		goto failed;
	}

	/* reset the default device */
	manager_set_default_adapter(-1);

	/* FIXME: it shouldn't be needed to register adapters again */
	for (i = 0; i < dl->dev_num; i++, dr++)
		manager_register_adapter(dr->dev_id, TRUE);

	ret_val = FALSE;

failed:
	if (sk >= 0)
		close(sk);

	g_free(dl);

	return ret_val;
}

static void disconnect_callback(DBusConnection *conn, void *user_data)
{
	set_dbus_connection(NULL);

	g_timeout_add(RECONNECT_RETRY_TIMEOUT,
				system_bus_reconnect, NULL);
}

void hcid_dbus_unregister(void)
{
	DBusConnection *conn = get_dbus_connection();
	char **children;
	int i;
	uint16_t dev_id;

	if (!conn || !dbus_connection_get_is_connected(conn))
		return;

	/* Unregister all paths in Adapter path hierarchy */
	if (!dbus_connection_list_registered(conn, "/", &children))
		return;

	for (i = 0; children[i]; i++) {
		char path[MAX_PATH_LENGTH];
		struct btd_adapter *adapter;

		if (children[i][0] != 'h')
			continue;

		snprintf(path, sizeof(path), "/%s", children[i]);

		adapter = manager_find_adapter_by_path(path);
		if (!adapter)
			continue;

		dev_id = adapter_get_dev_id(adapter);
		manager_unregister_adapter(dev_id);
	}

	dbus_free_string_array(children);
}

void hcid_dbus_exit(void)
{
	DBusConnection *conn = get_dbus_connection();

	if (!conn || !dbus_connection_get_is_connected(conn))
		return;

	manager_cleanup(conn, "/");

	set_dbus_connection(NULL);

	dbus_connection_unref(conn);
}

int hcid_dbus_init(void)
{
	DBusConnection *conn;
	DBusError err;

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, BLUEZ_NAME, &err);
	if (!conn) {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			return -EIO;
		}
		return -EALREADY;
	}

	if (g_dbus_set_disconnect_function(conn, disconnect_callback,
							NULL, NULL) == FALSE) {
		dbus_connection_unref(conn);
		return -EIO;
	}

	if (!manager_init(conn, "/"))
		return -EIO;

	set_dbus_connection(conn);

	return 0;
}

static void append_variant(DBusMessageIter *iter, int type, void *val)
{
	DBusMessageIter value;
	char sig[2] = { type, '\0' };

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, sig, &value);

	dbus_message_iter_append_basic(&value, type, val);

	dbus_message_iter_close_container(iter, &value);
}

static void append_array_variant(DBusMessageIter *iter, int type, void *val)
{
	DBusMessageIter variant, array;
	char type_sig[2] = { type, '\0' };
	char array_sig[3] = { DBUS_TYPE_ARRAY, type, '\0' };
	const char ***str_array = val;
	int i;

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
						array_sig, &variant);

	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						type_sig, &array);

	for (i = 0; (*str_array)[i]; i++)
		dbus_message_iter_append_basic(&array, type,
						&((*str_array)[i]));

	dbus_message_iter_close_container(&variant, &array);

	dbus_message_iter_close_container(iter, &variant);
}

void dict_append_entry(DBusMessageIter *dict,
			const char *key, int type, void *val)
{
	DBusMessageIter entry;

	if (type == DBUS_TYPE_STRING) {
		const char *str = *((const char **) val);
		if (str == NULL)
			return;
	}

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	append_variant(&entry, type, val);

	dbus_message_iter_close_container(dict, &entry);
}

void dict_append_array(DBusMessageIter *dict, const char *key, int type,
			void *val, int n_elements)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
						NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	append_array_variant(&entry, type, val);

	dbus_message_iter_close_container(dict, &entry);
}

dbus_bool_t emit_property_changed(DBusConnection *conn,
					const char *path,
					const char *interface,
					const char *name,
					int type, void *value)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	signal = dbus_message_new_signal(path, interface, "PropertyChanged");

	if (!signal) {
		error("Unable to allocate new %s.PropertyChanged signal",
				interface);
		return FALSE;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &name);

	append_variant(&iter, type, value);

	return g_dbus_send_message(conn, signal);
}

dbus_bool_t emit_array_property_changed(DBusConnection *conn,
					const char *path,
					const char *interface,
					const char *name,
					int type, void *value)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	signal = dbus_message_new_signal(path, interface, "PropertyChanged");

	if (!signal) {
		error("Unable to allocate new %s.PropertyChanged signal",
				interface);
		return FALSE;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &name);

	append_array_variant(&iter, type, value);

	return g_dbus_send_message(conn, signal);
}
