/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *  Copyright (C) 2011  Marcel Holtmann <marcel@holtmann.org>
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

#include <errno.h>
#include <fcntl.h>
#include <gdbus.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <bluetooth/bluetooth.h>

#include "dbus-common.h"
#include "error.h"
#include "log.h"

#include "monitor.h"
#include "textfile.h"

#define PROXIMITY_INTERFACE "org.bluez.Proximity"
#define PROXIMITY_PATH "/org/bluez/proximity"

struct monitor {
	char *linklosslevel;		/* Link Loss Alert Level */
};

static inline int create_filename(char *buf, size_t size,
				const bdaddr_t *bdaddr, const char *name)
{
	char addr[18];

	ba2str(bdaddr, addr);

	return create_name(buf, size, STORAGEDIR, addr, name);
}

static int write_proximity_config(bdaddr_t *sba, bdaddr_t *dba,
					const char *alert, const char *level)
{
	char filename[PATH_MAX + 1], addr[18], key[38];

	create_filename(filename, PATH_MAX, sba, "proximity");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(dba, addr);

	snprintf(key, sizeof(key), "%17s#%s", addr, alert);

	return textfile_put(filename, key, level);
}

static char *read_proximity_config(bdaddr_t *sba, bdaddr_t *dba,
							const char *alert)
{
	char filename[PATH_MAX + 1], addr[18], key[38];

	create_filename(filename, PATH_MAX, sba, "proximity");

	ba2str(dba, addr);
	snprintf(key, sizeof(key), "%17s#%s", addr, alert);

	return textfile_caseget(filename, key);
}

static DBusMessage *set_link_loss_alert(DBusConnection *conn, DBusMessage *msg,
						const char *level, void *data)
{
	struct monitor *monitor = data;
	bdaddr_t sba, dba;

	if (!g_str_equal("none", level) && !g_str_equal("mild", level) &&
			!g_str_equal("high", level))
		return btd_error_invalid_args(msg);

	if (g_strcmp0(monitor->linklosslevel, level) == 0)
		return dbus_message_new_method_return(msg);

	g_free(monitor->linklosslevel);
	monitor->linklosslevel = g_strdup(level);

	/* FIXME: using hardcoded values */
	bacpy(&sba, BDADDR_ANY);
	bacpy(&dba, BDADDR_ALL);
	write_proximity_config(&sba, &dba, "LinkLossAlertLevel", level);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct monitor *monitor = data;
	DBusMessageIter iter;
	DBusMessageIter dict;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dict_append_entry(&dict, "LinkLossAlertLevel",
			DBUS_TYPE_STRING, &monitor->linklosslevel);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *property;
	DBusMessageIter iter;
	DBusMessageIter sub;
	const char *level;

	if (!dbus_message_iter_init(msg, &iter))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return btd_error_invalid_args(msg);
	dbus_message_iter_recurse(&iter, &sub);

	if (g_str_equal("LinkLossAlertLevel", property)) {
		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)
			return btd_error_invalid_args(msg);

		dbus_message_iter_get_basic(&sub, &level);

		return set_link_loss_alert(conn, msg, level, data);
	}

	return btd_error_invalid_args(msg);
}

static GDBusMethodTable monitor_methods[] = {
	{ "GetProperties",	"",	"a{sv}",	get_properties	},
	{ "SetProperty",	"sv",	"",		set_property,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ }
};

static GDBusSignalTable monitor_signals[] = {
	{ "PropertyChanged",	"sv"	},
	{ }
};

static void monitor_destroy(gpointer user_data)
{
	struct monitor *monitor = user_data;

	g_free(monitor->linklosslevel);
	g_free(monitor);
}

int monitor_register(DBusConnection *conn)
{
	struct monitor *monitor;
	bdaddr_t sba, dba;
	char *level;
	int ret = -1;

	/* FIXME: using hardcoded values */
	bacpy(&sba, BDADDR_ANY);
	bacpy(&dba, BDADDR_ALL);

	level = read_proximity_config(&sba, &dba, "LinkLossAlertLevel");

	monitor = g_new0(struct monitor, 1);
	monitor->linklosslevel = (level ? : g_strdup("none"));

	if (g_dbus_register_interface(conn, PROXIMITY_PATH,
				PROXIMITY_INTERFACE,
				monitor_methods, monitor_signals,
				NULL, monitor, monitor_destroy) == TRUE) {
		DBG("Registered interface %s on path %s", PROXIMITY_INTERFACE,
							PROXIMITY_PATH);
		ret = 0;

	}

	error("D-Bus failed to register %s interface", PROXIMITY_INTERFACE);

	return ret;
}

void monitor_unregister(DBusConnection *conn)
{
	g_dbus_unregister_interface(conn, PROXIMITY_PATH, PROXIMITY_INTERFACE);
}
