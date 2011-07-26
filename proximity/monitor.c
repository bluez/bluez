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

#include <gdbus.h>

#include "error.h"
#include "log.h"

#include "monitor.h"

#define PROXIMITY_INTERFACE "org.bluez.Proximity"
#define PROXIMITY_PATH "/org/bluez/proximity"

struct monitor {
	char *linklosslevel;		/* Link Loss Alert Level */
};

static DBusMessage *set_link_loss_alert(DBusConnection *conn, DBusMessage *msg,
						const char *level, void *data)
{
	struct monitor *monitor = data;

	if (!g_str_equal("none", level) && !g_str_equal("mild", level) &&
			!g_str_equal("high", level))
		return btd_error_invalid_args(msg);

	if (g_strcmp0(monitor->linklosslevel, level) == 0)
		return dbus_message_new_method_return(msg);

	g_free(monitor->linklosslevel);
	monitor->linklosslevel = g_strdup(level);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return dbus_message_new_method_return(msg);
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
	int ret = -1;

	monitor = g_new0(struct monitor, 1);
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
