/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2016  Intel Corporation. All rights reserved.
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
#include <stdlib.h>
#include <stdint.h>
#include <readline/readline.h>
#include <wordexp.h>

#include "gdbus/gdbus.h"
#include "display.h"
#include "advertising.h"

#define AD_PATH "/org/bluez/advertising"
#define AD_IFACE "org.bluez.LEAdvertisement1"

static gboolean registered = FALSE;
static char *ad_type = NULL;

static void ad_release(DBusConnection *conn)
{
	registered = FALSE;

	g_dbus_unregister_interface(conn, AD_PATH, AD_IFACE);
}

static DBusMessage *release_advertising(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	rl_printf("Advertising released\n");

	ad_release(conn);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable ad_methods[] = {
	{ GDBUS_METHOD("Release", NULL, NULL, release_advertising) },
	{ }
};

static void register_setup(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	const char *path = AD_PATH;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);
	dbus_message_iter_close_container(iter, &dict);
}

static void register_reply(DBusMessage *message, void *user_data)
{
	DBusConnection *conn = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == FALSE) {
		registered = TRUE;
		rl_printf("Advertising object registered\n");
	} else {
		rl_printf("Failed to register advertisement: %s\n", error.name);
		dbus_error_free(&error);

		if (g_dbus_unregister_interface(conn, AD_PATH,
						AD_IFACE) == FALSE)
			rl_printf("Failed to unregister advertising object\n");
	}
}

static gboolean get_type(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	const char *type = "peripheral";

	if (!ad_type || strlen(ad_type) > 0)
		type = ad_type;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &type);

	return TRUE;
}

static const GDBusPropertyTable ad_props[] = {
	{ "Type", "s", get_type },
	{ }
};

void ad_register(DBusConnection *conn, GDBusProxy *manager, const char *type)
{
	if (registered == TRUE) {
		rl_printf("Advertisement is already registered\n");
		return;
	}

	ad_type = g_strdup(type);

	if (g_dbus_register_interface(conn, AD_PATH, AD_IFACE, ad_methods,
					NULL, ad_props, NULL, NULL) == FALSE) {
		rl_printf("Failed to register advertising object\n");
		return;
	}

	if (g_dbus_proxy_method_call(manager, "RegisterAdvertisement",
					register_setup, register_reply,
					conn, NULL) == FALSE) {
		rl_printf("Failed to register advertising\n");
		return;
	}
}

static void unregister_setup(DBusMessageIter *iter, void *user_data)
{
	const char *path = AD_PATH;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

static void unregister_reply(DBusMessage *message, void *user_data)
{
	DBusConnection *conn = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == FALSE) {
		registered = FALSE;
		rl_printf("Advertising object unregistered\n");
		if (g_dbus_unregister_interface(conn, AD_PATH,
							AD_IFACE) == FALSE)
			rl_printf("Failed to unregister advertising object\n");
	} else {
		rl_printf("Failed to unregister advertisement: %s\n",
								error.name);
		dbus_error_free(&error);
	}
}

void ad_unregister(DBusConnection *conn, GDBusProxy *manager)
{
	if (!manager)
		ad_release(conn);

	if (g_dbus_proxy_method_call(manager, "UnregisterAdvertisement",
					unregister_setup, unregister_reply,
					conn, NULL) == FALSE) {
		rl_printf("Failed to unregister advertisement method\n");
		return;
	}
}
