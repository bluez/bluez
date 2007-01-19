/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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

#include <dbus/dbus.h>

#include "dbus-helper.h"
#include "logging.h"
#include "notify.h"

#include "system.h"
#include "adapter.h"

#define ADAPTER_INTERFACE "org.bluez.Adapter"

static DBusConnection *connection = NULL;

DBusMessage *adapter_list(DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter iter, array;
	const char path[] = "/org/bluez/hci0", *ptr = path;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &array);

	dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &ptr);

	dbus_message_iter_close_container(&iter, &array);

	return reply;
}

DBusMessage *adapter_find(DBusMessage *msg)
{
	DBusMessage *reply;
	const char *pattern;
	const char path[] = "/org/bluez/hci0", *ptr = path;

	dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &pattern, DBUS_TYPE_INVALID);

	debug("Searching adapter with pattern \"%s\"", pattern);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &ptr,
					DBUS_TYPE_INVALID);

	return reply;
}

DBusMessage *adapter_default(DBusMessage *msg)
{
	DBusMessage *reply;
	const char path[] = "/org/bluez/hci0", *ptr = path;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &ptr,
					DBUS_TYPE_INVALID);

	return reply;
}

int adapter_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	info("Starting adapter framework");

	return 0;
}

void adapter_exit(void)
{
	info("Stopping adapter framework");

	dbus_connection_unref(connection);

	connection = NULL;
}
