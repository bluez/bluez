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
#include "service.h"

#define SERVICE_INTERFACE "org.bluez.Service"

static DBusConnection *connection = NULL;

DBusMessage *service_list(DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter iter, array;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &array);

	dbus_message_iter_close_container(&iter, &array);

	return reply;
}

DBusMessage *service_find(DBusMessage *msg)
{
	DBusMessage *reply;
	const char *pattern;

	dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &pattern, DBUS_TYPE_INVALID);

	debug("Searching service with pattern \"%s\"", pattern);

	reply = dbus_message_new_error(msg, ERROR_INTERFACE ".NotFound",
						"Service does not exists");

	return reply;
}

DBusMessage *service_activate(DBusMessage *msg)
{
	DBusMessage *reply;
	const char *pattern;

	dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &pattern, DBUS_TYPE_INVALID);

	debug("Activating service with pattern \"%s\"", pattern);

	reply = dbus_message_new_error(msg, ERROR_INTERFACE ".NotFound",
						"Service does not exists");

	return reply;
}

static void config_notify(int action, const char *name, void *data)
{
	switch (action) {
	case NOTIFY_CREATE:
		debug("File %s/%s created", CONFIGDIR, name);
		break;

	case NOTIFY_DELETE:
		debug("File %s/%s deleted", CONFIGDIR, name);
		break;

	case NOTIFY_MODIFY:
		debug("File %s/%s modified", CONFIGDIR, name);
		break;
	}
}

int service_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	info("Starting service framework");

	notify_add(CONFIGDIR, config_notify, NULL);

	return 0;
}

void service_exit(void)
{
	info("Stopping service framework");

	notify_remove(CONFIGDIR);

	dbus_connection_unref(connection);

	connection = NULL;
}
