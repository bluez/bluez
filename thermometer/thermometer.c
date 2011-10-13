/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011 GSyC/LibreSoft, Universidad Rey Juan Carlos.
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

#include <gdbus.h>
#include <errno.h>
#include <bluetooth/uuid.h>

#include "adapter.h"
#include "device.h"
#include "error.h"
#include "log.h"
#include "gattrib.h"
#include "attio.h"
#include "att.h"
#include "thermometer.h"

#define THERMOMETER_INTERFACE "org.bluez.Thermometer"

struct thermometer {
	DBusConnection		*conn;		/* The connection to the bus */
	struct btd_device	*dev;		/* Device reference */
	GAttrib			*attrib;	/* GATT connection */
	struct att_range	*svc_range;	/* Thermometer range */
	guint			attioid;	/* Att watcher id */
};

static GSList *thermometers = NULL;

static void destroy_thermometer(gpointer user_data)
{
	struct thermometer *t = user_data;

	if (t->attioid > 0)
		btd_device_remove_attio_callback(t->dev, t->attioid);

	if (t->attrib != NULL)
		g_attrib_unref(t->attrib);

	dbus_connection_unref(t->conn);
	btd_device_unref(t->dev);
	g_free(t->svc_range);
	g_free(t);
}

static gint cmp_device(gconstpointer a, gconstpointer b)
{
	const struct thermometer *t = a;
	const struct btd_device *dev = b;

	if (dev == t->dev)
		return 0;

	return -1;
}

static DBusMessage *get_properties(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	/* TODO: */
	return g_dbus_create_error(msg, ERROR_INTERFACE ".ThermometerError",
						"Function not implemented.");
}

static DBusMessage *set_property(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	/* TODO: */
	return g_dbus_create_error(msg, ERROR_INTERFACE ".ThermometerError",
						"Function not implemented.");
}

static DBusMessage *register_watcher(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	/* TODO: */
	return g_dbus_create_error(msg, ERROR_INTERFACE ".ThermometerError",
						"Function not implemented.");
}

static DBusMessage *unregister_watcher(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	/* TODO: */
	return g_dbus_create_error(msg, ERROR_INTERFACE ".ThermometerError",
						"Function not implemented.");
}

static DBusMessage *enable_intermediate(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	/* TODO: */
	return g_dbus_create_error(msg, ERROR_INTERFACE ".ThermometerError",
						"Function not implemented.");
}

static DBusMessage *disable_intermediate(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	/* TODO: */
	return g_dbus_create_error(msg, ERROR_INTERFACE ".ThermometerError",
						"Function not implemented.");
}

static GDBusMethodTable thermometer_methods[] = {
	{ "GetProperties",	"",	"a{sv}",	get_properties },
	{ "SetProperty",	"sv",	"",		set_property,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "RegisterWatcher",	"o",	"",		register_watcher },
	{ "UnregisterWatcher",	"o",	"",		unregister_watcher },
	{ "EnableIntermediateMeasurement", "o", "", enable_intermediate },
	{ "DisableIntermediateMeasurement","o",	"", disable_intermediate },
	{ }
};

static GDBusSignalTable thermometer_signals[] = {
	{ "PropertyChanged",	"sv"	},
	{ }
};

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct thermometer *t = user_data;

	t->attrib = g_attrib_ref(attrib);
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct thermometer *t = user_data;

	DBG("GATT Disconnected");

	g_attrib_unref(t->attrib);
	t->attrib = NULL;
}

int thermometer_register(DBusConnection *connection, struct btd_device *device,
						struct att_primary *tattr)
{
	const gchar *path = device_get_path(device);
	struct thermometer *t;

	t = g_new0(struct thermometer, 1);
	t->conn = dbus_connection_ref(connection);
	t->dev = btd_device_ref(device);
	t->svc_range = g_new0(struct att_range, 1);
	t->svc_range->start = tattr->start;
	t->svc_range->end = tattr->end;

	if (!g_dbus_register_interface(t->conn, path, THERMOMETER_INTERFACE,
				thermometer_methods, thermometer_signals,
				NULL, t, destroy_thermometer)) {
		error("D-Bus failed to register %s interface",
							THERMOMETER_INTERFACE);
		destroy_thermometer(t);
		return -EIO;
	}

	thermometers = g_slist_prepend(thermometers, t);

	t->attioid = btd_device_add_attio_callback(device, attio_connected_cb,
						attio_disconnected_cb, t);
	return 0;
}

void thermometer_unregister(struct btd_device *device)
{
	struct thermometer *t;
	GSList *l;

	l = g_slist_find_custom(thermometers, device, cmp_device);
	if (l == NULL)
		return;

	t = l->data;
	thermometers = g_slist_remove(thermometers, t);
	g_dbus_unregister_interface(t->conn, device_get_path(t->dev),
							THERMOMETER_INTERFACE);
}
