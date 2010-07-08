/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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

#include <glib.h>

#include <bluetooth/bluetooth.h>

#include "log.h"
#include "gdbus.h"
#include "btio.h"

#include "client.h"

#define CHAR_INTERFACE "org.bluez.Characteristic"

struct gatt_service {
	int id;
	bdaddr_t sba;
	bdaddr_t dba;
	char *path;
	GIOChannel *io;
	GSList *chars;
};

struct characteristic {
	char *path;
};

static int service_id = 0;
static int char_id = 0;
static GSList *services = NULL;

static DBusConnection *connection;

static void characteristic_free(void *user_data)
{
	struct characteristic *chr = user_data;

	g_free(chr->path);
	g_free(chr);
}

static void gatt_service_free(void *user_data)
{
	struct gatt_service *gatt = user_data;

	g_slist_foreach(gatt->chars, (GFunc) characteristic_free, NULL);
	g_free(gatt->path);
	g_free(gatt);
}

static int gatt_path_cmp(const struct gatt_service *gatt, const char *path)
{
	return strcmp(gatt->path, path);
}

static DBusMessage *get_characteristics(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return dbus_message_new_method_return(msg);
}

static DBusMessage *register_watcher(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_watcher(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable char_methods[] = {
	{ "GetCharacteristics",	"",	"a{oa{sv}}", get_characteristics},
	{ "RegisterCharacteristicsWatcher",	"o", "",
						register_watcher	},
	{ "UnregisterCharacteristicsWatcher",	"o", "",
						unregister_watcher	},
	{ }
};

static void connect_cb(GIOChannel *chan, GError *gerr, gpointer user_data)
{
	struct gatt_service *gatt = user_data;

	if (gerr) {
		error("%s", gerr->message);
		goto fail;
	}

	DBG("GATT connection established.");

	return;
fail:
	g_io_channel_unref(gatt->io);
	gatt->io = NULL;
}

int attrib_client_register(bdaddr_t *sba, bdaddr_t *dba, const char *path,
									int psm)
{
	struct gatt_service *gatt;
	struct characteristic *chr;
	GError *gerr = NULL;
	GIOChannel *io;

	/*
	 * Registering fake services/characteristics. The following
	 * paths/interfaces shall be registered after discover primary
	 * services only.
	 */

	gatt = g_new0(struct gatt_service, 1);
	gatt->id = service_id;
	gatt->path = g_strdup(path);
	bacpy(&gatt->sba, sba);
	bacpy(&gatt->dba, dba);

	chr = g_new0(struct characteristic, 1);
	chr->path = g_strdup_printf("%s/service%d/characteristic%d",
						path, service_id, char_id);
	gatt->chars = g_slist_append(gatt->chars, chr);

	if (!g_dbus_register_interface(connection, chr->path, CHAR_INTERFACE,
						char_methods, NULL, NULL, chr,
						characteristic_free)) {
		error("D-Bus failed to register %s interface", CHAR_INTERFACE);
		gatt_service_free(gatt);
		return -1;
	}

	io = bt_io_connect(BT_IO_L2CAP, connect_cb, gatt, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, sba,
					BT_IO_OPT_DEST_BDADDR, dba,
					BT_IO_OPT_PSM, psm,
					BT_IO_OPT_INVALID);

	if (!io) {
		error("%s", gerr->message);
		g_error_free(gerr);
		gatt_service_free(gatt);
		return -1;
	}

	gatt->io = io;

	services = g_slist_append(services, gatt);

	DBG("Registered interface %s on path %s", CHAR_INTERFACE, path);

	return 0;
}

void attrib_client_unregister(const char *path)
{
	struct gatt_service *gatt;
	GSList *l;

	l = g_slist_find_custom(services, path, (GCompareFunc) gatt_path_cmp);
	if (!l)
		return;

	gatt = l->data;
	services = g_slist_remove(services, gatt);
	gatt_service_free(gatt);
}

int attrib_client_init(DBusConnection *conn)
{

	connection = dbus_connection_ref(conn);

	/*
	 * FIXME: if the adapter supports BLE start scanning. Temporary
	 * solution, this approach doesn't allow to control scanning based
	 * on the discoverable property.
	 */

	return 0;
}

void attrib_client_exit(void)
{
	dbus_connection_unref(connection);
}
