/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010 GSyC/LibreSoft, Universidad Rey Juan Carlos.
 *  Authors:
 *  Santiago Carot Nemesio <sancane at gmail.com>
 *  Jose Antonio Santos-Cadenas <santoscadenas at gmail.com>
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

#include "log.h"
#include "error.h"
#include <stdint.h>
#include <hdp_types.h>
#include <hdp_util.h>
#include <adapter.h>
#include <device.h>
#include <hdp.h>
#include <mcap.h>

#include "../src/dbus-common.h"

static DBusConnection *connection = NULL;

static GSList *applications = NULL;
static uint8_t next_app_id = HDP_MDEP_INITIAL;

static int cmp_app_id(gconstpointer a, gconstpointer b)
{
	const struct hdp_application *app = a;
	const uint8_t *id = b;

	return app->id - *id;
}

static uint8_t get_app_id()
{
	GSList *l;
	uint8_t id = next_app_id;

	do {
		l = g_slist_find_custom(applications, &id, cmp_app_id);
		if (!l) {
			next_app_id = (id % HDP_MDEP_FINAL) + 1;
			return id;
		} else
			id = (id % HDP_MDEP_FINAL) + 1;
	} while (id != next_app_id);

	/* No more ids available */
	return 0;
}

static int cmp_app(gconstpointer a, gconstpointer b)
{
	const struct hdp_application *app = a;

	return g_strcmp0(app->path, b);
}

static gboolean set_app_path(struct hdp_application *app)
{
	app->id = get_app_id();
	if (!app->id)
		return FALSE;
	app->path = g_strdup_printf(MANAGER_PATH "/health_app_%d", app->id);

	return TRUE;
};

static void free_application(struct hdp_application *app)
{
	/* TODO: Remove watcher when done */

	g_free(app->oname);
	g_free(app->description);
	g_free(app->path);
	g_free(app);
}

static void remove_application(struct hdp_application *app)
{
	DBG("Application %s deleted", app->path);
	free_application(app);

	/* TODO: Update sdp records for each adapter */
}

static DBusMessage *manager_create_application(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct hdp_application *app;
	const char *name;
	DBusMessageIter iter;
	GError *err = NULL;
	DBusMessage *reply;

	dbus_message_iter_init(msg, &iter);
	app = hdp_get_app_config(&iter, &err);
	if (err) {
		reply = g_dbus_create_error(msg,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments: %s", err->message);
		g_error_free(err);
		return reply;
	}

	name = dbus_message_get_sender(msg);
	if (!name) {
		free_application(app);
		return g_dbus_create_error(msg,
					ERROR_INTERFACE ".HealthError",
					"Can't get sender name");
	}

	if (!set_app_path(app)){
		free_application(app);
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".HealthError",
				"Can't get a valid id for the application");
	}

	app->oname = g_strdup(name);

	applications = g_slist_prepend(applications, app);

	/* TODO: Add a watcher for client disconnections */
	/* TODO: Update sdp record for each adapter */

	DBG("Health application created with id %s", app->path);
	return g_dbus_create_reply(msg, DBUS_TYPE_OBJECT_PATH, &app->path,
							DBUS_TYPE_INVALID);
}

static DBusMessage *manager_destroy_application(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	const char *path;
	struct hdp_application *app;
	GSList *l;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID)){
		return g_dbus_create_error(msg,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
	}

	l = g_slist_find_custom(applications, path, cmp_app);

	app = l->data;
	applications = g_slist_remove(applications, app);

	remove_application(app);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void manager_path_unregister(gpointer data)
{
	g_slist_foreach(applications, (GFunc) free_application, NULL);

	g_slist_free(applications);
	applications = NULL;

	/* TODO: Update sdp records of all the adapters */
}

static GDBusMethodTable health_manager_methods[] = {
	{"CreateApplication", "a{sv}", "o", manager_create_application},
	{"DestroyApplication", "o", "", manager_destroy_application},
	{ NULL }
};

int hdp_adapter_register(DBusConnection *conn, struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);

	DBG("New health adapter %s", path);
	return 0;
}

void hdp_adapter_unregister(struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);

	DBG("Health adapter %s removed", path);
}

int hdp_device_register(DBusConnection *conn, struct btd_device *device)
{
	const char *path = device_get_path(device);

	DBG("New health device %s", path);
	return 0;
}

void hdp_device_unregister(struct btd_device *device)
{
	const char *path = device_get_path(device);

	DBG("Health device %s removed", path);
}

int hdp_manager_start(DBusConnection *conn)
{
	DBG("Starting Health manager");

	if (!g_dbus_register_interface(conn, MANAGER_PATH,
					HEALTH_MANAGER,
					health_manager_methods, NULL, NULL,
					NULL, manager_path_unregister)) {
		error("D-Bus failed to register %s interface", HEALTH_MANAGER);
		return -1;
	}

	connection = dbus_connection_ref(conn);

	return 0;
}

void hdp_manager_stop()
{
	g_dbus_unregister_interface(connection, MANAGER_PATH, HEALTH_MANAGER);

	dbus_connection_unref(connection);
	DBG("Stopped Health manager");
}
