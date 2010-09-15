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
#include <btio.h>
#include <mcap_lib.h>

#include <sdpd.h>
#include "../src/dbus-common.h"

static DBusConnection *connection = NULL;

static GSList *applications = NULL;
static uint8_t next_app_id = HDP_MDEP_INITIAL;

static GSList *adapters;

static gboolean update_adapter(struct hdp_adapter *adapter);

static int cmp_app_id(gconstpointer a, gconstpointer b)
{
	const struct hdp_application *app = a;
	const uint8_t *id = b;

	return app->id - *id;
}

static int cmp_adapter(gconstpointer a, gconstpointer b)
{
	const struct hdp_adapter *hdp_adapter = a;
	const struct btd_adapter *adapter = b;

	if (hdp_adapter->btd_adapter == adapter)
		return 0;
	return -1;
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

	g_slist_foreach(adapters, (GFunc) update_adapter, NULL);
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
	g_slist_foreach(adapters, (GFunc) update_adapter, NULL);

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

	g_slist_foreach(adapters, (GFunc) update_adapter, NULL);
}

static GDBusMethodTable health_manager_methods[] = {
	{"CreateApplication", "a{sv}", "o", manager_create_application},
	{"DestroyApplication", "o", "", manager_destroy_application},
	{ NULL }
};

static void mcl_connected(struct mcap_mcl *mcl, gpointer data)
{
	/* struct hdp_adapter *hdp_adapter = data; */
	/* TODO: Implement mcl_connected */
}

static void mcl_reconnected(struct mcap_mcl *mcl, gpointer data)
{
	/* struct hdp_adapter *hdp_adapter = data; */
	/* TODO: Implement mcl_reconnected */
}

static void mcl_disconnected(struct mcap_mcl *mcl, gpointer data)
{
	/* struct hdp_adapter *hdp_adapter = data; */
	/* TODO: Implement mcl_disconnected */
}

static void mcl_uncached(struct mcap_mcl *mcl, gpointer data)
{
	/* struct hdp_adapter *hdp_adapter = data; */
	/* TODO: Implement mcl_uncached */
}

static gboolean update_adapter(struct hdp_adapter *hdp_adapter)
{
	GError *err = NULL;
	bdaddr_t addr;

	if (!applications) {
		if (hdp_adapter->mi) {
			mcap_release_instance(hdp_adapter->mi);
			hdp_adapter->mi = NULL;
		}
		goto update;
	}

	if (hdp_adapter->mi)
		goto update;

	adapter_get_address(hdp_adapter->btd_adapter, &addr);
	hdp_adapter->mi = mcap_create_instance(&addr, BT_IO_SEC_HIGH, 0, 0,
					mcl_connected, mcl_reconnected,
					mcl_disconnected, mcl_uncached,
					NULL, /* CSP is not used by now */
					hdp_adapter, &err);

	if (!hdp_adapter->mi) {
		error("Error creating the MCAP instance: %s", err->message);
		g_error_free(err);
		return FALSE;
	}

	hdp_adapter->ccpsm = mcap_get_ctrl_psm(hdp_adapter->mi, &err);
	if (err) {
		error("Error getting MCAP control PSM: %s", err->message);
		goto fail;
	}

	hdp_adapter->dcpsm = mcap_get_data_psm(hdp_adapter->mi, &err);
	if (err) {
		error("Error getting MCAP data PSM: %s", err->message);
		goto fail;
	}

update:
	if (hdp_update_sdp_record(hdp_adapter, applications))
		return TRUE;
	error("Error updating the SDP record");

fail:
	if (hdp_adapter->mi)
		mcap_release_instance(hdp_adapter->mi);
	if (err)
		g_error_free(err);
	return FALSE;
}

int hdp_adapter_register(DBusConnection *conn, struct btd_adapter *adapter)
{
	struct hdp_adapter *hdp_adapter;

	hdp_adapter = g_new0(struct hdp_adapter, 1);
	hdp_adapter->btd_adapter = btd_adapter_ref(adapter);

	if(!update_adapter(hdp_adapter))
		goto fail;

	adapters = g_slist_append(adapters, hdp_adapter);

	return 0;

fail:
	btd_adapter_unref(hdp_adapter->btd_adapter);
	g_free(hdp_adapter);
	return -1;
}

void hdp_adapter_unregister(struct btd_adapter *adapter)
{
	struct hdp_adapter *hdp_adapter;
	GSList *l;

	l = g_slist_find_custom(adapters, adapter, cmp_adapter);

	if (!l)
		return;

	hdp_adapter = l->data;
	adapters = g_slist_remove(adapters, hdp_adapter);
	if (hdp_adapter->sdp_handler)
		remove_record_from_server(hdp_adapter->sdp_handler);
	if (hdp_adapter->mi)
		mcap_release_instance(hdp_adapter->mi);
	btd_adapter_unref(hdp_adapter->btd_adapter);
	g_free(hdp_adapter);
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
