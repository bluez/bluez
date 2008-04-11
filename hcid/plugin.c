/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <gmodule.h>
#include <string.h>

#include <sys/stat.h>
#include <errno.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <dbus/dbus.h>

#include "dbus-helper.h"
#include "adapter.h"
#include "dbus-hci.h"
#include "agent.h"
#include "plugin.h"
#include "device.h"
#include "logging.h"

static GSList *plugins = NULL;

struct bluetooth_plugin {
	GModule *module;
	struct bluetooth_plugin_desc *desc;
};

struct plugin_auth {
	plugin_auth_cb cb;
	void *user_data;
};

static gboolean add_plugin(GModule *module, struct bluetooth_plugin_desc *desc)
{
	struct bluetooth_plugin *plugin;

	if (desc->init() < 0)
		return FALSE;

	plugin = g_try_new0(struct bluetooth_plugin, 1);
	if (plugin == NULL)
		return FALSE;

	plugin->module = module;
	plugin->desc = desc;

	plugins = g_slist_append(plugins, plugin);

	return TRUE;
}

gboolean plugin_init(void)
{
	GDir *dir;
	const gchar *file;

	debug("Loading plugins %s", PLUGINDIR);

	dir = g_dir_open(PLUGINDIR, 0, NULL);
	if (!dir)
		return FALSE;

	while ((file = g_dir_read_name(dir)) != NULL) {
		GModule *module;
		struct bluetooth_plugin_desc *desc;
		gchar *filename;
		struct stat st;

		if (g_str_has_prefix(file, "lib") == FALSE ||
				g_str_has_suffix(file, ".so") == FALSE)
			continue;

		filename = g_build_filename(PLUGINDIR, file, NULL);

		if (stat(filename, &st) < 0) {
			error("Can't load plugin %s: %s (%d)", filename,
				strerror(errno), errno);
			g_free(filename);
			continue;
		}

		module = g_module_open(filename, 0);
		if (module == NULL) {
			error("Can't load plugin: %s", g_module_error());
			g_free(filename);
			continue;
		}

		g_free(filename);

		debug("%s", g_module_name(module));

		if (g_module_symbol(module, "bluetooth_plugin_desc",
					(gpointer) &desc) == FALSE) {
			error("Can't load plugin description");
			g_module_close(module);
			continue;
		}

		if (desc == NULL || desc->init == NULL) {
			g_module_close(module);
			continue;
		}

		if (add_plugin(module, desc) == FALSE) {
			error("Can't init plugin %s", g_module_name(module));
			g_module_close(module);
		}
	}

	g_dir_close(dir);

	return TRUE;
}

void plugin_cleanup(void)
{
	GSList *list;

	debug("Cleanup plugins");

	for (list = plugins; list; list = list->next) {
		struct bluetooth_plugin *plugin = list->data;

		debug("%s", g_module_name(plugin->module));

		if (plugin->desc->exit)
			plugin->desc->exit();

		g_module_close(plugin->module);

		g_free(plugin);
	}

	g_slist_free(plugins);
}

static struct adapter *ba2adapter(bdaddr_t *src)
{
	DBusConnection *conn = get_dbus_connection();
	struct adapter *adapter = NULL;
	char address[18], path[6];
	int dev_id;

	ba2str(src, address);
	dev_id = hci_devid(address);
	if (dev_id < 0)
		return NULL;

	/* FIXME: id2adapter? Create a list of adapters? */
	snprintf(path, sizeof(path), "/hci%d", dev_id);
	if (dbus_connection_get_object_user_data(conn,
			path, (void *) &adapter) == FALSE)
		return NULL;
	
	return adapter;
}

static void agent_auth_cb(struct agent *agent, DBusError *derr, void *user_data)
{
	struct plugin_auth *auth = user_data;

	auth->cb(derr, auth->user_data);

	g_free(auth);
}

int plugin_req_auth(bdaddr_t *src, bdaddr_t *dst,
		const char *uuid, plugin_auth_cb cb, void *user_data)
{
	struct plugin_auth *auth;
	struct adapter *adapter;
	struct device *device;
	struct agent *agent;
	char address[18];

	adapter = ba2adapter(src);
	if (!adapter)
		return -EPERM;

	/* Device connected? */
	if (!g_slist_find_custom(adapter->active_conn,
				dst, active_conn_find_by_bdaddr))
		return -ENOTCONN;

	/* FIXME: Is there a plugin that exports this service? */

	ba2str(dst, address);
	device = adapter_find_device(adapter, address);
	if (!device)
		return -EPERM;

	/* 
	 * FIXME: Trusted device? Currently, service are based on a friendly
	 * name, it is necessary convert UUID128 to friendly name or store the
	 * UUID128 in the trusted file.
	 */

	agent = (device->agent ? : adapter->agent);
	if (!agent)
		return -EPERM;

	auth = g_try_new0(struct plugin_auth, 1);
	if (!auth)
		return -ENOMEM;

	auth->cb = cb;
	auth->user_data = user_data;

	return agent_authorize(agent, device->path, uuid, agent_auth_cb, auth);
}

int plugin_cancel_auth(bdaddr_t *src)
{
	struct adapter *adapter = ba2adapter(src);
	struct device *device;
	struct agent *agent;
	char address[18];

	if (!adapter)
		return -EPERM;

	ba2str(src, address);
	device = adapter_find_device(adapter, address);
	if (!device)
		return -EPERM;

	/*
	 * FIXME: Cancel fails if authorization is requested to adapter's
	 * agent and in the meanwhile CreatePairedDevice is called.
	 */

	agent = (device->agent ? : adapter->agent);
	if (!agent)
		return -EPERM;

	return agent_cancel(agent);
}
