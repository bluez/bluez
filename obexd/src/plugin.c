/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include "logging.h"

#include "plugin.h"

static GSList *plugins = NULL;

struct obex_plugin {
	GModule *module;
	struct obex_plugin_desc *desc;
};

static gboolean add_plugin(GModule *module, struct obex_plugin_desc *desc)
{
	struct obex_plugin *plugin;

	if (desc->init() < 0)
		return FALSE;

	plugin = g_try_new0(struct obex_plugin, 1);
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

	if (strlen(PLUGINDIR) == 0)
		return FALSE;

	debug("Loading plugins %s", PLUGINDIR);

	dir = g_dir_open(PLUGINDIR, 0, NULL);
	if (!dir)
		return FALSE;

	while ((file = g_dir_read_name(dir)) != NULL) {
		GModule *module;
		struct obex_plugin_desc *desc;
		gchar *filename;
		struct stat st;

		if (g_str_has_prefix(file, "lib") == TRUE ||
				g_str_has_suffix(file, ".so") == FALSE)
			continue;

		filename = g_build_filename(PLUGINDIR, file, NULL);

		if (stat(filename, &st) < 0) {
			error("Can't load plugin %s: %s (%d)", filename,
				strerror(errno), errno);
			g_free(filename);
			continue;
		}

		module = g_module_open(filename, G_MODULE_BIND_LOCAL);
		if (module == NULL) {
			error("Can't load plugin: %s", g_module_error());
			g_free(filename);
			continue;
		}

		g_free(filename);

		debug("%s", g_module_name(module));

		if (g_module_symbol(module, "obex_plugin_desc",
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
		struct obex_plugin *plugin = list->data;

		debug("%s", g_module_name(plugin->module));

		if (plugin->desc->exit)
			plugin->desc->exit();

		g_module_close(plugin->module);

		g_free(plugin);
	}

	g_slist_free(plugins);
}
