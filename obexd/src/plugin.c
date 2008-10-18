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

#include <errno.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/stat.h>

#include <glib.h>

#include "plugin.h"
#include "logging.h"

static GSList *plugins = NULL;

struct obex_plugin {
	void *handle;
	struct obex_plugin_desc *desc;
};

static gboolean add_plugin(void *handle, struct obex_plugin_desc *desc)
{
	struct obex_plugin *plugin;

	if (desc->init == NULL)
		return FALSE;

	plugin = g_try_new0(struct obex_plugin, 1);
	if (plugin == NULL)
		return FALSE;

	plugin->handle = handle;
	plugin->desc = desc;

	if (desc->init() < 0) {
		g_free(plugin);
		return FALSE;
	}

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
		struct obex_plugin_desc *desc;
		void *handle;
		gchar *filename;
		struct stat st;

		if (g_str_has_prefix(file, "lib") == TRUE ||
				g_str_has_suffix(file, ".so") == FALSE)
			continue;

		filename = g_build_filename(PLUGINDIR, file, NULL);

		if (stat(filename, &st) < 0) {
			error("Can't find plugin %s: %s", filename,
							strerror(errno));
			g_free(filename);
			continue;
		}

		handle = dlopen(filename, RTLD_NOW);
		if (handle == NULL) {
			error("Can't load plugin %s: %s", filename,
								dlerror());
			g_free(filename);
			continue;
		}

		g_free(filename);

		desc = dlsym(handle, "obex_plugin_desc");
		if (desc == NULL) {
			error("Can't load plugin description: %s", dlerror());
			dlclose(handle);
			continue;
		}

		if (add_plugin(handle, desc) == FALSE)
			dlclose(handle);
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

		if (plugin->desc->exit)
			plugin->desc->exit();

		dlclose(plugin->handle);

		g_free(plugin);
	}

	g_slist_free(plugins);
}
