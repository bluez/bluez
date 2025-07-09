// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
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

#include "obexd.h"
#include "plugin.h"
#include "log.h"

/*
 * Plugins that are using libraries with threads and their own mainloop
 * will crash on exit. This is a bug inside these libraries, but there is
 * nothing much that can be done about it. One bad example is libebook.
 */
#define PLUGINFLAG (RTLD_NOW | RTLD_NODELETE)
#define IS_ENABLED(x) (x)

static GSList *plugins = NULL;

struct obex_plugin {
	void *handle;
	const struct obex_plugin_desc *desc;
};

static gboolean add_external_plugin(void *handle,
					const struct obex_plugin_desc *desc)
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
	DBG("Plugin %s loaded", desc->name);

	return TRUE;
}

static void add_plugin(const struct obex_plugin_desc *desc)
{
	struct obex_plugin *plugin;

	plugin = g_try_new0(struct obex_plugin, 1);
	if (plugin == NULL)
		return;

	plugin->desc = desc;

	if (desc->init() < 0) {
		g_free(plugin);
		return;
	}

	plugins = g_slist_append(plugins, plugin);
	DBG("Plugin %s loaded", desc->name);
}

static gboolean check_plugin(const struct obex_plugin_desc *desc,
				char **patterns, char **excludes)
{
	if (excludes) {
		for (; *excludes; excludes++)
			if (g_pattern_match_simple(*excludes, desc->name))
				break;
		if (*excludes) {
			info("Excluding %s", desc->name);
			return FALSE;
		}
	}

	if (patterns) {
		for (; *patterns; patterns++)
			if (g_pattern_match_simple(*patterns, desc->name))
				break;
		if (*patterns == NULL) {
			info("Ignoring %s", desc->name);
			return FALSE;
		}
	}

	return TRUE;
}


static void external_plugin_init(char **patterns, char **excludes)
{
	GDir *dir;
	const char *file;

	info("Using external plugins is not officially supported.\n");
	info("Consider upstreaming your plugins into the BlueZ project.");

	if (strlen(PLUGINDIR) == 0)
		return;

	DBG("Loading plugins %s", PLUGINDIR);

	dir = g_dir_open(PLUGINDIR, 0, NULL);
	if (!dir) {
		return;
	}

	while ((file = g_dir_read_name(dir)) != NULL) {
		const struct obex_plugin_desc *desc;
		void *handle;
		char *filename;

		if (g_str_has_prefix(file, "lib") == TRUE ||
				g_str_has_suffix(file, ".so") == FALSE)
			continue;

		filename = g_build_filename(PLUGINDIR, file, NULL);

		handle = dlopen(filename, PLUGINFLAG);
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

		if (check_plugin(desc, patterns, excludes) == FALSE) {
			dlclose(handle);
			continue;
		}

		if (add_external_plugin(handle, desc) == FALSE)
			dlclose(handle);
	}

	g_dir_close(dir);
}

#include "builtin.h"

void plugin_init(const char *pattern, const char *exclude)
{
	char **patterns = NULL;
	char **excludes = NULL;
	unsigned int i;

	if (pattern)
		patterns = g_strsplit_set(pattern, ":, ", -1);

	if (exclude)
		excludes = g_strsplit_set(exclude, ":, ", -1);

	DBG("Loading builtin plugins");

	for (i = 0; __obex_builtin[i]; i++) {
		if (check_plugin(__obex_builtin[i],
					patterns, excludes) == FALSE)
			continue;

		add_plugin(__obex_builtin[i]);
	}

	if IS_ENABLED(EXTERNAL_PLUGINS)
		external_plugin_init(patterns, excludes);

	g_strfreev(patterns);
	g_strfreev(excludes);
}

void plugin_cleanup(void)
{
	GSList *list;

	DBG("Cleanup plugins");

	for (list = plugins; list; list = list->next) {
		struct obex_plugin *plugin = list->data;

		if (plugin->desc->exit)
			plugin->desc->exit();

		if (plugin->handle != NULL)
			dlclose(plugin->handle);

		g_free(plugin);
	}

	g_slist_free(plugins);
}
