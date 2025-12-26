/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  Valve Corporation
 *
 */

#include "conf_d.h"

#include "src/log.h"

static gint confd_compare_filenames(gconstpointer a, gconstpointer b)
{
	return g_strcmp0(*(const gchar **)(a), *(const gchar **)(b));
}

static GPtrArray *confd_get_valid_files_sorted(const gchar *confd_path)
{
	const char *regex_pattern = "^([0-9][0-9])-([a-zA-Z0-9-_])*\\.conf$";
	g_autoptr(GRegex) regex = NULL;
	g_autoptr(GPtrArray) ret_confd_files = NULL;
	GDir *dir = NULL;
	GError *error = NULL;
	const gchar *filename = NULL;

	regex = g_regex_new(regex_pattern, 0, 0, &error);
	if (!regex) {
		DBG("Invalid regex: %s", error->message);
		g_clear_error(&error);
		return NULL;
	}

	dir = g_dir_open(confd_path, 0, &error);
	if (!dir) {
		DBG("%s", error->message);
		g_clear_error(&error);
		return NULL;
	}

	ret_confd_files = g_ptr_array_new_full(0, g_free);

	while ((filename = g_dir_read_name(dir)) != NULL) {
		g_autofree gchar *file_path = NULL;

		if (!g_regex_match(regex, filename, 0, NULL)) {
			DBG("Ignoring file in conf.d dir: '%s'", filename);
			continue;
		}

		file_path = g_build_filename(confd_path, filename, NULL);
		if (file_path)
			g_ptr_array_add(ret_confd_files, g_strdup(file_path));
	}

	g_dir_close(dir);

	if (ret_confd_files && ret_confd_files->len > 0) {
		g_ptr_array_sort(ret_confd_files, confd_compare_filenames);

		DBG("Will consider additional config files (in order):");
		for (guint i = 0; i < ret_confd_files->len; i++) {
			DBG(" - %s",
			    (const gchar *)(g_ptr_array_index(ret_confd_files,
							      i)));
		}

		return g_ptr_array_ref(ret_confd_files);
	} else {
		g_ptr_array_free(ret_confd_files, TRUE);
		ret_confd_files = NULL;
		return NULL;
	}
}

static void confd_override_config(GKeyFile *keyfile,
				  const gchar *new_conf_file_path,
				  gboolean accept_new_groups,
				  gboolean accept_new_keys)
{
	g_autoptr(GKeyFile) new_keyfile = NULL;
	gchar **existing_groups = NULL;
	gchar **groups = NULL;
	gchar **keys = NULL;
	gsize existing_groups_size = 0;
	gsize groups_size = 0;
	gsize keys_size = 0;
	g_autoptr(GError) error = NULL;

	new_keyfile = g_key_file_new();
	if (!g_key_file_load_from_file(new_keyfile, new_conf_file_path,
				       G_KEY_FILE_NONE, &error)) {
		if (error) {
			warn("%s", error->message);
			g_clear_error(&error);
		}
		return;
	}

	existing_groups = g_key_file_get_groups(keyfile, &existing_groups_size);

	groups = g_key_file_get_groups(new_keyfile, &groups_size);
	for (gsize gi = 0; gi < groups_size; gi++) {
		bool match = false;
		const gchar *group = groups[gi];

		for (gsize egi = 0; egi < existing_groups_size; egi++) {
			if (g_str_equal(group, existing_groups[egi])) {
				match = true;
				break;
			}
		}

		if (!match) {
			if (accept_new_groups == FALSE) {
				warn("Skipping group '%s' in '%s' "
				     "not known in previous config",
				     group, new_conf_file_path);
				continue;
			} else {
				DBG("Accepting group '%s' in '%s' "
				    "not known in previous config",
				    group, new_conf_file_path);
			}
		}

		keys = g_key_file_get_keys(new_keyfile, group, &keys_size,
					   NULL);
		if (keys == NULL) {
			DBG("No keys found in '%s' for group '%s'",
			    new_conf_file_path, group);
			continue;
		}

		for (gsize ki = 0; ki < keys_size; ki++) {
			const gchar *key = keys[ki];
			g_autofree gchar *value = NULL;
			g_autofree gchar *old_value = NULL;

			value = g_key_file_get_value(new_keyfile, group, key,
						     NULL);
			if (!value)
				continue;

			old_value =
				g_key_file_get_value(keyfile, group, key, NULL);
			if (old_value != NULL) {
				DBG("Overriding config value from "
				    "conf.d file: [%s] %s: '%s'->'%s'",
				    group, key, old_value, value);
				g_key_file_set_value(keyfile, group, key,
						     value);
			} else {
				if (accept_new_keys == TRUE) {
					DBG("Adding new config value from "
					    "conf.d file: [%s] %s: '%s'",
					    group, key, value);
					g_key_file_set_value(keyfile, group,
							     key, value);
				} else {
					DBG("Ignoring config value from "
					    "conf.d, unknown keys not allowed: "
					    "[%s] %s: '%s'",
					    group, key, value);
				}
			}
		}
		g_strfreev(keys);
	}
	g_strfreev(groups);
	g_strfreev(existing_groups);
}

void confd_process_config(GKeyFile *keyfile, const gchar *base_conf_file_path,
			  gboolean accept_new_groups, gboolean accept_new_keys)
{
	g_autofree gchar *confd_path = NULL;
	g_autoptr(GPtrArray) confd_files = NULL;

	confd_path = g_strconcat(base_conf_file_path, ".d", NULL);

	if (!g_file_test(confd_path,
			 (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_DIR))) {
		DBG("'%s' does not exist or not a directory", confd_path);
		return;
	}

	confd_files = confd_get_valid_files_sorted(confd_path);

	if (confd_files && confd_files->len > 0) {
		for (guint i = 0; i < confd_files->len; i++) {
			const gchar *confd_file =
				(const gchar *)(g_ptr_array_index(confd_files,
								  i));
			DBG("Processing config file: '%s'", confd_file);
			confd_override_config(keyfile, confd_file,
					      accept_new_groups,
					      accept_new_keys);
		}
	}
}
