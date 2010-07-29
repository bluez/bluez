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

#include <stdint.h>
#include <hdp_types.h>
#include <hdp_util.h>

typedef gboolean (*parse_item_f)(DBusMessageIter *iter, gpointer user_data,
								GError **err);

struct dict_entry_func {
	char		*key;
	parse_item_f	func;
};

static gboolean parse_dict_entry(struct dict_entry_func dict_context[],
							DBusMessageIter *iter,
							GError **err,
							gpointer user_data)
{
	DBusMessageIter entry;
	char *key;
	int ctype, i;
	struct dict_entry_func df;

	dbus_message_iter_recurse(iter, &entry);
	ctype = dbus_message_iter_get_arg_type(&entry);
	if (ctype != DBUS_TYPE_STRING) {
		g_set_error(err, HDP_ERROR, HDP_DIC_ENTRY_PARSE_ERROR,
			"Dictionary entries should have a string as key");
		return FALSE;
	}

	dbus_message_iter_get_basic(&entry, &key);
	dbus_message_iter_next(&entry);
	/* Find function and call it */
	for (i = 0, df = dict_context[0]; df.key; i++, df = dict_context[i]) {
		if (g_ascii_strcasecmp(df.key, key) == 0) {
			return df.func(&entry, user_data, err);
		}
	}

	g_set_error(err, HDP_ERROR, HDP_DIC_ENTRY_PARSE_ERROR,
			"No function found for parsing value for key %s", key);
	return FALSE;
}

static gboolean parse_dict(struct dict_entry_func dict_context[],
							DBusMessageIter *iter,
							GError **err,
							gpointer user_data)
{
	int ctype;
	DBusMessageIter dict;

	ctype = dbus_message_iter_get_arg_type(iter);
	if (ctype != DBUS_TYPE_ARRAY) {
		g_set_error(err, HDP_ERROR, HDP_DIC_PARSE_ERROR,
					"Dictionary should be an array");
		return FALSE;
	}

	dbus_message_iter_recurse(iter, &dict);
	while ((ctype = dbus_message_iter_get_arg_type(&dict)) !=
							DBUS_TYPE_INVALID) {
		if (ctype != DBUS_TYPE_DICT_ENTRY) {
			g_set_error(err, HDP_ERROR, HDP_DIC_PARSE_ERROR,
						"Dictionary array should "
						"contain dict entries");
			return FALSE;
		}

		/* Start parsing entry */
		if (!parse_dict_entry(dict_context, &dict, err,
							user_data))
			return FALSE;
		/* Finish entry parsing */

		dbus_message_iter_next(&dict);
	}

	return TRUE;
}

static gboolean parse_data_type(DBusMessageIter *iter, gpointer data,
								GError **err)
{
	struct hdp_application *app = data;
	DBusMessageIter *value, variant;
	int ctype;

	ctype = dbus_message_iter_get_arg_type(iter);
	value = iter;
	if (ctype == DBUS_TYPE_VARIANT) {
		/* Get value inside the variable */
		dbus_message_iter_recurse(iter, &variant);
		ctype = dbus_message_iter_get_arg_type(&variant);
		value = &variant;
	}

	if (ctype != DBUS_TYPE_UINT16) {
		g_set_error(err, HDP_ERROR, HDP_DIC_ENTRY_PARSE_ERROR,
			"Final value for data type should be uint16");
		return FALSE;
	}

	dbus_message_iter_get_basic(value, &app->data_type);
	app->data_type_set = TRUE;
	return TRUE;
}

static gboolean parse_role(DBusMessageIter *iter, gpointer data, GError **err)
{
	struct hdp_application *app = data;
	DBusMessageIter value;
	DBusMessageIter *string;
	int ctype;
	const char *role;

	ctype = dbus_message_iter_get_arg_type(iter);
	if (ctype == DBUS_TYPE_VARIANT) {
		/* Get value inside the variable */
		dbus_message_iter_recurse(iter, &value);
		ctype = dbus_message_iter_get_arg_type(&value);
		string = &value;
	} else
		string = iter;

	if (ctype != DBUS_TYPE_STRING) {
		g_set_error(err, HDP_ERROR, HDP_UNSPECIFIED_ERROR,
				"Value data spec should be variable or string");
		return FALSE;
	}

	dbus_message_iter_get_basic(string, &role);
	if (g_ascii_strcasecmp(role, HDP_SINK_ROLE_AS_STRING) == 0)
		app->role = HDP_SINK;
	else if (g_ascii_strcasecmp(role, HDP_SOURCE_ROLE_AS_STRING) == 0)
		app->role = HDP_SOURCE;
	else {
		g_set_error(err, HDP_ERROR, HDP_UNSPECIFIED_ERROR,
			"Role value should be \"source\" or \"sink\"");
		return FALSE;
	}

	app->role_set = TRUE;
	return TRUE;
}

static gboolean parse_desc(DBusMessageIter *iter, gpointer data, GError **err)
{
	struct hdp_application *app = data;
	DBusMessageIter *string, variant;
	int ctype;
	const char *desc;

	ctype = dbus_message_iter_get_arg_type(iter);
	if (ctype == DBUS_TYPE_VARIANT) {
		/* Get value inside the variable */
		dbus_message_iter_recurse(iter, &variant);
		ctype = dbus_message_iter_get_arg_type(&variant);
		string = &variant;
	} else
		string = iter;

	if (ctype != DBUS_TYPE_STRING) {
		g_set_error(err, HDP_ERROR, HDP_DIC_ENTRY_PARSE_ERROR,
				"Value data spec should be variable or string");
		return FALSE;
	}

	dbus_message_iter_get_basic(string, &desc);
	app->description = g_strdup(desc);
	return TRUE;
}

static gboolean parse_chan_type(DBusMessageIter *iter, gpointer data,
								GError **err)
{
	struct hdp_application *app = data;
	DBusMessageIter *value, variant;
	int ctype;

	ctype = dbus_message_iter_get_arg_type(iter);
	value = iter;
	if (ctype == DBUS_TYPE_VARIANT) {
		/* Get value inside the variable */
		dbus_message_iter_recurse(iter, &variant);
		ctype = dbus_message_iter_get_arg_type(&variant);
		value = &variant;
	}

	if (ctype != DBUS_TYPE_UINT16) {
		g_set_error(err, HDP_ERROR, HDP_DIC_ENTRY_PARSE_ERROR,
			"Final value for channel type should be a uint16");
		return FALSE;
	}

	dbus_message_iter_get_basic(value, &app->data_type);
	if (app->data_type < HDP_RELIABLE_DC ||
					app->data_type > HDP_STREAMING_DC) {
		g_set_error(err, HDP_ERROR, HDP_DIC_ENTRY_PARSE_ERROR,
						"Invalid value for data type");
		return FALSE;
	}

	app->data_type_set = TRUE;
	return TRUE;
}

static struct dict_entry_func dict_parser[] = {
	{"DataType",		parse_data_type},
	{"Role",		parse_role},
	{"Description",		parse_desc},
	{"ChannelType",		parse_chan_type},
	{NULL, NULL}
};

struct hdp_application *hdp_get_app_config(DBusMessageIter *iter, GError **err)
{
	struct hdp_application *app;

	app = g_new0(struct hdp_application, 1);
	if (!parse_dict(dict_parser, iter, err, app))
		goto fail;
	if (!app->data_type_set || !app->role_set) {
		g_set_error(err, HDP_ERROR, HDP_DIC_PARSE_ERROR,
						"Mandatory fields aren't set");
		goto fail;
	}
	return app;

fail:
	g_free(app);
	return NULL;
}
