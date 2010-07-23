/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
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

static gchar *opt_src = NULL;
static gchar *opt_dst = NULL;

static gboolean primary(const gchar *name, const gchar *value,
					gpointer user_data, GError **gerr)
{
	return TRUE;
}

static gboolean characteristics(const gchar *name, const gchar *value,
					gpointer user_data, GError **gerr)
{
	return TRUE;
}

static GOptionEntry gatt_options[] = {
	{ "primary", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, primary,
		"Primary Service Discovery", NULL},
	{ "characteristics", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
		characteristics, "Characteristics Discovery", NULL},
	{ NULL },
};

static GOptionEntry options[] = {
	{ "adapter", 'i', 0, G_OPTION_ARG_STRING, &opt_src,
		"Specify local adapter interface", "hciX" },
	{ "device", 'b', 0, G_OPTION_ARG_STRING, &opt_dst,
		"Specify remote Bluetooth address", "MAC" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GOptionGroup *gatt_group;
	GError *gerr = NULL;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	/* GATT commands */
	gatt_group = g_option_group_new("gatt", "GATT commands",
				"Show all GATT commands", NULL, NULL);
	g_option_context_add_group(context, gatt_group);
	g_option_group_add_entries(gatt_group, gatt_options);

	if (g_option_context_parse(context, &argc, &argv, &gerr) == FALSE) {
		g_printerr("%s\n", gerr->message);
		g_error_free(gerr);
	}

	g_option_context_free(context);

	return 0;
}
