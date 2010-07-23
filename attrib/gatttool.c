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

#include <errno.h>
#include <glib.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#define GATT_UNIX_PATH "/var/run/gatt"

static gchar *opt_src = NULL;
static gchar *opt_dst = NULL;
static int opt_start = 0x0001;
static int opt_end = 0xffff;

static int unix_connect(const char *address)
{
	struct sockaddr_un addr;
	int sk, err;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;
	strncpy(addr.sun_path, address, sizeof(addr.sun_path) - 1);

	sk = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sk < 0) {
		err = errno;
		g_printerr("Unix socket(%s) create failed: %s(%d)\n", address,
				strerror(err), err);
		return -err;
	}

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		g_printerr("Unix socket(%s) connect failed: %s(%d)\n", address,
				strerror(err), err);
		close(sk);
		return -err;
	}

	return sk;
}

static gboolean primary(const gchar *name, const gchar *value,
					gpointer user_data, GError **gerr)
{
	int sk;

	/* FIXME: implement option to select between unix/btio socket */
	sk = unix_connect(GATT_UNIX_PATH);
	if (sk < 0)
		return FALSE;

	/* FIXME: implement "discover all primary services */

	close(sk);

	return TRUE;
}

static gboolean characteristics(const gchar *name, const gchar *value,
					gpointer user_data, GError **gerr)
{
	return TRUE;
}

static GOptionEntry primary_options[] = {
	{ "start", 's' , 0, G_OPTION_ARG_INT, &opt_start,
		"Starting handle(optional)", "0x0000" },
	{ "end", 'e' , 0, G_OPTION_ARG_INT, &opt_end,
		"Ending handle(optional)", "0xffff" },
	{ NULL },
};

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
	GOptionGroup *gatt_group, *primary_group;
	GError *gerr = NULL;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	/* GATT commands */
	gatt_group = g_option_group_new("gatt", "GATT commands",
				"Show all GATT commands", NULL, NULL);
	g_option_context_add_group(context, gatt_group);
	g_option_group_add_entries(gatt_group, gatt_options);

	/* Primary Services arguments */
	primary_group = g_option_group_new("primary",
			"Discover primary services arguments",
			"Show all Primary arguments", NULL, NULL);
	g_option_context_add_group(context, primary_group);
	g_option_group_add_entries(primary_group, primary_options);

	if (g_option_context_parse(context, &argc, &argv, &gerr) == FALSE) {
		g_printerr("%s\n", gerr->message);
		g_error_free(gerr);
	}

	g_option_context_free(context);

	return 0;
}
