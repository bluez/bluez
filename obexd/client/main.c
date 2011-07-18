/*
 *
 *  OBEX Client
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>

#include <glib.h>
#include <gdbus.h>

#include "log.h"
#include "manager.h"

static GMainLoop *event_loop = NULL;

static char *option_debug = NULL;
static gboolean option_stderr = FALSE;

static gboolean parse_debug(const char *key, const char *value,
				gpointer user_data, GError **error)
{
	if (value)
		option_debug = g_strdup(value);
	else
		option_debug = g_strdup("*");

	return TRUE;
}

static GOptionEntry options[] = {
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Enable debug information output", "DEBUG" },
	{ "stderr", 's', 0, G_OPTION_ARG_NONE, &option_stderr,
				"Write log information to stderr" },
	{ NULL },
};

static void sig_term(int sig)
{
	g_main_loop_quit(event_loop);
}

int main(int argc, char *argv[])
{
	GOptionContext *context;
	struct sigaction sa;
	GError *gerr = NULL;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	g_option_context_parse(context, &argc, &argv, &gerr);
	if (gerr != NULL) {
		g_printerr("%s\n", gerr->message);
		g_error_free(gerr);
		exit(EXIT_FAILURE);
	}

	g_option_context_free(context);

	event_loop = g_main_loop_new(NULL, FALSE);

	if (manager_init() < 0)
		exit(EXIT_FAILURE);

	__obex_log_init("obex-client", option_debug, !option_stderr);

	DBG("Entering main loop");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(event_loop);

	manager_exit();

	g_main_loop_unref(event_loop);

	__obex_log_cleanup();

	return 0;
}
