/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <syslog.h>

#include <glib.h>

#ifdef HAVE_CAPNG
#include <cap-ng.h>
#endif

static GMainLoop *event_loop;

static void sig_term(int sig)
{
	g_main_loop_quit(event_loop);
}

static gboolean option_detach = TRUE;
static gboolean option_debug = FALSE;

static GOptionEntry options[] = {
	{ "nodaemon", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't run as daemon in background" },
	{ "debug", 'd', 0, G_OPTION_ARG_NONE, &option_debug,
				"Enable debug information output" },
	{ NULL },
};

static void debug(const char *format, ...)
{
	va_list ap;

	if (!option_debug)
		return;

	va_start(ap, format);

	vsyslog(LOG_DEBUG, format, ap);

	va_end(ap);
}

static void sig_debug(int sig)
{
	option_debug = !option_debug;
}

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *err = NULL;
	struct sigaction sa;

#ifdef HAVE_CAPNG
	/* Drop capabilities */
	capng_clear(CAPNG_SELECT_BOTH);
	capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE | CAPNG_PERMITTED,
					CAP_NET_BIND_SERVICE, CAP_NET_ADMIN,
						CAP_NET_RAW, CAP_IPC_LOCK, -1);
	capng_apply(CAPNG_SELECT_BOTH);
#endif

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (g_option_context_parse(context, &argc, &argv, &err) == FALSE) {
		if (err != NULL) {
			g_printerr("%s\n", err->message);
			g_error_free(err);
		} else
			g_printerr("An unknown error occurred\n");
		exit(1);
	}

	g_option_context_free(context);

	if (option_detach == TRUE) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	umask(0077);

	openlog("hcitrace", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);

	syslog(LOG_INFO, "HCI trace daemon %s", VERSION);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	sa.sa_handler = sig_debug;
	sigaction(SIGUSR2, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);

	if (option_debug == TRUE) {
		syslog(LOG_INFO, "Enabling debug information");
	}

	event_loop = g_main_loop_new(NULL, FALSE);

	debug("Entering main loop");

	g_main_loop_run(event_loop);

	g_main_loop_unref(event_loop);

	syslog(LOG_INFO, "Exit");

	closelog();

	return 0;
}
