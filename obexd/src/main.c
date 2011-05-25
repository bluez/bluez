/*
 *
 *  OBEX Server
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
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <termios.h>
#include <getopt.h>
#include <syslog.h>
#include <glib.h>

#include <gdbus.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "log.h"
#include "obexd.h"
#include "obex.h"
#include "obex-priv.h"
#include "server.h"
#include "service.h"

#define DEFAULT_ROOT_PATH "/tmp"

#define DEFAULT_CAP_FILE CONFIGDIR "/capability.xml"

static GMainLoop *main_loop = NULL;

static void sig_term(int sig)
{
	info("Terminating due to signal %d", sig);
	g_main_loop_quit(main_loop);
}

static void sig_debug(int sig)
{
	__obex_log_enable_debug();
}

static gboolean option_detach = TRUE;
static char *option_debug = NULL;

static char *option_root = NULL;
static char *option_root_setup = NULL;
static char *option_capability = NULL;
static char *option_plugin = NULL;
static char *option_noplugin = NULL;

static gboolean option_autoaccept = FALSE;
static gboolean option_symlinks = FALSE;

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
	{ "nodaemon", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't run as daemon in background" },
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Enable debug information output", "DEBUG" },
	{ "root", 'r', 0, G_OPTION_ARG_STRING, &option_root,
				"Specify root folder location", "PATH" },
	{ "root-setup", 'S', 0, G_OPTION_ARG_STRING, &option_root_setup,
				"Root folder setup script", "SCRIPT" },
	{ "symlinks", 'l', 0, G_OPTION_ARG_NONE, &option_symlinks,
				"Enable symlinks on root folder" },
	{ "capability", 'c', 0, G_OPTION_ARG_STRING, &option_capability,
				"Specify capability file", "FILE" },
	{ "auto-accept", 'a', 0, G_OPTION_ARG_NONE, &option_autoaccept,
				"Automatically accept push requests" },
	{ "plugin", 'p', 0, G_OPTION_ARG_STRING, &option_plugin,
				"Specify plugins to load", "NAME,..." },
	{ "noplugin", 'P', 0, G_OPTION_ARG_STRING, &option_noplugin,
				"Specify plugins not to load", "NAME,..." },
	{ NULL },
};

const char *obex_option_root_folder(void)
{
	return option_root;
}

gboolean obex_option_symlinks(void)
{
	return option_symlinks;
}

static gboolean is_dir(const char *dir) {
	struct stat st;

	if (stat(dir, &st) < 0) {
		error("stat(%s): %s (%d)", dir, strerror(errno), errno);
		return FALSE;
	}

	return S_ISDIR(st.st_mode);
}

static gboolean root_folder_setup(char *root, char *root_setup)
{
	int status;
	char *argv[3] = { root_setup, root, NULL };

	if (is_dir(root))
		return TRUE;

	if (root_setup == NULL)
		return FALSE;

	DBG("Setting up %s using %s", root, root_setup);

	if (!g_spawn_sync(NULL, argv, NULL, 0, NULL, NULL, NULL, NULL,
							&status, NULL)) {
		error("Unable to execute %s", root_setup);
		return FALSE;
	}

	if (WEXITSTATUS(status) != EXIT_SUCCESS) {
		error("%s exited with status %d", root_setup,
							WEXITSTATUS(status));
		return FALSE;
	}

	return is_dir(root);
}

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *err = NULL;
	struct sigaction sa;

#ifdef NEED_THREADS
	if (g_thread_supported() == FALSE)
		g_thread_init(NULL);
#endif

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (g_option_context_parse(context, &argc, &argv, &err) == FALSE) {
		if (err != NULL) {
			g_printerr("%s\n", err->message);
			g_error_free(err);
		} else
			g_printerr("An unknown error occurred\n");
		exit(EXIT_FAILURE);
	}

	g_option_context_free(context);

	if (option_detach == TRUE) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	__obex_log_init("obexd", option_debug, option_detach);

	DBG("Entering main loop");

	main_loop = g_main_loop_new(NULL, FALSE);

#ifdef NEED_THREADS
	if (dbus_threads_init_default() == FALSE) {
		fprintf(stderr, "Can't init usage of threads\n");
		exit(EXIT_FAILURE);
	}
#endif

	if (manager_init() == FALSE) {
		error("manager_init failed");
		exit(EXIT_FAILURE);
	}

	if (option_root == NULL)
		option_root = g_strdup(DEFAULT_ROOT_PATH);

	if (option_root[0] != '/') {
		char *old_root = option_root, *home = getenv("HOME");
		if (home) {
			option_root = g_strdup_printf("%s/%s", home, old_root);
			g_free(old_root);
		}
	}

	if (option_capability == NULL)
		option_capability = g_strdup(DEFAULT_CAP_FILE);

	plugin_init(option_plugin, option_noplugin);

	obex_server_init(OBEX_OPP, option_root, FALSE,
				option_autoaccept, option_symlinks,
				NULL);

	obex_server_init(OBEX_FTP, option_root, TRUE,
				option_autoaccept, option_symlinks,
				option_capability);

	obex_server_init(OBEX_PCSUITE, option_root, TRUE,
				option_autoaccept, option_symlinks,
				option_capability);

	obex_server_init(OBEX_PBAP, NULL, TRUE, FALSE, FALSE,
							option_capability);

	obex_server_init(OBEX_IRMC, NULL, TRUE, FALSE, FALSE,
							option_capability);

	obex_server_init(OBEX_SYNCEVOLUTION, NULL, TRUE, FALSE, FALSE, NULL);

	obex_server_init(OBEX_MAS, NULL, TRUE, FALSE, FALSE, NULL);

	if (!root_folder_setup(option_root, option_root_setup)) {
		error("Unable to setup root folder %s", option_root);
		exit(EXIT_FAILURE);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	sa.sa_handler = sig_debug;
	sigaction(SIGUSR2, &sa, NULL);

	g_main_loop_run(main_loop);

	obex_server_exit();

	plugin_cleanup();

	manager_cleanup();

	g_main_loop_unref(main_loop);

	g_free(option_capability);
	g_free(option_root);

	__obex_log_cleanup();

	return 0;
}
