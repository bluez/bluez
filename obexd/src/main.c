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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <getopt.h>
#include <syslog.h>
#include <glib.h>

#include <gdbus.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "bluetooth.h"
#include "phonebook.h"
#include "obexd.h"
#include "obex.h"

#define OPUSH_CHANNEL	9
#define FTP_CHANNEL	10

#define DEFAULT_ROOT_PATH "/tmp"

#define DEFAULT_CAP_FILE CONFIGDIR "/capability.xml"

static GMainLoop *main_loop = NULL;

static void test_phonebook(void)
{
	struct phonebook_context *context;
	struct phonebook_driver *driver;

	driver = phonebook_get_driver(NULL);
	if (driver == NULL)
		return;

	context = phonebook_create(driver);
	if (context == NULL)
		return;

	phonebook_pullphonebook(context);

	phonebook_unref(context);
}

static void tty_init(int service, const gchar *root_path, const gchar *capability,
		const gchar *devnode)
{
	struct server *server;
	struct termios options;
	gint fd;

	fd = open(devnode, O_RDWR);
	if (fd < 0)
		return;

	fcntl(fd, F_SETFL, 0);

	tcgetattr(fd, &options);

	options.c_cflag |= (CLOCAL | CREAD);
	options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
	options.c_oflag &= ~OPOST;
	options.c_cc[VMIN] = 0;
	options.c_cc[VTIME] = 10;

	tcsetattr(fd, TCSANOW, &options);

	server = g_malloc0(sizeof(struct server));
	server->service = service;
	server->folder = g_strdup(root_path);
	server->auto_accept = TRUE;
	server->capability = g_strdup(capability);

	if (obex_session_start(fd, server) < 0)
		close(fd);

	return;
}

static int server_start(int service, const char *root_path,
		gboolean auto_accept, const gchar *capability,
		const char *devnode)
{
	switch (service) {
	case OBEX_OPUSH:
		bluetooth_init(OBEX_OPUSH, "OBEX OPUSH server",
				root_path, OPUSH_CHANNEL, FALSE,
				auto_accept, capability);
		if (devnode)
			tty_init(OBEX_OPUSH, root_path, capability,
					devnode);
		break;
	case OBEX_FTP:
		bluetooth_init(OBEX_FTP, "OBEX FTP server",
				root_path, FTP_CHANNEL, TRUE,
				auto_accept, capability);

		if (devnode)
			tty_init(OBEX_FTP, root_path, capability, devnode);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void server_stop()
{
	/* FIXME: If Bluetooth enabled */
	bluetooth_exit();
}

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static gboolean option_detach = TRUE;
static gboolean option_debug = FALSE;

static gchar *option_root = NULL;
static gchar *option_capability = NULL;
static gchar *option_devnode = NULL;

static gboolean option_autoaccept = FALSE;
static gboolean option_opp = FALSE;
static gboolean option_ftp = FALSE;
static gboolean option_pbap = FALSE;

static GOptionEntry options[] = {
	{ "nodaemon", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't run as daemon in background" },
	{ "debug", 'd', 0, G_OPTION_ARG_NONE, &option_debug,
				"Enable debug information output" },
	{ "root", 'r', 0, G_OPTION_ARG_STRING, &option_root,
				"Specify root folder location", "PATH" },
	{ "capability", 'c', 0, G_OPTION_ARG_STRING, &option_capability,
				"Sepcify capability file", "FILE" },
	{ "tty", 't', 0, G_OPTION_ARG_STRING, &option_devnode,
				"Specify the TTY device", "DEVICE" },
	{ "auto-accept", 'a', 0, G_OPTION_ARG_NONE, &option_autoaccept,
				"Automatically accept push requests" },
	{ "opp", 'o', 0, G_OPTION_ARG_NONE, &option_opp,
				"Enable Object Push server" },
	{ "ftp", 'f', 0, G_OPTION_ARG_NONE, &option_ftp,
				"Enable File Transfer server" },
	{ "pbap", 'f', 0, G_OPTION_ARG_NONE, &option_pbap,
				"Enable Phonebook Access server" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *err = NULL;
	struct sigaction sa;
	int log_option = LOG_NDELAY | LOG_PID;

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
	} else
		log_option |= LOG_PERROR;

	if (option_opp == FALSE && option_ftp == FALSE &&
						option_pbap == FALSE) {
		fprintf(stderr, "No server selected (use either "
					"--opp or --ftp or both)\n");
		exit(EXIT_FAILURE);
	}

	openlog("obexd", log_option, LOG_DAEMON);

	if (option_debug == TRUE) {
		info("Enabling debug information");
		enable_debug();
	}

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

	plugin_init();

	if (option_root == NULL)
		option_root = g_strdup(DEFAULT_ROOT_PATH);

	if (option_capability == NULL)
		option_capability = g_strdup(DEFAULT_CAP_FILE);

	if (option_opp == TRUE)
		server_start(OBEX_OPUSH, option_root, option_autoaccept,
							NULL, option_devnode);

	if (option_ftp == TRUE)
		server_start(OBEX_FTP, option_root, option_autoaccept,
					option_capability, option_devnode);

	if (option_pbap == TRUE)
		test_phonebook();

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(main_loop);

	server_stop();

	plugin_cleanup();

	manager_cleanup();

	g_main_loop_unref(main_loop);

	g_free(option_devnode);
	g_free(option_capability);
	g_free(option_root);

	closelog();

	return 0;
}
