/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2009  Marcel Holtmann <marcel@holtmann.org>
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

#include "logging.h"
#include "bluetooth.h"
#include "obexd.h"
#include "obex.h"
#include "service.h"

#define DEFAULT_ROOT_PATH "/tmp"

#define DEFAULT_CAP_FILE CONFIGDIR "/capability.xml"

static GMainLoop *main_loop = NULL;

static int services = 0;
static gboolean tty_needs_reinit = FALSE;
static gboolean tty_open_allowed = TRUE;
static int signal_pipe[2];

#define TTY_RX_MTU 65535
#define TTY_TX_MTU 65535

int tty_init(int services, const gchar *root_path,
		const gchar *capability, gboolean symlinks,
		const gchar *devnode)
{
	struct server *server;
	struct termios options;
	int fd, err, arg;
	glong flags;
	GIOChannel *io = NULL;

	tty_needs_reinit = TRUE;

	if (!tty_open_allowed)
		return -EACCES;

	fd = open(devnode, O_RDWR | O_NOCTTY);
	if (fd < 0)
		return fd;

	flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

	tcgetattr(fd, &options);
	cfmakeraw(&options);
	options.c_oflag &= ~ONLCR;
	tcsetattr(fd, TCSANOW, &options);

	arg = fcntl(fd, F_GETFL);
	if (arg < 0) {
		err = -errno;
		goto failed;
	}

	arg |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, arg) < 0) {
		err = -errno;
		goto failed;
	}

	server = g_new0(struct server, 1);
	server->drivers = obex_service_driver_list(services);
	server->folder = g_strdup(root_path);
	server->auto_accept = TRUE;
	server->capability = g_strdup(capability);
	server->devnode = g_strdup(devnode);
	server->rx_mtu = TTY_RX_MTU;
	server->tx_mtu = TTY_TX_MTU;
	server->symlinks = symlinks;

	io = g_io_channel_unix_new(fd);
	g_io_channel_set_close_on_unref(io, TRUE);

	err = obex_session_start(io, server);
	g_io_channel_unref(io);

	if (err < 0) {
		server_free(server);
		goto failed;
	}

	tty_needs_reinit = FALSE;

	debug("Successfully opened %s", devnode);

	return 0;

failed:
	error("tty_init(): %s (%d)", strerror(-err), -err);
	if (io == NULL)
		close(fd);
	return err;
}

void tty_closed(void)
{
	tty_needs_reinit = TRUE;
}

static void sig_term(int sig)
{
	info("Terminating due to signal %d", sig);
	g_main_loop_quit(main_loop);
}

static void sig_debug(int sig)
{
	toggle_debug();
}

static gboolean option_detach = TRUE;
static gboolean option_debug = FALSE;

static gchar *option_root = NULL;
static gchar *option_root_setup = NULL;
static gchar *option_capability = NULL;
static gchar *option_devnode = NULL;

static gboolean option_autoaccept = FALSE;
static gboolean option_opp = FALSE;
static gboolean option_ftp = FALSE;
static gboolean option_pbap = FALSE;
static gboolean option_pcsuite = FALSE;
static gboolean option_symlinks = FALSE;
static gboolean option_syncevolution = FALSE;

static GOptionEntry options[] = {
	{ "nodaemon", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't run as daemon in background" },
	{ "debug", 'd', 0, G_OPTION_ARG_NONE, &option_debug,
				"Enable debug information output" },
	{ "root", 'r', 0, G_OPTION_ARG_STRING, &option_root,
				"Specify root folder location", "PATH" },
	{ "root-setup", 'S', 0, G_OPTION_ARG_STRING, &option_root_setup,
				"Root folder setup script", "SCRIPT" },
	{ "symlinks", 'l', 0, G_OPTION_ARG_NONE, &option_symlinks,
				"Enable symlinks on root folder" },
	{ "capability", 'c', 0, G_OPTION_ARG_STRING, &option_capability,
				"Specify capability file", "FILE" },
	{ "tty", 't', 0, G_OPTION_ARG_STRING, &option_devnode,
				"Specify the TTY device", "DEVICE" },
	{ "auto-accept", 'a', 0, G_OPTION_ARG_NONE, &option_autoaccept,
				"Automatically accept push requests" },
	{ "opp", 'o', 0, G_OPTION_ARG_NONE, &option_opp,
				"Enable Object Push server" },
	{ "ftp", 'f', 0, G_OPTION_ARG_NONE, &option_ftp,
				"Enable File Transfer server" },
	{ "pbap", 'p', 0, G_OPTION_ARG_NONE, &option_pbap,
				"Enable Phonebook Access server" },
	{ "pcsuite", 's', 0, G_OPTION_ARG_NONE, &option_pcsuite,
				"Enable PC Suite Services server" },
	{ "syncevolution", 'e', 0, G_OPTION_ARG_NONE, &option_syncevolution,
				"Enable OBEX server for SyncEvolution" },
	{ NULL },
};

static void sig_tty(int sig)
{
	if (write(signal_pipe[1], &sig, sizeof(sig)) != sizeof(sig))
		error("unable to write to signal pipe");
}

static gboolean handle_signal(GIOChannel *io, GIOCondition cond,
				void *user_data)
{
	int sig, fd = g_io_channel_unix_get_fd(io);

	if (read(fd, &sig, sizeof(sig)) != sizeof(sig)) {
		error("handle_signal: unable to read signal from pipe");
		return TRUE;
	}

	switch (sig) {
	case SIGUSR1:
		debug("SIGUSR1");
		tty_open_allowed = TRUE;
		if (tty_needs_reinit)
			tty_init(services, option_root, option_capability,
					option_symlinks, option_devnode);
		break;
	case SIGHUP:
		debug("SIGHUP");
		tty_open_allowed = FALSE;
		obex_tty_session_stop();
		break;
	default:
		error("handle_signal: got unexpected signal %d", sig);
		break;
	}

	return TRUE;
}

static int devnode_setup(void)
{
	struct sigaction sa;
	GIOChannel *pipe_io;

	if (pipe(signal_pipe) < 0)
		return -errno;

	pipe_io = g_io_channel_unix_new(signal_pipe[0]);
	g_io_add_watch(pipe_io, G_IO_IN, handle_signal, NULL);
	g_io_channel_unref(pipe_io);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_tty;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	if (option_pcsuite)
		tty_open_allowed = FALSE;

	return tty_init(services, option_root, option_capability,
			option_symlinks, option_devnode);
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
	gint status;
	char *argv[3] = { root_setup, root, NULL };

	if (is_dir(root))
		return TRUE;

	if (root_setup == NULL)
		return FALSE;

	debug("Setting up %s using %s", root, root_setup);

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
				option_pbap == FALSE &&
				option_syncevolution == FALSE) {
		fprintf(stderr, "No server selected (use either "
				"--opp, --ftp, --pbap or --syncevolution)\n");
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

	if (option_root[0] != '/') {
		char *old_root = option_root, *home = getenv("HOME");
		if (home) {
			option_root = g_strdup_printf("%s/%s", home, old_root);
			g_free(old_root);
		}
	}

	if (option_capability == NULL)
		option_capability = g_strdup(DEFAULT_CAP_FILE);

	if (option_opp == TRUE) {
		services |= OBEX_OPP;
		bluetooth_init(OBEX_OPP, option_root, FALSE,
				option_autoaccept, option_symlinks,
				NULL);
	}

	if (option_ftp == TRUE) {
		services |= OBEX_FTP;
		bluetooth_init(OBEX_FTP, option_root, TRUE,
				option_autoaccept, option_symlinks,
				option_capability);
	}

	if (option_pbap == TRUE) {
		services |= OBEX_PBAP;
		bluetooth_init(OBEX_PBAP, NULL, TRUE, FALSE, FALSE, NULL);
	}

	if (option_pcsuite == TRUE) {
		services |= OBEX_PCSUITE;
		bluetooth_init(OBEX_PCSUITE, option_root, TRUE,
				option_autoaccept, option_symlinks,
				option_capability);
	}

	if (option_syncevolution == TRUE) {
		services |= OBEX_SYNCEVOLUTION;
		bluetooth_init(OBEX_SYNCEVOLUTION, NULL, TRUE, FALSE,
							FALSE, NULL);
	}

	if (option_devnode)
		devnode_setup();

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

	bluetooth_exit();

	plugin_cleanup();

	manager_cleanup();

	g_main_loop_unref(main_loop);

	g_free(option_devnode);
	g_free(option_capability);
	g_free(option_root);

	closelog();

	return 0;
}
