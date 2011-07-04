/*
 *
 *  OBEX library with GLib integration
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <gobex/gobex.h>

static GMainLoop *main_loop = NULL;
static GObex *obex = NULL;

static gboolean option_packet = FALSE;
static gboolean option_bluetooth = FALSE;

static void sig_term(int sig)
{
	g_print("Terminating due to signal %d\n", sig);
	g_main_loop_quit(main_loop);
}

static GOptionEntry options[] = {
	{ "unix", 'u', G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE,
			&option_bluetooth, "Use a UNIX socket" },
	{ "bluetooth", 'b', 0, G_OPTION_ARG_NONE,
			&option_bluetooth, "Use Bluetooth" },
	{ "packet", 'p', 0, G_OPTION_ARG_NONE,
			&option_packet, "Packet based transport" },
	{ "stream", 's', G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE,
			&option_packet, "Stream based transport" },
	{ NULL },
};

static void disconn_func(GObex *obex, GError *err, gpointer user_data)
{
	g_printerr("Disconnected\n");
	g_main_loop_quit(main_loop);
}

static GIOChannel *unix_connect(void)
{
	GIOChannel *io;
	struct sockaddr_un addr = {
		AF_UNIX, "\0/gobex/server"
	};
	int sk, err, sock_type;

	if (option_packet)
		sock_type = SOCK_SEQPACKET;
	else
		sock_type = SOCK_STREAM;

	sk = socket(PF_LOCAL, sock_type, 0);
	if (sk < 0) {
		err = errno;
		g_printerr("Can't create unix socket: %s (%d)\n",
						strerror(err), err);
		return NULL;
	}

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		g_printerr("connect: %s (%d)\n", strerror(err), err);
		return NULL;
	}

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_flags(io, G_IO_FLAG_NONBLOCK, NULL);
	g_io_channel_set_close_on_unref(io, TRUE);

	g_print("Unix socket created: %d\n", sk);

	return io;
}

static void cmd_connect(int argc, char **argv)
{
}

static void cmd_help(int argc, char **argv);

static void cmd_exit(int argc, char **argv)
{
	g_main_loop_quit(main_loop);
}

static struct {
	const char *cmd;
	void (*func)(int argc, char **argv);
	const char *params;
	const char *desc;
} commands[] = {
	{ "help",	cmd_help,	"",		"Show this help"},
	{ "exit",	cmd_exit,	"",		"Exit application" },
	{ "quit",	cmd_exit,	"",		"Exit application" },
	{ "connect",	cmd_connect,	"[target]",	"OBEX Connect" },
	{ NULL },
};

static void cmd_help(int argc, char **argv)
{
	int i;

	for (i = 0; commands[i].cmd; i++)
		printf("%-15s %-30s %s\n", commands[i].cmd,
				commands[i].params, commands[i].desc);
}

static void parse_line(char *line_read)
{
	gchar **argvp;
	int argcp;
	int i;

	if (line_read == NULL) {
		g_print("\n");
		g_main_loop_quit(main_loop);
		return;
	}

	line_read = g_strstrip(line_read);

	if (*line_read == '\0') {
		free(line_read);
		return;
	}

	add_history(line_read);

	g_shell_parse_argv(line_read, &argcp, &argvp, NULL);

	free(line_read);

	for (i = 0; commands[i].cmd; i++)
		if (strcasecmp(commands[i].cmd, argvp[0]) == 0)
			break;

	if (commands[i].cmd)
		commands[i].func(argcp, argvp);
	else
		g_print("%s: command not found\n", argvp[0]);

	g_strfreev(argvp);
}

static gboolean prompt_read(GIOChannel *chan, GIOCondition cond,
							gpointer user_data)
{
	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		g_main_loop_quit(main_loop);
		return FALSE;
	}

	rl_callback_read_char();

	return TRUE;
}

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *err = NULL;
	struct sigaction sa;
	GIOChannel *io;
	GIOCondition events;
	GObexTransportType transport;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	g_option_context_parse(context, &argc, &argv, &err);
	if (err != NULL) {
		g_printerr("%s\n", err->message);
		g_error_free(err);
		exit(EXIT_FAILURE);
	}

	io = unix_connect();
	if (io == NULL)
		exit(EXIT_FAILURE);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	main_loop = g_main_loop_new(NULL, FALSE);

	if (option_packet)
		transport = G_OBEX_TRANSPORT_PACKET;
	else
		transport = G_OBEX_TRANSPORT_STREAM;

	obex = g_obex_new(io, transport, -1, -1);
	g_io_channel_unref(io);

	g_obex_set_disconnect_function(obex, disconn_func, NULL);

	io = g_io_channel_unix_new(STDIN_FILENO);
	g_io_channel_set_close_on_unref(io, TRUE);
	events = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	g_io_add_watch(io, events, prompt_read, NULL);
	g_io_channel_unref(io);
	rl_callback_handler_install("client> ", parse_line);

	g_main_loop_run(main_loop);

	rl_callback_handler_remove();
	clear_history();
	g_obex_unref(obex);
	g_option_context_free(context);
	g_main_loop_unref(main_loop);

	exit(EXIT_SUCCESS);
}
