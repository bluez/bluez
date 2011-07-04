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

#include <gobex/gobex.h>

static GMainLoop *main_loop = NULL;

static GSList *clients = NULL;

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
	g_print("Client disconnected\n");
	clients = g_slist_remove(clients, obex);
	g_obex_unref(obex);
}

static gboolean unix_accept(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int sk, cli_sk;
	GIOChannel *io;
	GObex *obex;
	GObexTransportType transport;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		g_io_channel_shutdown(chan, TRUE, NULL);
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(chan);

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	cli_sk = accept(sk, (struct sockaddr *) &addr, &addrlen);
	if (cli_sk < 0) {
		g_printerr("accept: %s (%d)\n", strerror(errno), errno);
		return TRUE;
	}

	g_print("Accepted new client connection on unix socket (fd=%d)\n",
								cli_sk);

	io = g_io_channel_unix_new(cli_sk);

	g_io_channel_set_flags(io, G_IO_FLAG_NONBLOCK, NULL);
	g_io_channel_set_close_on_unref(io, TRUE);

	if (option_packet)
		transport = G_OBEX_TRANSPORT_PACKET;
	else
		transport = G_OBEX_TRANSPORT_STREAM;

	obex = g_obex_new(io, transport, -1, -1);
	g_io_channel_unref(io);
	g_obex_set_disconnect_function(obex, disconn_func, NULL);
	clients = g_slist_append(clients, obex);;

	return TRUE;
}

static GIOChannel *unix_listen(void)
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

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		g_printerr("Can't bind unix socket: %s (%d)\n",
						strerror(errno), errno);
		close(sk);
		return NULL;
	}

	if (listen(sk, 1) < 0) {
		g_printerr("Can't listen on unix socket: %s (%d)\n",
						strerror(errno), errno);
		close(sk);
		return NULL;
	}

	io = g_io_channel_unix_new(sk);
	g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
							unix_accept, NULL);

	g_io_channel_set_flags(io, G_IO_FLAG_NONBLOCK, NULL);
	g_io_channel_set_close_on_unref(io, TRUE);

	g_print("Unix socket created: %d\n", sk);

	return io;
}

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *err = NULL;
	struct sigaction sa;
	GIOChannel *io;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	g_option_context_parse(context, &argc, &argv, &err);
	if (err != NULL) {
		g_printerr("%s\n", err->message);
		g_error_free(err);
		exit(EXIT_FAILURE);
	}

	io = unix_listen();
	if (io == NULL)
		exit(EXIT_FAILURE);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	main_loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(main_loop);

	g_io_channel_unref(io);
	g_slist_free_full(clients, (GDestroyNotify) g_obex_unref);
	g_option_context_free(context);
	g_main_loop_unref(main_loop);

	exit(EXIT_SUCCESS);
}
