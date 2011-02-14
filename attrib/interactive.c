/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
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
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <glib.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "btio.h"
#include "gattrib.h"
#include "gatttool.h"

static GIOChannel *iochannel = NULL;
static GAttrib *attrib = NULL;
static GMainLoop *event_loop;
static GString *prompt;

static gchar *opt_dst = NULL;
static gboolean opt_le = FALSE;

static void cmd_help(int argcp, char **argvp);

enum state {
	STATE_DISCONNECTED,
	STATE_CONNECTING,
	STATE_CONNECTED
} conn_state;

static char *get_prompt(void)
{
	if (conn_state == STATE_CONNECTING) {
		g_string_assign(prompt, "Connecting... ");
		return prompt->str;
	}

	if (conn_state == STATE_CONNECTED)
		g_string_assign(prompt, "[CON]");
	else
		g_string_assign(prompt, "[   ]");

	if (opt_dst)
		g_string_append_printf(prompt, "[%17s]", opt_dst);
	else
		g_string_append_printf(prompt, "[%17s]", "");

	if (opt_le)
		g_string_append(prompt, "[LE]");
	else
		g_string_append(prompt, "[BR]");

	g_string_append(prompt, "> ");

	return prompt->str;
}


static void set_state(enum state st)
{
	conn_state = st;
	rl_set_prompt(get_prompt());
	rl_redisplay();
}

static void connect_cb(GIOChannel *io, GError *err, gpointer user_data)
{
	if (err) {
		printf("connect error: %s\n", err->message);
		set_state(STATE_DISCONNECTED);
		return;
	}

	attrib = g_attrib_new(iochannel);
	set_state(STATE_CONNECTED);
}

static void cmd_exit(int argcp, char **argvp)
{
	rl_callback_handler_remove();
	g_main_loop_quit(event_loop);
}

static void cmd_connect(int argcp, char **argvp)
{
	if (conn_state != STATE_DISCONNECTED)
		return;

	if (argcp > 1) {
		g_free(opt_dst);
		opt_dst = strdup(argvp[1]);
	}

	if (opt_dst == NULL) {
		printf("Remote Bluetooth address required\n");
		return;
	}

	set_state(STATE_CONNECTING);
	iochannel = do_connect(opt_dst, opt_le, connect_cb);
	if (iochannel == NULL)
		set_state(STATE_DISCONNECTED);

	return;
}

static void cmd_disconnect(int argcp, char **argvp)
{
	if (conn_state == STATE_DISCONNECTED)
		return;

	g_attrib_unref(attrib);
	attrib = NULL;

	g_io_channel_shutdown(iochannel, FALSE, NULL);
	g_io_channel_unref(iochannel);
	iochannel = NULL;

	set_state(STATE_DISCONNECTED);

	return;
}

static struct {
	const char *cmd;
	void (*func)(int argcp, char **argvp);
	const char *desc;
} commands[] = {
	{ "help",	cmd_help,	"Show this help"},
	{ "exit",	cmd_exit,	"Exit interactive mode"},
	{ "connect",	cmd_connect,	"Connect to a remote device"},
	{ "disconnect",	cmd_disconnect,	"Disconnect from a remote device"},
	{ NULL, NULL, NULL}
};

static void cmd_help(int argcp, char **argvp)
{
	int i;

	for (i = 0; commands[i].cmd; i++)
		printf("%-12s\t%s\n", commands[i].cmd, commands[i].desc);
}

static void parse_line(char *line_read)
{
	gchar **argvp;
	int argcp;
	int i;

	if (line_read == NULL) {
		printf("\n");
		cmd_exit(0, NULL);
		return;
	}

	line_read = g_strstrip(line_read);

	if (*line_read == '\0')
		return;

	add_history(line_read);

	g_shell_parse_argv(line_read, &argcp, &argvp, NULL);

	for (i = 0; commands[i].cmd; i++)
		if (strcasecmp(commands[i].cmd, argvp[0]) == 0)
			break;

	if (commands[i].cmd)
		commands[i].func(argcp, argvp);
	else
		printf("%s: command not found\n", argvp[0]);

	g_strfreev(argvp);
}

static gboolean prompt_read(GIOChannel *chan, GIOCondition cond,
							gpointer user_data)
{
	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	rl_callback_read_char();

	return TRUE;
}

int interactive(gchar *dst, gboolean le)
{
	GIOChannel *pchan;
	gint events;

	opt_dst = dst;
	opt_le = le;

	prompt = g_string_new(NULL);

	event_loop = g_main_loop_new(NULL, FALSE);

	pchan = g_io_channel_unix_new(fileno(stdin));
	g_io_channel_set_close_on_unref(pchan, TRUE);
	events = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	g_io_add_watch(pchan, events, prompt_read, NULL);

	rl_callback_handler_install(get_prompt(), parse_line);

	g_main_loop_run(event_loop);

	rl_callback_handler_remove();
	cmd_disconnect(0, NULL);
	g_io_channel_unref(pchan);
	g_main_loop_unref(event_loop);
	g_string_free(prompt, TRUE);

	return 0;
}
