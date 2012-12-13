/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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
#include <signal.h>
#include <sys/signalfd.h>

#include <readline/readline.h>
#include <readline/history.h>
#include <glib.h>
#include <gdbus.h>

#define COLOR_OFF	"\x1B[0m"
#define COLOR_BLUE	"\x1B[0;34m"

static GMainLoop *main_loop;
static DBusConnection *dbus_conn;

static GList *ctrl_list;
static GDBusProxy *default_ctrl;

static inline void begin_message(void)
{
	rl_message("");
	printf("\r%*c\r", rl_end, ' ');
}

static inline void end_message(void)
{
	rl_clear_message();
}

static void connect_handler(DBusConnection *connection, void *user_data)
{
	rl_set_prompt(COLOR_BLUE "[bluetooth]" COLOR_OFF "# ");
	printf("\r");
	rl_on_new_line();
	rl_redisplay();
}

static void disconnect_handler(DBusConnection *connection, void *user_data)
{
	rl_set_prompt("[bluetooth]# ");
	printf("\r");
	rl_on_new_line();
	rl_redisplay();
}

static void print_adapter(GDBusProxy *proxy, const char *description)
{
	DBusMessageIter iter;
	const char *address, *name;

	if (g_dbus_proxy_get_property(proxy, "Address", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &address);

	if (g_dbus_proxy_get_property(proxy, "Name", &iter) == TRUE)
		dbus_message_iter_get_basic(&iter, &name);
	else
		name = "<unknown>";

	if (description != NULL)
		printf("[%s] ", description);

	printf("Controller %s %s %s\n", address, name,
				default_ctrl == proxy ? "[default]" : "");

}

static void print_property(GDBusProxy *proxy, const char *name)
{
	DBusMessageIter iter;
	dbus_bool_t valbool;
	dbus_uint32_t val32;
	const char *valstr;

	if (g_dbus_proxy_get_property(proxy, name, &iter) == FALSE)
		return;

	switch (dbus_message_iter_get_arg_type(&iter)) {
	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		dbus_message_iter_get_basic(&iter, &valstr);
		printf("\t%s: %s\n", name, valstr);
		break;
	case DBUS_TYPE_BOOLEAN:
		dbus_message_iter_get_basic(&iter, &valbool);
		printf("\t%s: %s\n", name, valbool == TRUE ? "yes" : "no");
		break;
	case DBUS_TYPE_UINT32:
		dbus_message_iter_get_basic(&iter, &val32);
		printf("\t%s: 0x%06x\n", name, val32);
		break;
	}
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.Adapter1")) {
		ctrl_list = g_list_append(ctrl_list, proxy);

		if (default_ctrl == NULL)
			default_ctrl = proxy;

		begin_message();
		print_adapter(proxy, "NEW");
		end_message();
	}
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.Adapter1")) {
		ctrl_list = g_list_remove(ctrl_list, proxy);

		begin_message();
		print_adapter(proxy, "DEL");
		end_message();

		if (default_ctrl == proxy)
			default_ctrl = NULL;
	}
}

static void message_handler(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
}

static void cmd_list(const void *arg)
{
	GList *list;

	for (list = g_list_first(ctrl_list); list; list = g_list_next(list)) {
		GDBusProxy *proxy = list->data;
		print_adapter(proxy, NULL);
	}
}

static void cmd_info(const void *arg)
{
	DBusMessageIter iter, value;
	const char *address;

	if (default_ctrl == NULL) {
		printf("No default controller available\n");
		return;
	}

	if (g_dbus_proxy_get_property(default_ctrl, "Address", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &address);
	printf("Controller %s\n", address);

	print_property(default_ctrl, "Name");
	print_property(default_ctrl, "Class");
	print_property(default_ctrl, "Powered");
	print_property(default_ctrl, "Discoverable");
	print_property(default_ctrl, "Pairable");

	if (g_dbus_proxy_get_property(default_ctrl, "UUIDs", &iter) == FALSE)
		return;

	dbus_message_iter_recurse(&iter, &value);

	while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_STRING) {
		const char *str;
		dbus_message_iter_get_basic(&value, &str);
		printf("\tUUID: %s\n", str);
		dbus_message_iter_next(&value);
	}
}

static void cmd_quit(const void *arg)
{
	g_main_loop_quit(main_loop);
}

static const struct {
	const char *str;
	void (*func) (const void *arg);
	const char *desc;
} cmd_table[] = {
	{ "list",  cmd_list,  "List controllers" },
	{ "info",  cmd_info,  "Controller info"  },
	{ "quit",  cmd_quit,  "Quit program"     },
	{ "exit",  cmd_quit                      },
	{ }
};

static void rl_handler(char *input)
{
	int i;

	if (!input) {
		rl_insert_text("quit");
		rl_redisplay();
		rl_crlf();
		g_main_loop_quit(main_loop);
		return;
	}

	if (!strlen(input))
		return;

	add_history(input);

	for (i = 0; cmd_table[i].str; i++) {
		if (strcmp(input, cmd_table[i].str))
			continue;

		cmd_table[i].func(cmd_table[i].str);
		return;
	}

	if (strcmp(input, "help")) {
		printf("Invalid command\n");
		return;
	}

	printf("Available commands:\n");

	for (i = 0; cmd_table[i].str; i++) {
		if (cmd_table[i].desc)
			printf("\t%s\t%s\n", cmd_table[i].str,
						cmd_table[i].desc);
	}
}

static gboolean input_handler(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	if (condition & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		g_main_loop_quit(main_loop);
		return FALSE;
	}

	rl_callback_read_char();
	return TRUE;
}

static guint setup_standard_input(void)
{
	GIOChannel *channel;
	guint source;

	channel = g_io_channel_unix_new(fileno(stdin));

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				input_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

static unsigned int __terminated = 0;

static gboolean signal_handler(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct signalfd_siginfo si;
	ssize_t result;
	int fd;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		g_main_loop_quit(main_loop);
		return FALSE;
	}

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, &si, sizeof(si));
	if (result != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		if (__terminated == 0) {
			rl_replace_line("", 0);
			rl_crlf();
			g_main_loop_quit(main_loop);
		}

		__terminated = 1;
		break;
	}

	return TRUE;
}

static guint setup_signalfd(void)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("Failed to set signal mask");
		return 0;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		perror("Failed to create signal descriptor");
		return 0;
	}

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

static gboolean option_version = FALSE;

static GOptionEntry options[] = {
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	GDBusClient *client;
	guint signal, input;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (g_option_context_parse(context, &argc, &argv, &error) == FALSE) {
		if (error != NULL) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		exit(1);
	}

	g_option_context_free(context);

	if (option_version == TRUE) {
		printf("%s\n", VERSION);
		exit(0);
	}

	main_loop = g_main_loop_new(NULL, FALSE);
	dbus_conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);

	rl_erase_empty_line = 1;
	rl_callback_handler_install(NULL, rl_handler);

	rl_set_prompt("[bluetooth]# ");
	rl_redisplay();

        input = setup_standard_input();
        signal = setup_signalfd();
	client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");

	g_dbus_client_set_connect_watch(client, connect_handler, NULL);
	g_dbus_client_set_disconnect_watch(client, disconnect_handler, NULL);
	g_dbus_client_set_signal_watch(client, message_handler, NULL);

	g_dbus_client_set_proxy_handlers(client, proxy_added,
							proxy_removed, NULL);

	g_main_loop_run(main_loop);

	g_dbus_client_unref(client);
	g_source_remove(signal);
	g_source_remove(input);

	rl_message("");
	rl_callback_handler_remove();

	dbus_connection_unref(dbus_conn);
	g_main_loop_unref(main_loop);

	return 0;
}
