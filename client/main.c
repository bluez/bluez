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

#include "display.h"

static GMainLoop *main_loop;
static DBusConnection *dbus_conn;

static GList *ctrl_list;
static GDBusProxy *default_ctrl;

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

static void print_iter(const char *label, const char *name,
						DBusMessageIter *iter)
{
	dbus_bool_t valbool;
	dbus_uint32_t val32;
	const char *valstr;

	switch (dbus_message_iter_get_arg_type(iter)) {
	case DBUS_TYPE_INVALID:
		printf("%s%s is inavlid\n", label, name);
		break;
	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		dbus_message_iter_get_basic(iter, &valstr);
		printf("%s%s: %s\n", label, name, valstr);
		break;
	case DBUS_TYPE_BOOLEAN:
		dbus_message_iter_get_basic(iter, &valbool);
		printf("%s%s: %s\n", label, name,
					valbool == TRUE ? "yes" : "no");
		break;
	case DBUS_TYPE_UINT32:
		dbus_message_iter_get_basic(iter, &val32);
		printf("%s%s: 0x%06x\n", label, name, val32);
		break;
	}
}

static void print_property(GDBusProxy *proxy, const char *name)
{
	DBusMessageIter iter;

	if (g_dbus_proxy_get_property(proxy, name, &iter) == FALSE)
		return;

	print_iter("\t", name, &iter);
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.Adapter1")) {
		ctrl_list = g_list_append(ctrl_list, proxy);

		if (!default_ctrl)
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

static void property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.Adapter1")) {
		DBusMessageIter addr_iter;

		begin_message();

		if (g_dbus_proxy_get_property(proxy, "Address",
						&addr_iter) == TRUE) {
			const char *address;

			dbus_message_iter_get_basic(&addr_iter, &address);
			printf("[CHG] Controller %s ", address);
		}

		print_iter("", name, iter);
		end_message();
	}
}

static void message_handler(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	begin_message();
	printf("[SIGNAL] %s.%s\n", dbus_message_get_interface(message),
					dbus_message_get_member(message));
	end_message();
}

static GDBusProxy *find_proxy_by_address(const char *address)
{
	GList *list;

	for (list = g_list_first(ctrl_list); list; list = g_list_next(list)) {
		GDBusProxy *proxy = list->data;
		DBusMessageIter iter;
		const char *str;

		if (g_dbus_proxy_get_property(proxy, "Address", &iter) == FALSE)
			continue;

		dbus_message_iter_get_basic(&iter, &str);

		if (!strcmp(address, str))
			return proxy;
	}

	return NULL;
}

static gboolean check_default_ctrl(void)
{
	if (!default_ctrl) {
		printf("No default controller available\n");
		return FALSE;
	}

	return TRUE;
}

static gboolean parse_argument_on_off(const char *arg, dbus_bool_t *value)
{
	if (!arg || !strlen(arg)) {
		printf("Missing on/off argument\n");
		return FALSE;
	}

	if (!strcmp(arg, "on") || !strcmp(arg, "yes")) {
		*value = TRUE;
		return TRUE;
	}

	if (!strcmp(arg, "off") || !strcmp(arg, "no")) {
		*value = FALSE;
		return TRUE;
	}

	printf("Invalid argument %s\n", arg);
	return FALSE;
}

static void cmd_list(const char *arg)
{
	GList *list;

	for (list = g_list_first(ctrl_list); list; list = g_list_next(list)) {
		GDBusProxy *proxy = list->data;
		print_adapter(proxy, NULL);
	}
}

static void cmd_info(const char *arg)
{
	GDBusProxy *proxy;
	DBusMessageIter iter, value;
	const char *address;

	if (!arg || !strlen(arg)) {
		if (check_default_ctrl() == FALSE)
			return;

		proxy = default_ctrl;
	} else {
		proxy = find_proxy_by_address(arg);
		if (!proxy) {
			printf("Controller %s not available\n", arg);
			return;
		}
	}

	if (g_dbus_proxy_get_property(proxy, "Address", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &address);
	printf("Controller %s\n", address);

	print_property(proxy, "Name");
	print_property(proxy, "Class");
	print_property(proxy, "Powered");
	print_property(proxy, "Discoverable");
	print_property(proxy, "Pairable");

	if (g_dbus_proxy_get_property(proxy, "UUIDs", &iter) == FALSE)
		return;

	dbus_message_iter_recurse(&iter, &value);

	while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_STRING) {
		const char *str;
		dbus_message_iter_get_basic(&value, &str);
		printf("\tUUID: %s\n", str);
		dbus_message_iter_next(&value);
	}
}

static void cmd_select(const char *arg)
{
	GDBusProxy *proxy;

	if (!arg || !strlen(arg)) {
		printf("Missing controller address argument\n");
		return;
	}

	proxy = find_proxy_by_address(arg);
	if (!proxy) {
		printf("Controller %s not available\n", arg);
		return;
	}

	default_ctrl = proxy;
	print_adapter(proxy, NULL);
}

static void generic_callback(const DBusError *error, void *user_data)
{
	char *str = user_data;

	begin_message();

	if (dbus_error_is_set(error))
		printf("Failed to set %s: %s\n", str, error->name);
	else
		printf("Changing %s succeeded\n", str);

	end_message();
}

static void cmd_power(const char *arg)
{
	dbus_bool_t powered;
	char *str;

	if (parse_argument_on_off(arg, &powered) == FALSE)
		return;

	if (check_default_ctrl() == FALSE)
		return;

	str = g_strdup_printf("power %s", powered == TRUE ? "on" : "off");

	if (g_dbus_proxy_set_property_basic(default_ctrl, "Powered",
					DBUS_TYPE_BOOLEAN, &powered,
					generic_callback, str, g_free) == TRUE)
		return;

	g_free(str);
}

static void cmd_pairable(const char *arg)
{
	dbus_bool_t pairable;
	char *str;

	if (parse_argument_on_off(arg, &pairable) == FALSE)
		return;

	if (check_default_ctrl() == FALSE)
		return;

	str = g_strdup_printf("pairable %s", pairable == TRUE ? "on" : "off");

	if (g_dbus_proxy_set_property_basic(default_ctrl, "Pairable",
					DBUS_TYPE_BOOLEAN, &pairable,
					generic_callback, str, g_free) == TRUE)
		return;

	g_free(str);
}

static void cmd_discoverable(const char *arg)
{
	dbus_bool_t discoverable;
	char *str;

	if (parse_argument_on_off(arg, &discoverable) == FALSE)
		return;

	if (check_default_ctrl() == FALSE)
		return;

	str = g_strdup_printf("discoverable %s",
				discoverable == TRUE ? "on" : "off");

	if (g_dbus_proxy_set_property_basic(default_ctrl, "Discoverable",
					DBUS_TYPE_BOOLEAN, &discoverable,
					generic_callback, str, g_free) == TRUE)
		return;

	g_free(str);
}

static void cmd_name(const char *arg)
{
	char *name;

	if (!arg || !strlen(arg)) {
		printf("Missing name argument\n");
		return;
	}

	if (!default_ctrl) {
		printf("No default controller available\n");
		return;
	}

	name = g_strdup(arg);

	if (g_dbus_proxy_set_property_basic(default_ctrl, "Name",
					DBUS_TYPE_STRING, &name,
					generic_callback, name, g_free) == TRUE)
		return;

	g_free(name);
}

static void cmd_quit(const char *arg)
{
	g_main_loop_quit(main_loop);
}

static char *ctrl_generator(const char *text, int state)
{
	static int index, len;
	GList *list;

	if (!state) {
		index = 0;
		len = strlen(text);
	}


	for (list = g_list_nth(ctrl_list, index); list;
						list = g_list_next(list)) {
		GDBusProxy *proxy = list->data;
		DBusMessageIter iter;
		const char *address;

		index++;

		if (g_dbus_proxy_get_property(proxy, "Address", &iter) == FALSE)
			continue;

		dbus_message_iter_get_basic(&iter, &address);

		if (!strncmp(address, text, len))
			return strdup(address);
        }

	return NULL;
}

static const struct {
	const char *cmd;
	const char *arg;
	void (*func) (const char *arg);
	const char *desc;
	char * (*gen) (const char *text, int state);
	void (*disp) (char **matches, int num_matches, int max_length);
} cmd_table[] = {
	{ "list",         NULL,       cmd_list, "List available controllers" },
	{ "info",         "[ctrl]",   cmd_info, "Controller information",
							ctrl_generator },
	{ "select",       "<ctrl>",   cmd_select, "Select default controller",
							ctrl_generator },
	{ "power",        "<on/off>", cmd_power, "Set controller power" },
	{ "name",         "<name>",   cmd_name,  "Set controller local name" },
	{ "pairable",     "<on/off>", cmd_pairable,
					"Set controller pairable mode" },
	{ "discoverable", "<on/off>", cmd_discoverable,
					"Set controller discoverable mode" },
	{ "quit",   NULL,     cmd_quit,   "Quit program" },
	{ "exit",   NULL,     cmd_quit },
	{ "help" },
	{ }
};

static char *cmd_generator(const char *text, int state)
{
	static int index, len;
	const char *cmd;

	if (!state) {
		index = 0;
		len = strlen(text);
	}

	while ((cmd = cmd_table[index].cmd)) {
		index++;

		if (!strncmp(cmd, text, len))
			return strdup(cmd);
	}

	return NULL;
}

static char **cmd_completion(const char *text, int start, int end)
{
	char **matches = NULL;

	if (start > 0) {
		int i;

		for (i = 0; cmd_table[i].cmd; i++) {
			if (strncmp(cmd_table[i].cmd,
					rl_line_buffer, start - 1))
				continue;

			if (!cmd_table[i].gen)
				continue;

			rl_completion_display_matches_hook = cmd_table[i].disp;
			matches = rl_completion_matches(text, cmd_table[i].gen);
			break;
		}
	} else {
		rl_completion_display_matches_hook = NULL;
		matches = rl_completion_matches(text, cmd_generator);
	}

	if (!matches)
		rl_attempted_completion_over = 1;

	return matches;
}

static void rl_handler(char *input)
{
	char *cmd, *arg;
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

	cmd = strtok_r(input, " ", &arg);
	if (!cmd)
		return;

	if (arg) {
		int len = strlen(arg);
		if (len > 0 && arg[len - 1] == ' ')
			arg[len - 1] = '\0';
	}

	for (i = 0; cmd_table[i].cmd; i++) {
		if (strcmp(cmd, cmd_table[i].cmd))
			continue;

		if (cmd_table[i].func) {
			cmd_table[i].func(arg);
			return;
		}
	}

	if (strcmp(cmd, "help")) {
		printf("Invalid command\n");
		return;
	}

	printf("Available commands:\n");

	for (i = 0; cmd_table[i].cmd; i++) {
		if (cmd_table[i].desc)
			printf("\t%s %s\t%s\n", cmd_table[i].cmd,
						cmd_table[i].arg ? : "    ",
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
		rl_replace_line("", 0);
		rl_crlf();
		rl_on_new_line();
		rl_redisplay();
		break;
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

	rl_attempted_completion_function = cmd_completion;

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

	g_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
							property_changed, NULL);

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
