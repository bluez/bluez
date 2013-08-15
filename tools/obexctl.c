/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <inttypes.h>

#include <readline/readline.h>
#include <readline/history.h>
#include <glib.h>
#include <gdbus.h>

#include <client/display.h>

/* String display constants */
#define COLORED_NEW	COLOR_GREEN "NEW" COLOR_OFF
#define COLORED_CHG	COLOR_YELLOW "CHG" COLOR_OFF
#define COLORED_DEL	COLOR_RED "DEL" COLOR_OFF

#define PROMPT_ON	COLOR_BLUE "[obex]" COLOR_OFF "# "
#define PROMPT_OFF	"[obex]# "

#define OBEX_SESSION_INTERFACE "org.bluez.obex.Session1"
#define OBEX_TRANSFER_INTERFACE "org.bluez.obex.Transfer1"
#define OBEX_CLIENT_INTERFACE "org.bluez.obex.Client1"

static GMainLoop *main_loop;
static DBusConnection *dbus_conn;
static GDBusProxy *default_session;
static GSList *sessions = NULL;
static GSList *transfers = NULL;
static GDBusProxy *client = NULL;

static void connect_handler(DBusConnection *connection, void *user_data)
{
	rl_set_prompt(PROMPT_ON);
	printf("\r");
	rl_on_new_line();
	rl_redisplay();
}

static void disconnect_handler(DBusConnection *connection, void *user_data)
{
	rl_set_prompt(PROMPT_OFF);
	printf("\r");
	rl_on_new_line();
	rl_redisplay();
}

static void cmd_quit(int argc, char *argv[])
{
	g_main_loop_quit(main_loop);
}

static void connect_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		rl_printf("Failed to connect: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	rl_printf("Connection successful\n");
}

static void append_variant(DBusMessageIter *iter, int type, void *val)
{
	DBusMessageIter value;
	char sig[2] = { type, '\0' };

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, sig, &value);

	dbus_message_iter_append_basic(&value, type, val);

	dbus_message_iter_close_container(iter, &value);
}

static void dict_append_entry(DBusMessageIter *dict, const char *key,
							int type, void *val)
{
	DBusMessageIter entry;

	if (type == DBUS_TYPE_STRING) {
		const char *str = *((const char **) val);
		if (str == NULL)
			return;
	}

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	append_variant(&entry, type, val);

	dbus_message_iter_close_container(dict, &entry);
}

struct connect_args {
	char *dev;
	char *target;
};

static void connect_args_free(void *data)
{
	struct connect_args *args = data;

	g_free(args->dev);
	g_free(args->target);
	g_free(args);
}

static void connect_setup(DBusMessageIter *iter, void *user_data)
{
	struct connect_args *args = user_data;
	DBusMessageIter dict;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &args->dev);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	if (args->target == NULL)
		goto done;

	dict_append_entry(&dict, "Target", DBUS_TYPE_STRING, &args->target);

done:
	dbus_message_iter_close_container(iter, &dict);
}

static void cmd_connect(int argc, char *argv[])
{
	struct connect_args *args;
	const char *target = "opp";

	if (argc < 2) {
		rl_printf("Missing device address argument\n");
		return;
	}

	if (!client) {
		rl_printf("Client proxy not available\n");
		return;
	}

	if (argc > 2)
		target = argv[2];

	args = g_new0(struct connect_args, 1);
	args->dev = g_strdup(argv[1]);
	args->target = g_strdup(target);

	if (g_dbus_proxy_method_call(client, "CreateSession", connect_setup,
			connect_reply, args, connect_args_free) == FALSE) {
		rl_printf("Failed to connect\n");
		return;
	}

	rl_printf("Attempting to connect to %s\n", argv[1]);
}

static void disconnect_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		rl_printf("Failed to disconnect: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	rl_printf("Disconnection successful\n");
}

static void disconnect_setup(DBusMessageIter *iter, void *user_data)
{
	GDBusProxy *proxy = user_data;
	const char *path;

	path = g_dbus_proxy_get_path(proxy);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

static GDBusProxy *find_session(const char *path)
{
	GSList *l;

	for (l = sessions; l; l = g_slist_next(l)) {
		GDBusProxy *proxy = l->data;

		if (strcmp(path, g_dbus_proxy_get_path(proxy)) == 0)
			return proxy;
	}

	return NULL;
}

static void cmd_disconnect(int argc, char *argv[])
{
	GDBusProxy *proxy;

	if (argc > 1)
		proxy = find_session(argv[1]);
	else
		proxy = default_session;

	if (proxy == NULL) {
		rl_printf("Session not available\n");
		return;
	}

	if (g_dbus_proxy_method_call(client, "RemoveSession", disconnect_setup,
				disconnect_reply, proxy, NULL) == FALSE) {
		rl_printf("Failed to disconnect\n");
		return;
	}

	rl_printf("Attempting to disconnect to %s\n",
						g_dbus_proxy_get_path(proxy));
}

static char *proxy_description(GDBusProxy *proxy, const char *title,
						const char *description)
{
	const char *path;

	path = g_dbus_proxy_get_path(proxy);

	return g_strdup_printf("%s%s%s%s %s ",
					description ? "[" : "",
					description ? : "",
					description ? "] " : "",
					title, path);
}

static void print_proxy(GDBusProxy *proxy, const char *title,
							const char *description)
{
	char *str;

	str = proxy_description(proxy, title, description);

	rl_printf("%s%s\n", str, default_session == proxy ? "[default]" : "");

	g_free(str);
}

static void cmd_list(int argc, char *arg[])
{
	GSList *l;

	for (l = sessions; l; l = g_slist_next(l)) {
		GDBusProxy *proxy = l->data;
		print_proxy(proxy, "Session", NULL);
	}
}

static bool check_default_session(void)
{
	if (!default_session) {
		rl_printf("No default session available\n");
		return FALSE;
	}

	return TRUE;
}

static void print_iter(const char *label, const char *name,
						DBusMessageIter *iter)
{
	dbus_bool_t valbool;
	dbus_uint64_t valu64;
	dbus_uint32_t valu32;
	dbus_uint16_t valu16;
	dbus_int16_t vals16;
	const char *valstr;
	DBusMessageIter subiter;

	if (iter == NULL) {
		rl_printf("%s%s is nil\n", label, name);
		return;
	}

	switch (dbus_message_iter_get_arg_type(iter)) {
	case DBUS_TYPE_INVALID:
		rl_printf("%s%s is invalid\n", label, name);
		break;
	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		dbus_message_iter_get_basic(iter, &valstr);
		rl_printf("%s%s: %s\n", label, name, valstr);
		break;
	case DBUS_TYPE_BOOLEAN:
		dbus_message_iter_get_basic(iter, &valbool);
		rl_printf("%s%s: %s\n", label, name,
					valbool == TRUE ? "yes" : "no");
		break;
	case DBUS_TYPE_UINT64:
		dbus_message_iter_get_basic(iter, &valu64);
		rl_printf("%s%s: %" PRIu64 "\n", label, name, valu64);
		break;
	case DBUS_TYPE_UINT32:
		dbus_message_iter_get_basic(iter, &valu32);
		rl_printf("%s%s: 0x%08x\n", label, name, valu32);
		break;
	case DBUS_TYPE_UINT16:
		dbus_message_iter_get_basic(iter, &valu16);
		rl_printf("%s%s: 0x%04x\n", label, name, valu16);
		break;
	case DBUS_TYPE_INT16:
		dbus_message_iter_get_basic(iter, &vals16);
		rl_printf("%s%s: %d\n", label, name, vals16);
		break;
	case DBUS_TYPE_VARIANT:
		dbus_message_iter_recurse(iter, &subiter);
		print_iter(label, name, &subiter);
		break;
	case DBUS_TYPE_ARRAY:
		dbus_message_iter_recurse(iter, &subiter);
		while (dbus_message_iter_get_arg_type(&subiter) !=
							DBUS_TYPE_INVALID) {
			print_iter(label, name, &subiter);
			dbus_message_iter_next(&subiter);
		}
		break;
	case DBUS_TYPE_DICT_ENTRY:
		dbus_message_iter_recurse(iter, &subiter);
		dbus_message_iter_get_basic(&subiter, &valstr);
		dbus_message_iter_next(&subiter);
		print_iter(label, valstr, &subiter);
		break;
	default:
		rl_printf("%s%s has unsupported type\n", label, name);
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

static void cmd_show(int argc, char *argv[])
{
	GDBusProxy *proxy;

	if (argc < 2) {
		if (check_default_session() == FALSE)
			return;

		proxy = default_session;
	} else {
		proxy = find_session(argv[1]);
		if (!proxy) {
			rl_printf("Session %s not available\n", argv[1]);
			return;
		}
	}

	rl_printf("Session %s\n", g_dbus_proxy_get_path(proxy));

	print_property(proxy, "Destination");
	print_property(proxy, "Target");
}

static void cmd_select(int argc, char *argv[])
{
	GDBusProxy *proxy;

	if (argc < 2) {
		rl_printf("Missing session address argument\n");
		return;
	}

	proxy = find_session(argv[1]);
	if (proxy == NULL) {
		rl_printf("Session %s not available\n", argv[1]);
		return;
	}

	if (default_session == proxy)
		return;

	default_session = proxy,
	print_proxy(proxy, "Session", NULL);
}

static const struct {
	const char *cmd;
	const char *arg;
	void (*func) (int argc, char *argv[]);
	const char *desc;
} cmd_table[] = {
	{ "connect",      "<dev> [uuid]", cmd_connect, "Connect session" },
	{ "disconnect",   "[session]", cmd_disconnect, "Disconnect session" },
	{ "list",         NULL,       cmd_list, "List available sessions" },
	{ "show",         "[session]", cmd_show, "Session information" },
	{ "select",       "<session>", cmd_select, "Select default session" },
	{ "quit",         NULL,       cmd_quit, "Quit program" },
	{ "exit",         NULL,       cmd_quit },
	{ "help" },
	{}
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

	if (start == 0) {
		rl_completion_display_matches_hook = NULL;
		matches = rl_completion_matches(text, cmd_generator);
	}

	if (!matches)
		rl_attempted_completion_over = 1;

	return matches;
}

static void rl_handler(char *input)
{
	int argc;
	char **argv = NULL;
	int i;

	if (!input) {
		rl_insert_text("quit");
		rl_redisplay();
		rl_crlf();
		g_main_loop_quit(main_loop);
		return;
	}

	if (!strlen(input))
		goto done;

	add_history(input);

	argv = g_strsplit(input, " ", -1);
	if (argv == NULL)
		goto done;

	for (argc = 0; argv[argc];)
		argc++;

	if (argc == 0)
		goto done;

	for (i = 0; cmd_table[i].cmd; i++) {
		if (strcmp(argv[0], cmd_table[i].cmd))
			continue;

		if (cmd_table[i].func) {
			cmd_table[i].func(argc, argv);
			goto done;
		}
	}

	if (strcmp(argv[0], "help")) {
		printf("Invalid command\n");
		goto done;
	}

	printf("Available commands:\n");

	for (i = 0; cmd_table[i].cmd; i++) {
		if (cmd_table[i].desc)
			printf("  %s %-*s %s\n", cmd_table[i].cmd,
					(int)(25 - strlen(cmd_table[i].cmd)),
					cmd_table[i].arg ? : "",
					cmd_table[i].desc ? : "");
	}

done:
	g_strfreev(argv);
	free(input);
}

static gboolean option_version = FALSE;

static GOptionEntry options[] = {
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit" },
	{ NULL },
};

static gboolean signal_handler(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	static unsigned int __terminated = 0;
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

static void client_added(GDBusProxy *proxy)
{
	if (client == NULL)
		client = proxy;

	print_proxy(proxy, "Client", COLORED_NEW);
}

static void session_added(GDBusProxy *proxy)
{
	sessions = g_slist_append(sessions, proxy);

	if (default_session == NULL)
		default_session = proxy;

	print_proxy(proxy, "Session", COLORED_NEW);
}

static void transfer_added(GDBusProxy *proxy)
{
	transfers = g_slist_append(transfers, proxy);

	print_proxy(proxy, "Transfer", COLORED_NEW);
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, OBEX_CLIENT_INTERFACE))
		client_added(proxy);
	else if (!strcmp(interface, OBEX_SESSION_INTERFACE))
		session_added(proxy);
	else if (!strcmp(interface, OBEX_TRANSFER_INTERFACE))
		transfer_added(proxy);
}

static void client_removed(GDBusProxy *proxy)
{
	print_proxy(proxy, "Client", COLORED_DEL);

	if (client == proxy)
		client = NULL;
}

static void session_removed(GDBusProxy *proxy)
{
	print_proxy(proxy, "Session", COLORED_DEL);

	if (default_session == proxy)
		default_session = NULL;

	sessions = g_slist_remove(sessions, proxy);
}

static void transfer_removed(GDBusProxy *proxy)
{
	print_proxy(proxy, "Transfer", COLORED_DEL);

	transfers = g_slist_remove(transfers, proxy);
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, OBEX_CLIENT_INTERFACE))
		client_removed(proxy);
	else if (!strcmp(interface, OBEX_SESSION_INTERFACE))
		session_removed(proxy);
	else if (!strcmp(interface, OBEX_TRANSFER_INTERFACE))
		transfer_removed(proxy);
}

static void session_property_changed(GDBusProxy *proxy, const char *name,
						DBusMessageIter *iter)
{
	char *str;

	str = proxy_description(proxy, "Session", COLORED_CHG);
	print_iter(str, name, iter);
	g_free(str);
}

static void transfer_property_changed(GDBusProxy *proxy, const char *name,
						DBusMessageIter *iter)
{
	char *str;

	str = proxy_description(proxy, "Transfer", COLORED_CHG);
	print_iter(str, name, iter);
	g_free(str);
}

static void property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, OBEX_SESSION_INTERFACE))
		session_property_changed(proxy, name, iter);
	else if (!strcmp(interface, OBEX_TRANSFER_INTERFACE))
		transfer_property_changed(proxy, name, iter);
}

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
	dbus_conn = g_dbus_setup_bus(DBUS_BUS_SESSION, NULL, NULL);

	rl_attempted_completion_function = cmd_completion;

	rl_erase_empty_line = 1;
	rl_callback_handler_install(NULL, rl_handler);

	rl_set_prompt(PROMPT_OFF);
	rl_redisplay();

	input = setup_standard_input();
	signal = setup_signalfd();
	client = g_dbus_client_new(dbus_conn, "org.bluez.obex",
							"/org/bluez/obex");

	g_dbus_client_set_connect_watch(client, connect_handler, NULL);
	g_dbus_client_set_disconnect_watch(client, disconnect_handler, NULL);

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
