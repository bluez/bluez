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
#include <signal.h>
#include <getopt.h>
#include <string.h>

#include <dbus/dbus.h>
#include <glib.h>
#include <gdbus/gdbus.h>

#define BLUEZ_BUS_NAME "org.bluez"
#define BLUEZ_PATH "/org/bluez"
#define BLUEZ_ADAPTER_INTERFACE "org.bluez.Adapter1"
#define BLUEZ_MEDIA_INTERFACE "org.bluez.Media1"
#define MPRIS_PLAYER_INTERFACE "org.mpris.MediaPlayer2.Player"
#define MPRIS_PLAYER_PATH "/org/mpris/MediaPlayer2"

static GMainLoop *main_loop;
static GDBusProxy *adapter = NULL;
static DBusConnection *sys = NULL;
static DBusConnection *session = NULL;

static void dict_append_entry(DBusMessageIter *dict, const char *key, int type,
								void *val);

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static DBusMessage *get_all(DBusConnection *conn, const char *name)
{
	DBusMessage *msg, *reply;
	DBusError err;
	const char *iface = MPRIS_PLAYER_INTERFACE;

	msg = dbus_message_new_method_call(name, MPRIS_PLAYER_PATH,
					DBUS_INTERFACE_PROPERTIES, "GetAll");
	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return NULL;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &iface,
					DBUS_TYPE_INVALID);

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		return NULL;
	}

	return reply;
}

static void append_variant(DBusMessageIter *iter, int type, void *val)
{
	DBusMessageIter value;
	char sig[2] = { type, '\0' };

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, sig, &value);

	dbus_message_iter_append_basic(&value, type, val);

	dbus_message_iter_close_container(iter, &value);
}

static void append_array_variant(DBusMessageIter *iter, int type, void *val,
							int n_elements)
{
	DBusMessageIter variant, array;
	char type_sig[2] = { type, '\0' };
	char array_sig[3] = { DBUS_TYPE_ARRAY, type, '\0' };

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
						array_sig, &variant);

	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						type_sig, &array);

	if (dbus_type_is_fixed(type) == TRUE) {
		dbus_message_iter_append_fixed_array(&array, type, val,
							n_elements);
	} else if (type == DBUS_TYPE_STRING || type == DBUS_TYPE_OBJECT_PATH) {
		const char ***str_array = val;
		int i;

		for (i = 0; i < n_elements; i++)
			dbus_message_iter_append_basic(&array, type,
							&((*str_array)[i]));
	}

	dbus_message_iter_close_container(&variant, &array);

	dbus_message_iter_close_container(iter, &variant);
}

static void dict_append_array(DBusMessageIter *dict, const char *key, int type,
			void *val, int n_elements)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
						NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	append_array_variant(&entry, type, val, n_elements);

	dbus_message_iter_close_container(dict, &entry);
}

static int parse_metadata_entry(DBusMessageIter *entry, const char *key,
						DBusMessageIter *metadata)
{
	DBusMessageIter var;
	int type;

	printf("metadata %s found\n", key);

	if (dbus_message_iter_get_arg_type(entry) != DBUS_TYPE_VARIANT)
		return -EINVAL;

	dbus_message_iter_recurse(entry, &var);

	type = dbus_message_iter_get_arg_type(&var);
	if (type == DBUS_TYPE_ARRAY) {
		char **values;
		int i;
		DBusMessageIter array;

		dbus_message_iter_recurse(&var, &array);

		values = dbus_malloc0(sizeof(char *) * 8);

		i = 0;
		while (dbus_message_iter_get_arg_type(&array) !=
							DBUS_TYPE_INVALID) {
			dbus_message_iter_get_basic(&array, &(values[i++]));
			dbus_message_iter_next(&array);
		}

		dict_append_array(metadata, key, DBUS_TYPE_STRING, &values, i);
		dbus_free(values);
	} else if (dbus_type_is_basic(type)) {
		const void *value;

		dbus_message_iter_get_basic(&var, &value);
		dict_append_entry(metadata, key, type, &value);
	} else
		return -EINVAL;

	return 0;
}

static int parse_metadata(DBusMessageIter *args, DBusMessageIter *metadata)
{
	DBusMessageIter dict;
	int ctype;

	ctype = dbus_message_iter_get_arg_type(args);
	if (ctype != DBUS_TYPE_ARRAY)
		return -EINVAL;

	dbus_message_iter_recurse(args, &dict);

	while ((ctype = dbus_message_iter_get_arg_type(&dict)) !=
							DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char *key;

		if (ctype != DBUS_TYPE_DICT_ENTRY)
			return -EINVAL;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return -EINVAL;

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (parse_metadata_entry(&entry, key, metadata) < 0)
			return -EINVAL;

		dbus_message_iter_next(&dict);
	}

	return 0;
}

static void append_metadata(DBusMessageIter *iter, DBusMessageIter *dict)
{
	DBusMessageIter value, metadata;

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "a{sv}",
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &metadata);

	parse_metadata(dict, &metadata);

	dbus_message_iter_close_container(&value, &metadata);
	dbus_message_iter_close_container(iter, &value);
}

static void dict_append_entry(DBusMessageIter *dict, const char *key, int type,
								void *val)
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

	if (strcasecmp(key, "Metadata") == 0)
		append_metadata(&entry, val);
	else
		append_variant(&entry, type, val);

	dbus_message_iter_close_container(dict, &entry);
}

static dbus_bool_t emit_properties_changed(DBusConnection *conn,
					const char *path,
					const char *interface,
					const char *name,
					int type, void *value)
{
	DBusMessage *signal;
	DBusMessageIter iter, dict, array;
	dbus_bool_t result;

	signal = dbus_message_new_signal(path, DBUS_INTERFACE_PROPERTIES,
							"PropertiesChanged");

	if (!signal) {
		fprintf(stderr, "Unable to allocate new %s.PropertyChanged"
							" signal", interface);
		return FALSE;
	}

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &interface);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dict_append_entry(&dict, name, type, value);

	dbus_message_iter_close_container(&iter, &dict);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array);
	dbus_message_iter_close_container(&iter, &array);

	result = dbus_connection_send(conn, signal, NULL);
	dbus_message_unref(signal);

	return result;
}

static int parse_property(DBusConnection *conn, const char *path,
						const char *key,
						DBusMessageIter *entry,
						DBusMessageIter *properties)
{
	DBusMessageIter var;
	const void *value;
	int type;

	printf("property %s found\n", key);

	if (dbus_message_iter_get_arg_type(entry) != DBUS_TYPE_VARIANT)
		return -EINVAL;

	dbus_message_iter_recurse(entry, &var);

	if (strcasecmp(key, "Metadata") == 0) {
		if (properties)
			dict_append_entry(properties, key,
						DBUS_TYPE_DICT_ENTRY, &var);
		else
			emit_properties_changed(sys, path,
					MPRIS_PLAYER_INTERFACE, key,
					DBUS_TYPE_DICT_ENTRY, &var);

		return 0;
	}

	type = dbus_message_iter_get_arg_type(&var);
	if (!dbus_type_is_basic(type))
		return -EINVAL;

	dbus_message_iter_get_basic(&var, &value);

	if (properties)
		dict_append_entry(properties, key, type, &value);
	else
		emit_properties_changed(sys, path,
					MPRIS_PLAYER_INTERFACE, key,
					type, &value);

	return 0;
}

static int parse_properties(DBusConnection *conn, const char *path,
						DBusMessageIter *args,
						DBusMessageIter *properties)
{
	DBusMessageIter dict;
	int ctype;

	ctype = dbus_message_iter_get_arg_type(args);
	if (ctype != DBUS_TYPE_ARRAY)
		return -EINVAL;

	dbus_message_iter_recurse(args, &dict);

	while ((ctype = dbus_message_iter_get_arg_type(&dict)) !=
							DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char *key;

		if (ctype != DBUS_TYPE_DICT_ENTRY)
			return -EINVAL;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return -EINVAL;

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (parse_property(conn, path, key, &entry, properties) < 0)
			return -EINVAL;

		dbus_message_iter_next(&dict);
	}

	return 0;
}

static char *sender2path(const char *sender)
{
	char *path;

	path = g_strconcat("/", sender, NULL);
	return g_strdelimit(path, ":.", '_');
}

static DBusHandlerResult player_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	char *owner = data;
	dbus_uint32_t serial;
	DBusMessage *copy, *reply;
	DBusError err;

	copy = dbus_message_copy(msg);
	dbus_message_set_destination(copy, owner);
	reply = dbus_connection_send_with_reply_and_block(session, copy, -1,
									&err);
	if (!reply) {
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		dbus_message_unref(copy);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	dbus_message_unref(copy);

	copy = dbus_message_copy(reply);
	serial = dbus_message_get_serial(msg);
	dbus_message_set_serial(copy, serial);

	dbus_message_unref(copy);
	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static const DBusObjectPathVTable player_table = {
	.message_function = player_message,
};

static void add_player(DBusConnection *conn, const char *name,
							const char *sender)
{
	DBusMessage *reply = get_all(conn, name);
	DBusMessage *msg;
	DBusMessageIter iter, args, properties;
	DBusError err;
	char *path, *owner;

	if (!reply || !adapter)
		return;

	msg = dbus_message_new_method_call(BLUEZ_BUS_NAME,
					g_dbus_proxy_get_path(adapter),
					BLUEZ_MEDIA_INTERFACE,
					"RegisterPlayer");
	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return;
	}

	path = sender2path(sender);
	dbus_connection_get_object_path_data(sys, path, (void **) &owner);

	if (owner != NULL)
		goto done;

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &path);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &properties);

	dbus_message_iter_init(reply, &args);

	if (parse_properties(conn, path, &args, &properties) < 0)
		goto done;

	dbus_message_iter_close_container(&iter, &properties);

	dbus_message_unref(reply);

	dbus_error_init(&err);

	owner = strdup(sender);

	if (!dbus_connection_register_object_path(sys, path, &player_table,
								owner)) {
		fprintf(stderr, "Can't register object path for player\n");
		free(owner);
		goto done;
	}

	reply = dbus_connection_send_with_reply_and_block(sys, msg, -1, &err);
	if (!reply) {
		fprintf(stderr, "Can't register player\n");
		free(owner);
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
	}

done:
	if (reply)
		dbus_message_unref(reply);
	dbus_message_unref(msg);
	g_free(path);
}

static void remove_player(DBusConnection *conn, const char *sender)
{
	DBusMessage *msg;
	char *path;

	if (!adapter)
		return;

	msg = dbus_message_new_method_call(BLUEZ_BUS_NAME,
					g_dbus_proxy_get_path(adapter),
					BLUEZ_MEDIA_INTERFACE,
					"UnregisterPlayer");
	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return;
	}

	path = sender2path(sender);
	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &path,
					DBUS_TYPE_INVALID);

	dbus_connection_send(sys, msg, NULL);

	dbus_connection_unregister_object_path(sys, path);

	dbus_message_unref(msg);
	g_free(path);
}

static gboolean properties_changed(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	DBusMessageIter iter;
	const char *iface;
	char *path;

	dbus_message_iter_init(msg, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_iter_get_basic(&iter, &iface);

	printf("PropertiesChanged interface %s\n", iface);

	dbus_message_iter_next(&iter);

	path = sender2path(dbus_message_get_sender(msg));
	parse_properties(conn, path, &iter, NULL);

	g_free(path);

	return TRUE;
}

static gboolean name_owner_changed(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *name, *old, *new;

	if (!dbus_message_get_args(msg, NULL,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_STRING, &old,
					DBUS_TYPE_STRING, &new,
					DBUS_TYPE_INVALID)) {
		fprintf(stderr, "Invalid arguments for NameOwnerChanged signal");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (!g_str_has_prefix(name, "org.mpris"))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (*new == '\0') {
		printf("player %s at %s disappear\n", name, old);
		remove_player(conn, old);
	} else {
		printf("player %s at %s found\n", name, new);
		add_player(conn, name, new);
	}

	return TRUE;
}

static char *get_name_owner(DBusConnection *conn, const char *name)
{
	DBusMessage *msg, *reply;
	DBusError err;
	char *owner;

	msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
					DBUS_INTERFACE_DBUS, "GetNameOwner");

	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return NULL;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &name,
							DBUS_TYPE_INVALID);

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		return NULL;
	}

	if (!dbus_message_get_args(reply, NULL,
					DBUS_TYPE_STRING, &owner,
					DBUS_TYPE_INVALID)) {
		dbus_message_unref(reply);
		return NULL;
	}

	owner = g_strdup(owner);

	dbus_message_unref(reply);

	dbus_connection_flush(conn);

	return owner;
}

static void parse_list_names(DBusConnection *conn, DBusMessageIter *args)
{
	DBusMessageIter array;
	int ctype;

	ctype = dbus_message_iter_get_arg_type(args);
	if (ctype != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(args, &array);

	while ((ctype = dbus_message_iter_get_arg_type(&array)) !=
							DBUS_TYPE_INVALID) {
		const char *name;
		char *owner;

		if (ctype != DBUS_TYPE_STRING)
			goto next;

		dbus_message_iter_get_basic(&array, &name);

		if (!g_str_has_prefix(name, "org.mpris"))
			goto next;

		owner = get_name_owner(conn, name);

		if (owner == NULL)
			goto next;

		printf("player %s at %s found\n", name, owner);

		add_player(conn, name, owner);

		g_free(owner);
next:
		dbus_message_iter_next(&array);
	}
}

static void list_names(DBusConnection *conn)
{
	DBusMessage *msg, *reply;
	DBusMessageIter iter;
	DBusError err;

	msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
					DBUS_INTERFACE_DBUS, "ListNames");

	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return;
	}

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		return;
	}

	dbus_message_iter_init(reply, &iter);

	parse_list_names(conn, &iter);

	dbus_message_unref(reply);

	dbus_connection_flush(conn);
}

static void usage(void)
{
	printf("Bluetooth mpris-player ver %s\n\n", VERSION);

	printf("Usage:\n");
}

static struct option main_options[] = {
	{ 0, 0, 0, 0 }
};

static void connect_handler(DBusConnection *connection, void *user_data)
{
	printf("org.bluez appeared\n");
}

static void disconnect_handler(DBusConnection *connection, void *user_data)
{
	printf("org.bluez disappeared\n");
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	if (adapter != NULL)
		return;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, BLUEZ_ADAPTER_INTERFACE)) {
		printf("Bluetooth Adapter %s found\n",
						g_dbus_proxy_get_path(proxy));
		adapter = proxy;
		list_names(session);
	}
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	if (adapter == NULL)
		return;

	interface = g_dbus_proxy_get_interface(proxy);

	if (strcmp(interface, BLUEZ_ADAPTER_INTERFACE))
		return;

	if (adapter != proxy)
		return;

	printf("Bluetooth Adapter %s removed\n", g_dbus_proxy_get_path(proxy));
	adapter = NULL;
}

int main(int argc, char *argv[])
{
	GDBusClient *client;
	guint owner_watch, properties_watch;
	struct sigaction sa;
	int opt;

	while ((opt = getopt_long(argc, argv, "h", main_options,
							NULL)) != EOF) {
		switch(opt) {
		case 'h':
			usage();
			exit(0);
		default:
			exit(1);
		}
	}

	main_loop = g_main_loop_new(NULL, FALSE);

	sys = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);
	if (!sys) {
		fprintf(stderr, "Can't get on system bus");
		exit(1);
	}

	session = g_dbus_setup_bus(DBUS_BUS_SESSION, NULL, NULL);
	if (!session) {
		fprintf(stderr, "Can't get on session bus");
		exit(1);
	}

	owner_watch = g_dbus_add_signal_watch(session, NULL, NULL,
						DBUS_INTERFACE_DBUS,
						"NameOwnerChanged",
						name_owner_changed,
						NULL, NULL);


	properties_watch = g_dbus_add_properties_watch(session, NULL, NULL,
							MPRIS_PLAYER_INTERFACE,
							properties_changed,
							NULL, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags   = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	client = g_dbus_client_new(sys, BLUEZ_BUS_NAME, BLUEZ_PATH);

	g_dbus_client_set_connect_watch(client, connect_handler, NULL);
	g_dbus_client_set_disconnect_watch(client, disconnect_handler, NULL);

	g_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
							NULL, NULL);

	g_main_loop_run(main_loop);

	g_dbus_remove_watch(session, owner_watch);
	g_dbus_remove_watch(session, properties_watch);

	g_dbus_client_unref(client);

	dbus_connection_unref(session);
	dbus_connection_unref(sys);

	g_main_loop_unref(main_loop);

	return 0;
}
