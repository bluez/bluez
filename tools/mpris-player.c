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
#include <inttypes.h>

#include <dbus/dbus.h>
#include <glib.h>
#include <gdbus/gdbus.h>

#define BLUEZ_BUS_NAME "org.bluez"
#define BLUEZ_PATH "/org/bluez"
#define BLUEZ_ADAPTER_INTERFACE "org.bluez.Adapter1"
#define BLUEZ_MEDIA_INTERFACE "org.bluez.Media1"
#define BLUEZ_MEDIA_PLAYER_INTERFACE "org.bluez.MediaPlayer1"
#define BLUEZ_MEDIA_TRANSPORT_INTERFACE "org.bluez.MediaTransport1"
#define MPRIS_BUS_NAME "org.mpris.MediaPlayer2."
#define MPRIS_INTERFACE "org.mpris.MediaPlayer2"
#define MPRIS_PLAYER_INTERFACE "org.mpris.MediaPlayer2.Player"
#define MPRIS_PLAYER_PATH "/org/mpris/MediaPlayer2"
#define ERROR_INTERFACE "org.mpris.MediaPlayer2.Error"

static GMainLoop *main_loop;
static GDBusProxy *adapter = NULL;
static DBusConnection *sys = NULL;
static DBusConnection *session = NULL;
static GDBusClient *client = NULL;
static GSList *players = NULL;
static GSList *transports = NULL;

static gboolean option_version = FALSE;
static gboolean option_export = FALSE;

struct player {
	char *bus_name;
	DBusConnection *conn;
	GDBusProxy *proxy;
	GDBusProxy *device;
	GDBusProxy *transport;
};

typedef int (* parse_metadata_func) (DBusMessageIter *iter, const char *key,
						DBusMessageIter *metadata);

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

static int parse_metadata(DBusMessageIter *args, DBusMessageIter *metadata,
						parse_metadata_func func)
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

		if (func(&entry, key, metadata) < 0)
			return -EINVAL;

		dbus_message_iter_next(&dict);
	}

	return 0;
}

static void append_metadata(DBusMessageIter *iter, DBusMessageIter *dict,
						parse_metadata_func func)
{
	DBusMessageIter value, metadata;

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "a{sv}",
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &metadata);

	parse_metadata(dict, &metadata, func);

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
		append_metadata(&entry, val, parse_metadata_entry);
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

static struct player *find_player_by_bus_name(const char *name)
{
	GSList *l;

	for (l = players; l; l = l->next) {
		struct player *player = l->data;

		if (strcmp(player->bus_name, name) == 0)
			return player;
	}

	return NULL;
}

static const DBusObjectPathVTable player_table = {
	.message_function = player_message,
};

static void add_player(DBusConnection *conn, const char *name,
							const char *sender)
{
	DBusMessage *reply = NULL;
	DBusMessage *msg;
	DBusMessageIter iter, args, properties;
	DBusError err;
	char *path, *owner;
	struct player *player;

	if (!adapter)
		return;

	player = find_player_by_bus_name(name);
	if (player == NULL) {
		reply = get_all(conn, name);
		if (reply == NULL)
			return;
		dbus_message_iter_init(reply, &args);
	}

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

	if (player != NULL) {
		if (!g_dbus_get_properties(player->conn,
						MPRIS_PLAYER_PATH,
						MPRIS_PLAYER_INTERFACE,
						&iter))
			goto done;
	} else {
		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
				&properties);
		if (parse_properties(conn, path, &args, &properties) < 0)
			goto done;
		dbus_message_iter_close_container(&iter, &properties);
		dbus_message_unref(reply);
	}

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
	char *path, *owner;

	if (!adapter)
		return;

	path = sender2path(sender);
	dbus_connection_get_object_path_data(sys, path, (void **) &owner);

	if (owner == NULL) {
		g_free(path);
		return;
	}

	msg = dbus_message_new_method_call(BLUEZ_BUS_NAME,
					g_dbus_proxy_get_path(adapter),
					BLUEZ_MEDIA_INTERFACE,
					"UnregisterPlayer");
	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		g_free(path);
		return;
	}

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
	char *path, *owner;

	dbus_message_iter_init(msg, &iter);

	path = sender2path(dbus_message_get_sender(msg));
	dbus_connection_get_object_path_data(sys, path, (void **) &owner);

	if (owner == NULL)
		goto done;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_iter_get_basic(&iter, &iface);

	printf("PropertiesChanged interface %s\n", iface);

	dbus_message_iter_next(&iter);

	parse_properties(conn, path, &iter, NULL);

done:
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
	} else if (option_export || find_player_by_bus_name(name) == NULL) {
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

static GOptionEntry options[] = {
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit" },
	{ "export", 'e', 0, G_OPTION_ARG_NONE, &option_export,
				"Export remote players" },
	{ NULL },
};

static void connect_handler(DBusConnection *connection, void *user_data)
{
	printf("org.bluez appeared\n");
}

static void disconnect_handler(DBusConnection *connection, void *user_data)
{
	printf("org.bluez disappeared\n");
}

static void player_free(void *data)
{
	struct player *player = data;

	if (player->conn) {
		dbus_connection_close(player->conn);
		dbus_connection_unref(player->conn);
	}

	g_dbus_proxy_unref(player->device);
	g_dbus_proxy_unref(player->proxy);

	if (player->transport)
		g_dbus_proxy_unref(player->transport);

	g_free(player->bus_name);
	g_free(player);
}

struct pending_call {
	struct player *player;
	DBusMessage *msg;
};

static void pending_call_free(void *data)
{
	struct pending_call *p = data;

	if (p->msg)
		dbus_message_unref(p->msg);

	g_free(p);
}

static void player_reply(DBusMessage *message, void *user_data)
{
	struct pending_call *p = user_data;
	struct player *player = p->player;
	DBusMessage *msg = p->msg;
	DBusMessage *reply;
	DBusError err;

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, message)) {
		fprintf(stderr, "error: %s", err.name);
		reply = g_dbus_create_error(msg, err.name, "%s", err.message);
		dbus_error_free(&err);
	} else
		reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	g_dbus_send_message(player->conn, reply);
}

static void player_control(struct player *player, DBusMessage *msg,
							const char *name)
{
	struct pending_call *p;

	p = g_new0(struct pending_call, 1);
	p->player = player;
	p->msg = dbus_message_ref(msg);

	g_dbus_proxy_method_call(player->proxy, name, NULL, player_reply,
						p, pending_call_free);
}

static const char *status_to_playback(const char *status)
{
	if (strcasecmp(status, "playing") == 0)
		return "Playing";
	else if (strcasecmp(status, "paused") == 0)
		return "Paused";
	else
		return "Stopped";
}

static const char *player_get_status(struct player *player)
{
	const char *status;
	DBusMessageIter value;

	if (g_dbus_proxy_get_property(player->proxy, "Status", &value)) {
		dbus_message_iter_get_basic(&value, &status);
		return status_to_playback(status);
	}

	if (player->transport == NULL)
		goto done;

	if (!g_dbus_proxy_get_property(player->transport, "State", &value))
		goto done;

	dbus_message_iter_get_basic(&value, &status);

	if (strcasecmp(status, "active") == 0)
		return "Playing";

done:
	return "Stopped";
}

static DBusMessage *player_toggle(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct player *player = data;
	const char *status;

	status = player_get_status(player);

	if (strcasecmp(status, "Playing") == 0)
		player_control(player, msg, "Pause");
	else
		player_control(player, msg, "Play");

	return NULL;
}

static DBusMessage *player_play(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct player *player = data;

	player_control(player, msg, "Play");

	return NULL;
}

static DBusMessage *player_pause(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct player *player = data;

	player_control(player, msg, "Pause");

	return NULL;
}

static DBusMessage *player_stop(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct player *player = data;

	player_control(player, msg, "Stop");

	return NULL;
}

static DBusMessage *player_next(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct player *player = data;

	player_control(player, msg, "Next");

	return NULL;
}

static DBusMessage *player_previous(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct player *player = data;

	player_control(player, msg, "Previous");

	return NULL;
}

static gboolean status_exists(const GDBusPropertyTable *property, void *data)
{
	struct player *player = data;

	return player_get_status(player) != NULL;
}

static gboolean get_status(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct player *player = data;
	const char *status;

	status = player_get_status(player);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &status);

	return TRUE;
}

static gboolean repeat_exists(const GDBusPropertyTable *property, void *data)
{
	DBusMessageIter iter;
	struct player *player = data;

	return g_dbus_proxy_get_property(player->proxy, "Repeat", &iter);
}

static const char *repeat_to_loopstatus(const char *value)
{
	if (strcasecmp(value, "off") == 0)
		return "None";
	else if (strcasecmp(value, "singletrack") == 0)
		return "Track";
	else if (strcasecmp(value, "alltracks") == 0)
		return "Playlist";

	return NULL;
}

static gboolean get_repeat(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct player *player = data;
	DBusMessageIter value;
	const char *status;

	if (!g_dbus_proxy_get_property(player->proxy, "Repeat", &value))
		return FALSE;

	dbus_message_iter_get_basic(&value, &status);

	status = repeat_to_loopstatus(status);
	if (status == NULL)
		return FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &status);

	return TRUE;
}

static const char *loopstatus_to_repeat(const char *value)
{
	if (strcasecmp(value, "None") == 0)
		return "off";
	else if (strcasecmp(value, "Track") == 0)
		return "singletrack";
	else if (strcasecmp(value, "Playlist") == 0)
		return "alltracks";

	return NULL;
}

static void property_result(const DBusError *err, void *user_data)
{
	GDBusPendingPropertySet id = GPOINTER_TO_UINT(user_data);

	if (!dbus_error_is_set(err))
		return g_dbus_pending_property_success(id);

	g_dbus_pending_property_error(id, err->name, err->message);
}

static void set_repeat(const GDBusPropertyTable *property,
			DBusMessageIter *iter, GDBusPendingPropertySet id,
			void *data)
{
	struct player *player = data;
	const char *value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING) {
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
		return;
	}

	dbus_message_iter_get_basic(iter, &value);

	value = loopstatus_to_repeat(value);
	if (value == NULL) {
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
		return;
	}

	g_dbus_proxy_set_property_basic(player->proxy, "Repeat",
					DBUS_TYPE_STRING, &value,
					property_result, GUINT_TO_POINTER(id),
					NULL);
}

static gboolean get_double(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	double value = 1.0;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_DOUBLE, &value);

	return TRUE;
}

static gboolean shuffle_exists(const GDBusPropertyTable *property, void *data)
{
	DBusMessageIter iter;
	struct player *player = data;

	return g_dbus_proxy_get_property(player->proxy, "Shuffle", &iter);
}

static gboolean get_shuffle(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct player *player = data;
	DBusMessageIter value;
	const char *string;
	dbus_bool_t shuffle;

	if (!g_dbus_proxy_get_property(player->proxy, "Shuffle", &value))
		return FALSE;

	dbus_message_iter_get_basic(&value, &string);

	shuffle = strcmp(string, "off") != 0;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &shuffle);

	return TRUE;
}

static void set_shuffle(const GDBusPropertyTable *property,
			DBusMessageIter *iter, GDBusPendingPropertySet id,
			void *data)
{
	struct player *player = data;
	dbus_bool_t shuffle;
	const char *value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_BOOLEAN) {
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
		return;
	}

	dbus_message_iter_get_basic(iter, &shuffle);
	value = shuffle ? "alltracks" : "off";

	g_dbus_proxy_set_property_basic(player->proxy, "Shuffle",
					DBUS_TYPE_STRING, &value,
					property_result, GUINT_TO_POINTER(id),
					NULL);
}

static gboolean position_exists(const GDBusPropertyTable *property, void *data)
{
	DBusMessageIter iter;
	struct player *player = data;

	return g_dbus_proxy_get_property(player->proxy, "Position", &iter);
}

static gboolean get_position(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct player *player = data;
	DBusMessageIter var;
	uint32_t position;
	int64_t value;

	if (!g_dbus_proxy_get_property(player->proxy, "Position", &var))
		return FALSE;

	dbus_message_iter_get_basic(&var, &position);

	value = position * 1000;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_INT64, &value);

	return TRUE;
}

static gboolean track_exists(const GDBusPropertyTable *property, void *data)
{
	DBusMessageIter iter;
	struct player *player = data;

	return g_dbus_proxy_get_property(player->proxy, "Track", &iter);
}

static gboolean parse_string_metadata(DBusMessageIter *iter, const char *key,
						DBusMessageIter *metadata)
{
	const char *value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING)
		return FALSE;

	dbus_message_iter_get_basic(iter, &value);

	dict_append_entry(metadata, key, DBUS_TYPE_STRING, &value);

	return TRUE;
}

static gboolean parse_array_metadata(DBusMessageIter *iter, const char *key,
						DBusMessageIter *metadata)
{
	char **value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING)
		return FALSE;

	value = dbus_malloc0(sizeof(char *));

	dbus_message_iter_get_basic(iter, &(value[0]));

	dict_append_array(metadata, key, DBUS_TYPE_STRING, &value, 1);

	dbus_free(value);

	return TRUE;
}

static gboolean parse_int64_metadata(DBusMessageIter *iter, const char *key,
						DBusMessageIter *metadata)
{
	uint32_t duration;
	int64_t value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_UINT32)
		return FALSE;

	dbus_message_iter_get_basic(iter, &duration);

	value = duration * 1000;

	dict_append_entry(metadata, key, DBUS_TYPE_INT64, &value);

	return TRUE;
}

static gboolean parse_int32_metadata(DBusMessageIter *iter, const char *key,
						DBusMessageIter *metadata)
{
	uint32_t value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_UINT32)
		return FALSE;

	dbus_message_iter_get_basic(iter, &value);

	dict_append_entry(metadata, key, DBUS_TYPE_INT32, &value);

	return TRUE;
}

static int parse_track_entry(DBusMessageIter *entry, const char *key,
						DBusMessageIter *metadata)
{
	DBusMessageIter var;

	if (dbus_message_iter_get_arg_type(entry) != DBUS_TYPE_VARIANT)
		return -EINVAL;

	dbus_message_iter_recurse(entry, &var);

	if (strcasecmp(key, "Title") == 0) {
		if (!parse_string_metadata(&var, "xesam:title", metadata))
			return -EINVAL;
	} else if (strcasecmp(key, "Artist") == 0) {
		if (!parse_array_metadata(&var, "xesam:artist", metadata))
			return -EINVAL;
	} else if (strcasecmp(key, "Album") == 0) {
		if (!parse_string_metadata(&var, "xesam:album", metadata))
			return -EINVAL;
	} else if (strcasecmp(key, "Genre") == 0) {
		if (!parse_array_metadata(&var, "xesam:genre", metadata))
			return -EINVAL;
	} else if (strcasecmp(key, "Duration") == 0) {
		if (!parse_int64_metadata(&var, "mpris:length", metadata))
			return -EINVAL;
	} else if (strcasecmp(key, "TrackNumber") == 0) {
		if (!parse_int32_metadata(&var, "xesam:trackNumber", metadata))
			return -EINVAL;
	}

	return 0;
}

static gboolean get_track(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct player *player = data;
	DBusMessageIter var, metadata;

	if (!g_dbus_proxy_get_property(player->proxy, "Track", &var))
		return FALSE;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &metadata);

	parse_metadata(&var, &metadata, parse_track_entry);

	dbus_message_iter_close_container(iter, &metadata);

	return TRUE;
}

static gboolean get_enable(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	dbus_bool_t value = TRUE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &value);

	return TRUE;
}


static gboolean get_volume(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct player *player = data;
	double value = 0.0;
	uint16_t volume;
	DBusMessageIter var;

	if (player->transport == NULL)
		goto done;

	if (!g_dbus_proxy_get_property(player->transport, "Volume", &var))
		goto done;

	dbus_message_iter_get_basic(&var, &volume);

	value = (double) volume / 127;

done:
	dbus_message_iter_append_basic(iter, DBUS_TYPE_DOUBLE, &value);

	return TRUE;
}

static const GDBusMethodTable player_methods[] = {
	{ GDBUS_ASYNC_METHOD("PlayPause", NULL, NULL, player_toggle) },
	{ GDBUS_ASYNC_METHOD("Play", NULL, NULL, player_play) },
	{ GDBUS_ASYNC_METHOD("Pause", NULL, NULL, player_pause) },
	{ GDBUS_ASYNC_METHOD("Stop", NULL, NULL, player_stop) },
	{ GDBUS_ASYNC_METHOD("Next", NULL, NULL, player_next) },
	{ GDBUS_ASYNC_METHOD("Previous", NULL, NULL, player_previous) },
	{ }
};

static const GDBusSignalTable player_signals[] = {
	{ GDBUS_SIGNAL("Seeked", GDBUS_ARGS({"Position", "x"})) },
	{ }
};

static const GDBusPropertyTable player_properties[] = {
	{ "PlaybackStatus", "s", get_status, NULL, status_exists },
	{ "LoopStatus", "s", get_repeat, set_repeat, repeat_exists },
	{ "Rate", "d", get_double, NULL, NULL },
	{ "MinimumRate", "d", get_double, NULL, NULL },
	{ "MaximumRate", "d", get_double, NULL, NULL },
	{ "Shuffle", "b", get_shuffle, set_shuffle, shuffle_exists },
	{ "Position", "x", get_position, NULL, position_exists },
	{ "Metadata", "a{sv}", get_track, NULL, track_exists },
	{ "Volume", "d", get_volume, NULL, NULL },
	{ "CanGoNext", "b", get_enable, NULL, NULL },
	{ "CanGoPrevious", "b", get_enable, NULL, NULL },
	{ "CanPlay", "b", get_enable, NULL, NULL },
	{ "CanPause", "b", get_enable, NULL, NULL },
	{ "CanSeek", "b", get_enable, NULL, NULL },
	{ "CanControl", "b", get_enable, NULL, NULL },
	{ }
};

static gboolean get_disable(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	dbus_bool_t value = FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &value);

	return TRUE;
}

static gboolean get_name(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct player *player = data;
	DBusMessageIter var;
	const char *alias;
	char *name;

	if (!g_dbus_proxy_get_property(player->device, "Alias", &var))
		return FALSE;

	dbus_message_iter_get_basic(&var, &alias);

	if (g_dbus_proxy_get_property(player->proxy, "Name", &var)) {
		dbus_message_iter_get_basic(&var, &name);
		name = g_strconcat(alias, " ", name, NULL);
	} else
		name = g_strdup(alias);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &name);

	g_free(name);

	return TRUE;
}

static const GDBusMethodTable mpris_methods[] = {
	{ }
};

static const GDBusPropertyTable mpris_properties[] = {
	{ "CanQuit", "b", get_disable, NULL, NULL },
	{ "Fullscreen", "b", get_disable, NULL, NULL },
	{ "CanSetFullscreen", "b", get_disable, NULL, NULL },
	{ "CanRaise", "b", get_disable, NULL, NULL },
	{ "HasTrackList", "b", get_disable, NULL, NULL },
	{ "Identity", "s", get_name, NULL, NULL },
	{ }
};

#define a_z "abcdefghijklmnopqrstuvwxyz"
#define A_Z "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define _0_9 "_0123456789"

static char *mpris_busname(char *name)
{
	if (g_ascii_isdigit(name[0]))
		return g_strconcat(MPRIS_BUS_NAME, "bt_",
				g_strcanon(name, A_Z a_z _0_9, '_'), NULL);
	else
		return g_strconcat(MPRIS_BUS_NAME,
				g_strcanon(name, A_Z a_z _0_9, '_'), NULL);
}

static GDBusProxy *find_transport_by_path(const char *path)
{
	GSList *l;

	for (l = transports; l; l = l->next) {
		GDBusProxy *transport = l->data;
		DBusMessageIter iter;
		const char *value;

		if (!g_dbus_proxy_get_property(transport, "Device", &iter))
			continue;

		dbus_message_iter_get_basic(&iter, &value);

		if (strcmp(path, value) == 0)
			return transport;
	}

	return NULL;
}

static void register_player(GDBusProxy *proxy)
{
	struct player *player;
	DBusMessageIter iter;
	const char *path, *alias, *name;
	char *busname;
	GDBusProxy *device, *transport;

	if (!g_dbus_proxy_get_property(proxy, "Device", &iter))
		return;

	dbus_message_iter_get_basic(&iter, &path);

	device = g_dbus_proxy_new(client, path, "org.bluez.Device1");
	if (device == NULL)
		return;

	if (!g_dbus_proxy_get_property(device, "Alias", &iter))
		return;

	dbus_message_iter_get_basic(&iter, &alias);

	if (g_dbus_proxy_get_property(proxy, "Name", &iter)) {
		dbus_message_iter_get_basic(&iter, &name);
		busname = g_strconcat(alias, " ", name, NULL);
	} else
		busname = g_strdup(alias);

	player = g_new0(struct player, 1);
	player->bus_name = mpris_busname(busname);
	player->proxy = g_dbus_proxy_ref(proxy);
	player->device = device;

	g_free(busname);

	players = g_slist_prepend(players, player);

	printf("Player %s created\n", player->bus_name);

	player->conn = g_dbus_setup_private(DBUS_BUS_SESSION, player->bus_name,
									NULL);
	if (!session) {
		fprintf(stderr, "Could not register bus name %s",
							player->bus_name);
		goto fail;
	}

	if (!g_dbus_register_interface(player->conn, MPRIS_PLAYER_PATH,
						MPRIS_INTERFACE,
						mpris_methods,
						NULL,
						mpris_properties,
						player, NULL)) {
		fprintf(stderr, "Could not register interface %s",
						MPRIS_INTERFACE);
		goto fail;
	}

	if (!g_dbus_register_interface(player->conn, MPRIS_PLAYER_PATH,
						MPRIS_PLAYER_INTERFACE,
						player_methods,
						player_signals,
						player_properties,
						player, player_free)) {
		fprintf(stderr, "Could not register interface %s",
						MPRIS_PLAYER_INTERFACE);
		goto fail;
	}

	transport = find_transport_by_path(path);
	if (transport)
		player->transport = g_dbus_proxy_ref(transport);

	return;

fail:
	players = g_slist_remove(players, player);
	player_free(player);
}

static struct player *find_player_by_device(const char *device)
{
	GSList *l;

	for (l = players; l; l = l->next) {
		struct player *player = l->data;
		const char *path = g_dbus_proxy_get_path(player->device);

		if (g_strcmp0(device, path) == 0)
			return player;
	}

	return NULL;
}

static void register_transport(GDBusProxy *proxy)
{
	struct player *player;
	DBusMessageIter iter;
	const char *path;

	if (g_slist_find(transports, proxy) != NULL)
		return;

	if (!g_dbus_proxy_get_property(proxy, "Volume", &iter))
		return;

	if (!g_dbus_proxy_get_property(proxy, "Device", &iter))
		return;

	dbus_message_iter_get_basic(&iter, &path);

	transports = g_slist_append(transports, proxy);

	player = find_player_by_device(path);
	if (player == NULL || player->transport != NULL)
		return;

	player->transport = g_dbus_proxy_ref(proxy);
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, BLUEZ_ADAPTER_INTERFACE)) {
		if (adapter != NULL)
			return;

		printf("Bluetooth Adapter %s found\n",
						g_dbus_proxy_get_path(proxy));
		adapter = proxy;
		list_names(session);
	} else if (!strcmp(interface, BLUEZ_MEDIA_PLAYER_INTERFACE)) {
		printf("Bluetooth Player %s found\n",
						g_dbus_proxy_get_path(proxy));
		register_player(proxy);
	} else if (!strcmp(interface, BLUEZ_MEDIA_TRANSPORT_INTERFACE)) {
		printf("Bluetooth Transport %s found\n",
						g_dbus_proxy_get_path(proxy));
		register_transport(proxy);
	}
}

static void unregister_player(struct player *player)
{
	players = g_slist_remove(players, player);

	g_dbus_unregister_interface(player->conn, MPRIS_PLAYER_PATH,
						MPRIS_INTERFACE);

	g_dbus_unregister_interface(player->conn, MPRIS_PLAYER_PATH,
						MPRIS_PLAYER_INTERFACE);
}

static struct player *find_player(GDBusProxy *proxy)
{
	GSList *l;

	for (l = players; l; l = l->next) {
		struct player *player = l->data;

		if (player->proxy == proxy)
			return player;
	}

	return NULL;
}

static struct player *find_player_by_transport(GDBusProxy *proxy)
{
	GSList *l;

	for (l = players; l; l = l->next) {
		struct player *player = l->data;

		if (player->transport == proxy)
			return player;
	}

	return NULL;
}

static void unregister_transport(GDBusProxy *proxy)
{
	struct player *player;

	if (g_slist_find(transports, proxy) == NULL)
		return;

	transports = g_slist_remove(transports, proxy);

	player = find_player_by_transport(proxy);
	if (player == NULL)
		return;

	g_dbus_proxy_unref(player->transport);
	player->transport = NULL;
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	if (adapter == NULL)
		return;

	interface = g_dbus_proxy_get_interface(proxy);

	if (strcmp(interface, BLUEZ_ADAPTER_INTERFACE) == 0) {
		if (adapter != proxy)
			return;
		printf("Bluetooth Adapter %s removed\n",
						g_dbus_proxy_get_path(proxy));
		adapter = NULL;
	} else if (strcmp(interface, BLUEZ_MEDIA_PLAYER_INTERFACE) == 0) {
		struct player *player;

		player = find_player(proxy);
		if (player == NULL)
			return;

		printf("Bluetooth Player %s removed\n",
						g_dbus_proxy_get_path(proxy));
		unregister_player(player);
	} else if (strcmp(interface, BLUEZ_MEDIA_TRANSPORT_INTERFACE) == 0) {
		printf("Bluetooth Transport %s removed\n",
						g_dbus_proxy_get_path(proxy));
		unregister_transport(proxy);
	}
}

static const char *property_to_mpris(const char *property)
{
	if (strcasecmp(property, "Repeat") == 0)
		return "LoopStatus";
	else if (strcasecmp(property, "Shuffle") == 0)
		return "Shuffle";
	else if (strcasecmp(property, "Status") == 0)
		return "PlaybackStatus";
	else if (strcasecmp(property, "Position") == 0)
		return "Position";
	else if (strcasecmp(property, "Track") == 0)
		return "Metadata";

	return NULL;
}

static void player_property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	struct player *player;
	const char *property;
	uint32_t position;
	uint64_t value;

	player = find_player(proxy);
	if (player == NULL)
		return;

	property = property_to_mpris(name);
	if (property == NULL)
		return;

	g_dbus_emit_property_changed(player->conn, MPRIS_PLAYER_PATH,
						MPRIS_PLAYER_INTERFACE,
						property);

	if (strcasecmp(name, "Position") != 0)
		return;

	dbus_message_iter_get_basic(iter, &position);

	value = position * 1000;

	g_dbus_emit_signal(player->conn, MPRIS_PLAYER_PATH,
					MPRIS_PLAYER_INTERFACE, "Seeked",
					DBUS_TYPE_INT64, &value,
					DBUS_TYPE_INVALID);
}

static void transport_property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	struct player *player;
	DBusMessageIter var;
	const char *path;

	if (strcasecmp(name, "Volume") != 0 && strcasecmp(name, "State") != 0)
		return;

	if (!g_dbus_proxy_get_property(proxy, "Device", &var))
		return;

	dbus_message_iter_get_basic(&var, &path);

	player = find_player_by_device(path);
	if (player == NULL)
		return;

	if (strcasecmp(name, "State") == 0) {
		if (!g_dbus_proxy_get_property(player->proxy, "Status", &var))
			g_dbus_emit_property_changed(player->conn,
						MPRIS_PLAYER_PATH,
						MPRIS_PLAYER_INTERFACE,
						"PlaybackStatus");
		return;
	}

	g_dbus_emit_property_changed(player->conn, MPRIS_PLAYER_PATH,
						MPRIS_PLAYER_INTERFACE,
						name);
}

static void property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (strcmp(interface, BLUEZ_MEDIA_PLAYER_INTERFACE) == 0)
		return player_property_changed(proxy, name, iter, user_data);

	if (strcmp(interface, BLUEZ_MEDIA_TRANSPORT_INTERFACE) == 0)
		return transport_property_changed(proxy, name, iter,
								user_data);
}

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	guint owner_watch, properties_watch;
	struct sigaction sa;

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
		usage();
		exit(0);
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
						property_changed, NULL);

	g_main_loop_run(main_loop);

	g_dbus_remove_watch(session, owner_watch);
	g_dbus_remove_watch(session, properties_watch);

	g_dbus_client_unref(client);

	dbus_connection_unref(session);
	dbus_connection_unref(sys);

	g_main_loop_unref(main_loop);

	return 0;
}
