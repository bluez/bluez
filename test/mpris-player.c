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

static volatile sig_atomic_t __io_canceled = 0;
static volatile sig_atomic_t __io_terminated = 0;
static char *adapter = NULL;
static DBusConnection *sys = NULL;
static DBusConnection *session = NULL;

static void sig_term(int sig)
{
	__io_canceled = 1;
}

static DBusMessage *get_all(DBusConnection *conn, const char *name)
{
	DBusMessage *msg, *reply;
	DBusError err;
	const char *iface = "org.mpris.MediaPlayer2.Player";

	msg = dbus_message_new_method_call(name, "/org/mpris/MediaPlayer2",
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
		fprintf(stderr, "Can't get default adapter\n");
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

	append_variant(&entry, type, val);

	dbus_message_iter_close_container(dict, &entry);
}

static dbus_bool_t emit_property_changed(DBusConnection *conn,
					const char *path,
					const char *interface,
					const char *name,
					int type, void *value)
{
	DBusMessage *signal;
	DBusMessageIter iter;
	dbus_bool_t result;

	signal = dbus_message_new_signal(path, interface, "PropertyChanged");

	if (!signal) {
		fprintf(stderr, "Unable to allocate new %s.PropertyChanged"
							" signal", interface);
		return FALSE;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &name);

	append_variant(&iter, type, value);

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

	printf("property %s found\n", key);

	if (dbus_message_iter_get_arg_type(entry) != DBUS_TYPE_VARIANT)
		return -EINVAL;

	dbus_message_iter_recurse(entry, &var);

	if (strcasecmp(key, "PlaybackStatus") == 0) {
		const char *value;

		if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_STRING)
			return -EINVAL;

		dbus_message_iter_get_basic(&var, &value);

		if (properties)
			dict_append_entry(properties, "Status",
						DBUS_TYPE_STRING, &value);
		else
			emit_property_changed(sys, path,
					"org.bluez.MediaPlayer", "Status",
					DBUS_TYPE_STRING, &value);
	} else if (strcasecmp(key, "Position") == 0) {
		int64_t usec, msec;

		if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_INT64)
			return -EINVAL;

		dbus_message_iter_get_basic(&var, &usec);
		msec = usec / 1000;

		if (properties)
			dict_append_entry(properties, "Position",
						DBUS_TYPE_UINT32, &msec);
		else
			emit_property_changed(sys, path,
					"org.bluez.MediaPlayer", "Position",
					DBUS_TYPE_UINT32, &msec);
	} else if (strcasecmp(key, "Shuffle") == 0) {
		dbus_bool_t value;
		const char *str;

		if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_BOOLEAN)
			return -EINVAL;

		dbus_message_iter_get_basic(&var, &value);

		str = value ? "on" : "off";
		if (properties)
			dict_append_entry(properties, "Shuffle",
						DBUS_TYPE_STRING, &str);
		else
			emit_property_changed(sys, path,
					"org.bluez.MediaPlayer", "Shuffle",
					DBUS_TYPE_UINT32, &str);
	}

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

static int parse_metadata_entry(DBusMessageIter *entry, const char *key,
						DBusMessageIter *metadata)
{
	DBusMessageIter var;

	printf("metadata %s found\n", key);

	if (dbus_message_iter_get_arg_type(entry) != DBUS_TYPE_VARIANT)
		return -EINVAL;

	dbus_message_iter_recurse(entry, &var);

	if (strcasecmp(key, "xesam:title") == 0) {
		const char *value;

		if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_STRING)
			return -EINVAL;

		dbus_message_iter_get_basic(&var, &value);
		dict_append_entry(metadata, "Title", DBUS_TYPE_STRING,
								&value);
	} else if (strcasecmp(key, "xesam:artist") == 0) {
		const char *value;
		DBusMessageIter array;

		if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_ARRAY)
			return -EINVAL;

		dbus_message_iter_recurse(&var, &array);

		if (dbus_message_iter_get_arg_type(&array) !=
							DBUS_TYPE_STRING)
			return -EINVAL;

		dbus_message_iter_get_basic(&array, &value);
		dict_append_entry(metadata, "Artist", DBUS_TYPE_STRING,
								&value);
	} else if (strcasecmp(key, "xesam:album") == 0) {
		const char *value;

		if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_STRING)
			return -EINVAL;

		dbus_message_iter_get_basic(&var, &value);
		dict_append_entry(metadata, "Album", DBUS_TYPE_STRING,
								&value);
	} else if (strcasecmp(key, "xesam:genre") == 0) {
		const char *value;
		DBusMessageIter array;

		if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_ARRAY)
			return -EINVAL;

		dbus_message_iter_recurse(&var, &array);

		if (dbus_message_iter_get_arg_type(&array) !=
							DBUS_TYPE_STRING)
			return -EINVAL;

		dbus_message_iter_get_basic(&array, &value);
		dict_append_entry(metadata, "Genre", DBUS_TYPE_STRING,
								&value);
	} else if (strcasecmp(key, "mpris:length") == 0) {
		int64_t usec, msec;

		if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_INT64)
			return -EINVAL;

		dbus_message_iter_get_basic(&var, &usec);
		msec = usec / 1000;

		dict_append_entry(metadata, "Duration", DBUS_TYPE_UINT32,
								&msec);
	} else if (strcasecmp(key, "xesam:trackNumber") == 0) {
		int32_t value;

		if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_INT32)
			return -EINVAL;

		dbus_message_iter_get_basic(&var, &value);

		dict_append_entry(metadata, "Number", DBUS_TYPE_UINT32,
								&value);
	}

	return 0;
}

static int parse_track(DBusMessageIter *args, DBusMessageIter *metadata)
{
	DBusMessageIter var, dict;
	int ctype;

	ctype = dbus_message_iter_get_arg_type(args);
	if (ctype != DBUS_TYPE_VARIANT)
		return -EINVAL;

	dbus_message_iter_recurse(args, &var);

	ctype = dbus_message_iter_get_arg_type(&var);
	if (ctype != DBUS_TYPE_ARRAY)
		return -EINVAL;

	dbus_message_iter_recurse(&var, &dict);

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

		if (strcasecmp(key, "Metadata") == 0)
			return parse_track(&entry, metadata);

		dbus_message_iter_next(&dict);
	}

	return -EINVAL;
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
	if (dbus_message_is_method_call(msg, "org.bluez.MediaPlayer",
								"Release")) {
		printf("Release\n");
		exit(1);
	}

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
	DBusMessageIter iter, args, properties, metadata;
	DBusError err;
	char *path;

	if (!reply)
		return;

	msg = dbus_message_new_method_call("org.bluez", adapter,
					"org.bluez.Media",
					"RegisterPlayer");
	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return;
	}

	dbus_message_iter_init_append(msg, &iter);

	path = sender2path(sender);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &path);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &properties);

	dbus_message_iter_init(reply, &args);

	if (parse_properties(conn, path, &args, &properties) < 0)
		goto done;

	dbus_message_iter_close_container(&iter, &properties);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &metadata);

	dbus_message_iter_init(reply, &args);

	if (parse_metadata(&args, &metadata) < 0)
		goto done;

	dbus_message_iter_close_container(&iter, &metadata);

	dbus_message_unref(reply);

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(sys, msg, -1, &err);
	if (!reply) {
		fprintf(stderr, "Can't register player\n");
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		goto done;
	}

	if (!dbus_connection_register_object_path(sys, path, &player_table,
								NULL))
		fprintf(stderr, "Can't register object path for agent\n");

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

	msg = dbus_message_new_method_call("org.bluez", adapter,
					"org.bluez.Media",
					"UnregisterPlayer");
	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return;
	}

	path = sender2path(sender);
	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &path,
					DBUS_TYPE_INVALID);

	dbus_connection_send(sys, msg, NULL);

	dbus_message_unref(msg);
	g_free(path);
}

static DBusHandlerResult properties_changed(DBusConnection *conn,
							DBusMessage *msg)
{
	DBusMessage *signal;
	DBusMessageIter iter, entry, metadata;
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

	signal = dbus_message_new_signal(path, "org.bluez.MediaPlayer",
							"TrackChanged");
	if (!signal) {
		fprintf(stderr, "Unable to allocate new PropertyChanged"
							" signal\n");
		goto err;
	}

	dbus_message_iter_init_append(signal, &entry);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &metadata);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_next(&iter);

	if (parse_metadata(&iter, &metadata) < 0)
		goto err;

	dbus_message_iter_close_container(&entry, &metadata);

	dbus_connection_send(sys, signal, NULL);
	dbus_message_unref(signal);
	g_free(path);

	return DBUS_HANDLER_RESULT_HANDLED;

err:
	if (signal)
		dbus_message_unref(signal);
	g_free(path);
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult session_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *name, *old, *new;

	if (dbus_message_is_signal(msg, DBUS_INTERFACE_PROPERTIES,
						"PropertiesChanged"))
		return properties_changed(conn, msg);

	if (!dbus_message_is_signal(msg, DBUS_INTERFACE_DBUS,
						"NameOwnerChanged"))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

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

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult system_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *name, *old, *new;

	if (!dbus_message_is_signal(msg, DBUS_INTERFACE_DBUS,
						"NameOwnerChanged"))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_get_args(msg, NULL,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_STRING, &old,
					DBUS_TYPE_STRING, &new,
					DBUS_TYPE_INVALID)) {
		fprintf(stderr, "Invalid arguments for NameOwnerChanged signal");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (!strcmp(name, "org.bluez") && *new == '\0') {
		fprintf(stderr, "bluetoothd disconnected\n");
		__io_terminated = 1;
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static char *get_default_adapter(DBusConnection *conn)
{
	DBusMessage *msg, *reply;
	DBusError err;
	const char *reply_path;
	char *path;

	msg = dbus_message_new_method_call("org.bluez", "/",
					"org.bluez.Manager", "DefaultAdapter");

	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return NULL;
	}

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		fprintf(stderr, "Can't get default adapter\n");
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		return NULL;
	}

	if (!dbus_message_get_args(reply, &err,
					DBUS_TYPE_OBJECT_PATH, &reply_path,
					DBUS_TYPE_INVALID)) {
		fprintf(stderr, "Can't get reply arguments\n");
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		dbus_message_unref(reply);
		return NULL;
	}

	path = strdup(reply_path);

	dbus_message_unref(reply);

	dbus_connection_flush(conn);

	return path;
}

static char *get_adapter(DBusConnection *conn, const char *adapter)
{
	DBusMessage *msg, *reply;
	DBusError err;
	const char *reply_path;
	char *path;

	if (!adapter)
		return get_default_adapter(conn);

	msg = dbus_message_new_method_call("org.bluez", "/",
					"org.bluez.Manager", "FindAdapter");

	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return NULL;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &adapter,
					DBUS_TYPE_INVALID);

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		fprintf(stderr, "Can't find adapter %s\n", adapter);
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		return NULL;
	}

	if (!dbus_message_get_args(reply, &err,
					DBUS_TYPE_OBJECT_PATH, &reply_path,
					DBUS_TYPE_INVALID)) {
		fprintf(stderr, "Can't get reply arguments\n");
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		dbus_message_unref(reply);
		return NULL;
	}

	path = strdup(reply_path);

	dbus_message_unref(reply);

	dbus_connection_flush(conn);

	return path;
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
		fprintf(stderr, "Can't find adapter %s\n", adapter);
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
		fprintf(stderr, "Can't find adapter %s\n", adapter);
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
	printf("Bluetooth player ver %s\n\n", VERSION);

	printf("Usage:\n"
		"\tplayer [--adapter adapter id]\n"
		"\n");
}

static struct option main_options[] = {
	{ "adapter",	1, 0, 'a' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct sigaction sa;
	char *adapter_id = NULL;
	char match[128];
	int opt;

	while ((opt = getopt_long(argc, argv, "+a,h", main_options, NULL)) != EOF) {
		switch(opt) {
		case '1':
			adapter_id = optarg;
			break;
		case 'h':
			usage();
			exit(0);
		default:
			exit(1);
		}
	}

	sys = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!sys) {
		fprintf(stderr, "Can't get on system bus");
		exit(1);
	}

	adapter = get_adapter(sys, adapter_id);
	if (!adapter)
		exit(1);

	if (!dbus_connection_add_filter(sys, system_filter, NULL, NULL)) {
		fprintf(stderr, "Can't add signal filter");
		exit(1);
	}

	snprintf(match, sizeof(match),
			"interface=%s,member=NameOwnerChanged,arg0=%s",
			DBUS_INTERFACE_DBUS, "org.bluez");

	dbus_bus_add_match(sys, match, NULL);

	session = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (!session) {
		fprintf(stderr, "Can't get on session bus");
		exit(1);
	}

	if (!dbus_connection_add_filter(session, session_filter, NULL, NULL)) {
		fprintf(stderr, "Can't add signal filter");
		exit(1);
	}

	snprintf(match, sizeof(match),
			"interface=%s,member=NameOwnerChanged",
			DBUS_INTERFACE_DBUS);

	dbus_bus_add_match(session, match, NULL);

	snprintf(match, sizeof(match),
			"interface=%s,member=PropertiesChanged,arg0=%s",
			DBUS_INTERFACE_PROPERTIES,
			"org.mpris.MediaPlayer2.Player");

	list_names(session);

	dbus_bus_add_match(session, match, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags   = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	while (!__io_canceled && !__io_terminated) {
		if (dbus_connection_read_write_dispatch(sys, 500) != TRUE)
			break;
		if (dbus_connection_read_write_dispatch(session, 500) != TRUE)
			break;
	}

	dbus_connection_unref(sys);

	return 0;
}
