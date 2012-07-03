/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2011  Bartosz Szatkowski <bulislaw@linux.com> for Comarch
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

#include <errno.h>
#include <string.h>
#include <glib.h>
#include <gdbus.h>

#include "dbus.h"
#include "log.h"

#include "map.h"
#include "transfer.h"
#include "session.h"
#include "driver.h"

#define OBEX_MAS_UUID \
	"\xBB\x58\x2B\x40\x42\x0C\x11\xDB\xB0\xDE\x08\x00\x20\x0C\x9A\x66"
#define OBEX_MAS_UUID_LEN 16

#define MAP_INTERFACE "org.bluez.obex.MessageAccess"
#define MAP_MSG_INTERFACE "org.bluez.obex.Message"
#define ERROR_INTERFACE "org.bluez.obex.Error"
#define MAS_UUID "00001132-0000-1000-8000-00805f9b34fb"

struct map_data {
	struct obc_session *session;
	DBusMessage *msg;
	GHashTable *messages;
};

#define MAP_MSG_FLAG_PRIORITY	0x01
#define MAP_MSG_FLAG_READ	0x02
#define MAP_MSG_FLAG_SENT	0x04
#define MAP_MSG_FLAG_PROTECTED	0x08

struct map_msg {
	struct map_data *data;
	char *path;
	char *handle;
	char *subject;
	char *timestamp;
	char *sender;
	char *sender_address;
	char *replyto;
	char *recipient;
	char *recipient_address;
	char *type;
	uint64_t size;
	char *status;
	uint8_t flags;
};

struct map_parser {
	struct map_data *data;
	DBusMessageIter *iter;
};

static DBusConnection *conn = NULL;

static void simple_cb(struct obc_session *session,
						struct obc_transfer *transfer,
						GError *err, void *user_data)
{
	DBusMessage *reply;
	struct map_data *map = user_data;

	if (err != NULL)
		reply = g_dbus_create_error(map->msg,
						ERROR_INTERFACE ".Failed",
						"%s", err->message);
	else
		reply = dbus_message_new_method_return(map->msg);

	g_dbus_send_message(conn, reply);
	dbus_message_unref(map->msg);
}

static DBusMessage *map_setpath(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct map_data *map = user_data;
	const char *folder;
	GError *err = NULL;

	if (dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &folder,
						DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
					ERROR_INTERFACE ".InvalidArguments",
					NULL);

	obc_session_setpath(map->session, folder, simple_cb, map, &err);
	if (err != NULL) {
		DBusMessage *reply;
		reply =  g_dbus_create_error(message,
						ERROR_INTERFACE ".Failed",
						"%s", err->message);
		g_error_free(err);
		return reply;
	}

	map->msg = dbus_message_ref(message);

	return NULL;
}

static void folder_element(GMarkupParseContext *ctxt, const gchar *element,
				const gchar **names, const gchar **values,
				gpointer user_data, GError **gerr)
{
	DBusMessageIter dict, *iter = user_data;
	const gchar *key;
	gint i;

	if (strcasecmp("folder", element) != 0)
		return;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	for (i = 0, key = names[i]; key; key = names[++i]) {
		if (strcasecmp("name", key) == 0)
			obex_dbus_dict_append(&dict, "Name", DBUS_TYPE_STRING,
								&values[i]);
	}

	dbus_message_iter_close_container(iter, &dict);
}

static const GMarkupParser folder_parser = {
	folder_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static void folder_listing_cb(struct obc_session *session,
						struct obc_transfer *transfer,
						GError *err, void *user_data)
{
	struct map_data *map = user_data;
	GMarkupParseContext *ctxt;
	DBusMessage *reply;
	DBusMessageIter iter, array;
	char *contents;
	size_t size;
	int perr;

	if (err != NULL) {
		reply = g_dbus_create_error(map->msg,
						ERROR_INTERFACE ".Failed",
						"%s", err->message);
		goto done;
	}

	perr = obc_transfer_get_contents(transfer, &contents, &size);
	if (perr < 0) {
		reply = g_dbus_create_error(map->msg,
						ERROR_INTERFACE ".Failed",
						"Error reading contents: %s",
						strerror(-perr));
		goto done;
	}

	reply = dbus_message_new_method_return(map->msg);
	if (reply == NULL)
		return;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &array);
	ctxt = g_markup_parse_context_new(&folder_parser, 0, &array, NULL);
	g_markup_parse_context_parse(ctxt, contents, size, NULL);
	g_markup_parse_context_free(ctxt);
	dbus_message_iter_close_container(&iter, &array);
	g_free(contents);

done:
	g_dbus_send_message(conn, reply);
	dbus_message_unref(map->msg);
}

static DBusMessage *map_get_folder_listing(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct map_data *map = user_data;
	struct obc_transfer *transfer;
	GError *err = NULL;
	DBusMessage *reply;

	transfer = obc_transfer_get("x-obex/folder-listing", NULL, NULL, &err);
	if (transfer == NULL)
		goto fail;

	if (obc_session_queue(map->session, transfer, folder_listing_cb, map,
								&err)) {
		map->msg = dbus_message_ref(message);
		return NULL;
	}

fail:
	reply = g_dbus_create_error(message, ERROR_INTERFACE ".Failed", "%s",
								err->message);
	g_error_free(err);
	return reply;
}

static void map_msg_free(void *data)
{
	struct map_msg *msg = data;

	g_free(msg->path);
	g_free(msg->subject);
	g_free(msg->handle);
	g_free(msg->timestamp);
	g_free(msg->sender);
	g_free(msg->sender_address);
	g_free(msg->replyto);
	g_free(msg->recipient);
	g_free(msg->recipient_address);
	g_free(msg->type);
	g_free(msg->status);
	g_free(msg);
}

static const GDBusMethodTable map_msg_methods[] = {
	{ }
};

static struct map_msg *map_msg_create(struct map_data *data, const char *handle)
{
	struct map_msg *msg;

	msg = g_new0(struct map_msg, 1);
	msg->data = data;
	msg->path = g_strdup_printf("%s/message%s",
					obc_session_get_path(data->session),
					handle);

	if (!g_dbus_register_interface(conn, msg->path, MAP_MSG_INTERFACE,
						map_msg_methods, NULL, NULL,
						msg, map_msg_free)) {
		map_msg_free(msg);
		return NULL;
	}

	msg->handle = g_strdup(handle);
	g_hash_table_insert(data->messages, msg->handle, msg);

	return msg;
}

static void parse_subject(struct map_msg *msg, const char *value,
							DBusMessageIter *iter)
{
	g_free(msg->subject);
	msg->subject = g_strdup(value);
	obex_dbus_dict_append(iter, "Subject", DBUS_TYPE_STRING, &value);
}

static void parse_datetime(struct map_msg *msg, const char *value,
							DBusMessageIter *iter)
{
	g_free(msg->timestamp);
	msg->timestamp = g_strdup(value);
	obex_dbus_dict_append(iter, "Timestamp", DBUS_TYPE_STRING, &value);
}

static void parse_sender(struct map_msg *msg, const char *value,
							DBusMessageIter *iter)
{
	g_free(msg->sender);
	msg->sender = g_strdup(value);
	obex_dbus_dict_append(iter, "Sender", DBUS_TYPE_STRING, &value);
}

static void parse_sender_address(struct map_msg *msg, const char *value,
							DBusMessageIter *iter)
{
	g_free(msg->sender_address);
	msg->sender_address = g_strdup(value);
	obex_dbus_dict_append(iter, "SenderAddress", DBUS_TYPE_STRING,
								&value);
}

static void parse_replyto(struct map_msg *msg, const char *value,
							DBusMessageIter *iter)
{
	g_free(msg->replyto);
	msg->replyto = g_strdup(value);
	obex_dbus_dict_append(iter, "ReplyTo", DBUS_TYPE_STRING, &value);
}

static void parse_recipient(struct map_msg *msg, const char *value,
							DBusMessageIter *iter)
{
	g_free(msg->recipient);
	msg->recipient = g_strdup(value);
	obex_dbus_dict_append(iter, "Recipient", DBUS_TYPE_STRING, &value);
}

static void parse_recipient_address(struct map_msg *msg, const char *value,
							DBusMessageIter *iter)
{
	g_free(msg->recipient_address);
	msg->recipient_address = g_strdup(value);
	obex_dbus_dict_append(iter, "RecipientAddress", DBUS_TYPE_STRING,
								&value);
}

static void parse_type(struct map_msg *msg, const char *value,
							DBusMessageIter *iter)
{
	g_free(msg->type);
	msg->type = g_strdup(value);
	obex_dbus_dict_append(iter, "Type", DBUS_TYPE_STRING, &value);
}

static void parse_status(struct map_msg *msg, const char *value,
							DBusMessageIter *iter)
{
	g_free(msg->status);
	msg->status = g_strdup(value);
	obex_dbus_dict_append(iter, "Status", DBUS_TYPE_STRING, &value);
}

static void parse_size(struct map_msg *msg, const char *value,
							DBusMessageIter *iter)
{
	msg->size = g_ascii_strtoll(value, NULL, 10);
	obex_dbus_dict_append(iter, "Size", DBUS_TYPE_UINT64, &msg->size);
}

static void parse_priority(struct map_msg *msg, const char *value,
							DBusMessageIter *iter)
{
	gboolean flag = strcasecmp(value, "no");

	if (flag)
		msg->flags |= MAP_MSG_FLAG_PRIORITY;
	else
		msg->flags &= ~MAP_MSG_FLAG_PRIORITY;

	obex_dbus_dict_append(iter, "Priority", DBUS_TYPE_BOOLEAN, &flag);
}

static void parse_read(struct map_msg *msg, const char *value,
							DBusMessageIter *iter)
{
	gboolean flag = strcasecmp(value, "no");

	if (flag)
		msg->flags |= MAP_MSG_FLAG_READ;
	else
		msg->flags &= ~MAP_MSG_FLAG_READ;

	obex_dbus_dict_append(iter, "Read", DBUS_TYPE_BOOLEAN, &flag);
}

static void parse_sent(struct map_msg *msg, const char *value,
							DBusMessageIter *iter)
{
	gboolean flag = strcasecmp(value, "no");

	if (flag)
		msg->flags |= MAP_MSG_FLAG_SENT;
	else
		msg->flags &= ~MAP_MSG_FLAG_SENT;

	obex_dbus_dict_append(iter, "Sent", DBUS_TYPE_BOOLEAN, &flag);
}

static void parse_protected(struct map_msg *msg, const char *value,
							DBusMessageIter *iter)
{
	gboolean flag = strcasecmp(value, "no");

	if (flag)
		msg->flags |= MAP_MSG_FLAG_PROTECTED;
	else
		msg->flags &= ~MAP_MSG_FLAG_PROTECTED;

	obex_dbus_dict_append(iter, "Protected", DBUS_TYPE_BOOLEAN, &flag);
}

static struct map_msg_parser {
	const char *name;
	void (*func) (struct map_msg *msg, const char *value,
							DBusMessageIter *iter);
} msg_parsers[] = {
		{ "subject", parse_subject },
		{ "datetime", parse_datetime },
		{ "sender_name", parse_sender },
		{ "sender_addressing", parse_sender_address },
		{ "replyto_addressing", parse_replyto },
		{ "recipient_name", parse_recipient },
		{ "recipient_addressing", parse_recipient_address },
		{ "type", parse_type },
		{ "reception_status", parse_status },
		{ "size", parse_size },
		{ "priority", parse_priority },
		{ "read", parse_read },
		{ "sent", parse_sent },
		{ "protected", parse_protected },
		{ }
};

static void msg_element(GMarkupParseContext *ctxt, const gchar *element,
				const gchar **names, const gchar **values,
				gpointer user_data, GError **gerr)
{
	struct map_parser *parser = user_data;
	struct map_data *data = parser->data;
	DBusMessageIter entry, dict, *iter = parser->iter;
	struct map_msg *msg;
	const gchar *key;
	gint i;

	if (strcasecmp("msg", element) != 0)
		return;

	for (i = 0, key = names[i]; key; key = names[++i]) {
		if (strcasecmp(key, "handle") == 0)
			break;
	}

	msg = g_hash_table_lookup(data->messages, key);
	if (msg == NULL) {
		msg = map_msg_create(data, values[i]);
		if (msg == NULL)
			return;
	}

	dbus_message_iter_open_container(iter, DBUS_TYPE_DICT_ENTRY, NULL,
								&entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
								&msg->path);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	for (i = 0, key = names[i]; key; key = names[++i]) {
		struct map_msg_parser *parser;

		for (parser = msg_parsers; parser && parser->name; parser++) {
			if (strcasecmp(key, parser->name) == 0) {
				parser->func(msg, values[i], &dict);
				break;
			}
		}
	}

	dbus_message_iter_close_container(&entry, &dict);
	dbus_message_iter_close_container(iter, &entry);
}

static const GMarkupParser msg_parser = {
	msg_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static void message_listing_cb(struct obc_session *session,
						struct obc_transfer *transfer,
						GError *err, void *user_data)
{
	struct map_data *map = user_data;
	struct map_parser *parser;
	GMarkupParseContext *ctxt;
	DBusMessage *reply;
	DBusMessageIter iter, array;
	char *contents;
	size_t size;
	int perr;

	if (err != NULL) {
		reply = g_dbus_create_error(map->msg,
						ERROR_INTERFACE ".Failed",
						"%s", err->message);
		goto done;
	}

	perr = obc_transfer_get_contents(transfer, &contents, &size);
	if (perr < 0) {
		reply = g_dbus_create_error(map->msg,
						ERROR_INTERFACE ".Failed",
						"Error reading contents: %s",
						strerror(-perr));
		goto done;
	}

	reply = dbus_message_new_method_return(map->msg);
	if (reply == NULL)
		return;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_OBJECT_PATH_AS_STRING
					DBUS_TYPE_ARRAY_AS_STRING
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&array);

	parser = g_new(struct map_parser, 1);
	parser->data = map;
	parser->iter = &array;

	ctxt = g_markup_parse_context_new(&msg_parser, 0, parser, NULL);
	g_markup_parse_context_parse(ctxt, contents, size, NULL);
	g_markup_parse_context_free(ctxt);
	dbus_message_iter_close_container(&iter, &array);
	g_free(contents);
	g_free(parser);

done:
	g_dbus_send_message(conn, reply);
	dbus_message_unref(map->msg);
}

static DBusMessage *map_get_message_listing(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct map_data *map = user_data;
	struct obc_transfer *transfer;
	const char *folder;
	DBusMessageIter msg_iter;
	GError *err = NULL;
	DBusMessage *reply;

	dbus_message_iter_init(message, &msg_iter);

	if (dbus_message_iter_get_arg_type(&msg_iter) != DBUS_TYPE_STRING)
		return g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);

	dbus_message_iter_get_basic(&msg_iter, &folder);

	transfer = obc_transfer_get("x-bt/MAP-msg-listing", folder, NULL, &err);
	if (transfer == NULL)
		goto fail;

	if (obc_session_queue(map->session, transfer, message_listing_cb, map,
								&err)) {
		map->msg = dbus_message_ref(message);
		return NULL;
	}

fail:
	reply = g_dbus_create_error(message, ERROR_INTERFACE ".Failed", "%s",
								err->message);
	g_error_free(err);
	return reply;
}

static const GDBusMethodTable map_methods[] = {
	{ GDBUS_ASYNC_METHOD("SetFolder",
				GDBUS_ARGS({ "name", "s" }), NULL,
				map_setpath) },
	{ GDBUS_ASYNC_METHOD("GetFolderListing",
					GDBUS_ARGS({ "dummy", "a{ss}" }),
					GDBUS_ARGS({ "content", "aa{sv}" }),
					map_get_folder_listing) },
	{ GDBUS_ASYNC_METHOD("GetMessageListing",
			GDBUS_ARGS({ "folder", "s" }, { "dummy", "a{ss}" }),
			GDBUS_ARGS({ "messages", "a{oa{sv}}" }),
			map_get_message_listing) },
	{ }
};

static void map_msg_remove(void *data)
{
	struct map_msg *msg = data;
	char *path;

	path = msg->path;
	msg->path = NULL;
	g_dbus_unregister_interface(conn, path, MAP_MSG_INTERFACE);
	g_free(path);
}

static void map_free(void *data)
{
	struct map_data *map = data;

	obc_session_unref(map->session);
	g_hash_table_unref(map->messages);
	g_free(map);
}

static int map_probe(struct obc_session *session)
{
	struct map_data *map;
	const char *path;

	path = obc_session_get_path(session);

	DBG("%s", path);

	map = g_try_new0(struct map_data, 1);
	if (!map)
		return -ENOMEM;

	map->session = obc_session_ref(session);
	map->messages = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
								map_msg_remove);

	if (!g_dbus_register_interface(conn, path, MAP_INTERFACE, map_methods,
					NULL, NULL, map, map_free)) {
		map_free(map);

		return -ENOMEM;
	}

	return 0;
}

static void map_remove(struct obc_session *session)
{
	const char *path = obc_session_get_path(session);

	DBG("%s", path);

	g_dbus_unregister_interface(conn, path, MAP_INTERFACE);
}

static struct obc_driver map = {
	.service = "MAP",
	.uuid = MAS_UUID,
	.target = OBEX_MAS_UUID,
	.target_len = OBEX_MAS_UUID_LEN,
	.probe = map_probe,
	.remove = map_remove
};

int map_init(void)
{
	int err;

	DBG("");

	conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (!conn)
		return -EIO;

	err = obc_driver_register(&map);
	if (err < 0) {
		dbus_connection_unref(conn);
		conn = NULL;
		return err;
	}

	return 0;
}

void map_exit(void)
{
	DBG("");

	dbus_connection_unref(conn);
	conn = NULL;

	obc_driver_unregister(&map);
}
