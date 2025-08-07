// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Intel Corporation
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "bluetooth/bluetooth.h"

#include "gdbus/gdbus.h"

#include "btio/btio.h"
#include "obexd/src/plugin.h"
#include "obexd/src/obex.h"
#include "obexd/src/service.h"
#include "obexd/src/mimetype.h"
#include "obexd/src/log.h"
#include "obexd/src/manager.h"
#include "obexd/src/obexd.h"
#include "filesystem.h"

#define SYNCML_TARGET_SIZE 11

static const uint8_t SYNCML_TARGET[SYNCML_TARGET_SIZE] = {
			0x53, 0x59, 0x4E, 0x43, 0x4D, 0x4C, 0x2D, 0x53,
			0x59, 0x4E, 0x43 };

#define SYNCEVOLUTION_CHANNEL  19

#define SYNCEVOLUTION_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\
<record>								\
 <attribute id=\"0x0001\">						\
    <sequence>								\
      <uuid value=\"00000002-0000-1000-8000-0002ee000002\"/>		\
    </sequence>							\
 </attribute>								\
									\
 <attribute id=\"0x0004\">						\
    <sequence>								\
      <sequence>							\
        <uuid value=\"0x0100\"/>					\
      </sequence>							\
      <sequence>							\
        <uuid value=\"0x0003\"/>					\
        <uint8 value=\"%u\" name=\"channel\"/>				\
      </sequence>							\
      <sequence>							\
        <uuid value=\"0x0008\"/>					\
      </sequence>							\
    </sequence>							\
 </attribute>								\
									\
 <attribute id=\"0x0100\">						\
    <text value=\"%s\" name=\"name\"/>					\
 </attribute>								\
</record>"

#define SYNCE_BUS_NAME	"org.syncevolution"
#define SYNCE_PATH	"/org/syncevolution/Server"
#define SYNCE_SERVER_INTERFACE	"org.syncevolution.Server"
#define SYNCE_CONN_INTERFACE	"org.syncevolution.Connection"

struct synce_context {
	struct obex_session *os;
	DBusConnection *dbus_conn;
	char *conn_obj;
	unsigned int reply_watch;
	unsigned int abort_watch;
	GString *buffer;
	int lasterr;
	char *id;
};

static void append_dict_entry(DBusMessageIter *dict, const char *key,
							int type, void *val)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &val);
	dbus_message_iter_close_container(dict, &entry);
}

static gboolean reply_signal(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct synce_context *context = data;
	const char *path = dbus_message_get_path(msg);
	DBusMessageIter iter, array_iter;
	char *value;
	int length;

	if (strcmp(context->conn_obj, path) != 0) {
		obex_object_set_io_flags(context, G_IO_ERR, -EPERM);
		context->lasterr = -EPERM;
		return FALSE;
	}

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_recurse(&iter, &array_iter);
	dbus_message_iter_get_fixed_array(&array_iter, &value, &length);

	context->buffer = g_string_new_len(value, length);
	obex_object_set_io_flags(context, G_IO_IN, 0);
	context->lasterr = 0;

	return TRUE;
}

static gboolean abort_signal(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct synce_context *context = data;

	obex_object_set_io_flags(context, G_IO_ERR, -EPERM);
	context->lasterr = -EPERM;

	return TRUE;
}

static void connect_cb(DBusPendingCall *call, void *user_data)
{
	struct synce_context *context = user_data;
	DBusConnection *conn;
	DBusMessage *reply;
	DBusError err;
	char *path;

	conn = context->dbus_conn;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_message_get_args(reply, &err, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE) {
		error("%s", err.message);
		dbus_error_free(&err);
		goto failed;
	}

	DBG("Got conn object %s from syncevolution", path);
	context->conn_obj = g_strdup(path);

	context->reply_watch = g_dbus_add_signal_watch(conn, NULL, path,
						SYNCE_CONN_INTERFACE, "Reply",
						reply_signal, context, NULL);

	context->abort_watch = g_dbus_add_signal_watch(conn, NULL, path,
						SYNCE_CONN_INTERFACE, "Abort",
						abort_signal, context, NULL);

	dbus_message_unref(reply);

	return;

failed:
	obex_object_set_io_flags(context, G_IO_ERR, -EPERM);
	context->lasterr = -EPERM;
}

static void process_cb(DBusPendingCall *call, void *user_data)
{
	struct synce_context *context = user_data;
	DBusMessage *reply;
	DBusError derr;

	reply = dbus_pending_call_steal_reply(call);
	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("process_cb(): syncevolution replied with an error:"
					" %s, %s", derr.name, derr.message);
		dbus_error_free(&derr);

		obex_object_set_io_flags(context, G_IO_ERR, -EPERM);
		context->lasterr = -EPERM;
		goto done;
	}

	obex_object_set_io_flags(context, G_IO_OUT, 0);
	context->lasterr = 0;

done:
	dbus_message_unref(reply);
}

static void *synce_connect(struct obex_session *os, int *err)
{
	DBusConnection *conn;
	struct synce_context *context;
	char *address;

	manager_register_session(os);

	conn = manager_dbus_get_connection();
	if (!conn)
		goto failed;

	context = g_new0(struct synce_context, 1);
	context->dbus_conn = conn;
	context->lasterr = -EAGAIN;
	context->os = os;

	if (obex_getpeername(os, &address) == 0) {
		context->id = g_strdup_printf("%s+%d", address,
							SYNCEVOLUTION_CHANNEL);
		g_free(address);
	}

	if (err)
		*err = 0;

	return context;

failed:
	if (err)
		*err = -EPERM;

	return NULL;
}

static int synce_put(struct obex_session *os, void *user_data)
{
	return 0;
}

static int synce_get(struct obex_session *os, void *user_data)
{
	return obex_get_stream_start(os, NULL);
}

static void close_cb(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError derr;

	reply = dbus_pending_call_steal_reply(call);
	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("close_cb(): syncevolution replied with an error:"
					" %s, %s", derr.name, derr.message);
		dbus_error_free(&derr);
	}

	dbus_message_unref(reply);
}

static void synce_disconnect(struct obex_session *os, void *user_data)
{
	struct synce_context *context = user_data;

	g_free(context);
}

static void *synce_open(const char *name, int oflag, mode_t mode,
				void *user_data, size_t *size, int *err)
{
	struct synce_context *context = user_data;

	if (err)
		*err = context ? 0 : -EFAULT;

	return user_data;
}

static int synce_close(void *object)
{
	struct synce_context *context = object;
	DBusMessage *msg;
	const char *error;
	gboolean normal;
	DBusPendingCall *call;

	if (!context->conn_obj)
		goto done;

	msg = dbus_message_new_method_call(SYNCE_BUS_NAME, context->conn_obj,
						SYNCE_CONN_INTERFACE, "Close");
	if (!msg)
		goto failed;

	normal = TRUE;
	error = "none";
	dbus_message_append_args(msg, DBUS_TYPE_BOOLEAN, &normal,
				DBUS_TYPE_STRING, &error, DBUS_TYPE_INVALID);

	g_dbus_send_message_with_reply(context->dbus_conn, msg, &call, -1);
	dbus_pending_call_set_notify(call, close_cb, NULL, NULL);
	dbus_message_unref(msg);
	dbus_pending_call_unref(call);

failed:
	g_dbus_remove_watch(context->dbus_conn, context->reply_watch);
	context->reply_watch = 0;
	g_dbus_remove_watch(context->dbus_conn, context->abort_watch);
	context->abort_watch = 0;

	g_free(context->conn_obj);
	context->conn_obj = NULL;

done:
	dbus_connection_unref(context->dbus_conn);
	g_free(context);
	return 0;
}

static ssize_t synce_read(void *object, void *buf, size_t count)
{
	struct synce_context *context = object;
	DBusConnection *conn;
	char transport[36], transport_description[24];
	const char *session;
	DBusMessage *msg;
	DBusMessageIter iter, dict;
	gboolean authenticate;
	DBusPendingCall *call;

	if (context->buffer)
		return string_read(context->buffer, buf, count);

	conn = manager_dbus_get_connection();
	if (conn == NULL)
		return -EPERM;

	msg = dbus_message_new_method_call(SYNCE_BUS_NAME, SYNCE_PATH,
				SYNCE_SERVER_INTERFACE, "Connect");
	if (!msg)
		return -EPERM;

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
		DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_STRING_AS_STRING
		DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	append_dict_entry(&dict, "id", DBUS_TYPE_STRING, context->id);

	snprintf(transport, sizeof(transport), "%s.obexd", OBEXD_SERVICE);
	append_dict_entry(&dict, "transport", DBUS_TYPE_STRING, transport);

	snprintf(transport_description, sizeof(transport_description),
						"version %s", VERSION);
	append_dict_entry(&dict, "transport_description", DBUS_TYPE_STRING,
							transport_description);

	dbus_message_iter_close_container(&iter, &dict);

	authenticate = FALSE;
	session = "";
	dbus_message_append_args(msg, DBUS_TYPE_BOOLEAN, &authenticate,
			DBUS_TYPE_STRING, &session, DBUS_TYPE_INVALID);

	if (!g_dbus_send_message_with_reply(conn, msg, &call, -1)) {
		error("D-Bus call to %s failed.", SYNCE_SERVER_INTERFACE);
		dbus_message_unref(msg);
		return -EPERM;
	}

	dbus_pending_call_set_notify(call, connect_cb, context, NULL);

	dbus_pending_call_unref(call);
	dbus_message_unref(msg);

	return -EAGAIN;
}

static ssize_t synce_write(void *object, const void *buf, size_t count)
{
	struct synce_context *context = object;
	DBusMessage *msg;
	DBusMessageIter iter, array_iter;
	DBusPendingCall *call;
	const char *type = obex_get_type(context->os);

	if (context->lasterr == 0)
		return count;

	if (!context->conn_obj)
		return -EFAULT;

	msg = dbus_message_new_method_call(SYNCE_BUS_NAME, context->conn_obj,
					SYNCE_CONN_INTERFACE, "Process");
	if (!msg)
		return -EFAULT;

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_BYTE_AS_STRING, &array_iter);

	dbus_message_iter_append_fixed_array(&array_iter, DBUS_TYPE_BYTE,
						&buf, count);
	dbus_message_iter_close_container(&iter, &array_iter);

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &type,
						DBUS_TYPE_INVALID);

	if (!g_dbus_send_message_with_reply(context->dbus_conn, msg,
								&call, -1)) {
		error("D-Bus call to %s failed.", SYNCE_CONN_INTERFACE);
		dbus_message_unref(msg);
		return -EPERM;
	}

	dbus_pending_call_set_notify(call, process_cb, context, NULL);

	dbus_message_unref(msg);
	dbus_pending_call_unref(call);

	return -EAGAIN;
}

static const struct obex_mime_type_driver synce_driver = {
	.target = SYNCML_TARGET,
	.target_size = SYNCML_TARGET_SIZE,
	.open = synce_open,
	.close = synce_close,
	.read = synce_read,
	.write = synce_write,
};

static const struct obex_service_driver synce = {
	.name = "OBEX server for SyncML, using SyncEvolution",
	.service = OBEX_SYNCEVOLUTION,
	.channel = SYNCEVOLUTION_CHANNEL,
	.secure = TRUE,
	.record = SYNCEVOLUTION_RECORD,
	.target = SYNCML_TARGET,
	.target_size = SYNCML_TARGET_SIZE,
	.get = synce_get,
	.put = synce_put,
	.connect = synce_connect,
	.disconnect = synce_disconnect,
};

static int synce_init(void)
{
	int err;

	err = obex_mime_type_driver_register(&synce_driver);
	if (err < 0)
		return err;

	return obex_service_driver_register(&synce);
}

static void synce_exit(void)
{
	obex_service_driver_unregister(&synce);
	obex_mime_type_driver_unregister(&synce_driver);
}

OBEX_PLUGIN_DEFINE(syncevolution, synce_init, synce_exit)
