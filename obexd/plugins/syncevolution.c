/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Intel Corporation
 *  Copyright (C) 2007-2009  Marcel Holtmann <marcel@holtmann.org>
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

#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <dbus/dbus.h>

#include <bluetooth/bluetooth.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "plugin.h"
#include "obex.h"
#include "service.h"
#include "logging.h"
#include "dbus.h"
#include "btio.h"
#include "obexd.h"

#define SYNCML_TARGET_SIZE 11

static const guint8 SYNCML_TARGET[SYNCML_TARGET_SIZE] = {
			0x53, 0x59, 0x4E, 0x43, 0x4D, 0x4C, 0x2D, 0x53,
			0x59, 0x4E, 0x43 };

#define SYNCEVOLUTION_CHANNEL  16

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

static char match_string[256];

struct synce_context {
	struct obex_session *os;
	DBusConnection *dbus_conn;
	gchar *conn_obj;
	gboolean reply_received;
};

struct callback_data {
	obex_t *obex;
	obex_object_t *obj;
};

static GSList *context_list = NULL;

static struct synce_context *find_context(struct obex_session *os)
{
	GSList *l;

	for (l = context_list; l != NULL; l = l->next) {
		struct synce_context *context = l->data;

		if (context->os == os)
			return context;
	}

	return NULL;
}

static struct synce_context *find_context_by_conn_obj(const char *path)
{
	GSList *l;

	for (l = context_list; l != NULL; l = l->next) {
		struct synce_context *context = l->data;

		if (strcmp(context->conn_obj, path) == 0)
			return context;
	}

	return NULL;
}

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

static void handle_connection_reply_signal(DBusMessage *msg,
				const char *obj_path, void *data)
{
	struct synce_context *context = data;
	struct obex_session *os = context->os;
	DBusMessageIter iter, array_iter;
	gchar *value;
	gint length;

	if (strcmp(context->conn_obj, obj_path) != 0)
		return;

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_recurse(&iter, &array_iter);
	dbus_message_iter_get_fixed_array(&array_iter, &value, &length);

	if (length == 0)
		return;

	os->buf = g_malloc(length);
	memcpy(os->buf, value, length);
	os->size = length;
	os->finished = TRUE;
	context->reply_received = TRUE;
	OBEX_ResumeRequest(os->obex);
}

static void handle_connection_abort_signal(DBusMessage *msg,
				const char *obj_path, void *data)
{
	struct synce_context *context = data;
	struct obex_session *os = context->os;

	os->size = 0;
	os->finished = TRUE;
	OBEX_ResumeRequest(os->obex);
	OBEX_TransportDisconnect(os->obex);
}

static DBusHandlerResult signal_filter(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	const char *path = dbus_message_get_path(msg);
	struct synce_context *context;

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	context = find_context_by_conn_obj(path);
	if (!context)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_is_signal(msg, SYNCE_CONN_INTERFACE, "Reply")) {
		debug("Reply signal is received.");
		handle_connection_reply_signal(msg, path, context);
	} else if (dbus_message_is_signal(msg, SYNCE_CONN_INTERFACE, "Abort")) {
		debug("Abort signal is received.");
		handle_connection_abort_signal(msg, path, context);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void connect_cb(DBusPendingCall *call, void *user_data)
{
	static gboolean signal_filter_added = FALSE;
	struct callback_data *cb_data = user_data;
	obex_t *obex = cb_data->obex;
	obex_object_t *obj = cb_data->obj;
	struct obex_session *os = OBEX_GetUserData(obex);
	struct synce_context *context;
	DBusConnection *conn;
	DBusMessage *reply;
	gchar *path;
	obex_headerdata_t hd;

	context = find_context(os);
	if (!context) {
		g_free(cb_data);
		goto failed;
	}

	conn = context->dbus_conn;

	reply = dbus_pending_call_steal_reply(call);

	dbus_message_get_args(reply, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID);
	debug("Got conn object %s from syncevolution", path);
	context->conn_obj = g_strdup(path);

	/* add signal filter */
	if (!signal_filter_added) {
		if (!dbus_connection_add_filter(conn, signal_filter,
							os, NULL)) {
			error("Can't add signal filter");
			dbus_message_unref(reply);
			g_free(cb_data);
			goto failed;
		}
		signal_filter_added = TRUE;
	}

	snprintf(match_string, sizeof(match_string), "type=signal,interface=%s,"
			"path=%s", SYNCE_CONN_INTERFACE, context->conn_obj);
	dbus_bus_add_match(conn, match_string, NULL);
	dbus_connection_flush(conn);

	dbus_message_unref(reply);
	g_free(cb_data);

	/* Append received UUID in WHO header */
	register_session(os->cid, os);
	emit_session_created(os->cid);

	hd.bs = SYNCML_TARGET;
	OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_WHO, hd, SYNCML_TARGET_SIZE,
							OBEX_FL_FIT_ONE_PACKET);
	hd.bq4 = os->cid;
	OBEX_ObjectAddHeader(obex, obj,	OBEX_HDR_CONNECTION, hd, 4,
						OBEX_FL_FIT_ONE_PACKET);
	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
	OBEX_ResumeRequest(obex);

	return;

failed:
	OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
	OBEX_ResumeRequest(obex);
}

static void process_cb(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError derr;

	reply = dbus_pending_call_steal_reply(call);
	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("process_cb(): syncevolution replied with an error:"
					" %s, %s", derr.name, derr.message);
		dbus_error_free(&derr);
	}

	dbus_message_unref(reply);
}

static void synce_connect(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os = OBEX_GetUserData(obex);
	DBusConnection *conn;
	GError *err = NULL;
	gchar address[18], id[36], transport[36], transport_description[24];
	const char *session;
	guint8 channel;
	DBusMessage *msg;
	DBusMessageIter iter, dict;
	gboolean authenticate;
	DBusPendingCall *call;
	struct callback_data *cb_data;
	struct synce_context *context;

	conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (!conn)
		goto failed;

	bt_io_get(os->io, BT_IO_RFCOMM, &err,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_CHANNEL, &channel,
			BT_IO_OPT_INVALID);

	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto failed;
	}

	msg = dbus_message_new_method_call(SYNCE_BUS_NAME, SYNCE_PATH,
				SYNCE_SERVER_INTERFACE, "Connect");
	if (!msg)
		goto failed;

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
		DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_STRING_AS_STRING
		DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	snprintf(id, sizeof(id), "%s+%u", address, channel);
	append_dict_entry(&dict, "id", DBUS_TYPE_STRING, id);

	snprintf(transport, sizeof(transport), "%s.obexd",
					OPENOBEX_SERVICE);
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

	if (!dbus_connection_send_with_reply(conn, msg, &call, -1)) {
		error("D-Bus call to %s failed.", SYNCE_SERVER_INTERFACE);
		dbus_message_unref(msg);
		goto failed;
	}

	cb_data = g_malloc0(sizeof(struct callback_data));
	cb_data->obex = obex;
	cb_data->obj = obj;
	dbus_pending_call_set_notify(call, connect_cb, cb_data, NULL);

	context = g_new0(struct synce_context, 1);
	context->os = os;
	context->dbus_conn = conn;
	context_list = g_slist_append(context_list, context);

	dbus_pending_call_unref(call);
	dbus_message_unref(msg);
	OBEX_SuspendRequest(obex, obj);

	return;

failed:
	OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
}

static void synce_put(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;
	struct synce_context *context;
	DBusMessage *msg;
	DBusMessageIter iter, array_iter;
	DBusPendingCall *call;

	os = OBEX_GetUserData(obex);
	if (!os)
		return;

	context = find_context(os);
	if (!context)
		return;

	if (!context->conn_obj) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_SERVICE_UNAVAILABLE,
					OBEX_RSP_SERVICE_UNAVAILABLE);
		return;
	}

	msg = dbus_message_new_method_call(SYNCE_BUS_NAME, context->conn_obj,
					SYNCE_CONN_INTERFACE, "Process");
	if (!msg)
		return;

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_BYTE_AS_STRING, &array_iter);
	dbus_message_iter_append_fixed_array(&array_iter, DBUS_TYPE_BYTE,
						&os->buf, os->offset);
	dbus_message_iter_close_container(&iter, &array_iter);

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &os->type,
						DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(context->dbus_conn, msg,
								&call, -1)) {
		error("D-Bus call to %s failed.", SYNCE_CONN_INTERFACE);
		dbus_message_unref(msg);
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return;
	}

	dbus_pending_call_set_notify(call, process_cb, os, NULL);

	dbus_message_unref(msg);
	dbus_pending_call_unref(call);

	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
}

static void synce_get(obex_t *obex, obex_object_t *obj)
{
	obex_headerdata_t hd;
	struct obex_session *os;
	struct synce_context *context;

	os = OBEX_GetUserData(obex);
	if (!os)
		return;

	context = find_context(os);
	if (!context)
		return;

	if (!context->reply_received)
		OBEX_SuspendRequest(obex, obj);

	hd.bs = NULL;
	OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_BODY, hd, 0,
					OBEX_FL_STREAM_START);

	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
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

static void synce_disconnect(obex_t *obex)
{
	struct obex_session *os = OBEX_GetUserData(obex);
	struct synce_context *context;
	DBusMessage *msg;
	const gchar *error;
	gboolean normal;
	DBusPendingCall *call;

	context = find_context(os);
	if (!context)
		return;

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

	dbus_connection_send_with_reply(context->dbus_conn, msg, &call, -1);
	dbus_pending_call_set_notify(call, close_cb, NULL, NULL);
	dbus_message_unref(msg);
	dbus_pending_call_unref(call);

failed:
	snprintf(match_string, sizeof(match_string),
				"type=signal,interface=%s,path=%s",
				SYNCE_CONN_INTERFACE, context->conn_obj);
	dbus_bus_remove_match(context->dbus_conn, match_string, NULL);
	g_free(context->conn_obj);
	context->conn_obj = NULL;

done:
	dbus_connection_unref(context->dbus_conn);
	context_list = g_slist_remove(context_list, context);
	g_free(context);
}

static void synce_reset(obex_t *obex)
{
	struct obex_session *os = OBEX_GetUserData(obex);
	struct synce_context *context = find_context(os);

	if (context)
		context->reply_received = 0;
}

struct obex_service_driver synce = {
	.name = "OBEX server for SyncML, using SyncEvolution",
	.service = OBEX_SYNCEVOLUTION,
	.channel = SYNCEVOLUTION_CHANNEL,
	.record = SYNCEVOLUTION_RECORD,
	.target = SYNCML_TARGET,
	.target_size = SYNCML_TARGET_SIZE,
	.get = synce_get,
	.put = synce_put,
	.connect = synce_connect,
	.disconnect = synce_disconnect,
	.reset = synce_reset
};

static int synce_init(void)
{
	return obex_service_driver_register(&synce);
}

static void synce_exit(void)
{
	obex_service_driver_unregister(&synce);
}

OBEX_PLUGIN_DEFINE(syncevolution, synce_init, synce_exit)
