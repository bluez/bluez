/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include <glib.h>
#include <gdbus.h>
#include <gw-obex.h>

#include "log.h"
#include "transfer.h"
#include "session.h"

#define TRANSFER_INTERFACE  "org.openobex.Transfer"
#define TRANSFER_BASEPATH   "/org/openobex"

#define DEFAULT_BUFFER_SIZE 4096

static guint64 counter = 0;

struct transfer_callback {
	transfer_callback_t func;
	void *data;
};

static void append_entry(DBusMessageIter *dict,
				const char *key, int type, void *val)
{
	DBusMessageIter entry, value;
	const char *signature;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	switch (type) {
	case DBUS_TYPE_STRING:
		signature = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_BYTE:
		signature = DBUS_TYPE_BYTE_AS_STRING;
		break;
	case DBUS_TYPE_UINT64:
		signature = DBUS_TYPE_UINT64_AS_STRING;
		break;
	default:
		signature = DBUS_TYPE_VARIANT_AS_STRING;
		break;
	}

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
							signature, &value);
	dbus_message_iter_append_basic(&value, type, val);
	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}

static DBusMessage *transfer_get_properties(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct transfer_data *transfer = user_data;
	DBusMessage *reply;
	DBusMessageIter iter, dict;

	reply = dbus_message_new_method_return(message);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	append_entry(&dict, "Name", DBUS_TYPE_STRING, &transfer->name);
	append_entry(&dict, "Size", DBUS_TYPE_UINT64, &transfer->size);
	append_entry(&dict, "Filename", DBUS_TYPE_STRING, &transfer->filename);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *transfer_cancel(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct transfer_data *transfer = user_data;
	struct session_data *session = transfer->session;
	const gchar *sender, *agent;
	DBusMessage *reply;

	sender = dbus_message_get_sender(message);
	agent = session_get_agent(session);
	if (g_str_equal(sender, agent) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.NotAuthorized",
				"Not Authorized");

	reply = dbus_message_new_method_return(message);
	if (!reply)
		return NULL;

	transfer_abort(transfer);

	return reply;
}

static GDBusMethodTable transfer_methods[] = {
	{ "GetProperties", "", "a{sv}", transfer_get_properties },
	{ "Cancel", "", "", transfer_cancel },
	{ }
};

static void transfer_free(struct transfer_data *transfer)
{
	struct session_data *session = transfer->session;

	DBG("%p", transfer);

	if (transfer->xfer) {
		gw_obex_xfer_close(transfer->xfer, NULL);
		gw_obex_xfer_free(transfer->xfer);
	}

	if (transfer->fd > 0)
		close(transfer->fd);

	session_remove_transfer(session, transfer);

	session_unref(session);

	if (transfer->params != NULL) {
		g_free(transfer->params->data);
		g_free(transfer->params);
	}

	if (transfer->conn)
		dbus_connection_unref(transfer->conn);

	g_free(transfer->callback);
	g_free(transfer->filename);
	g_free(transfer->name);
	g_free(transfer->type);
	g_free(transfer->path);
	g_free(transfer->buffer);
	g_free(transfer);
}

struct transfer_data *transfer_register(struct session_data *session,
						const char *filename,
						const char *name,
						const char *type,
						struct transfer_params *params)
{
	struct transfer_data *transfer;

	transfer = g_new0(struct transfer_data, 1);
	transfer->session = session_ref(session);
	transfer->filename = g_strdup(filename);
	transfer->name = g_strdup(name);
	transfer->type = g_strdup(type);
	transfer->params = params;

	/* for OBEX specific mime types we don't need to register a transfer */
	if (type != NULL &&
			(strncmp(type, "x-obex/", 7) == 0 ||
			strncmp(type, "x-bt/", 5) == 0))
		goto done;

	transfer->path = g_strdup_printf("%s/transfer%ju",
			TRANSFER_BASEPATH, counter++);

	transfer->conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (transfer->conn == NULL) {
		transfer_free(transfer);
		return NULL;
	}

	if (g_dbus_register_interface(transfer->conn, transfer->path,
				TRANSFER_INTERFACE,
				transfer_methods, NULL, NULL,
				transfer, NULL) == FALSE) {
		transfer_free(transfer);
		return NULL;
	}

done:
	DBG("%p registered %s", transfer, transfer->path);

	session_add_transfer(session, transfer);

	return transfer;
}

void transfer_unregister(struct transfer_data *transfer)
{
	if (transfer->path) {
		g_dbus_unregister_interface(transfer->conn,
			transfer->path, TRANSFER_INTERFACE);
	}

	DBG("%p unregistered %s", transfer, transfer->path);

	transfer_free(transfer);
}

static gboolean transfer_read(struct transfer_data *transfer, GwObexXfer *xfer)
{
	gint bsize, bread;

	/* check if object size is available */
	if (transfer->size == 0)
		transfer->size = gw_obex_xfer_object_size(xfer);

	/* read all buffered data */
	do {
		bsize = transfer->buffer_len - transfer->filled;

		if (bsize < DEFAULT_BUFFER_SIZE) {
			transfer->buffer_len += DEFAULT_BUFFER_SIZE;
			transfer->buffer = g_realloc(transfer->buffer,
							transfer->buffer_len);
			bsize += DEFAULT_BUFFER_SIZE;
		}

		if (gw_obex_xfer_read(xfer, transfer->buffer +
				transfer->filled, bsize, &bread,
				&transfer->err) == FALSE) {
			if (transfer->err == GW_OBEX_ERROR_NO_DATA) {
				transfer->err = 0;
				return TRUE;
			} else
				return FALSE;
		}

		transfer->filled += bread;
		transfer->transferred += bread;
	} while (bread != 0);

	/* set size to transferred if object is done and size is unknown */
	if (gw_obex_xfer_object_done(xfer) == TRUE &&
			transfer->size == GW_OBEX_UNKNOWN_LENGTH)
		transfer->size = transfer->transferred;

	return TRUE;
}

static void get_buf_xfer_progress(GwObexXfer *xfer,
					gpointer user_data)
{
	struct transfer_data *transfer = user_data;
	struct transfer_callback *callback = transfer->callback;

	if (transfer_read(transfer, xfer) == FALSE)
		goto fail;

	if (gw_obex_xfer_object_done(xfer)) {
		int bsize;
		if (transfer->filled > 0 &&
				transfer->buffer[transfer->filled - 1] == '\0')
			goto done;

		bsize = transfer->buffer_len - transfer->filled;
		if (bsize < 1) {
			transfer->buffer_len += DEFAULT_BUFFER_SIZE;
			transfer->buffer = g_realloc(transfer->buffer,
						transfer->buffer_len);
		}

		transfer->buffer[transfer->filled] = '\0';
		goto done;
	}

	return;

done:
	transfer->size = strlen(transfer->buffer);
fail:
	if (callback)
		callback->func(transfer, transfer->size, transfer->err,
				callback->data);
}

static void get_xfer_progress(GwObexXfer *xfer, gpointer user_data)
{
	struct transfer_data *transfer = user_data;
	struct transfer_callback *callback = transfer->callback;

	if (transfer_read(transfer, xfer) == FALSE)
		goto done;

	if (transfer->fd > 0) {
		gint w;

		w = write(transfer->fd, transfer->buffer, transfer->filled);
		if (w < 0) {
			transfer->err = -errno;
			goto done;
		}

		transfer->filled -= w;
	}

done:
	if (callback)
		callback->func(transfer, transfer->transferred, transfer->err,
				callback->data);
}

static void put_buf_xfer_progress(GwObexXfer *xfer, gpointer user_data)
{
	struct transfer_data *transfer = user_data;
	struct transfer_callback *callback = transfer->callback;
	gint written;

	if (transfer->transferred == transfer->size)
		goto done;

	if (gw_obex_xfer_write(xfer, transfer->buffer + transfer->transferred,
				transfer->size - transfer->transferred,
				&written, &transfer->err) == FALSE)
		goto done;

	if (gw_obex_xfer_flush(xfer, &transfer->err) == FALSE)
		goto done;

	transfer->transferred += written;

done:
	if (callback)
		callback->func(transfer, transfer->transferred, transfer->err,
				callback->data);
}

static void put_xfer_progress(GwObexXfer *xfer, gpointer user_data)
{
	struct transfer_data *transfer = user_data;
	struct transfer_callback *callback = transfer->callback;
	gint written;

	if (transfer->buffer_len == 0) {
		transfer->buffer_len = DEFAULT_BUFFER_SIZE;
		transfer->buffer = g_new0(char, DEFAULT_BUFFER_SIZE);
	}

	do {
		ssize_t len;

		len = read(transfer->fd, transfer->buffer + transfer->filled,
				transfer->buffer_len - transfer->filled);
		if (len < 0) {
			transfer->err = -errno;
			goto done;
		}

		transfer->filled += len;

		if (transfer->filled == 0) {
			gw_obex_xfer_close(xfer, &transfer->err);
			goto done;
		}

		if (gw_obex_xfer_write(xfer, transfer->buffer,
					transfer->filled,
					&written, &transfer->err) == FALSE)
			goto done;

		transfer->filled -= written;
		transfer->transferred += written;
	} while (transfer->filled == 0);

	memmove(transfer->buffer, transfer->buffer + written, transfer->filled);

done:
	if (callback)
		callback->func(transfer, transfer->transferred, transfer->err,
				callback->data);
}

static void transfer_set_callback(struct transfer_data *transfer,
					transfer_callback_t func,
					void *user_data)
{
	struct transfer_callback *callback;

	g_free(transfer->callback);

	callback = g_new0(struct transfer_callback, 1);
	callback->func = func;
	callback->data = user_data;

	transfer->callback = callback;
}

int transfer_get(struct transfer_data *transfer, transfer_callback_t func,
			void *user_data)
{
	struct session_data *session = transfer->session;
	GwObex *obex;
	gw_obex_xfer_cb_t cb;

	if (transfer->xfer != NULL)
		return -EALREADY;

	if (transfer->type != NULL &&
			(strncmp(transfer->type, "x-obex/", 7) == 0 ||
			strncmp(transfer->type, "x-bt/", 5) == 0))
		cb = get_buf_xfer_progress;
	else {
		int fd = open(transfer->name ? : transfer->filename,
				O_WRONLY | O_CREAT, 0600);

		if (fd < 0) {
			error("open(): %s(%d)", strerror(errno), errno);
			return -errno;
		}
		transfer->fd = fd;
		cb = get_xfer_progress;
	}

	obex = session_get_obex(session);

	if (transfer->params != NULL)
		transfer->xfer = gw_obex_get_async_with_apparam(obex,
							transfer->filename,
							transfer->type,
							transfer->params->data,
							transfer->params->size,
							NULL);
	else
		transfer->xfer = gw_obex_get_async(obex,
							transfer->filename,
							transfer->type,
							NULL);
	if (transfer->xfer == NULL)
		return -ENOTCONN;

	if (func)
		transfer_set_callback(transfer, func, user_data);

	gw_obex_xfer_set_callback(transfer->xfer, cb, transfer);

	return 0;
}

int transfer_put(struct transfer_data *transfer, transfer_callback_t func,
			void *user_data)
{
	struct session_data *session = transfer->session;
	GwObex *obex;
	gw_obex_xfer_cb_t cb;
	struct stat st;
	int fd, size;

	if (transfer->xfer != NULL)
		return -EALREADY;

	if (transfer->buffer) {
		cb = put_buf_xfer_progress;
		goto done;
	}

	fd = open(transfer->filename, O_RDONLY);
	if (fd < 0) {
		error("open(): %s(%d)", strerror(errno), errno);
		return -errno;
	}

	if (fstat(fd, &st) < 0) {
		close(fd);
		error("fstat(): %s(%d)", strerror(errno), errno);
		return -errno;
	}

	transfer->fd = fd;
	transfer->size = st.st_size;
	cb = put_xfer_progress;

done:
	obex = session_get_obex(session);
	size = transfer->size < UINT32_MAX ? transfer->size : 0;
	transfer->xfer = gw_obex_put_async(obex, transfer->name,
						transfer->type, size,
						-1, NULL);
	if (transfer->xfer == NULL)
		return -ENOTCONN;

	if (func)
		transfer_set_callback(transfer, func, user_data);

	gw_obex_xfer_set_callback(transfer->xfer, cb, transfer);

	return 0;
}

void transfer_abort(struct transfer_data *transfer)
{
	struct transfer_callback *callback = transfer->callback;

	if (transfer->xfer == NULL)
		return;

	gw_obex_xfer_abort(transfer->xfer, NULL);
	gw_obex_xfer_free(transfer->xfer);
	transfer->xfer = NULL;

	if (callback)
		callback->func(transfer, transfer->transferred, -ECANCELED,
				callback->data);
}
