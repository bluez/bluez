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
#include <string.h>

#include <gw-obex.h>
#include <gdbus.h>

#include "log.h"

#include "session.h"
#include "transfer.h"
#include "driver.h"
#include "ftp.h"

#define FTP_INTERFACE "org.openobex.FileTransfer"
#define FTP_UUID "00001106-0000-1000-8000-00805f9b34fb"
#define PCSUITE_UUID "00005005-0000-1000-8000-0002ee000001"

static DBusConnection *conn = NULL;

struct ftp_data {
	struct obc_session *session;
	DBusMessage *msg;
};

static DBusMessage *change_folder(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	GwObex *obex = obc_session_get_obex(session);
	const char *folder;
	int err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &folder,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	if (gw_obex_chdir(obex, folder, &err) == FALSE) {
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"%s", OBEX_ResponseToString(err));
	}

	return dbus_message_new_method_return(message);
}

static void append_variant(DBusMessageIter *iter, int type, void *val)
{
	DBusMessageIter value;
	char sig[2] = { type, '\0' };

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, sig, &value);

	dbus_message_iter_append_basic(&value, type, val);

	dbus_message_iter_close_container(iter, &value);
}

static void dict_append_entry(DBusMessageIter *dict,
			const char *key, int type, void *val)
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

static void xml_element(GMarkupParseContext *ctxt,
			const gchar *element,
			const gchar **names,
			const gchar **values,
			gpointer user_data,
			GError **gerr)
{
	DBusMessageIter dict, *iter = user_data;
	gchar *key;
	gint i;

	if (strcasecmp("folder", element) != 0 && strcasecmp("file", element) != 0)
		return;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dict_append_entry(&dict, "Type", DBUS_TYPE_STRING, &element);

	/* FIXME: User, Group, Other permission must be reviewed */

	i = 0;
	for (key = (gchar *) names[i]; key; key = (gchar *) names[++i]) {
		key[0] = g_ascii_toupper(key[0]);
		if (g_str_equal("Size", key) == TRUE) {
			guint64 size;
			size = g_ascii_strtoll(values[i], NULL, 10);
			dict_append_entry(&dict, key, DBUS_TYPE_UINT64, &size);
		} else
			dict_append_entry(&dict, key, DBUS_TYPE_STRING, &values[i]);
	}

	dbus_message_iter_close_container(iter, &dict);
}

static const GMarkupParser parser = {
	xml_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static void get_file_callback(struct obc_session *session, GError *err,
							void *user_data)
{
	struct ftp_data *ftp = user_data;
	DBusMessage *reply;

	if (!ftp->msg)
		return;

	if (err)
		reply = g_dbus_create_error(ftp->msg,
					"org.openobex.Error.Failed",
					"%s", err->message);
	else
		reply = dbus_message_new_method_return(ftp->msg);

	g_dbus_send_message(conn, reply);

	dbus_message_unref(ftp->msg);
	ftp->msg = NULL;
}

static void list_folder_callback(struct obc_session *session,
					GError *err, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_transfer *transfer = obc_session_get_transfer(session);
	GMarkupParseContext *ctxt;
	DBusMessage *reply;
	DBusMessageIter iter, array;
	const char *buf;
	int size;

	reply = dbus_message_new_method_return(ftp->msg);

	buf = obc_transfer_get_buffer(transfer, &size);
	if (size == 0)
		goto done;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &array);
	ctxt = g_markup_parse_context_new(&parser, 0, &array, NULL);
	g_markup_parse_context_parse(ctxt, buf, strlen(buf) - 1, NULL);
	g_markup_parse_context_free(ctxt);
	dbus_message_iter_close_container(&iter, &array);

	obc_transfer_clear_buffer(transfer);

done:
	g_dbus_send_message(conn, reply);
	dbus_message_unref(ftp->msg);
	ftp->msg = NULL;
}

static DBusMessage *create_folder(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	GwObex *obex = obc_session_get_obex(session);
	const char *folder;
	int err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &folder,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	if (gw_obex_mkdir(obex, folder, &err) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"%s", OBEX_ResponseToString(err));

	return dbus_message_new_method_return(message);
}

static DBusMessage *list_folder(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;

	if (ftp->msg)
		return g_dbus_create_error(message,
				"org.openobex.Error.InProgress",
				"Transfer in progress");

	if (obc_session_get(session, "x-obex/folder-listing",
			NULL, NULL, NULL, 0, list_folder_callback, ftp) < 0)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");

	ftp->msg = dbus_message_ref(message);

	return NULL;
}

static DBusMessage *get_file(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	const char *target_file, *source_file;

	if (ftp->msg)
		return g_dbus_create_error(message,
				"org.openobex.Error.InProgress",
				"Transfer in progress");

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &target_file,
				DBUS_TYPE_STRING, &source_file,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	if (obc_session_get(session, NULL, source_file,
			target_file, NULL, 0, get_file_callback, NULL) < 0)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");

	ftp->msg = dbus_message_ref(message);

	return NULL;
}

static DBusMessage *put_file(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	gchar *sourcefile, *targetfile;

	if (dbus_message_get_args(message, NULL,
					DBUS_TYPE_STRING, &sourcefile,
					DBUS_TYPE_STRING, &targetfile,
					DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments",
				"Invalid arguments in method call");

	if (obc_session_send(session, sourcefile, targetfile) < 0)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");

	return dbus_message_new_method_return(message);
}

static DBusMessage *copy_file(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	GwObex *obex = obc_session_get_obex(session);
	const char *filename, *destname;
	int err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &filename,
				DBUS_TYPE_STRING, &destname,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	if (gw_obex_copy(obex, filename, destname, &err) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"%s", OBEX_ResponseToString(err));

	return dbus_message_new_method_return(message);
}

static DBusMessage *move_file(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	GwObex *obex = obc_session_get_obex(session);
	const char *filename, *destname;
	int err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &filename,
				DBUS_TYPE_STRING, &destname,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	if (gw_obex_move(obex, filename, destname, &err) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"%s", OBEX_ResponseToString(err));

	return dbus_message_new_method_return(message);
}

static DBusMessage *delete(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct ftp_data *ftp = user_data;
	struct obc_session *session = ftp->session;
	GwObex *obex = obc_session_get_obex(session);
	const char *file;
	int err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &file,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	if (gw_obex_delete(obex, file, &err) == FALSE) {
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"%s", OBEX_ResponseToString(err));
	}

	return dbus_message_new_method_return(message);
}

static GDBusMethodTable ftp_methods[] = {
	{ "ChangeFolder",	"s", "",	change_folder	},
	{ "CreateFolder",	"s", "",	create_folder	},
	{ "ListFolder",		"", "aa{sv}",	list_folder,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetFile",		"ss", "",	get_file,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "PutFile",		"ss", "",	put_file	},
	{ "CopyFile",		"ss", "",	copy_file	},
	{ "MoveFile",		"ss", "",	move_file	},
	{ "Delete",		"s", "",	delete		},
	{ }
};

static void ftp_free(void *data)
{
	struct ftp_data *ftp = data;

	obc_session_unref(ftp->session);
	g_free(ftp);
}

static int ftp_probe(struct obc_session *session)
{
	struct ftp_data *ftp;
	const char *path;

	path = obc_session_get_path(session);

	DBG("%s", path);

	ftp = g_try_new0(struct ftp_data, 1);
	if (!ftp)
		return -ENOMEM;

	ftp->session = obc_session_ref(session);

	if (!g_dbus_register_interface(conn, path, FTP_INTERFACE, ftp_methods,
						NULL, NULL, ftp, ftp_free)) {
		ftp_free(ftp);
		return -ENOMEM;
	}

	return 0;
}

static void ftp_remove(struct obc_session *session)
{
	const char *path = obc_session_get_path(session);

	DBG("%s", path);

	g_dbus_unregister_interface(conn, path, FTP_INTERFACE);
}

static struct obc_driver ftp = {
	.service = "FTP",
	.uuid = FTP_UUID,
	.target = OBEX_FTP_UUID,
	.target_len = OBEX_FTP_UUID_LEN,
	.probe = ftp_probe,
	.remove = ftp_remove
};

static struct obc_driver pcsuite = {
	.service = "PCSUITE",
	.uuid = PCSUITE_UUID,
	.target = OBEX_FTP_UUID,
	.target_len = OBEX_FTP_UUID_LEN,
	.probe = ftp_probe,
	.remove = ftp_remove
};

int ftp_init(void)
{
	int err;

	DBG("");

	conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (!conn)
		return -EIO;

	err = obc_driver_register(&ftp);
	if (err < 0)
		goto failed;

	err = obc_driver_register(&pcsuite);
	if (err < 0) {
		obc_driver_unregister(&ftp);
		goto failed;
	}

	return 0;

failed:
	dbus_connection_unref(conn);
	conn = NULL;
	return err;
}

void ftp_exit(void)
{
	DBG("");

	dbus_connection_unref(conn);
	conn = NULL;

	obc_driver_unregister(&ftp);
	obc_driver_unregister(&pcsuite);
}
