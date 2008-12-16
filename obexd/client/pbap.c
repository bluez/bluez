/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2008  Intel Corporation
 *  Copyright (C) 2007-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <glib.h>
#include <gdbus.h>

#include "session.h"
#include "pbap.h"

#define ERROR_INF PBAP_INTERFACE ".Error"

#define FORMAT_VCARD21	0x0
#define FORMAT_VCARD30	0x1

#define ORDER_INDEXED		0x0
#define ORDER_ALPHANUMERIC	0x1
#define ORDER_PHONETIC		0x2

#define DEFAULT_COUNT	65535
#define DEFAULT_OFFSET	0

#define PULLPHONEBOOK		0x1
#define GETPHONEBOOKSIZE	0x2

#define ORDER_TAG		0x01
#define SEARCHVALUE_TAG		0x02
#define SEARCHATTRIB_TAG	0x03
#define MAXLISTCOUNT_TAG	0x04
#define LISTSTARTOFFSET_TAG	0x05
#define FILTER_TAG		0x06
#define FORMAT_TAG		0X07
#define PHONEBOOKSIZE_TAG	0X08
#define NEWMISSEDCALLS_TAG	0X09

/* The following length is in the unit of byte */
#define ORDER_LEN		1
#define SEARCHATTRIB_LEN	1
#define MAXLISTCOUNT_LEN	2
#define LISTSTARTOFFSET_LEN	2
#define FILTER_LEN		8
#define FORMAT_LEN		1
#define PHONEBOOKSIZE_LEN	2
#define NEWMISSEDCALLS_LEN	1

#define get_be16(val)	GUINT16_FROM_BE(bt_get_unaligned((guint16 *) val))

struct pullphonebook_apparam {
	uint8_t     filter_tag;
	uint8_t     filter_len;
	uint64_t    filter;
	uint8_t     format_tag;
	uint8_t     format_len;
	uint8_t     format;
	uint8_t     maxlistcount_tag;
	uint8_t     maxlistcount_len;
	uint16_t    maxlistcount;
	uint8_t     liststartoffset_tag;
	uint8_t     liststartoffset_len;
	uint16_t    liststartoffset;
} __attribute__ ((packed));

struct pullvcardentry_apparam {
        uint8_t     filter_tag;
        uint8_t     filter_len;
        uint64_t    filter;
        uint8_t     format_tag;
        uint8_t     format_len;
        uint8_t     format;
} __attribute__ ((packed));

struct apparam_hdr {
	uint8_t		tag;
	uint8_t		len;
	uint8_t		val[0];
} __attribute__ ((packed));

#define APPARAM_HDR_SIZE 2

static gchar *build_phonebook_path(const char *location, const char *item)
{
	gchar *path = NULL, *tmp, *tmp1;

	if (!g_ascii_strcasecmp(location, "INT") ||
			!g_ascii_strcasecmp(location, "INTERNAL"))
		path = g_strdup("telecom");
	else if (!g_ascii_strncasecmp(location, "SIM", 3)) {
		if (strlen(location) == 3)
			tmp = g_strdup("SIM1");
		else
			tmp = g_ascii_strup(location, 4);

		path = g_build_filename(tmp, "telecom", NULL);
		g_free(tmp);
	} else
		return NULL;

	if (!g_ascii_strcasecmp(item, "PB") ||
		!g_ascii_strcasecmp(item, "ICH") ||
		!g_ascii_strcasecmp(item, "OCH") ||
		!g_ascii_strcasecmp(item, "MCH") ||
		!g_ascii_strcasecmp(item, "CCH")) {
		tmp = path;
		tmp1 = g_ascii_strdown(item, -1);
		path = g_build_filename(tmp, tmp1, NULL);
		g_free(tmp);
		g_free(tmp1);
	} else {
		g_free(path);
		return NULL;
	}

	return path;
}

/* should only be called inside pbap_set_path */
static void pbap_reset_path(struct session_data *session)
{
	int err = 0;
	char **paths = NULL, **item;
	struct pbap_data *pbapdata = session->pbapdata;

	if (!pbapdata->path)
		return;

	gw_obex_chdir(session->obex, "", &err);

	paths = g_strsplit(pbapdata->path, "/", 3);

	for (item = paths; *item; item++)
		gw_obex_chdir(session->obex, *item, &err);

	g_strfreev(paths);
}

static gint pbap_set_path(struct session_data *session, const char *path)
{
	int err = 0;
	char **paths = NULL, **item;
	struct pbap_data *pbapdata = session->pbapdata;

	if (!path)
		return OBEX_RSP_BAD_REQUEST;

	if (pbapdata->path != NULL && 	g_str_equal(pbapdata->path, path))
		return 0;

	if (gw_obex_chdir(session->obex, "", &err) == FALSE) {
		if (err == OBEX_RSP_NOT_IMPLEMENTED)
			goto done;
		goto fail;
	}

	paths = g_strsplit(path, "/", 3);
	for (item = paths; *item; item++) {
		if (gw_obex_chdir(session->obex, *item, &err) == FALSE) {
			/* we need to reset the path to the saved one on fail*/
			pbap_reset_path(session);
			goto fail;
		}
	}

	g_strfreev(paths);

done:
	g_free(pbapdata->path);
	pbapdata->path = g_strdup(path);
	return 0;

fail:
	if (paths)
		g_strfreev(paths);

	return err;
}

static void read_return_apparam(struct session_data *session,
				guint16 *phone_book_size, guint8 *new_missed_calls)
{
	GwObexXfer *xfer = session->xfer;
	unsigned char *buf;
	size_t size = 0;

	*phone_book_size = 0;
	*new_missed_calls = 0;

	if (xfer == NULL)
		return;

	buf = gw_obex_xfer_object_apparam(xfer, &size);

	if (size < APPARAM_HDR_SIZE)
		return;

	while (size > APPARAM_HDR_SIZE) {
		struct apparam_hdr *hdr = (struct apparam_hdr *) buf;

		if (hdr->len > size - APPARAM_HDR_SIZE) {
			fprintf(stderr, "Unexpected PBAP pullphonebook app"
					" length, tag %d, len %d\n",
					hdr->tag, hdr->len);
			return;
		}

		switch (hdr->tag) {
		case PHONEBOOKSIZE_TAG:
			if (hdr->len == PHONEBOOKSIZE_LEN)
				*phone_book_size = get_be16(hdr->val);
			break;
		case NEWMISSEDCALLS_TAG:
			if (hdr->len == NEWMISSEDCALLS_LEN)
				*new_missed_calls = hdr->val[0];
			break;
		default:
			fprintf(stderr, "Unexpected PBAP pullphonebook app"
					" parameter, tag %d, len %d\n",
					hdr->tag, hdr->len);
		}

		buf += APPARAM_HDR_SIZE + hdr->len;
		size -= APPARAM_HDR_SIZE + hdr->len;
	}
}

static void pull_phonebook_callback(struct session_data *session,
					void *user_data)
{
	DBusMessage *reply;
	char *buf = "";

	reply = dbus_message_new_method_return(session->msg);

	if (session->filled > 0)
		buf = session->buffer;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &buf,
			DBUS_TYPE_INVALID);

	session->filled = 0;
	g_dbus_send_message(session->conn, reply);
	dbus_message_unref(session->msg);
	session->msg = NULL;
}

static void phonebook_size_callback(struct session_data *session,
					void *user_data)
{
	DBusMessage *reply;
	guint16 phone_book_size;
	guint8 new_missed_calls;

	reply = dbus_message_new_method_return(session->msg);

	read_return_apparam(session, &phone_book_size, &new_missed_calls);

	dbus_message_append_args(reply,
			DBUS_TYPE_UINT16, &phone_book_size,
			DBUS_TYPE_INVALID);

	session->filled = 0;
	g_dbus_send_message(session->conn, reply);
	dbus_message_unref(session->msg);
	session->msg = NULL;
}

static DBusMessage *pull_phonebook(struct session_data *session,
					DBusMessage *message, guint8 type,
					const char *name, uint64_t filter,
					uint8_t format,	uint16_t maxlistcount,
					uint16_t liststartoffset)
{
	struct pullphonebook_apparam apparam;
	session_callback_t func;

	if (session->msg)
		return g_dbus_create_error(message,
				"org.openobex.Error.InProgress",
				"Transfer in progress");

	apparam.filter_tag = FILTER_TAG;
	apparam.filter_len = FILTER_LEN;
	apparam.filter = GUINT64_TO_BE(filter);
	apparam.format_tag = FORMAT_TAG;
	apparam.format_len = FORMAT_LEN;
	apparam.format = format;
	apparam.maxlistcount_tag = MAXLISTCOUNT_TAG;
	apparam.maxlistcount_len = MAXLISTCOUNT_LEN;
	apparam.maxlistcount = GUINT16_TO_BE(maxlistcount);
	apparam.liststartoffset_tag = LISTSTARTOFFSET_TAG;
	apparam.liststartoffset_len = LISTSTARTOFFSET_LEN;
	apparam.liststartoffset = GUINT16_TO_BE(liststartoffset);

	switch (type) {
	case PULLPHONEBOOK:
		func = pull_phonebook_callback;
		break;
	case GETPHONEBOOKSIZE:
		func = phonebook_size_callback;
		break;
	default:
		fprintf(stderr, "Unexpected type : 0x%2x\n", type);
	}

	if (session_get(session, "x-bt/phonebook", name, NULL,
				(guint8 *) &apparam, sizeof(apparam),
				func) < 0)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");

	session->msg = dbus_message_ref(message);
	session->filled = 0;

	return NULL;
}

static int set_format(struct session_data *session, const char *formatstr)
{
	struct pbap_data *pbapdata = session->pbapdata;

	if (!formatstr || g_str_equal(formatstr, "")) {
		pbapdata->format = FORMAT_VCARD21;
		return 0;
	}

	if (!g_ascii_strcasecmp(formatstr, "vcard21"))
		pbapdata->format = FORMAT_VCARD21;
	else if (!g_ascii_strcasecmp(formatstr, "vcard30"))
		pbapdata->format = FORMAT_VCARD30;
	else
		return -EINVAL;

	return 0;
}

static int set_order(struct session_data *session, const char *orderstr)
{
	struct pbap_data *pbapdata = session->pbapdata;

	if (!orderstr || g_str_equal(orderstr, "")) {
		pbapdata->order = ORDER_INDEXED;
		return 0;
	}

	if (!g_ascii_strcasecmp(orderstr, "indexed"))
		pbapdata->order = ORDER_INDEXED;
	else if (!g_ascii_strcasecmp(orderstr, "alphanumeric"))
		pbapdata->order = ORDER_ALPHANUMERIC;
	else if (!g_ascii_strcasecmp(orderstr, "phonetic"))
		pbapdata->order = ORDER_PHONETIC;
	else
		return -EINVAL;

	return 0;
}

static DBusMessage *pbap_select(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *item, *location;
	char *path = NULL;
	int err = 0;

	if (dbus_message_get_args(message, NULL,
			DBUS_TYPE_STRING, &location,
			DBUS_TYPE_STRING, &item,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", NULL);

	path = build_phonebook_path(location, item);
	if (!path)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", "InvalidPhonebook");

	err = pbap_set_path(session, path);
	g_free(path);
	if (err)
		return g_dbus_create_error(message,
				ERROR_INF ".Failed",
				OBEX_ResponseToString(err));

	return dbus_message_new_method_return(message);
}

static DBusMessage *pbap_pull_all(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	struct pbap_data *pbapdata = session->pbapdata;
	DBusMessage * err;
	char *name;

	if (!pbapdata->path)
		return g_dbus_create_error(message,
				ERROR_INF ".Forbidden", "Call Select first of all");

	name = g_strconcat(pbapdata->path, ".vcf", NULL);

	err = pull_phonebook(session, message, PULLPHONEBOOK, name,
				pbapdata->filter, pbapdata->format,
				DEFAULT_COUNT, DEFAULT_OFFSET);
	g_free(name);
	return err;
}

static DBusMessage *pbap_pull_vcard(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	struct pbap_data *pbapdata = session->pbapdata;
	struct pullvcardentry_apparam apparam;
	const char *name;

	if (!pbapdata->path)
		return g_dbus_create_error(message,
				ERROR_INF ".Forbidden", "Call Select first of all");

	if (dbus_message_get_args(message, NULL,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", NULL);

	if (session->msg)
		return g_dbus_create_error(message,
				"org.openobex.Error.InProgress",
				"Transfer in progress");

	apparam.filter_tag = FILTER_TAG;
	apparam.filter_len = FILTER_LEN;
	apparam.filter = GUINT64_TO_BE(pbapdata->filter);
	apparam.format_tag = FORMAT_TAG;
	apparam.format_len = FORMAT_LEN;
	apparam.format = pbapdata->format;

	if (session_get(session, "x-bt/vcard", name, NULL,
			(guint8 *)&apparam, sizeof(apparam),
			pull_phonebook_callback) < 0)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");

	session->msg = dbus_message_ref(message);
	session->filled = 0;

	return NULL;
}

static DBusMessage *pbap_get_size(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	struct pbap_data *pbapdata = session->pbapdata;
	DBusMessage * err;
	char *name;

	if (!pbapdata->path)
		return g_dbus_create_error(message,
				ERROR_INF ".Forbidden", "Call Select first of all");

	name = g_strconcat(pbapdata->path, ".vcf", NULL);

	err = pull_phonebook(session, message, GETPHONEBOOKSIZE, name,
				pbapdata->filter, pbapdata->format,
				0, DEFAULT_OFFSET);
	g_free(name);
	return err;
}

static DBusMessage *pbap_set_format(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *format;

	if (dbus_message_get_args(message, NULL,
			DBUS_TYPE_STRING, &format,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", NULL);

	if (set_format(session, format) < 0)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", "InvalidFormat");

	return dbus_message_new_method_return(message);
}

static DBusMessage *pbap_set_order(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *order;

	if (dbus_message_get_args(message, NULL,
			DBUS_TYPE_STRING, &order,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", NULL);

	if (set_order(session, order) < 0)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", "InvalidOrder");

	return dbus_message_new_method_return(message);
}

static GDBusMethodTable pbap_methods[] = {
	{ "Select",	"ss",	"",	pbap_select },
	{ "PullAll",	"",	"s",	pbap_pull_all,
					G_DBUS_METHOD_FLAG_ASYNC },
	{ "Pull",	"s",	"s",	pbap_pull_vcard,
					G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetSize",	"",	"q",	pbap_get_size,
					G_DBUS_METHOD_FLAG_ASYNC },
	{ "SetFormat",	"s",	"",	pbap_set_format },
	{ "SetOrder",	"s",	"",	pbap_set_order },
	{ }
};

gboolean pbap_register_interface(DBusConnection *connection, const char *path,
				void *user_data, GDBusDestroyFunction destroy)
{
	struct session_data *session = user_data;

	session->pbapdata = g_try_malloc0(sizeof(struct pbap_data));
	if (!session->pbapdata)
		return FALSE;

	return g_dbus_register_interface(connection, path, PBAP_INTERFACE,
				pbap_methods, NULL, NULL, user_data, destroy);
}

void pbap_unregister_interface(DBusConnection *connection, const char *path,
				void *user_data)
{
	struct session_data *session = user_data;

	g_dbus_unregister_interface(connection, path, PBAP_INTERFACE);
	if (session->pbapdata)
		g_free(session->pbapdata);
}
