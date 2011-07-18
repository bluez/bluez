/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2010  Intel Corporation
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
#include <glib.h>
#include <gdbus.h>

#include "log.h"
#include "transfer.h"
#include "session.h"
#include "pbap.h"

#define ERROR_INF PBAP_INTERFACE ".Error"

#define FORMAT_VCARD21	0x0
#define FORMAT_VCARD30	0x1

#define ORDER_INDEXED		0x0
#define ORDER_ALPHANUMERIC	0x1
#define ORDER_PHONETIC		0x2

#define ATTRIB_NAME		0x0
#define ATTRIB_NUMBER		0x1
#define ATTRIB_SOUND		0x2

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

static const char *filter_list[] = {
	"VERSION",
	"FN",
	"N",
	"PHOTO",
	"BDAY",
	"ADR",
	"LABEL",
	"TEL",
	"EMAIL",
	"MAILER",
	"TZ",
	"GEO",
	"TITLE",
	"ROLE",
	"LOGO",
	"AGENT",
	"ORG",
	"NOTE",
	"REV",
	"SOUND",
	"URL",
	"UID",
	"KEY",
	"NICKNAME",
	"CATEGORIES",
	"PROID",
	"CLASS",
	"SORT-STRING",
	"X-IRMC-CALL-DATETIME",
	NULL
};

#define FILTER_BIT_MAX	63
#define FILTER_ALL	0xFFFFFFFFFFFFFFFFULL

#define PBAP_INTERFACE  "org.openobex.PhonebookAccess"

struct pbap_data {
	struct session_data *session;
	char *path;
	DBusConnection *conn;
	DBusMessage *msg;
	guint8 format;
	guint8 order;
	uint64_t filter;
};

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

static void listing_element(GMarkupParseContext *ctxt,
				const gchar *element,
				const gchar **names,
				const gchar **values,
				gpointer user_data,
				GError **gerr)
{
	DBusMessageIter *item = user_data, entry;
	gchar **key;
	const gchar *handle = NULL, *vcardname = NULL;

	if (g_str_equal(element, "card") != TRUE)
		return;

	for (key = (gchar **) names; *key; key++, values++) {
		if (g_str_equal(*key, "handle") == TRUE)
			handle = *values;
		else if (g_str_equal(*key, "name") == TRUE)
			vcardname = *values;
	}

	if (!handle || !vcardname)
		return;

	dbus_message_iter_open_container(item, DBUS_TYPE_STRUCT, NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &handle);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &vcardname);
	dbus_message_iter_close_container(item, &entry);
}

static const GMarkupParser listing_parser = {
	listing_element,
	NULL,
	NULL,
	NULL,
	NULL
};
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
static void pbap_reset_path(struct pbap_data *pbap)
{
	int err = 0;
	char **paths = NULL, **item;
	GwObex *obex = session_get_obex(pbap->session);

	if (!pbap->path)
		return;

	gw_obex_chdir(obex, "", &err);

	paths = g_strsplit(pbap->path, "/", 3);

	for (item = paths; *item; item++)
		gw_obex_chdir(obex, *item, &err);

	g_strfreev(paths);
}

static gint pbap_set_path(struct pbap_data *pbap, const char *path)
{
	int err = 0;
	char **paths = NULL, **item;
	GwObex *obex = session_get_obex(pbap->session);

	if (!path)
		return OBEX_RSP_BAD_REQUEST;

	if (pbap->path != NULL && g_str_equal(pbap->path, path))
		return 0;

	if (gw_obex_chdir(obex, "", &err) == FALSE) {
		if (err == OBEX_RSP_NOT_IMPLEMENTED)
			goto done;
		goto fail;
	}

	paths = g_strsplit(path, "/", 3);
	for (item = paths; *item; item++) {
		if (gw_obex_chdir(obex, *item, &err) == FALSE) {
			/* we need to reset the path to the saved one on fail*/
			pbap_reset_path(pbap);
			goto fail;
		}
	}

	g_strfreev(paths);

done:
	g_free(pbap->path);
	pbap->path = g_strdup(path);
	return 0;

fail:
	if (paths)
		g_strfreev(paths);

	return err;
}

static void read_return_apparam(struct session_data *session,
				guint16 *phone_book_size, guint8 *new_missed_calls)
{
	struct transfer_data *transfer = session_get_transfer(session);
	GwObexXfer *xfer = transfer->xfer;
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
			error("Unexpected PBAP pullphonebook app"
					" length, tag %d, len %d",
					hdr->tag, hdr->len);
			return;
		}

		switch (hdr->tag) {
		case PHONEBOOKSIZE_TAG:
			if (hdr->len == PHONEBOOKSIZE_LEN) {
				guint16 val;
				memcpy(&val, hdr->val, sizeof(val));
				*phone_book_size = get_be16(&val);
			}
			break;
		case NEWMISSEDCALLS_TAG:
			if (hdr->len == NEWMISSEDCALLS_LEN)
				*new_missed_calls = hdr->val[0];
			break;
		default:
			error("Unexpected PBAP pullphonebook app"
					" parameter, tag %d, len %d",
					hdr->tag, hdr->len);
		}

		buf += APPARAM_HDR_SIZE + hdr->len;
		size -= APPARAM_HDR_SIZE + hdr->len;
	}
}

static void pull_phonebook_callback(struct session_data *session,
					GError *err, void *user_data)
{
	struct transfer_data *transfer = session_get_transfer(session);
	struct pbap_data *pbap = user_data;
	DBusMessage *reply;
	char *buf = "";

	if (pbap->msg == NULL)
		goto done;

	if (err) {
		reply = g_dbus_create_error(pbap->msg,
						"org.openobex.Error.Failed",
						"%s", err->message);
		goto send;
	}

	reply = dbus_message_new_method_return(pbap->msg);

	if (transfer->filled > 0)
		buf = transfer->buffer;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &buf,
			DBUS_TYPE_INVALID);

	transfer->filled = 0;

send:
	g_dbus_send_message(pbap->conn, reply);
	dbus_message_unref(pbap->msg);
	pbap->msg = NULL;

done:
	transfer_unregister(transfer);
}

static void phonebook_size_callback(struct session_data *session,
					GError *err, void *user_data)
{
	struct transfer_data *transfer = session_get_transfer(session);
	struct pbap_data *pbap = user_data;
	DBusMessage *reply;
	guint16 phone_book_size;
	guint8 new_missed_calls;

	if (pbap->msg == NULL)
		goto done;

	if (err) {
		reply = g_dbus_create_error(pbap->msg,
						"org.openobex.Error.Failed",
						"%s", err->message);
		goto send;
	}

	reply = dbus_message_new_method_return(pbap->msg);

	read_return_apparam(session, &phone_book_size, &new_missed_calls);

	dbus_message_append_args(reply,
			DBUS_TYPE_UINT16, &phone_book_size,
			DBUS_TYPE_INVALID);

	transfer->filled = 0;

send:
	g_dbus_send_message(pbap->conn, reply);
	dbus_message_unref(pbap->msg);
	pbap->msg = NULL;

done:
	transfer_unregister(transfer);
}

static void pull_vcard_listing_callback(struct session_data *session,
					GError *err, void *user_data)
{
	struct transfer_data *transfer = session_get_transfer(session);
	struct pbap_data *pbap = user_data;
	GMarkupParseContext *ctxt;
	DBusMessage *reply;
	DBusMessageIter iter, array;
	int i;

	if (pbap->msg == NULL)
		goto complete;

	if (err) {
		reply = g_dbus_create_error(pbap->msg,
						"org.openobex.Error.Failed",
						"%s", err->message);
		goto send;
	}

	reply = dbus_message_new_method_return(pbap->msg);

	if (transfer->filled == 0)
		goto send;

	for (i = transfer->filled - 1; i > 0; i--) {
		if (transfer->buffer[i] != '\0')
			break;

		transfer->filled--;
	}

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_STRUCT_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_STRING_AS_STRING
			DBUS_STRUCT_END_CHAR_AS_STRING, &array);
	ctxt = g_markup_parse_context_new(&listing_parser, 0, &array, NULL);
	g_markup_parse_context_parse(ctxt, transfer->buffer,
					transfer->filled, NULL);
	g_markup_parse_context_free(ctxt);
	dbus_message_iter_close_container(&iter, &array);

	transfer->filled = 0;

send:
	g_dbus_send_message(pbap->conn, reply);
	dbus_message_unref(pbap->msg);
	pbap->msg = NULL;
complete:
	transfer_unregister(transfer);
}

static DBusMessage *pull_phonebook(struct pbap_data *pbap,
					DBusMessage *message, guint8 type,
					const char *name, uint64_t filter,
					guint8 format, guint16 maxlistcount,
					guint16 liststartoffset)
{
	struct pullphonebook_apparam apparam;
	session_callback_t func;

	if (pbap->msg)
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
		error("Unexpected type : 0x%2x", type);
		return NULL;
	}

	if (session_get(pbap->session, "x-bt/phonebook", name, NULL,
				(guint8 *) &apparam, sizeof(apparam),
				func, pbap) < 0)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");

	pbap->msg = dbus_message_ref(message);

	return NULL;
}

static guint8 *fill_apparam(guint8 *dest, void *buf, guint8 tag, guint8 len)
{
	if (dest && buf) {
		*dest++ = tag;
		*dest++ = len;
		memcpy(dest, buf, len);
		dest += len;
	}

	return dest;
}

static DBusMessage *pull_vcard_listing(struct pbap_data *pbap,
					DBusMessage *message, const char *name,
					guint8 order, char *searchval, guint8 attrib,
					guint16 count, guint16 offset)
{
	guint8 *p, *apparam = NULL;
	gint apparam_size;
	int err;

	if (pbap->msg)
		return g_dbus_create_error(message,
				"org.openobex.Error.InProgress",
				"Transfer in progress");

	/* trunc the searchval string if it's length exceed the max value of guint8 */
	if (strlen(searchval) > 254)
		searchval[255] = '\0';

	apparam_size = APPARAM_HDR_SIZE + ORDER_LEN +
			(APPARAM_HDR_SIZE + strlen(searchval) + 1) +
			(APPARAM_HDR_SIZE + SEARCHATTRIB_LEN) +
			(APPARAM_HDR_SIZE + MAXLISTCOUNT_LEN) +
			(APPARAM_HDR_SIZE + LISTSTARTOFFSET_LEN);
	apparam = g_try_malloc0(apparam_size);
	if (!apparam)
		return g_dbus_create_error(message,
				ERROR_INF ".Failed", "No Memory");

	p = apparam;

	p = fill_apparam(p, &order, ORDER_TAG, ORDER_LEN);
	p = fill_apparam(p, searchval, SEARCHVALUE_TAG, strlen(searchval) + 1);
	p = fill_apparam(p, &attrib, SEARCHATTRIB_TAG, SEARCHATTRIB_LEN);

	count = GUINT16_TO_BE(count);
	p = fill_apparam(p, &count, MAXLISTCOUNT_TAG, MAXLISTCOUNT_LEN);

	offset = GUINT16_TO_BE(offset);
	p = fill_apparam(p, &offset, LISTSTARTOFFSET_TAG, LISTSTARTOFFSET_LEN);

	err = session_get(pbap->session, "x-bt/vcard-listing", name, NULL,
				apparam, apparam_size,
				pull_vcard_listing_callback, pbap);
	g_free(apparam);
	if (err < 0)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");

	pbap->msg = dbus_message_ref(message);

	return NULL;
}

static int set_format(struct pbap_data *pbap, const char *formatstr)
{
	if (!formatstr || g_str_equal(formatstr, "")) {
		pbap->format = FORMAT_VCARD21;
		return 0;
	}

	if (!g_ascii_strcasecmp(formatstr, "vcard21"))
		pbap->format = FORMAT_VCARD21;
	else if (!g_ascii_strcasecmp(formatstr, "vcard30"))
		pbap->format = FORMAT_VCARD30;
	else
		return -EINVAL;

	return 0;
}

static int set_order(struct pbap_data *pbap, const char *orderstr)
{
	if (!orderstr || g_str_equal(orderstr, "")) {
		pbap->order = ORDER_INDEXED;
		return 0;
	}

	if (!g_ascii_strcasecmp(orderstr, "indexed"))
		pbap->order = ORDER_INDEXED;
	else if (!g_ascii_strcasecmp(orderstr, "alphanumeric"))
		pbap->order = ORDER_ALPHANUMERIC;
	else if (!g_ascii_strcasecmp(orderstr, "phonetic"))
		pbap->order = ORDER_PHONETIC;
	else
		return -EINVAL;

	return 0;
}

static uint64_t get_filter_mask(const char *filterstr)
{
	int i, bit = -1;

	if (!filterstr)
		return 0;

	if (!g_ascii_strcasecmp(filterstr, "ALL"))
		return FILTER_ALL;

	for (i = 0; filter_list[i] != NULL; i++)
		if (!g_ascii_strcasecmp(filterstr, filter_list[i]))
			return 1ULL << i;

	if (strlen(filterstr) < 4 || strlen(filterstr) > 5
			|| g_ascii_strncasecmp(filterstr, "bit", 3) != 0)
		return 0;

	sscanf(&filterstr[3], "%d", &bit);
	if (bit >= 0 && bit <= FILTER_BIT_MAX)
		return 1ULL << bit;
	else
		return 0;
}

static int add_filter(struct pbap_data *pbap, const char *filterstr)
{
	uint64_t mask;

	mask = get_filter_mask(filterstr);

	if (mask == 0)
		return -EINVAL;

	pbap->filter |= mask;
	return 0;
}

static int remove_filter(struct pbap_data *pbap, const char *filterstr)
{
	uint64_t mask;

	mask = get_filter_mask(filterstr);

	if (mask == 0)
		return -EINVAL;

	pbap->filter &= ~mask;
	return 0;
}

static gchar **get_filter_strs(uint64_t filter, gint *size)
{
	gchar **list, **item;
	gint i;
	gint filter_list_size = sizeof(filter_list) / sizeof(filter_list[0]) - 1;

	list = g_try_malloc0(sizeof(gchar **) * (FILTER_BIT_MAX + 2));

	if (!list)
		return NULL;

	item = list;

	for (i = 0; i < filter_list_size; i++)
		if (filter & (1ULL << i))
			*(item++) = g_strdup(filter_list[i]);

	for (i = filter_list_size; i <= FILTER_BIT_MAX; i++)
		if (filter & (1ULL << i))
			*(item++) = g_strdup_printf("%s%d", "BIT", i);

	*item = NULL;
	*size = item - list;
	return list;
}

static DBusMessage *pbap_select(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
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

	err = pbap_set_path(pbap, path);
	g_free(path);
	if (err)
		return g_dbus_create_error(message,
				ERROR_INF ".Failed",
				"%s", OBEX_ResponseToString(err));

	return dbus_message_new_method_return(message);
}

static DBusMessage *pbap_pull_all(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
	DBusMessage * err;
	char *name;

	if (!pbap->path)
		return g_dbus_create_error(message,
				ERROR_INF ".Forbidden", "Call Select first of all");

	name = g_strconcat(pbap->path, ".vcf", NULL);

	err = pull_phonebook(pbap, message, PULLPHONEBOOK, name,
				pbap->filter, pbap->format,
				DEFAULT_COUNT, DEFAULT_OFFSET);
	g_free(name);
	return err;
}

static DBusMessage *pbap_pull_vcard(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
	struct pullvcardentry_apparam apparam;
	const char *name;

	if (!pbap->path)
		return g_dbus_create_error(message,
				ERROR_INF ".Forbidden",
				"Call Select first of all");

	if (dbus_message_get_args(message, NULL,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", NULL);

	if (pbap->msg)
		return g_dbus_create_error(message,
				"org.openobex.Error.InProgress",
				"Transfer in progress");

	apparam.filter_tag = FILTER_TAG;
	apparam.filter_len = FILTER_LEN;
	apparam.filter = GUINT64_TO_BE(pbap->filter);
	apparam.format_tag = FORMAT_TAG;
	apparam.format_len = FORMAT_LEN;
	apparam.format = pbap->format;

	if (session_get(pbap->session, "x-bt/vcard", name, NULL,
			(guint8 *)&apparam, sizeof(apparam),
			pull_phonebook_callback, pbap) < 0)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");

	pbap->msg = dbus_message_ref(message);

	return NULL;
}

static DBusMessage *pbap_list(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;

	if (!pbap->path)
		return g_dbus_create_error(message,
				ERROR_INF ".Forbidden", "Call Select first of all");

	return pull_vcard_listing(pbap, message, "", pbap->order, "",
				ATTRIB_NAME, DEFAULT_COUNT, DEFAULT_OFFSET);
}

static DBusMessage *pbap_search(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
	char *field, *value;
	guint8 attrib;

	if (dbus_message_get_args(message, NULL,
			DBUS_TYPE_STRING, &field,
			DBUS_TYPE_STRING, &value,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", NULL);

	if (!pbap->path)
		return g_dbus_create_error(message,
				ERROR_INF ".Forbidden", "Call Select first of all");

	if (!field || g_str_equal(field, ""))
		attrib = ATTRIB_NAME;
	else if (!g_ascii_strcasecmp(field, "name"))
		attrib = ATTRIB_NAME;
	else if (!g_ascii_strcasecmp(field, "number"))
		attrib = ATTRIB_NUMBER;
	else if (!g_ascii_strcasecmp(field, "sound"))
		attrib = ATTRIB_SOUND;
	else
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", NULL);

	return pull_vcard_listing(pbap, message, "", pbap->order, value,
					attrib, DEFAULT_COUNT, DEFAULT_OFFSET);
}

static DBusMessage *pbap_get_size(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
	DBusMessage * err;
	char *name;

	if (!pbap->path)
		return g_dbus_create_error(message,
				ERROR_INF ".Forbidden", "Call Select first of all");

	name = g_strconcat(pbap->path, ".vcf", NULL);

	err = pull_phonebook(pbap, message, GETPHONEBOOKSIZE, name,
				pbap->filter, pbap->format, 0,
				DEFAULT_OFFSET);
	g_free(name);
	return err;
}

static DBusMessage *pbap_set_format(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
	const char *format;

	if (dbus_message_get_args(message, NULL,
			DBUS_TYPE_STRING, &format,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", NULL);

	if (set_format(pbap, format) < 0)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", "InvalidFormat");

	return dbus_message_new_method_return(message);
}

static DBusMessage *pbap_set_order(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
	const char *order;

	if (dbus_message_get_args(message, NULL,
			DBUS_TYPE_STRING, &order,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", NULL);

	if (set_order(pbap, order) < 0)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", "InvalidFilter");

	return dbus_message_new_method_return(message);
}

static DBusMessage *pbap_set_filter(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
	char **filters, **item;
	gint size;
	uint64_t oldfilter = pbap->filter;

	if (dbus_message_get_args(message, NULL, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING, &filters, &size,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", NULL);

	remove_filter(pbap, "ALL");
	if (size == 0)
		goto done;

	for (item = filters; *item; item++) {
		if (add_filter(pbap, *item) < 0) {
			pbap->filter = oldfilter;
			g_strfreev(filters);
			return g_dbus_create_error(message,
					ERROR_INF ".InvalidArguments", "InvalidFilters");
		}
	}

done:
	g_strfreev(filters);
	return dbus_message_new_method_return(message);
}

static DBusMessage *pbap_get_filter(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
	gchar **filters = NULL;
	gint size;
	DBusMessage *reply;

	filters = get_filter_strs(pbap->filter, &size);
	reply = dbus_message_new_method_return(message);
	dbus_message_append_args(reply, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING, &filters, size,
				DBUS_TYPE_INVALID);

	g_strfreev(filters);
	return reply;
}

static DBusMessage *pbap_list_filter_fields(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	gchar **filters = NULL;
	gint size;
	DBusMessage *reply;

	filters = get_filter_strs(FILTER_ALL, &size);
	reply = dbus_message_new_method_return(message);
	dbus_message_append_args(reply, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING, &filters, size,
				DBUS_TYPE_INVALID);

	g_strfreev(filters);
	return reply;
}

static GDBusMethodTable pbap_methods[] = {
	{ "Select",	"ss",	"",	pbap_select },
	{ "PullAll",	"",	"s",	pbap_pull_all,
					G_DBUS_METHOD_FLAG_ASYNC },
	{ "Pull",	"s",	"s",	pbap_pull_vcard,
					G_DBUS_METHOD_FLAG_ASYNC },
	{ "List",	"",	"a(ss)",	pbap_list,
					G_DBUS_METHOD_FLAG_ASYNC },
	{ "Search",	"ss",	"a(ss)",	pbap_search,
					G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetSize",	"",	"q",	pbap_get_size,
					G_DBUS_METHOD_FLAG_ASYNC },
	{ "SetFormat",	"s",	"",	pbap_set_format },
	{ "SetOrder",	"s",	"",	pbap_set_order },
	{ "SetFilter",	"as",	"",	pbap_set_filter },
	{ "GetFilter",	"",	"as",	pbap_get_filter },
	{ "ListFilterFields", "",	"as",	pbap_list_filter_fields },
	{ }
};

static void pbap_free(void *data)
{
	struct pbap_data *pbap = data;

	session_unref(pbap->session);
	dbus_connection_unref(pbap->conn);
	g_free(pbap);
}

gboolean pbap_register_interface(DBusConnection *connection, const char *path,
							void *user_data)
{
	struct session_data *session = user_data;
	struct pbap_data *pbap;

	pbap = g_try_new0(struct pbap_data, 1);
	if (!pbap)
		return FALSE;

	pbap->session = session_ref(session);
	pbap->conn = dbus_connection_ref(connection);

	if (g_dbus_register_interface(connection, path, PBAP_INTERFACE,
			pbap_methods, NULL, NULL, pbap, pbap_free) == FALSE) {
		pbap_free(pbap);
		return FALSE;
	}

	return TRUE;
}

void pbap_unregister_interface(DBusConnection *connection, const char *path)
{
	g_dbus_unregister_interface(connection, path, PBAP_INTERFACE);
}
