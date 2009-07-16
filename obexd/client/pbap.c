/*
 *
 *  OBEX Client
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
static void pbap_reset_path(struct session_data *session)
{
	int err = 0;
	char **paths = NULL, **item;
	struct pbap_data *pbapdata = session_get_data(session);

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
	struct pbap_data *pbapdata = session_get_data(session);

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
			if (hdr->len == PHONEBOOKSIZE_LEN) {
				guint16 val;
				memcpy(&val, hdr->val, sizeof(val));
				*phone_book_size = val;
			}
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

static void pull_vcard_listing_callback(struct session_data *session,
					void *user_data)
{
	GMarkupParseContext *ctxt;
	DBusMessage *reply;
	DBusMessageIter iter, array;
	int i;

	reply = dbus_message_new_method_return(session->msg);

	if (session->filled == 0)
		goto done;

	for (i = session->filled - 1; i > 0; i--) {
		if (session->buffer[i] != '\0')
			break;

		session->filled--;
	}

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_STRUCT_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_STRING_AS_STRING
			DBUS_STRUCT_END_CHAR_AS_STRING, &array);
	ctxt = g_markup_parse_context_new(&listing_parser, 0, &array, NULL);
	g_markup_parse_context_parse(ctxt, session->buffer,
					session->filled, NULL);
	g_markup_parse_context_free(ctxt);
	dbus_message_iter_close_container(&iter, &array);

	session->filled = 0;

done:
	g_dbus_send_message(session->conn, reply);
	dbus_message_unref(session->msg);
	session->msg = NULL;
}

static DBusMessage *pull_phonebook(struct session_data *session,
					DBusMessage *message, guint8 type,
					const char *name, uint64_t filter,
					guint8 format, guint16 maxlistcount,
					guint16 liststartoffset)
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
		return NULL;
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

static DBusMessage *pull_vcard_listing(struct session_data *session,
					DBusMessage *message, const char *name,
					guint8 order, char *searchval, guint8 attrib,
					guint16 count, guint16 offset)
{
	guint8 *p, *apparam = NULL;
	gint apparam_size;
	int err;

	if (session->msg)
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

	err = session_get(session, "x-bt/vcard-listing", name, NULL,
				apparam, apparam_size, pull_vcard_listing_callback);
	g_free(apparam);
	if (err < 0)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");

	session->msg = dbus_message_ref(message);
	session->filled = 0;

	return NULL;
}

static int set_format(struct session_data *session, const char *formatstr)
{
	struct pbap_data *pbapdata = session_get_data(session);

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
	struct pbap_data *pbapdata = session_get_data(session);

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

static int add_filter(struct session_data *session, const char *filterstr)
{
	struct pbap_data *pbapdata = session_get_data(session);
	uint64_t mask;

	mask = get_filter_mask(filterstr);

	if (mask == 0)
		return -EINVAL;

	pbapdata->filter |= mask;
	return 0;
}

static int remove_filter(struct session_data *session, const char *filterstr)
{
	struct pbap_data *pbapdata = session_get_data(session);
	uint64_t mask;

	mask = get_filter_mask(filterstr);

	if (mask == 0)
		return -EINVAL;

	pbapdata->filter &= ~mask;
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
	struct pbap_data *pbapdata = session_get_data(session);
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
	struct pbap_data *pbapdata = session_get_data(session);
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

static DBusMessage *pbap_list(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	struct pbap_data *pbapdata = session_get_data(session);

	if (!pbapdata->path)
		return g_dbus_create_error(message,
				ERROR_INF ".Forbidden", "Call Select first of all");

	return pull_vcard_listing(session, message, "", pbapdata->order, "",
				ATTRIB_NAME, DEFAULT_COUNT, DEFAULT_OFFSET);
}

static DBusMessage *pbap_search(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	struct pbap_data *pbapdata = session_get_data(session);
	char *field, *value;
	guint8 attrib;

	if (dbus_message_get_args(message, NULL,
			DBUS_TYPE_STRING, &field,
			DBUS_TYPE_STRING, &value,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", NULL);

	if (!pbapdata->path)
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

	return pull_vcard_listing(session, message, "", pbapdata->order, value,
				attrib, DEFAULT_COUNT, DEFAULT_OFFSET);
}

static DBusMessage *pbap_get_size(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	struct pbap_data *pbapdata = session_get_data(session);
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
				ERROR_INF ".InvalidArguments", "InvalidFilter");

	return dbus_message_new_method_return(message);
}

static DBusMessage *pbap_set_filter(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	struct pbap_data *pbapdata = session_get_data(session);
	char **filters, **item;
	gint size;
	uint64_t oldfilter = pbapdata->filter;

	if (dbus_message_get_args(message, NULL, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING, &filters, &size,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", NULL);

	remove_filter(session, "ALL");
	if (size == 0)
		goto done;

	for (item = filters; *item; item++) {
		if (add_filter(session, *item) < 0) {
			pbapdata->filter = oldfilter;
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
	struct session_data *session = user_data;
	struct pbap_data *pbapdata = session_get_data(session);
	gchar **filters = NULL;
	gint size;
	DBusMessage *reply;

	filters = get_filter_strs(pbapdata->filter, &size);
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

gboolean pbap_register_interface(DBusConnection *connection, const char *path,
				void *user_data, GDBusDestroyFunction destroy)
{
	struct session_data *session = user_data;
	void *priv;

	priv = g_try_malloc0(sizeof(struct pbap_data));
	if (!priv)
		return FALSE;

	session_set_data(session, priv);

	return g_dbus_register_interface(connection, path, PBAP_INTERFACE,
				pbap_methods, NULL, NULL, user_data, destroy);
}

void pbap_unregister_interface(DBusConnection *connection, const char *path,
				void *user_data)
{
	struct session_data *session = user_data;
	void *priv = session_get_data(session);

	g_dbus_unregister_interface(connection, path, PBAP_INTERFACE);
	g_free(priv);
}
