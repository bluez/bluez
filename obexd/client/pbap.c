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
#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <gdbus/gdbus.h>

#include <bluetooth/bluetooth.h>
#include <gobex/gobex-apparam.h>

#include "log.h"

#include "transfer.h"
#include "session.h"
#include "driver.h"
#include "pbap.h"

#define OBEX_PBAP_UUID \
	"\x79\x61\x35\xF0\xF0\xC5\x11\xD8\x09\x66\x08\x00\x20\x0C\x9A\x66"
#define OBEX_PBAP_UUID_LEN 16

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

#define PBAP_INTERFACE "org.bluez.obex.PhonebookAccess1"
#define ERROR_INTERFACE "org.bluez.obex.Error"
#define PBAP_UUID "0000112f-0000-1000-8000-00805f9b34fb"

struct pbap_data {
	struct obc_session *session;
	char *path;
};

struct pending_request {
	struct pbap_data *pbap;
	DBusMessage *msg;
};

static DBusConnection *conn = NULL;

static struct pending_request *pending_request_new(struct pbap_data *pbap,
							DBusMessage *message)
{
	struct pending_request *p;

	p = g_new0(struct pending_request, 1);
	p->pbap = pbap;
	p->msg = dbus_message_ref(message);

	return p;
}

static void pending_request_free(struct pending_request *p)
{
	dbus_message_unref(p->msg);
	g_free(p);
}

static void listing_element(GMarkupParseContext *ctxt,
				const char *element,
				const char **names,
				const char **values,
				gpointer user_data,
				GError **gerr)
{
	DBusMessageIter *item = user_data, entry;
	char **key;
	const char *handle = NULL, *vcardname = NULL;

	if (g_str_equal(element, "card") != TRUE)
		return;

	for (key = (char **) names; *key; key++, values++) {
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
static char *build_phonebook_path(const char *location, const char *item)
{
	char *path = NULL, *tmp, *tmp1;

	if (!g_ascii_strcasecmp(location, "int") ||
			!g_ascii_strcasecmp(location, "internal"))
		path = g_strdup("/telecom");
	else if (!g_ascii_strncasecmp(location, "sim", 3)) {
		if (strlen(location) == 3)
			tmp = g_strdup("sim1");
		else
			tmp = g_ascii_strup(location, 4);

		path = g_build_filename("/", tmp, "telecom", NULL);
		g_free(tmp);
	} else
		return NULL;

	if (!g_ascii_strcasecmp(item, "pb") ||
		!g_ascii_strcasecmp(item, "ich") ||
		!g_ascii_strcasecmp(item, "och") ||
		!g_ascii_strcasecmp(item, "mch") ||
		!g_ascii_strcasecmp(item, "cch")) {
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
	if (!pbap->path)
		return;

	obc_session_setpath(pbap->session, pbap->path, NULL, NULL, NULL);
}

static void pbap_setpath_cb(struct obc_session *session,
						struct obc_transfer *transfer,
						GError *err, void *user_data)
{
	struct pending_request *request = user_data;
	struct pbap_data *pbap = request->pbap;

	if (err != NULL)
		pbap_reset_path(pbap);

	if (err) {
		DBusMessage *reply = g_dbus_create_error(request->msg,
						ERROR_INTERFACE ".Failed",
						"%s", err->message);
		g_dbus_send_message(conn, reply);
	} else
		g_dbus_send_reply(conn, request->msg, DBUS_TYPE_INVALID);

	pending_request_free(request);
}

static void read_return_apparam(struct obc_transfer *transfer,
				guint16 *phone_book_size, guint8 *new_missed_calls)
{
	GObexApparam *apparam;

	*phone_book_size = 0;
	*new_missed_calls = 0;

	apparam = obc_transfer_get_apparam(transfer);
	if (apparam == NULL)
		return;

	g_obex_apparam_get_uint16(apparam, PHONEBOOKSIZE_TAG,
							phone_book_size);
	g_obex_apparam_get_uint8(apparam, NEWMISSEDCALLS_TAG,
							new_missed_calls);
}

static void phonebook_size_callback(struct obc_session *session,
						struct obc_transfer *transfer,
						GError *err, void *user_data)
{
	struct pending_request *request = user_data;
	DBusMessage *reply;
	guint16 phone_book_size;
	guint8 new_missed_calls;

	if (err) {
		reply = g_dbus_create_error(request->msg,
						ERROR_INTERFACE ".Failed",
						"%s", err->message);
		goto send;
	}

	reply = dbus_message_new_method_return(request->msg);

	read_return_apparam(transfer, &phone_book_size, &new_missed_calls);

	dbus_message_append_args(reply,
			DBUS_TYPE_UINT16, &phone_book_size,
			DBUS_TYPE_INVALID);

send:
	g_dbus_send_message(conn, reply);
	pending_request_free(request);
}

static void pull_vcard_listing_callback(struct obc_session *session,
						struct obc_transfer *transfer,
						GError *err, void *user_data)
{
	struct pending_request *request = user_data;
	GMarkupParseContext *ctxt;
	DBusMessage *reply;
	DBusMessageIter iter, array;
	char *contents;
	size_t size;
	int perr;

	if (err) {
		reply = g_dbus_create_error(request->msg,
						ERROR_INTERFACE ".Failed",
						"%s", err->message);
		goto send;
	}

	perr = obc_transfer_get_contents(transfer, &contents, &size);
	if (perr < 0) {
		reply = g_dbus_create_error(request->msg,
						ERROR_INTERFACE ".Failed",
						"Error reading contents: %s",
						strerror(-perr));
		goto send;
	}

	reply = dbus_message_new_method_return(request->msg);

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_STRUCT_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_STRING_AS_STRING
			DBUS_STRUCT_END_CHAR_AS_STRING, &array);
	ctxt = g_markup_parse_context_new(&listing_parser, 0, &array, NULL);
	g_markup_parse_context_parse(ctxt, contents, size, NULL);
	g_markup_parse_context_free(ctxt);
	dbus_message_iter_close_container(&iter, &array);
	g_free(contents);

send:
	g_dbus_send_message(conn, reply);
	pending_request_free(request);
}

static GObexApparam *parse_format(GObexApparam *apparam, DBusMessageIter *iter)
{
	const char *string;
	guint8 format;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING)
		return NULL;

	dbus_message_iter_get_basic(iter, &string);

	if (!string || g_str_equal(string, ""))
		format = FORMAT_VCARD21;
	else if (!g_ascii_strcasecmp(string, "vcard21"))
		format = FORMAT_VCARD21;
	else if (!g_ascii_strcasecmp(string, "vcard30"))
		format = FORMAT_VCARD30;
	else
		return NULL;

	return g_obex_apparam_set_uint8(apparam, FORMAT_TAG, format);
}

static GObexApparam *parse_order(GObexApparam *apparam, DBusMessageIter *iter)
{
	const char *string;
	guint8 order;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING)
		return NULL;

	dbus_message_iter_get_basic(iter, &string);

	if (!string || g_str_equal(string, ""))
		order = ORDER_INDEXED;
	else if (!g_ascii_strcasecmp(string, "indexed"))
		order = ORDER_INDEXED;
	else if (!g_ascii_strcasecmp(string, "alphanumeric"))
		order = ORDER_ALPHANUMERIC;
	else if (!g_ascii_strcasecmp(string, "phonetic"))
		order = ORDER_PHONETIC;
	else
		return NULL;

	return g_obex_apparam_set_uint8(apparam, ORDER_TAG, order);
}

static GObexApparam *parse_offset(GObexApparam *apparam, DBusMessageIter *iter)
{
	guint16 num;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_UINT16)
		return NULL;

	dbus_message_iter_get_basic(iter, &num);

	return g_obex_apparam_set_uint16(apparam, LISTSTARTOFFSET_TAG, num);
}

static GObexApparam *parse_max_count(GObexApparam *apparam,
							DBusMessageIter *iter)
{
	guint16 num;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_UINT16)
		return NULL;

	dbus_message_iter_get_basic(iter, &num);

	return g_obex_apparam_set_uint16(apparam, MAXLISTCOUNT_TAG, num);
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

static int set_field(guint64 *filter, const char *filterstr)
{
	guint64 mask;

	mask = get_filter_mask(filterstr);

	if (mask == 0)
		return -EINVAL;

	*filter |= mask;
	return 0;
}

static GObexApparam *parse_fields(GObexApparam *apparam, DBusMessageIter *iter)
{
	DBusMessageIter array;
	guint64 filter = 0;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return NULL;

	dbus_message_iter_recurse(iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRING) {
		const char *string;

		dbus_message_iter_get_basic(&array, &string);

		if (set_field(&filter, string) < 0)
			return NULL;

		dbus_message_iter_next(&array);
	}

	return g_obex_apparam_set_uint64(apparam, FILTER_TAG, filter);
}

static GObexApparam *parse_filters(GObexApparam *apparam,
							DBusMessageIter *iter)
{
	DBusMessageIter array;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return NULL;

	dbus_message_iter_recurse(iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		const char *key;
		DBusMessageIter value, entry;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (strcasecmp(key, "Format") == 0) {
			if (parse_format(apparam, &value) == NULL)
				return NULL;
		} else if (strcasecmp(key, "Order") == 0) {
			if (parse_order(apparam, &value) == NULL)
				return NULL;
		} else if (strcasecmp(key, "Offset") == 0) {
			if (parse_offset(apparam, &value) == NULL)
				return NULL;
		} else if (strcasecmp(key, "MaxCount") == 0) {
			if (parse_max_count(apparam, &value) == NULL)
				return NULL;
		} else if (strcasecmp(key, "Fields") == 0) {
			if (parse_fields(apparam, &value) == NULL)
				return NULL;
		}

		dbus_message_iter_next(&array);
	}

	return apparam;
}

static DBusMessage *pull_phonebook(struct pbap_data *pbap,
						DBusMessage *message,
						guint8 type,
						const char *targetfile,
						GObexApparam *apparam)
{
	struct pending_request *request;
	struct obc_transfer *transfer;
	char *name;
	session_callback_t func;
	DBusMessage *reply;
	GError *err = NULL;

	name = g_strconcat(g_path_skip_root(pbap->path), ".vcf", NULL);

	transfer = obc_transfer_get("x-bt/phonebook", name, targetfile, &err);
	if (transfer == NULL) {
		g_obex_apparam_free(apparam);
		goto fail;
	}

	switch (type) {
	case PULLPHONEBOOK:
		func = NULL;
		request = NULL;
		break;
	case GETPHONEBOOKSIZE:
		func = phonebook_size_callback;
		request = pending_request_new(pbap, message);
		break;
	default:
		error("Unexpected type : 0x%2x", type);
		return NULL;
	}

	obc_transfer_set_apparam(transfer, apparam);

	if (!obc_session_queue(pbap->session, transfer, func, request, &err)) {
		if (request != NULL)
			pending_request_free(request);

		goto fail;
	}

	g_free(name);

	if (targetfile == NULL)
		return NULL;

	return obc_transfer_create_dbus_reply(transfer, message);

fail:
	g_free(name);
	reply = g_dbus_create_error(message, ERROR_INTERFACE ".Failed", "%s",
								err->message);
	g_error_free(err);
	return reply;
}

static DBusMessage *pull_vcard_listing(struct pbap_data *pbap,
					DBusMessage *message, const char *name,
					GObexApparam *apparam)
{
	struct pending_request *request;
	struct obc_transfer *transfer;
	GError *err = NULL;
	DBusMessage *reply;

	transfer = obc_transfer_get("x-bt/vcard-listing", name, NULL, &err);
	if (transfer == NULL) {
		g_obex_apparam_free(apparam);
		goto fail;
	}

	obc_transfer_set_apparam(transfer, apparam);

	request = pending_request_new(pbap, message);
	if (obc_session_queue(pbap->session, transfer,
				pull_vcard_listing_callback, request, &err))
		return NULL;

	pending_request_free(request);

fail:
	reply = g_dbus_create_error(message, ERROR_INTERFACE ".Failed", "%s",
								err->message);
	g_error_free(err);
	return reply;
}

static DBusMessage *pbap_select(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
	const char *item, *location;
	char *path;
	struct pending_request *request;
	GError *err = NULL;

	if (dbus_message_get_args(message, NULL,
			DBUS_TYPE_STRING, &location,
			DBUS_TYPE_STRING, &item,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);

	path = build_phonebook_path(location, item);
	if (path == NULL)
		return g_dbus_create_error(message,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid path");

	if (pbap->path != NULL && g_str_equal(pbap->path, path)) {
		g_free(path);
		return dbus_message_new_method_return(message);
	}

	request = pending_request_new(pbap, message);

	obc_session_setpath(pbap->session, path, pbap_setpath_cb, request,
									&err);
	if (err != NULL) {
		DBusMessage *reply;
		reply =  g_dbus_create_error(message, ERROR_INTERFACE ".Failed",
							"%s", err->message);
		g_error_free(err);
		g_free(path);
		pending_request_free(request);
		return reply;
	}

	g_free(pbap->path);
	pbap->path = path;

	return NULL;
}

static DBusMessage *pbap_pull_all(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
	const char *targetfile;
	GObexApparam *apparam;
	DBusMessageIter args;

	if (!pbap->path)
		return g_dbus_create_error(message,
					ERROR_INTERFACE ".Forbidden",
					"Call Select first of all");

	dbus_message_iter_init(message, &args);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING)
		return g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);

	dbus_message_iter_get_basic(&args, &targetfile);
	dbus_message_iter_next(&args);

	apparam = g_obex_apparam_set_uint16(NULL, MAXLISTCOUNT_TAG,
							DEFAULT_COUNT);
	apparam = g_obex_apparam_set_uint16(apparam, LISTSTARTOFFSET_TAG,
							DEFAULT_OFFSET);

	if (parse_filters(apparam, &args) == NULL) {
		g_obex_apparam_free(apparam);
		return g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);
	}

	return pull_phonebook(pbap, message, PULLPHONEBOOK, targetfile,
								apparam);
}

static DBusMessage *pull_vcard(struct pbap_data *pbap, DBusMessage *message,
				const char *name, const char *targetfile,
				GObexApparam *apparam)
{
	struct obc_transfer *transfer;
	DBusMessage *reply;
	GError *err = NULL;

	transfer = obc_transfer_get("x-bt/vcard", name, targetfile, &err);
	if (transfer == NULL) {
		g_obex_apparam_free(apparam);
		goto fail;
	}

	obc_transfer_set_apparam(transfer, apparam);

	if (!obc_session_queue(pbap->session, transfer, NULL, NULL, &err))
		goto fail;

	return obc_transfer_create_dbus_reply(transfer, message);

fail:
	reply = g_dbus_create_error(message, ERROR_INTERFACE ".Failed", "%s",
								err->message);
	g_error_free(err);
	return reply;
}

static DBusMessage *pbap_pull_vcard(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
	GObexApparam *apparam;
	const char *name, *targetfile;
	DBusMessageIter args;

	if (!pbap->path)
		return g_dbus_create_error(message,
				ERROR_INTERFACE ".Forbidden",
				"Call Select first of all");

	dbus_message_iter_init(message, &args);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING)
		return g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);

	dbus_message_iter_get_basic(&args, &name);
	dbus_message_iter_next(&args);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING)
		return g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);

	dbus_message_iter_get_basic(&args, &targetfile);
	dbus_message_iter_next(&args);

	apparam = g_obex_apparam_set_uint16(NULL, MAXLISTCOUNT_TAG,
							DEFAULT_COUNT);
	apparam = g_obex_apparam_set_uint16(apparam, LISTSTARTOFFSET_TAG,
							DEFAULT_OFFSET);

	if (parse_filters(apparam, &args) == NULL) {
		g_obex_apparam_free(apparam);
		return g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);
	}

	return pull_vcard(pbap, message, name, targetfile, apparam);
}

static DBusMessage *pbap_list(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
	GObexApparam *apparam;
	DBusMessageIter args;

	if (!pbap->path)
		return g_dbus_create_error(message,
					ERROR_INTERFACE ".Forbidden",
					"Call Select first of all");

	dbus_message_iter_init(message, &args);

	apparam = g_obex_apparam_set_uint16(NULL, MAXLISTCOUNT_TAG,
							DEFAULT_COUNT);
	apparam = g_obex_apparam_set_uint16(apparam, LISTSTARTOFFSET_TAG,
							DEFAULT_OFFSET);

	if (parse_filters(apparam, &args) == NULL) {
		g_obex_apparam_free(apparam);
		return g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);
	}

	return pull_vcard_listing(pbap, message, "", apparam);
}

static GObexApparam *parse_attribute(GObexApparam *apparam, const char *field)
{
	guint8 attrib;

	if (!field || g_str_equal(field, ""))
		attrib = ATTRIB_NAME;
	else if (!g_ascii_strcasecmp(field, "name"))
		attrib = ATTRIB_NAME;
	else if (!g_ascii_strcasecmp(field, "number"))
		attrib = ATTRIB_NUMBER;
	else if (!g_ascii_strcasecmp(field, "sound"))
		attrib = ATTRIB_SOUND;
	else
		return NULL;

	return g_obex_apparam_set_uint8(apparam, SEARCHATTRIB_TAG, attrib);
}

static DBusMessage *pbap_search(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
	char *field, *value;
	GObexApparam *apparam;
	DBusMessageIter args;

	if (!pbap->path)
		return g_dbus_create_error(message,
					ERROR_INTERFACE ".Forbidden",
					"Call Select first of all");

	dbus_message_iter_init(message, &args);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING)
		return g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);

	dbus_message_iter_get_basic(&args, &field);
	dbus_message_iter_next(&args);

	apparam = parse_attribute(NULL, field);
	if (apparam == NULL)
		return g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING)
		return g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);

	dbus_message_iter_get_basic(&args, &value);
	dbus_message_iter_next(&args);

	apparam = g_obex_apparam_set_uint16(apparam, MAXLISTCOUNT_TAG,
							DEFAULT_COUNT);
	apparam = g_obex_apparam_set_uint16(apparam, LISTSTARTOFFSET_TAG,
							DEFAULT_OFFSET);
	apparam = g_obex_apparam_set_string(apparam, SEARCHVALUE_TAG, value);

	if (parse_filters(apparam, &args) == NULL) {
		g_obex_apparam_free(apparam);
		return g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);
	}

	return pull_vcard_listing(pbap, message, "", apparam);
}

static DBusMessage *pbap_get_size(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct pbap_data *pbap = user_data;
	GObexApparam *apparam;
	DBusMessageIter args;

	if (!pbap->path)
		return g_dbus_create_error(message,
					ERROR_INTERFACE ".Forbidden",
					"Call Select first of all");

	dbus_message_iter_init(message, &args);

	apparam = g_obex_apparam_set_uint16(NULL, MAXLISTCOUNT_TAG, 0);
	apparam = g_obex_apparam_set_uint16(apparam, LISTSTARTOFFSET_TAG,
							DEFAULT_OFFSET);

	return pull_phonebook(pbap, message, GETPHONEBOOKSIZE, NULL, apparam);
}

static char **get_filter_strs(uint64_t filter, int *size)
{
	char **list, **item;
	int i;

	list = g_malloc0(sizeof(char **) * (FILTER_BIT_MAX + 2));

	item = list;

	for (i = 0; filter_list[i] != NULL; i++)
		if (filter & (1ULL << i))
			*(item++) = g_strdup(filter_list[i]);

	for (; i <= FILTER_BIT_MAX; i++)
		if (filter & (1ULL << i))
			*(item++) = g_strdup_printf("%s%d", "BIT", i);

	*item = NULL;
	*size = item - list;
	return list;
}

static DBusMessage *pbap_list_filter_fields(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	char **filters = NULL;
	int size;
	DBusMessage *reply;

	filters = get_filter_strs(FILTER_ALL, &size);
	reply = dbus_message_new_method_return(message);
	dbus_message_append_args(reply, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING, &filters, size,
				DBUS_TYPE_INVALID);

	g_strfreev(filters);
	return reply;
}

static const GDBusMethodTable pbap_methods[] = {
	{ GDBUS_ASYNC_METHOD("Select",
			GDBUS_ARGS({ "location", "s" }, { "phonebook", "s" }),
			NULL, pbap_select) },
	{ GDBUS_METHOD("PullAll",
			GDBUS_ARGS({ "targetfile", "s" },
					{ "filters", "a{sv}" }),
			GDBUS_ARGS({ "transfer", "o" },
					{ "properties", "a{sv}" }),
			pbap_pull_all) },
	{ GDBUS_METHOD("Pull",
			GDBUS_ARGS({ "vcard", "s" }, { "targetfile", "s" },
					{ "filters", "a{sv}" }),
			GDBUS_ARGS({ "transfer", "o" },
					{ "properties", "a{sv}" }),
			pbap_pull_vcard) },
	{ GDBUS_ASYNC_METHOD("List",
			GDBUS_ARGS({ "filters", "a{sv}" }),
			GDBUS_ARGS({ "vcard_listing", "a(ss)" }),
			pbap_list) },
	{ GDBUS_ASYNC_METHOD("Search",
			GDBUS_ARGS({ "field", "s" }, { "value", "s" },
					{ "filters", "a{sv}" }),
			GDBUS_ARGS({ "vcard_listing", "a(ss)" }),
			pbap_search) },
	{ GDBUS_ASYNC_METHOD("GetSize",
				NULL, GDBUS_ARGS({ "size", "q" }),
				pbap_get_size) },
	{ GDBUS_METHOD("ListFilterFields",
				NULL, GDBUS_ARGS({ "fields", "as" }),
				pbap_list_filter_fields) },
	{ }
};

static void pbap_free(void *data)
{
	struct pbap_data *pbap = data;

	obc_session_unref(pbap->session);
	g_free(pbap->path);
	g_free(pbap);
}

static int pbap_probe(struct obc_session *session)
{
	struct pbap_data *pbap;
	const char *path;

	path = obc_session_get_path(session);

	DBG("%s", path);

	pbap = g_try_new0(struct pbap_data, 1);
	if (!pbap)
		return -ENOMEM;

	pbap->session = obc_session_ref(session);

	if (!g_dbus_register_interface(conn, path, PBAP_INTERFACE, pbap_methods,
						NULL, NULL, pbap, pbap_free)) {
		pbap_free(pbap);
		return -ENOMEM;
	}

	return 0;
}

static void pbap_remove(struct obc_session *session)
{
	const char *path = obc_session_get_path(session);

	DBG("%s", path);

	g_dbus_unregister_interface(conn, path, PBAP_INTERFACE);
}

static struct obc_driver pbap = {
	.service = "PBAP",
	.uuid = PBAP_UUID,
	.target = OBEX_PBAP_UUID,
	.target_len = OBEX_PBAP_UUID_LEN,
	.probe = pbap_probe,
	.remove = pbap_remove
};

int pbap_init(void)
{
	int err;

	DBG("");

	conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (!conn)
		return -EIO;

	err = obc_driver_register(&pbap);
	if (err < 0) {
		dbus_connection_unref(conn);
		conn = NULL;
		return err;
	}

	return 0;
}

void pbap_exit(void)
{
	DBG("");

	dbus_connection_unref(conn);
	conn = NULL;

	obc_driver_unregister(&pbap);
}
