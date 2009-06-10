/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2009  Intel Corporation
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

#include <plugin.h>
#include <logging.h>
#include <phonebook.h>

#include <libebook/e-book.h>

#define DEFAULT_COUNT 65535

#define EOL_CHARS "\n"
#define VL_VERSION "<?xml version=\"1.0\"?>" EOL_CHARS
#define VL_TYPE "<!DOCTYPE vcard-listing SYSTEM \"vcard-listing.dtd\">" EOL_CHARS
#define VL_BODY_BEGIN "<vCard-listing version=\"1.0\">" EOL_CHARS
#define VL_BODY_END "</vCard-listing>" EOL_CHARS
#define VL_ELEMENT "<card handle = \"%d.vcf\" name = \"%s\"/>" EOL_CHARS

#define QUERY_FAMILY_NAME "(contains \"family_name\" \"%s\")"
#define QUERY_GIVEN_NAME "(contains \"given_name\" \"%s\")"
#define QUERY_PHONE "(contains \"phone\" \"%s\")"

struct phonebook_data {
	struct phonebook_context *context;
	guint64 filter;
	guint8 format;
	guint16 maxlistcount;
	guint16 liststartoffset;
	guint16 index;
};

static char *vcard_attribs[29] = { EVC_VERSION, EVC_FN, EVC_N, EVC_PHOTO,
				EVC_BDAY, EVC_ADR, EVC_LABEL, EVC_TEL,
				EVC_EMAIL, EVC_MAILER, NULL, EVC_GEO,
				EVC_TITLE, EVC_ROLE, EVC_LOGO, NULL,
				EVC_ORG, EVC_NOTE, EVC_REV, NULL, EVC_URL,
				EVC_UID, EVC_KEY, EVC_NICKNAME, EVC_CATEGORIES,
				EVC_PRODID, NULL, NULL, NULL };

static int ebook_create(struct phonebook_context *context)
{
	DBG("context %p", context);

	return 0;
}

static void ebook_destroy(struct phonebook_context *context)
{
	DBG("context %p", context);
}

static void ebookpull_cb(EBook *book, EBookStatus status, GList *list,
				gpointer user_data)
{
	struct phonebook_data *pb_data = user_data;
	struct phonebook_context *context = pb_data->context;
	guint64 filter = pb_data->filter;
	guint8 format = pb_data->format;
	guint16 liststartoffset = pb_data->liststartoffset, offset = 0;
	guint16 maxlistcount = pb_data->maxlistcount, count = 0;
	GList *contacts = list;
	GString *pb;
	gchar *result;
	gint32 str_len;

	pb = g_string_new(NULL);

	/* Mandatory attributes for vCard 3.0 are VERSION, N, FN and TEL */
	if (filter != 0 && format == EVC_FORMAT_VCARD_30)
		filter = filter | 0x87;

	for (; contacts != NULL; contacts = g_list_next(contacts)) {
		EContact *contact = NULL;
		EVCard *evcard = NULL, *evcard_filtered = NULL;
		GList *attrib_list = NULL, *l;
		char *vcard;

		if (offset < liststartoffset) {
			offset++;
			continue;
		}

		if (count < maxlistcount)
			count++;
		else
			break;

		contact = E_CONTACT(contacts->data);
		evcard = E_VCARD(contact);
		attrib_list = e_vcard_get_attributes(evcard);

		if (!filter) {
			vcard = e_vcard_to_string(evcard, format);
			goto done;
		}

		evcard_filtered = e_vcard_new();
		for (l = attrib_list; l; l = l->next) {
			int i;
			const char *attrib_name = e_vcard_attribute_get_name(
						(EVCardAttribute *)l->data);

			for (i = 0; i <= 28; i++) {
				int mask;

				mask = 1 << i;
				if (!(filter & mask))
					continue;
				if (g_strcmp0(vcard_attribs[i], attrib_name))
					continue;
				e_vcard_add_attribute(
					evcard_filtered,
					e_vcard_attribute_copy(
					(EVCardAttribute *)l->data));
				break;
			}
		}
		vcard = e_vcard_to_string(evcard_filtered, format);
		g_object_unref(evcard_filtered);

done:		g_string_append_printf(pb, "%s\n", vcard);
		g_free(vcard);
	}

	result = g_string_free(pb, FALSE);
	str_len = strlen(result);
	phonebook_return(context, result, str_len);

	if (str_len != 0)
		phonebook_return(context, NULL, 0);

	g_free(result);
	g_free(pb_data);
	phonebook_unref(context);
	g_object_unref(book);
}

static int ebook_pullphonebook(struct phonebook_context *context,
		gchar *objname, guint64 filter, guint8 format,
		guint16 maxlistcount, guint16 liststartoffset,
		guint16 *phonebooksize, guint8 *newmissedcalls)
{
	struct phonebook_data *pb_data;
	EBook *book;
	EBookQuery *query;

	DBG("context %p", context);

	if (maxlistcount == 0) {
		*phonebooksize = DEFAULT_COUNT;
		return 0;
	}

	if (format != EVC_FORMAT_VCARD_30) {
		DBG("libebook does not support e_vcard_to_string_vcard_21()");
		return -1;
	}

	phonebook_ref(context);

	pb_data = g_new0(struct phonebook_data, 1);
	pb_data->context = context;
	pb_data->filter = filter;
	pb_data->format = format;
	pb_data->maxlistcount = maxlistcount;
	pb_data->liststartoffset = liststartoffset;

	book = e_book_new_default_addressbook(NULL);

	e_book_open(book, FALSE, NULL);

	query = e_book_query_any_field_contains("");

	e_book_async_get_contacts(book, query, ebookpull_cb, pb_data);

	e_book_query_unref(query);

	return 0;
}

static void ebooklist_cb(EBook *book, EBookStatus status, GList *list,
				gpointer user_data)
{
	struct phonebook_data *pb_data = user_data;
	struct phonebook_context *context = pb_data->context;
	guint16 liststartoffset = pb_data->liststartoffset, offset = 0;
	guint16 maxlistcount = pb_data->maxlistcount, count = 0;
	GString *listing;
	GList *contacts = list;
	gchar *result;
	gint32 str_len;

	listing = g_string_new(VL_VERSION);
	listing = g_string_append(listing, VL_TYPE);
	listing = g_string_append(listing, VL_BODY_BEGIN);

	for (; contacts != NULL; contacts = g_list_next(contacts)) {
		EContact *contact = NULL;
		EVCard *evcard = NULL;
		EVCardAttribute *name_attrib = NULL;
		GList *name_values = NULL;
		gchar *name = NULL, *name_part = NULL, *element = NULL;

		if (offset < liststartoffset) {
			offset++;
			continue;
		}

		if (count < maxlistcount)
			count++;
		else
			break;

		contact = E_CONTACT(contacts->data);
		evcard = E_VCARD(contact);
		name_attrib = e_vcard_get_attribute(evcard, EVC_N);

		if (name_attrib) {
			name_values = e_vcard_attribute_get_values(name_attrib);
			for (; name_values; name_values = name_values->next) {
				if (!name_part) {
					name_part = g_strdup(name_values->data);
					continue;
				}
				name = g_strjoin(";", name_part,
						name_values->data, NULL);
				g_free(name_part);
				name_part = name;
			}

			element = g_strdup_printf(VL_ELEMENT, offset, name);
			listing = g_string_append(listing, element);

			g_free(name);
			g_free(element);
		}

		offset++;
	}

	listing = g_string_append(listing, VL_BODY_END);
	result = g_string_free(listing, FALSE);
	str_len = strlen(result);
	phonebook_return(context, result, str_len);

	if (str_len != 0)
		phonebook_return(context, NULL, 0);

	g_free(result);
	g_free(pb_data);
	phonebook_unref(context);
	g_object_unref(book);
}

static int ebook_pullvcardlisting(struct phonebook_context *context,
		gchar *objname, guint8 order, guint8 *searchval,
		guint8 searchattrib, guint16 maxlistcount,
		guint16 liststartoffset, guint16 *phonebooksize,
		guint8 *newmissedcalls)
{
	struct phonebook_data *pb_data;
	EBook *book;
	EBookQuery *query = NULL, *query1 = NULL, *query2 = NULL;
	gchar *str1 = NULL, *str2 = NULL;
	gchar **value_list = NULL;

	DBG("context %p", context);

	if (maxlistcount == 0) {
		*phonebooksize = DEFAULT_COUNT;
		return 0;
	}

	/* libebook does not support sound attribute */
	if (searchattrib >= 2) {
		DBG("libebook does not support sound attribute");
		return -1;
	}

	phonebook_ref(context);

	pb_data = g_new0(struct phonebook_data, 1);
	pb_data->context = context;
	pb_data->maxlistcount = maxlistcount;
	pb_data->liststartoffset = liststartoffset;

	book = e_book_new_default_addressbook(NULL);

	e_book_open(book, FALSE, NULL);

	/* All the vCards shall be returned if SearchValue header is
	 * not specified */
	if (!searchval || !strlen((char *)searchval)) {
		query = e_book_query_any_field_contains("");
		goto done;
	}

	if (searchattrib == 0) {
		value_list = g_strsplit((gchar *)searchval, ";", 5);

		if (value_list[0])
			str1 = g_strdup_printf(QUERY_FAMILY_NAME,
						value_list[0]);
		if (value_list[1])
			str2 = g_strdup_printf(QUERY_GIVEN_NAME, value_list[1]);

		if (str1)
			query1 = e_book_query_from_string(str1);
		if (str2)
			query2 = e_book_query_from_string(str2);
		if (query1 && query2)
			query = e_book_query_andv(query1, query2, NULL);
		else
			query = query1;
	} else {
		str1 = g_strdup_printf(QUERY_PHONE, searchval);
		query = e_book_query_from_string((const char *)searchval);
	}

done:
	e_book_async_get_contacts(book, query, ebooklist_cb, pb_data);

	g_free(str1);
	g_free(str2);
	if (query1 && query1 != query)
		e_book_query_unref(query1);
	if (query2)
		e_book_query_unref(query2);
	e_book_query_unref(query);
	g_strfreev(value_list);

	return 0;
}

static void ebookpullentry_cb(EBook *book, EBookStatus status, GList *list,
                                gpointer user_data)
{
	struct phonebook_data *pb_data = user_data;
	struct phonebook_context *context = pb_data->context;
	guint64 filter = pb_data->filter;
	guint8 format = pb_data->format;
	guint16 index = pb_data->index, i = 0;
	GList *contacts = list, *attrib_list = NULL, *l;
	EContact *contact = NULL;
	EVCard *evcard = NULL, *evcard_filtered = NULL;
	gint32 str_len = 0;
	char *vcard = NULL;

	if (filter != 0 && format == EVC_FORMAT_VCARD_30)
		filter = filter | 0x87;

	for (; contacts != NULL; contacts = g_list_next(contacts)) {
		if (i < index) {
			i++;
			continue;
		}

		contact = E_CONTACT(contacts->data);
		evcard = E_VCARD(contact);

		if (!filter) {
			vcard = e_vcard_to_string(evcard, format);
			break;
		}

		attrib_list = e_vcard_get_attributes(evcard);
		evcard_filtered = e_vcard_new();
		for (l = attrib_list; l; l = l->next) {
			int i;
			const char *attrib_name = e_vcard_attribute_get_name(
						(EVCardAttribute *)l->data);
			for (i = 0; i <= 28; i++) {
				int mask;

				mask = 1 << i;
				if (!(filter & mask))
					continue;
				if (g_strcmp0(vcard_attribs[i], attrib_name))
					continue;

				e_vcard_add_attribute(
					evcard_filtered,
					e_vcard_attribute_copy(
					(EVCardAttribute *)l->data));
				 break;
			}
		}
		vcard = e_vcard_to_string(evcard_filtered, format);
		g_object_unref(evcard_filtered);
		break;
	}

	if (vcard)
		str_len = strlen(vcard);

	phonebook_return(context, vcard, str_len);

	if (str_len != 0)
		phonebook_return(context, NULL, 0);

	g_free(vcard);
	g_free(pb_data);
	phonebook_unref(context);
	g_object_unref(book);
}

static int ebook_pullvcardentry(struct phonebook_context *context,
		gchar *objname, guint64 filter, guint8 format)
{
	struct phonebook_data *pb_data;
	EBook *book;
	EBookQuery *query;
	gint index;
	gchar *ptr = NULL;

	DBG("context %p", context);

	if (format != EVC_FORMAT_VCARD_30) {
		DBG("libebook does not support e_vcard_to_string_vcard_21()");
		return -1;
	}

	phonebook_ref(context);

	ptr = g_strrstr(objname, "/");
	sscanf(ptr, "/%d.vcf", &index);
	pb_data = g_new0(struct phonebook_data, 1);
	pb_data->context = context;
	pb_data->filter = filter;
	pb_data->format = format;
	pb_data->index = index;

	book = e_book_new_default_addressbook(NULL);

	e_book_open(book, FALSE, NULL);

	query = e_book_query_any_field_contains("");

	e_book_async_get_contacts(book, query, ebookpullentry_cb, pb_data);

	return 0;
}

static struct phonebook_driver ebook_driver = {
	.name		= "ebook",
	.create		= ebook_create,
	.destroy	= ebook_destroy,
	.pullphonebook	= ebook_pullphonebook,
	.pullvcardlisting = ebook_pullvcardlisting,
	.pullvcardentry = ebook_pullvcardentry,
};

static int ebook_init(void)
{
	return phonebook_driver_register(&ebook_driver);
}

static void ebook_exit(void)
{
	phonebook_driver_unregister(&ebook_driver);
}

OBEX_PLUGIN_DEFINE("ebook", ebook_init, ebook_exit)
