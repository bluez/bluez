/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2009-2010  Intel Corporation
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

#include <string.h>
#include <errno.h>
#include <glib.h>
#include <bluetooth/bluetooth.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include <libebook/e-book.h>

#include "logging.h"
#include "obex.h"
#include "service.h"
#include "phonebook.h"

#define EOL	"\r\n"
#define VCARD_LISTING_BEGIN						\
	"<?xml version=\"1.0\"?>" EOL					\
	"<!DOCTYPE vcard-listing SYSTEM \"vcard-listing.dtd\">" EOL 	\
	"<vCard-listing version=\"1.0\">" EOL
#define VCARD_LISTING_ELEMENT	"<card handle = \"%d.vcf\" name = \"%s\"/>" EOL
#define VCARD_LISTING_END	"</vCard-listing>"

#define QUERY_FN "(contains \"family_name\" \"%s\")"
#define QUERY_NAME "(contains \"given_name\" \"%s\")"
#define QUERY_PHONE "(contains \"phone\" \"%s\")"

struct query_data {
	const struct apparam_field *params;
	phonebook_cb cb;
	gpointer user_data;
};

static EBook *ebook = NULL;

static gchar *attribute_mask[] = {
/* 0 */		"VERSION",
		"FN",
		"N",
		"PHOTO",
		"BDAY",
		"ADR",
		"LABEL",
		"TEL",
/* 8 */		"EMAIL",
		"MAILER",
		"TZ",
		"GEO",
		"TITLE",
		"ROLE",
		"LOGO",
		"AGENT",
/* 16 */	"ORG",
		"NOTE",
		"REV",
		"SOUND",
		"URL",
		"UID",
		"KEY",
		"NICKNAME",
/* 24 */	"CATEGORIES",
		"PROID",
		"CLASS",
		"SORT-STRING",
/* 28 */	"X-IRMC-CALL-DATETIME",
		NULL

};

static gchar *evcard_to_string(EVCard *evcard, guint format, guint64 filter)
{
	EVCard *evcard2;
	gchar *vcard;
	guint i;

	if (!filter)
		return e_vcard_to_string(evcard, format);

	/*
	 * Mandatory attributes for vCard 2.1 are VERSION ,N and TEL.
	 * Mandatory attributes for vCard 3.0 are VERSION, N, FN and TEL
	 */
	filter = (format == EVC_FORMAT_VCARD_30 ? filter | 0x85: filter | 0x87);

	evcard2 = e_vcard_new();
	for (i = 0; i < 29; i++) {
		EVCardAttribute *attrib;

		if (!(filter & (1 << i)))
			continue;

		attrib = e_vcard_get_attribute(evcard, attribute_mask[i]);
		if (!attrib)
			continue;

		e_vcard_add_attribute(evcard2, e_vcard_attribute_copy(attrib));
	}

	vcard = e_vcard_to_string(evcard2, format);
	g_object_unref(evcard2);

	return vcard;
}

static void ebookpull_cb(EBook *book, EBookStatus status, GList *contacts,
				gpointer user_data)
{
	struct query_data *data = user_data;
	GString *string = g_string_new("");
	GList *l = g_list_nth(contacts, data->params->liststartoffset);
	guint count = 0, maxcount = data->params->maxlistcount;

	/* FIXME: Missing 0.vcf */

	for (; l && count < maxcount; l = g_list_next(l), count++) {
		EContact *contact = E_CONTACT(l->data);
		EVCard *evcard = E_VCARD(contact);
		gchar *vcard;

		vcard = evcard_to_string(evcard,
				data->params->format, data->params->filter);

		string = g_string_append(string, vcard);
		g_free(vcard);
	}

	data->cb(string->str, string->len, count, 0, data->user_data);

	g_string_free(string, TRUE);
	g_free(data);
}

static gchar *evcard_name_attribute_to_string(EVCard *evcard)
{
	EVCardAttribute *attrib;
	GList *l;
	GString *name = NULL;

	attrib = e_vcard_get_attribute(evcard, EVC_N);
	if (!attrib)
		return NULL;

	for (l = e_vcard_attribute_get_values(attrib); l; l = l->next) {
		const gchar *value = l->data;

		if (!strlen(value))
			continue;

		if (!name)
			name = g_string_new(value);
		else {
			name = g_string_append(name, ";");
			name = g_string_append(name, l->data);
		}
	}

	if (!name)
		return NULL;

	return g_string_free(name, FALSE);
}

static void ebooklist_cb(EBook *book, EBookStatus status, GList *contacts,
				gpointer user_data)
{
	struct query_data *data = user_data;
	GString *string = g_string_new(VCARD_LISTING_BEGIN);
	GList *l = g_list_nth(contacts, data->params->liststartoffset);
	guint count = 0, maxcount = data->params->maxlistcount;

	for (; l && count < maxcount; l = g_list_next(l), count++) {
		EContact *contact = E_CONTACT(l->data);
		EVCard *evcard = E_VCARD(contact);
		gchar *element, *name;

		name = evcard_name_attribute_to_string(evcard);
		if (!name)
			continue;

		element = g_strdup_printf(VCARD_LISTING_ELEMENT, count, name);

		string = g_string_append(string, element);
		g_free(name);
		g_free(element);
	}

	string = g_string_append(string, VCARD_LISTING_END);

	data->cb(string->str, string->len, count, 0, data->user_data);

	g_string_free(string, TRUE);
	g_free(data);
}

int phonebook_init(void)
{
	GError *gerr = NULL;

	ebook = e_book_new_default_addressbook(&gerr);
	if (!ebook) {
		error("Can't create user's default address book: %s",
				gerr->message);
		g_error_free(gerr);
		return -EIO;
	}

	if (!e_book_open(ebook, FALSE, &gerr)) {
		error("Can't open e-book address book: %s", gerr->message);
		g_error_free(gerr);
		return -EIO;
	}

	return 0;
}

void phonebook_exit(void)
{
	if (ebook)
		g_object_unref(ebook);
}

int phonebook_set_folder(const gchar *current_folder,
		const gchar *new_folder, guint8 flags)
{
	gboolean root, child;
	int ret;

	root = (!current_folder || strlen(current_folder) == 0);
	child = (new_folder && strlen(new_folder) != 0);

	/* Evolution back-end will support telecom/pb folder only */
	switch (flags) {
	case 0x02:
		/* Go back to root */
		if (!child)
			return 0;

		/* Go down 1 level */
		if (root)
			ret = (strcmp("telecom", new_folder) != 0) ? -EBADR: 0;
		else if (strcmp("telecom", current_folder) == 0)
			ret = (strcmp("pb", new_folder) != 0) ? -EBADR: 0;
		else
			ret = -EBADR;

		break;
	case 0x03:
		/* Go up 1 level */
		if (root)
			/* Already root */
			return -EBADR;

		if (!child)
			return 0;

		/* /telecom or /telecom/pb */
		if (strcmp("telecom", current_folder) == 0)
			ret = (strcmp("telecom", new_folder) != 0) ? -EBADR : 0;
		else if (strcmp("telecom/pb", current_folder) == 0)
			ret = (strcmp("pb", new_folder) != 0) ? -EBADR : 0;
		else
			ret = -EBADR;
		break;
	default:
		ret = -EBADR;
		break;
	}

	return ret;
}

gint phonebook_pull(const gchar *name, const struct apparam_field *params,
		phonebook_cb cb, gpointer user_data)
{
	struct query_data *data;
	EBookQuery *query;

	query = e_book_query_any_field_contains("");

	data = g_new0(struct query_data, 1);
	data->cb = cb;
	data->params = params;
	data->user_data = user_data;

	e_book_async_get_contacts(ebook, query, ebookpull_cb, data);

	e_book_query_unref(query);

	return 0;
}

int phonebook_get_entry(const gchar *name, const struct apparam_field *params,
		phonebook_cb cb, gpointer user_data)
{
	return -1;
}

static EBookQuery *create_query(guint8 attrib, guint8 *searchval)
{
	EBookQuery *query;
	gchar *fam, *given, *str, **values;

	if (!searchval || strlen((gchar *) searchval) == 0)
		return e_book_query_any_field_contains("");

	switch (attrib) {
	case 0:
		/* Name */
		values = g_strsplit((gchar *) searchval, ";", 2);

		str = NULL;

		fam = (values[0] ? g_strdup_printf(QUERY_FN, values[0]) : NULL);

		if (values[1]) {
			given =	g_strdup_printf(QUERY_NAME, values[1]);
			str = (fam ? g_strconcat(fam, " and ", given, NULL) : given);
			g_free(fam);
			g_free(given);
		}

		if (!str)
			str = fam;

		g_strfreev(values);
		break;
	case 1:
		/* Number */
		str = g_strdup_printf(QUERY_PHONE, searchval);
		break;
	case 2:
		/* Sound */
		/* TODO: not yet implemented */
	default:
		return NULL;
	}

	query = e_book_query_from_string(str);
	g_free(str);

	return query;
}

int phonebook_list(const gchar *name, const struct apparam_field *params,
		phonebook_cb cb, gpointer user_data)
{
	struct query_data *data;
	EBookQuery *query;

	query = create_query(params->searchattrib, params->searchval);
	if (!query)
		return -EBADR;

	data = g_new0(struct query_data, 1);
	data->cb = cb;
	data->params = params;
	data->user_data = user_data;

	e_book_async_get_contacts(ebook, query, ebooklist_cb, data);

	e_book_query_unref(query);

	return 0;
}
