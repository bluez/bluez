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

#define QUERY_FN "(contains \"family_name\" \"%s\")"
#define QUERY_NAME "(contains \"given_name\" \"%s\")"
#define QUERY_PHONE "(contains \"phone\" \"%s\")"

struct contacts_query {
	const struct apparam_field *params;
	phonebook_cb cb;
	gpointer user_data;
};

struct cache_query {
	phonebook_entry_cb entry_cb;
	phonebook_cache_ready_cb ready_cb;
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

static void ebookpull_cb(EBook *book, EBookStatus estatus, GList *contacts,
							gpointer user_data)
{
	struct contacts_query *data = user_data;
	GString *string = g_string_new("");
	guint count = 0, maxcount;
	GList *l;

	if (estatus != E_BOOK_ERROR_OK) {
		error("E-Book query failed: status %d", estatus);
		goto done;
	}

	/*
	 * When MaxListCount s zero, PCE wants to know the number of used
	 * indexes in the phonebook of interest. All other parameters that
	 * may be present in the request shall be ignored.
	 */
	maxcount = data->params->maxlistcount;
	if (maxcount == 0) {
		count = g_list_length(contacts);
		goto done;
	}

	l = g_list_nth(contacts, data->params->liststartoffset);

	/* FIXME: Missing 0.vcf */

	for (; l && count < maxcount; l = g_list_next(l), count++) {
		EContact *contact = E_CONTACT(l->data);
		EVCard *evcard = E_VCARD(contact);
		gchar *vcard;

		vcard = evcard_to_string(evcard, data->params->format,
						data->params->filter);

		string = g_string_append(string, vcard);
		g_free(vcard);
	}

done:
	data->cb(string->str, string->len, count, 0, data->user_data);

	g_string_free(string, TRUE);
	g_free(data);
}

static void ebook_entry_cb(EBook *book, EBookStatus estatus,
			EContact *contact, gpointer user_data)
{
	struct contacts_query *data = user_data;
	EVCard *evcard;
	gchar *vcard;
	size_t len;

	if (estatus != E_BOOK_ERROR_OK) {
		error("E-Book query failed: status %d", estatus);
		data->cb(NULL, 0, 1, 0, data->user_data);
		g_free(data);
		return;
	}

	evcard = E_VCARD(contact);

	vcard = evcard_to_string(evcard, data->params->format,
					data->params->filter);

	len = vcard ? strlen(vcard) : 0;

	data->cb(vcard, len, 1, 0, data->user_data);

	g_free(vcard);
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

static void cache_cb(EBook *book, EBookStatus estatus, GList *contacts,
							gpointer user_data)
{
	struct cache_query *data = user_data;
	GList *l;

	if (estatus != E_BOOK_ERROR_OK) {
		error("E-Book query failed: status %d", estatus);
		goto done;
	}

	for (l = contacts; l; l = g_list_next(l)) {
		EContact *contact = E_CONTACT(l->data);
		EVCard *evcard = E_VCARD(contact);
		EVCardAttribute *attrib;
		gchar *uid, *tel, *name;

		name = evcard_name_attribute_to_string(evcard);
		if (!name)
			continue;

		attrib = e_vcard_get_attribute(evcard, EVC_UID);
		if (!attrib)
			continue;

		uid =  e_vcard_attribute_get_value(attrib);
		if (!uid)
			continue;

		attrib = e_vcard_get_attribute(evcard, EVC_TEL);
		if (!attrib)
			continue;

		tel =  e_vcard_attribute_get_value(attrib);

		data->entry_cb(uid, PHONEBOOK_INVALID_HANDLE, name, NULL,
							tel, data->user_data);
		g_free(name);
		g_free(uid);
		g_free(tel);
	}
done:
	data->ready_cb(data->user_data);
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

gchar *phonebook_set_folder(const gchar *current_folder,
		const gchar *new_folder, guint8 flags, int *err)
{
	gboolean root, child;
	gchar *fullname = NULL, *tmp1, *tmp2, *base;
	int ret = 0, len;

	root = (g_strcmp0("/", current_folder) == 0);
	child = (new_folder && strlen(new_folder) != 0);

	/* Evolution back-end will support telecom/pb folder only */

	switch (flags) {
	case 0x02:
		/* Go back to root */
		if (!child) {
			fullname = g_strdup("/");
			goto done;
		}

		/* Go down 1 level */
		fullname = g_build_filename(current_folder, new_folder, NULL);
		if (strcmp("/telecom", fullname) != 0 &&
				strcmp("/telecom/pb", fullname) != 0) {
			g_free(fullname);
			fullname = NULL;
			ret = -EBADR;
		}

		break;
	case 0x03:
		/* Go up 1 level */
		if (root) {
			/* Already root */
			ret = -EBADR;
			goto done;
		}

		/*
		 * Removing one level of the current folder. Current folder
		 * contains AT LEAST one level since it is not at root folder.
		 * Use glib utility functions to handle invalid chars in the
		 * folder path properly.
		 */
		tmp1 = g_path_get_basename(current_folder);
		tmp2 = g_strrstr(current_folder, tmp1);
		len = tmp2 - (current_folder + 1);

		g_free(tmp1);

		if (len == 0)
			base = g_strdup("/");
		else
			base = g_strndup(current_folder, len);

		/* Return one level only */
		if (!child) {
			fullname = base;
			goto done;
		}

		fullname = g_build_filename(base, new_folder, NULL);
		if (strcmp(fullname, "/telecom") != 0 &&
				strcmp(fullname, "/telecom/pb") != 0) {
			g_free(fullname);
			fullname = NULL;
			ret = -EBADR;
		}

		g_free(base);

		break;
	default:
		ret = -EBADR;
		break;
	}

done:
	if (err)
		*err = ret;

	return fullname;
}

gint phonebook_pull(const gchar *name, const struct apparam_field *params,
					phonebook_cb cb, gpointer user_data)
{
	struct contacts_query *data;
	EBookQuery *query;

	query = e_book_query_any_field_contains("");

	data = g_new0(struct contacts_query, 1);
	data->cb = cb;
	data->params = params;
	data->user_data = user_data;

	e_book_async_get_contacts(ebook, query, ebookpull_cb, data);

	e_book_query_unref(query);

	return 0;
}

int phonebook_get_entry(const gchar *folder, const gchar *id,
					const struct apparam_field *params,
					phonebook_cb cb, gpointer user_data)
{
	struct contacts_query *data;

	data = g_new0(struct contacts_query, 1);
	data->cb = cb;
	data->params = params;
	data->user_data = user_data;

	if (e_book_async_get_contact(ebook, id, ebook_entry_cb, data)) {
		g_free(data);
		return -EPERM;
	}

	return 0;
}

int phonebook_create_cache(const gchar *name, phonebook_entry_cb entry_cb,
		phonebook_cache_ready_cb ready_cb, gpointer user_data)
{
	struct cache_query *data;
	EBookQuery *query;
	gboolean ret;

	query = e_book_query_any_field_contains("");

	data = g_new0(struct cache_query, 1);
	data->entry_cb = entry_cb;
	data->ready_cb = ready_cb;
	data->user_data = user_data;

	ret = e_book_async_get_contacts(ebook, query, cache_cb, data);

	e_book_query_unref(query);

	return (ret == FALSE ? 0 : -EBADR);
}
