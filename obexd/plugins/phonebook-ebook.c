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
#include <libebook/e-book.h>

#include "lib/bluetooth.h"

#include "obexd/src/log.h"
#include "obexd/src/obex.h"
#include "obexd/src/service.h"
#include "phonebook.h"

#define QUERY_FN "(contains \"family_name\" \"%s\")"
#define QUERY_NAME "(contains \"given_name\" \"%s\")"
#define QUERY_PHONE "(contains \"phone\" \"%s\")"

struct query_context {
	const struct apparam_field *params;
	phonebook_cb contacts_cb;
	phonebook_entry_cb entry_cb;
	phonebook_cache_ready_cb ready_cb;
	EBookQuery *query;
	unsigned int count;
	GString *buf;
	char *id;
	unsigned queued_calls;
	void *user_data;
	GSList *ebooks;
	gboolean canceled;
};

static char *attribute_mask[] = {
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

static void close_ebooks(GSList *ebooks)
{
	g_slist_free_full(ebooks, g_object_unref);
}

static void free_query_context(struct query_context *data)
{
	g_free(data->id);

	if (data->buf != NULL)
		g_string_free(data->buf, TRUE);

	if (data->query != NULL)
		e_book_query_unref(data->query);

	close_ebooks(data->ebooks);

	g_free(data);
}

static char *evcard_to_string(EVCard *evcard, unsigned int format,
							uint64_t filter)
{
	EVCard *evcard2;
	GList *l;
	char *vcard;

	if (!filter)
		return e_vcard_to_string(evcard, EVC_FORMAT_VCARD_30);
		/* XXX There is no support for VCARD 2.1 at this time */

	/*
	 * Mandatory attributes for vCard 2.1 are VERSION ,N and TEL.
	 * Mandatory attributes for vCard 3.0 are VERSION, N, FN and TEL
	 */
	filter = format == EVC_FORMAT_VCARD_30 ? filter | 0x87: filter | 0x85;

	l = e_vcard_get_attributes(evcard);
	evcard2 = e_vcard_new();
	for (; l; l = g_list_next(l)) {
		EVCardAttribute *attrib = l->data;
		const char *name;
		int i;

		if (!attrib)
			continue;

		name = e_vcard_attribute_get_name(attrib);

		for (i = 0; attribute_mask[i] != NULL; i++) {
			if (!(filter & (1 << i)))
				continue;
			if (g_strcmp0(name, attribute_mask[i]) != 0)
				continue;

			e_vcard_add_attribute(evcard2,
					e_vcard_attribute_copy(attrib));
		}
	}

	vcard = e_vcard_to_string(evcard2, format);
	g_object_unref(evcard2);

	return vcard;
}

static void ebookpull_cb(EBook *book, const GError *gerr, GList *contacts,
							void *user_data)
{
	struct query_context *data = user_data;
	GList *l;
	unsigned int count, maxcount;

	data->queued_calls--;

	if (data->canceled)
		goto canceled;

	if (gerr != NULL) {
		error("E-Book query failed: %s", gerr->message);
		goto done;
	}

	DBG("");

	/*
	 * When MaxListCount is zero, PCE wants to know the number of used
	 * indexes in the phonebook of interest. All other parameters that
	 * may be present in the request shall be ignored.
	 */
	maxcount = data->params->maxlistcount;
	if (maxcount == 0) {
		data->count += g_list_length(contacts);
		goto done;
	}

	l = g_list_nth(contacts, data->params->liststartoffset);

	for (count = 0; l && count + data->count < maxcount; l = g_list_next(l),
								count++) {
		EContact *contact = E_CONTACT(l->data);
		EVCard *evcard = E_VCARD(contact);
		char *vcard;

		vcard = evcard_to_string(evcard, EVC_FORMAT_VCARD_30,
						data->params->filter);

		data->buf = g_string_append(data->buf, vcard);
		data->buf = g_string_append(data->buf, "\r\n");
		g_free(vcard);
	}

	DBG("collected %d vcards", count);

	data->count += count;

	g_list_free_full(contacts, g_object_unref);

done:
	if (data->queued_calls == 0) {
		GString *buf = data->buf;
		data->buf = NULL;

		data->contacts_cb(buf->str, buf->len, data->count,
						0, TRUE, data->user_data);

		g_string_free(buf, TRUE);

	}

	return;

canceled:
	if (data->queued_calls == 0)
		free_query_context(data);
}

static void ebook_entry_cb(EBook *book, const GError *gerr,
				EContact *contact, void *user_data)
{
	struct query_context *data = user_data;
	EVCard *evcard;
	char *vcard;
	size_t len;

	data->queued_calls--;

	if (data->canceled)
		goto done;

	if (gerr != NULL) {
		error("E-Book query failed: %s", gerr->message);
		goto done;
	}

	DBG("");

	evcard = E_VCARD(contact);

	vcard = evcard_to_string(evcard, EVC_FORMAT_VCARD_30,
					data->params->filter);

	len = vcard ? strlen(vcard) : 0;

	data->count++;
	data->contacts_cb(vcard, len, 1, 0, TRUE, data->user_data);

	g_free(vcard);
	g_object_unref(contact);

	return;

done:
	if (data->queued_calls == 0) {
		if (data->count == 0)
			data->contacts_cb(NULL, 0, 1, 0, TRUE,
						data->user_data);
		else if (data->canceled)
			free_query_context(data);
	}
}

static char *evcard_name_attribute_to_string(EVCard *evcard)
{
	EVCardAttribute *attrib;
	GList *l;
	GString *name = NULL;

	attrib = e_vcard_get_attribute(evcard, EVC_N);
	if (!attrib)
		return NULL;

	for (l = e_vcard_attribute_get_values(attrib); l; l = l->next) {
		const char *value = l->data;

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

static void cache_cb(EBook *book, const GError *gerr, GList *contacts,
							void *user_data)
{
	struct query_context *data = user_data;
	GList *l;

	data->queued_calls--;

	if (data->canceled)
		goto canceled;

	if (gerr != NULL) {
		error("E-Book operation failed: %s", gerr->message);
		goto done;
	}

	DBG("");

	for (l = contacts; l; l = g_list_next(l)) {
		EContact *contact = E_CONTACT(l->data);
		EVCard *evcard = E_VCARD(contact);
		EVCardAttribute *attrib;
		char *uid, *tel, *name;

		name = evcard_name_attribute_to_string(evcard);
		if (!name)
			continue;

		attrib = e_vcard_get_attribute(evcard, EVC_UID);
		if (!attrib)
			continue;

		uid = e_vcard_attribute_get_value(attrib);
		if (!uid)
			continue;

		attrib = e_vcard_get_attribute(evcard, EVC_TEL);
		if (attrib)
			tel = e_vcard_attribute_get_value(attrib);
		else
			tel = g_strdup("");

		data->entry_cb(uid, PHONEBOOK_INVALID_HANDLE, name, NULL,
							tel, data->user_data);

		g_free(name);
		g_free(uid);
		g_free(tel);
	}

	g_list_free_full(contacts, g_object_unref);

done:
	if (data->queued_calls == 0)
		data->ready_cb(data->user_data);

	return;

canceled:
	if (data->queued_calls == 0)
		free_query_context(data);
}

static GSList *traverse_sources(GSList *ebooks, GSList *sources,
							char **default_src) {
	GError *gerr = NULL;

	for (; sources != NULL; sources = g_slist_next(sources)) {
		char *uri;
		ESource *source = E_SOURCE(sources->data);
		EBook *ebook = e_book_new(source, &gerr);

		if (ebook == NULL) {
			error("Can't create user's address book: %s",
								gerr->message);
			g_clear_error(&gerr);
			continue;
		}

		uri = e_source_get_uri(source);
		if (g_strcmp0(*default_src, uri) == 0) {
			g_free(uri);
			continue;
		}
		g_free(uri);

		if (e_book_open(ebook, FALSE, &gerr) == FALSE) {
			error("Can't open e-book address book: %s",
							gerr->message);
			g_object_unref(ebook);
			g_clear_error(&gerr);
			continue;
		}

		if (*default_src == NULL)
			*default_src = e_source_get_uri(source);

		DBG("%s address book opened", e_source_peek_name(source));

		ebooks = g_slist_append(ebooks, ebook);
	}

	return ebooks;
}

int phonebook_init(void)
{
	g_type_init();

	return 0;
}

static GSList *open_ebooks(void)
{
	GError *gerr = NULL;
	ESourceList *src_list;
	GSList *list;
	char *default_src = NULL;
	GSList *ebooks = NULL;

	if (e_book_get_addressbooks(&src_list, &gerr) == FALSE) {
		error("Can't list user's address books: %s", gerr->message);
		g_error_free(gerr);
		return NULL;
	}

	list = e_source_list_peek_groups(src_list);
	while (list != NULL) {
		ESourceGroup *group = E_SOURCE_GROUP(list->data);
		GSList *sources = e_source_group_peek_sources(group);

		ebooks = traverse_sources(ebooks, sources, &default_src);

		list = list->next;
	}

	g_free(default_src);
	g_object_unref(src_list);

	return ebooks;
}

void phonebook_exit(void)
{
}

char *phonebook_set_folder(const char *current_folder,
		const char *new_folder, uint8_t flags, int *err)
{
	gboolean root, child;
	char *fullname = NULL, *tmp1, *tmp2, *base;
	int ret = 0, len;

	root = (g_strcmp0("/", current_folder) == 0);
	child = (new_folder && strlen(new_folder) != 0);

	/* Evolution back-end will support /telecom/pb folder only */

	switch (flags) {
	case 0x02:
		/* Go back to root */
		if (!child) {
			fullname = g_strdup("/");
			goto done;
		}

		/* Go down 1 level */
		fullname = g_build_filename(current_folder, new_folder, NULL);
		if (strcmp(PB_TELECOM_FOLDER, fullname) != 0 &&
				strcmp(PB_CONTACTS_FOLDER, fullname) != 0) {
			g_free(fullname);
			fullname = NULL;
			ret = -ENOENT;
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
		if (strcmp(fullname, PB_TELECOM_FOLDER) != 0 &&
				strcmp(fullname, PB_CONTACTS_FOLDER) != 0) {
			g_free(fullname);
			fullname = NULL;
			ret = -ENOENT;
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

void phonebook_req_finalize(void *request)
{
	struct query_context *data = request;

	if (data->queued_calls == 0)
		free_query_context(data);
	else
		data->canceled = TRUE;
}

void *phonebook_pull(const char *name, const struct apparam_field *params,
				phonebook_cb cb, void *user_data, int *err)
{
	struct query_context *data;

	if (g_strcmp0(PB_CONTACTS, name) != 0) {
		if (err)
			*err = -ENOENT;

		return NULL;
	}

	data = g_new0(struct query_context, 1);
	data->contacts_cb = cb;
	data->params = params;
	data->user_data = user_data;
	data->buf = g_string_new("");
	data->query = e_book_query_any_field_contains("");
	data->ebooks = open_ebooks();

	if (err)
		*err = data->ebooks == NULL ? -EIO : 0;

	return data;
}

int phonebook_pull_read(void *request)
{
	struct query_context *data = request;
	GSList *l;

	if (!data)
		return -ENOENT;

	for (l = data->ebooks; l != NULL; l = g_slist_next(l)) {
		EBook *ebook = l->data;

		if (e_book_is_opened(ebook) == FALSE)
			continue;

		if (e_book_get_contacts_async(ebook, data->query,
						ebookpull_cb, data) == TRUE)
			data->queued_calls++;
	}

	if (data->queued_calls == 0)
		return -ENOENT;

	return 0;
}

void *phonebook_get_entry(const char *folder, const char *id,
				const struct apparam_field *params,
				phonebook_cb cb, void *user_data, int *err)
{
	struct query_context *data;
	GSList *l;

	data = g_new0(struct query_context, 1);
	data->contacts_cb = cb;
	data->params = params;
	data->user_data = user_data;
	data->id = g_strdup(id);
	data->ebooks = open_ebooks();

	for (l = data->ebooks; l != NULL; l = g_slist_next(l)) {
		EBook *ebook = l->data;

		if (e_book_is_opened(ebook) == FALSE)
			continue;

		if (e_book_get_contact_async(ebook, data->id,
						ebook_entry_cb, data) == TRUE)
			data->queued_calls++;
	}

	if (err)
		*err = (data->queued_calls == 0 ? -ENOENT : 0);

	return data;
}

void *phonebook_create_cache(const char *name, phonebook_entry_cb entry_cb,
		phonebook_cache_ready_cb ready_cb, void *user_data, int *err)
{
	struct query_context *data;
	EBookQuery *query;
	GSList *l;
	EContact *me;
	EVCard *evcard;
	GError *gerr = NULL;
	EBook *eb;
	EVCardAttribute *attrib;
	char *uid, *tel, *cname;

	if (g_strcmp0(PB_CONTACTS_FOLDER, name) != 0) {
		if (err)
			*err = -ENOENT;

		return NULL;
	}

	DBG("");

	query = e_book_query_any_field_contains("");

	data = g_new0(struct query_context, 1);
	data->entry_cb = entry_cb;
	data->ready_cb = ready_cb;
	data->user_data = user_data;
	data->query = query;
	data->ebooks = open_ebooks();

	/* Add 0.vcf */
	if (e_book_get_self(&me, &eb, &gerr) == FALSE) {
		g_error_free(gerr);
		goto next;
	}

	evcard = E_VCARD(me);

	cname = evcard_name_attribute_to_string(evcard);
	if (!cname)
		cname = g_strdup("");

	attrib = e_vcard_get_attribute(evcard, EVC_UID);
	uid = e_vcard_attribute_get_value(attrib);
	if (!uid)
		uid = g_strdup("");

	attrib = e_vcard_get_attribute(evcard, EVC_TEL);
	if (attrib)
		tel =  e_vcard_attribute_get_value(attrib);
	else
		tel = g_strdup("");

	data->entry_cb(uid, 0, cname, NULL, tel, data->user_data);

	data->count++;

	g_free(cname);
	g_free(uid);
	g_free(tel);
	g_object_unref(eb);

next:
	for (l = data->ebooks; l != NULL; l = g_slist_next(l)) {
		EBook *ebook = l->data;

		if (e_book_is_opened(ebook) == FALSE)
			continue;

		if (e_book_get_contacts_async(ebook, query,
						cache_cb, data) == TRUE)
			data->queued_calls++;
	}

	if (err)
		*err = (data->queued_calls == 0 ? -ENOENT : 0);

	return data;
}
