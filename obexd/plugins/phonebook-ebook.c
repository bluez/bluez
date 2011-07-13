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

#include "log.h"
#include "obex.h"
#include "service.h"
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
};

static GSList *ebooks = NULL;

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

static void free_query_context(struct query_context *data)
{
	g_free(data->id);

	if (data->buf != NULL)
		g_string_free(data->buf, TRUE);

	if (data->query != NULL)
		e_book_query_unref(data->query);

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
	unsigned int count = 0, maxcount;

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
		count += g_list_length(contacts);
		goto done;
	}

	l = g_list_nth(contacts, data->params->liststartoffset);

	for (; l && count + data->count < maxcount; l = g_list_next(l),
								count++) {
		EContact *contact = E_CONTACT(l->data);
		EVCard *evcard = E_VCARD(contact);
		char *vcard;

		vcard = evcard_to_string(evcard, data->params->format,
						data->params->filter);

		data->buf = g_string_append(data->buf, vcard);
		data->buf = g_string_append(data->buf, "\r\n");
		g_free(vcard);
	}

	data->count += count;

done:
	g_list_free_full(contacts, g_object_unref);

	DBG("collected %d vcards", count);

	data->queued_calls--;
	if (data->queued_calls == 0)
		data->contacts_cb(data->buf->str, data->buf->len, data->count,
						0, TRUE, data->user_data);
}

static void ebook_entry_cb(EBook *book, const GError *gerr,
				EContact *contact, void *user_data)
{
	struct query_context *data = user_data;
	EVCard *evcard;
	char *vcard;
	size_t len;

	if (gerr != NULL) {
		error("E-Book query failed: %s", gerr->message);
		goto done;
	}

	DBG("");

	evcard = E_VCARD(contact);

	vcard = evcard_to_string(evcard, data->params->format,
					data->params->filter);

	len = vcard ? strlen(vcard) : 0;

	data->count++;
	data->contacts_cb(vcard, len, 1, 0, TRUE, data->user_data);

	g_free(vcard);
	g_object_unref(contact);

done:
	data->queued_calls--;
	if (data->queued_calls == 0) {
		if (data->count == 0)
			data->contacts_cb(NULL, 0, 1, 0, TRUE,
						data->user_data);

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
		if (!attrib)
			tel = e_vcard_attribute_get_value(attrib);
		else
			tel = g_strdup("");

		data->entry_cb(uid, PHONEBOOK_INVALID_HANDLE, name, NULL,
							tel, data->user_data);

		g_free(name);
		g_free(uid);
		g_free(tel);
	}

done:
	g_list_free_full(contacts, g_object_unref);

	data->queued_calls--;
	if (data->queued_calls == 0)
		data->ready_cb(data->user_data);
}

static int traverse_sources(GSList *sources, char *default_src) {
	GError *gerr;

	while (sources != NULL) {
		EBook *ebook = e_book_new(E_SOURCE(sources->data), &gerr);
		if (ebook == NULL) {
			error("Can't create user's address book: %s",
								gerr->message);
			sources = sources->next;

			g_error_free(gerr);
			continue;
		}

		if (g_strcmp0(default_src, e_source_get_uri(
					E_SOURCE(sources->data))) == 0) {
			sources = sources->next;

			continue;
		}

		if (e_book_open(ebook, FALSE, &gerr) == FALSE) {
			error("Can't open e-book address book: %s",
							gerr->message);
			sources = sources->next;

			g_object_unref(ebook);
			g_error_free(gerr);
			continue;
		}

		if (default_src == NULL)
			default_src = e_source_get_uri(E_SOURCE(sources->data));

		DBG("%s address book opened",
					e_source_peek_name(sources->data));

		ebooks = g_slist_append(ebooks, ebook);

		sources = sources->next;
	}

	return 0;
}

int phonebook_init(void)
{
	GError *gerr;
	ESourceList *src_list;
	GSList *list;
	gchar *default_src = NULL;
	int status = 0;

	if (ebooks)
		return 0;

	g_type_init();

	if (e_book_get_addressbooks(&src_list, &gerr) == FALSE) {
		error("Can't list user's address books: %s", gerr->message);
		g_error_free(gerr);

		status = -EIO;
		goto fail;
	}

	list = e_source_list_peek_groups(src_list);
	while (list) {
		ESourceGroup *group = E_SOURCE_GROUP(list->data);

		GSList *sources = e_source_group_peek_sources(group);

		traverse_sources(sources, default_src);

		list = list->next;
	}

	return status;

fail:
	g_slist_free_full(ebooks, g_object_unref);
	g_object_unref(src_list);

	return status;
}

void phonebook_exit(void)
{
	DBG("");

	if (ebooks == NULL)
		return;

	g_slist_free_full(ebooks, g_object_unref);
	ebooks = NULL;
}

char *phonebook_set_folder(const char *current_folder,
		const char *new_folder, uint8_t flags, int *err)
{
	gboolean root, child;
	char *fullname = NULL, *tmp1, *tmp2, *base;
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
		if (strcmp(fullname, "/telecom") != 0 &&
				strcmp(fullname, "/telecom/pb") != 0) {
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
	GSList *ebook = ebooks;

	DBG("");

	while (ebook != NULL) {
		if (e_book_cancel(ebook->data, NULL) == TRUE)
			data->queued_calls--;

		ebook = ebook->next;
	}

	if (data != NULL && data->queued_calls == 0)
		free_query_context(data);
}

void *phonebook_pull(const char *name, const struct apparam_field *params,
				phonebook_cb cb, void *user_data, int *err)
{
	struct query_context *data;

	if (g_strcmp0("/telecom/pb.vcf", name) != 0) {
		if (err)
			*err = -ENOENT;

		return NULL;
	}

	data = g_new0(struct query_context, 1);
	data->contacts_cb = cb;
	data->params = params;
	data->user_data = user_data;
	data->buf = g_string_new("");

	if (err)
		*err = 0;

	return data;
}

int phonebook_pull_read(void *request)
{
	struct query_context *data = request;
	gboolean ret;
	GSList *ebook;

	if (!data)
		return -ENOENT;

	data->query = e_book_query_any_field_contains("");

	ebook = ebooks;
	while (ebook != NULL) {
		if (e_book_is_opened(ebook->data) == TRUE) {
			ret = e_book_get_contacts_async(ebook->data,
					data->query, ebookpull_cb, data);
			if (ret == TRUE)
				data->queued_calls++;
		}

		ebook = ebook->next;
	}

	if (data->queued_calls == 0)
		return -ENOENT;

	return 0;
}

void *phonebook_get_entry(const char *folder, const char *id,
				const struct apparam_field *params,
				phonebook_cb cb, void *user_data, int *err)
{
	gboolean ret;
	struct query_context *data;
	GSList *ebook;

	data = g_new0(struct query_context, 1);
	data->contacts_cb = cb;
	data->params = params;
	data->user_data = user_data;
	data->id = g_strdup(id);

	ebook = ebooks;
	while (ebook != NULL) {
		if (e_book_is_opened(ebook->data) == TRUE) {
			ret = e_book_get_contact_async(ebook->data, data->id,
							ebook_entry_cb, data);
			if (ret == TRUE)
				data->queued_calls++;
		}

		ebook = ebook->next;
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
	gboolean ret;
	GSList *ebook;
	EContact *me;
	EVCard *evcard;
	GError *gerr;
	EBook *eb;
	EVCardAttribute *attrib;
	char *uid, *tel, *cname;


	if (g_strcmp0("/telecom/pb", name) != 0) {
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
	ebook = ebooks;
	while (ebook != NULL) {
		if (e_book_is_opened(ebook->data) == TRUE) {
			ret = e_book_get_contacts_async(ebook->data, query,
								cache_cb, data);
			if (ret == TRUE)
				data->queued_calls++;
		}

		ebook = ebook->next;
	}

	if (err)
		*err = (data->queued_calls == 0 ? -ENOENT : 0);

	return data;
}
