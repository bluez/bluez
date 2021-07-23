// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2009-2021  Intel Corporation
 *  Copyright (C) 2007-2021  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2021       Dylan Van Assche <me@dylanvanassche.be>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <glib.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libebook/libebook.h>
#include <libedataserver/libedataserver.h>

#include "obexd/src/log.h"
#include "phonebook.h"

#define CONNECTION_TIMEOUT 30  // seconds
#define PB_FORMAT_VCARD21	0
#define PB_FORMAT_VCARD30	1
#define PB_FORMAT_NONE		2

ESourceRegistry *registry;
ESource *address_book;
EBookClient *book_client;

struct query_context {
	const struct apparam_field *params;
	phonebook_cb contacts_cb;
	phonebook_entry_cb entry_cb;
	phonebook_cache_ready_cb ready_cb;
	gchar *query;
	unsigned int count;
	GString *buf;
	char *uid;
	unsigned queued_calls;
	void *user_data;
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

static void free_query_context(struct query_context *data)
{
	g_free(data->uid);

	if (data->buf != NULL)
		g_string_free(data->buf, TRUE);

	if (data->query != NULL)
		g_free(data->query);

	g_free(data);
}

static char *evcard_to_string(EVCard *evcard, unsigned int format,
							       uint64_t filter)
{
	EVCard *evcard2;
	GList *l;
	char *vcard;

	if (!filter)
		return e_vcard_to_string(evcard, format);

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

char *phonebook_set_folder(const char *current_folder, const char *new_folder,
						       uint8_t flags, int *err)
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
	/* Free resources after pull request */
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
	EBookQuery *query;

	/* Request should be for '/telecom/pb.vcf', reject others */
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
	query = e_book_query_any_field_contains("");  // all contacts
	data->query = e_book_query_to_string(query);
	e_book_query_unref(query);

	return data;
}

static void phonebook_pull_read_ready(GObject *source_object,
				      GAsyncResult *result, gpointer user_data)
{
	struct query_context *data = user_data;
	GSList *l = NULL;
	GSList *contacts = NULL;
	GError *gerr = NULL;
	unsigned int count, maxcount;

	/* Finish async call to retrieve contacts */
	data->queued_calls--;

	if (data->canceled)
		goto canceled;

	e_book_client_get_contacts_finish(E_BOOK_CLIENT(source_object),
						     result, &contacts, &gerr);

	if (gerr != NULL) {
		error("Failed to retrieve contacts, invalid query");
		g_error_free(gerr);
		goto done;
	}

	/*
	 * When MaxListCount is zero, PCE wants to know the number of used
	 * indexes in the phonebook of interest. All other parameters that
	 * may be present in the request shall be ignored.
	 */
	maxcount = data->params->maxlistcount;
	if (maxcount == 0) {
		data->count += g_slist_length(contacts);
		goto done;
	}

	/*
	 * Convert each contact to a vCard and append the card to
	 * the buffer string.
	 */
	l = g_slist_nth(contacts, data->params->liststartoffset);
	for (count = 0; l && count + data->count < maxcount;
						l = g_slist_next(l), count++) {
		EContact *contact = E_CONTACT(l->data);
		EVCard *evcard = E_VCARD(contact);
		char *vcard;

		if (data->params->format == PB_FORMAT_VCARD30)
			vcard = evcard_to_string(evcard, EVC_FORMAT_VCARD_30,
							 data->params->filter);
		else if (data->params->format == PB_FORMAT_VCARD21)
			vcard = evcard_to_string(evcard, EVC_FORMAT_VCARD_21,
							 data->params->filter);
		else
			error("unknown format: %d", data->params->format);

		data->buf = g_string_append(data->buf, vcard);
		data->buf = g_string_append(data->buf, "\r\n");
		g_free(vcard);
	}

	DBG("collected %d contacts", count);

	data->count += count;
	g_slist_free_full(contacts, (GDestroyNotify) g_object_unref);

done:
	if (data->queued_calls == 0) {
		GString *buf = data->buf;
		data->buf = NULL;

		data->contacts_cb(buf->str, buf->len, data->count, 0, TRUE,
							      data->user_data);
		g_string_free(buf, TRUE);
	}

	return;

canceled:
	if (data->queued_calls == 0)
		free_query_context(data);
}

int phonebook_pull_read(void *request)
{
	struct query_context *data = request;
	GError *gerr = NULL;

	if (!data) {
		error("Request data is empty");
		return -ENOENT;
	}

	DBG("retrieving all contacts");

	/* Fetch async contacts from default address book */
	e_book_client_get_contacts(book_client, data->query, NULL,
			(GAsyncReadyCallback) phonebook_pull_read_ready, data);
	data->queued_calls++;

	return 0;
}

static void phonebook_get_entry_ready(GObject *source_object,
				      GAsyncResult *result, gpointer user_data)
{
	GError *gerr = NULL;
	EContact *contact = NULL;
	struct query_context *data = user_data;
	EVCard *evcard;
	char *vcard;
	size_t len;

	data->queued_calls--;

	e_book_client_get_contact_finish(E_BOOK_CLIENT(source_object), result,
							      &contact, &gerr);
	if (data->canceled)
		goto done;

	if (gerr != NULL) {
		error("Getting contact failed: %s", gerr->message);
		g_error_free(gerr);
		goto done;
	}

	evcard = E_VCARD(contact);

	if (data->params->format == PB_FORMAT_VCARD30)
		vcard = evcard_to_string(evcard, EVC_FORMAT_VCARD_30,
							 data->params->filter);
	else if (data->params->format == PB_FORMAT_VCARD21)
		vcard = evcard_to_string(evcard, EVC_FORMAT_VCARD_21,
							 data->params->filter);
	else
		error("Unknown vCard format: %d", data->params->format);

	len = vcard ? strlen(vcard) : 0;

	data->count++;
	data->contacts_cb(vcard, len, 1, 0, TRUE, data->user_data);

	g_free(vcard);

	DBG("retrieving entry successful");

done:
	if (data->queued_calls == 0) {
		if (data->count == 0)
			data->contacts_cb(NULL, 0, 1, 0, TRUE,
					  data->user_data);
		else if (data->canceled)
			free_query_context(data);
	}

	g_object_unref(contact);
}

void *phonebook_get_entry(const char *folder, const char *id,
			   const struct apparam_field *params, phonebook_cb cb,
						     void *user_data, int *err)
{
	struct query_context *data;
	GSList *l;

	DBG("retrieving entry: %s", id);

	data = g_new0(struct query_context, 1);
	data->contacts_cb = cb;
	data->params = params;
	data->user_data = user_data;
	data->uid = g_strdup(id);

	/* Fetch async contacts from default address book */
	e_book_client_get_contact(book_client, data->uid, NULL,
			(GAsyncReadyCallback) phonebook_get_entry_ready, data);
	data->queued_calls++;

	if (err)
		*err = (data->queued_calls == 0 ? -ENOENT : 0);

	return data;
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

static void phonebook_create_cache_ready(GObject *source_object,
				      GAsyncResult *result, gpointer user_data)
{
	struct query_context *data = user_data;
	GSList *l = NULL;
	GSList *contacts = NULL;
	GError *gerr = NULL;

	data->queued_calls--;

	if (data->canceled)
		goto canceled;

	e_book_client_get_contacts_finish(E_BOOK_CLIENT(source_object),
						     result, &contacts, &gerr);

	if (gerr != NULL) {
		error("Getting contacts failed: %s", gerr->message);
		goto done;
	}

	for (l = contacts; l; l = g_slist_next(l)) {
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

	DBG("caching successful");

	g_slist_free_full(contacts, (GDestroyNotify) g_object_unref);

done:
	if (data->queued_calls == 0)
		data->ready_cb(data->user_data);

	return;

canceled:
	if (data->queued_calls == 0)
		free_query_context(data);
}

void *phonebook_create_cache(const char *name, phonebook_entry_cb entry_cb,
		  phonebook_cache_ready_cb ready_cb, void *user_data, int *err)
{
	/* Build a cache of contacts */
	struct query_context *data;
	EBookQuery *query;
	EContact *me;
	EBookClient *me_client;
	EVCard *evcard;
	GError *gerr = NULL;
	EVCardAttribute *attrib;
	char *uid, *tel, *cname;

	if (g_strcmp0(PB_CONTACTS_FOLDER, name) != 0) {
		if (err)
			*err = -ENOENT;

		return NULL;
	}

	DBG("creating cache");

	data = g_new0(struct query_context, 1);
	data->entry_cb = entry_cb;
	data->ready_cb = ready_cb;
	data->user_data = user_data;
	query = e_book_query_any_field_contains("");  // all contacts
	data->query = e_book_query_to_string(query);
	e_book_query_unref(query);

	/* Myself as contact should always be 0.vcf if found in address book */
	if (!e_book_client_get_self(registry, &me, &me_client, &gerr)) {
		DBG("owner is not in address book: %s", gerr->message);
		g_error_free(gerr);
		goto next;
	}

	DBG("caching address book owner");

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

next:
	/* Fetch async contacts from default address book */
	DBG("caching contacts");
	e_book_client_get_contacts(book_client, data->query, NULL,
		     (GAsyncReadyCallback) phonebook_create_cache_ready, data);
	data->queued_calls++;

	if (err)
		*err = (data->queued_calls == 0 ? -ENOENT : 0);

	return data;
}

int phonebook_init(void)
{
	EClient *client;
	GError *gerr = NULL;

	/* Acquire ESource Registry */
	registry = e_source_registry_new_sync(NULL, &gerr);
	if (gerr != NULL) {
		error("Unable to acquire registery: %s\n", gerr->message);
		g_error_free(gerr);
		return -1;
	}

	/* Get ref to default address book */
	address_book = e_source_registry_ref_default_address_book(registry);
	if (address_book == NULL) {
		error("Unable to get reference to default address book");
		return -2;
	}

	/* Allocate e-book client for address book */
	gerr = NULL;
	client = e_book_client_connect_sync(address_book, CONNECTION_TIMEOUT,
								  NULL, &gerr);
	if (gerr != NULL || client == NULL) {
		error("Cannot connect ebook client to EDS: %s",
					gerr != NULL ? gerr->message : "NULL");
		g_error_free(gerr);
		return -3;
	}
	book_client = E_BOOK_CLIENT(client);

	DBG("created address book client");

	return 0;
}

void phonebook_exit(void)
{
	g_object_unref(book_client);
	g_object_unref(address_book);
	g_object_unref(registry);
}
