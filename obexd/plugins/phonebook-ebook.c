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

#define EOL_CHARS "\n"
#define VL_VERSION "<?xml version=\"1.0\"?>" EOL_CHARS
#define VL_TYPE "<!DOCTYPE vcard-listing SYSTEM \"vcard-listing.dtd\">" EOL_CHARS
#define VL_BODY_BEGIN "<vCard-listing version=\"1.0\">" EOL_CHARS
#define VL_BODY_END "</vCard-listing>" EOL_CHARS
#define VL_ELEMENT "<card handle = \"%d.vcf\" name = \"%s\"/>" EOL_CHARS

#define QUERY_FAMILY_NAME "(contains \"family_name\" \"%s\")"
#define QUERY_GIVEN_NAME "(contains \"given_name\" \"%s\")"
#define QUERY_PHONE "(contains \"phone\" \"%s\")"

struct query_data {
	const struct apparam_field *params;
	phonebook_cb cb;
	gpointer user_data;
};

static EBook *ebook = NULL;

static void ebookpull_cb(EBook *book, EBookStatus status, GList *contacts,
				gpointer user_data)
{
	struct query_data *data = user_data;
	GString *string = g_string_new("");
	GList *l;

	for (l = contacts; l; l = g_list_next(l)) {
		EContact *contact;
		EVCard *evcard;
		gchar *vcard;

		contact = E_CONTACT(contacts->data);
		evcard = E_VCARD(contact);
		vcard = e_vcard_to_string(evcard, EVC_FORMAT_VCARD_30);
		string = g_string_append(string, vcard);
		g_free(vcard);
	}

	data->cb(string->str, string->len,
			g_list_length(contacts), 0, data->user_data);

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
