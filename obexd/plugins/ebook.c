/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Marcel Holtmann <marcel@holtmann.org>
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

static int ebook_create(struct phonebook_context *context)
{
	DBG("context %p", context);

	return 0;
}

static void ebook_destroy(struct phonebook_context *context)
{
	DBG("context %p", context);
}

static int ebook_pullphonebook(struct phonebook_context *context)
{
	EBook *book;
	EBookQuery *query;
	GList *contacts = NULL;
	GString *pb;
	gchar *result;

	DBG("context %p", context);

	book = e_book_new_default_addressbook(NULL);

	e_book_open(book, FALSE, NULL);

	query = e_book_query_any_field_contains("");

	e_book_get_contacts(book, query, &contacts, NULL);

	pb = g_string_new(NULL);

	for (; contacts != NULL; contacts = g_list_next(contacts)) {
		EContact *contact = E_CONTACT(contacts->data);
		char *vcard;

		vcard = e_vcard_to_string(E_VCARD(contact),
						EVC_FORMAT_VCARD_30);
		g_string_append_printf(pb, "%s\n", vcard);
		g_free(vcard);
	}

	result = g_string_free(pb, FALSE);
	phonebook_return(context, result, strlen(result));
	g_free(result);

	e_book_query_unref(query);

	g_object_unref(book);

	return 0;
}

static struct phonebook_driver ebook_driver = {
	.name		= "ebook",
	.create		= ebook_create,
	.destroy	= ebook_destroy,
	.pullphonebook	= ebook_pullphonebook,
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
