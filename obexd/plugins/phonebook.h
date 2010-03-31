/*
 *
 *  OBEX Server
 *
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

#define EOL	"\r\n"
#define VCARD_LISTING_BEGIN \
	"<?xml version=\"1.0\"?>"				EOL\
	"<!DOCTYPE vcard-listing SYSTEM \"vcard-listing.dtd\">" EOL\
	"<vCard-listing version=\"1.0\">"			EOL
#define VCARD_LISTING_ELEMENT		"<card handle = \"%d.vcf\" name = \"%s\"/>" EOL
#define VCARD_LISTING_END	"</vCard-listing>"

struct apparam_field {
	/* list and pull attributes */
	guint16		maxlistcount;
	guint16		liststartoffset;

	/* pull and vcard attributes */
	guint64		filter;
	guint8		format;

	/* list attributes only */
	guint8		order;
	guint8		searchattrib;
	guint8		*searchval;
};

/*
 * Interface between the PBAP core and backends to retrieve
 * all contacts that match the application parameters rules.
 * Contacts will be returned in the vcard format.
 */
typedef void (*phonebook_cb) (const gchar *buffer, size_t bufsize,
		gint vcards, gint missed, gpointer user_data);

/*
 * Interface between the PBAP core and backends to
 * append a new entry in the PBAP folder cache.
 */
typedef void (*phonebook_entry_cb) (const gchar *id, const gchar *name,
		const gchar *sound, const gchar *tel, gpointer user_data);

/*
 * After notify all entries to PBAP core, the backend
 * needs to notify that the operation has finished.
 */
typedef void (*phonebook_cache_ready_cb) (gpointer user_data);


int phonebook_init(void);
void phonebook_exit(void);

int phonebook_set_folder(const gchar *current_folder,
		const gchar *new_folder, guint8 flags);

/*
 * PullPhoneBook never use cached entries. PCE use this
 * function to get all entries of a given folder.
 */
int phonebook_pull(const gchar *name, const struct apparam_field *params,
		phonebook_cb cb, gpointer user_data);

int phonebook_get_entry(const gchar *id, const struct apparam_field *params,
		phonebook_cb cb, gpointer user_data);

/*
 * PBAP core will keep the contacts cache per folder. SetPhoneBook or
 * PullvCardListing can invalidate the cache if the current folder changes.
 */
int phonebook_create_cache(const gchar *name, phonebook_entry_cb entry_cb,
		phonebook_cache_ready_cb ready_cb, gpointer user_data);
