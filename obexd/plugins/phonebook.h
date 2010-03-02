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

struct apparam_field {
	guint64		filter;
	guint16		maxlistcount;
	guint16		liststartoffset;
	guint8		format;
	guint8		order;
	guint8		searchattrib;
	guint8		*searchval;
};

typedef void (*phonebook_cb) (const gchar *buffer, size_t bufsize,
		gint vcards, gint missed, gpointer user_data);

int phonebook_init(void);
void phonebook_exit(void);

int phonebook_set_folder(const gchar *current_folder,
		const gchar *new_folder, guint8 flags);

int phonebook_query(const gchar *name, phonebook_cb cb, gpointer user_data);
