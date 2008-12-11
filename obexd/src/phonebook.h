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

#include <glib.h>

struct phonebook_driver;

struct phonebook_context {
	gint refcount;

	struct phonebook_driver *driver;
	void *driver_data;
};

extern struct phonebook_context *phonebook_create(
			struct phonebook_driver *driver);
extern struct phonebook_context *phonebook_ref(
			struct phonebook_context *context);
extern void phonebook_unref(struct phonebook_context *context);

static inline void *phonebook_get_data(struct phonebook_context *context)
{
	return context->driver_data;
}

static inline void phonebook_set_data(struct phonebook_context *context,
								void *data)
{
	context->driver_data = data;
}

extern int phonebook_pullphonebook(struct phonebook_context *context,
			gchar *objname, guint64 filter, guint8 format,
			guint16 maxlistcount, guint16 liststartoffset,
			guint16 *phonebooksize, guint8 *newmissedcalls);
extern int phonebook_pullvcardlisting(struct phonebook_context *context,
			gchar *objname, guint8 order, guint8 *searchval,
			guint8 searchattrib, guint16 maxlistcount,
			guint16 liststartoffset, guint16 *phonebooksize,
			guint8 *newmissedcalls);
extern void phonebook_return(struct phonebook_context *context,
						char *buf, int size);

struct phonebook_driver {
	const char *name;
	int (*create) (struct phonebook_context *context);
	void (*destroy) (struct phonebook_context *context);
	int (*pullphonebook) (struct phonebook_context *context,
			gchar *objname, guint64 filter, guint8 format,
			guint16 maxlistcount, guint16 liststartoffset,
			guint16 *phonebooksize, guint8 *newmissedcalls);
	int (*pullvcardlisting) (struct phonebook_context *context,
			gchar *objname, guint8 order, guint8 *searchval,
			guint8 searchattrib, guint16 maxlistcount,
			guint16 liststartoffset, guint16 *phonebooksize,
			guint8 *newmissedcalls);
	int (*pullvcardentry) (struct phonebook_context *context);
};

extern int phonebook_driver_register(struct phonebook_driver *driver);
extern void phonebook_driver_unregister(struct phonebook_driver *driver);

struct phonebook_driver *phonebook_get_driver(const char *name);
