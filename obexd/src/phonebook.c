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
#include <glib.h>
#include <stdlib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "obex.h"

static GSList *driver_list = NULL;

int phonebook_driver_register(struct phonebook_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_append(driver_list, driver);

	return 0;
}

void phonebook_driver_unregister(struct phonebook_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);
}

struct phonebook_context *phonebook_create(struct phonebook_driver *driver)
{
	struct phonebook_context *context;

	if (driver == NULL)
		return NULL;

	context = g_try_new0(struct phonebook_context, 1);
	if (context == NULL)
		return NULL;

	DBG("context %p", context);

	context->refcount = 1;
	context->driver = driver;

	if (driver->create) {
		if (driver->create(context) < 0) {
			g_free(context);
			return NULL;
		}
	}

	return context;
}

struct phonebook_context *phonebook_ref(struct phonebook_context *context)
{
	DBG("context %p refcount %d", context,
				g_atomic_int_get(&context->refcount) + 1);

	g_atomic_int_inc(&context->refcount);

	return context;
}

void phonebook_unref(struct phonebook_context *context)
{
	DBG("context %p refcount %d", context,
				g_atomic_int_get(&context->refcount) - 1);

	if (g_atomic_int_dec_and_test(&context->refcount) == TRUE) {
		if (context->driver->destroy)
			context->driver->destroy(context);
		g_free(context);
	}
}

int phonebook_pullphonebook(struct phonebook_context *context, gchar *objname,
			guint64 filter, guint8 format, guint16 maxlistcount,
			guint16 liststartoffset, guint16 *phonebooksize,
			guint8 *newmissedcalls)
{
	if (!context->driver->pullphonebook)
		return -1;

	return context->driver->pullphonebook(context, objname, filter, format,
				maxlistcount, liststartoffset, phonebooksize,
				newmissedcalls);
}

int phonebook_pullvcardlisting(struct phonebook_context *context,
			gchar *objname, guint8 order, guint8 *searchval,
			guint8 searchattrib, guint16 maxlistcount,
			guint16 liststartoffset, guint16 *phonebooksize,
			guint8 *newmissedcalls)
{
	if (!context->driver->pullvcardlisting)
		return -1;

	return context->driver->pullvcardlisting(context, objname, order,
				searchval, searchattrib, maxlistcount,
				liststartoffset, phonebooksize, newmissedcalls);
}

int phonebook_pullvcardentry(struct phonebook_context *context, gchar *objname,
						guint64 filter, guint8 format)
{
	if (!context->driver->pullvcardentry)
		return -1;

	return context->driver->pullvcardentry(context, objname, filter,
								format);
}

/* if buf is NULL or size is 0, this indicate that no more result will
 * be returned by PBAP plugin
 * */
void phonebook_return(struct phonebook_context *context,
						char *buf, int size)
{
	struct obex_session *session;

	DBG("context %p", context);

	session = pbap_get_session(context);

	if (buf == NULL || size == 0) {
		session->finished = 1;
		OBEX_ResumeRequest(session->obex);
		return;
	}

	session->buf = g_realloc(session->buf, session->size + size);
	memcpy(session->buf + session->size, buf, size);
	session->size += size;

	OBEX_ResumeRequest(session->obex);
}

struct phonebook_driver *phonebook_get_driver(const char *name)
{
	DBG("name %s", name);

	return g_slist_nth_data(driver_list, 0);
}
