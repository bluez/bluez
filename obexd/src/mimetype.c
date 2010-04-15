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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <errno.h>
#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "obex.h"
#include "mimetype.h"

static GSList *drivers = NULL;

static GSList *watches = NULL;

struct io_watch {
	gpointer object;
	obex_object_io_func func;
	gpointer user_data;
};

void obex_object_set_io_flags(gpointer object, int flags, int err)
{
	GSList *l;

	for (l = watches; l; l = l->next) {
		struct io_watch *watch = l->data;

		if (watch->object != object)
			continue;

		if (watch->func(object, flags, err, watch->user_data) == TRUE)
			continue;

		if (g_slist_find(watches, watch) == NULL)
			continue;

		watches = g_slist_remove(watches, watch);
		g_free(watch);
	}
}

static struct io_watch *find_io_watch(gpointer object)
{
	GSList *l;

	for (l = watches; l; l = l->next) {
		struct io_watch *watch = l->data;

		if (watch->object == object)
			return watch;
	}

	return NULL;
}

static void reset_io_watch(gpointer object)
{
	struct io_watch *watch;

	watch = find_io_watch(object);
	if (watch == NULL)
		return;

	watches = g_slist_remove(watches, watch);
	g_free(watch);
}

static int set_io_watch(gpointer object, obex_object_io_func func,
				gpointer user_data)
{
	struct io_watch *watch;

	if (func == NULL) {
		reset_io_watch(object);
		return 0;
	}

	watch = find_io_watch(object);
	if (watch)
		return -EPERM;

	watch = g_new0(struct io_watch, 1);
	watch->object = object;
	watch->func = func;
	watch->user_data = user_data;

	watches = g_slist_append(watches, watch);

	return 0;
}

struct obex_mime_type_driver *obex_mime_type_driver_find(const guint8 *target,
		const char *mimetype, const guint8 *who, guint who_size)
{
	GSList *l;

	for (l = drivers; l; l = l->next) {
		struct obex_mime_type_driver *driver = l->data;

		if (memcmp0(target, driver->target, TARGET_SIZE))
			continue;

		if (memcmp0(who, driver->who, who_size))
			continue;

		if (g_strcmp0(mimetype, driver->mimetype) == 0)
			return driver;
	}

	return NULL;
}

int obex_mime_type_driver_register(struct obex_mime_type_driver *driver)
{
	if (!driver) {
		error("Invalid driver");
		return -EINVAL;
	}

	if (obex_mime_type_driver_find(driver->target, driver->mimetype,
					driver->who, driver->who_size)) {
		error("Permission denied: %s could not be registered",
				driver->mimetype);
		return -EPERM;
	}

	if (driver->set_io_watch == NULL)
		driver->set_io_watch = set_io_watch;

	debug("driver %p mimetype %s registered", driver, driver->mimetype);

	drivers = g_slist_append(drivers, driver);

	return 0;
}

void obex_mime_type_driver_unregister(struct obex_mime_type_driver *driver)
{
	if (!g_slist_find(drivers, driver)) {
		error("Unable to unregister: No such driver %p", driver);
		return;
	}

	debug("driver %p mimetype %s unregistered", driver, driver->mimetype);

	drivers = g_slist_remove(drivers, driver);
}
