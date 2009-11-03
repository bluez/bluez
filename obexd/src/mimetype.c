/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2009  Marcel Holtmann <marcel@holtmann.org>
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
#include "mimetype.h"
#include "obex.h"

static GSList *drivers = NULL;

struct obex_mime_type_driver *obex_mime_type_driver_find(const guint8 *target, const char *mimetype)
{
	GSList *l;

	for (l = drivers; l; l = l->next) {
		struct obex_mime_type_driver *driver = l->data;

		if (driver->target && target &&
				memcmp(target, driver->target, TARGET_SIZE))
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

	if (obex_mime_type_driver_find(driver->target, driver->mimetype)) {
		error("Permission denied: %s could not be registered", driver->mimetype);
		return -EPERM;
	}

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
