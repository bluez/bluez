// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <glib.h>

#include "obex.h"
#include "server.h"
#include "transport.h"
#include "log.h"

static GSList *drivers = NULL;

static const struct obex_transport_driver *
obex_transport_driver_find(const char *name)
{
	const GSList *l;

	for (l = drivers; l; l = l->next) {
		const struct obex_transport_driver *driver = l->data;

		if (g_strcmp0(name, driver->name) == 0)
			return driver;
	}

	return NULL;
}

const GSList *obex_transport_driver_list(void)
{
	return drivers;
}

int obex_transport_driver_register(const struct obex_transport_driver *driver)
{
	if (!driver) {
		error("Invalid driver");
		return -EINVAL;
	}

	if (obex_transport_driver_find(driver->name) != NULL) {
		error("Permission denied: transport %s already registered",
			driver->name);
		return -EPERM;
	}

	DBG("driver %p transport %s registered", driver, driver->name);

	drivers = g_slist_prepend(drivers, (gpointer)driver);

	return 0;
}

void
obex_transport_driver_unregister(const struct obex_transport_driver *driver)
{
	if (!g_slist_find(drivers, driver)) {
		error("Unable to unregister: No such driver %p", driver);
		return;
	}

	DBG("driver %p transport %s unregistered", driver, driver->name);

	drivers = g_slist_remove(drivers, driver);
}

static void call_cb(gpointer data, gpointer ctxt)
{
	struct obex_transport_driver *driver =
		(struct obex_transport_driver *)data;
	if (driver->uid_state)
		driver->uid_state(((struct logind_cb_context *)ctxt));
}

static int call_uid_state_cb(gpointer ctxt)
{
	g_slist_foreach(drivers, call_cb, ctxt);
}

gboolean obex_transport_driver_init(void)
{
}
