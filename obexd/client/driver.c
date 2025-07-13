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

#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <glib.h>

#include "gdbus/gdbus.h"

#include "obexd/src/log.h"
#include "transfer.h"
#include "session.h"
#include "driver.h"

static GSList *drivers = NULL;

struct obc_driver *obc_driver_find(const char *pattern)
{
	GSList *l;

	for (l = drivers; l; l = l->next) {
		struct obc_driver *driver = l->data;

		if (strcasecmp(pattern, driver->service) == 0)
			return driver;

		if (strcasecmp(pattern, driver->uuid) == 0)
			return driver;
	}

	return NULL;
}

int obc_driver_register(struct obc_driver *driver)
{
	if (!driver) {
		error("Invalid driver");
		return -EINVAL;
	}

	if (obc_driver_find(driver->service)) {
		error("Permission denied: service %s already registered",
			driver->service);
		return -EPERM;
	}

	DBG("driver %p service %s registered", driver, driver->service);

	drivers = g_slist_append(drivers, driver);

	return 0;
}

void obc_driver_unregister(struct obc_driver *driver)
{
	if (!g_slist_find(drivers, driver)) {
		error("Unable to unregister: No such driver %p", driver);
		return;
	}

	DBG("driver %p service %s unregistered", driver, driver->service);

	drivers = g_slist_remove(drivers, driver);
}

static void call_cb(gpointer data, gpointer ctxt)
{
	struct obc_driver *driver = (struct obc_driver *)data;

	if (driver->uid_state)
		driver->uid_state(((struct logind_cb_context *)ctxt));
}

static void call_uid_state_cb(gpointer ctxt)
{
	g_slist_foreach(drivers, call_cb, ctxt);
}

gboolean obc_driver_init(void)
{
	return logind_register(call_uid_state_cb) >= 0;
}
