/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#define START_REPLY_TIMEOUT	5000

struct service {
	char *filename;
	char *object_path;

	DBusMessage *action;	/* Either Start or Stop method call */

	guint startup_timer;
	guint shutdown_timer;

	/* These are set when the service is running */
	GPid pid;		/* Process id */
	char *bus_name;		/* D-Bus unique name */

	/* Information parsed from the service file */
	char *name;
	char *descr;
	char *ident;
	gboolean autostart;

	/* Services without a *.service file */
	gboolean external;
};

void release_services(DBusConnection *conn);

void append_available_services(DBusMessageIter *iter);

struct service *search_service(DBusConnection *conn, const char *pattern);

int service_start(struct service *service, DBusConnection *conn);

int init_services(const char *path);

int service_register(DBusConnection *conn, const char *bus_name, const char *ident,
				const char *name, const char *description);

int service_unregister(DBusConnection *conn, struct service *service);
