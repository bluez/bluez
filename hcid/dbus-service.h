/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
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

#ifndef __BLUEZ_DBUS_SERVICE_H
#define __BLUEZ_DBUS_SERVICE_H

#define START_REPLY_TIMEOUT	5000
#define SERVICE_RUNNING		1
#define SERVICE_NOT_RUNNING	0

struct service_agent {
	char *id;	/* Connection id */
	char *name;
	char *description;
	int running;
	struct slist *trusted_devices;
	struct slist *records;
};

struct service_call {
	DBusConnection *conn;
	DBusMessage *msg;
	struct service_agent *agent;
};

int register_service_agent(DBusConnection *conn, const char *sender, const char *path,
				const char *name, const char *description);
int unregister_service_agent(DBusConnection *conn, const char *sender,
				const char *path);

void release_service_agents(DBusConnection *conn);
void append_available_services(DBusMessageIter *iter);

int register_agent_records(struct slist *lrecords);

struct service_call *service_call_new(DBusConnection *conn, DBusMessage *msg,
					struct service_agent *agent);
void service_call_free(void *data);

#endif /* __BLUEZ_DBUS_SERVICE_H */
