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

#ifndef __BLUEZ_DBUS_SECURITY_H
#define __BLUEZ_DBUS_SECURITY_H

#define SECURITY_INTERFACE "org.bluez.Security"

struct passkey_agent {
	struct adapter *adapter;
	DBusConnection *conn;
	char *addr;
	char *name;
	char *path;
	GSList *pending_requests;
	int exited;
	guint timeout;
};

struct pending_agent_request {
	struct passkey_agent *agent;
	int dev;
	bdaddr_t sba;
	bdaddr_t bda;
	char *path;
	DBusPendingCall *call;
	int old_if;
	char *pin;
};

struct authorization_agent {
	DBusConnection *conn;
	char *name;
	char *path;
	GSList *pending_requests;
};

struct pend_auth_agent_req {
	DBusMessage *msg;
	struct authorization_agent *agent;
	char *adapter_path;
	char *address;
	char *service_path;
	char *action;
	DBusPendingCall *call;
};

DBusHandlerResult handle_security_method(DBusConnection *conn, DBusMessage *msg, void *data);

int handle_passkey_request(DBusConnection *conn, int dev, const char *path,
				bdaddr_t *sba, bdaddr_t *dba);

int handle_confirm_request(DBusConnection *conn, int dev, const char *path,
				bdaddr_t *sba, bdaddr_t *dba, const char *pin);

void release_default_agent(void);

void release_default_auth_agent(void);

void release_passkey_agents(struct adapter *adapter, bdaddr_t *bda);

void cancel_passkey_agent_requests(GSList *agents, const char *path, bdaddr_t *dba);

#endif /* __BLUEZ_DBUS_SECURITY_H */
