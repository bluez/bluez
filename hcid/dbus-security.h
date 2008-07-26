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

#define SECURITY_INTERFACE "org.bluez.Security"

dbus_bool_t security_init(DBusConnection *conn, const char *path);
dbus_bool_t security_cleanup(DBusConnection *conn, const char *path);

int handle_passkey_request_old(DBusConnection *conn, int dev,
						struct adapter *adapter,
						bdaddr_t *sba, bdaddr_t *dba);

int handle_confirm_request_old(DBusConnection *conn, int dev,
						struct adapter *adapter,
						bdaddr_t *sba, bdaddr_t *dba,
							const char *pin);

void release_default_agent_old(void);

void release_default_auth_agent(void);

void release_passkey_agents(struct adapter *adapter, bdaddr_t *bda);

void cancel_passkey_agent_requests(GSList *agents, const char *path, bdaddr_t *dba);

int handle_authorize_request_old(struct service *service, const char *path,
				const char *address, const char *uuid,
				service_auth_cb cb, void *user_data);
int cancel_authorize_request_old(const char *path, const char *address);
