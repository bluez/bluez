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

struct service {
	char *object_path;
	char *ident;
	char *name;
};

void release_services(DBusConnection *conn);

void append_available_services(DBusMessageIter *iter);

struct service *search_service(const char *pattern);

struct service *search_service_by_uuid(const char *uuid);

int service_unregister(DBusConnection *conn, struct service *service);

int register_service(const char *ident, const char **uuids);
void unregister_service(const char *ident);

typedef void (*service_auth_cb) (DBusError *derr, void *user_data);
int service_req_auth(const bdaddr_t *src, const bdaddr_t *dst,
		const char *uuid, service_auth_cb cb, void *user_data);
int service_cancel_auth(const bdaddr_t *src, const bdaddr_t *dst);
