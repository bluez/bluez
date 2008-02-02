/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <bluetooth/bluetooth.h>

struct session_data {
	DBusConnection *conn;
	DBusMessage *msg;
	uid_t uid;
	bdaddr_t bdaddr;
	uint8_t channel;
	char *identifier;
	GIOChannel *rfcomm_io;
};

struct session_data *session_create(DBusConnection *conn, DBusMessage *msg);
void session_destroy(struct session_data *session);

const char *session_connect(struct session_data *session,
				const char *address, const char *pathname);
