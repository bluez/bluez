/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2008  Intel Corporation
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

#include <gdbus.h>

#define PBAP_INTERFACE  "org.openobex.PhonebookAccess"

struct pbap_data {
	char *path;
	guint8 format;
	guint8 order;
	uint64_t filter;
};

gboolean pbap_register_interface(DBusConnection *connection, const char *path,
				void *user_data, GDBusDestroyFunction destroy);
void pbap_unregister_interface(DBusConnection *connection, const char *path,
				void *user_data);