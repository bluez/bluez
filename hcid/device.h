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

#define DEVICE_INTERFACE	"org.bluez.Device"

struct device {
	gchar		*address;
	gchar		*path;
	struct adapter	*adapter;
	GSList		*uuids;
	gboolean	temporary;
	struct agent	*agent;
};

struct device *device_create(DBusConnection *conn, struct adapter *adapter,
				const gchar *address, GSList *uuids);
void device_remove(struct device *device, DBusConnection *conn);
gint device_address_cmp(struct device *device, const gchar *address);
int device_browse(struct device *device, DBusConnection *conn,
			DBusMessage *msg);
