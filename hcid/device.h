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

struct btd_device {
	char *path;
	bdaddr_t src;
	bdaddr_t dst;
};

struct device {
	struct btd_device dev;
	gchar		*address;
	gchar		*path;
	struct adapter	*adapter;
	GSList		*uuids;
	GSList		*drivers;
	gboolean	temporary;
	struct agent	*agent;
	guint		disconn_timer;
	int		discov_active;		/* Service discovery active */
	char		*discov_requestor;	/* discovery requestor unique name */
	guint		discov_listener;

	/* For Secure Simple Pairing */
	uint8_t		cap;
	uint8_t		auth;
};

struct device *device_create(DBusConnection *conn, struct adapter *adapter,
				const gchar *address);
void device_remove(DBusConnection *conn, struct device *device);
gint device_address_cmp(struct device *device, const gchar *address);
int device_browse(struct device *device, DBusConnection *conn,
			DBusMessage *msg, uuid_t *search);
void device_probe_drivers(struct device *device, GSList *uuids);

#define BTD_UUIDS(args...) ((const char *[]) { args, NULL } )

struct btd_device_driver {
	const char *name;
	const char **uuids;
	int (*probe) (struct btd_device *device);
	void (*remove) (struct btd_device *device);
};

int btd_register_device_driver(struct btd_device_driver *driver);
void btd_unregister_device_driver(struct btd_device_driver *driver);
