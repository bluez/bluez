/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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

struct service {
	char *filename;
	char *object_path;

	DBusMessage *action;	/* Either Start or Stop method call */

	guint startup_timer;
	guint shutdown_timer;

	/* These are set when the service is running */
	GPid pid;		/* Process id */
	char *bus_name;		/* D-Bus unique name */
	guint watch_id;		/* Id for the child watch */

	/* Information parsed from the service file */
	char *exec;		/* Location of executable */
	char *name;
	char *descr;
	char *ident;

	GSList *trusted_devices;
	GSList *records; 	/* list of binary records */
};

struct service_call {
	DBusConnection *conn;
	DBusMessage *msg;
	struct service *service;
};

struct binary_record {
	uint32_t ext_handle;
	uint32_t handle;
	sdp_buf_t *buf;
};

struct binary_record *binary_record_new();
void binary_record_free(struct binary_record *rec);
int binary_record_cmp(struct binary_record *rec, uint32_t *handle);

void release_services(DBusConnection *conn);

void append_available_services(DBusMessageIter *iter);

const char *search_service(DBusConnection *conn, const char *pattern);

int register_service_records(GSList *lrecords);

struct service_call *service_call_new(DBusConnection *conn, DBusMessage *msg,
					struct service *service);
void service_call_free(void *data);

int init_services(const char *path);

#endif /* __BLUEZ_DBUS_SERVICE_H */
