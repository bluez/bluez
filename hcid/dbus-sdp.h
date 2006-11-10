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

#ifndef __BLUEZ_DBUS_SDP_H
#define __BLUEZ_DBUS_SDP_H

#include <stdint.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>

#define SDP_INTERFACE "org.bluez.SDP"

typedef enum {
	SDP_FORMAT_XML,
	SDP_FORMAT_BINARY
} sdp_format_t;

DBusHandlerResult handle_sdp_method(DBusConnection *conn, DBusMessage *msg, void *data);

DBusHandlerResult get_remote_svc_handles(DBusConnection *conn, DBusMessage *msg, void *data);

DBusHandlerResult get_remote_svc_rec(DBusConnection *conn, DBusMessage *msg, void *data, sdp_format_t format);

uint16_t sdp_str2svclass(const char *str);

typedef void get_record_cb_t(sdp_record_t *rec, void *data, int err);

int get_record_with_uuid(DBusConnection *conn, DBusMessage *msg,
			uint16_t dev_id, const char *dst,
			const uuid_t *uuid, get_record_cb_t *cb, void *data);

int get_record_with_handle(DBusConnection *conn, DBusMessage *msg,
			uint16_t dev_id, const char *dst,
			uint32_t handle, get_record_cb_t *cb, void *data);


#endif /* __BLUEZ_DBUS_SDP_H */
