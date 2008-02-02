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

#define BASE_PATH		"/org/bluez"

#define MAX_PATH_LENGTH 64

typedef DBusHandlerResult (*service_handler_func_t) (DBusConnection *conn,
							DBusMessage *msg,
							void *user_data);

struct service_data {
	const char		*name;
	service_handler_func_t	handler_func;
};

service_handler_func_t find_service_handler(struct service_data *services, DBusMessage *msg);

int str2uuid(uuid_t *uuid, const char *string);

int l2raw_connect(const char *local, const bdaddr_t *remote);

int find_conn(int s, int dev_id, long arg);

#define check_address(address) bachk(address)

DBusHandlerResult handle_method_call(DBusConnection *conn, DBusMessage *msg, void *data);

void hcid_dbus_exit(void);
int hcid_dbus_init(void);

int register_sdp_binary(uint8_t *data, uint32_t size, uint32_t *handle);
int register_sdp_record(sdp_record_t *rec);
int unregister_sdp_record(uint32_t handle);
int update_sdp_record(uint32_t handle, sdp_record_t *rec);
void cleanup_sdp_session(void);
