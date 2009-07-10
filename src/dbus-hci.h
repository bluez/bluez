/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
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

int hcid_dbus_request_pin(int dev, bdaddr_t *sba, struct hci_conn_info *ci);
void hcid_dbus_inquiry_result(bdaddr_t *local, bdaddr_t *peer, uint32_t class, int8_t rssi, uint8_t *data);
void hcid_dbus_remote_class(bdaddr_t *local, bdaddr_t *peer, uint32_t class);
void hcid_dbus_remote_name(bdaddr_t *local, bdaddr_t *peer, uint8_t status, char *name);
void hcid_dbus_conn_complete(bdaddr_t *local, uint8_t status, uint16_t handle, bdaddr_t *peer);
void hcid_dbus_disconn_complete(bdaddr_t *local, uint8_t status, uint16_t handle, uint8_t reason);
void hcid_dbus_bonding_process_complete(bdaddr_t *local, bdaddr_t *peer, uint8_t status);
void hcid_dbus_simple_pairing_complete(bdaddr_t *local, bdaddr_t *peer, uint8_t status);
void hcid_dbus_setscan_enable_complete(bdaddr_t *local);
void hcid_dbus_write_class_complete(bdaddr_t *local);
void hcid_dbus_write_simple_pairing_mode_complete(bdaddr_t *local);
int hcid_dbus_get_io_cap(bdaddr_t *local, bdaddr_t *remote,
						uint8_t *cap, uint8_t *auth);
int hcid_dbus_set_io_cap(bdaddr_t *local, bdaddr_t *remote,
						uint8_t cap, uint8_t auth);
int hcid_dbus_user_confirm(bdaddr_t *sba, bdaddr_t *dba, uint32_t passkey);
int hcid_dbus_user_passkey(bdaddr_t *sba, bdaddr_t *dba);
int hcid_dbus_user_notify(bdaddr_t *sba, bdaddr_t *dba, uint32_t passkey);
int hcid_dbus_link_key_notify(bdaddr_t *local, bdaddr_t *peer,
				uint8_t *key, uint8_t key_type,
				int pin_length, uint8_t old_key_type);

DBusMessage *new_authentication_return(DBusMessage *msg, uint8_t status);

const char *class_to_icon(uint32_t class);

void set_dbus_connection(DBusConnection *conn);

DBusConnection *get_dbus_connection(void);
