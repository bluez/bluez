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

void hcid_dbus_set_experimental();
int hcid_dbus_use_experimental();
int hcid_dbus_register_device(uint16_t id);
int hcid_dbus_unregister_device(uint16_t id);
int hcid_dbus_start_device(uint16_t id);
int hcid_dbus_stop_device(uint16_t id);
int hcid_dbus_request_pin(int dev, bdaddr_t *sba, struct hci_conn_info *ci);

void hcid_dbus_inquiry_start(bdaddr_t *local);
void hcid_dbus_inquiry_complete(bdaddr_t *local);
void hcid_dbus_periodic_inquiry_start(bdaddr_t *local, uint8_t status);
void hcid_dbus_periodic_inquiry_exit(bdaddr_t *local, uint8_t status);
void hcid_dbus_inquiry_result(bdaddr_t *local, bdaddr_t *peer, uint32_t class, int8_t rssi, uint8_t *data);
void hcid_dbus_remote_class(bdaddr_t *local, bdaddr_t *peer, uint32_t class);
void hcid_dbus_remote_name(bdaddr_t *local, bdaddr_t *peer, uint8_t status, char *name);
void hcid_dbus_conn_complete(bdaddr_t *local, uint8_t status, uint16_t handle, bdaddr_t *peer);
void hcid_dbus_disconn_complete(bdaddr_t *local, uint8_t status, uint16_t handle, uint8_t reason);
void hcid_dbus_bonding_process_complete(bdaddr_t *local, bdaddr_t *peer, uint8_t status);
void hcid_dbus_setname_complete(bdaddr_t *local);
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

int unregister_adapter_path(const char *path);

DBusMessage *new_authentication_return(DBusMessage *msg, uint8_t status);

int get_default_dev_id(void);

int cancel_discovery(struct adapter *adapter);
int cancel_periodic_discovery(struct adapter *adapter);

int active_conn_find_by_bdaddr(const void *data, const void *user_data);
void bonding_request_free(struct bonding_request_info *dev);
int found_device_cmp(const struct remote_dev_info *d1,
			const struct remote_dev_info *d2);
int found_device_add(GSList **list, bdaddr_t *bdaddr, int8_t rssi,
			name_status_t name_status);
int found_device_req_name(struct adapter *dbus_data);

int set_limited_discoverable(int dd, const uint8_t *cls, gboolean limited);
int set_service_classes(int dd, const uint8_t *cls, uint8_t value);

int discov_timeout_handler(void *data);

void set_dbus_connection(DBusConnection *conn);

DBusConnection *get_dbus_connection(void);
struct adapter *adapter_find(const bdaddr_t *sba);
