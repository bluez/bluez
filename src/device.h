/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#define DEVICE_INTERFACE	"org.bluez.Device1"

struct btd_device;

struct btd_device *device_create(struct btd_adapter *adapter,
				const char *address, uint8_t bdaddr_type);
struct btd_device *device_create_from_storage(struct btd_adapter *adapter,
				const char *address, GKeyFile *key_file);
char *btd_device_get_storage_path(struct btd_device *device,
				const char *filename);

void device_set_name(struct btd_device *device, const char *name);
void device_get_name(struct btd_device *device, char *name, size_t len);
bool device_name_known(struct btd_device *device);
void device_set_class(struct btd_device *device, uint32_t class);
uint16_t btd_device_get_vendor(struct btd_device *device);
uint16_t btd_device_get_vendor_src(struct btd_device *device);
uint16_t btd_device_get_product(struct btd_device *device);
uint16_t btd_device_get_version(struct btd_device *device);
void device_remove(struct btd_device *device, gboolean remove_stored);
gint device_address_cmp(struct btd_device *device, const gchar *address);
gint device_bdaddr_cmp(struct btd_device *device, bdaddr_t *bdaddr);
GSList *device_get_uuids(struct btd_device *device);
void device_probe_profiles(struct btd_device *device, GSList *profiles);
const sdp_record_t *btd_device_get_record(struct btd_device *device,
						const char *uuid);
struct gatt_primary *btd_device_get_primary(struct btd_device *device,
							const char *uuid);
GSList *btd_device_get_primaries(struct btd_device *device);
void btd_device_gatt_set_service_changed(struct btd_device *device,
						uint16_t start, uint16_t end);
void btd_device_add_uuid(struct btd_device *device, const char *uuid);
void device_add_eir_uuids(struct btd_device *dev, GSList *uuids);
void device_probe_profile(gpointer a, gpointer b);
void device_remove_profile(gpointer a, gpointer b);
struct btd_adapter *device_get_adapter(struct btd_device *device);
const bdaddr_t *device_get_address(struct btd_device *device);
uint8_t device_get_addr_type(struct btd_device *device);
const gchar *device_get_path(struct btd_device *device);
struct agent *device_get_agent(struct btd_device *device);
gboolean device_is_bredr(struct btd_device *device);
gboolean device_is_le(struct btd_device *device);
gboolean device_is_temporary(struct btd_device *device);
gboolean device_is_paired(struct btd_device *device);
gboolean device_is_bonded(struct btd_device *device);
gboolean device_is_trusted(struct btd_device *device);
void device_set_paired(struct btd_device *device, gboolean paired);
void device_set_temporary(struct btd_device *device, gboolean temporary);
void device_set_bonded(struct btd_device *device, gboolean bonded);
void device_set_legacy(struct btd_device *device, bool legacy);
void device_set_rssi(struct btd_device *device, int8_t rssi);
void device_set_auto_connect(struct btd_device *device, gboolean enable);
gboolean device_is_connected(struct btd_device *device);
void device_bonding_complete(struct btd_device *device, uint8_t status);
gboolean device_is_bonding(struct btd_device *device, const char *sender);
void device_cancel_bonding(struct btd_device *device, uint8_t status);
int device_request_pincode(struct btd_device *device, gboolean secure);
int device_request_passkey(struct btd_device *device);
int device_confirm_passkey(struct btd_device *device, uint32_t passkey,
							uint8_t confirm_hint);
int device_notify_passkey(struct btd_device *device, uint32_t passkey,
							uint8_t entered);
int device_notify_pincode(struct btd_device *device, gboolean secure,
							const char *pincode);
void device_cancel_authentication(struct btd_device *device, gboolean aborted);
gboolean device_is_authenticating(struct btd_device *device);
void device_add_connection(struct btd_device *device);
void device_remove_connection(struct btd_device *device);
void device_request_disconnect(struct btd_device *device, DBusMessage *msg);

typedef void (*disconnect_watch) (struct btd_device *device, gboolean removal,
					void *user_data);

guint device_add_disconnect_watch(struct btd_device *device,
				disconnect_watch watch, void *user_data,
				GDestroyNotify destroy);
void device_remove_disconnect_watch(struct btd_device *device, guint id);
int device_get_appearance(struct btd_device *device, uint16_t *value);
void device_set_appearance(struct btd_device *device, uint16_t value);

struct btd_device *btd_device_ref(struct btd_device *device);
void btd_device_unref(struct btd_device *device);

int device_block(struct btd_device *device, gboolean update_only);
int device_unblock(struct btd_device *device, gboolean silent,
							gboolean update_only);
void btd_device_set_pnpid(struct btd_device *device, uint8_t vendor_id_src,
			uint16_t vendor_id, uint16_t product_id,
			uint16_t product_ver);
GIOChannel *device_att_connect(gpointer user_data);

struct btd_profile;

void device_profile_connected(struct btd_device *dev,
					struct btd_profile *profile, int err);
void device_profile_disconnected(struct btd_device *dev,
					struct btd_profile *profile, int err);
