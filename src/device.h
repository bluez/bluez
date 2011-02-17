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

#define DEVICE_INTERFACE	"org.bluez.Device"

struct btd_device;
struct att_primary;

typedef enum {
	AUTH_TYPE_PINCODE,
	AUTH_TYPE_PASSKEY,
	AUTH_TYPE_CONFIRM,
	AUTH_TYPE_NOTIFY,
} auth_type_t;

typedef enum {
	DEVICE_TYPE_UNKNOWN,
	DEVICE_TYPE_BREDR,
	DEVICE_TYPE_LE,
	DEVICE_TYPE_DUALMODE
} device_type_t;

struct btd_device *device_create(DBusConnection *conn,
				struct btd_adapter *adapter,
				const gchar *address, device_type_t type);
void device_set_name(struct btd_device *device, const char *name);
void device_get_name(struct btd_device *device, char *name, size_t len);
device_type_t device_get_type(struct btd_device *device);
void device_remove(struct btd_device *device, gboolean remove_stored);
gint device_address_cmp(struct btd_device *device, const gchar *address);
int device_browse_primary(struct btd_device *device, DBusConnection *conn,
				DBusMessage *msg, gboolean secure);
int device_browse_sdp(struct btd_device *device, DBusConnection *conn,
			DBusMessage *msg, uuid_t *search, gboolean reverse);
void device_probe_drivers(struct btd_device *device, GSList *profiles);
const sdp_record_t *btd_device_get_record(struct btd_device *device,
						const char *uuid);
GSList *btd_device_get_primaries(struct btd_device *device);
void btd_device_add_service(struct btd_device *device, const char *path);
void device_add_primary(struct btd_device *device, struct att_primary *prim);
void btd_device_add_uuid(struct btd_device *device, const char *uuid);
struct btd_adapter *device_get_adapter(struct btd_device *device);
void device_get_address(struct btd_device *device, bdaddr_t *bdaddr);
const gchar *device_get_path(struct btd_device *device);
struct agent *device_get_agent(struct btd_device *device);
gboolean device_is_busy(struct btd_device *device);
gboolean device_is_temporary(struct btd_device *device);
gboolean device_is_paired(struct btd_device *device);
gboolean device_is_trusted(struct btd_device *device);
void device_set_paired(struct btd_device *device, gboolean paired);
void device_set_temporary(struct btd_device *device, gboolean temporary);
void device_set_cap(struct btd_device *device, uint8_t cap);
void device_set_type(struct btd_device *device, device_type_t type);
uint8_t device_get_cap(struct btd_device *device);
void device_set_auth(struct btd_device *device, uint8_t auth);
uint8_t device_get_auth(struct btd_device *device);
gboolean device_is_connected(struct btd_device *device);
DBusMessage *device_create_bonding(struct btd_device *device,
				DBusConnection *conn, DBusMessage *msg,
				const char *agent_path, uint8_t capability);
void device_remove_bonding(struct btd_device *device);
void device_bonding_complete(struct btd_device *device, uint8_t status);
void device_simple_pairing_complete(struct btd_device *device, uint8_t status);
gboolean device_is_creating(struct btd_device *device, const char *sender);
gboolean device_is_bonding(struct btd_device *device, const char *sender);
void device_cancel_bonding(struct btd_device *device, uint8_t status);
int device_request_authentication(struct btd_device *device, auth_type_t type,
				uint32_t passkey, void *cb);
void device_cancel_authentication(struct btd_device *device, gboolean aborted);
gboolean device_is_authenticating(struct btd_device *device);
gboolean device_is_authorizing(struct btd_device *device);
void device_set_authorizing(struct btd_device *device, gboolean auth);
void device_add_connection(struct btd_device *device, DBusConnection *conn);
void device_remove_connection(struct btd_device *device, DBusConnection *conn);
void device_request_disconnect(struct btd_device *device, DBusMessage *msg);

typedef void (*disconnect_watch) (struct btd_device *device, gboolean removal,
					void *user_data);

guint device_add_disconnect_watch(struct btd_device *device,
				disconnect_watch watch, void *user_data,
				GDestroyNotify destroy);
void device_remove_disconnect_watch(struct btd_device *device, guint id);

#define BTD_UUIDS(args...) ((const char *[]) { args, NULL } )

struct btd_device_driver {
	const char *name;
	const char **uuids;
	int (*probe) (struct btd_device *device, GSList *uuids);
	void (*remove) (struct btd_device *device);
};

int btd_register_device_driver(struct btd_device_driver *driver);
void btd_unregister_device_driver(struct btd_device_driver *driver);

struct btd_device *btd_device_ref(struct btd_device *device);
void btd_device_unref(struct btd_device *device);
