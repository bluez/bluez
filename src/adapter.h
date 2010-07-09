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

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <dbus/dbus.h>
#include <glib.h>

#define ADAPTER_INTERFACE	"org.bluez.Adapter"

/* Discover types */
#define DISCOVER_TYPE_NONE	0x00
#define STD_INQUIRY		0x01
#define PERIODIC_INQUIRY	0x02

/* Actions executed after inquiry complete */
#define RESOLVE_NAME		0x10

#define MAX_NAME_LENGTH		248

typedef enum {
	NAME_ANY,
	NAME_NOT_REQUIRED, /* used by get remote name without name resolving */
	NAME_REQUIRED,      /* remote name needs be resolved       */
	NAME_REQUESTED,    /* HCI remote name request was sent    */
	NAME_SENT          /* D-Bus signal RemoteNameUpdated sent */
} name_status_t;

struct btd_adapter;

struct remote_dev_info {
	bdaddr_t bdaddr;
	int8_t rssi;
	uint32_t class;
	char *name;
	char *alias;
	dbus_bool_t legacy;
	name_status_t name_status;
};

struct hci_dev {
	int ignore;

	uint8_t  features[8];
	uint8_t  lmp_ver;
	uint16_t lmp_subver;
	uint16_t hci_rev;
	uint16_t manufacturer;

	uint8_t  ssp_mode;
	uint8_t  name[MAX_NAME_LENGTH];
};

int adapter_start(struct btd_adapter *adapter);

int adapter_stop(struct btd_adapter *adapter);

int adapter_update(struct btd_adapter *adapter, uint8_t cls);

int adapter_update_ssp_mode(struct btd_adapter *adapter, uint8_t mode);

struct btd_device *adapter_get_device(DBusConnection *conn,
				struct btd_adapter *adapter, const char *address);

struct btd_device *adapter_find_device(struct btd_adapter *adapter, const char *dest);

struct btd_device *adapter_find_connection(struct btd_adapter *adapter, uint16_t handle);

void adapter_remove_device(DBusConnection *conn, struct btd_adapter *adapter,
						struct btd_device *device,
						gboolean remove_storage);
struct btd_device *adapter_create_device(DBusConnection *conn,
				struct btd_adapter *adapter, const char *address);

int pending_remote_name_cancel(struct btd_adapter *adapter);

int adapter_resolve_names(struct btd_adapter *adapter);

void clear_found_devices_list(struct btd_adapter *adapter);

struct btd_adapter *adapter_create(DBusConnection *conn, int id,
				gboolean devup);
void adapter_remove(struct btd_adapter *adapter);
uint16_t adapter_get_dev_id(struct btd_adapter *adapter);
const gchar *adapter_get_path(struct btd_adapter *adapter);
void adapter_get_address(struct btd_adapter *adapter, bdaddr_t *bdaddr);
void adapter_set_state(struct btd_adapter *adapter, int state);
int adapter_get_state(struct btd_adapter *adapter);
gboolean adapter_is_ready(struct btd_adapter *adapter);
struct remote_dev_info *adapter_search_found_devices(struct btd_adapter *adapter,
						struct remote_dev_info *match);
void adapter_update_found_devices(struct btd_adapter *adapter, bdaddr_t *bdaddr,
				int8_t rssi, uint32_t class, const char *name,
				const char *alias, gboolean legacy,
				name_status_t name_status);
int adapter_remove_found_device(struct btd_adapter *adapter, bdaddr_t *bdaddr);
void adapter_emit_device_found(struct btd_adapter *adapter,
				struct remote_dev_info *dev);
void adapter_update_oor_devices(struct btd_adapter *adapter);
void adapter_mode_changed(struct btd_adapter *adapter, uint8_t scan_mode);
void adapter_setname_complete(bdaddr_t *local, uint8_t status);
void adapter_update_tx_power(bdaddr_t *bdaddr, uint8_t status, void *ptr);
void adapter_update_local_name(bdaddr_t *bdaddr, uint8_t status, void *ptr);
void adapter_service_insert(const bdaddr_t *bdaddr, void *rec);
void adapter_service_remove(const bdaddr_t *bdaddr, void *rec);
sdp_list_t *adapter_get_services(struct btd_adapter *adapter);
void adapter_set_class_complete(bdaddr_t *bdaddr, uint8_t status);

struct agent *adapter_get_agent(struct btd_adapter *adapter);
void adapter_add_connection(struct btd_adapter *adapter,
				struct btd_device *device, uint16_t handle);
void adapter_remove_connection(struct btd_adapter *adapter,
				struct btd_device *device, uint16_t handle);
gboolean adapter_has_discov_sessions(struct btd_adapter *adapter);

struct btd_adapter *btd_adapter_ref(struct btd_adapter *adapter);
void btd_adapter_unref(struct btd_adapter *adapter);

int btd_adapter_set_class(struct btd_adapter *adapter, uint8_t major,
							uint8_t minor);


struct btd_adapter_driver {
	const char *name;
	int (*probe) (struct btd_adapter *adapter);
	void (*remove) (struct btd_adapter *adapter);
};

typedef void (*service_auth_cb) (DBusError *derr, void *user_data);

int btd_register_adapter_driver(struct btd_adapter_driver *driver);
void btd_unregister_adapter_driver(struct btd_adapter_driver *driver);
int btd_request_authorization(const bdaddr_t *src, const bdaddr_t *dst,
		const char *uuid, service_auth_cb cb, void *user_data);
int btd_cancel_authorization(const bdaddr_t *src, const bdaddr_t *dst);

const char *adapter_any_get_path(void);

const char *btd_adapter_any_request_path(void);
void btd_adapter_any_release_path(void);
gboolean adapter_is_pairable(struct btd_adapter *adapter);
gboolean adapter_powering_down(struct btd_adapter *adapter);

int btd_adapter_restore_powered(struct btd_adapter *adapter);
int btd_adapter_switch_online(struct btd_adapter *adapter);
int btd_adapter_switch_offline(struct btd_adapter *adapter);

struct btd_adapter_ops {
	int (*setup) (void);
	void (*cleanup) (void);
	int (*start) (int index);
	int (*stop) (int index);
	int (*set_powered) (int index, gboolean powered);
	int (*set_connectable) (int index);
	int (*set_discoverable) (int index);
	int (*set_limited_discoverable) (int index, uint32_t class,
						gboolean limited);
	int (*start_discovery) (int index, gboolean periodic);
	int (*stop_discovery) (int index);
	int (*resolve_name) (int index, bdaddr_t *bdaddr);
	int (*cancel_resolve_name) (int index, bdaddr_t *bdaddr);
	int (*set_name) (int index, const char *name);
	int (*read_name) (int index);
	int (*set_class) (int index, uint32_t class);
};

int btd_register_adapter_ops(struct btd_adapter_ops *btd_adapter_ops);
void btd_adapter_cleanup_ops(struct btd_adapter_ops *btd_adapter_ops);
int adapter_ops_setup(void);
