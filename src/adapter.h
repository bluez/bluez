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
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <dbus/dbus.h>
#include <glib.h>

#define ADAPTER_INTERFACE	"org.bluez.Adapter"

#define MODE_OFF		0x00
#define MODE_CONNECTABLE	0x01
#define MODE_DISCOVERABLE	0x02
#define MODE_UNKNOWN		0xff

/* Discover states */
#define STATE_IDLE		0x00
#define STATE_LE_SCAN		0x01
#define STATE_STDINQ		0x02
#define STATE_PINQ		0x04
#define STATE_RESOLVNAME	0x08
#define STATE_SUSPENDED		0x10

/* Supported host/controller discover type */
#define DISC_LE			0x01
#define DISC_STDINQ		0x02
#define DISC_INTERLEAVE		0x04
#define DISC_PINQ		0x08
#define DISC_RESOLVNAME		0x10

#define MAX_NAME_LENGTH		248

/* Invalid SSP passkey value used to indicate negative replies */
#define INVALID_PASSKEY		0xffffffff

typedef enum {
	NAME_ANY,
	NAME_NOT_REQUIRED, /* used by get remote name without name resolving */
	NAME_REQUIRED,      /* remote name needs be resolved       */
	NAME_REQUESTED,    /* HCI remote name request was sent    */
} name_status_t;

struct btd_adapter;

struct link_key_info {
	bdaddr_t bdaddr;
	unsigned char key[16];
	uint8_t type;
	uint8_t pin_len;
};

struct remote_dev_info {
	bdaddr_t bdaddr;
	int8_t rssi;
	uint32_t class;
	char *name;
	char *alias;
	dbus_bool_t legacy;
	name_status_t name_status;
	gboolean le;
	char **uuids;
	size_t uuid_count;
	GSList *services;
	uint8_t evt_type;
	uint8_t bdaddr_type;
	uint8_t flags;
};

struct hci_dev {
	uint8_t  features[8];
	uint8_t  extfeatures[8];
	uint8_t  lmp_ver;
	uint16_t lmp_subver;
	uint16_t hci_rev;
	uint16_t manufacturer;

	uint8_t  ssp_mode;
	char     name[MAX_NAME_LENGTH + 1];
};

void btd_adapter_start(struct btd_adapter *adapter);

int btd_adapter_stop(struct btd_adapter *adapter);

void btd_adapter_get_mode(struct btd_adapter *adapter, uint8_t *mode,
					uint8_t *on_mode, gboolean *pairable);

int adapter_update_ssp_mode(struct btd_adapter *adapter, uint8_t mode);

struct btd_device *adapter_get_device(DBusConnection *conn,
				struct btd_adapter *adapter, const char *address);

struct btd_device *adapter_find_device(struct btd_adapter *adapter, const char *dest);

void adapter_remove_device(DBusConnection *conn, struct btd_adapter *adapter,
						struct btd_device *device,
						gboolean remove_storage);

int adapter_resolve_names(struct btd_adapter *adapter);

struct btd_adapter *adapter_create(DBusConnection *conn, int id);
gboolean adapter_init(struct btd_adapter *adapter);
void adapter_remove(struct btd_adapter *adapter);
uint16_t adapter_get_dev_id(struct btd_adapter *adapter);
const gchar *adapter_get_path(struct btd_adapter *adapter);
void adapter_get_address(struct btd_adapter *adapter, bdaddr_t *bdaddr);
void adapter_set_state(struct btd_adapter *adapter, int state);
int adapter_get_state(struct btd_adapter *adapter);
int adapter_get_discover_type(struct btd_adapter *adapter);
struct remote_dev_info *adapter_search_found_devices(struct btd_adapter *adapter,
						struct remote_dev_info *match);
void adapter_update_device_from_info(struct btd_adapter *adapter,
					bdaddr_t bdaddr, int8_t rssi,
					uint8_t evt_type, const char *name,
					GSList *services, int flags);
void adapter_update_found_devices(struct btd_adapter *adapter, bdaddr_t *bdaddr,
				int8_t rssi, uint32_t class, const char *name,
				const char *alias, gboolean legacy,
				GSList *services, name_status_t name_status);
int adapter_remove_found_device(struct btd_adapter *adapter, bdaddr_t *bdaddr);
void adapter_emit_device_found(struct btd_adapter *adapter,
						struct remote_dev_info *dev);
void adapter_mode_changed(struct btd_adapter *adapter, uint8_t scan_mode);
void adapter_update_local_name(struct btd_adapter *adapter, const char *name);
void adapter_service_insert(struct btd_adapter *adapter, void *rec);
void adapter_service_remove(struct btd_adapter *adapter, void *rec);
void btd_adapter_class_changed(struct btd_adapter *adapter,
							uint32_t new_class);
void btd_adapter_pairable_changed(struct btd_adapter *adapter,
							gboolean pairable);

struct agent *adapter_get_agent(struct btd_adapter *adapter);
void adapter_add_connection(struct btd_adapter *adapter,
						struct btd_device *device);
void adapter_remove_connection(struct btd_adapter *adapter,
						struct btd_device *device);
gboolean adapter_has_discov_sessions(struct btd_adapter *adapter);
void adapter_suspend_discovery(struct btd_adapter *adapter);
void adapter_resume_discovery(struct btd_adapter *adapter);

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

typedef void (*bt_hci_result_t) (uint8_t status, gpointer user_data);

struct btd_adapter_ops {
	int (*setup) (void);
	void (*cleanup) (void);
	int (*set_powered) (int index, gboolean powered);
	int (*set_discoverable) (int index, gboolean discoverable);
	int (*set_pairable) (int index, gboolean pairable);
	int (*set_limited_discoverable) (int index, gboolean limited);
	int (*start_inquiry) (int index, uint8_t length, gboolean periodic);
	int (*stop_inquiry) (int index);
	int (*start_scanning) (int index);
	int (*stop_scanning) (int index);

	int (*resolve_name) (int index, bdaddr_t *bdaddr);
	int (*cancel_resolve_name) (int index, bdaddr_t *bdaddr);
	int (*set_name) (int index, const char *name);
	int (*set_dev_class) (int index, uint8_t major, uint8_t minor);
	int (*set_fast_connectable) (int index, gboolean enable);
	int (*read_clock) (int index, bdaddr_t *bdaddr, int which, int timeout,
					uint32_t *clock, uint16_t *accuracy);
	int (*read_bdaddr) (int index, bdaddr_t *bdaddr);
	int (*block_device) (int index, bdaddr_t *bdaddr);
	int (*unblock_device) (int index, bdaddr_t *bdaddr);
	int (*get_conn_list) (int index, GSList **conns);
	int (*read_local_version) (int index, struct hci_version *ver);
	int (*read_local_features) (int index, uint8_t *features);
	int (*disconnect) (int index, bdaddr_t *bdaddr);
	int (*remove_bonding) (int index, bdaddr_t *bdaddr);
	int (*pincode_reply) (int index, bdaddr_t *bdaddr, const char *pin);
	int (*confirm_reply) (int index, bdaddr_t *bdaddr, gboolean success);
	int (*passkey_reply) (int index, bdaddr_t *bdaddr, uint32_t passkey);
	int (*enable_le) (int index);
	int (*encrypt_link) (int index, bdaddr_t *bdaddr, bt_hci_result_t cb,
							gpointer user_data);
	int (*set_did) (int index, uint16_t vendor, uint16_t product,
							uint16_t version);
	int (*add_uuid) (int index, uuid_t *uuid, uint8_t svc_hint);
	int (*remove_uuid) (int index, uuid_t *uuid);
	int (*disable_cod_cache) (int index);
	int (*restore_powered) (int index);
	int (*load_keys) (int index, GSList *keys, gboolean debug_keys);
	int (*set_io_capability) (int index, uint8_t io_capability);
	int (*create_bonding) (int index, bdaddr_t *bdaddr, uint8_t io_cap);
	int (*cancel_bonding) (int index, bdaddr_t *bdaddr);
	int (*read_local_oob_data) (int index);
	int (*add_remote_oob_data) (int index, bdaddr_t *bdaddr, uint8_t *hash,
							uint8_t *randomizer);
	int (*remove_remote_oob_data) (int index, bdaddr_t *bdaddr);
};

int btd_register_adapter_ops(struct btd_adapter_ops *ops, gboolean priority);
void btd_adapter_cleanup_ops(struct btd_adapter_ops *btd_adapter_ops);
int adapter_ops_setup(void);

typedef void (*btd_adapter_powered_cb) (struct btd_adapter *adapter,
						gboolean powered);
void btd_adapter_register_powered_callback(struct btd_adapter *adapter,
						btd_adapter_powered_cb cb);
void btd_adapter_unregister_powered_callback(struct btd_adapter *adapter,
						btd_adapter_powered_cb cb);

/* If TRUE, enables fast connectabe, i.e. reduces page scan interval and changes
 * type. If FALSE, disables fast connectable, i.e. sets page scan interval and
 * type to default values. Valid for both connectable and discoverable modes. */
int btd_adapter_set_fast_connectable(struct btd_adapter *adapter,
							gboolean enable);

int btd_adapter_read_clock(struct btd_adapter *adapter, bdaddr_t *bdaddr,
				int which, int timeout, uint32_t *clock,
				uint16_t *accuracy);

int btd_adapter_block_address(struct btd_adapter *adapter, bdaddr_t *bdaddr);
int btd_adapter_unblock_address(struct btd_adapter *adapter, bdaddr_t *bdaddr);

int btd_adapter_disconnect_device(struct btd_adapter *adapter,
							bdaddr_t *bdaddr);

int btd_adapter_remove_bonding(struct btd_adapter *adapter, bdaddr_t *bdaddr);

int btd_adapter_pincode_reply(struct btd_adapter *adapter, bdaddr_t *bdaddr,
							const char *pin);
int btd_adapter_confirm_reply(struct btd_adapter *adapter, bdaddr_t *bdaddr,
							gboolean success);
int btd_adapter_passkey_reply(struct btd_adapter *adapter, bdaddr_t *bdaddr,
							uint32_t passkey);

void btd_adapter_update_local_ext_features(struct btd_adapter *adapter,
						const uint8_t *features);

int btd_adapter_encrypt_link(struct btd_adapter *adapter, bdaddr_t *bdaddr,
				bt_hci_result_t cb, gpointer user_data);

int btd_adapter_set_did(struct btd_adapter *adapter, uint16_t vendor,
					uint16_t product, uint16_t version);

int adapter_create_bonding(struct btd_adapter *adapter, bdaddr_t *bdaddr,
							uint8_t io_cap);

int adapter_cancel_bonding(struct btd_adapter *adapter, bdaddr_t *bdaddr);

int btd_adapter_read_local_oob_data(struct btd_adapter *adapter);

int btd_adapter_add_remote_oob_data(struct btd_adapter *adapter,
			bdaddr_t *bdaddr, uint8_t *hash, uint8_t *randomizer);

int btd_adapter_remove_remote_oob_data(struct btd_adapter *adapter,
							bdaddr_t *bdaddr);
