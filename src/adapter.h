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
#include <stdbool.h>

#define ADAPTER_INTERFACE	"org.bluez.Adapter1"

#define MAX_NAME_LENGTH		248

/* Invalid SSP passkey value used to indicate negative replies */
#define INVALID_PASSKEY		0xffffffff

struct btd_adapter;

typedef void (*oob_read_local_cb_t) (struct btd_adapter *adapter,
					uint8_t *hash, uint8_t *randomizer,
					void *user_data);
typedef void (*oob_bonding_cb_t) (struct btd_adapter *adapter,
					const bdaddr_t *bdaddr, uint8_t status,
					void *user_data);

struct oob_handler {
	oob_read_local_cb_t read_local_cb;
	oob_bonding_cb_t bonding_cb;
	bdaddr_t remote_addr;
	void *user_data;
};

struct link_key_info {
	bdaddr_t bdaddr;
	unsigned char key[16];
	uint8_t type;
	uint8_t pin_len;
};

struct smp_ltk_info {
	bdaddr_t bdaddr;
	uint8_t bdaddr_type;
	uint8_t authenticated;
	uint8_t master;
	uint8_t enc_size;
	uint16_t ediv;
	uint8_t rand[8];
	uint8_t val[16];
};

void adapter_cleanup(void);
struct btd_adapter *adapter_find(const bdaddr_t *sba);

void btd_adapter_start(struct btd_adapter *adapter);

int btd_adapter_stop(struct btd_adapter *adapter);

bool btd_adapter_get_pairable(struct btd_adapter *adapter);

void btd_adapter_get_major_minor(struct btd_adapter *adapter, uint8_t *major,
							uint8_t *minor);

uint32_t btd_adapter_get_class(struct btd_adapter *adapter);
const char *btd_adapter_get_name(struct btd_adapter *adapter);
struct btd_device *adapter_get_device(struct btd_adapter *adapter,
				const gchar *address, uint8_t addr_type);
sdp_list_t *btd_adapter_get_services(struct btd_adapter *adapter);

struct btd_device *adapter_find_device(struct btd_adapter *adapter, const char *dest);

void adapter_remove_device(struct btd_adapter *adapter,
						struct btd_device *device,
						gboolean remove_storage);

struct btd_adapter *adapter_create(int id);
gboolean adapter_setup(struct btd_adapter *adapter, gboolean powered,
					bool connectable, bool discoverable);
void adapter_remove(struct btd_adapter *adapter);
void adapter_set_discovering(struct btd_adapter *adapter,
						gboolean discovering);
uint16_t adapter_get_dev_id(struct btd_adapter *adapter);
const gchar *adapter_get_path(struct btd_adapter *adapter);
const bdaddr_t *adapter_get_address(struct btd_adapter *adapter);
void adapter_update_found_devices(struct btd_adapter *adapter,
					const bdaddr_t *bdaddr,
					uint8_t bdaddr_type, int8_t rssi,
					bool confirm_name, bool legacy,
					uint8_t *data, uint8_t data_len);
void adapter_update_connectable(struct btd_adapter *adapter, bool connectable);
void adapter_update_discoverable(struct btd_adapter *adapter,
							bool discoverable);
int adapter_set_name(struct btd_adapter *adapter, const char *name);
void adapter_name_changed(struct btd_adapter *adapter, const char *name);
void adapter_service_insert(struct btd_adapter *adapter, void *rec);
void adapter_service_remove(struct btd_adapter *adapter, void *rec);
void btd_adapter_class_changed(struct btd_adapter *adapter,
							uint8_t *new_class);
void adapter_update_pairable(struct btd_adapter *adapter, bool pairable);

struct agent *adapter_get_agent(struct btd_adapter *adapter);
void adapter_add_connection(struct btd_adapter *adapter,
						struct btd_device *device);
void adapter_remove_connection(struct btd_adapter *adapter,
						struct btd_device *device);

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

void adapter_add_profile(struct btd_adapter *adapter, gpointer p);
void adapter_remove_profile(struct btd_adapter *adapter, gpointer p);
int btd_register_adapter_driver(struct btd_adapter_driver *driver);
void btd_unregister_adapter_driver(struct btd_adapter_driver *driver);
guint btd_request_authorization(const bdaddr_t *src, const bdaddr_t *dst,
		const char *uuid, service_auth_cb cb, void *user_data);
int btd_cancel_authorization(guint id);

int btd_adapter_restore_powered(struct btd_adapter *adapter);

typedef ssize_t (*btd_adapter_pin_cb_t) (struct btd_adapter *adapter,
			struct btd_device *dev, char *out, gboolean *display);
void btd_adapter_register_pin_cb(struct btd_adapter *adapter,
						btd_adapter_pin_cb_t cb);
void btd_adapter_unregister_pin_cb(struct btd_adapter *adapter,
						btd_adapter_pin_cb_t cb);
ssize_t btd_adapter_get_pin(struct btd_adapter *adapter, struct btd_device *dev,
					char *pin_buf, gboolean *display);

/* If TRUE, enables fast connectabe, i.e. reduces page scan interval and changes
 * type. If FALSE, disables fast connectable, i.e. sets page scan interval and
 * type to default values. Valid for both connectable and discoverable modes. */
int btd_adapter_set_fast_connectable(struct btd_adapter *adapter,
							gboolean enable);

int btd_adapter_read_clock(struct btd_adapter *adapter, const bdaddr_t *bdaddr,
				int which, int timeout, uint32_t *clock,
				uint16_t *accuracy);

int btd_adapter_block_address(struct btd_adapter *adapter,
				const bdaddr_t *bdaddr, uint8_t bdaddr_type);
int btd_adapter_unblock_address(struct btd_adapter *adapter,
				const bdaddr_t *bdaddr, uint8_t bdaddr_type);

int btd_adapter_disconnect_device(struct btd_adapter *adapter,
							const bdaddr_t *bdaddr,
							uint8_t bdaddr_type);

int btd_adapter_remove_bonding(struct btd_adapter *adapter,
				const bdaddr_t *bdaddr, uint8_t bdaddr_type);

int btd_adapter_pincode_reply(struct btd_adapter *adapter,
					const  bdaddr_t *bdaddr,
					const char *pin, size_t pin_len);
int btd_adapter_confirm_reply(struct btd_adapter *adapter,
				const bdaddr_t *bdaddr, uint8_t bdaddr_type,
				gboolean success);
int btd_adapter_passkey_reply(struct btd_adapter *adapter,
				const bdaddr_t *bdaddr, uint8_t bdaddr_type,
				uint32_t passkey);

int btd_adapter_set_did(struct btd_adapter *adapter, uint16_t vendor,
					uint16_t product, uint16_t version,
					uint16_t source);

int adapter_create_bonding(struct btd_adapter *adapter, const bdaddr_t *bdaddr,
					uint8_t addr_type, uint8_t io_cap);

int adapter_cancel_bonding(struct btd_adapter *adapter, const bdaddr_t *bdaddr,
							uint8_t addr_type);

void adapter_bonding_complete(struct btd_adapter *adapter,
					const bdaddr_t *bdaddr,
					uint8_t addr_type, uint8_t status);

int adapter_set_io_capability(struct btd_adapter *adapter, uint8_t io_cap);

int btd_adapter_read_local_oob_data(struct btd_adapter *adapter);
void adapter_read_local_oob_data_complete(struct btd_adapter *adapter,
					uint8_t *hash, uint8_t *randomizer);

int btd_adapter_add_remote_oob_data(struct btd_adapter *adapter,
					const bdaddr_t *bdaddr,
					uint8_t *hash, uint8_t *randomizer);

int btd_adapter_remove_remote_oob_data(struct btd_adapter *adapter,
							const bdaddr_t *bdaddr);

int btd_adapter_gatt_server_start(struct btd_adapter *adapter);
void btd_adapter_gatt_server_stop(struct btd_adapter *adapter);

int btd_adapter_ssp_enabled(struct btd_adapter *adapter);

void adapter_connect_list_add(struct btd_adapter *adapter,
						struct btd_device *device);
void adapter_connect_list_remove(struct btd_adapter *adapter,
						struct btd_device *device);

void btd_adapter_set_oob_handler(struct btd_adapter *adapter,
						struct oob_handler *handler);
gboolean btd_adapter_check_oob_handler(struct btd_adapter *adapter);
void adapter_store_cached_name(const bdaddr_t *local, const bdaddr_t *peer,
							const char *name);

void btd_adapter_for_each_device(struct btd_adapter *adapter,
			void (*cb)(struct btd_device *device, void *data),
			void *data);
