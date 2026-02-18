// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2017  Intel Corporation. All rights reserved.
 *
 */

struct btp_adapter {
	struct l_dbus_proxy *proxy;
	struct l_dbus_proxy *ad_proxy;
	uint8_t index;
	uint32_t supported_settings;
	uint32_t current_settings;
	uint32_t default_settings;
	struct l_queue *devices;
};

struct btp_device {
	struct l_dbus_proxy *proxy;
	uint8_t address_type;
	bdaddr_t address;
	struct l_queue *services;
	struct l_queue *characteristics;
	struct l_queue *descriptors;
};

struct btp_agent {
	bool registered;
	struct l_dbus_proxy *proxy;
	struct l_dbus_message *pending_req;
};

struct gatt_attribute {
	struct l_dbus_proxy *proxy;
	uint16_t handle;
	bt_uuid_t uuid;
};

struct l_queue *get_adapters_list(void);
struct btp_adapter *find_adapter_by_proxy(struct l_dbus_proxy *proxy);
struct btp_adapter *find_adapter_by_index(uint8_t index);
struct btp_adapter *find_adapter_by_path(const char *path);
struct btp_device *find_device_by_address(struct btp_adapter *adapter,
							const bdaddr_t *addr,
							uint8_t addr_type);
struct btp_device *find_device_by_path(const char *path);
struct btp_adapter *find_adapter_by_device(struct btp_device *device);
struct btp_device *find_device_by_proxy(struct l_dbus_proxy *proxy);

struct btp_agent *get_agent(void);

bool request_default_agent(l_dbus_client_proxy_result_func_t reply,
						void *user_data,
						l_dbus_destroy_func_t destroy);
