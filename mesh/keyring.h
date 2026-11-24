/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
 *
 *
 */

struct keyring_net_key {
	uint16_t net_idx;
	uint8_t phase;
	uint8_t old_key[16];
	uint8_t new_key[16];
};

struct keyring_app_key {
	uint16_t app_idx;
	uint16_t net_idx;
	uint8_t old_key[16];
	uint8_t new_key[16];
};

bool keyring_put_net_key(struct mesh_node *node, uint16_t net_idx,
					const struct keyring_net_key *key);
bool keyring_get_net_key(struct mesh_node *node, uint16_t net_idx,
						struct keyring_net_key *key);
bool keyring_del_net_key(struct mesh_node *node, uint16_t net_idx);
bool keyring_put_app_key(struct mesh_node *node, uint16_t app_idx,
				uint16_t net_idx, struct keyring_app_key *key);
bool keyring_finalize_app_keys(struct mesh_node *node, uint16_t net_id);
bool keyring_get_app_key(struct mesh_node *node, uint16_t app_idx,
						struct keyring_app_key *key);
bool keyring_del_app_key(struct mesh_node *node, uint16_t app_idx);
bool keyring_get_remote_dev_key(struct mesh_node *node, uint16_t unicast,
							uint8_t dev_key[16]);
bool keyring_put_remote_dev_key(struct mesh_node *node, uint16_t unicast,
				uint8_t count, const uint8_t dev_key[16]);
bool keyring_del_remote_dev_key(struct mesh_node *node, uint16_t unicast,
								uint8_t count);
bool keyring_del_remote_dev_key_all(struct mesh_node *node, uint16_t unicast);
bool keyring_build_export_keys_reply(struct mesh_node *node,
					struct l_dbus_message_builder *builder);
