/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 */

#define BLUEZ_MESH_NAME "org.bluez.mesh"

#define MESH_NETWORK_INTERFACE "org.bluez.mesh.Network1"
#define MESH_NODE_INTERFACE "org.bluez.mesh.Node1"
#define MESH_MANAGEMENT_INTERFACE "org.bluez.mesh.Management1"
#define MESH_ELEMENT_INTERFACE "org.bluez.mesh.Element1"
#define MESH_APPLICATION_INTERFACE "org.bluez.mesh.Application1"
#define MESH_PROVISION_AGENT_INTERFACE "org.bluez.mesh.ProvisionAgent1"
#define MESH_PROVISIONER_INTERFACE "org.bluez.mesh.Provisioner1"
#define ERROR_INTERFACE "org.bluez.mesh.Error"

enum mesh_io_type;

typedef void (*mesh_ready_func_t)(void *user_data, bool success);
typedef void (*prov_rx_cb_t)(void *user_data, const uint8_t *data,
								uint16_t len);

bool mesh_init(const char *config_dir, const char *mesh_conf_fname,
					enum mesh_io_type type, void *opts,
					mesh_ready_func_t cb, void *user_data);
void mesh_cleanup(void);
bool mesh_dbus_init(struct l_dbus *dbus);

const char *mesh_status_str(uint8_t err);
bool mesh_send_pkt(uint8_t count, uint16_t interval, void *data, uint16_t len);
bool mesh_send_cancel(const uint8_t *filter, uint8_t len);
bool mesh_reg_prov_rx(prov_rx_cb_t cb, void *user_data);
void mesh_unreg_prov_rx(prov_rx_cb_t cb);
const char *mesh_prov_status_str(uint8_t status);
const char *mesh_get_storage_dir(void);
bool mesh_beacon_enabled(void);
bool mesh_relay_supported(void);
bool mesh_friendship_supported(void);
uint16_t mesh_get_crpl(void);
uint8_t mesh_get_friend_queue_size(void);
