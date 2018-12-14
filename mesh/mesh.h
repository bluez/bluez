/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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
#define MESH_ELEMENT_INTERFACE "org.bluez.mesh.Element1"
#define MESH_APPLICATION_INTERFACE "org.bluez.mesh.Application1"
#define MESH_PROVISION_AGENT_INTERFACE "org.bluez.mesh.ProvisionAgent1"
#define ERROR_INTERFACE "org.bluez.mesh.Error"

typedef void (*prov_rx_cb_t)(void *user_data, const uint8_t *data,
								uint16_t len);
bool mesh_init(uint16_t index, const char *in_config_name);
void mesh_cleanup(void);
bool mesh_dbus_init(struct l_dbus *dbus);

const char *mesh_status_str(uint8_t err);
bool mesh_send_pkt(uint8_t count, uint16_t interval, uint8_t *data,
								uint16_t len);
bool mesh_send_cancel(const uint8_t *filter, uint8_t len);
bool mesh_reg_prov_rx(prov_rx_cb_t cb, void *user_data);
void mesh_unreg_prov_rx(prov_rx_cb_t cb);
