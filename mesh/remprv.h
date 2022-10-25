/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2023  Intel Corporation. All rights reserved.
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

#define REM_PROV_SRV_MODEL	SET_ID(SIG_VENDOR, 0x0004)
#define REM_PROV_CLI_MODEL	SET_ID(SIG_VENDOR, 0x0005)

#define PB_REMOTE_MAX_SCAN_QUEUE_SIZE	5

#define PB_REMOTE_STATE_IDLE		0x00
#define PB_REMOTE_STATE_LINK_OPENING	0x01
#define PB_REMOTE_STATE_LINK_ACTIVE	0x02
#define PB_REMOTE_STATE_OB_PKT_TX	0x03
#define PB_REMOTE_STATE_LINK_CLOSING	0x04

#define PB_REMOTE_TYPE_LOCAL	0x01
#define PB_REMOTE_TYPE_ADV	0x02
#define PB_REMOTE_TYPE_GATT	0x04

#define PB_REMOTE_SCAN_TYPE_NONE	0x00
#define PB_REMOTE_SCAN_TYPE_UNLIMITED	0x01
#define PB_REMOTE_SCAN_TYPE_LIMITED	0x02
#define PB_REMOTE_SCAN_TYPE_DETAILED	0x03

/* Remote Provisioning Opcode List */
#define OP_REM_PROV_SCAN_CAP_GET	0x804F
#define OP_REM_PROV_SCAN_CAP_STATUS	0x8050
#define OP_REM_PROV_SCAN_GET		0x8051
#define OP_REM_PROV_SCAN_START		0x8052
#define OP_REM_PROV_SCAN_STOP		0x8053
#define OP_REM_PROV_SCAN_STATUS		0x8054
#define OP_REM_PROV_SCAN_REPORT		0x8055
#define OP_REM_PROV_EXT_SCAN_START	0x8056
#define OP_REM_PROV_EXT_SCAN_REPORT	0x8057
#define OP_REM_PROV_LINK_GET		0x8058
#define OP_REM_PROV_LINK_OPEN		0x8059
#define OP_REM_PROV_LINK_CLOSE		0x805A
#define OP_REM_PROV_LINK_STATUS		0x805B
#define OP_REM_PROV_LINK_REPORT		0x805C
#define OP_REM_PROV_PDU_SEND		0x805D
#define OP_REM_PROV_PDU_OB_REPORT	0x805E
#define OP_REM_PROV_PDU_REPORT		0x805F

/* Remote Provisioning Errors */
#define PB_REM_ERR_SUCCESS			0x00
#define PB_REM_ERR_SCANNING_CANNOT_START	0x01
#define PB_REM_ERR_INVALID_STATE		0x02
#define PB_REM_ERR_LIMITED_RESOURCES		0x03
#define PB_REM_ERR_CANNOT_OPEN			0x04
#define PB_REM_ERR_OPEN_FAILED			0x05
#define PB_REM_ERR_CLOSED_BY_DEVICE		0x06
#define PB_REM_ERR_CLOSED_BY_SERVER		0x07
#define PB_REM_ERR_CLOSED_BY_CLIENT		0x08
#define PB_REM_ERR_CLOSED_CANNOT_RX_PDU		0x09
#define PB_REM_ERR_CLOSED_CANNOT_TX_PDU		0x0A

void remote_prov_server_init(struct mesh_node *node, uint8_t ele_idx);
void remote_prov_client_init(struct mesh_node *node, uint8_t ele_idx);
bool register_nppi_acceptor(mesh_prov_open_func_t open_cb,
					mesh_prov_close_func_t close_cb,
					mesh_prov_receive_func_t rx_cb,
					mesh_prov_ack_func_t ack_cb,
					void *user_data);
