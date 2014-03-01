/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#include "src/shared/util.h"
#include "src/shared/crypto.h"
#include "monitor/mainloop.h"
#include "monitor/bt.h"

#include "le.h"

#define WHITE_LIST_SIZE  16

struct bt_le {
	volatile int ref_count;
	int vhci_fd;
	struct bt_crypto *crypto;

	uint8_t  event_mask[16];
	uint16_t manufacturer;
	uint8_t  commands[64];
	uint8_t  features[8];
	uint8_t  bdaddr[6];

	uint8_t  le_event_mask[8];
	uint16_t le_mtu;
	uint8_t  le_max_pkt;
	uint8_t  le_features[8];
	uint8_t  le_random_addr[6];
	uint16_t le_adv_min_interval;
	uint16_t le_adv_max_interval;
	uint8_t  le_adv_type;
	uint8_t  le_adv_own_addr_type;
	uint8_t  le_adv_direct_addr_type;
	uint8_t  le_adv_direct_addr[6];
	uint8_t  le_adv_channel_map;
	uint8_t  le_adv_filter_policy;
	int8_t   le_adv_tx_power;
	uint8_t  le_adv_data_len;
	uint8_t  le_adv_data[31];
	uint8_t  le_scan_rsp_data_len;
	uint8_t  le_scan_rsp_data[31];
	uint8_t  le_adv_enable;

	uint8_t  le_white_list_size;
	uint8_t  le_states[8];
};

static void reset_defaults(struct bt_le *hci)
{
	memset(hci->event_mask, 0, sizeof(hci->event_mask));
	hci->event_mask[0] |= 0x10;	/* Disconnection Complete */
	hci->event_mask[0] |= 0x80;	/* Encryption Change */
	hci->event_mask[1] |= 0x08;	/* Read Remote Version Information Complete */
	hci->event_mask[1] |= 0x20;	/* Command Complete */
	hci->event_mask[1] |= 0x40;	/* Command Status */
	hci->event_mask[1] |= 0x80;	/* Hardware Error */
	hci->event_mask[2] |= 0x04;	/* Number of Completed Packets */
	hci->event_mask[3] |= 0x02;	/* Data Buffer Overflow */
	hci->event_mask[5] |= 0x80;	/* Encryption Key Refresh Complete */

	hci->manufacturer = 0x003f;	/* Bluetooth SIG (63) */

	memset(hci->commands, 0, sizeof(hci->commands));
	//hci->commands[0]  |= 0x20;	/* Disconnect */
	//hci->commands[2]  |= 0x80;	/* Read Remote Version Information */
	hci->commands[5]  |= 0x40;	/* Set Event Mask */
	hci->commands[5]  |= 0x80;	/* Reset */
	//hci->commands[10] |= 0x04;	/* Read Transmit Power Level */
	hci->commands[14] |= 0x08;	/* Read Local Version Information */
	hci->commands[14] |= 0x10;	/* Read Local Supported Commands */
	hci->commands[14] |= 0x20;	/* Read Local Supported Features */
	hci->commands[14] |= 0x80;	/* Read Buffer Size */
	hci->commands[15] |= 0x02;	/* Read BD ADDR */
	//hci->commands[15] |= 0x20;	/* Read RSSI */
	hci->commands[25] |= 0x01;	/* LE Set Event Mask */
	hci->commands[25] |= 0x02;	/* LE Read Buffer Size */
	hci->commands[25] |= 0x04;	/* LE Read Local Supported Features */
	hci->commands[25] |= 0x10;	/* LE Set Random Address */
	hci->commands[25] |= 0x20;	/* LE Set Advertising Parameters */
	hci->commands[25] |= 0x40;	/* LE Read Advertising Channel TX Power */
	hci->commands[25] |= 0x80;	/* LE Set Advertising Data */
	hci->commands[26] |= 0x01;	/* LE Set Scan Response Data */
	hci->commands[26] |= 0x02;	/* LE Set Advertise Enable */
	//hci->commands[26] |= 0x04;	/* LE Set Scan Parameters */
	//hci->commands[26] |= 0x08;	/* LE Set Scan Enable */
	//hci->commands[26] |= 0x10;	/* LE Create Connection */
	//hci->commands[26] |= 0x20;	/* LE Create Connection Cancel */
	hci->commands[26] |= 0x40;	/* LE Read White List Size */
	hci->commands[26] |= 0x80;	/* LE Clear White List */
	//hci->commands[27] |= 0x01;	/* LE Add Device To White List */
	//hci->commands[27] |= 0x02;	/* LE Remove Device From White List */
	//hci->commands[27] |= 0x04;	/* LE Connection Update */
	//hci->commands[27] |= 0x08;	/* LE Set Host Channel Classification */
	//hci->commands[27] |= 0x10;	/* LE Read Channel Map */
	//hci->commands[27] |= 0x20;	/* LE Read Remote Used Features */
	hci->commands[27] |= 0x40;	/* LE Encrypt */
	hci->commands[27] |= 0x80;	/* LE Rand */
	//hci->commands[28] |= 0x01;	/* LE Start Encryption */
	//hci->commands[28] |= 0x02;	/* LE Long Term Key Request Reply */
	//hci->commands[28] |= 0x04;	/* LE Long Term Key Request Negative Reply */
	hci->commands[28] |= 0x08;	/* LE Read Supported States */
	//hci->commands[28] |= 0x10;	/* LE Receiver Test */
	//hci->commands[28] |= 0x20;	/* LE Transmitter Test */
	//hci->commands[28] |= 0x40;	/* LE Test End */
	//hci->commands[33] |= 0x10;	/* LE Remote Connection Parameter Request Reply */
	//hci->commands[33] |= 0x20;	/* LE Remote Connection Parameter Request Negative Reply */

	memset(hci->features, 0, sizeof(hci->features));
	hci->features[4] |= 0x20;	/* BR/EDR Not Supported */
	hci->features[4] |= 0x40;	/* LE Supported */

	memset(hci->bdaddr, 0, sizeof(hci->bdaddr));

	memset(hci->le_event_mask, 0, sizeof(hci->le_event_mask));
	hci->le_event_mask[0] |= 0x01;	/* LE Connection Complete */
	hci->le_event_mask[0] |= 0x02;	/* LE Advertising Report */
	hci->le_event_mask[0] |= 0x04;	/* LE Connection Update Complete */
	hci->le_event_mask[0] |= 0x08;	/* LE Read Remote Used Features Complete */
	hci->le_event_mask[0] |= 0x10;	/* LE Long Term Key Request */
	//hci->le_event_mask[0] |= 0x20;	/* LE Remote Connection Parameter Request */

	hci->le_mtu = 64;
	hci->le_max_pkt = 1;

	memset(hci->le_features, 0, sizeof(hci->le_features));
	hci->le_features[0] |= 0x01;	/* LE Encryption */
	//hci->le_features[0] |= 0x02;	/* Connection Parameter Request Procedure */
	//hci->le_features[0] |= 0x04;	/* Extended Reject Indication */
	//hci->le_features[0] |= 0x08;	/* Slave-initiated Features Exchange */
	//hci->le_features[0] |= 0x10;	/* LE Ping */

	memset(hci->le_random_addr, 0, sizeof(hci->le_random_addr));

	hci->le_adv_min_interval = 0x0800;
	hci->le_adv_max_interval = 0x0800;
	hci->le_adv_type = 0x00;
	hci->le_adv_own_addr_type = 0x00;
	hci->le_adv_direct_addr_type = 0x00;
	memset(hci->le_adv_direct_addr, 0, 6);
	hci->le_adv_channel_map = 0x07;
	hci->le_adv_filter_policy = 0x00;

	hci->le_adv_tx_power = 0;

	memset(hci->le_adv_data, 0, sizeof(hci->le_adv_data));
	hci->le_adv_data_len = 0;

	memset(hci->le_scan_rsp_data, 0, sizeof(hci->le_scan_rsp_data));
	hci->le_scan_rsp_data_len = 0;

	hci->le_adv_enable = 0x00;

	hci->le_white_list_size = WHITE_LIST_SIZE;

	memset(hci->le_states, 0, sizeof(hci->le_states));
	hci->le_states[0] |= 0x01;	/* Non-connectable Advertising */
	hci->le_states[0] |= 0x02;	/* Scannable Advertising */
	hci->le_states[0] |= 0x04;	/* Connectable Advertising */
	hci->le_states[0] |= 0x08;	/* Directed Advertising */
	hci->le_states[0] |= 0x10;	/* Passive Scanning */
	hci->le_states[0] |= 0x20;	/* Active Scanning */
	hci->le_states[0] |= 0x40;	/* Initiating */
	hci->le_states[0] |= 0x80;	/* Connection */
}

static void send_event(struct bt_le *hci, uint8_t event,
						void *data, uint8_t size)
{
	uint8_t type = BT_H4_EVT_PKT;
	struct bt_hci_evt_hdr hdr;
	struct iovec iov[3];
	int iovcnt;

	hdr.evt  = event;
	hdr.plen = size;

	iov[0].iov_base = &type;
	iov[0].iov_len  = 1;
	iov[1].iov_base = &hdr;
	iov[1].iov_len  = sizeof(hdr);

	if (size > 0) {
		iov[2].iov_base = data;
		iov[2].iov_len  = size;
		iovcnt = 3;
	} else
		iovcnt = 2;

	if (writev(hci->vhci_fd, iov, iovcnt) < 0)
		fprintf(stderr, "Write to /dev/vhci failed (%m)\n");
}

static void cmd_complete(struct bt_le *hci, uint16_t opcode,
						const void *data, uint8_t len)
{
	struct bt_hci_evt_cmd_complete *cc;
	void *pkt_data;

	pkt_data = alloca(sizeof(*cc) + len);
	if (!pkt_data)
		return;

	cc = pkt_data;
	cc->ncmd = 0x01;
	cc->opcode = cpu_to_le16(opcode);

	if (len > 0)
		memcpy(pkt_data + sizeof(*cc), data, len);

	send_event(hci, BT_HCI_EVT_CMD_COMPLETE, pkt_data, sizeof(*cc) + len);
}

static void cmd_status(struct bt_le *hci, uint8_t status, uint16_t opcode)
{
	struct bt_hci_evt_cmd_status cs;

	cs.status = status;
	cs.ncmd = 0x01;
	cs.opcode = cpu_to_le16(opcode);

	send_event(hci, BT_HCI_EVT_CMD_STATUS, &cs, sizeof(cs));
}

static void cmd_set_event_mask(struct bt_le *hci,
						const void *data, uint8_t size)
{
	const struct bt_hci_cmd_set_event_mask *cmd = data;
	uint8_t status;

	memcpy(hci->event_mask, cmd->mask, 8);

	status = BT_HCI_ERR_SUCCESS;
	cmd_complete(hci, BT_HCI_CMD_SET_EVENT_MASK, &status, sizeof(status));
}

static void cmd_reset(struct bt_le *hci, const void *data, uint8_t size)
{
	uint8_t status;

	reset_defaults(hci);

	status = BT_HCI_ERR_SUCCESS;
	cmd_complete(hci, BT_HCI_CMD_RESET, &status, sizeof(status));
}

static void cmd_read_local_version(struct bt_le *hci,
						const void *data, uint8_t size)
{
	struct bt_hci_rsp_read_local_version rsp;

	rsp.status = BT_HCI_ERR_SUCCESS;
	rsp.hci_ver = 0x06;
	rsp.hci_rev = cpu_to_le16(0x0000);
	rsp.lmp_ver = 0x06;
	rsp.manufacturer = cpu_to_le16(hci->manufacturer);
	rsp.lmp_subver = cpu_to_le16(0x0000);

	cmd_complete(hci, BT_HCI_CMD_READ_LOCAL_VERSION, &rsp, sizeof(rsp));
}

static void cmd_read_local_commands(struct bt_le *hci,
						const void *data, uint8_t size)
{
	struct bt_hci_rsp_read_local_commands rsp;

	rsp.status = BT_HCI_ERR_SUCCESS;
	memcpy(rsp.commands, hci->commands, 64);

	cmd_complete(hci, BT_HCI_CMD_READ_LOCAL_COMMANDS, &rsp, sizeof(rsp));
}

static void cmd_read_local_features(struct bt_le *hci,
						const void *data, uint8_t size)
{
	struct bt_hci_rsp_read_local_features rsp;

	rsp.status = BT_HCI_ERR_SUCCESS;
	memcpy(rsp.features, hci->features, 8);

	cmd_complete(hci, BT_HCI_CMD_READ_LOCAL_FEATURES, &rsp, sizeof(rsp));
}

static void cmd_read_buffer_size(struct bt_le *hci,
						const void *data, uint8_t size)
{
	struct bt_hci_rsp_read_buffer_size rsp;

	rsp.status = BT_HCI_ERR_SUCCESS;
	rsp.acl_mtu = cpu_to_le16(0x0000);
	rsp.sco_mtu = 0x00;
	rsp.acl_max_pkt = cpu_to_le16(0x0000);
	rsp.sco_max_pkt = cpu_to_le16(0x0000);

	cmd_complete(hci, BT_HCI_CMD_READ_BUFFER_SIZE, &rsp, sizeof(rsp));
}

static void cmd_read_bd_addr(struct bt_le *hci, const void *data, uint8_t size)
{
	struct bt_hci_rsp_read_bd_addr rsp;

	rsp.status = BT_HCI_ERR_SUCCESS;
	memcpy(rsp.bdaddr, hci->bdaddr, 6);

	cmd_complete(hci, BT_HCI_CMD_READ_BD_ADDR, &rsp, sizeof(rsp));
}

static void cmd_le_set_event_mask(struct bt_le *hci,
						const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_set_event_mask *cmd = data;
	uint8_t status;

	memcpy(hci->le_event_mask, cmd->mask, 8);

	status = BT_HCI_ERR_SUCCESS;
	cmd_complete(hci, BT_HCI_CMD_LE_SET_EVENT_MASK,
						&status, sizeof(status));
}

static void cmd_le_read_buffer_size(struct bt_le *hci,
						const void *data, uint8_t size)
{
	struct bt_hci_rsp_le_read_buffer_size rsp;

	rsp.status = BT_HCI_ERR_SUCCESS;
	rsp.le_mtu = cpu_to_le16(hci->le_mtu);
	rsp.le_max_pkt = hci->le_max_pkt;

	cmd_complete(hci, BT_HCI_CMD_LE_READ_BUFFER_SIZE, &rsp, sizeof(rsp));
}

static void cmd_le_read_local_features(struct bt_le *hci,
						const void *data, uint8_t size)
{
	struct bt_hci_rsp_le_read_local_features rsp;

	rsp.status = BT_HCI_ERR_SUCCESS;
	memcpy(rsp.features, hci->le_features, 8);

	cmd_complete(hci, BT_HCI_CMD_LE_READ_LOCAL_FEATURES,
							&rsp, sizeof(rsp));
}

static void cmd_le_set_random_address(struct bt_le *hci,
						const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_set_random_address *cmd = data;
	uint8_t status;

	memcpy(hci->le_random_addr, cmd->addr, 6);

	status = BT_HCI_ERR_SUCCESS;
	cmd_complete(hci, BT_HCI_CMD_LE_SET_RANDOM_ADDRESS,
						&status, sizeof(status));
}

static void cmd_le_set_adv_parameters(struct bt_le *hci,
						const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_set_adv_parameters *cmd = data;
	uint16_t min_interval, max_interval;
	uint8_t status;

	if (hci->le_adv_enable == 0x01) {
		cmd_status(hci, BT_HCI_ERR_COMMAND_DISALLOWED,
					BT_HCI_CMD_LE_SET_ADV_PARAMETERS);
		return;
	}

	min_interval = le16_to_cpu(cmd->min_interval);
	max_interval = le16_to_cpu(cmd->max_interval);

	/* Valid range for advertising type is 0x00 to 0x03 */
	switch (cmd->type) {
	case 0x00:	/* ADV_IND */
		/* Range for advertising interval min is 0x0020 to 0x4000 */
		if (min_interval < 0x0020 || min_interval > 0x4000) {
			cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS,
					BT_HCI_CMD_LE_SET_ADV_PARAMETERS);
			return;
		}
		/* Range for advertising interval max is 0x0020 to 0x4000 */
		if (max_interval < 0x0020 || max_interval > 0x4000) {
			cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS,
					BT_HCI_CMD_LE_SET_ADV_PARAMETERS);
			return;
		}
		/* Advertising interval max shall be less or equal */
		if (min_interval > max_interval) {
			cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS,
					BT_HCI_CMD_LE_SET_ADV_PARAMETERS);
			return;
		}
		break;

	case 0x01:	/* ADV_DIRECT_IND */
		/* Range for direct address type is 0x00 to 0x01 */
		if (cmd->direct_addr_type > 0x01) {
			cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS,
					BT_HCI_CMD_LE_SET_ADV_PARAMETERS);
			return;
		}
		break;

	case 0x02:	/* ADV_SCAN_IND */
	case 0x03:	/* ADV_NONCONN_IND */
		/* Range for advertising interval min is 0x00a0 to 0x4000 */
		if (min_interval < 0x00a0 || min_interval > 0x4000) {
			cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS,
					BT_HCI_CMD_LE_SET_ADV_PARAMETERS);
			return;
		}
		/* Range for advertising interval max is 0x00a0 to 0x4000 */
		if (max_interval < 0x00a0 || max_interval > 0x4000) {
			cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS,
					BT_HCI_CMD_LE_SET_ADV_PARAMETERS);
			return;
		}
		/* Advertising interval min shall be less or equal */
		if (min_interval > max_interval) {
			cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS,
					BT_HCI_CMD_LE_SET_ADV_PARAMETERS);
			return;
		}
		break;

	default:
		cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS,
					BT_HCI_CMD_LE_SET_ADV_PARAMETERS);
		return;
	}

	/* Valid range for own address type is 0x00 to 0x01 */
	if (cmd->own_addr_type > 0x01) {
		cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS,
					BT_HCI_CMD_LE_SET_ADV_PARAMETERS);
		return;
	}

	/* Valid range for advertising channel map is 0x01 to 0x07 */
	if (cmd->channel_map < 0x01 || cmd->channel_map > 0x07) {
		cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS,
					BT_HCI_CMD_LE_SET_ADV_PARAMETERS);
		return;
	}

	/* Valid range for advertising filter policy is 0x00 to 0x03 */
	if (cmd->filter_policy > 0x03) {
		cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS,
					BT_HCI_CMD_LE_SET_ADV_PARAMETERS);
		return;
	}

	hci->le_adv_min_interval = min_interval;
	hci->le_adv_max_interval = max_interval;
	hci->le_adv_type = cmd->type;
	hci->le_adv_own_addr_type = cmd->own_addr_type;
	hci->le_adv_direct_addr_type = cmd->direct_addr_type;
	memcpy(hci->le_adv_direct_addr, cmd->direct_addr, 6);
	hci->le_adv_channel_map = cmd->channel_map;
	hci->le_adv_filter_policy = cmd->filter_policy;

	status = BT_HCI_ERR_SUCCESS;
	cmd_complete(hci, BT_HCI_CMD_LE_SET_ADV_PARAMETERS,
						&status, sizeof(status));
}

static void cmd_le_read_adv_tx_power(struct bt_le *hci,
						const void *data, uint8_t size)
{
	struct bt_hci_rsp_le_read_adv_tx_power rsp;

	rsp.status = BT_HCI_ERR_SUCCESS;
	rsp.level = hci->le_adv_tx_power;

	cmd_complete(hci, BT_HCI_CMD_LE_READ_ADV_TX_POWER, &rsp, sizeof(rsp));
}

static void cmd_le_set_adv_data(struct bt_le *hci,
						const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_set_adv_data *cmd = data;
	uint8_t status;

	/* Valid range for advertising data length is 0x00 to 0x1f */
	if (cmd->len > 0x1f) {
		cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS,
					BT_HCI_CMD_LE_SET_ADV_DATA);
		return;
	}

	hci->le_adv_data_len = cmd->len;
	memcpy(hci->le_adv_data, cmd->data, 31);

	status = BT_HCI_ERR_SUCCESS;
	cmd_complete(hci, BT_HCI_CMD_LE_SET_ADV_DATA, &status, sizeof(status));
}

static void cmd_le_set_scan_rsp_data(struct bt_le *hci,
						const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_set_scan_rsp_data *cmd = data;
	uint8_t status;

	/* Valid range for scan response data length is 0x00 to 0x1f */
	if (cmd->len > 0x1f) {
		cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS,
					BT_HCI_CMD_LE_SET_SCAN_RSP_DATA);
		return;
	}

	hci->le_scan_rsp_data_len = cmd->len;
	memcpy(hci->le_scan_rsp_data, cmd->data, 31);

	status = BT_HCI_ERR_SUCCESS;
	cmd_complete(hci, BT_HCI_CMD_LE_SET_SCAN_RSP_DATA,
						&status, sizeof(status));
}

static void cmd_le_set_adv_enable(struct bt_le *hci,
						const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_set_adv_enable *cmd = data;
	uint8_t status;

	/* Valid range for advertising enable is 0x00 to 0x01 */
	if (cmd->enable > 0x01) {
		cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS,
					BT_HCI_CMD_LE_SET_ADV_ENABLE);
		return;
	}

	if (cmd->enable == hci->le_adv_enable) {
		cmd_status(hci, BT_HCI_ERR_COMMAND_DISALLOWED,
					BT_HCI_CMD_LE_SET_ADV_ENABLE);
		return;
	}

	hci->le_adv_enable = cmd->enable;

	status = BT_HCI_ERR_SUCCESS;
	cmd_complete(hci, BT_HCI_CMD_LE_SET_ADV_ENABLE,
						&status, sizeof(status));
}

static void cmd_le_read_white_list_size(struct bt_le *hci,
						const void *data, uint8_t size)
{
	struct bt_hci_rsp_le_read_white_list_size rsp;

	rsp.status = BT_HCI_ERR_SUCCESS;
	rsp.size = hci->le_white_list_size;

	cmd_complete(hci, BT_HCI_CMD_LE_READ_WHITE_LIST_SIZE,
							&rsp, sizeof(rsp));
}

static void cmd_le_clear_white_list(struct bt_le *hci,
						const void *data, uint8_t size)
{
	uint8_t status;

	status = BT_HCI_ERR_SUCCESS;
	cmd_complete(hci, BT_HCI_CMD_LE_CLEAR_WHITE_LIST,
						&status, sizeof(status));
}

static void cmd_le_encrypt(struct bt_le *hci, const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_encrypt *cmd = data;
	struct bt_hci_rsp_le_encrypt rsp;

	if (!bt_crypto_e(hci->crypto, cmd->key, cmd->plaintext, rsp.data)) {
		cmd_status(hci, BT_HCI_ERR_COMMAND_DISALLOWED,
					BT_HCI_CMD_LE_ENCRYPT);
		return;
	}

	rsp.status = BT_HCI_ERR_SUCCESS;

	cmd_complete(hci, BT_HCI_CMD_LE_ENCRYPT, &rsp, sizeof(rsp));
}

static void cmd_le_rand(struct bt_le *hci, const void *data, uint8_t size)
{
	struct bt_hci_rsp_le_rand rsp;
	uint8_t value[8];

	if (!bt_crypto_random_bytes(hci->crypto, value, 8)) {
		cmd_status(hci, BT_HCI_ERR_COMMAND_DISALLOWED,
					BT_HCI_CMD_LE_RAND);
		return;
	}

	rsp.status = BT_HCI_ERR_SUCCESS;
	memcpy(&rsp.number, value, 8);

	cmd_complete(hci, BT_HCI_CMD_LE_RAND, &rsp, sizeof(rsp));
}

static void cmd_le_read_supported_states(struct bt_le *hci,
						const void *data, uint8_t size)
{
	struct bt_hci_rsp_le_read_supported_states rsp;

	rsp.status = BT_HCI_ERR_SUCCESS;
	memcpy(rsp.states, hci->le_states, 8);

	cmd_complete(hci, BT_HCI_CMD_LE_READ_SUPPORTED_STATES,
							&rsp, sizeof(rsp));
}

static const struct {
	uint16_t opcode;
	void (*func) (struct bt_le *hci, const void *data, uint8_t size);
	uint8_t size;
	bool fixed;
} cmd_table[] = {
	{ BT_HCI_CMD_SET_EVENT_MASK,       cmd_set_event_mask,      8, true },
	{ BT_HCI_CMD_RESET,                cmd_reset,               0, true },
	{ BT_HCI_CMD_READ_LOCAL_VERSION,   cmd_read_local_version,  0, true },
	{ BT_HCI_CMD_READ_LOCAL_COMMANDS,  cmd_read_local_commands, 0, true },
	{ BT_HCI_CMD_READ_LOCAL_FEATURES,  cmd_read_local_features, 0, true },
	{ BT_HCI_CMD_READ_BUFFER_SIZE,     cmd_read_buffer_size,    0, true },
	{ BT_HCI_CMD_READ_BD_ADDR,         cmd_read_bd_addr,        0, true },

	{ BT_HCI_CMD_LE_SET_EVENT_MASK,
				cmd_le_set_event_mask, 8, true },
	{ BT_HCI_CMD_LE_READ_BUFFER_SIZE,
				cmd_le_read_buffer_size, 0, true },
	{ BT_HCI_CMD_LE_READ_LOCAL_FEATURES,
				cmd_le_read_local_features, 0, true },
	{ BT_HCI_CMD_LE_SET_RANDOM_ADDRESS,
				cmd_le_set_random_address, 6, true },
	{ BT_HCI_CMD_LE_SET_ADV_PARAMETERS,
				cmd_le_set_adv_parameters, 15, true },
	{ BT_HCI_CMD_LE_READ_ADV_TX_POWER,
				cmd_le_read_adv_tx_power, 0, true },
	{ BT_HCI_CMD_LE_SET_ADV_DATA,
				cmd_le_set_adv_data, 32, true },
	{ BT_HCI_CMD_LE_SET_SCAN_RSP_DATA,
				cmd_le_set_scan_rsp_data, 32, true },
	{ BT_HCI_CMD_LE_SET_ADV_ENABLE,
				cmd_le_set_adv_enable, 1, true },

	{ BT_HCI_CMD_LE_READ_WHITE_LIST_SIZE,
				cmd_le_read_white_list_size, 0, true },
	{ BT_HCI_CMD_LE_CLEAR_WHITE_LIST,
				cmd_le_clear_white_list, 0, true },

	{ BT_HCI_CMD_LE_ENCRYPT, cmd_le_encrypt, 32, true },
	{ BT_HCI_CMD_LE_RAND, cmd_le_rand, 0, true },

	{ BT_HCI_CMD_LE_READ_SUPPORTED_STATES,
				cmd_le_read_supported_states, 0, true },

	{ }
};

static void process_command(struct bt_le *hci, const void *data, size_t size)
{
	const struct bt_hci_cmd_hdr *hdr = data;
	uint16_t opcode;
	unsigned int i;

	if (size < sizeof(*hdr))
		return;

	data += sizeof(*hdr);
	size -= sizeof(*hdr);

	opcode = le16_to_cpu(hdr->opcode);

	if (hdr->plen != size) {
		cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS, opcode);
		return;
	}

	for (i = 0; cmd_table[i].func; i++) {
		if (cmd_table[i].opcode != opcode)
			continue;

		if ((cmd_table[i].fixed && size != cmd_table[i].size) ||
						size < cmd_table[i].size) {
			cmd_status(hci, BT_HCI_ERR_INVALID_PARAMETERS, opcode);
			return;
		}

		cmd_table[i].func(hci, data, size);
		return;
	}

	cmd_status(hci, BT_HCI_ERR_UNKNOWN_COMMAND, opcode);
}

static void vhci_read_callback(int fd, uint32_t events, void *user_data)
{
	struct bt_le *hci = user_data;
	unsigned char buf[4096];
	ssize_t len;

	if (events & (EPOLLERR | EPOLLHUP))
		return;

	len = read(hci->vhci_fd, buf, sizeof(buf));
	if (len < 1)
		return;

	switch (buf[0]) {
	case BT_H4_CMD_PKT:
		process_command(hci, buf + 1, len - 1);
		break;
	}
}

struct bt_le *bt_le_new(void)
{
	unsigned char setup_cmd[2];
	struct bt_le *hci;

	hci = calloc(1, sizeof(*hci));
	if (!hci)
		return NULL;

	reset_defaults(hci);

	hci->vhci_fd = open("/dev/vhci", O_RDWR);
	if (hci->vhci_fd < 0) {
		free(hci);
		return NULL;
	}

	setup_cmd[0] = HCI_VENDOR_PKT;
	setup_cmd[1] = HCI_BREDR;

	if (write(hci->vhci_fd, setup_cmd, sizeof(setup_cmd)) < 0) {
		close(hci->vhci_fd);
		free(hci);
		return NULL;
	}

	mainloop_add_fd(hci->vhci_fd, EPOLLIN, vhci_read_callback, hci, NULL);

	hci->crypto = bt_crypto_new();

	return bt_le_ref(hci);
}

struct bt_le *bt_le_ref(struct bt_le *hci)
{
	if (!hci)
		return NULL;

	__sync_fetch_and_add(&hci->ref_count, 1);

	return hci;
}

void bt_le_unref(struct bt_le *hci)
{
	if (!hci)
		return;

	if (__sync_sub_and_fetch(&hci->ref_count, 1))
		return;

	bt_crypto_unref(hci->crypto);

	mainloop_remove_fd(hci->vhci_fd);

	close(hci->vhci_fd);

	free(hci);
}
