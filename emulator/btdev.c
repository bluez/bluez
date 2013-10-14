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

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>

#include "monitor/bt.h"
#include "btdev.h"

#define le16_to_cpu(val) (val)
#define le32_to_cpu(val) (val)
#define cpu_to_le16(val) (val)
#define cpu_to_le32(val) (val)

#define has_bredr(btdev)	(!((btdev)->features[4] & 0x20))
#define has_le(btdev)		(!!((btdev)->features[4] & 0x40))

struct hook {
	btdev_hook_func handler;
	void *user_data;
	enum btdev_hook_type type;
	uint16_t opcode;
};

#define MAX_HOOK_ENTRIES 16

struct btdev {
	enum btdev_type type;

	struct btdev *conn;

	btdev_command_func command_handler;
	void *command_data;

	btdev_send_func send_handler;
	void *send_data;

	struct hook *hook_list[MAX_HOOK_ENTRIES];

        uint16_t manufacturer;
        uint8_t  version;
	uint16_t revision;
	uint8_t  commands[64];
	uint8_t  max_page;
	uint8_t  features[8];
	uint8_t  feat_page_2[8];
	uint16_t acl_mtu;
	uint16_t acl_max_pkt;
	uint8_t  country_code;
	uint8_t  bdaddr[6];
	uint8_t  le_features[8];
	uint8_t  le_states[8];

	uint16_t default_link_policy;
	uint8_t  event_mask[8];
	uint8_t  event_mask_page2[8];
	uint8_t  event_filter;
	uint8_t  name[248];
	uint8_t  dev_class[3];
	uint16_t voice_setting;
	uint16_t conn_accept_timeout;
	uint16_t page_timeout;
	uint8_t  scan_enable;
	uint16_t page_scan_interval;
	uint16_t page_scan_window;
	uint16_t page_scan_type;
	uint8_t  auth_enable;
	uint16_t inquiry_scan_interval;
	uint16_t inquiry_scan_window;
	uint8_t  inquiry_mode;
	uint8_t  afh_assessment_mode;
	uint8_t  ext_inquiry_fec;
	uint8_t  ext_inquiry_rsp[240];
	uint8_t  simple_pairing_mode;
	uint8_t  le_supported;
	uint8_t  le_simultaneous;
	uint8_t  le_event_mask[8];
	uint8_t  le_adv_data[31];
	uint8_t  le_adv_data_len;
	uint8_t  le_scan_enable;
	uint8_t  le_filter_dup;
	uint8_t  le_adv_enable;

	uint16_t sync_train_interval;
	uint32_t sync_train_timeout;
	uint8_t  sync_train_service_data;
};

#define MAX_BTDEV_ENTRIES 16

static struct btdev *btdev_list[MAX_BTDEV_ENTRIES] = { };

static int get_hook_index(struct btdev *btdev, enum btdev_hook_type type,
								uint16_t opcode)
{
	int i;

	for (i = 0; i < MAX_HOOK_ENTRIES; i++) {
		if (btdev->hook_list[i] == NULL)
			continue;

		if (btdev->hook_list[i]->type == type &&
					btdev->hook_list[i]->opcode == opcode)
			return i;
	}

	return -1;
}

static bool run_hooks(struct btdev *btdev, enum btdev_hook_type type,
				uint16_t opcode, const void *data, uint16_t len)
{
	int index = get_hook_index(btdev, type, opcode);
	if (index < 0)
		return true;

	return btdev->hook_list[index]->handler(data, len,
					btdev->hook_list[index]->user_data);
}

static inline int add_btdev(struct btdev *btdev)
{
	int i, index = -1;

	for (i = 0; i < MAX_BTDEV_ENTRIES; i++) {
		if (btdev_list[i] == NULL) {
			index = i;
			btdev_list[index] = btdev;
			break;
		}
	}

	return index;
}

static inline int del_btdev(struct btdev *btdev)
{
	int i, index = -1;

	for (i = 0; i < MAX_BTDEV_ENTRIES; i++) {
		if (btdev_list[i] == btdev) {
			index = i;
			btdev_list[index] = NULL;
			break;
		}
	}

	return index;
}

static inline struct btdev *find_btdev_by_bdaddr(const uint8_t *bdaddr)
{
	int i;

	for (i = 0; i < MAX_BTDEV_ENTRIES; i++) {
		if (btdev_list[i] && !memcmp(btdev_list[i]->bdaddr, bdaddr, 6))
			return btdev_list[i];
	}

	return NULL;
}

static void hexdump(const unsigned char *buf, uint16_t len)
{
	static const char hexdigits[] = "0123456789abcdef";
	char str[68];
	uint16_t i;

	if (!len)
		return;

	for (i = 0; i < len; i++) {
		str[((i % 16) * 3) + 0] = hexdigits[buf[i] >> 4];
		str[((i % 16) * 3) + 1] = hexdigits[buf[i] & 0xf];
		str[((i % 16) * 3) + 2] = ' ';
		str[(i % 16) + 49] = isprint(buf[i]) ? buf[i] : '.';

		if ((i + 1) % 16 == 0) {
			str[47] = ' ';
			str[48] = ' ';
			str[65] = '\0';
			printf("%-12c%s\n", ' ', str);
			str[0] = ' ';
		}
	}

	if (i % 16 > 0) {
		uint16_t j;
		for (j = (i % 16); j < 16; j++) {
			str[(j * 3) + 0] = ' ';
			str[(j * 3) + 1] = ' ';
			str[(j * 3) + 2] = ' ';
			str[j + 49] = ' ';
		}
		str[47] = ' ';
		str[48] = ' ';
		str[65] = '\0';
		printf("%-12c%s\n", ' ', str);
	}
}

static void get_bdaddr(uint16_t id, uint8_t index, uint8_t *bdaddr)
{
	bdaddr[0] = id & 0xff;
	bdaddr[1] = id >> 8;
	bdaddr[2] = index;
	bdaddr[3] = 0x01;
	bdaddr[4] = 0xaa;
	bdaddr[5] = 0x00;
}

static void set_common_commands_all(struct btdev *btdev)
{
	btdev->commands[5]  |= 0x40;	/* Set Event Mask */
	btdev->commands[5]  |= 0x80;	/* Reset */
	btdev->commands[14] |= 0x08;	/* Read Local Version */
	btdev->commands[14] |= 0x10;	/* Read Local Supported Commands */
	btdev->commands[14] |= 0x20;	/* Read Local Supported Features */
	btdev->commands[14] |= 0x80;	/* Read Buffer Size */
}

static void set_common_commands_bredrle(struct btdev *btdev)
{
	btdev->commands[0]  |= 0x20;	/* Disconnect */
	btdev->commands[2]  |= 0x80;	/* Read Remote Version Information */
	btdev->commands[10] |= 0x40;	/* Host Buffer Size */
	btdev->commands[15] |= 0x02;	/* Read BD ADDR */
}

static void set_bredr_commands(struct btdev *btdev)
{
	set_common_commands_all(btdev);
	set_common_commands_bredrle(btdev);

	btdev->commands[0]  |= 0x01;	/* Inquiry */
	btdev->commands[0]  |= 0x02;	/* Inquiry Cancel */
	btdev->commands[0]  |= 0x10;	/* Create Connection */
	btdev->commands[0]  |= 0x40;	/* Add SCO Connection */
	btdev->commands[0]  |= 0x80;	/* Cancel Create Connection */
	btdev->commands[1]  |= 0x01;	/* Accept Connection Request */
	btdev->commands[1]  |= 0x02;	/* Reject Connection Request */
	btdev->commands[2]  |= 0x08;	/* Remote Name Request */
	btdev->commands[2]  |= 0x10;	/* Cancel Remote Name Request */
	btdev->commands[2]  |= 0x20;	/* Read Remote Supported Features */
	btdev->commands[2]  |= 0x40;	/* Read Remote Extended Features */
	btdev->commands[5]  |= 0x08;	/* Read Default Link Policy */
	btdev->commands[5]  |= 0x10;	/* Write Default Link Policy */
	btdev->commands[6]  |= 0x01;	/* Set Event Filter */
	btdev->commands[6]  |= 0x20;	/* Read Stored Link Key */
	btdev->commands[6]  |= 0x40;	/* Write Stored Link Key */
	btdev->commands[6]  |= 0x80;	/* Delete Stored Link Key */
	btdev->commands[7]  |= 0x01;	/* Write Local Name */
	btdev->commands[7]  |= 0x02;	/* Read Local Name */
	btdev->commands[7]  |= 0x04;	/* Read Connection Accept Timeout */
	btdev->commands[7]  |= 0x08;	/* Write Connection Accept Timeout */
	btdev->commands[7]  |= 0x10;	/* Read Page Timeout */
	btdev->commands[7]  |= 0x20;	/* Write Page Timeout */
	btdev->commands[7]  |= 0x40;	/* Read Scan Enable */
	btdev->commands[7]  |= 0x80;	/* Write Scan Enable */
	btdev->commands[8]  |= 0x01;	/* Read Page Scan Activity */
	btdev->commands[8]  |= 0x02;	/* Write Page Scan Activity */
	btdev->commands[8]  |= 0x04;	/* Read Inquiry Scan Activity */
	btdev->commands[8]  |= 0x08;	/* Write Inquiry Scan Activity */
	btdev->commands[8]  |= 0x10;	/* Read Authentication Enable */
	btdev->commands[8]  |= 0x20;	/* Write Authentication Enable */
	btdev->commands[9]  |= 0x01;	/* Read Class Of Device */
	btdev->commands[9]  |= 0x02;	/* Write Class Of Device */
	btdev->commands[9]  |= 0x04;	/* Read Voice Setting */
	btdev->commands[9]  |= 0x08;	/* Write Voice Setting */
	btdev->commands[11] |= 0x10;	/* Write Current IAC LAP */
	btdev->commands[12] |= 0x40;	/* Read Inquiry Mode */
	btdev->commands[12] |= 0x80;	/* Write Inquiry Mode */
	btdev->commands[13] |= 0x01;	/* Read Page Scan Type */
	btdev->commands[13] |= 0x02;	/* Write Page Scan Type */
	btdev->commands[13] |= 0x04;	/* Read AFH Assess Mode */
	btdev->commands[13] |= 0x08;	/* Write AFH Assess Mode */
	btdev->commands[14] |= 0x40;	/* Read Local Extended Features */
	btdev->commands[15] |= 0x01;	/* Read Country Code */
	btdev->commands[16] |= 0x04;	/* Enable Device Under Test Mode */
	btdev->commands[16] |= 0x08;	/* Setup Synchronous Connection */
	btdev->commands[17] |= 0x01;	/* Read Extended Inquiry Response */
	btdev->commands[17] |= 0x02;	/* Write Extended Inquiry Response */
	btdev->commands[17] |= 0x20;	/* Read Simple Pairing Mode */
	btdev->commands[17] |= 0x40;	/* Write Simple Pairing Mode */
	btdev->commands[17] |= 0x80;	/* Read Local OOB Data */
	btdev->commands[18] |= 0x01;	/* Read Inquiry Response TX Power */
	btdev->commands[18] |= 0x02;	/* Write Inquiry Response TX Power */
	btdev->commands[23] |= 0x04;	/* Read Data Block Size */
}

static void set_le_commands(struct btdev *btdev)
{
	set_common_commands_all(btdev);
	set_common_commands_bredrle(btdev);

	btdev->commands[24] |= 0x20;	/* Read LE Host Supported */
	btdev->commands[24] |= 0x20;	/* Write LE Host Supported */
	btdev->commands[25] |= 0x01;	/* LE Set Event Mask */
	btdev->commands[25] |= 0x02;	/* LE Read Buffer Size */
	btdev->commands[25] |= 0x04;	/* LE Read Local Features */
	btdev->commands[25] |= 0x20;	/* LE Set Adv Parameters */
	btdev->commands[25] |= 0x40;	/* LE Read Adv TX Power */
	btdev->commands[25] |= 0x80;	/* LE Set Adv Data */
	btdev->commands[26] |= 0x02;	/* LE Set Adv Enable */
	btdev->commands[26] |= 0x04;	/* LE Set Scan Parameters */
	btdev->commands[26] |= 0x08;	/* LE Set Scan Enable */
	btdev->commands[26] |= 0x40;	/* LE Read White List Size */
	btdev->commands[27] |= 0x80;	/* LE Rand */
	btdev->commands[28] |= 0x08;	/* LE Read Supported States */
	btdev->commands[28] |= 0x10;	/* LE Receiver Test */
	btdev->commands[28] |= 0x20;	/* LE Transmitter Test */
	btdev->commands[28] |= 0x40;	/* LE Test End */
}

static void set_bredrle_commands(struct btdev *btdev)
{
	set_bredr_commands(btdev);
	set_le_commands(btdev);

	/* Extra BR/EDR commands we want to only support for >= 4.0
	 * adapters.
	 */
	btdev->commands[22] |= 0x04;	/* Set Event Mask Page 2 */
	btdev->commands[31] |= 0x80;	/* Read Sync Train Parameters */
}

static void set_amp_commands(struct btdev *btdev)
{
	set_common_commands_all(btdev);

	btdev->commands[22] |= 0x20;	/* Read Local AMP Info */
}

static void set_bredrle_features(struct btdev *btdev)
{
	btdev->features[0] |= 0x04;	/* Encryption */
	btdev->features[0] |= 0x20;	/* Role switch */
	btdev->features[0] |= 0x80;	/* Sniff mode */
	btdev->features[1] |= 0x08;	/* SCO link */
	btdev->features[3] |= 0x40;	/* RSSI with inquiry results */
	btdev->features[3] |= 0x80;	/* Extended SCO link */
	btdev->features[4] |= 0x08;	/* AFH capable slave */
	btdev->features[4] |= 0x10;	/* AFH classification slave */
	btdev->features[4] |= 0x40;	/* LE Supported */
	btdev->features[5] |= 0x02;	/* Sniff subrating */
	btdev->features[5] |= 0x04;	/* Pause encryption */
	btdev->features[5] |= 0x08;	/* AFH capable master */
	btdev->features[5] |= 0x10;	/* AFH classification master */
	btdev->features[6] |= 0x01;	/* Extended Inquiry Response */
	btdev->features[6] |= 0x02;	/* Simultaneous LE and BR/EDR */
	btdev->features[6] |= 0x08;	/* Secure Simple Pairing */
	btdev->features[6] |= 0x10;	/* Encapsulated PDU */
	btdev->features[6] |= 0x20;	/* Erroneous Data Reporting */
	btdev->features[6] |= 0x40;	/* Non-flushable Packet Boundary Flag */
	btdev->features[7] |= 0x01;	/* Link Supervision Timeout Event */
	btdev->features[7] |= 0x02;	/* Inquiry TX Power Level */
	btdev->features[7] |= 0x80;	/* Extended features */

	btdev->feat_page_2[0] |= 0x01;	/* CSB - Master Operation */
	btdev->feat_page_2[0] |= 0x02;	/* CSB - Slave Operation */
	btdev->feat_page_2[0] |= 0x04;	/* Synchronization Train */
	btdev->feat_page_2[0] |= 0x08;	/* Synchronization Scan */
	btdev->feat_page_2[0] |= 0x10;	/* Inquiry Response Notification */

	btdev->max_page = 2;
}

static void set_bredr_features(struct btdev *btdev)
{
	btdev->features[0] |= 0x04;	/* Encryption */
	btdev->features[0] |= 0x20;	/* Role switch */
	btdev->features[0] |= 0x80;	/* Sniff mode */
	btdev->features[1] |= 0x08;	/* SCO link */
	btdev->features[3] |= 0x40;	/* RSSI with inquiry results */
	btdev->features[3] |= 0x80;	/* Extended SCO link */
	btdev->features[4] |= 0x08;	/* AFH capable slave */
	btdev->features[4] |= 0x10;	/* AFH classification slave */
	btdev->features[5] |= 0x02;	/* Sniff subrating */
	btdev->features[5] |= 0x04;	/* Pause encryption */
	btdev->features[5] |= 0x08;	/* AFH capable master */
	btdev->features[5] |= 0x10;	/* AFH classification master */
	btdev->features[6] |= 0x01;	/* Extended Inquiry Response */
	btdev->features[6] |= 0x08;	/* Secure Simple Pairing */
	btdev->features[6] |= 0x10;	/* Encapsulated PDU */
	btdev->features[6] |= 0x20;	/* Erroneous Data Reporting */
	btdev->features[6] |= 0x40;	/* Non-flushable Packet Boundary Flag */
	btdev->features[7] |= 0x01;	/* Link Supervision Timeout Event */
	btdev->features[7] |= 0x02;	/* Inquiry TX Power Level */
	btdev->features[7] |= 0x80;	/* Extended features */

	btdev->max_page = 1;
}

static void set_le_features(struct btdev *btdev)
{
	btdev->features[4] |= 0x20;	/* BR/EDR Not Supported */
	btdev->features[4] |= 0x40;	/* LE Supported */

	btdev->max_page = 1;
}

static void set_amp_features(struct btdev *btdev)
{
}

struct btdev *btdev_create(enum btdev_type type, uint16_t id)
{
	struct btdev *btdev;
	int index;

	btdev = malloc(sizeof(*btdev));
	if (!btdev)
		return NULL;

	memset(btdev, 0, sizeof(*btdev));
	btdev->type = type;

	btdev->manufacturer = 63;

	if (type == BTDEV_TYPE_BREDR)
		btdev->version = 0x05;
	else
		btdev->version = 0x06;

	btdev->revision = 0x0000;

	switch (btdev->type) {
	case BTDEV_TYPE_BREDRLE:
		set_bredrle_features(btdev);
		set_bredrle_commands(btdev);
		break;
	case BTDEV_TYPE_BREDR:
		set_bredr_features(btdev);
		set_bredr_commands(btdev);
		break;
	case BTDEV_TYPE_LE:
		set_le_features(btdev);
		set_le_commands(btdev);
		break;
	case BTDEV_TYPE_AMP:
		set_amp_features(btdev);
		set_amp_commands(btdev);
		break;
	}

	btdev->page_scan_interval = 0x0800;
	btdev->page_scan_window = 0x0012;
	btdev->page_scan_type = 0x00;

	btdev->sync_train_interval = 0x0080;
	btdev->sync_train_timeout = 0x0002ee00;
	btdev->sync_train_service_data = 0x00;

	btdev->acl_mtu = 192;
	btdev->acl_max_pkt = 1;

	btdev->country_code = 0x00;

	index = add_btdev(btdev);
	if (index < 0) {
		free(btdev);
		return NULL;
	}

	get_bdaddr(id, index, btdev->bdaddr);

	return btdev;
}

void btdev_destroy(struct btdev *btdev)
{
	if (!btdev)
		return;

	del_btdev(btdev);

	free(btdev);
}

const uint8_t *btdev_get_bdaddr(struct btdev *btdev)
{
	return btdev->bdaddr;
}

uint8_t *btdev_get_features(struct btdev *btdev)
{
	return btdev->features;
}

void btdev_set_command_handler(struct btdev *btdev, btdev_command_func handler,
							void *user_data)
{
	if (!btdev)
		return;

	btdev->command_handler = handler;
	btdev->command_data = user_data;
}

void btdev_set_send_handler(struct btdev *btdev, btdev_send_func handler,
							void *user_data)
{
	if (!btdev)
		return;

	btdev->send_handler = handler;
	btdev->send_data = user_data;
}

static void send_packet(struct btdev *btdev, const void *data, uint16_t len)
{
	if (!btdev->send_handler)
		return;

	btdev->send_handler(data, len, btdev->send_data);
}

static void send_event(struct btdev *btdev, uint8_t event,
						const void *data, uint8_t len)
{
	struct bt_hci_evt_hdr *hdr;
	uint16_t pkt_len;
	void *pkt_data;

	pkt_len = 1 + sizeof(*hdr) + len;

	pkt_data = malloc(pkt_len);
	if (!pkt_data)
		return;

	((uint8_t *) pkt_data)[0] = BT_H4_EVT_PKT;

	hdr = pkt_data + 1;
	hdr->evt = event;
	hdr->plen = len;

	if (len > 0)
		memcpy(pkt_data + 1 + sizeof(*hdr), data, len);

	if (run_hooks(btdev, BTDEV_HOOK_POST_EVT, event, pkt_data, pkt_len))
		send_packet(btdev, pkt_data, pkt_len);

	free(pkt_data);
}

static void cmd_complete(struct btdev *btdev, uint16_t opcode,
						const void *data, uint8_t len)
{
	struct bt_hci_evt_hdr *hdr;
	struct bt_hci_evt_cmd_complete *cc;
	uint16_t pkt_len;
	void *pkt_data;

	pkt_len = 1 + sizeof(*hdr) + sizeof(*cc) + len;

	pkt_data = malloc(pkt_len);
	if (!pkt_data)
		return;

	((uint8_t *) pkt_data)[0] = BT_H4_EVT_PKT;

	hdr = pkt_data + 1;
	hdr->evt = BT_HCI_EVT_CMD_COMPLETE;
	hdr->plen = sizeof(*cc) + len;

	cc = pkt_data + 1 + sizeof(*hdr);
	cc->ncmd = 0x01;
	cc->opcode = cpu_to_le16(opcode);

	if (len > 0)
		memcpy(pkt_data + 1 + sizeof(*hdr) + sizeof(*cc), data, len);

	if (run_hooks(btdev, BTDEV_HOOK_POST_CMD, opcode, pkt_data, pkt_len))
		send_packet(btdev, pkt_data, pkt_len);

	free(pkt_data);
}

static void cmd_status(struct btdev *btdev, uint8_t status, uint16_t opcode)
{
	struct bt_hci_evt_hdr *hdr;
	struct bt_hci_evt_cmd_status *cs;
	uint16_t pkt_len;
	void *pkt_data;

	pkt_len = 1 + sizeof(*hdr) + sizeof(*cs);

	pkt_data = malloc(pkt_len);
	if (!pkt_data)
		return;

	((uint8_t *) pkt_data)[0] = BT_H4_EVT_PKT;

	hdr = pkt_data + 1;
	hdr->evt = BT_HCI_EVT_CMD_STATUS;
	hdr->plen = sizeof(*cs);

	cs = pkt_data + 1 + sizeof(*hdr);
	cs->status = status;
	cs->ncmd = 0x01;
	cs->opcode = cpu_to_le16(opcode);

	if (run_hooks(btdev, BTDEV_HOOK_POST_CMD, opcode, pkt_data, pkt_len))
		send_packet(btdev, pkt_data, pkt_len);

	free(pkt_data);
}

static void num_completed_packets(struct btdev *btdev)
{
	if (btdev->conn) {
		struct bt_hci_evt_num_completed_packets ncp;

		ncp.num_handles = 1;
		ncp.handle = cpu_to_le16(42);
		ncp.count = cpu_to_le16(1);

		send_event(btdev, BT_HCI_EVT_NUM_COMPLETED_PACKETS,
							&ncp, sizeof(ncp));
	}
}

static void inquiry_complete(struct btdev *btdev, uint8_t status)
{
	struct bt_hci_evt_inquiry_complete ic;
	int i;

	for (i = 0; i < MAX_BTDEV_ENTRIES; i++) {
		if (!btdev_list[i] || btdev_list[i] == btdev)
			continue;

		if (!(btdev_list[i]->scan_enable & 0x02))
			continue;

		if (btdev->inquiry_mode == 0x02 &&
					btdev_list[i]->ext_inquiry_rsp[0]) {
			struct bt_hci_evt_ext_inquiry_result ir;

			ir.num_resp = 0x01;
			memcpy(ir.bdaddr, btdev_list[i]->bdaddr, 6);
			ir.pscan_rep_mode = 0x00;
			ir.pscan_period_mode = 0x00;
			memcpy(ir.dev_class, btdev_list[i]->dev_class, 3);
			ir.clock_offset = 0x0000;
			ir.rssi = -60;
			memcpy(ir.data, btdev_list[i]->ext_inquiry_rsp, 240);

			send_event(btdev, BT_HCI_EVT_EXT_INQUIRY_RESULT,
							&ir, sizeof(ir));
			continue;
		}

		if (btdev->inquiry_mode > 0x00) {
			struct bt_hci_evt_inquiry_result_with_rssi ir;

			ir.num_resp = 0x01;
			memcpy(ir.bdaddr, btdev_list[i]->bdaddr, 6);
			ir.pscan_rep_mode = 0x00;
			ir.pscan_period_mode = 0x00;
			memcpy(ir.dev_class, btdev_list[i]->dev_class, 3);
			ir.clock_offset = 0x0000;
			ir.rssi = -60;

			send_event(btdev, BT_HCI_EVT_INQUIRY_RESULT_WITH_RSSI,
							&ir, sizeof(ir));
		} else {
			struct bt_hci_evt_inquiry_result ir;

			ir.num_resp = 0x01;
			memcpy(ir.bdaddr, btdev_list[i]->bdaddr, 6);
			ir.pscan_rep_mode = 0x00;
			ir.pscan_period_mode = 0x00;
			ir.pscan_mode = 0x00;
			memcpy(ir.dev_class, btdev_list[i]->dev_class, 3);
			ir.clock_offset = 0x0000;

			send_event(btdev, BT_HCI_EVT_INQUIRY_RESULT,
							&ir, sizeof(ir));
		}
        }

	ic.status = status;

	send_event(btdev, BT_HCI_EVT_INQUIRY_COMPLETE, &ic, sizeof(ic));
}

static void conn_complete(struct btdev *btdev,
					const uint8_t *bdaddr, uint8_t status)
{
	struct bt_hci_evt_conn_complete cc;

	if (!status) {
		struct btdev *remote = find_btdev_by_bdaddr(bdaddr);

		btdev->conn = remote;
		remote->conn = btdev;

		cc.status = status;
		memcpy(cc.bdaddr, btdev->bdaddr, 6);
		cc.encr_mode = 0x00;

		cc.handle = cpu_to_le16(42);
		cc.link_type = 0x01;

		send_event(remote, BT_HCI_EVT_CONN_COMPLETE, &cc, sizeof(cc));

		cc.handle = cpu_to_le16(42);
		cc.link_type = 0x01;
	} else {
		cc.handle = cpu_to_le16(0x0000);
		cc.link_type = 0x01;
	}

	cc.status = status;
	memcpy(cc.bdaddr, bdaddr, 6);
	cc.encr_mode = 0x00;

	send_event(btdev, BT_HCI_EVT_CONN_COMPLETE, &cc, sizeof(cc));
}

static void sync_conn_complete(struct btdev *btdev, uint16_t voice_setting,
								uint8_t status)
{
	struct bt_hci_evt_sync_conn_complete cc;

	if (!btdev->conn)
		return;

	cc.status = status;
	memcpy(cc.bdaddr, btdev->conn->bdaddr, 6);

	cc.handle = cpu_to_le16(status == BT_HCI_ERR_SUCCESS ? 257 : 0);
	cc.link_type = 0x02;
	cc.tx_interval = 0x000c;
	cc.retrans_window = 0x06;
	cc.rx_pkt_len = 60;
	cc.tx_pkt_len = 60;
	cc.air_mode = (voice_setting == 0x0060) ? 0x02 : 0x03;

	send_event(btdev, BT_HCI_EVT_SYNC_CONN_COMPLETE, &cc, sizeof(cc));
}

static void sco_conn_complete(struct btdev *btdev, uint8_t status)
{
	struct bt_hci_evt_conn_complete cc;

	if (!btdev->conn)
		return;

	cc.status = status;
	memcpy(cc.bdaddr, btdev->conn->bdaddr, 6);
	cc.handle = cpu_to_le16(status == BT_HCI_ERR_SUCCESS ? 257 : 0);
	cc.link_type = 0x00;
	cc.encr_mode = 0x00;

	send_event(btdev, BT_HCI_EVT_CONN_COMPLETE, &cc, sizeof(cc));
}

static void le_conn_complete(struct btdev *btdev,
					const uint8_t *bdaddr, uint8_t status)
{
	char buf[1 + sizeof(struct bt_hci_evt_le_conn_complete)];
	struct bt_hci_evt_le_conn_complete *cc = (void *) &buf[1];

	memset(buf, 0, sizeof(buf));

	buf[0] = BT_HCI_EVT_LE_CONN_COMPLETE;

	if (!status) {
		struct btdev *remote = find_btdev_by_bdaddr(bdaddr);

		btdev->conn = remote;
		remote->conn = btdev;

		cc->status = status;
		memcpy(cc->peer_addr, btdev->bdaddr, 6);

		cc->role = 0x01;
		cc->handle = cpu_to_le16(42);

		send_event(remote, BT_HCI_EVT_LE_META_EVENT, buf, sizeof(buf));

		cc->handle = cpu_to_le16(42);
	}

	cc->status = status;
	memcpy(cc->peer_addr, bdaddr, 6);
	cc->role = 0x00;

	send_event(btdev, BT_HCI_EVT_LE_META_EVENT, buf, sizeof(buf));
}

static void le_conn_request(struct btdev *btdev, const uint8_t *bdaddr)
{
	struct btdev *remote = find_btdev_by_bdaddr(bdaddr);

	if (remote && remote->le_adv_enable)
		le_conn_complete(btdev, bdaddr, 0);
	else
		le_conn_complete(btdev, bdaddr,
					BT_HCI_ERR_CONN_FAILED_TO_ESTABLISH);
}

static void conn_request(struct btdev *btdev, const uint8_t *bdaddr)
{
	struct btdev *remote = find_btdev_by_bdaddr(bdaddr);

	if (remote) {
		if (remote->scan_enable & 0x02) {
			struct bt_hci_evt_conn_request cr;

			memcpy(cr.bdaddr, btdev->bdaddr, 6);
			memcpy(cr.dev_class, btdev->dev_class, 3);
			cr.link_type = 0x01;

			send_event(remote, BT_HCI_EVT_CONN_REQUEST,
							&cr, sizeof(cr));
		} else
			conn_complete(btdev, bdaddr, BT_HCI_ERR_PAGE_TIMEOUT);
	} else
		conn_complete(btdev, bdaddr, BT_HCI_ERR_UNKNOWN_CONN_ID);
}

static void disconnect_complete(struct btdev *btdev, uint16_t handle,
							uint8_t reason)
{
	struct bt_hci_evt_disconnect_complete dc;
	struct btdev *remote;

	if (!btdev) {
		dc.status = BT_HCI_ERR_UNKNOWN_CONN_ID;
		dc.handle = cpu_to_le16(handle);
		dc.reason = 0x00;

		send_event(btdev, BT_HCI_EVT_DISCONNECT_COMPLETE,
							&dc, sizeof(dc));
		return;
	}

	dc.status = BT_HCI_ERR_SUCCESS;
	dc.handle = cpu_to_le16(handle);
	dc.reason = reason;

	remote = btdev->conn;

	btdev->conn = NULL;
	remote->conn = NULL;

	send_event(btdev, BT_HCI_EVT_DISCONNECT_COMPLETE, &dc, sizeof(dc));
	send_event(remote, BT_HCI_EVT_DISCONNECT_COMPLETE, &dc, sizeof(dc));
}

static void name_request_complete(struct btdev *btdev,
					const uint8_t *bdaddr, uint8_t status)
{
        struct bt_hci_evt_remote_name_request_complete nc;

	nc.status = status;
	memcpy(nc.bdaddr, bdaddr, 6);
	memset(nc.name, 0, 248);

	if (!status) {
		struct btdev *remote = find_btdev_by_bdaddr(bdaddr);

		if (remote)
			memcpy(nc.name, remote->name, 248);
		else
			nc.status = BT_HCI_ERR_UNKNOWN_CONN_ID;
	}

	send_event(btdev, BT_HCI_EVT_REMOTE_NAME_REQUEST_COMPLETE,
							&nc, sizeof(nc));
}

static void remote_features_complete(struct btdev *btdev, uint16_t handle)
{
	struct bt_hci_evt_remote_features_complete rfc;

	if (btdev->conn) {
		rfc.status = BT_HCI_ERR_SUCCESS;
		rfc.handle = cpu_to_le16(handle);
		memcpy(rfc.features, btdev->conn->features, 8);
	} else {
		rfc.status = BT_HCI_ERR_UNKNOWN_CONN_ID;
		rfc.handle = cpu_to_le16(handle);
		memset(rfc.features, 0, 8);
	}

	send_event(btdev, BT_HCI_EVT_REMOTE_FEATURES_COMPLETE,
							&rfc, sizeof(rfc));
}

static void remote_ext_features_complete(struct btdev *btdev, uint16_t handle,
								uint8_t page)
{
	struct bt_hci_evt_remote_ext_features_complete refc;

	if (btdev->conn && page < 0x02) {
		refc.handle = cpu_to_le16(handle);
		refc.page = page;
		refc.max_page = 0x01;

		switch (page) {
		case 0x00:
			refc.status = BT_HCI_ERR_SUCCESS;
			memcpy(refc.features, btdev->conn->features, 8);
			break;
		case 0x01:
			refc.status = BT_HCI_ERR_SUCCESS;
			memset(refc.features, 0, 8);
			break;
		default:
			refc.status = BT_HCI_ERR_INVALID_PARAMETERS;
			memset(refc.features, 0, 8);
			break;
		}
	} else {
		refc.status = BT_HCI_ERR_UNKNOWN_CONN_ID;
		refc.handle = cpu_to_le16(handle);
		refc.page = page;
		refc.max_page = 0x01;
		memset(refc.features, 0, 8);
	}

	send_event(btdev, BT_HCI_EVT_REMOTE_EXT_FEATURES_COMPLETE,
							&refc, sizeof(refc));
}

static void remote_version_complete(struct btdev *btdev, uint16_t handle)
{
	struct bt_hci_evt_remote_version_complete rvc;

	if (btdev->conn) {
		rvc.status = BT_HCI_ERR_SUCCESS;
		rvc.handle = cpu_to_le16(handle);
		rvc.lmp_ver = btdev->conn->version;
		rvc.manufacturer = cpu_to_le16(btdev->conn->manufacturer);
		rvc.lmp_subver = cpu_to_le16(btdev->conn->revision);
	} else {
		rvc.status = BT_HCI_ERR_UNKNOWN_CONN_ID;
		rvc.handle = cpu_to_le16(handle);
		rvc.lmp_ver = 0x00;
		rvc.manufacturer = cpu_to_le16(0);
		rvc.lmp_subver = cpu_to_le16(0);
	}

	send_event(btdev, BT_HCI_EVT_REMOTE_VERSION_COMPLETE,
							&rvc, sizeof(rvc));
}

static void le_send_adv_report(struct btdev *btdev, const struct btdev *remote)
{
	struct __packed {
		uint8_t subevent;
		union {
			struct bt_hci_evt_le_adv_report lar;
			uint8_t raw[10 + 31 + 1];
		};
	} meta_event;

	meta_event.subevent = BT_HCI_EVT_LE_ADV_REPORT;

	memset(&meta_event.lar, 0, sizeof(meta_event.lar));
	meta_event.lar.num_reports = 1;
	memcpy(meta_event.lar.addr, remote->bdaddr, 6);
	meta_event.lar.data_len = remote->le_adv_data_len;
	memcpy(meta_event.lar.data, remote->le_adv_data,
						meta_event.lar.data_len);
	/* Not available */
	meta_event.raw[10 + meta_event.lar.data_len] = 127;
	send_event(btdev, BT_HCI_EVT_LE_META_EVENT, &meta_event,
					1 + 10 + meta_event.lar.data_len + 1);
}

static void le_set_adv_enable_complete(struct btdev *btdev)
{
	int i;

	for (i = 0; i < MAX_BTDEV_ENTRIES; i++) {
		if (!btdev_list[i] || btdev_list[i] == btdev)
			continue;

		if (!btdev_list[i]->le_scan_enable)
			continue;

		le_send_adv_report(btdev_list[i], btdev);
	}
}

static void le_set_scan_enable_complete(struct btdev *btdev)
{
	int i;

	for (i = 0; i < MAX_BTDEV_ENTRIES; i++) {
		if (!btdev_list[i] || btdev_list[i] == btdev)
			continue;

		if (!btdev_list[i]->le_adv_enable)
			continue;

		le_send_adv_report(btdev, btdev_list[i]);
	}
}

static void default_cmd(struct btdev *btdev, uint16_t opcode,
						const void *data, uint8_t len)
{
	const struct bt_hci_cmd_remote_name_request_cancel *rnrc;
	const struct bt_hci_cmd_write_default_link_policy *wdlp;
	const struct bt_hci_cmd_set_event_mask *sem;
	const struct bt_hci_cmd_set_event_filter *sef;
	const struct bt_hci_cmd_write_local_name *wln;
	const struct bt_hci_cmd_write_conn_accept_timeout *wcat;
	const struct bt_hci_cmd_write_page_timeout *wpt;
	const struct bt_hci_cmd_write_scan_enable *wse;
	const struct bt_hci_cmd_write_page_scan_activity *wpsa;
	const struct bt_hci_cmd_write_inquiry_scan_activity *wisa;
	const struct bt_hci_cmd_write_page_scan_type *wpst;
	const struct bt_hci_cmd_write_auth_enable *wae;
	const struct bt_hci_cmd_write_class_of_dev *wcod;
	const struct bt_hci_cmd_write_voice_setting *wvs;
	const struct bt_hci_cmd_write_inquiry_mode *wim;
	const struct bt_hci_cmd_write_afh_assessment_mode *waam;
	const struct bt_hci_cmd_write_ext_inquiry_response *weir;
	const struct bt_hci_cmd_write_simple_pairing_mode *wspm;
	const struct bt_hci_cmd_write_le_host_supported *wlhs;
	const struct bt_hci_cmd_set_event_mask_page2 *semp2;
	const struct bt_hci_cmd_le_set_event_mask *lsem;
	const struct bt_hci_cmd_le_set_adv_data *lsad;
	const struct bt_hci_cmd_setup_sync_conn *ssc;
	const struct bt_hci_cmd_le_set_adv_enable *lsae;
	const struct bt_hci_cmd_le_set_scan_enable *lsse;
	const struct bt_hci_cmd_read_local_amp_assoc *rlaa_cmd;
	struct bt_hci_rsp_read_default_link_policy rdlp;
	struct bt_hci_rsp_read_stored_link_key rslk;
	struct bt_hci_rsp_write_stored_link_key wslk;
	struct bt_hci_rsp_delete_stored_link_key dslk;
	struct bt_hci_rsp_read_local_name rln;
	struct bt_hci_rsp_read_conn_accept_timeout rcat;
	struct bt_hci_rsp_read_page_timeout rpt;
	struct bt_hci_rsp_read_scan_enable rse;
	struct bt_hci_rsp_read_page_scan_activity rpsa;
	struct bt_hci_rsp_read_inquiry_scan_activity risa;
	struct bt_hci_rsp_read_page_scan_type rpst;
	struct bt_hci_rsp_read_auth_enable rae;
	struct bt_hci_rsp_read_class_of_dev rcod;
	struct bt_hci_rsp_read_voice_setting rvs;
	struct bt_hci_rsp_read_num_supported_iac rnsi;
	struct bt_hci_rsp_read_current_iac_lap *rcil;
	struct bt_hci_rsp_read_inquiry_mode rim;
	struct bt_hci_rsp_read_afh_assessment_mode raam;
	struct bt_hci_rsp_read_ext_inquiry_response reir;
	struct bt_hci_rsp_read_simple_pairing_mode rspm;
	struct bt_hci_rsp_read_local_oob_data rlod;
	struct bt_hci_rsp_read_inquiry_resp_tx_power rirtp;
	struct bt_hci_rsp_read_le_host_supported rlhs;
	struct bt_hci_rsp_read_sync_train_params rstp;
	struct bt_hci_rsp_read_local_version rlv;
	struct bt_hci_rsp_read_local_commands rlc;
	struct bt_hci_rsp_read_local_features rlf;
	struct bt_hci_rsp_read_local_ext_features rlef;
	struct bt_hci_rsp_read_buffer_size rbs;
	struct bt_hci_rsp_read_country_code rcc;
	struct bt_hci_rsp_read_bd_addr rba;
	struct bt_hci_rsp_read_data_block_size rdbs;
	struct bt_hci_rsp_read_local_amp_info rlai;
	struct bt_hci_rsp_read_local_amp_assoc rlaa_rsp;
	struct bt_hci_rsp_le_read_buffer_size lrbs;
	struct bt_hci_rsp_le_read_local_features lrlf;
	struct bt_hci_rsp_le_read_adv_tx_power lratp;
	struct bt_hci_rsp_le_read_supported_states lrss;
	struct bt_hci_rsp_le_read_white_list_size lrwls;
	struct bt_hci_rsp_le_rand lr;
	struct bt_hci_rsp_le_test_end lte;
	struct bt_hci_rsp_remote_name_request_cancel rnrc_rsp;
	uint8_t status, page;

	switch (opcode) {
	case BT_HCI_CMD_INQUIRY:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		cmd_status(btdev, BT_HCI_ERR_SUCCESS, opcode);
		break;

	case BT_HCI_CMD_INQUIRY_CANCEL:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_CREATE_CONN:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		cmd_status(btdev, BT_HCI_ERR_SUCCESS, opcode);
		break;

	case BT_HCI_CMD_DISCONNECT:
		cmd_status(btdev, BT_HCI_ERR_SUCCESS, opcode);
		break;

	case BT_HCI_CMD_CREATE_CONN_CANCEL:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		cmd_status(btdev, BT_HCI_ERR_SUCCESS, opcode);
		break;

	case BT_HCI_CMD_ACCEPT_CONN_REQUEST:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		cmd_status(btdev, BT_HCI_ERR_SUCCESS, opcode);
		break;

	case BT_HCI_CMD_REJECT_CONN_REQUEST:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		cmd_status(btdev, BT_HCI_ERR_SUCCESS, opcode);
		break;

	case BT_HCI_CMD_REMOTE_NAME_REQUEST:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		cmd_status(btdev, BT_HCI_ERR_SUCCESS, opcode);
		break;

	case BT_HCI_CMD_REMOTE_NAME_REQUEST_CANCEL:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rnrc = data;
		rnrc_rsp.status = BT_HCI_ERR_SUCCESS;
		memcpy(rnrc_rsp.bdaddr, rnrc->bdaddr, 6);
		cmd_complete(btdev, opcode, &rnrc_rsp, sizeof(rnrc_rsp));
		break;

	case BT_HCI_CMD_READ_REMOTE_FEATURES:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		cmd_status(btdev, BT_HCI_ERR_SUCCESS, opcode);
		break;

	case BT_HCI_CMD_READ_REMOTE_EXT_FEATURES:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		cmd_status(btdev, BT_HCI_ERR_SUCCESS, opcode);
		break;

	case BT_HCI_CMD_READ_REMOTE_VERSION:
		cmd_status(btdev, BT_HCI_ERR_SUCCESS, opcode);
		break;

	case BT_HCI_CMD_READ_DEFAULT_LINK_POLICY:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rdlp.status = BT_HCI_ERR_SUCCESS;
		rdlp.policy = cpu_to_le16(btdev->default_link_policy);
		cmd_complete(btdev, opcode, &rdlp, sizeof(rdlp));
		break;

	case BT_HCI_CMD_WRITE_DEFAULT_LINK_POLICY:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		wdlp = data;
		btdev->default_link_policy = le16_to_cpu(wdlp->policy);
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_SET_EVENT_MASK:
		sem = data;
		memcpy(btdev->event_mask, sem->mask, 8);
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_RESET:
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_SET_EVENT_FILTER:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		sef = data;
		btdev->event_filter = sef->type;
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_STORED_LINK_KEY:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rslk.status = BT_HCI_ERR_SUCCESS;
		rslk.max_num_keys = cpu_to_le16(0);
		rslk.num_keys = cpu_to_le16(0);
		cmd_complete(btdev, opcode, &rslk, sizeof(rslk));
		break;

	case BT_HCI_CMD_WRITE_STORED_LINK_KEY:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		wslk.status = BT_HCI_ERR_SUCCESS;
		wslk.num_keys = 0;
		cmd_complete(btdev, opcode, &wslk, sizeof(wslk));
		break;

	case BT_HCI_CMD_DELETE_STORED_LINK_KEY:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		dslk.status = BT_HCI_ERR_SUCCESS;
		dslk.num_keys = cpu_to_le16(0);
		cmd_complete(btdev, opcode, &dslk, sizeof(dslk));
		break;

	case BT_HCI_CMD_WRITE_LOCAL_NAME:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		wln = data;
		memcpy(btdev->name, wln->name, 248);
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_LOCAL_NAME:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rln.status = BT_HCI_ERR_SUCCESS;
		memcpy(rln.name, btdev->name, 248);
		cmd_complete(btdev, opcode, &rln, sizeof(rln));
		break;

	case BT_HCI_CMD_READ_CONN_ACCEPT_TIMEOUT:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rcat.status = BT_HCI_ERR_SUCCESS;
		rcat.timeout = cpu_to_le16(btdev->conn_accept_timeout);
		cmd_complete(btdev, opcode, &rcat, sizeof(rcat));
		break;

	case BT_HCI_CMD_WRITE_CONN_ACCEPT_TIMEOUT:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		wcat = data;
		btdev->conn_accept_timeout = le16_to_cpu(wcat->timeout);
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_PAGE_TIMEOUT:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rpt.status = BT_HCI_ERR_SUCCESS;
		rpt.timeout = cpu_to_le16(btdev->page_timeout);
		cmd_complete(btdev, opcode, &rpt, sizeof(rpt));
		break;

	case BT_HCI_CMD_WRITE_PAGE_TIMEOUT:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		wpt = data;
		btdev->page_timeout = le16_to_cpu(wpt->timeout);
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_SCAN_ENABLE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rse.status = BT_HCI_ERR_SUCCESS;
		rse.enable = btdev->scan_enable;
		cmd_complete(btdev, opcode, &rse, sizeof(rse));
		break;

	case BT_HCI_CMD_WRITE_SCAN_ENABLE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		wse = data;
		btdev->scan_enable = wse->enable;
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_PAGE_SCAN_ACTIVITY:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rpsa.status = BT_HCI_ERR_SUCCESS;
		rpsa.interval = cpu_to_le16(btdev->page_scan_interval);
		rpsa.window = cpu_to_le16(btdev->page_scan_window);
		cmd_complete(btdev, opcode, &rpsa, sizeof(rpsa));
		break;

	case BT_HCI_CMD_WRITE_PAGE_SCAN_ACTIVITY:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		wpsa = data;
		btdev->page_scan_interval = le16_to_cpu(wpsa->interval);
		btdev->page_scan_window = le16_to_cpu(wpsa->window);
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_INQUIRY_SCAN_ACTIVITY:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		risa.status = BT_HCI_ERR_SUCCESS;
		risa.interval = cpu_to_le16(btdev->inquiry_scan_interval);
		risa.window = cpu_to_le16(btdev->inquiry_scan_window);
		cmd_complete(btdev, opcode, &risa, sizeof(risa));
		break;

	case BT_HCI_CMD_WRITE_INQUIRY_SCAN_ACTIVITY:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		wisa = data;
		btdev->inquiry_scan_interval = le16_to_cpu(wisa->interval);
		btdev->inquiry_scan_window = le16_to_cpu(wisa->window);
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_PAGE_SCAN_TYPE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rpst.status = BT_HCI_ERR_SUCCESS;
		rpst.type = btdev->page_scan_type;
		cmd_complete(btdev, opcode, &rpst, sizeof(rpst));
		break;

	case BT_HCI_CMD_WRITE_PAGE_SCAN_TYPE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		wpst = data;
		btdev->page_scan_type = wpst->type;
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_AUTH_ENABLE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rae.status = BT_HCI_ERR_SUCCESS;
		rae.enable = btdev->auth_enable;
		cmd_complete(btdev, opcode, &rae, sizeof(rae));
		break;

	case BT_HCI_CMD_WRITE_AUTH_ENABLE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		wae = data;
		btdev->auth_enable = wae->enable;
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_CLASS_OF_DEV:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rcod.status = BT_HCI_ERR_SUCCESS;
		memcpy(rcod.dev_class, btdev->dev_class, 3);
		cmd_complete(btdev, opcode, &rcod, sizeof(rcod));
		break;

	case BT_HCI_CMD_WRITE_CLASS_OF_DEV:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		wcod = data;
		memcpy(btdev->dev_class, wcod->dev_class, 3);
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_VOICE_SETTING:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rvs.status = BT_HCI_ERR_SUCCESS;
		rvs.setting = cpu_to_le16(btdev->voice_setting);
		cmd_complete(btdev, opcode, &rvs, sizeof(rvs));
		break;

	case BT_HCI_CMD_WRITE_VOICE_SETTING:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		wvs = data;
		btdev->voice_setting = le16_to_cpu(wvs->setting);
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_HOST_BUFFER_SIZE:
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_NUM_SUPPORTED_IAC:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rnsi.status = BT_HCI_ERR_SUCCESS;
		rnsi.num_iac = 0x01;
		cmd_complete(btdev, opcode, &rnsi, sizeof(rnsi));
		break;

	case BT_HCI_CMD_READ_CURRENT_IAC_LAP:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rcil = alloca(sizeof(*rcil) + 3);
		rcil->status = BT_HCI_ERR_SUCCESS;
		rcil->num_iac = 0x01;
		rcil->iac_lap[0] = 0x33;
		rcil->iac_lap[1] = 0x8b;
		rcil->iac_lap[2] = 0x9e;
		cmd_complete(btdev, opcode, rcil, sizeof(*rcil) + 3);
		break;

	case BT_HCI_CMD_WRITE_CURRENT_IAC_LAP:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_INQUIRY_MODE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rim.status = BT_HCI_ERR_SUCCESS;
		rim.mode = btdev->inquiry_mode;
		cmd_complete(btdev, opcode, &rim, sizeof(rim));
		break;

	case BT_HCI_CMD_WRITE_INQUIRY_MODE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		wim = data;
		btdev->inquiry_mode = wim->mode;
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_AFH_ASSESSMENT_MODE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		raam.status = BT_HCI_ERR_SUCCESS;
		raam.mode = btdev->afh_assessment_mode;
		cmd_complete(btdev, opcode, &raam, sizeof(raam));
		break;

	case BT_HCI_CMD_WRITE_AFH_ASSESSMENT_MODE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		waam = data;
		btdev->afh_assessment_mode = waam->mode;
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_EXT_INQUIRY_RESPONSE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		reir.status = BT_HCI_ERR_SUCCESS;
		reir.fec = btdev->ext_inquiry_fec;
		memcpy(reir.data, btdev->ext_inquiry_rsp, 240);
		cmd_complete(btdev, opcode, &reir, sizeof(reir));
		break;

	case BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		weir = data;
		btdev->ext_inquiry_fec = weir->fec;
		memcpy(btdev->ext_inquiry_rsp, weir->data, 240);
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_SIMPLE_PAIRING_MODE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rspm.status = BT_HCI_ERR_SUCCESS;
		rspm.mode = btdev->simple_pairing_mode;
		cmd_complete(btdev, opcode, &rspm, sizeof(rspm));
		break;

	case BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		wspm = data;
		btdev->simple_pairing_mode = wspm->mode;
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_LOCAL_OOB_DATA:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rlod.status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &rlod, sizeof(rlod));
		break;

	case BT_HCI_CMD_READ_INQUIRY_RESP_TX_POWER:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rirtp.status = BT_HCI_ERR_SUCCESS;
		rirtp.level = 0;
		cmd_complete(btdev, opcode, &rirtp, sizeof(rirtp));
		break;

	case BT_HCI_CMD_READ_LE_HOST_SUPPORTED:
		if (btdev->type != BTDEV_TYPE_BREDRLE)
			goto unsupported;
		rlhs.status = BT_HCI_ERR_SUCCESS;
		rlhs.supported = btdev->le_supported;
		rlhs.simultaneous = btdev->le_simultaneous;
		cmd_complete(btdev, opcode, &rlhs, sizeof(rlhs));
		break;

	case BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED:
		if (btdev->type != BTDEV_TYPE_BREDRLE)
			goto unsupported;
		wlhs = data;
		btdev->le_supported = wlhs->supported;
		btdev->le_simultaneous = wlhs->simultaneous;
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_READ_SYNC_TRAIN_PARAMS:
		if (btdev->type != BTDEV_TYPE_BREDRLE)
			goto unsupported;
		rstp.status = BT_HCI_ERR_SUCCESS;
		rstp.interval = cpu_to_le16(btdev->sync_train_interval);
		rstp.timeout = cpu_to_le32(btdev->sync_train_timeout);
		rstp.service_data = btdev->sync_train_service_data;
		cmd_complete(btdev, opcode, &rstp, sizeof(rstp));
		break;

	case BT_HCI_CMD_READ_LOCAL_VERSION:
		rlv.status = BT_HCI_ERR_SUCCESS;
		rlv.hci_ver = btdev->version;
		rlv.hci_rev = cpu_to_le16(btdev->revision);
		rlv.lmp_ver = btdev->version;
		rlv.manufacturer = cpu_to_le16(btdev->manufacturer);
		rlv.lmp_subver = cpu_to_le16(btdev->revision);
		cmd_complete(btdev, opcode, &rlv, sizeof(rlv));
		break;

	case BT_HCI_CMD_READ_LOCAL_COMMANDS:
		rlc.status = BT_HCI_ERR_SUCCESS;
		memcpy(rlc.commands, btdev->commands, 64);
		cmd_complete(btdev, opcode, &rlc, sizeof(rlc));
		break;

	case BT_HCI_CMD_READ_LOCAL_FEATURES:
		rlf.status = BT_HCI_ERR_SUCCESS;
		memcpy(rlf.features, btdev->features, 8);
		cmd_complete(btdev, opcode, &rlf, sizeof(rlf));
		break;

	case BT_HCI_CMD_READ_LOCAL_EXT_FEATURES:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;

		page = ((const uint8_t *) data)[0];

		rlef.page = page;
		rlef.max_page = btdev->max_page;

		if (page > btdev->max_page) {
			rlef.status = BT_HCI_ERR_INVALID_PARAMETERS;
			memset(rlef.features, 0, 8);
			cmd_complete(btdev, opcode, &rlef, sizeof(rlef));
			break;
		}

		switch (page) {
		case 0x00:
			rlef.status = BT_HCI_ERR_SUCCESS;
			memcpy(rlef.features, btdev->features, 8);
			break;
		case 0x01:
			rlef.status = BT_HCI_ERR_SUCCESS;
			memset(rlef.features, 0, 8);
			if (btdev->simple_pairing_mode)
				rlef.features[0] |= 0x01;
			if (btdev->le_supported)
				rlef.features[0] |= 0x02;
			if (btdev->le_simultaneous)
				rlef.features[0] |= 0x04;
			break;
		case 0x02:
			rlef.status = BT_HCI_ERR_SUCCESS;
			memcpy(rlef.features, btdev->feat_page_2, 8);
			break;
		default:
			rlef.status = BT_HCI_ERR_INVALID_PARAMETERS;
			memset(rlef.features, 0, 8);
			break;
		}
		cmd_complete(btdev, opcode, &rlef, sizeof(rlef));
		break;

	case BT_HCI_CMD_READ_BUFFER_SIZE:
		rbs.status = BT_HCI_ERR_SUCCESS;
		rbs.acl_mtu = cpu_to_le16(btdev->acl_mtu);
		rbs.sco_mtu = 0;
		rbs.acl_max_pkt = cpu_to_le16(btdev->acl_max_pkt);
		rbs.sco_max_pkt = cpu_to_le16(0);
		cmd_complete(btdev, opcode, &rbs, sizeof(rbs));
		break;

	case BT_HCI_CMD_READ_COUNTRY_CODE:
		rcc.status = BT_HCI_ERR_SUCCESS;
		rcc.code = btdev->country_code;
		cmd_complete(btdev, opcode, &rcc, sizeof(rcc));
		break;

	case BT_HCI_CMD_READ_BD_ADDR:
		rba.status = BT_HCI_ERR_SUCCESS;
		memcpy(rba.bdaddr, btdev->bdaddr, 6);
		cmd_complete(btdev, opcode, &rba, sizeof(rba));
		break;

	case BT_HCI_CMD_READ_DATA_BLOCK_SIZE:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		rdbs.status = BT_HCI_ERR_SUCCESS;
		rdbs.max_acl_len = cpu_to_le16(btdev->acl_mtu);
		rdbs.block_len = cpu_to_le16(btdev->acl_mtu);
		rdbs.num_blocks = cpu_to_le16(btdev->acl_max_pkt);
		cmd_complete(btdev, opcode, &rdbs, sizeof(rdbs));
		break;

	case BT_HCI_CMD_READ_LOCAL_AMP_INFO:
		if (btdev->type != BTDEV_TYPE_AMP)
			goto unsupported;
		rlai.status = BT_HCI_ERR_SUCCESS;
		rlai.amp_status = 0x01;		/* Used for Bluetooth only */
		rlai.total_bw = cpu_to_le32(0);
		rlai.max_bw = cpu_to_le32(0);
		rlai.min_latency = cpu_to_le32(0);
		rlai.max_pdu = cpu_to_le32(672);
		rlai.amp_type = 0x01;		/* 802.11 AMP Controller */
		rlai.pal_cap = cpu_to_le16(0x0000);
		rlai.max_assoc_len = cpu_to_le16(672);
		rlai.max_flush_to = cpu_to_le32(0xffffffff);
		rlai.be_flush_to = cpu_to_le32(0xffffffff);
		cmd_complete(btdev, opcode, &rlai, sizeof(rlai));
		break;

	case BT_HCI_CMD_READ_LOCAL_AMP_ASSOC:
		if (btdev->type != BTDEV_TYPE_AMP)
			goto unsupported;
		rlaa_cmd = data;
		rlaa_rsp.status = BT_HCI_ERR_SUCCESS;
		rlaa_rsp.phy_handle = rlaa_cmd->phy_handle;
		rlaa_rsp.remain_assoc_len = cpu_to_le16(1);
		rlaa_rsp.assoc_fragment[0] = 0x42;
		memset(rlaa_rsp.assoc_fragment + 1, 0,
					sizeof(rlaa_rsp.assoc_fragment) - 1);
		cmd_complete(btdev, opcode, &rlaa_rsp, sizeof(rlaa_rsp));
		break;

	case BT_HCI_CMD_SET_EVENT_MASK_PAGE2:
		if (btdev->type != BTDEV_TYPE_BREDRLE)
			goto unsupported;
		semp2 = data;
		memcpy(btdev->event_mask_page2, semp2->mask, 8);
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_LE_SET_EVENT_MASK:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		lsem = data;
		memcpy(btdev->le_event_mask, lsem->mask, 8);
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_LE_READ_BUFFER_SIZE:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		lrbs.status = BT_HCI_ERR_SUCCESS;
		lrbs.le_mtu = cpu_to_le16(btdev->acl_mtu);
		lrbs.le_max_pkt = btdev->acl_max_pkt;
		cmd_complete(btdev, opcode, &lrbs, sizeof(lrbs));
		break;

	case BT_HCI_CMD_LE_READ_LOCAL_FEATURES:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		lrlf.status = BT_HCI_ERR_SUCCESS;
		memcpy(lrlf.features, btdev->le_features, 8);
		cmd_complete(btdev, opcode, &lrlf, sizeof(lrlf));
		break;

	case BT_HCI_CMD_LE_SET_ADV_PARAMETERS:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		if (btdev->le_adv_enable)
			status = BT_HCI_ERR_COMMAND_DISALLOWED;
		else
			status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_LE_READ_ADV_TX_POWER:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		lratp.status = BT_HCI_ERR_SUCCESS;
		lratp.level = 0;
		cmd_complete(btdev, opcode, &lratp, sizeof(lratp));
		break;

	case BT_HCI_CMD_LE_SET_ADV_ENABLE:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		lsae = data;
		if (btdev->le_adv_enable == lsae->enable)
			status = BT_HCI_ERR_COMMAND_DISALLOWED;
		else {
			btdev->le_adv_enable = lsae->enable;
			status = BT_HCI_ERR_SUCCESS;
		}
		cmd_complete(btdev, opcode, &status, sizeof(status));
		if (status == BT_HCI_ERR_SUCCESS && btdev->le_adv_enable)
			le_set_adv_enable_complete(btdev);
		break;

	case BT_HCI_CMD_LE_SET_SCAN_PARAMETERS:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		if (btdev->le_scan_enable)
			status = BT_HCI_ERR_COMMAND_DISALLOWED;
		else
			status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_LE_SET_SCAN_ENABLE:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		lsse = data;
		if (btdev->le_scan_enable == lsse->enable)
			status = BT_HCI_ERR_COMMAND_DISALLOWED;
		else {
			btdev->le_scan_enable = lsse->enable;
			btdev->le_filter_dup = lsse->filter_dup;
			status = BT_HCI_ERR_SUCCESS;
		}
		cmd_complete(btdev, opcode, &status, sizeof(status));
		if (status == BT_HCI_ERR_SUCCESS && btdev->le_scan_enable)
			le_set_scan_enable_complete(btdev);
		break;

	case BT_HCI_CMD_LE_CREATE_CONN:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		cmd_status(btdev, BT_HCI_ERR_SUCCESS, opcode);
		break;

	case BT_HCI_CMD_LE_READ_WHITE_LIST_SIZE:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		lrwls.status = BT_HCI_ERR_SUCCESS;
		lrwls.size = 0;
		cmd_complete(btdev, opcode, &lrwls, sizeof(lrwls));
		break;

	case BT_HCI_CMD_LE_READ_SUPPORTED_STATES:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		lrss.status = BT_HCI_ERR_SUCCESS;
		memcpy(lrss.states, btdev->le_states, 8);
		cmd_complete(btdev, opcode, &lrss, sizeof(lrss));
		break;

	case BT_HCI_CMD_LE_SET_ADV_DATA:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		lsad = data;
		btdev->le_adv_data_len = lsad->len;
		memcpy(btdev->le_adv_data, lsad->data, 31);
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_LE_RAND:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		lr.status = BT_HCI_ERR_SUCCESS;
		lr.number[0] = rand();
		lr.number[1] = rand();
		lr.number[2] = rand();
		lr.number[3] = rand();
		lr.number[4] = rand();
		lr.number[5] = rand();
		lr.number[6] = rand();
		lr.number[7] = rand();
		cmd_complete(btdev, opcode, &lr, sizeof(lr));
		break;

	case BT_HCI_CMD_SETUP_SYNC_CONN:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		ssc = data;
		status = BT_HCI_ERR_SUCCESS;
		cmd_status(btdev, BT_HCI_ERR_SUCCESS, opcode);
		sync_conn_complete(btdev, ssc->voice_setting,
							BT_HCI_ERR_SUCCESS);
		break;

	case BT_HCI_CMD_ADD_SCO_CONN:
		if (btdev->type == BTDEV_TYPE_LE)
			goto unsupported;
		sco_conn_complete(btdev, BT_HCI_ERR_SUCCESS);
		break;

	case BT_HCI_CMD_ENABLE_DUT_MODE:
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_LE_RECEIVER_TEST:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_LE_TRANSMITTER_TEST:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		status = BT_HCI_ERR_SUCCESS;
		cmd_complete(btdev, opcode, &status, sizeof(status));
		break;

	case BT_HCI_CMD_LE_TEST_END:
		if (btdev->type == BTDEV_TYPE_BREDR)
			goto unsupported;
		lte.status = BT_HCI_ERR_SUCCESS;
		lte.num_packets = 0;
		cmd_complete(btdev, opcode, &lte, sizeof(lte));
		break;

	default:
		goto unsupported;
	}

	return;

unsupported:
	printf("Unsupported command 0x%4.4x\n", opcode);
	hexdump(data, len);
	cmd_status(btdev, BT_HCI_ERR_UNKNOWN_COMMAND, opcode);
}

static void default_cmd_completion(struct btdev *btdev, uint16_t opcode,
						const void *data, uint8_t len)
{
	const struct bt_hci_cmd_create_conn *cc;
	const struct bt_hci_cmd_disconnect *dc;
	const struct bt_hci_cmd_create_conn_cancel *ccc;
	const struct bt_hci_cmd_accept_conn_request *acr;
	const struct bt_hci_cmd_reject_conn_request *rcr;
	const struct bt_hci_cmd_remote_name_request *rnr;
	const struct bt_hci_cmd_remote_name_request_cancel *rnrc;
	const struct bt_hci_cmd_read_remote_features *rrf;
	const struct bt_hci_cmd_read_remote_ext_features *rref;
	const struct bt_hci_cmd_read_remote_version *rrv;
	const struct bt_hci_cmd_le_create_conn *lecc;

	switch (opcode) {
	case BT_HCI_CMD_INQUIRY:
		if (btdev->type == BTDEV_TYPE_LE)
			return;
		inquiry_complete(btdev, BT_HCI_ERR_SUCCESS);
		break;

	case BT_HCI_CMD_CREATE_CONN:
		if (btdev->type == BTDEV_TYPE_LE)
			return;
		cc = data;
		conn_request(btdev, cc->bdaddr);
		break;

	case BT_HCI_CMD_DISCONNECT:
		dc = data;
		disconnect_complete(btdev, le16_to_cpu(dc->handle), dc->reason);
		break;

	case BT_HCI_CMD_CREATE_CONN_CANCEL:
		if (btdev->type == BTDEV_TYPE_LE)
			return;
		ccc = data;
		conn_complete(btdev, ccc->bdaddr, BT_HCI_ERR_UNKNOWN_CONN_ID);
		break;

	case BT_HCI_CMD_ACCEPT_CONN_REQUEST:
		if (btdev->type == BTDEV_TYPE_LE)
			return;
		acr = data;
		conn_complete(btdev, acr->bdaddr, BT_HCI_ERR_SUCCESS);
		break;

	case BT_HCI_CMD_REJECT_CONN_REQUEST:
		if (btdev->type == BTDEV_TYPE_LE)
			return;
		rcr = data;
		conn_complete(btdev, rcr->bdaddr, BT_HCI_ERR_UNKNOWN_CONN_ID);
		break;

	case BT_HCI_CMD_REMOTE_NAME_REQUEST:
		if (btdev->type == BTDEV_TYPE_LE)
			return;
		rnr = data;
		name_request_complete(btdev, rnr->bdaddr, BT_HCI_ERR_SUCCESS);
		break;

	case BT_HCI_CMD_REMOTE_NAME_REQUEST_CANCEL:
		if (btdev->type == BTDEV_TYPE_LE)
			return;
		rnrc = data;
		name_request_complete(btdev, rnrc->bdaddr,
						BT_HCI_ERR_UNKNOWN_CONN_ID);
		break;

	case BT_HCI_CMD_READ_REMOTE_FEATURES:
		if (btdev->type == BTDEV_TYPE_LE)
			return;
		rrf = data;
		remote_features_complete(btdev, le16_to_cpu(rrf->handle));
		break;

	case BT_HCI_CMD_READ_REMOTE_EXT_FEATURES:
		if (btdev->type == BTDEV_TYPE_LE)
			return;
		rref = data;
		remote_ext_features_complete(btdev, le16_to_cpu(rref->handle),
								rref->page);
		break;

	case BT_HCI_CMD_READ_REMOTE_VERSION:
		rrv = data;
		remote_version_complete(btdev, le16_to_cpu(rrv->handle));
		break;

	case BT_HCI_CMD_LE_CREATE_CONN:
		if (btdev->type == BTDEV_TYPE_BREDR)
			return;
		lecc = data;
		le_conn_request(btdev, lecc->peer_addr);
		break;
	}
}

struct btdev_callback {
	void (*function)(btdev_callback callback, uint8_t response,
				uint8_t status, const void *data, uint8_t len);
	void *user_data;
	uint16_t opcode;
	const void *data;
	uint8_t len;
};

void btdev_command_response(btdev_callback callback, uint8_t response,
                                uint8_t status, const void *data, uint8_t len)
{
	callback->function(callback, response, status, data, len);
}

static void handler_callback(btdev_callback callback, uint8_t response,
				uint8_t status, const void *data, uint8_t len)
{
	struct btdev *btdev = callback->user_data;

	switch (response) {
	case BTDEV_RESPONSE_DEFAULT:
		if (!run_hooks(btdev, BTDEV_HOOK_PRE_CMD, callback->opcode,
						callback->data, callback->len))
			return;
		default_cmd(btdev, callback->opcode,
					callback->data, callback->len);

		if (!run_hooks(btdev, BTDEV_HOOK_PRE_EVT, callback->opcode,
						callback->data, callback->len))
			return;
		default_cmd_completion(btdev, callback->opcode,
					callback->data, callback->len);
		break;
	case BTDEV_RESPONSE_COMMAND_STATUS:
		cmd_status(btdev, status, callback->opcode);
		break;
	case BTDEV_RESPONSE_COMMAND_COMPLETE:
		cmd_complete(btdev, callback->opcode, data, len);
		break;
	default:
		cmd_status(btdev, BT_HCI_ERR_UNKNOWN_COMMAND,
						callback->opcode);
		break;
	}
}

static void process_cmd(struct btdev *btdev, const void *data, uint16_t len)
{
	struct btdev_callback callback;
	const struct bt_hci_cmd_hdr *hdr = data;

	if (len < sizeof(*hdr))
		return;

	callback.function = handler_callback;
	callback.user_data = btdev;
	callback.opcode = le16_to_cpu(hdr->opcode);
	callback.data = data + sizeof(*hdr);
	callback.len = hdr->plen;

	if (btdev->command_handler)
		btdev->command_handler(callback.opcode,
					callback.data, callback.len,
					&callback, btdev->command_data);
	else {
		if (!run_hooks(btdev, BTDEV_HOOK_PRE_CMD, callback.opcode,
						callback.data, callback.len))
			return;
		default_cmd(btdev, callback.opcode,
					callback.data, callback.len);

		if (!run_hooks(btdev, BTDEV_HOOK_PRE_EVT, callback.opcode,
						callback.data, callback.len))
			return;
		default_cmd_completion(btdev, callback.opcode,
					callback.data, callback.len);
	}
}

void btdev_receive_h4(struct btdev *btdev, const void *data, uint16_t len)
{
	uint8_t pkt_type;

	if (!btdev)
		return;

	if (len < 1)
		return;

	pkt_type = ((const uint8_t *) data)[0];

	switch (pkt_type) {
	case BT_H4_CMD_PKT:
		process_cmd(btdev, data + 1, len - 1);
		break;
	case BT_H4_ACL_PKT:
		if (btdev->conn)
			send_packet(btdev->conn, data, len);
		num_completed_packets(btdev);
		break;
	default:
		printf("Unsupported packet 0x%2.2x\n", pkt_type);
		break;
	}
}

int btdev_add_hook(struct btdev *btdev, enum btdev_hook_type type,
				uint16_t opcode, btdev_hook_func handler,
				void *user_data)
{
	int i;

	if (!btdev)
		return -1;

	if (get_hook_index(btdev, type, opcode) > 0)
		return -1;

	for (i = 0; i < MAX_HOOK_ENTRIES; i++) {
		if (btdev->hook_list[i] == NULL) {
			btdev->hook_list[i] = malloc(sizeof(struct hook));
			if (btdev->hook_list[i] == NULL)
				return -1;

			btdev->hook_list[i]->handler = handler;
			btdev->hook_list[i]->user_data = user_data;
			btdev->hook_list[i]->opcode = opcode;
			btdev->hook_list[i]->type = type;
			return i;
		}
	}

	return -1;
}

bool btdev_del_hook(struct btdev *btdev, enum btdev_hook_type type,
								uint16_t opcode)
{
	int i;

	if (!btdev)
		return false;

	for (i = 0; i < MAX_HOOK_ENTRIES; i++) {
		if (btdev->hook_list[i] == NULL)
			continue;

		if (btdev->hook_list[i]->type != type ||
					btdev->hook_list[i]->opcode != opcode)
			continue;

		free(btdev->hook_list[i]);
		btdev->hook_list[i] = NULL;

		return true;
	}

	return false;
}
