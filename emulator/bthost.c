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

#include "monitor/bt.h"
#include "bthost.h"

#define le16_to_cpu(val) (val)
#define le32_to_cpu(val) (val)
#define cpu_to_le16(val) (val)
#define cpu_to_le32(val) (val)

struct bthost {
	bthost_send_func send_handler;
	void *send_data;
};

struct bthost *bthost_create(void)
{
	struct bthost *bthost;

	bthost = malloc(sizeof(*bthost));
	if (!bthost)
		return NULL;

	memset(bthost, 0, sizeof(*bthost));

	return bthost;
}

void bthost_destroy(struct bthost *bthost)
{
	if (!bthost)
		return;

	free(bthost);
}

void bthost_set_send_handler(struct bthost *bthost, bthost_send_func handler,
							void *user_data)
{
	if (!bthost)
		return;

	bthost->send_handler = handler;
	bthost->send_data = user_data;
}

static void send_packet(struct bthost *bthost, const void *data, uint16_t len)
{
	if (!bthost->send_handler)
		return;

	bthost->send_handler(data, len, bthost->send_data);
}

static void send_command(struct bthost *bthost, uint16_t opcode,
						const void *data, uint8_t len)
{
	struct bt_hci_cmd_hdr *hdr;
	uint16_t pkt_len;
	void *pkt_data;

	pkt_len = 1 + sizeof(*hdr) + len;

	pkt_data = malloc(pkt_len);
	if (!pkt_data)
		return;

	((uint8_t *) pkt_data)[0] = BT_H4_CMD_PKT;

	hdr = pkt_data + 1;
	hdr->opcode = cpu_to_le16(opcode);
	hdr->plen = len;

	if (len > 0)
		memcpy(pkt_data + 1 + sizeof(*hdr), data, len);

	send_packet(bthost, pkt_data, pkt_len);

	free(pkt_data);
}

static void process_evt(struct bthost *bthost, const void *data, uint16_t len)
{
	const struct bt_hci_evt_hdr *hdr = data;

	if (len < sizeof(*hdr))
		return;

	switch (hdr->evt) {
	case BT_HCI_EVT_CMD_COMPLETE:
		break;

	case BT_HCI_EVT_CMD_STATUS:
		break;

	default:
		printf("Unsupported event 0x%2.2x\n", hdr->evt);
		break;
	}
}

void bthost_receive_h4(struct bthost *bthost, const void *data, uint16_t len)
{
	uint8_t pkt_type;

	if (!bthost)
		return;

	if (len < 1)
		return;

	pkt_type = ((const uint8_t *) data)[0];

	switch (pkt_type) {
	case BT_H4_EVT_PKT:
		process_evt(bthost, data + 1, len - 1);
		break;
	default:
		printf("Unsupported packet 0x%2.2x\n", pkt_type);
		break;
	}
}

void bthost_start(struct bthost *bthost)
{
	if (!bthost)
		return;

	send_command(bthost, BT_HCI_CMD_RESET, NULL, 0);
}

void bthost_stop(struct bthost *bthost)
{
}
