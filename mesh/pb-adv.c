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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>

#include "mesh/mesh-defs.h"
#include "mesh/crypto.h"
#include "mesh/net.h"
#include "mesh/mesh-io.h"
#include "mesh/mesh.h"
#include "mesh/prov.h"
#include "mesh/provision.h"
#include "mesh/pb-adv.h"


struct pb_adv_session {
	mesh_prov_open_func_t open_cb;
	mesh_prov_close_func_t close_cb;
	mesh_prov_receive_func_t rx_cb;
	mesh_prov_ack_func_t ack_cb;
	struct l_timeout *tx_timeout;
	uint32_t link_id;
	uint16_t exp_len;
	uint8_t exp_fcs;
	uint8_t exp_segs;
	uint8_t got_segs;
	uint8_t trans_num;
	uint8_t local_acked;
	uint8_t local_trans_num;
	uint8_t peer_trans_num;
	uint8_t last_peer_trans_num;
	uint8_t sar[80];
	uint8_t uuid[16];
	bool initiator;
	bool opened;
	void *user_data;
};

#define PB_ADV_ACK 0x01
#define PB_ADV_OPEN_REQ 0x03
#define PB_ADV_OPEN_CFM 0x07
#define PB_ADV_CLOSE 0x0B

#define PB_ADV_MTU	24

struct pb_ack {
	uint8_t ad_type;
	uint32_t link_id;
	uint8_t trans_num;
	uint8_t opcode;
} __packed;

struct pb_open_req{
	uint8_t ad_type;
	uint32_t link_id;
	uint8_t trans_num;
	uint8_t opcode;
	uint8_t uuid[16];
} __packed;

struct pb_open_cfm{
	uint8_t ad_type;
	uint32_t link_id;
	uint8_t trans_num;
	uint8_t opcode;
} __packed;

struct pb_close_ind {
	uint8_t ad_type;
	uint32_t link_id;
	uint8_t trans_num;
	uint8_t opcode;
	uint8_t reason;
} __packed;

static struct pb_adv_session *pb_session = NULL;

static const uint8_t filter[1] = { MESH_AD_TYPE_PROVISION };

static void send_adv_segs(struct pb_adv_session *session, const uint8_t *data,
							uint16_t size)
{
	uint16_t init_size;
	uint8_t buf[PB_ADV_MTU + 6] = { MESH_AD_TYPE_PROVISION };
	uint8_t max_seg;
	uint8_t consumed;
	int i;

	if (!size)
		return;

	mesh_send_cancel(filter, sizeof(filter));

	l_put_be32(session->link_id, buf + 1);
	buf[1 + 4] = ++session->local_trans_num;

	if (size > PB_ADV_MTU - 4) {
		max_seg = 1 +
			(((size - (PB_ADV_MTU - 4)) - 1) / (PB_ADV_MTU - 1));
		init_size = PB_ADV_MTU - 4;
	} else {
		max_seg = 0;
		init_size = size;
	}

	/* print_packet("FULL-TX", data, size); */

	l_debug("Sending %u fragments for %u octets", max_seg + 1, size);

	buf[6] = max_seg << 2;
	l_put_be16(size, buf + 7);
	buf[9] = mesh_crypto_compute_fcs(data, size);
	memcpy(buf + 10, data, init_size);

	l_debug("max_seg: %2.2x", max_seg);
	l_debug("size: %2.2x, CRC: %2.2x", size, buf[9]);
	/* print_packet("PB-TX", buf + 1, init_size + 9); */
	mesh_send_pkt(MESH_IO_TX_COUNT_UNLIMITED, 200, buf, init_size + 10);

	consumed = init_size;

	for (i = 1; i <= max_seg; i++) {
		uint8_t seg_size; /* Amount of payload data being sent */

		if (size - consumed > PB_ADV_MTU - 1)
			seg_size = PB_ADV_MTU - 1;
		else
			seg_size = size - consumed;

		buf[6] = (i << 2) | 0x02;
		memcpy(buf + 7, data + consumed, seg_size);

		/* print_packet("PB-TX", buf + 1, seg_size + 6); */

		mesh_send_pkt(MESH_IO_TX_COUNT_UNLIMITED, 200,
							buf, seg_size + 7);

		consumed += seg_size;
	}
}

static void tx_timeout(struct l_timeout *timeout, void *user_data)
{
	struct pb_adv_session *session = user_data;
	mesh_prov_close_func_t cb;

	if (!session || pb_session != session)
		return;

	l_timeout_remove(session->tx_timeout);
	session->tx_timeout = NULL;

	mesh_send_cancel(filter, sizeof(filter));

	l_info("TX timeout");
	cb = pb_session->close_cb;
	user_data = pb_session->user_data;
	l_free(pb_session);
	pb_session = NULL;
	cb(user_data, 1);
}

static void pb_adv_tx(void *user_data, void *data, uint16_t len)
{
	struct pb_adv_session *session = user_data;

	if (!session || pb_session != session)
		return;

	l_timeout_remove(session->tx_timeout);
	session->tx_timeout = l_timeout_create(30, tx_timeout, session, NULL);

	send_adv_segs(session, data, len);
}

static void send_open_req(struct pb_adv_session *session)
{
	struct pb_open_req open_req = { MESH_AD_TYPE_PROVISION };

	l_put_be32(session->link_id, &open_req.link_id);
	open_req.trans_num = 0;
	open_req.opcode = PB_ADV_OPEN_REQ;
	memcpy(open_req.uuid, session->uuid, 16);

	mesh_send_cancel(filter, sizeof(filter));
	mesh_send_pkt(MESH_IO_TX_COUNT_UNLIMITED, 500, &open_req,
							sizeof(open_req));
}

static void send_open_cfm(struct pb_adv_session *session)
{
	struct pb_open_cfm open_cfm = { MESH_AD_TYPE_PROVISION };

	l_put_be32(session->link_id, &open_cfm.link_id);
	open_cfm.trans_num = 0;
	open_cfm.opcode = PB_ADV_OPEN_CFM;

	mesh_send_cancel(filter, sizeof(filter));
	mesh_send_pkt(MESH_IO_TX_COUNT_UNLIMITED, 500, &open_cfm,
							sizeof(open_cfm));
}

static void send_ack(struct pb_adv_session *session, uint8_t trans_num)
{
	struct pb_ack ack = { MESH_AD_TYPE_PROVISION };

	l_put_be32(session->link_id, &ack.link_id);
	ack.trans_num = trans_num;
	ack.opcode = PB_ADV_ACK;

	mesh_send_pkt(1, 100, &ack, sizeof(ack));
}

static void send_close_ind(struct pb_adv_session *session, uint8_t reason)
{
	struct pb_close_ind close_ind = { MESH_AD_TYPE_PROVISION };

	if (!pb_session || pb_session != session)
		return;

	l_put_be32(session->link_id, &close_ind.link_id);
	close_ind.trans_num = 0;
	close_ind.opcode = PB_ADV_CLOSE;
	close_ind.reason = reason;

	mesh_send_cancel(filter, sizeof(filter));
	mesh_send_pkt(10, 100, &close_ind, sizeof(close_ind));
}

static void pb_adv_packet(void *user_data, const uint8_t *pkt, uint16_t len)
{
	struct pb_adv_session *session = user_data;
	uint32_t link_id;
	size_t offset;
	uint8_t trans_num;
	uint8_t type;
	bool first;

	if (!session || pb_session != session)
		return;

	link_id = l_get_be32(pkt + 1);
	type = l_get_u8(pkt + 6);

	/* Validate new or existing Connection ID */
	if (session->link_id) {
		if (session->link_id != link_id)
			return;
	} else if (type != 0x03)
		return;
	else if (!link_id)
		return;

	trans_num = l_get_u8(pkt + 5);
	pkt += 7;
	len -= 7;

	switch (type) {
	case PB_ADV_OPEN_CFM:
		/*
		 * Ignore if:
		 * 1. We are acceptor
		 * 2. We are already provisioning on different link_id
		 */

		if (!session->initiator)
			return;

		first = !session->opened;
		session->opened = true;

		/* Only call Open callback once */
		if (first) {
			l_debug("PB-ADV open confirmed");
			session->open_cb(session->user_data, pb_adv_tx,
							session, PB_ADV);
		}
		return;

	case PB_ADV_OPEN_REQ:
		/*
		 * Ignore if:
		 * 1. We are initiator
		 * 2. Open request not addressed to us
		 * 3. We are already provisioning on different link_id
		 */

		if (session->initiator)
			return;

		if (memcmp(pkt, session->uuid, 16))
			return;

		first = !session->link_id;
		session->link_id = link_id;
		session->last_peer_trans_num = 0xFF;
		session->local_acked = 0xFF;
		session->peer_trans_num = 0x00;
		session->local_trans_num = 0x7F;
		session->opened = true;

		/* Only call Open callback once */
		if (first) {
			l_debug("PB-ADV open requested");
			session->open_cb(session->user_data, pb_adv_tx,
							session, PB_ADV);
		}

		/* Send CFM once per received request */
		send_open_cfm(session);
		break;

	case PB_ADV_CLOSE:
		l_timeout_remove(session->tx_timeout);
		l_debug("Link closed notification: %2.2x", pkt[0]);
		/* Wrap callback for pre-cleaning */
		if (true) {
			mesh_prov_close_func_t cb = session->close_cb;
			void *user_data = session->user_data;

			l_free(session);
			pb_session = NULL;
			cb(user_data, pkt[0]);
		}
		break;

	case PB_ADV_ACK:
		if (!session->opened)
			return;

		if (trans_num != session->local_trans_num)
			return;

		if (session->local_acked > trans_num)
			return;

		mesh_send_cancel(filter, sizeof(filter));
		session->local_acked = trans_num;
		session->ack_cb(session->user_data, trans_num);
		break;

	default: /* DATA SEGMENT */
		if (!session->opened)
			return;

		if (trans_num == session->last_peer_trans_num) {
			send_ack(session, trans_num);
			return;
		}

		switch(type & 0x03) {
		case 0x00:
			session->peer_trans_num = trans_num;
			session->exp_len = l_get_be16(pkt);

			l_debug("PB-ADV start with %u fragments, %d octets",
						type >> 2, session->exp_len);

			if (session->exp_len > sizeof(session->sar)) {
				l_debug("Incoming length exceeded: %d",
							session->exp_len);
				return;
			}

			session->exp_fcs = l_get_u8(pkt + 2);
			session->exp_segs = 0xff >> (7 - (type >> 2));

			/* Save first segment */
			memcpy(session->sar, pkt + 3, len - 3);
			session->got_segs |= 1;
			break;

		case 0x02:
			session->peer_trans_num = trans_num;
			offset = 20 + (((type >> 2) - 1) * 23);

			if (offset + len - 3 > sizeof(session->sar)) {
				l_debug("Length exceeded: %d",
							session->exp_len);
				return;
			}

			l_debug("Processing fragment %u", type >> 2);
			memcpy(session->sar + offset, pkt, len);
			session->got_segs |= 1 << (type >> 2);
			break;

		default:
			/* Malformed or unrecognized */
			return;
		}

		if (session->got_segs != session->exp_segs)
			return;

		/* Validate RXed packet and pass up to Provisioning */
		if (!mesh_crypto_check_fcs(session->sar,
					session->exp_len,
					session->exp_fcs)) {

			/* This can be a false negative if first
			 * segment missed, and can almost always
			 * be ignored.
			 */

			l_debug("Invalid FCS");
			return;
		}

		if (session->last_peer_trans_num != session->peer_trans_num) {
			session->got_segs = 0;
			session->rx_cb(session->user_data, session->sar,
							session->exp_len);
		}

		session->last_peer_trans_num = session->peer_trans_num;
		send_ack(session, session->last_peer_trans_num);
	}
}

bool pb_adv_reg(bool initiator, mesh_prov_open_func_t open_cb,
		mesh_prov_close_func_t close_cb,
		mesh_prov_receive_func_t rx_cb, mesh_prov_ack_func_t ack_cb,
		uint8_t uuid[16], void *user_data)
{
	if (pb_session)
		return false;

	pb_session = l_new(struct pb_adv_session, 1);
	pb_session->open_cb = open_cb;
	pb_session->close_cb = close_cb;
	pb_session->rx_cb = rx_cb;
	pb_session->ack_cb = ack_cb;
	pb_session->user_data = user_data;
	pb_session->initiator = initiator;
	memcpy(pb_session->uuid, uuid, 16);

	mesh_reg_prov_rx(pb_adv_packet, pb_session);

	if (initiator) {
		l_getrandom(&pb_session->link_id, sizeof(pb_session->link_id));
		send_open_req(pb_session);
	}

	return true;
}

void pb_adv_unreg(void *user_data)
{
	if (!pb_session || pb_session->user_data != user_data)
		return;

	l_timeout_remove(pb_session->tx_timeout);
	send_close_ind(pb_session, 0);
	l_free(pb_session);
	pb_session = NULL;
}
