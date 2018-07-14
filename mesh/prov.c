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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/time.h>
#include <ell/ell.h>

#include "mesh/mesh-defs.h"

#include "mesh/mesh-io.h"
#include "mesh/display.h"
#include "mesh/crypto.h"
#include "mesh/net.h"
#include "mesh/prov.h"

#define PB_ADV_MTU	24

#define DEFAULT_CONN_ID	0x00000000
#define DEFAULT_PROV_MSG_NUM	0x00
#define DEFAULT_DEV_MSG_NUM	0x80

#define TX_TIMEOUT	30

struct mesh_prov *mesh_prov_new(struct mesh_net *net, uint16_t remote)
{
	struct mesh_prov *prov;

	prov = l_new(struct mesh_prov, 1);

	prov->remote = remote;
	prov->net = net;

	return mesh_prov_ref(prov);
}

struct mesh_prov *mesh_prov_ref(struct mesh_prov *prov)
{
	if (!prov)
		return NULL;

	__sync_fetch_and_add(&prov->ref_count, 1);

	return prov;
}

void mesh_prov_unref(struct mesh_prov *prov)
{
	struct mesh_io *io;
	uint8_t type;

	if (!prov)
		return;

	if (__sync_sub_and_fetch(&prov->ref_count, 1))
		return;

	io = mesh_net_get_io(prov->net);
	type = MESH_AD_TYPE_BEACON;
	mesh_io_send_cancel(io, &type, 1);
	type = MESH_AD_TYPE_PROVISION;
	mesh_io_send_cancel(io, &type, 1);
	mesh_io_deregister_recv_cb(io, MESH_IO_FILTER_PROV);
	mesh_io_deregister_recv_cb(io, MESH_IO_FILTER_BEACON);
	l_timeout_remove(prov->tx_timeout);


	l_info("Freed Prov Data");
	l_free(prov);
}

static void packet_received(struct mesh_prov *prov, const void *data,
						uint16_t size, uint8_t fcs)
{
	if (prov->receive_callback)
		prov->receive_callback(data, size, prov);
}

static void send_open_req(struct mesh_prov *prov)
{
	struct mesh_io *io;
	uint8_t open_req[23] = { MESH_AD_TYPE_PROVISION };
	struct mesh_io_send_info info = {
		.type = MESH_IO_TIMING_TYPE_GENERAL,
		.u.gen.interval = 50,
		.u.gen.cnt = 1,
		.u.gen.min_delay = 0,
		.u.gen.max_delay = 0,
	};

	if (!prov)
		return;

	io = mesh_net_get_io(prov->net);
	if (!io)
		return;

	l_put_be32(prov->conn_id, open_req + 1);
	open_req[1 + 4] = prov->local_msg_num = 0;
	open_req[1 + 4 + 1] = 0x03; /* OPEN_REQ */
	memcpy(open_req + 1 + 4 + 1 + 1, prov->uuid, 16);

	/* print_packet("PB-TX", open_req + 1, sizeof(open_req) - 1); */
	mesh_io_send_cancel(io, open_req, 1);
	mesh_io_send(io, &info, open_req, sizeof(open_req));
}

static void send_open_cfm(struct mesh_prov *prov)
{
	struct mesh_io *io;
	uint8_t open_cfm[7] = { MESH_AD_TYPE_PROVISION };
	struct mesh_io_send_info info = {
		.type = MESH_IO_TIMING_TYPE_GENERAL,
		.u.gen.interval = 50,
		.u.gen.cnt = 1,
		.u.gen.min_delay = 0,
		.u.gen.max_delay = 0,
	};

	if (!prov)
		return;

	io = mesh_net_get_io(prov->net);
	if (!io)
		return;

	l_put_be32(prov->conn_id, open_cfm + 1);
	open_cfm[1 + 4] = 0;
	open_cfm[1 + 4 + 1] = 0x07; /* OPEN_CFM */

	/* print_packet("PB-TX", open_cfm + 1, sizeof(open_cfm) - 1); */

	mesh_io_send_cancel(io, open_cfm, 1);
	mesh_io_send(io, &info, open_cfm, sizeof(open_cfm));
}

static void send_close_ind(struct mesh_prov *prov, uint8_t reason)
{
	uint8_t buf[8] = { MESH_AD_TYPE_PROVISION };
	struct mesh_io *io;
	struct mesh_io_send_info info = {
		.type = MESH_IO_TIMING_TYPE_GENERAL,
		.u.gen.interval = 50,
		.u.gen.cnt = 3,
		.u.gen.min_delay = 0,
		.u.gen.max_delay = 0,
	};

	if (!prov)
		return;

	if (prov->bearer == MESH_BEARER_ADV) {
		io = mesh_net_get_io(prov->net);
		if (!io)
			return;

		l_put_be32(prov->conn_id, buf + 1);
		buf[5] = 0;
		buf[6] = 0x0B; /* CLOSE_IND */
		buf[7] = reason;

		/* print_packet("PB-TX", buf + 1, sizeof(buf) - 1); */

		mesh_io_send_cancel(io, buf, 1);
		mesh_io_send(io, &info, buf, sizeof(buf));
	}

	prov->bearer = MESH_BEARER_IDLE;
}

static void tx_timeout(struct l_timeout *timeout, void *user_data)
{
	struct mesh_prov *prov = user_data;
	uint8_t cancel[] = { MESH_AD_TYPE_PROVISION };
	struct mesh_io *io;

	if (!prov)
		return;

	l_timeout_remove(prov->tx_timeout);
	prov->tx_timeout = NULL;

	io = mesh_net_get_io(prov->net);
	if (!io)
		return;

	mesh_io_send_cancel(io, cancel, sizeof(cancel));

	l_info("TX timeout");
	mesh_prov_close(prov, 1);
}

static void send_adv_segs(struct mesh_prov *prov)
{
	struct mesh_io *io = mesh_net_get_io(prov->net);
	struct mesh_io_send_info info = {
		.type = MESH_IO_TIMING_TYPE_GENERAL,
		.u.gen.interval = 50,
		.u.gen.cnt = MESH_IO_TX_COUNT_UNLIMITED,
		.u.gen.min_delay = 0,
		.u.gen.max_delay = 0,
	};
	const void *data = prov->packet_buf;
	uint16_t size = prov->packet_len;
	uint16_t init_size;
	uint8_t buf[1 + PB_ADV_MTU + 5] = { MESH_AD_TYPE_PROVISION };
	uint8_t max_seg;
	uint8_t consumed;
	int i;

	if (!size)
		return;

	mesh_io_send_cancel(io, buf, 1);

	l_put_be32(prov->conn_id, buf + 1);
	buf[1 + 4] = prov->local_msg_num;

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

	buf[1 + 4 + 1] = max_seg << 2;
	l_put_be16(size, buf + 1 + 4 + 1 + 1);
	buf[9] = mesh_crypto_compute_fcs(data, size);
	memcpy(buf + 1 + 4 + 1 + 1 + 2 + 1, data, init_size);

	l_debug("max_seg: %2.2x", max_seg);
	l_debug("size: %2.2x, CRC: %2.2x", size, buf[9]);

	/* print_packet("PB-TX", buf + 1, init_size + 9); */
	mesh_io_send(io, &info, buf, init_size + 10);

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

		mesh_io_send(io, &info, buf, seg_size + 7);

		consumed += seg_size;
	}
}

static void send_adv_msg(struct mesh_prov *prov, const void *data,
								uint16_t size)
{
	l_timeout_remove(prov->tx_timeout);
	prov->tx_timeout = l_timeout_create(TX_TIMEOUT, tx_timeout, prov, NULL);

	memcpy(prov->packet_buf, data, size);
	prov->packet_len = size;

	send_adv_segs(prov);
}

static void send_ack(struct mesh_prov *prov)
{
	struct mesh_io *io = mesh_net_get_io(prov->net);
	struct mesh_io_send_info info = {
		.type = MESH_IO_TIMING_TYPE_GENERAL,
		.u.gen.interval = 50,
		.u.gen.cnt = 1,
		.u.gen.min_delay = 0,
		.u.gen.max_delay = 0,
	};
	uint8_t ack[7] = { MESH_AD_TYPE_PROVISION };

	l_put_be32(prov->conn_id, ack + 1);
	ack[1 + 4] = prov->last_peer_msg_num;
	ack[1 + 4 + 1] = 0x01; /* ACK */

	/* print_packet("ADV-ACK", ack + 1, sizeof(ack) - 1); */
	mesh_io_send(io, &info, ack, sizeof(ack));
}

static void adv_data_pkt(uint8_t type, const void *pkt, uint8_t size,
								void *user_data)
{
	const uint8_t *data = pkt;
	struct mesh_prov *prov = user_data;
	uint16_t offset = 0;

	if ((type & 0x03) == 0x00) {
		uint8_t last_seg = type >> 2;

		prov->expected_len = l_get_be16(data);
		prov->expected_fcs = l_get_u8(data + 2);

		/* print_packet("Pkt", pkt, size); */
		data += 3;
		size -= 3;

		prov->trans = MESH_TRANS_RX;

		if (prov->expected_len > sizeof(prov->peer_buf)) {
			l_info("Incoming pkt exceeds storage %d > %ld",
				prov->expected_len, sizeof(prov->peer_buf));
			return;
		} else if (last_seg == 0)
			prov->trans = MESH_TRANS_IDLE;

		prov->expected_segs = 0xff >> (7 - last_seg);
		prov->got_segs |= 1;
		memcpy(prov->peer_buf, data, size);

	} else if ((type & 0x03) == 0x02) {
		offset = (PB_ADV_MTU - 4) + ((type >> 2) - 1) *
							(PB_ADV_MTU - 1);

		if (offset + size > prov->expected_len) {
			l_info("Incoming pkt exceeds agreed len %d + %d > %d",
					offset, size, prov->expected_len);
			return;
		}

		prov->trans = MESH_TRANS_RX;

		l_debug("Processing fragment %u", type & 0x3f);

		prov->got_segs |= 1 << (type >> 2);
		memcpy(prov->peer_buf + offset, data, size);

	} else if (type == 0x01) {
		if (prov->send_callback) {
			void *data = prov->send_data;
			mesh_prov_send_func_t cb = prov->send_callback;

			prov->trans = MESH_TRANS_IDLE;
			prov->send_callback = NULL;
			prov->send_data = NULL;

			cb(true, data);
		}
		return;
	} else
		return;

	if (prov->got_segs != prov->expected_segs)
		return;

	/* Validate RXed packet and pass up to Provisioning */
	if (!mesh_crypto_check_fcs(prov->peer_buf,
				prov->expected_len,
				prov->expected_fcs)) {
		l_debug("Invalid FCS");
		return;
	}

	prov->last_peer_msg_num = prov->peer_msg_num;
	send_ack(prov);

	prov->trans = MESH_TRANS_IDLE;

	packet_received(prov, prov->peer_buf,
			prov->expected_len, prov->expected_fcs);

	/* Reset Re-Assembly for next packet */
	prov->expected_len = sizeof(prov->peer_buf);
	prov->expected_fcs = 0;
	prov->expected_segs = 0;
	prov->got_segs = 0;

}

static void adv_bearer_packet(void *user_data, struct mesh_io_recv_info *info,
					const uint8_t *pkt, uint16_t len)
{
	struct mesh_prov *prov = user_data;
	uint32_t conn_id;
	uint8_t msg_num;
	uint8_t type;

	if (len < 6) {
		l_info("  Too short packet");
		return;
	}

	conn_id = l_get_be32(pkt + 1);
	msg_num = l_get_u8(pkt + 1 + 4);
	type = l_get_u8(pkt + 1 + 4 + 1);

	/*if (prov->conn_id == conn_id) print_packet("ADV-RX", pkt, len); */

	if (prov->conn_id != DEFAULT_CONN_ID) {
		if (prov->conn_id != conn_id) {
			l_debug("rxed unknown conn_id: %8.8x != %8.8x",
							conn_id, prov->conn_id);
			return;
		}
	} else if (type != 0x03)
		return;

	/* print_packet("PB-ADV-RX", pkt, len); */

	/* Normalize pkt to start of PROV pkt payload */
	pkt += 7;
	len -= 7;

	if (type == 0x07) { /* OPEN_CFM */
		if (conn_id != prov->conn_id)
			return;

		if (msg_num != prov->local_msg_num)
			return;

		l_info("Link open confirmed");

		prov->bearer = MESH_BEARER_ADV;
		if (prov->open_callback)
			prov->open_callback(prov->receive_data);
	} else if (type == 0x01) {
		if (conn_id != prov->conn_id)
			return;

		if (msg_num != prov->local_msg_num)
			return;

		l_debug("Got ACK %d", msg_num);
		adv_data_pkt(type, pkt, len, user_data);
	} else if (type == 0x03) {
		/*
		 * Ignore if:
		 * 1. We are already provisioning
		 * 2. We are not advertising that we are unprovisioned
		 * 3. Open request not addressed to us
		 */
		if (prov->conn_id != DEFAULT_CONN_ID &&
				prov->conn_id != conn_id)
			return;

		if (prov->local_msg_num != (DEFAULT_DEV_MSG_NUM - 1))
			return;

		if (memcmp(pkt, prov->uuid, 16))
			return;

		l_info("Link open request");

		prov->last_peer_msg_num = 0xFF;
		prov->bearer = MESH_BEARER_ADV;
		if (prov->open_callback && prov->conn_id == DEFAULT_CONN_ID)
			prov->open_callback(prov->receive_data);

		prov->conn_id = conn_id;
		prov->peer_msg_num = msg_num;
		send_open_cfm(prov);
	} else if (type == 0x0B) {
		if (prov->conn_id != conn_id)
			return;

		prov->conn_id = DEFAULT_CONN_ID;
		prov->local_msg_num = 0xFF;
		prov->peer_msg_num = 0xFF;
		prov->last_peer_msg_num = 0xFF;

		l_timeout_remove(prov->tx_timeout);
		prov->tx_timeout = NULL;

		l_info("Link closed notification: %2.2x", pkt[0]);

		if (prov->close_callback)
			prov->close_callback(prov->receive_data, pkt[0]);
	} else if ((type & 0x03) == 0x00) {
		if (prov->conn_id != conn_id)
			return;

		if (msg_num == prov->last_peer_msg_num) {
			send_ack(prov);
			return;
		}

		prov->peer_msg_num = msg_num;

		l_debug("Processing Data with %u fragments,%d octets",
						type >> 2, l_get_be16(pkt));
		adv_data_pkt(type, pkt, len, user_data);

	} else if ((type & 0x03) == 0x02) {
		if (prov->conn_id != conn_id)
			return;

		if (msg_num == prov->last_peer_msg_num) {
			send_ack(prov);
			return;
		}

		prov->peer_msg_num = msg_num;

		l_debug("Processing fragment %u", type >> 2);
		adv_data_pkt(type, pkt, len, user_data);
	}
}

static void beacon_packet(void *user_data, struct mesh_io_recv_info *info,
					const uint8_t *pkt, uint16_t len)
{
	struct mesh_prov *prov = user_data;
	struct mesh_io *io;

	pkt++;
	len--;

	if (len < 19)
		return;

	if (!pkt[0])
		print_packet("UnProv-BEACON-RX", pkt, len);

	/* Ignore devices not matching UUID */
	if (pkt[0] || memcmp(pkt + 1, prov->uuid, 16))
		return;

	io = mesh_net_get_io(prov->net);
	mesh_io_deregister_recv_cb(io, MESH_IO_FILTER_BEACON);

	if ((prov->conn_id != DEFAULT_CONN_ID) ||
			(prov->bearer != MESH_BEARER_IDLE)) {
		l_info("PB-ADV: Already Provisioning");
		return;
	}

	l_getrandom(&prov->conn_id, sizeof(prov->conn_id));
	prov->bearer = MESH_BEARER_ADV;
	send_open_req(prov);
}

static bool mesh_prov_enable(struct mesh_prov *prov, enum mesh_prov_mode mode,
							uint8_t uuid[16])
{
	const uint8_t pb_adv_data[] = { MESH_AD_TYPE_BEACON, 0 };
	uint8_t adv_data[62];
	uint8_t adv_len, type;
	struct mesh_io *io;
	struct mesh_io_send_info tx_info = {
		.type = MESH_IO_TIMING_TYPE_GENERAL,
		.u.gen.interval = 1000,	/* ms */
		.u.gen.cnt = 0,		/* 0 == Infinite */
		.u.gen.min_delay = 0,	/* no delay */
		.u.gen.max_delay = 0,	/* no delay */
	};

	if (!prov || !prov->net)
		return false;


	prov->mode = mode;
	memcpy(prov->uuid, uuid, 16);
	prov->conn_id = DEFAULT_CONN_ID;
	io = mesh_net_get_io(prov->net);

	switch (mode) {
	case MESH_PROV_MODE_NONE:
		break;
	case MESH_PROV_MODE_INITIATOR:
		print_packet("Searching for uuid", uuid, 16);
		prov->local_msg_num = DEFAULT_PROV_MSG_NUM;
		prov->peer_msg_num = DEFAULT_DEV_MSG_NUM;
		mesh_io_register_recv_cb(io, MESH_IO_FILTER_PROV,
						adv_bearer_packet, prov);
		mesh_io_register_recv_cb(io, MESH_IO_FILTER_BEACON,
						beacon_packet, prov);
		break;

	case MESH_PROV_MODE_ADV_ACCEPTOR:
		prov->local_msg_num = DEFAULT_DEV_MSG_NUM - 1;
		prov->peer_msg_num = DEFAULT_PROV_MSG_NUM;

		print_packet("Beaconing as unProvisioned uuid", uuid, 16);
		adv_len = sizeof(pb_adv_data);
		memcpy(adv_data, pb_adv_data, adv_len);
		memcpy(adv_data + adv_len, uuid, 16);
		adv_len += 16;
		adv_len += 2;
		mesh_io_register_recv_cb(io, MESH_IO_FILTER_PROV,
						adv_bearer_packet, prov);
		type = MESH_AD_TYPE_BEACON;
		mesh_io_send_cancel(io, &type, 1);
		mesh_io_send(io, &tx_info, adv_data, adv_len);
		break;

	case MESH_PROV_MODE_GATT_CLIENT:
	case MESH_PROV_MODE_MESH_GATT_CLIENT:
	case MESH_PROV_MODE_GATT_ACCEPTOR:
	case MESH_PROV_MODE_MESH_SERVER:
	case MESH_PROV_MODE_MESH_CLIENT:
	default:
		l_error("Unimplemented Prov Mode: %d", mode);
		break;
	}

	return true;
}

bool mesh_prov_listen(struct mesh_net *net, uint8_t uuid[16], uint8_t caps[12],
					mesh_prov_open_func_t open_callback,
					mesh_prov_close_func_t close_callback,
					mesh_prov_receive_func_t recv_callback,
					void *user_data)
{
	struct mesh_prov *prov = mesh_net_get_prov(net);

	if (!prov) {
		prov = mesh_prov_new(net, 0);
		if (!prov)
			return false;

		mesh_net_set_prov(net, prov);
	}

	prov->open_callback = open_callback;
	prov->close_callback = close_callback;
	prov->receive_callback = recv_callback;
	prov->receive_data = prov; /* TODO: retink the callback placement */
	memcpy(prov->caps, caps, sizeof(prov->caps));

	prov->trans = MESH_TRANS_IDLE;


	return mesh_prov_enable(prov, MESH_PROV_MODE_ADV_ACCEPTOR, uuid);
}

unsigned int mesh_prov_send(struct mesh_prov *prov,
					const void *ptr, uint16_t size,
					mesh_prov_send_func_t send_callback,
					void *user_data)
{
	const uint8_t *data = ptr;

	if (!prov)
		return 0;

	if (prov->trans != MESH_TRANS_IDLE)
		return 0;

	if (prov->remote) {
		/* TODO -- PB-Remote */
	} else {
		prov->send_callback = send_callback;
		prov->send_data = user_data;
		prov->trans = MESH_TRANS_TX;
		prov->local_msg_num++;
		send_adv_msg(prov, data, size);
	}

	return 1;
}

bool mesh_prov_close(struct mesh_prov *prov, uint8_t reason)
{
	if (!prov)
		return false;

	prov->local_msg_num = 0;
	send_close_ind(prov, reason);

	prov->conn_id = DEFAULT_CONN_ID;
	prov->local_msg_num = 0xFF;
	prov->peer_msg_num = 0xFF;
	prov->last_peer_msg_num = 0xFF;

	if (prov->tx_timeout) {
		l_timeout_remove(prov->tx_timeout);

		/* If timing out, give Close indication 1 second of
		 * provisioning timing to get final Close indication out
		 */
		prov->tx_timeout = l_timeout_create(1, tx_timeout, prov, NULL);
	}

	if (prov->close_callback)
		prov->close_callback(prov->receive_data, reason);

	return false;
}

void mesh_prov_set_addr(struct mesh_prov *prov, uint16_t addr)
{
	prov->addr = addr;
}

uint16_t mesh_prov_get_idx(struct mesh_prov *prov)
{
	return prov->net_idx;
}
