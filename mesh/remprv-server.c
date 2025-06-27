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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/time.h>
#include <time.h>
#include <ell/ell.h>

#include "src/shared/ad.h"

#include "mesh/mesh-defs.h"
#include "mesh/mesh-io.h"
#include "mesh/util.h"
#include "mesh/node.h"
#include "mesh/net.h"
#include "mesh/appkey.h"
#include "mesh/model.h"
#include "mesh/prov.h"
#include "mesh/provision.h"
#include "mesh/pb-adv.h"
#include "mesh/remprv.h"

#define EXT_LIST_SIZE	60

#define RPR_DEV_KEY	0x00
#define RPR_ADDR	0x01
#define RPR_COMP	0x02
#define RPR_ADV		0xFF	/* Internal use only*/

struct rem_scan_data {
	struct mesh_node *node;
	struct l_timeout *timeout;
	uint8_t *list;
	uint16_t client;
	uint16_t oob_info;
	uint16_t net_idx;
	uint8_t state;
	uint8_t scanned_limit;
	uint8_t addr[6];
	uint8_t uuid[16];
	uint8_t to_secs;
	uint8_t rxed_ads;
	uint8_t ext_cnt;
	bool fltr;
	uint8_t ext[0];
};

static struct rem_scan_data *rpb_scan;

struct rem_prov_data {
	struct mesh_node *node;
	struct l_timeout *timeout;
	void *trans_data;
	uint16_t client;
	uint16_t net_idx;
	uint8_t svr_pdu_num;
	uint8_t cli_pdu_num;
	uint8_t state;
	uint8_t nppi_proc;
	union {
		struct {
			mesh_prov_open_func_t open_cb;
			mesh_prov_close_func_t close_cb;
			mesh_prov_receive_func_t rx_cb;
			mesh_prov_ack_func_t ack_cb;
			struct mesh_prov_node_info info;
		} nppi;
		struct {
			uint8_t uuid[17];
			prov_trans_tx_t tx;
		} adv;
	} u;
};

static struct rem_prov_data *rpb_prov;

static const uint8_t prvb[2] = {BT_AD_MESH_BEACON, 0x00};
static const uint8_t pkt_filter = BT_AD_MESH_PROV;
static const char *name = "Test Name";

static const uint8_t zero[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static void srv_open(void *user_data, prov_trans_tx_t adv_tx,
					void *trans_data, uint8_t nppi_proc)
{
	struct rem_prov_data *prov = user_data;
	uint8_t msg[5];
	int n;

	if (prov != rpb_prov || prov->state != PB_REMOTE_STATE_LINK_OPENING)
		return;

	l_debug("Remote Link open confirmed");
	prov->u.adv.tx = adv_tx;
	prov->trans_data = trans_data;
	prov->state = PB_REMOTE_STATE_LINK_ACTIVE;

	n = mesh_model_opcode_set(OP_REM_PROV_LINK_REPORT, msg);
	msg[n++] = PB_REM_ERR_SUCCESS;
	msg[n++] = prov->state;

	mesh_model_send(prov->node, 0, prov->client, APP_IDX_DEV_LOCAL,
				prov->net_idx, DEFAULT_TTL, true, n, msg);
}

static void srv_rx(void *user_data, const void *dptr, uint16_t len)
{
	struct rem_prov_data *prov = user_data;
	const uint8_t *data = dptr;
	uint8_t msg[69];
	int n;

	if (prov != rpb_prov || prov->state < PB_REMOTE_STATE_LINK_ACTIVE ||
								len > 65)
		return;

	l_debug("Remote PB IB-PDU");

	prov->svr_pdu_num++;
	n = mesh_model_opcode_set(OP_REM_PROV_PDU_REPORT, msg);
	msg[n++] = prov->svr_pdu_num;
	memcpy(msg + n, data, len);
	n += len;

	mesh_model_send(prov->node, 0, prov->client, APP_IDX_DEV_LOCAL,
				prov->net_idx, DEFAULT_TTL, true, n, msg);
}

static void srv_ack(void *user_data, uint8_t msg_num)
{
	struct rem_prov_data *prov = user_data;
	uint8_t msg[4];
	int n;

	if (prov != rpb_prov || prov->state != PB_REMOTE_STATE_OB_PKT_TX)
		return;

	l_debug("Remote PB ACK");

	prov->state = PB_REMOTE_STATE_LINK_ACTIVE;
	n = mesh_model_opcode_set(OP_REM_PROV_PDU_OB_REPORT, msg);
	msg[n++] = prov->cli_pdu_num;

	mesh_model_send(prov->node, 0, prov->client, APP_IDX_DEV_LOCAL,
				prov->net_idx, DEFAULT_TTL, true, n, msg);
}

static void srv_close(void *user_data, uint8_t reason)
{
	struct rem_prov_data *prov = user_data;
	uint8_t msg[4];
	int n;

	if (prov != rpb_prov || prov->state < PB_REMOTE_STATE_LINK_ACTIVE)
		return;

	l_debug("Remote PB Close");

	prov->state = PB_REMOTE_STATE_LINK_CLOSING;
	n = mesh_model_opcode_set(OP_REM_PROV_LINK_REPORT, msg);
	msg[n++] = prov->state;
	msg[n++] = reason;

	mesh_model_send(prov->node, 0, prov->client, APP_IDX_DEV_LOCAL,
				prov->net_idx, DEFAULT_TTL, true, n, msg);
}

static void send_prov_status(struct rem_prov_data *prov, uint8_t status)
{
	uint16_t n;
	uint8_t msg[5];
	bool segmented = prov->state == PB_REMOTE_STATE_LINK_CLOSING ?
								true : false;

	n = mesh_model_opcode_set(OP_REM_PROV_LINK_STATUS, msg);
	msg[n++] = status;
	msg[n++] = prov->state;

	l_info("RPB-Link Status(%d): dst %4.4x", prov->state, prov->client);

	mesh_model_send(prov->node, 0, prov->client, APP_IDX_DEV_LOCAL,
				prov->net_idx, DEFAULT_TTL, segmented, n, msg);
}

static void remprv_prov_cancel(struct l_timeout *timeout,
						void *user_data)
{
	struct rem_prov_data *prov = user_data;

	if (prov != rpb_prov)
		return;

	l_timeout_remove(prov->timeout);
	l_free(prov);
	rpb_prov = NULL;
}

static void deregister_ext_ad_type(uint8_t ad_type)
{
	uint8_t short_ad;

	switch (ad_type) {
	case BT_AD_MESH_BEACON:
	case BT_AD_MESH_DATA:
	case BT_AD_MESH_PROV:
	case BT_AD_UUID16_SOME:
	case BT_AD_UUID32_SOME:
	case BT_AD_UUID128_SOME:
	case BT_AD_NAME_SHORT:
		return;

	case BT_AD_UUID16_ALL:
	case BT_AD_UUID32_ALL:
	case BT_AD_UUID128_ALL:
	case BT_AD_NAME_COMPLETE:
		/* Automatically get short versions */
		short_ad = ad_type - 1;
		mesh_io_deregister_recv_cb(NULL, &short_ad, 1);

		/* fall through */
	default:
		mesh_io_deregister_recv_cb(NULL, &ad_type, 1);
		break;
	}
}

static void remprv_scan_cancel(struct l_timeout *timeout,
						void *user_data)
{
	struct rem_scan_data *scan = user_data;
	uint8_t msg[22 + EXT_LIST_SIZE];
	uint16_t i, n;

	if (!scan || scan != rpb_scan)
		return;

	for (n = 0; n < scan->ext_cnt; n++)
		deregister_ext_ad_type(scan->ext[n]);

	if (scan->timeout == timeout) {
		/* Return Extended Results */
		if (scan->ext_cnt) {
			/* Return Extended Result */
			n = mesh_model_opcode_set(
					OP_REM_PROV_EXT_SCAN_REPORT, msg);
			msg[n++] = PB_REM_ERR_SUCCESS;
			memcpy(msg + n, scan->uuid, 16);
			n += 16;

			if (scan->oob_info) {
				l_put_le16(0, msg + n);
				n += 2;
			}

			i = 0;
			while (scan->list[i]) {
				msg[n++] = scan->list[i];
				memcpy(msg + n, &scan->list[i + 1],
								scan->list[i]);
				n += scan->list[i];
				i += scan->list[i] + 1;
			}
		}
	}

	l_timeout_remove(scan->timeout);
	l_free(scan->list);
	l_free(scan);
	rpb_scan = NULL;
}

static void scan_pkt(void *user_data, struct mesh_io_recv_info *info,
					const uint8_t *data, uint16_t len)
{
	struct rem_scan_data *scan = user_data;
	uint8_t msg[22 + EXT_LIST_SIZE];
	uint8_t addr[6];
	uint16_t i, n;
	int8_t rssi;
	uint8_t filled = 0;
	bool report = false;

	if (scan != rpb_scan)
		return;

	if (info) {
		rssi = info->rssi;
		memcpy(addr, info->addr, 6);
	} else {
		rssi = 0;
		memset(addr, 0, 6);
	}

	if (scan->ext_cnt)
		goto extended_scan;

	/* RX Unprovisioned Beacon */
	if (data[0] != BT_AD_MESH_BEACON || data[1] ||
			(len != 18 && len != 20 && len != 24))
		return;

	data += 2;
	len -= 2;

	for (n = 0; !report && n < scan->scanned_limit; n++) {
		if (!memcmp(&scan->list[n * 17 + 1], data, 16)) {

			/* Repeat UUID, check RSSI */
			if ((int8_t) scan->list[n * 17] < rssi) {
				report = true;
				scan->list[n * 17] = (uint8_t) rssi;
			}

		} else if (!memcmp(&scan->list[n * 17 + 1], zero, 16)) {

			/* Found Empty slot */
			report = true;
			scan->list[n * 17] = (uint8_t) rssi;
			memcpy(&scan->list[n * 17 + 1], data, 16);
		}

		filled++;
	}

	if (!report)
		return;

	n = mesh_model_opcode_set(OP_REM_PROV_SCAN_REPORT, msg);
	msg[n++] = (uint8_t) rssi;
	memcpy(msg + n, data, len);
	n += len;

	/* Always return oob_info, even if it wasn't in beacon */
	if (len == 16) {
		l_put_le16(0, msg + n);
		n += 2;
	}

	goto send_report;

extended_scan:
	if (data[0] == BT_AD_MESH_BEACON && !data[1]) {
		if (len != 18 && len != 20 && len != 24)
			return;

		/* Check UUID */
		if (memcmp(data + 2, scan->uuid, 16))
			return;

		/* Zero AD list if prior data RXed from different bd_addr */
		if (memcmp(scan->addr, addr, 6)) {
			scan->list[0] = 0;
			scan->rxed_ads = 0;
		}

		memcpy(scan->addr, addr, 6);
		scan->fltr = true;

		if (len >= 20)
			scan->oob_info = l_get_le16(data + 18);

		if (scan->rxed_ads != scan->ext_cnt)
			return;


	} else if (data[0] != BT_AD_MESH_BEACON) {
		if (!scan->fltr || !memcmp(scan->addr, addr, 6)) {
			i = 0;
			while (scan->list[i]) {
				/* check if seen */
				if (scan->list[i + 1] == data[0])
					return;

				i += scan->list[i] + 1;
			}

			/* Overflow Protection */
			if (i + len + 1 > EXT_LIST_SIZE)
				return;

			scan->list[i] = len;
			scan->list[i + len + 1] = 0;
			memcpy(scan->list + i + 1, data, len);
			scan->rxed_ads++;
		}

		if (scan->rxed_ads != scan->ext_cnt)
			return;

	} else
		return;

	n = mesh_model_opcode_set(OP_REM_PROV_EXT_SCAN_REPORT, msg);
	msg[n++] = PB_REM_ERR_SUCCESS;
	memcpy(msg + n, scan->uuid, 16);
	n += 16;
	l_put_le16(scan->oob_info, msg + n);
	n += 2;

	i = 0;
	while (scan->list[i]) {
		msg[n++] = scan->list[i];
		memcpy(msg + n, &scan->list[i + 1], scan->list[i]);
		n += scan->list[i];
		i += scan->list[i];
	}

send_report:
	print_packet("App Tx", msg, n);
	mesh_model_send(scan->node, 0, scan->client, APP_IDX_DEV_LOCAL,
				scan->net_idx, DEFAULT_TTL, true, n, msg);

	/* Clean-up if we are done reporting*/
	if (filled == scan->scanned_limit || scan->ext_cnt)
		remprv_scan_cancel(NULL, scan);
}

static bool register_ext_ad_type(uint8_t ad_type, struct rem_scan_data *scan)
{
	uint8_t short_ad;

	switch (ad_type) {
	case BT_AD_MESH_PROV:
	case BT_AD_UUID16_SOME:
	case BT_AD_UUID32_SOME:
	case BT_AD_UUID128_SOME:
	case BT_AD_NAME_SHORT:
		/* Illegal Requests */
		return false;

	case BT_AD_UUID16_ALL:
	case BT_AD_UUID32_ALL:
	case BT_AD_UUID128_ALL:
	case BT_AD_NAME_COMPLETE:
		/* Automatically get short versions */
		short_ad = ad_type - 1;
		mesh_io_register_recv_cb(NULL, &short_ad, 1, scan_pkt, scan);

		/* fall through */
	default:
		mesh_io_register_recv_cb(NULL, &ad_type, 1, scan_pkt, scan);

		/* fall through */

	case BT_AD_MESH_BEACON:
		/* Ignored/auto request */
		break;
	}

	return true;
}

static void link_active(void *user_data)
{
	struct rem_prov_data *prov = user_data;
	uint8_t msg[5];
	int n;

	if (prov != rpb_prov || prov->state != PB_REMOTE_STATE_LINK_OPENING)
		return;

	l_debug("Remote Link open confirmed");
	prov->state = PB_REMOTE_STATE_LINK_ACTIVE;

	n = mesh_model_opcode_set(OP_REM_PROV_LINK_REPORT, msg);
	msg[n++] = PB_REM_ERR_SUCCESS;
	msg[n++] = PB_REMOTE_STATE_LINK_ACTIVE;

	mesh_model_send(prov->node, 0, prov->client, APP_IDX_DEV_LOCAL,
				prov->net_idx, DEFAULT_TTL, true, n, msg);
}

bool register_nppi_acceptor(mesh_prov_open_func_t open_cb,
					mesh_prov_close_func_t close_cb,
					mesh_prov_receive_func_t rx_cb,
					mesh_prov_ack_func_t ack_cb,
					void *user_data)
{
	struct rem_prov_data *prov = rpb_prov;

	if (!prov || prov->nppi_proc == RPR_ADV)
		return false;

	prov->u.nppi.open_cb = open_cb;
	prov->u.nppi.close_cb = close_cb;
	prov->u.nppi.rx_cb = rx_cb;
	prov->u.nppi.ack_cb = ack_cb;
	prov->trans_data = user_data;

	open_cb(user_data, srv_rx, prov, prov->nppi_proc);

	l_idle_oneshot(link_active, prov, NULL);

	return true;
}

static bool nppi_cmplt(void *user_data, uint8_t status,
					const struct mesh_prov_node_info *info)
{
	struct rem_prov_data *prov = user_data;

	if (prov != rpb_prov)
		return false;

	/* Save new info to apply on Link Close */
	prov->u.nppi.info = *info;
	return true;
}

static bool start_dev_key_refresh(struct mesh_node *node, uint8_t nppi_proc,
						struct rem_prov_data *prov)
{
	uint8_t num_ele = node_get_num_elements(node);

	prov->nppi_proc = nppi_proc;
	return acceptor_start(num_ele, NULL, 0x0001, 60, NULL, nppi_cmplt,
									prov);
}

static bool remprv_srv_pkt(uint16_t src, uint16_t unicast, uint16_t app_idx,
					uint16_t net_idx, const uint8_t *data,
					uint16_t size, const void *user_data)
{
	struct rem_prov_data *prov = rpb_prov;
	struct rem_scan_data *scan = rpb_scan;
	struct mesh_node *node = (struct mesh_node *) user_data;
	const uint8_t *pkt = data;
	bool segmented = false;
	uint32_t opcode;
	uint8_t msg[69];
	uint8_t old_state, status;
	uint16_t n;

	if (app_idx != APP_IDX_DEV_LOCAL)
		return false;

	if (mesh_model_opcode_get(pkt, size, &opcode, &n)) {
		size -= n;
		pkt += n;
	} else
		return false;

	n = 0;

	switch (opcode) {
	default:
		return false;

	case OP_REM_PROV_SCAN_CAP_GET:
		if (size != 0)
			return true;

		/* Compose Scan Info Status */
		n = mesh_model_opcode_set(OP_REM_PROV_SCAN_CAP_STATUS, msg);
		msg[n++] = PB_REMOTE_MAX_SCAN_QUEUE_SIZE;
		msg[n++] = 1; /* Active Scanning Supported */
		break;

	case OP_REM_PROV_EXT_SCAN_START:
		if (!size || !pkt[0])
			return true;

		/* Size check the message */
		if (pkt[0] + 18 == size) {
			/* Range check the Timeout */
			if (!pkt[size - 1] || pkt[size - 1] > 5)
				return true;
		} else if (pkt[0] + 1 != size)
			return true;

		/* Get local device extended info */
		if (pkt[0] + 18 != size) {
			n = mesh_model_opcode_set(
					OP_REM_PROV_EXT_SCAN_REPORT, msg);
			msg[n++] = PB_REM_ERR_SUCCESS;
			memcpy(msg + n, node_uuid_get(node), 16);
			n += 16;
			l_put_le16(0, msg + n);
			n += 2;
			size--;
			pkt++;

			while (size--) {
				if (*pkt++ == BT_AD_NAME_COMPLETE) {
					msg[n] = strlen(name) + 1;
					if (msg[n] > sizeof(msg) - n - 1)
						msg[n] = sizeof(msg) - n - 1;
					n++;
					msg[n++] = BT_AD_NAME_COMPLETE;
					memcpy(&msg[n], name, msg[n - 2] - 1);
					n += msg[n - 2] - 1;
					goto send_pkt;
				}
			}

			/* Send internal report */
			l_debug("Send internal extended info %d", n);
			goto send_pkt;
		}

		status = PB_REM_ERR_SUCCESS;
		if (scan) {
			if (scan->client != src || scan->node != node ||
						scan->ext_cnt != pkt[0])
				status = PB_REM_ERR_SCANNING_CANNOT_START;
			else if (memcmp(scan->ext, pkt + 1, pkt[0]))
				status = PB_REM_ERR_SCANNING_CANNOT_START;
			else if (memcmp(scan->uuid, pkt + 2, 16))
				status = PB_REM_ERR_SCANNING_CANNOT_START;
		}

		if (status != PB_REM_ERR_SUCCESS) {
			n = mesh_model_opcode_set(OP_REM_PROV_EXT_SCAN_REPORT,
									msg);
			msg[n++] = status;
			memset(msg + n, 0, 16);
			n += 16;
			segmented = true;
			break;
		}

		/* Ignore extended requests while already scanning */
		if (scan)
			return true;

		scan = (void *) l_new(uint8_t,
					sizeof(struct rem_scan_data) + pkt[0]);

		/* Validate and register Extended AD types */
		for (n = 0; n < pkt[0]; n++) {
			if (!register_ext_ad_type(pkt[1 + n], scan)) {
				/* Invalid AD type detected -- Undo */
				while (n--)
					deregister_ext_ad_type(pkt[1 + n]);

				l_free(scan);
				return true;
			}
		}

		rpb_scan = scan;
		scan->client = src;
		scan->net_idx = net_idx;
		memcpy(scan->uuid, pkt + size - 17, 16);
		scan->ext_cnt = pkt[0];
		memcpy(scan->ext, pkt + 1, pkt[0]);
		scan->list = l_malloc(EXT_LIST_SIZE);
		scan->list[0] = 0;

		mesh_io_register_recv_cb(NULL, prvb, sizeof(prvb),
								scan_pkt, scan);

		scan->timeout = l_timeout_create(pkt[size-1],
						remprv_scan_cancel, scan, NULL);
		return true;

	case OP_REM_PROV_SCAN_START:
		if (size != 2 && size != 18)
			return true;

		/* Reject Timeout of Zero */
		if (!pkt[1])
			return true;

		status = PB_REM_ERR_SUCCESS;
		if (scan) {
			if (scan->ext_cnt || scan->client != src ||
							scan->node != node)
				status = PB_REM_ERR_SCANNING_CANNOT_START;
			else if (!!(scan->fltr) != !!(size != 18))
				status = PB_REM_ERR_SCANNING_CANNOT_START;
			else if (scan->fltr && memcmp(scan->uuid, pkt + 2, 16))
				status = PB_REM_ERR_SCANNING_CANNOT_START;
		}

		if (status != PB_REM_ERR_SUCCESS) {
			n = mesh_model_opcode_set(OP_REM_PROV_SCAN_STATUS, msg);
			msg[n++] = status;
			msg[n++] = scan ? scan->state : 0;
			msg[n++] = scan ? scan->scanned_limit :
						PB_REMOTE_MAX_SCAN_QUEUE_SIZE;
			msg[n++] = scan ? scan->to_secs : 0;
			break;
		}

		if (!scan)
			scan = l_new(struct rem_scan_data, 1);

		rpb_scan = scan;

		if (size == 18) {
			memcpy(scan->uuid, pkt + 2, 16);
			scan->fltr = true;
			scan->state = 0x02; /* Limited */
		} else {
			memset(scan->uuid, 0, 16);
			scan->fltr = false;
			scan->state = 0x01; /* Unlimited */
		}

		scan->client = src;
		scan->net_idx = net_idx;
		scan->node = node;

		if (!scan->list)
			scan->list = l_new(uint8_t,
					23 * PB_REMOTE_MAX_SCAN_QUEUE_SIZE);

		mesh_io_register_recv_cb(NULL, prvb, 2, scan_pkt, scan);

		scan->to_secs = pkt[1];

		if (pkt[0])
			scan->scanned_limit = pkt[0];
		else
			scan->scanned_limit = PB_REMOTE_MAX_SCAN_QUEUE_SIZE;

		scan->timeout = l_timeout_create(pkt[1],
					remprv_scan_cancel, scan, NULL);

		/* fall through */

	case OP_REM_PROV_SCAN_GET:
		/* Compose Scan Status */
		n = mesh_model_opcode_set(OP_REM_PROV_SCAN_STATUS, msg);
		msg[n++] = PB_REM_ERR_SUCCESS;
		msg[n++] = scan ? scan->state : 0;
		msg[n++] = scan ? scan->scanned_limit :
						PB_REMOTE_MAX_SCAN_QUEUE_SIZE;
		msg[n++] = scan ? scan->to_secs : 0;
		break;

	case OP_REM_PROV_SCAN_STOP:
		if (size != 0 || !scan)
			return true;

		remprv_scan_cancel(NULL, scan);
		return true;

	case OP_REM_PROV_LINK_GET:
		if (size != 0 || !prov)
			return true;

		send_prov_status(prov, PB_REM_ERR_SUCCESS);
		return true;

	case OP_REM_PROV_LINK_OPEN:
		/* Sanity check args */
		if (size != 16 && size != 17 && size != 1)
			return true;

		if (size == 17 && (pkt[16] == 0 || pkt[16] > 0x3c))
			return true;

		if (size == 1 && pkt[0] > 0x02)
			return true;

		if (prov) {
			if (prov->client != src || prov->node != node ||
				(size == 1 && prov->nppi_proc != pkt[0]) ||
				(size >= 16 && (prov->nppi_proc != RPR_ADV ||
					memcmp(prov->u.adv.uuid, pkt, 16)))) {

				/* Send Reject (in progress) */
				send_prov_status(prov, PB_REM_ERR_CANNOT_OPEN);
				n = mesh_model_opcode_set(
						OP_REM_PROV_LINK_STATUS, msg);
				msg[n++] = PB_REM_ERR_CANNOT_OPEN;
				msg[n++] = PB_REMOTE_STATE_LINK_ACTIVE;
				break;
			}

			/* Send redundant  Success */
			send_prov_status(prov, PB_REM_ERR_SUCCESS);
			return true;
		}

		if (scan && scan->client != src && scan->node != node) {
			n = mesh_model_opcode_set(OP_REM_PROV_LINK_STATUS, msg);
			msg[n++] = PB_REM_ERR_CANNOT_OPEN;
			msg[n++] = PB_REMOTE_STATE_LINK_ACTIVE;
			break;
		}

		print_packet("Remote Prov Link Open", pkt, size);

		remprv_scan_cancel(NULL, scan);

		rpb_prov = prov = l_new(struct rem_prov_data, 1);
		prov->client = src;
		prov->net_idx = net_idx;
		prov->node = node;
		prov->state = PB_REMOTE_STATE_LINK_OPENING;

		if (size == 1) {
			status = start_dev_key_refresh(node, pkt[0], prov);

		} else {
			if (size == 17)
				prov->timeout = l_timeout_create(pkt[16],
						remprv_prov_cancel, prov, NULL);


			prov->nppi_proc = RPR_ADV;
			memcpy(prov->u.adv.uuid, pkt, 16);
			status = pb_adv_reg(true, srv_open, srv_close, srv_rx,
							srv_ack, pkt, prov);
		}

		if (status)
			send_prov_status(prov, PB_REM_ERR_SUCCESS);
		else {
			n = mesh_model_opcode_set(OP_REM_PROV_LINK_STATUS, msg);
			msg[n++] = PB_REM_ERR_CANNOT_OPEN;
			msg[n++] = PB_REMOTE_STATE_IDLE;
			remprv_prov_cancel(NULL, prov);
		}

		return true;

	case OP_REM_PROV_LINK_CLOSE:
		if (size != 1)
			return true;

		if (!prov || prov->node != node || prov->client != src)
			return true;

		old_state = prov->state;
		prov->state = PB_REMOTE_STATE_LINK_CLOSING;
		mesh_io_send_cancel(NULL, &pkt_filter, sizeof(pkt_filter));
		send_prov_status(prov, PB_REM_ERR_SUCCESS);
		if (pkt[0] == 0x02 &&
				old_state >= PB_REMOTE_STATE_LINK_ACTIVE) {
			msg[0] = PROV_FAILED;
			msg[1] = PROV_ERR_CANT_ASSIGN_ADDR;
			if (prov->nppi_proc == RPR_ADV)
				prov->u.adv.tx(prov->trans_data, msg, 2);
			else
				prov->u.nppi.rx_cb(prov->trans_data, msg, 2);
		}

		if (prov->nppi_proc == RPR_ADV)
			pb_adv_unreg(prov);

		else if (prov->nppi_proc <= RPR_COMP) {
			/* Hard or Soft refresh of local node, based on NPPI */
			node_refresh(prov->node, (prov->nppi_proc == RPR_ADDR),
							&prov->u.nppi.info);
		}

		remprv_prov_cancel(NULL, prov);

		return true;

	case OP_REM_PROV_PDU_SEND:
		if (!prov || prov->node != node || prov->client != src)
			return true;

		if (size < 2)
			return true;


		prov->cli_pdu_num = *pkt++;
		size--;
		prov->state = PB_REMOTE_STATE_OB_PKT_TX;

		if (prov->nppi_proc == RPR_ADV)
			prov->u.adv.tx(prov->trans_data, pkt, size);
		else {
			srv_ack(prov, prov->cli_pdu_num);
			prov->u.nppi.rx_cb(prov->trans_data, pkt, size);
		}

		return true;
	}

send_pkt:
	l_info("PB-SVR: src %4.4x dst %4.4x", unicast, src);
	print_packet("App Tx", msg, n);
	mesh_model_send(node, 0, src, APP_IDX_DEV_LOCAL,
				net_idx, DEFAULT_TTL, segmented, n, msg);

	return true;
}

static void remprv_srv_unregister(void *user_data)
{
}

static const struct mesh_model_ops ops = {
	.unregister = remprv_srv_unregister,
	.recv = remprv_srv_pkt,
	.bind = NULL,
	.sub = NULL,
	.pub = NULL
};

void remote_prov_server_init(struct mesh_node *node, uint8_t ele_idx)
{
	mesh_model_register(node, ele_idx, REM_PROV_SRV_MODEL, &ops, node);
}
