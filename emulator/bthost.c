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
#include <endian.h>
#include <stdbool.h>

#include "bluetooth/bluetooth.h"

#include "monitor/bt.h"
#include "bthost.h"

/* ACL handle and flags pack/unpack */
#define acl_handle_pack(h, f)	(uint16_t)((h & 0x0fff)|(f << 12))
#define acl_handle(h)		(h & 0x0fff)
#define acl_flags(h)		(h >> 12)

#define le16_to_cpu(val) (val)
#define le32_to_cpu(val) (val)
#define cpu_to_le16(val) (val)
#define cpu_to_le32(val) (val)

struct cmd {
	struct cmd *next;
	struct cmd *prev;
	uint8_t data[256 + sizeof(struct bt_hci_cmd_hdr)];
	uint16_t len;
};

struct cmd_queue {
	struct cmd *head;
	struct cmd *tail;
};

struct cid_hook {
	uint16_t cid;
	bthost_cid_hook_func_t func;
	void *user_data;
	struct cid_hook *next;
};

struct btconn {
	uint16_t handle;
	uint8_t addr_type;
	uint16_t next_cid;
	struct l2conn *l2conns;
	struct cid_hook *cid_hooks;
	struct btconn *next;
};

struct l2conn {
	uint16_t scid;
	uint16_t dcid;
	struct l2conn *next;
};

struct l2cap_pending_req {
	uint8_t ident;
	bthost_l2cap_rsp_cb cb;
	void *user_data;
	struct l2cap_pending_req *next;
};

struct bthost {
	uint8_t bdaddr[6];
	bthost_send_func send_handler;
	void *send_data;
	struct cmd_queue cmd_q;
	uint8_t ncmd;
	struct btconn *conns;
	bthost_cmd_complete_cb cmd_complete_cb;
	void *cmd_complete_data;
	bthost_new_conn_cb new_conn_cb;
	void *new_conn_data;
	uint16_t server_psm;
	struct l2cap_pending_req *l2reqs;
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

static void l2conn_free(struct l2conn *conn)
{
	free(conn);
}

static void btconn_free(struct btconn *conn)
{
	while (conn->l2conns) {
		struct l2conn *l2conn = conn->l2conns;

		conn->l2conns = l2conn->next;
		l2conn_free(l2conn);
	}

	while (conn->cid_hooks) {
		struct cid_hook *hook = conn->cid_hooks;

		conn->cid_hooks = hook->next;
		free(hook);
	}

	free(conn);
}

static struct btconn *bthost_find_conn(struct bthost *bthost, uint16_t handle)
{
	struct btconn *conn;

	for (conn = bthost->conns; conn != NULL; conn = conn->next) {
		if (conn->handle == handle)
			return conn;
	}

	return NULL;
}

static void bthost_add_l2cap_conn(struct bthost *bthost, struct btconn *conn,
						uint16_t scid, uint16_t dcid)
{
	struct l2conn *l2conn;

	l2conn = malloc(sizeof(*l2conn));
	if (!l2conn)
		return;

	memset(l2conn, 0, sizeof(*l2conn));

	l2conn->scid = scid;
	l2conn->dcid = dcid;

	l2conn->next = conn->l2conns;
	conn->l2conns = l2conn;
}

static struct l2conn *btconn_find_l2cap_conn_by_scid(struct btconn *conn,
								uint16_t scid)
{
	struct l2conn *l2conn;

	for (l2conn = conn->l2conns; l2conn != NULL; l2conn = l2conn->next) {
		if (l2conn->scid == scid)
			return l2conn;
	}

	return NULL;
}

void bthost_destroy(struct bthost *bthost)
{
	struct cmd *cmd;

	if (!bthost)
		return;

	for (cmd = bthost->cmd_q.tail; cmd != NULL; cmd = cmd->next)
		free(cmd);

	while (bthost->conns) {
		struct btconn *conn = bthost->conns;

		bthost->conns = conn->next;
		btconn_free(conn);
	}

	while (bthost->l2reqs) {
		struct l2cap_pending_req *req = bthost->l2reqs;

		bthost->l2reqs = req->next;
		req->cb(0, NULL, 0, req->user_data);
		free(req);
	}

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

static void queue_command(struct bthost *bthost, const void *data,
								uint16_t len)
{
	struct cmd_queue *cmd_q = &bthost->cmd_q;
	struct cmd *cmd;

	cmd = malloc(sizeof(*cmd));
	if (!cmd)
		return;

	memset(cmd, 0, sizeof(*cmd));

	memcpy(cmd->data, data, len);
	cmd->len = len;

	if (cmd_q->tail)
		cmd_q->tail->next = cmd;

	cmd->prev = cmd_q->tail;
	cmd_q->tail = cmd;
}

static void send_packet(struct bthost *bthost, const void *data, uint16_t len)
{
	if (!bthost->send_handler)
		return;

	bthost->send_handler(data, len, bthost->send_data);
}

static void send_acl(struct bthost *bthost, uint16_t handle, uint16_t cid,
						const void *data, uint16_t len)
{
	struct bt_hci_acl_hdr *acl_hdr;
	struct bt_l2cap_hdr *l2_hdr;
	uint16_t pkt_len;
	void *pkt_data;

	pkt_len = 1 + sizeof(*acl_hdr) + sizeof(*l2_hdr) + len;

	pkt_data = malloc(pkt_len);
	if (!pkt_data)
		return;

	((uint8_t *) pkt_data)[0] = BT_H4_ACL_PKT;

	acl_hdr = pkt_data + 1;
	acl_hdr->handle = acl_handle_pack(handle, 0);
	acl_hdr->dlen = cpu_to_le16(len + sizeof(*l2_hdr));

	l2_hdr = pkt_data + 1 + sizeof(*acl_hdr);
	l2_hdr->cid = cpu_to_le16(cid);
	l2_hdr->len = cpu_to_le16(len);

	if (len > 0)
		memcpy(pkt_data + 1 + sizeof(*acl_hdr) + sizeof(*l2_hdr),
								data, len);

	send_packet(bthost, pkt_data, pkt_len);

	free(pkt_data);
}

static uint8_t l2cap_sig_send(struct bthost *bthost, struct btconn *conn,
					uint8_t code, uint8_t ident,
					const void *data, uint16_t len)
{
	static uint8_t next_ident = 1;
	struct bt_l2cap_hdr_sig *hdr;
	uint16_t pkt_len, cid;
	void *pkt_data;

	pkt_len = sizeof(*hdr) + len;

	pkt_data = malloc(pkt_len);
	if (!pkt_data)
		return 0;

	if (!ident) {
		ident = next_ident++;
		if (!ident)
			ident = next_ident++;
	}

	hdr = pkt_data;
	hdr->code  = code;
	hdr->ident = ident;
	hdr->len   = cpu_to_le16(len);

	if (len > 0)
		memcpy(pkt_data + sizeof(*hdr), data, len);

	if (conn->addr_type == BDADDR_BREDR)
		cid = 0x0001;
	else
		cid = 0x0005;

	send_acl(bthost, conn->handle, cid, pkt_data, pkt_len);

	free(pkt_data);

	return ident;
}

void bthost_add_cid_hook(struct bthost *bthost, uint16_t handle, uint16_t cid,
				bthost_cid_hook_func_t func, void *user_data)
{
	struct cid_hook *hook;
	struct btconn *conn;

	conn = bthost_find_conn(bthost, handle);
	if (!conn)
		return;

	hook = malloc(sizeof(*hook));
	if (!hook)
		return;

	memset(hook, 0, sizeof(*hook));

	hook->cid = cid;
	hook->func = func;
	hook->user_data = user_data;

	hook->next = conn->cid_hooks;
	conn->cid_hooks = hook;
}

void bthost_send_cid(struct bthost *bthost, uint16_t handle, uint16_t cid,
					const void *data, uint16_t len)
{
	struct btconn *conn;

	conn = bthost_find_conn(bthost, handle);
	if (!conn)
		return;

	send_acl(bthost, handle, cid, data, len);
}

bool bthost_l2cap_req(struct bthost *bthost, uint16_t handle, uint8_t code,
				const void *data, uint16_t len,
				bthost_l2cap_rsp_cb cb, void *user_data)
{
	struct l2cap_pending_req *req;
	struct btconn *conn;
	uint8_t ident;

	conn = bthost_find_conn(bthost, handle);
	if (!conn)
		return false;

	ident = l2cap_sig_send(bthost, conn, code, 0, data, len);
	if (!ident)
		return false;

	if (!cb)
		return true;

	req = malloc(sizeof(*req));
	if (!req)
		return false;

	memset(req, 0, sizeof(*req));
	req->ident = ident;
	req->cb = cb;
	req->user_data = user_data;

	req->next = bthost->l2reqs;
	bthost->l2reqs = req;

	return true;
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

	if (bthost->ncmd) {
		send_packet(bthost, pkt_data, pkt_len);
		bthost->ncmd--;
	} else {
		queue_command(bthost, pkt_data, pkt_len);
	}

	free(pkt_data);
}

static void next_cmd(struct bthost *bthost)
{
	struct cmd_queue *cmd_q = &bthost->cmd_q;
	struct cmd *cmd = cmd_q->tail;
	struct cmd *next;

	if (!cmd)
		return;

	next = cmd->next;

	if (!bthost->ncmd)
		return;

	send_packet(bthost, cmd->data, cmd->len);
	bthost->ncmd--;

	if (next)
		next->prev = NULL;

	cmd_q->tail = next;

	free(cmd);
}

static void read_bd_addr_complete(struct bthost *bthost, const void *data,
								uint8_t len)
{
	const struct bt_hci_rsp_read_bd_addr *ev = data;

	if (len < sizeof(*ev))
		return;

	if (ev->status)
		return;

	memcpy(bthost->bdaddr, ev->bdaddr, 6);
}

static void evt_cmd_complete(struct bthost *bthost, const void *data,
								uint8_t len)
{
	const struct bt_hci_evt_cmd_complete *ev = data;
	const void *param;
	uint16_t opcode;

	if (len < sizeof(*ev))
		return;

	param = data + sizeof(*ev);

	bthost->ncmd = ev->ncmd;

	opcode = le16toh(ev->opcode);

	switch (opcode) {
	case BT_HCI_CMD_RESET:
		break;
	case BT_HCI_CMD_READ_BD_ADDR:
		read_bd_addr_complete(bthost, param, len - sizeof(*ev));
		break;
	case BT_HCI_CMD_WRITE_SCAN_ENABLE:
		break;
	case BT_HCI_CMD_LE_SET_ADV_ENABLE:
		break;
	default:
		printf("Unhandled cmd_complete opcode 0x%04x\n", opcode);
		break;
	}

	if (bthost->cmd_complete_cb)
		bthost->cmd_complete_cb(opcode, 0, param, len - sizeof(*ev),
						bthost->cmd_complete_data);

	next_cmd(bthost);
}

static void evt_cmd_status(struct bthost *bthost, const void *data,
								uint8_t len)
{
	const struct bt_hci_evt_cmd_status *ev = data;
	uint16_t opcode;

	if (len < sizeof(*ev))
		return;

	bthost->ncmd = ev->ncmd;

	opcode = le16toh(ev->opcode);

	if (ev->status && bthost->cmd_complete_cb)
		bthost->cmd_complete_cb(opcode, ev->status, NULL, 0,
						bthost->cmd_complete_data);

	next_cmd(bthost);
}

static void evt_conn_request(struct bthost *bthost, const void *data,
								uint8_t len)
{
	const struct bt_hci_evt_conn_request *ev = data;
	struct bt_hci_cmd_accept_conn_request cmd;

	if (len < sizeof(*ev))
		return;

	memset(&cmd, 0, sizeof(cmd));
	memcpy(cmd.bdaddr, ev->bdaddr, sizeof(ev->bdaddr));

	send_command(bthost, BT_HCI_CMD_ACCEPT_CONN_REQUEST, &cmd,
								sizeof(cmd));
}

static void init_conn(struct bthost *bthost, uint16_t handle, uint8_t addr_type)
{
	struct btconn *conn;

	conn = malloc(sizeof(*conn));
	if (!conn)
		return;

	memset(conn, 0, sizeof(*conn));
	conn->handle = handle;
	conn->addr_type = addr_type;
	conn->next_cid = 0x0040;

	conn->next = bthost->conns;
	bthost->conns = conn;

	if (bthost->new_conn_cb)
		bthost->new_conn_cb(conn->handle, bthost->new_conn_data);
}

static void evt_conn_complete(struct bthost *bthost, const void *data,
								uint8_t len)
{
	const struct bt_hci_evt_conn_complete *ev = data;

	if (len < sizeof(*ev))
		return;

	if (ev->status)
		return;

	init_conn(bthost, le16_to_cpu(ev->handle), BDADDR_BREDR);
}

static void evt_disconn_complete(struct bthost *bthost, const void *data,
								uint8_t len)
{
	const struct bt_hci_evt_disconnect_complete *ev = data;
	struct btconn **curr;
	uint16_t handle;

	if (len < sizeof(*ev))
		return;

	if (ev->status)
		return;

	handle = le16_to_cpu(ev->handle);

	for (curr = &bthost->conns; *curr;) {
		struct btconn *conn = *curr;

		if (conn->handle == handle) {
			*curr = conn->next;
			btconn_free(conn);
		} else {
			curr = &conn->next;
		}
	}
}

static void evt_num_completed_packets(struct bthost *bthost, const void *data,
								uint8_t len)
{
	const struct bt_hci_evt_num_completed_packets *ev = data;

	if (len < sizeof(*ev))
		return;
}

static void evt_le_conn_complete(struct bthost *bthost, const void *data,
								uint8_t len)
{
	const struct bt_hci_evt_le_conn_complete *ev = data;
	uint8_t addr_type;

	if (len < sizeof(*ev))
		return;

	if (ev->status)
		return;

	if (ev->peer_addr_type == 0x00)
		addr_type = BDADDR_LE_PUBLIC;
	else
		addr_type = BDADDR_LE_RANDOM;

	init_conn(bthost, le16_to_cpu(ev->handle), addr_type);
}

static void evt_le_meta_event(struct bthost *bthost, const void *data,
								uint8_t len)
{
	const uint8_t *event = data;
	const void *evt_data = data + 1;

	if (len < 1)
		return;

	switch (*event) {
	case BT_HCI_EVT_LE_CONN_COMPLETE:
		evt_le_conn_complete(bthost, evt_data, len - 1);
		break;
	default:
		break;
	}
}

static void process_evt(struct bthost *bthost, const void *data, uint16_t len)
{
	const struct bt_hci_evt_hdr *hdr = data;
	const void *param;

	if (len < sizeof(*hdr))
		return;

	if (sizeof(*hdr) + hdr->plen != len)
		return;

	param = data + sizeof(*hdr);

	switch (hdr->evt) {
	case BT_HCI_EVT_CMD_COMPLETE:
		evt_cmd_complete(bthost, param, hdr->plen);
		break;

	case BT_HCI_EVT_CMD_STATUS:
		evt_cmd_status(bthost, param, hdr->plen);
		break;

	case BT_HCI_EVT_CONN_REQUEST:
		evt_conn_request(bthost, param, hdr->plen);
		break;

	case BT_HCI_EVT_CONN_COMPLETE:
		evt_conn_complete(bthost, param, hdr->plen);
		break;

	case BT_HCI_EVT_DISCONNECT_COMPLETE:
		evt_disconn_complete(bthost, param, hdr->plen);
		break;

	case BT_HCI_EVT_NUM_COMPLETED_PACKETS:
		evt_num_completed_packets(bthost, param, hdr->plen);
		break;

	case BT_HCI_EVT_LE_META_EVENT:
		evt_le_meta_event(bthost, param, hdr->plen);
		break;

	default:
		printf("Unsupported event 0x%2.2x\n", hdr->evt);
		break;
	}
}

static bool l2cap_cmd_rej(struct bthost *bthost, struct btconn *conn,
				uint8_t ident, const void *data, uint16_t len)
{
	const struct bt_l2cap_pdu_cmd_reject *rsp = data;

	if (len < sizeof(*rsp))
		return false;

	return true;
}

static bool l2cap_conn_req(struct bthost *bthost, struct btconn *conn,
				uint8_t ident, const void *data, uint16_t len)
{
	const struct bt_l2cap_pdu_conn_req *req = data;
	struct bt_l2cap_pdu_conn_rsp rsp;
	uint16_t psm;

	if (len < sizeof(*req))
		return false;

	psm = le16_to_cpu(req->psm);

	memset(&rsp, 0, sizeof(rsp));
	rsp.scid = req->scid;

	if (bthost->server_psm && bthost->server_psm == psm)
		rsp.dcid = cpu_to_le16(conn->next_cid++);
	else
		rsp.result = cpu_to_le16(0x0002); /* PSM Not Supported */

	l2cap_sig_send(bthost, conn, BT_L2CAP_PDU_CONN_RSP, ident, &rsp,
								sizeof(rsp));

	if (!rsp.result) {
		struct bt_l2cap_pdu_config_req conf_req;

		bthost_add_l2cap_conn(bthost, conn, le16_to_cpu(rsp.dcid),
							le16_to_cpu(rsp.scid));

		memset(&conf_req, 0, sizeof(conf_req));
		conf_req.dcid = rsp.dcid;

		l2cap_sig_send(bthost, conn, BT_L2CAP_PDU_CONFIG_REQ, 0,
						&conf_req, sizeof(conf_req));
	}

	return true;
}

static bool l2cap_conn_rsp(struct bthost *bthost, struct btconn *conn,
				uint8_t ident, const void *data, uint16_t len)
{
	const struct bt_l2cap_pdu_conn_rsp *rsp = data;

	if (len < sizeof(*rsp))
		return false;

	bthost_add_l2cap_conn(bthost, conn, le16_to_cpu(rsp->scid),
						le16_to_cpu(rsp->dcid));

	if (le16_to_cpu(rsp->result) == 0x0001) {
		struct bt_l2cap_pdu_config_req req;

		memset(&req, 0, sizeof(req));
		req.dcid = rsp->dcid;

		l2cap_sig_send(bthost, conn, BT_L2CAP_PDU_CONFIG_REQ, 0,
							&req, sizeof(req));
	}

	return true;
}

static bool l2cap_config_req(struct bthost *bthost, struct btconn *conn,
				uint8_t ident, const void *data, uint16_t len)
{
	const struct bt_l2cap_pdu_config_req *req = data;
	struct bt_l2cap_pdu_config_rsp rsp;
	struct l2conn *l2conn;
	uint16_t dcid;

	if (len < sizeof(*req))
		return false;

	dcid = le16_to_cpu(req->dcid);

	l2conn = btconn_find_l2cap_conn_by_scid(conn, dcid);
	if (!l2conn)
		return false;

	memset(&rsp, 0, sizeof(rsp));
	rsp.scid  = cpu_to_le16(l2conn->dcid);
	rsp.flags = req->flags;

	l2cap_sig_send(bthost, conn, BT_L2CAP_PDU_CONFIG_RSP, ident, &rsp,
								sizeof(rsp));

	return true;
}

static bool l2cap_config_rsp(struct bthost *bthost, struct btconn *conn,
				uint8_t ident, const void *data, uint16_t len)
{
	const struct bt_l2cap_pdu_config_rsp *rsp = data;

	if (len < sizeof(*rsp))
		return false;

	return true;
}

static bool l2cap_disconn_req(struct bthost *bthost, struct btconn *conn,
				uint8_t ident, const void *data, uint16_t len)
{
	const struct bt_l2cap_pdu_disconn_req *req = data;
	struct bt_l2cap_pdu_disconn_rsp rsp;

	if (len < sizeof(*req))
		return false;

	memset(&rsp, 0, sizeof(rsp));
	rsp.dcid = req->dcid;
	rsp.scid = req->scid;

	l2cap_sig_send(bthost, conn, BT_L2CAP_PDU_DISCONN_RSP, ident, &rsp,
								sizeof(rsp));

	return true;
}

static bool l2cap_info_req(struct bthost *bthost, struct btconn *conn,
				uint8_t ident, const void *data, uint16_t len)
{
	const struct bt_l2cap_pdu_info_req *req = data;
	struct bt_l2cap_pdu_info_rsp rsp;

	if (len < sizeof(*req))
		return false;

	rsp.type = req->type;
	rsp.result = cpu_to_le16(0x0001); /* Not Supported */

	l2cap_sig_send(bthost, conn, BT_L2CAP_PDU_INFO_RSP, ident, &rsp,
								sizeof(rsp));

	return true;
}

static void handle_pending_l2reqs(struct bthost *bthost, struct btconn *conn,
						uint8_t ident, uint8_t code,
						const void *data, uint16_t len)
{
	struct l2cap_pending_req **curr;

	for (curr = &bthost->l2reqs; *curr != NULL;) {
		struct l2cap_pending_req *req = *curr;

		if (req->ident != ident) {
			curr = &req->next;
			continue;
		}

		*curr = req->next;
		req->cb(code, data, len, req->user_data);
		free(req);
	}
}

static void l2cap_sig(struct bthost *bthost, struct btconn *conn,
						const void *data, uint16_t len)
{
	const struct bt_l2cap_hdr_sig *hdr = data;
	struct bt_l2cap_pdu_cmd_reject rej;
	uint16_t hdr_len;
	bool ret;

	if (len < sizeof(*hdr))
		goto reject;

	hdr_len = le16_to_cpu(hdr->len);

	if (sizeof(*hdr) + hdr_len != len)
		goto reject;

	switch (hdr->code) {
	case BT_L2CAP_PDU_CMD_REJECT:
		ret = l2cap_cmd_rej(bthost, conn, hdr->ident,
						data + sizeof(*hdr), hdr_len);
		break;

	case BT_L2CAP_PDU_CONN_REQ:
		ret = l2cap_conn_req(bthost, conn, hdr->ident,
						data + sizeof(*hdr), hdr_len);
		break;

	case BT_L2CAP_PDU_CONN_RSP:
		ret = l2cap_conn_rsp(bthost, conn, hdr->ident,
						data + sizeof(*hdr), hdr_len);
		break;

	case BT_L2CAP_PDU_CONFIG_REQ:
		ret = l2cap_config_req(bthost, conn, hdr->ident,
						data + sizeof(*hdr), hdr_len);
		break;

	case BT_L2CAP_PDU_CONFIG_RSP:
		ret = l2cap_config_rsp(bthost, conn, hdr->ident,
						data + sizeof(*hdr), hdr_len);
		break;

	case BT_L2CAP_PDU_DISCONN_REQ:
		ret = l2cap_disconn_req(bthost, conn, hdr->ident,
						data + sizeof(*hdr), hdr_len);
		break;

	case BT_L2CAP_PDU_INFO_REQ:
		ret = l2cap_info_req(bthost, conn, hdr->ident,
						data + sizeof(*hdr), hdr_len);
		break;

	default:
		printf("Unknown L2CAP code 0x%02x\n", hdr->code);
		ret = false;
	}

	handle_pending_l2reqs(bthost, conn, hdr->ident, hdr->code,
						data + sizeof(*hdr), hdr_len);

	if (ret)
		return;

reject:
	memset(&rej, 0, sizeof(rej));
	l2cap_sig_send(bthost, conn, BT_L2CAP_PDU_CMD_REJECT, 0,
							&rej, sizeof(rej));
}

static bool l2cap_conn_param_req(struct bthost *bthost, struct btconn *conn,
				uint8_t ident, const void *data, uint16_t len)
{
	const struct bt_l2cap_pdu_conn_param_req *req = data;
	struct bt_l2cap_pdu_conn_param_rsp rsp;
	struct bt_hci_cmd_le_conn_update hci_cmd;

	if (len < sizeof(*req))
		return false;

	memset(&hci_cmd, 0, sizeof(hci_cmd));
	hci_cmd.handle = cpu_to_le16(conn->handle);
	hci_cmd.min_interval = req->min_interval;
	hci_cmd.max_interval = req->max_interval;
	hci_cmd.latency = req->latency;
	hci_cmd.supv_timeout = req->timeout;
	hci_cmd.min_length = cpu_to_le16(0x0001);
	hci_cmd.max_length = cpu_to_le16(0x0001);

	send_command(bthost, BT_HCI_CMD_LE_CONN_UPDATE,
						&hci_cmd, sizeof(hci_cmd));

	memset(&rsp, 0, sizeof(rsp));
	l2cap_sig_send(bthost, conn, BT_L2CAP_PDU_CONN_PARAM_RSP, ident,
							&rsp, sizeof(rsp));

	return true;
}

static bool l2cap_conn_param_rsp(struct bthost *bthost, struct btconn *conn,
				uint8_t ident, const void *data, uint16_t len)
{
	const struct bt_l2cap_pdu_conn_param_req *rsp = data;

	if (len < sizeof(*rsp))
		return false;

	return true;
}

static void l2cap_le_sig(struct bthost *bthost, struct btconn *conn,
						const void *data, uint16_t len)
{
	const struct bt_l2cap_hdr_sig *hdr = data;
	struct bt_l2cap_pdu_cmd_reject rej;
	uint16_t hdr_len;
	bool ret;

	if (len < sizeof(*hdr))
		goto reject;

	hdr_len = le16_to_cpu(hdr->len);

	if (sizeof(*hdr) + hdr_len != len)
		goto reject;

	switch (hdr->code) {
	case BT_L2CAP_PDU_CMD_REJECT:
		ret = l2cap_cmd_rej(bthost, conn, hdr->ident,
						data + sizeof(*hdr), hdr_len);
		break;

	case BT_L2CAP_PDU_CONN_PARAM_REQ:
		ret = l2cap_conn_param_req(bthost, conn, hdr->ident,
						data + sizeof(*hdr), hdr_len);
		break;

	case BT_L2CAP_PDU_CONN_PARAM_RSP:
		ret = l2cap_conn_param_rsp(bthost, conn, hdr->ident,
						data + sizeof(*hdr), hdr_len);
		break;

	default:
		printf("Unknown L2CAP code 0x%02x\n", hdr->code);
		ret = false;
	}

	handle_pending_l2reqs(bthost, conn, hdr->ident, hdr->code,
						data + sizeof(*hdr), hdr_len);

	if (ret)
		return;

reject:
	memset(&rej, 0, sizeof(rej));
	l2cap_sig_send(bthost, conn, BT_L2CAP_PDU_CMD_REJECT, 0,
							&rej, sizeof(rej));
}

static struct cid_hook *find_cid_hook(struct btconn *conn, uint16_t cid)
{
	struct cid_hook *hook;

	for (hook = conn->cid_hooks; hook != NULL; hook = hook->next) {
		if (hook->cid == cid)
			return hook;
	}

	return NULL;
}

static void process_acl(struct bthost *bthost, const void *data, uint16_t len)
{
	const struct bt_hci_acl_hdr *acl_hdr = data;
	const struct bt_l2cap_hdr *l2_hdr = data + sizeof(*acl_hdr);
	uint16_t handle, cid, acl_len, l2_len;
	struct cid_hook *hook;
	struct btconn *conn;
	const void *l2_data;

	if (len < sizeof(*acl_hdr) + sizeof(*l2_hdr))
		return;

	acl_len = le16_to_cpu(acl_hdr->dlen);
	if (len != sizeof(*acl_hdr) + acl_len)
		return;

	handle = acl_handle(acl_hdr->handle);
	conn = bthost_find_conn(bthost, handle);
	if (!conn) {
		printf("ACL data for unknown handle 0x%04x\n", handle);
		return;
	}

	l2_len = le16_to_cpu(l2_hdr->len);
	if (len - sizeof(*acl_hdr) != sizeof(*l2_hdr) + l2_len)
		return;

	l2_data = data + sizeof(*acl_hdr) + sizeof(*l2_hdr);

	cid = le16_to_cpu(l2_hdr->cid);

	hook = find_cid_hook(conn, cid);
	if (hook) {
		hook->func(l2_data, l2_len, hook->user_data);
		return;
	}

	switch (cid) {
	case 0x0001:
		l2cap_sig(bthost, conn, l2_data, l2_len);
		break;
	case 0x0005:
		l2cap_le_sig(bthost, conn, l2_data, l2_len);
		break;
	default:
		printf("Packet for unknown CID 0x%04x (%u)\n", cid, cid);
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
	case BT_H4_ACL_PKT:
		process_acl(bthost, data + 1, len - 1);
		break;
	default:
		printf("Unsupported packet 0x%2.2x\n", pkt_type);
		break;
	}
}

void bthost_set_cmd_complete_cb(struct bthost *bthost,
				bthost_cmd_complete_cb cb, void *user_data)
{
	bthost->cmd_complete_cb = cb;
	bthost->cmd_complete_data = user_data;
}

void bthost_set_connect_cb(struct bthost *bthost, bthost_new_conn_cb cb,
							void *user_data)
{
	bthost->new_conn_cb = cb;
	bthost->new_conn_data = user_data;
}

void bthost_hci_connect(struct bthost *bthost, const uint8_t *bdaddr,
							uint8_t addr_type)
{
	if (addr_type == BDADDR_BREDR) {
		struct bt_hci_cmd_create_conn cc;

		memset(&cc, 0, sizeof(cc));
		memcpy(cc.bdaddr, bdaddr, sizeof(cc.bdaddr));

		send_command(bthost, BT_HCI_CMD_CREATE_CONN, &cc, sizeof(cc));
	} else {
		struct bt_hci_cmd_le_create_conn cc;

		memset(&cc, 0, sizeof(cc));
		memcpy(cc.peer_addr, bdaddr, sizeof(cc.peer_addr));

		if (addr_type == BDADDR_LE_RANDOM)
			cc.peer_addr_type = 0x01;

		send_command(bthost, BT_HCI_CMD_LE_CREATE_CONN,
							&cc, sizeof(cc));
	}
}

void bthost_write_scan_enable(struct bthost *bthost, uint8_t scan)
{
	send_command(bthost, BT_HCI_CMD_WRITE_SCAN_ENABLE, &scan, 1);
}

void bthost_set_adv_enable(struct bthost *bthost, uint8_t enable)
{
	send_command(bthost, BT_HCI_CMD_LE_SET_ADV_ENABLE, &enable, 1);
}

void bthost_set_server_psm(struct bthost *bthost, uint16_t psm)
{
	bthost->server_psm = psm;
}

void bthost_start(struct bthost *bthost)
{
	if (!bthost)
		return;

	bthost->ncmd = 1;

	send_command(bthost, BT_HCI_CMD_RESET, NULL, 0);

	send_command(bthost, BT_HCI_CMD_READ_BD_ADDR, NULL, 0);
}

void bthost_stop(struct bthost *bthost)
{
}
