/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Google Inc.
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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "src/shared/io.h"
#include "src/shared/queue.h"
#include "src/shared/util.h"
#include "src/shared/timeout.h"
#include "lib/uuid.h"
#include "src/shared/att.h"

#define ATT_DEFAULT_LE_MTU		23
#define ATT_MIN_PDU_LEN			1  /* At least 1 byte for the opcode. */
#define ATT_OP_CMD_MASK			0x40
#define ATT_OP_SIGNED_MASK		0x80
#define ATT_TIMEOUT_INTERVAL		30000  /* 30000 ms */

struct att_send_op;

struct bt_att {
	int ref_count;
	int fd;
	bool close_on_unref;
	struct io *io;
	bool invalid;  /* bt_att becomes invalid when a request times out */

	struct queue *req_queue;	/* Queued ATT protocol requests */
	struct att_send_op *pending_req;
	struct queue *ind_queue;	/* Queued ATT protocol indications */
	struct att_send_op *pending_ind;
	struct queue *write_queue;	/* Queue of PDUs ready to send */
	bool writer_active;

	uint8_t *buf;
	uint16_t mtu;

	unsigned int next_send_id;	/* IDs for "send" ops */
	unsigned int next_reg_id;	/* IDs for registered callbacks */

	bt_att_timeout_func_t timeout_callback;
	bt_att_destroy_func_t timeout_destroy;
	void *timeout_data;

	bt_att_debug_func_t debug_callback;
	bt_att_destroy_func_t debug_destroy;
	void *debug_data;
};

enum att_op_type {
	ATT_OP_TYPE_REQ,
	ATT_OP_TYPE_RSP,
	ATT_OP_TYPE_CMD,
	ATT_OP_TYPE_IND,
	ATT_OP_TYPE_NOT,
	ATT_OP_TYPE_CONF,
	ATT_OP_TYPE_UNKNOWN,
};

static const struct {
	uint8_t opcode;
	enum att_op_type type;
} att_opcode_type_table[] = {
	{ BT_ATT_OP_ERROR_RSP,			ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_MTU_REQ,			ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_MTU_RSP,			ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_FIND_INFO_REQ,		ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_FIND_INFO_RSP,		ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_FIND_BY_TYPE_VAL_REQ,	ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_FIND_BY_TYPE_VAL_RSP,	ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_READ_BY_TYPE_REQ,		ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_READ_BY_TYPE_RSP,		ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_READ_REQ,			ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_READ_RSP,			ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_READ_BLOB_REQ,		ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_READ_BLOB_RSP,		ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_READ_MULT_REQ,		ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_READ_MULT_RSP,		ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_READ_BY_GRP_TYPE_REQ,	ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_READ_BY_GRP_TYPE_RSP,	ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_WRITE_REQ,			ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_WRITE_RSP,			ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_WRITE_CMD,			ATT_OP_TYPE_CMD },
	{ BT_ATT_OP_SIGNED_WRITE_CMD,		ATT_OP_TYPE_CMD },
	{ BT_ATT_OP_PREP_WRITE_REQ,		ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_PREP_WRITE_RSP,		ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_EXEC_WRITE_REQ,		ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_EXEC_WRITE_RSP,		ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_HANDLE_VAL_NOT,		ATT_OP_TYPE_NOT },
	{ BT_ATT_OP_HANDLE_VAL_IND,		ATT_OP_TYPE_IND },
	{ BT_ATT_OP_HANDLE_VAL_CONF,		ATT_OP_TYPE_CONF },
	{ }
};

static enum att_op_type get_op_type(uint8_t opcode)
{
	int i;

	for (i = 0; att_opcode_type_table[i].opcode; i++) {
		if (att_opcode_type_table[i].opcode == opcode)
			return att_opcode_type_table[i].type;
	}

	return ATT_OP_TYPE_UNKNOWN;
}

struct att_send_op {
	unsigned int id;
	unsigned int timeout_id;
	enum att_op_type type;
	uint16_t opcode;
	void *pdu;
	uint16_t len;
	bt_att_request_func_t callback;
	bt_att_destroy_func_t destroy;
	void *user_data;
};

static bool encode_mtu_req(struct att_send_op *op, const void *param,
						uint16_t length, uint16_t mtu)
{
	const struct bt_att_mtu_req_param *p = param;
	const uint16_t len = 3;

	if (length != sizeof(*p))
		return false;

	if (len > mtu)
		return false;

	op->pdu = malloc(len);
	if (!op->pdu)
		return false;

	((uint8_t *) op->pdu)[0] = op->opcode;
	put_le16(p->client_rx_mtu, ((uint8_t *) op->pdu) + 1);
	op->len = len;

	return true;
}

static bool encode_pdu(struct att_send_op *op, const void *param,
						uint16_t length, uint16_t mtu)
{
	/* If no parameters are given, simply set the PDU to consist of the
	 * opcode (e.g. BT_ATT_OP_WRITE_RSP),
	 */
	if (!length || !param) {
		op->len = 1;
		op->pdu = malloc(1);
		if (!op->pdu)
			return false;

		((uint8_t *) op->pdu)[0] = op->opcode;
		return true;
	}

	/* TODO: If the opcode has the "signed" bit set, make sure that the
	 * resulting PDU contains the authentication signature. Return an error,
	 * if the provided parameters structure is such that it leaves no room
	 * for an authentication signature in the PDU, or if no signing data
	 * has been set to generate the authentication signature.
	 */

	switch (op->opcode) {
	case BT_ATT_OP_MTU_REQ:
		return encode_mtu_req(op, param, length, mtu);
	default:
		break;
	}

	return false;
}

static struct att_send_op *create_att_send_op(uint8_t opcode, const void *param,
						uint16_t length, uint16_t mtu,
						bt_att_request_func_t callback,
						void *user_data,
						bt_att_destroy_func_t destroy)
{
	struct att_send_op *op;
	enum att_op_type op_type;

	if (!length && !param)
		return NULL;

	op_type = get_op_type(opcode);
	if (op_type == ATT_OP_TYPE_UNKNOWN)
		return NULL;

	/* If the opcode corresponds to an operation type that does not elicit a
	 * response from the remote end, then no callback should have been
	 * provided, since it will never be called.
	 */
	if (callback && op_type != ATT_OP_TYPE_REQ && op_type != ATT_OP_TYPE_IND)
		return NULL;

	/* Similarly, if the operation does elicit a response then a callback
	 * must be provided.
	 */
	if (!callback && (op_type == ATT_OP_TYPE_REQ || op_type == ATT_OP_TYPE_IND))
		return NULL;

	op = new0(struct att_send_op, 1);
	if (!op)
		return NULL;

	op->type = op_type;
	op->opcode = opcode;
	op->callback = callback;
	op->destroy = destroy;
	op->user_data = user_data;

	if (!encode_pdu(op, param, length, mtu)) {
		free(op);
		return NULL;
	}

	return op;
}

static struct att_send_op *pick_next_send_op(struct bt_att *att)
{
	struct att_send_op *op;

	/* See if any operations are already in the write queue */
	op = queue_pop_head(att->write_queue);
	if (op)
		return op;

	/* If there is no pending request, pick an operation from the
	 * request queue.
	 */
	if (!att->pending_req) {
		op = queue_pop_head(att->req_queue);
		if (op)
			return op;
	}

	/* There is either a request pending or no requests queued. If there is
	 * no pending indication, pick an operation from the indication queue.
	 */
	if (!att->pending_ind) {
		op = queue_pop_head(att->ind_queue);
		if (op)
			return op;
	}

	return NULL;
}

static void destroy_att_send_op(void *data)
{
	struct att_send_op *op = data;

	if (op->timeout_id)
		timeout_remove(op->timeout_id);

	if (op->destroy)
		op->destroy(op->user_data);

	free(op->pdu);
	free(op);
}

struct timeout_data {
	struct bt_att *att;
	unsigned int id;
};

static bool timeout_cb(void *user_data)
{
	struct timeout_data *timeout = user_data;
	struct bt_att *att = timeout->att;
	struct att_send_op *op = NULL;

	if (att->pending_req && att->pending_req->id == timeout->id) {
		op = att->pending_req;
		att->pending_req = NULL;
	} else if (att->pending_ind && att->pending_ind->id == timeout->id) {
		op = att->pending_ind;
		att->pending_ind = NULL;
	}

	if (!op)
		return false;

	att->invalid = true;

	util_debug(att->debug_callback, att->debug_data,
				"Operation timed out: 0x%02x", op->opcode);

	if (att->timeout_callback)
		att->timeout_callback(op->id, op->opcode, att->timeout_data);

	op->timeout_id = 0;
	destroy_att_send_op(op);

	return false;
}

static void write_watch_destroy(void *user_data)
{
	struct bt_att *att = user_data;

	att->writer_active = false;
}

static bool can_write_data(struct io *io, void *user_data)
{
	struct bt_att *att = user_data;
	struct att_send_op *op;
	struct timeout_data *timeout;
	ssize_t bytes_written;

	op = pick_next_send_op(att);
	if (!op)
		return false;

	bytes_written = write(att->fd, op->pdu, op->len);
	if (bytes_written < 0) {
		util_debug(att->debug_callback, att->debug_data,
					"write failed: %s", strerror(errno));
		if (op->callback)
			op->callback(BT_ATT_OP_ERROR_RSP, NULL, 0,
							op->user_data);

		destroy_att_send_op(op);
		return true;
	}

	util_debug(att->debug_callback, att->debug_data,
					"ATT op 0x%02x", op->opcode);

	util_hexdump('<', op->pdu, bytes_written,
					att->debug_callback, att->debug_data);

	/* Based on the operation type, set either the pending request or the
	 * pending indication. If it came from the write queue, then there is
	 * no need to keep it around.
	 */
	switch (op->type) {
	case ATT_OP_TYPE_REQ:
		att->pending_req = op;
		break;
	case ATT_OP_TYPE_IND:
		att->pending_ind = op;
		break;
	default:
		destroy_att_send_op(op);
		return true;
	}

	timeout = new0(struct timeout_data, 1);
	if (!timeout)
		return true;

	timeout->att = att;
	timeout->id = op->id;
	op->timeout_id = timeout_add(ATT_TIMEOUT_INTERVAL, timeout_cb,
								timeout, free);

	/* Return true as there may be more operations ready to write. */
	return true;
}

static void wakeup_writer(struct bt_att *att)
{
	if (att->writer_active)
		return;

	/* Set the write handler only if there is anything that can be sent
	 * at all.
	 */
	if (queue_isempty(att->write_queue)) {
		if ((att->pending_req || queue_isempty(att->req_queue)) &&
			(att->pending_ind || queue_isempty(att->ind_queue)))
			return;
	}

	if (!io_set_write_handler(att->io, can_write_data, att,
							write_watch_destroy))
		return;

	att->writer_active = true;
}

static bool request_complete(struct bt_att *att, uint8_t req_opcode,
					uint8_t rsp_opcode, const void *param,
					uint16_t len)
{
	struct att_send_op *op = att->pending_req;

	if (!op) {
		/* There is no pending request so the response is unexpected. */
		wakeup_writer(att);
		return false;
	}

	if (op->opcode != req_opcode) {
		/* The request opcode corresponding to the received response
		 * opcode does not match the currently pending request.
		 */
		return false;
	}

	if (op->callback)
		op->callback(rsp_opcode, param, len, op->user_data);

	destroy_att_send_op(op);
	att->pending_req = NULL;

	wakeup_writer(att);
	return true;
}

static bool handle_error_rsp(struct bt_att *att, uint8_t opcode, uint8_t *pdu,
								ssize_t pdu_len)
{
	struct bt_att_error_rsp_param param;

	if (pdu_len != 5)
		return false;

	memset(&param, 0, sizeof(param));
	param.request_opcode = pdu[1];
	param.handle = get_le16(pdu + 2);
	param.error_code = pdu[4];

	return request_complete(att, pdu[1], opcode, &param, sizeof(param));
}

static bool handle_mtu_rsp(struct bt_att *att, uint8_t opcode, uint8_t *pdu,
								ssize_t pdu_len)
{
	struct bt_att_mtu_rsp_param param;

	if (pdu_len != 3)
		return false;

	memset(&param, 0, sizeof(param));
	param.server_rx_mtu = get_le16(pdu + 1);

	return request_complete(att, BT_ATT_OP_MTU_REQ, opcode,
							&param, sizeof(param));
}

static void handle_rsp(struct bt_att *att, uint8_t opcode, uint8_t *pdu,
								ssize_t pdu_len)
{
	bool success;

	switch (opcode) {
	case BT_ATT_OP_ERROR_RSP:
		success = handle_error_rsp(att, opcode, pdu, pdu_len);
		break;
	case BT_ATT_OP_MTU_RSP:
		success = handle_mtu_rsp(att, opcode, pdu, pdu_len);
		break;
	default:
		success = false;
		util_debug(att->debug_callback, att->debug_data,
				"Unknown response opcode: 0x%02x", opcode);
		break;
	}

	if (success)
		return;

	util_debug(att->debug_callback, att->debug_data,
			"Failed to handle respone PDU; opcode: 0x%02x", opcode);

	if (att->pending_req)
		request_complete(att, att->pending_req->opcode,
						BT_ATT_OP_ERROR_RSP, NULL, 0);
}

static bool can_read_data(struct io *io, void *user_data)
{
	struct bt_att *att = user_data;
	uint8_t opcode;
	uint8_t *pdu;
	ssize_t bytes_read;

	bytes_read = read(att->fd, att->buf, att->mtu);
	if (bytes_read < 0)
		return false;

	util_hexdump('>', att->buf, bytes_read,
					att->debug_callback, att->debug_data);

	if (bytes_read < ATT_MIN_PDU_LEN)
		return true;

	pdu = att->buf;
	opcode = pdu[0];

	/* Act on the received PDU based on the opcode type */
	switch (get_op_type(opcode)) {
	case ATT_OP_TYPE_RSP:
		handle_rsp(att, opcode, pdu, bytes_read);
		break;
	default:
		util_debug(att->debug_callback, att->debug_data,
				"ATT opcode cannot be handled: 0x%02x", opcode);
		break;
	}

	return true;
}

struct bt_att *bt_att_new(int fd)
{
	struct bt_att *att;

	if (fd < 0)
		return NULL;

	att = new0(struct bt_att, 1);
	if (!att)
		return NULL;

	att->fd = fd;

	att->mtu = ATT_DEFAULT_LE_MTU;
	att->buf = malloc(att->mtu);
	if (!att->buf)
		goto fail;

	att->io = io_new(fd);
	if (!att->io)
		goto fail;

	att->req_queue = queue_new();
	if (!att->req_queue)
		goto fail;

	att->ind_queue = queue_new();
	if (!att->ind_queue)
		goto fail;

	att->write_queue = queue_new();
	if (!att->write_queue)
		goto fail;

	if (!io_set_read_handler(att->io, can_read_data, att, NULL))
		goto fail;

	return bt_att_ref(att);

fail:
	queue_destroy(att->req_queue, NULL);
	queue_destroy(att->ind_queue, NULL);
	queue_destroy(att->write_queue, NULL);
	io_destroy(att->io);
	free(att->buf);
	free(att);

	return NULL;
}

struct bt_att *bt_att_ref(struct bt_att *att)
{
	if (!att)
		return NULL;

	__sync_fetch_and_add(&att->ref_count, 1);

	return att;
}

void bt_att_unref(struct bt_att *att)
{
	if (!att)
		return;

	if (__sync_sub_and_fetch(&att->ref_count, 1))
		return;

	bt_att_cancel_all(att);

	io_set_write_handler(att->io, NULL, NULL, NULL);
	io_set_read_handler(att->io, NULL, NULL, NULL);

	queue_destroy(att->req_queue, NULL);
	queue_destroy(att->ind_queue, NULL);
	queue_destroy(att->write_queue, NULL);
	att->req_queue = NULL;
	att->ind_queue = NULL;
	att->write_queue = NULL;

	io_destroy(att->io);
	att->io = NULL;

	if (att->close_on_unref)
		close(att->fd);

	if (att->timeout_destroy)
		att->timeout_destroy(att->timeout_data);

	if (att->debug_destroy)
		att->debug_destroy(att->debug_data);

	free(att->buf);
	att->buf = NULL;

	free(att);
}

bool bt_att_set_close_on_unref(struct bt_att *att, bool do_close)
{
	if (!att)
		return false;

	att->close_on_unref = do_close;

	return true;
}

bool bt_att_set_debug(struct bt_att *att, bt_att_debug_func_t callback,
				void *user_data, bt_att_destroy_func_t destroy)
{
	if (!att)
		return false;

	if (att->debug_destroy)
		att->debug_destroy(att->debug_data);

	att->debug_callback = callback;
	att->debug_destroy = destroy;
	att->debug_data = user_data;

	return true;
}

uint16_t bt_att_get_mtu(struct bt_att *att)
{
	if (!att)
		return 0;

	return att->mtu;
}

bool bt_att_set_mtu(struct bt_att *att, uint16_t mtu)
{
	void *buf;

	if (!att)
		return false;

	if (mtu < ATT_DEFAULT_LE_MTU)
		return false;

	buf = malloc(mtu);
	if (!buf)
		return false;

	free(att->buf);

	att->mtu = mtu;
	att->buf = buf;

	return true;
}

bool bt_att_set_timeout_cb(struct bt_att *att, bt_att_timeout_func_t callback,
						void *user_data,
						bt_att_destroy_func_t destroy)
{
	if (!att)
		return false;

	if (att->timeout_destroy)
		att->timeout_destroy(att->timeout_data);

	att->timeout_callback = callback;
	att->timeout_destroy = destroy;
	att->timeout_data = user_data;

	return true;
}

unsigned int bt_att_send(struct bt_att *att, uint8_t opcode,
				const void *param, uint16_t length,
				bt_att_request_func_t callback, void *user_data,
				bt_att_destroy_func_t destroy)
{
	struct att_send_op *op;
	bool result;

	if (!att)
		return 0;

	if (att->invalid)
		return 0;

	op = create_att_send_op(opcode, param, length, att->mtu, callback,
							user_data, destroy);
	if (!op)
		return 0;

	if (att->next_send_id < 1)
		att->next_send_id = 1;

	op->id = att->next_send_id++;

	/* Add the op to the correct queue based on its type */
	switch (op->type) {
	case ATT_OP_TYPE_REQ:
		result = queue_push_tail(att->req_queue, op);
		break;
	case ATT_OP_TYPE_IND:
		result = queue_push_tail(att->ind_queue, op);
		break;
	default:
		result = queue_push_tail(att->write_queue, op);
		break;
	}

	if (!result) {
		free(op->pdu);
		free(op);
		return 0;
	}

	wakeup_writer(att);

	return op->id;
}

static bool match_op_id(const void *a, const void *b)
{
	const struct att_send_op *op = a;
	unsigned int id = PTR_TO_UINT(b);

	return op->id == id;
}

bool bt_att_cancel(struct bt_att *att, unsigned int id)
{
	struct att_send_op *op;

	if (!att || !id)
		return false;

	if (att->pending_req && att->pending_req->id == id) {
		op = att->pending_req;
		goto done;
	}

	if (att->pending_ind && att->pending_ind->id == id) {
		op = att->pending_ind;
		goto done;
	}

	op = queue_remove_if(att->req_queue, match_op_id, UINT_TO_PTR(id));
	if (op)
		goto done;

	op = queue_remove_if(att->ind_queue, match_op_id, UINT_TO_PTR(id));
	if (op)
		goto done;

	op = queue_remove_if(att->write_queue, match_op_id, UINT_TO_PTR(id));
	if (op)
		goto done;

	if (!op)
		return false;

done:
	destroy_att_send_op(op);

	wakeup_writer(att);

	return true;
}

bool bt_att_cancel_all(struct bt_att *att)
{
	if (!att)
		return false;

	queue_remove_all(att->req_queue, NULL, NULL, destroy_att_send_op);
	queue_remove_all(att->ind_queue, NULL, NULL, destroy_att_send_op);
	queue_remove_all(att->write_queue, NULL, NULL, destroy_att_send_op);

	if (att->pending_req)
		destroy_att_send_op(att->pending_req);

	if (att->pending_ind)
		destroy_att_send_op(att->pending_ind);

	return true;
}

unsigned int bt_att_register(struct bt_att *att, uint8_t opcode,
				bt_att_request_func_t callback,
				void *user_data, bt_att_destroy_func_t destroy)
{
	/* TODO */
	return 0;
}

bool bt_att_unregister(struct bt_att *att, unsigned int id)
{
	/* TODO */
	return false;
}

bool bt_att_unregister_all(struct bt_att *att)
{
	/* TODO */
	return false;
}
