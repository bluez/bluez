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

#include <sys/uio.h>

#include "src/shared/att.h"
#include "lib/uuid.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/gatt-helpers.h"
#include "src/shared/att-types.h"
#include "src/shared/util.h"

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

struct async_read_op {
	struct bt_gatt_server *server;
	uint8_t opcode;
	bool done;
	uint8_t *pdu;
	size_t pdu_len;
	size_t value_len;
	struct queue *db_data;
};

struct async_write_op {
	struct bt_gatt_server *server;
	uint8_t opcode;
};

struct bt_gatt_server {
	struct gatt_db *db;
	struct bt_att *att;
	int ref_count;
	uint16_t mtu;

	unsigned int mtu_id;
	unsigned int read_by_grp_type_id;
	unsigned int read_by_type_id;
	unsigned int find_info_id;
	unsigned int write_id;
	unsigned int write_cmd_id;
	unsigned int read_id;

	struct async_read_op *pending_read_op;
	struct async_write_op *pending_write_op;

	bt_gatt_server_debug_func_t debug_callback;
	bt_gatt_server_destroy_func_t debug_destroy;
	void *debug_data;
};

static void bt_gatt_server_free(struct bt_gatt_server *server)
{
	if (server->debug_destroy)
		server->debug_destroy(server->debug_data);

	bt_att_unregister(server->att, server->mtu_id);
	bt_att_unregister(server->att, server->read_by_grp_type_id);
	bt_att_unregister(server->att, server->read_by_type_id);
	bt_att_unregister(server->att, server->find_info_id);
	bt_att_unregister(server->att, server->write_id);
	bt_att_unregister(server->att, server->write_cmd_id);
	bt_att_unregister(server->att, server->read_id);

	if (server->pending_read_op)
		server->pending_read_op->server = NULL;

	if (server->pending_write_op)
		server->pending_write_op->server = NULL;

	bt_att_unref(server->att);
	free(server);
}

static uint8_t att_ecode_from_error(int err)
{
	if (err < 0 || err > UINT8_MAX)
		return 0xff;

	return err;
}

static void encode_error_rsp(uint8_t opcode, uint16_t handle, uint8_t ecode,
								uint8_t pdu[4])
{
	pdu[0] = opcode;
	pdu[3] = ecode;
	put_le16(handle, pdu + 1);
}

static bool get_uuid_le(const uint8_t *uuid, size_t len, bt_uuid_t *out_uuid)
{
	uint128_t u128;

	switch (len) {
	case 2:
		bt_uuid16_create(out_uuid, get_le16(uuid));
		return true;
	case 16:
		bswap_128(uuid, &u128.data);
		bt_uuid128_create(out_uuid, u128);
		return true;
	default:
		return false;
	}

	return false;
}

static void attribute_read_cb(struct gatt_db_attribute *attrib, int err,
					const uint8_t *value, size_t length,
					void *user_data)
{
	struct iovec *iov = user_data;

	iov->iov_base = (void *) value;
	iov->iov_len = length;
}

static bool encode_read_by_grp_type_rsp(struct gatt_db *db, struct queue *q,
						uint16_t mtu,
						uint8_t *pdu, uint16_t *len)
{
	int iter = 0;
	uint16_t start_handle, end_handle;
	struct iovec value;
	uint8_t data_val_len;

	*len = 0;

	while (queue_peek_head(q)) {
		struct gatt_db_attribute *attrib = queue_pop_head(q);

		value.iov_base = NULL;
		value.iov_len = 0;

		/*
		 * This should never be deferred to the read callback for
		 * primary/secondary service declarations.
		 */
		if (!gatt_db_attribute_read(attrib, 0,
						BT_ATT_OP_READ_BY_GRP_TYPE_REQ,
						NULL, attribute_read_cb,
						&value) || !value.iov_len)
			return false;

		/*
		 * Use the first attribute to determine the length of each
		 * attribute data unit. Stop the list when a different attribute
		 * value is seen.
		 */
		if (iter == 0) {
			data_val_len = MIN(MIN((unsigned)mtu - 6, 251),
								value.iov_len);
			pdu[0] = data_val_len + 4;
			iter++;
		} else if (value.iov_len != data_val_len)
			break;

		/* Stop if this unit would surpass the MTU */
		if (iter + data_val_len + 4 > mtu - 1)
			break;

		gatt_db_attribute_get_service_handles(attrib, &start_handle,
								&end_handle);

		put_le16(start_handle, pdu + iter);
		put_le16(end_handle, pdu + iter + 2);
		memcpy(pdu + iter + 4, value.iov_base, data_val_len);

		iter += data_val_len + 4;
	}

	*len = iter;

	return true;
}

static void read_by_grp_type_cb(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct bt_gatt_server *server = user_data;
	uint16_t start, end;
	bt_uuid_t type;
	bt_uuid_t prim, snd;
	uint16_t mtu = bt_att_get_mtu(server->att);
	uint8_t rsp_pdu[mtu];
	uint16_t rsp_len;
	uint8_t rsp_opcode;
	uint8_t ecode = 0;
	uint16_t ehandle = 0;
	struct queue *q = NULL;

	if (length != 6 && length != 20) {
		ecode = BT_ATT_ERROR_INVALID_PDU;
		goto error;
	}

	q = queue_new();
	if (!q) {
		ecode = BT_ATT_ERROR_INSUFFICIENT_RESOURCES;
		goto error;
	}

	start = get_le16(pdu);
	end = get_le16(pdu + 2);
	get_uuid_le(pdu + 4, length - 4, &type);

	util_debug(server->debug_callback, server->debug_data,
				"Read By Grp Type - start: 0x%04x end: 0x%04x",
				start, end);

	if (!start || !end) {
		ecode = BT_ATT_ERROR_INVALID_HANDLE;
		goto error;
	}

	ehandle = start;

	if (start > end) {
		ecode = BT_ATT_ERROR_INVALID_HANDLE;
		goto error;
	}

	/*
	 * GATT defines that only the <<Primary Service>> and
	 * <<Secondary Service>> group types can be used for the
	 * "Read By Group Type" request (Core v4.1, Vol 3, sec 2.5.3). Return an
	 * error if any other group type is given.
	 */
	bt_uuid16_create(&prim, GATT_PRIM_SVC_UUID);
	bt_uuid16_create(&snd, GATT_SND_SVC_UUID);
	if (bt_uuid_cmp(&type, &prim) && bt_uuid_cmp(&type, &snd)) {
		ecode = BT_ATT_ERROR_UNSUPPORTED_GROUP_TYPE;
		goto error;
	}

	gatt_db_read_by_group_type(server->db, start, end, type, q);

	if (queue_isempty(q)) {
		ecode = BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND;
		goto error;
	}

	if (!encode_read_by_grp_type_rsp(server->db, q, mtu, rsp_pdu,
								&rsp_len)) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto error;
	}

	rsp_opcode = BT_ATT_OP_READ_BY_GRP_TYPE_RSP;

	goto done;

error:
	rsp_opcode = BT_ATT_OP_ERROR_RSP;
	rsp_len = 4;
	encode_error_rsp(opcode, ehandle, ecode, rsp_pdu);

done:
	queue_destroy(q, NULL);
	bt_att_send(server->att, rsp_opcode, rsp_pdu, rsp_len,
							NULL, NULL, NULL);
}

static void async_read_op_destroy(struct async_read_op *op)
{
	if (op->server)
		op->server->pending_read_op = NULL;

	queue_destroy(op->db_data, NULL);
	free(op->pdu);
	free(op);
}

static void process_read_by_type(struct async_read_op *op);

static void read_by_type_read_complete_cb(struct gatt_db_attribute *attr,
						int err, const uint8_t *value,
						size_t len, void *user_data)
{
	struct async_read_op *op = user_data;
	struct bt_gatt_server *server = op->server;
	uint16_t mtu;
	uint16_t handle;

	if (!server) {
		async_read_op_destroy(op);
		return;
	}

	mtu = bt_att_get_mtu(server->att);
	handle = gatt_db_attribute_get_handle(attr);

	/* Terminate the operation if there was an error */
	if (err) {
		uint8_t pdu[4];
		uint8_t att_ecode = att_ecode_from_error(err);

		encode_error_rsp(BT_ATT_OP_READ_BY_TYPE_REQ, handle, att_ecode,
									pdu);
		bt_att_send(server->att, BT_ATT_OP_ERROR_RSP, pdu, 4, NULL,
								NULL, NULL);
		async_read_op_destroy(op);
		return;
	}

	if (op->pdu_len == 0) {
		op->value_len = MIN(MIN((unsigned) mtu - 4, 253), len);
		op->pdu[0] = op->value_len + 2;
		op->pdu_len++;
	} else if (len != op->value_len) {
		op->done = true;
		goto done;
	}

	/* Stop if this would surpass the MTU */
	if (op->pdu_len + op->value_len + 2 > (unsigned) mtu - 1) {
		op->done = true;
		goto done;
	}

	/* Encode the current value */
	put_le16(handle, op->pdu + op->pdu_len);
	memcpy(op->pdu + op->pdu_len + 2, value, op->value_len);

	op->pdu_len += op->value_len + 2;

	if (op->pdu_len == (unsigned) mtu - 1)
		op->done = true;

done:
	process_read_by_type(op);
}

static void process_read_by_type(struct async_read_op *op)
{
	struct bt_gatt_server *server = op->server;
	uint8_t rsp_opcode;
	uint8_t rsp_len;
	uint8_t ecode;
	uint16_t ehandle;
	struct gatt_db_attribute *attr;
	uint32_t perm;

	attr = queue_pop_head(op->db_data);

	if (op->done || !attr) {
		rsp_opcode = BT_ATT_OP_READ_BY_TYPE_RSP;
		rsp_len = op->pdu_len;
		goto done;
	}

	if (!gatt_db_attribute_get_permissions(attr, &perm)) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto error;
	}

	/*
	 * Check for the READ access permission. Encryption,
	 * authentication, and authorization permissions need to be
	 * checked by the read handler, since bt_att is agnostic to
	 * connection type and doesn't have security information on it.
	 */
	if (perm && !(perm & BT_ATT_PERM_READ)) {
		ecode = BT_ATT_ERROR_READ_NOT_PERMITTED;
		goto error;
	}

	if (gatt_db_attribute_read(attr, 0, op->opcode, NULL,
				read_by_type_read_complete_cb, op))
		return;

	ecode = BT_ATT_ERROR_UNLIKELY;

error:
	ehandle = gatt_db_attribute_get_handle(attr);
	rsp_opcode = BT_ATT_OP_ERROR_RSP;
	rsp_len = 4;
	encode_error_rsp(BT_ATT_OP_READ_BY_TYPE_REQ, ehandle, ecode, op->pdu);

done:
	bt_att_send(server->att, rsp_opcode, op->pdu, rsp_len, NULL,
								NULL, NULL);
	async_read_op_destroy(op);
}

static void read_by_type_cb(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct bt_gatt_server *server = user_data;
	uint16_t start, end;
	bt_uuid_t type;
	uint8_t rsp_pdu[4];
	uint16_t ehandle = 0;
	uint8_t ecode;
	struct queue *q = NULL;
	struct async_read_op *op;

	if (length != 6 && length != 20) {
		ecode = BT_ATT_ERROR_INVALID_PDU;
		goto error;
	}

	q = queue_new();
	if (!q) {
		ecode = BT_ATT_ERROR_INSUFFICIENT_RESOURCES;
		goto error;
	}

	start = get_le16(pdu);
	end = get_le16(pdu + 2);
	get_uuid_le(pdu + 4, length - 4, &type);

	util_debug(server->debug_callback, server->debug_data,
				"Read By Type - start: 0x%04x end: 0x%04x",
				start, end);

	if (!start || !end) {
		ecode = BT_ATT_ERROR_INVALID_HANDLE;
		goto error;
	}

	ehandle = start;

	if (start > end) {
		ecode = BT_ATT_ERROR_INVALID_HANDLE;
		goto error;
	}

	gatt_db_read_by_type(server->db, start, end, type, q);

	if (queue_isempty(q)) {
		ecode = BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND;
		goto error;
	}

	if (server->pending_read_op) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto error;
	}

	op = new0(struct async_read_op, 1);
	if (!op) {
		ecode = BT_ATT_ERROR_INSUFFICIENT_RESOURCES;
		goto error;
	}

	op->pdu = malloc(bt_att_get_mtu(server->att));
	if (!op->pdu) {
		free(op);
		ecode = BT_ATT_ERROR_INSUFFICIENT_RESOURCES;
		goto error;
	}

	op->opcode = opcode;
	op->server = server;
	op->db_data = q;
	server->pending_read_op = op;

	process_read_by_type(op);

	return;

error:
	encode_error_rsp(opcode, ehandle, ecode, rsp_pdu);
	queue_destroy(q, NULL);
	bt_att_send(server->att, BT_ATT_OP_ERROR_RSP, rsp_pdu, 4,
							NULL, NULL, NULL);
}

static void put_uuid_le(const bt_uuid_t *src, void *dst)
{
	bt_uuid_t uuid;

	switch (src->type) {
	case BT_UUID16:
		put_le16(src->value.u16, dst);
		break;
	case BT_UUID128:
		bswap_128(&src->value.u128, dst);
		break;
	case BT_UUID32:
		bt_uuid_to_uuid128(src, &uuid);
		bswap_128(&uuid.value.u128, dst);
		break;
	default:
		break;
	}
}

static bool encode_find_info_rsp(struct gatt_db *db, struct queue *q,
						uint16_t mtu,
						uint8_t *pdu, uint16_t *len)
{
	uint16_t handle;
	struct gatt_db_attribute *attr;
	const bt_uuid_t *type;
	int uuid_len, cur_uuid_len;
	int iter = 0;

	*len = 0;

	while (queue_peek_head(q)) {
		attr = queue_pop_head(q);
		handle = gatt_db_attribute_get_handle(attr);
		type = gatt_db_attribute_get_type(attr);
		if (!handle || !type)
			return false;

		cur_uuid_len = bt_uuid_len(type);

		if (iter == 0) {
			switch (cur_uuid_len) {
			case 2:
				uuid_len = 2;
				pdu[0] = 0x01;
				break;
			case 4:
			case 16:
				uuid_len = 16;
				pdu[0] = 0x02;
				break;
			default:
				return false;
			}

			iter++;
		} else if (cur_uuid_len != uuid_len)
			break;

		if (iter + uuid_len + 2 > mtu - 1)
			break;

		put_le16(handle, pdu + iter);
		put_uuid_le(type, pdu + iter + 2);

		iter += uuid_len + 2;
	}

	*len = iter;

	return true;
}

static void find_info_cb(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct bt_gatt_server *server = user_data;
	uint16_t start, end;
	uint16_t mtu = bt_att_get_mtu(server->att);
	uint8_t rsp_pdu[mtu];
	uint16_t rsp_len;
	uint8_t rsp_opcode;
	uint8_t ecode = 0;
	uint16_t ehandle = 0;
	struct queue *q = NULL;

	if (length != 4) {
		ecode = BT_ATT_ERROR_INVALID_PDU;
		goto error;
	}

	q = queue_new();
	if (!q) {
		ecode = BT_ATT_ERROR_INSUFFICIENT_RESOURCES;
		goto error;
	}

	start = get_le16(pdu);
	end = get_le16(pdu + 2);

	util_debug(server->debug_callback, server->debug_data,
					"Find Info - start: 0x%04x end: 0x%04x",
					start, end);

	if (!start || !end) {
		ecode = BT_ATT_ERROR_INVALID_HANDLE;
		goto error;
	}

	ehandle = start;

	if (start > end) {
		ecode = BT_ATT_ERROR_INVALID_HANDLE;
		goto error;
	}

	gatt_db_find_information(server->db, start, end, q);

	if (queue_isempty(q)) {
		ecode = BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND;
		goto error;
	}

	if (!encode_find_info_rsp(server->db, q, mtu, rsp_pdu, &rsp_len)) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto error;
	}

	rsp_opcode = BT_ATT_OP_FIND_INFO_RSP;

	goto done;

error:
	rsp_opcode = BT_ATT_OP_ERROR_RSP;
	rsp_len = 4;
	encode_error_rsp(opcode, ehandle, ecode, rsp_pdu);

done:
	queue_destroy(q, NULL);
	bt_att_send(server->att, rsp_opcode, rsp_pdu, rsp_len,
							NULL, NULL, NULL);
}

static void async_write_op_destroy(struct async_write_op *op)
{
	if (op->server)
		op->server->pending_write_op = NULL;

	free(op);
}

static void write_complete_cb(struct gatt_db_attribute *attr, int err,
								void *user_data)
{
	struct async_write_op *op = user_data;
	struct bt_gatt_server *server = op->server;
	uint16_t handle;

	if (!server || op->opcode == BT_ATT_OP_WRITE_CMD) {
		async_write_op_destroy(op);
		return;
	}

	handle = gatt_db_attribute_get_handle(attr);

	if (err) {
		uint8_t rsp_pdu[4];
		uint8_t att_ecode = att_ecode_from_error(err);

		encode_error_rsp(op->opcode, handle, att_ecode, rsp_pdu);
		bt_att_send(server->att, BT_ATT_OP_ERROR_RSP, rsp_pdu, 4,
							NULL, NULL, NULL);
	} else {
		bt_att_send(server->att, BT_ATT_OP_WRITE_RSP, NULL, 0,
							NULL, NULL, NULL);
	}

	async_write_op_destroy(op);
}

static void write_cb(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct bt_gatt_server *server = user_data;
	struct gatt_db_attribute *attr;
	uint16_t handle = 0;
	uint8_t rsp_pdu[4];
	struct async_write_op *op = NULL;
	uint8_t ecode;
	uint32_t perm;

	if (length < 2) {
		ecode = BT_ATT_ERROR_INVALID_PDU;
		goto error;
	}

	handle = get_le16(pdu);
	attr = gatt_db_get_attribute(server->db, handle);
	if (!attr) {
		ecode = BT_ATT_ERROR_INVALID_HANDLE;
		goto error;
	}

	util_debug(server->debug_callback, server->debug_data,
				"Write %s - handle: 0x%04x",
				(opcode == BT_ATT_OP_WRITE_REQ) ? "Req" : "Cmd",
				handle);

	if (!gatt_db_attribute_get_permissions(attr, &perm)) {
		ecode = BT_ATT_ERROR_INVALID_HANDLE;
		goto error;
	}

	if (!(perm & BT_ATT_PERM_WRITE)) {
		ecode = BT_ATT_ERROR_WRITE_NOT_PERMITTED;
		goto error;
	}

	if (server->pending_write_op) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto error;
	}

	op = new0(struct async_write_op, 1);
	if (!op) {
		ecode = BT_ATT_ERROR_INSUFFICIENT_RESOURCES;
		goto error;
	}

	op->server = server;
	op->opcode = opcode;
	server->pending_write_op = op;

	if (gatt_db_attribute_write(attr, 0, pdu + 2, length - 2, opcode,
						NULL, write_complete_cb, op))
		return;

	if (op)
		async_write_op_destroy(op);

	ecode = BT_ATT_ERROR_UNLIKELY;

error:
	if (opcode == BT_ATT_OP_WRITE_CMD)
		return;

	encode_error_rsp(opcode, handle, ecode, rsp_pdu);
	bt_att_send(server->att, BT_ATT_OP_ERROR_RSP, rsp_pdu, 4,
							NULL, NULL, NULL);
}

static void read_complete_cb(struct gatt_db_attribute *attr, int err,
					const uint8_t *value, size_t len,
					void *user_data)
{
	struct async_read_op *op = user_data;
	struct bt_gatt_server *server = op->server;
	uint16_t mtu;
	uint16_t handle;

	if (!server) {
		async_read_op_destroy(op);
		return;
	}

	mtu = bt_att_get_mtu(server->att);
	handle = gatt_db_attribute_get_handle(attr);

	if (err) {
		uint8_t pdu[4];
		uint8_t att_ecode = att_ecode_from_error(err);

		encode_error_rsp(op->opcode, handle, att_ecode, pdu);
		bt_att_send(server->att, BT_ATT_OP_ERROR_RSP, pdu, 4, NULL,
								NULL, NULL);
		async_read_op_destroy(op);
		return;
	}

	/* TODO: Send Read Blob response based on the request */

	bt_att_send(server->att, BT_ATT_OP_READ_RSP, len ? value : NULL,
						MIN((unsigned) mtu - 1, len),
						NULL, NULL, NULL);
	async_read_op_destroy(op);
}

static void read_cb(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct bt_gatt_server *server = user_data;
	uint16_t mtu = bt_att_get_mtu(server->att);
	uint8_t error_pdu[4];
	uint16_t handle = 0;
	struct gatt_db_attribute *attr;
	uint8_t ecode;
	uint32_t perm;
	struct async_read_op *op = NULL;

	if (length != 2) {
		ecode = BT_ATT_ERROR_INVALID_PDU;
		goto error;
	}

	handle = get_le16(pdu);
	attr = gatt_db_get_attribute(server->db, handle);
	if (!attr) {
		ecode = BT_ATT_ERROR_INVALID_HANDLE;
		goto error;
	}

	util_debug(server->debug_callback, server->debug_data,
					"Read - handle: 0x%04x", handle);

	if (!gatt_db_attribute_get_permissions(attr, &perm)) {
		ecode = BT_ATT_ERROR_INVALID_HANDLE;
		goto error;
	}

	if (perm && !(perm & BT_ATT_PERM_READ)) {
		ecode = BT_ATT_ERROR_READ_NOT_PERMITTED;
		goto error;
	}

	if (server->pending_read_op) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto error;
	}

	op = new0(struct async_read_op, 1);
	if (!op) {
		ecode = BT_ATT_ERROR_INSUFFICIENT_RESOURCES;
		goto error;
	}

	op->opcode = opcode;
	op->server = server;
	server->pending_read_op = op;

	if (gatt_db_attribute_read(attr, 0, opcode, NULL, read_complete_cb, op))
		return;

	ecode = BT_ATT_ERROR_UNLIKELY;

error:
	if (op)
		async_read_op_destroy(op);

	encode_error_rsp(opcode, handle, ecode, error_pdu);
	bt_att_send(server->att, BT_ATT_OP_ERROR_RSP, error_pdu, 4, NULL, NULL,
									NULL);
}

static void exchange_mtu_cb(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct bt_gatt_server *server = user_data;
	uint16_t client_rx_mtu;
	uint16_t final_mtu;
	uint8_t rsp_pdu[4];

	if (length != 2) {
		encode_error_rsp(opcode, 0, BT_ATT_ERROR_INVALID_PDU, rsp_pdu);
		bt_att_send(server->att, BT_ATT_OP_ERROR_RSP, rsp_pdu,
					sizeof(rsp_pdu), NULL, NULL, NULL);
		return;
	}

	client_rx_mtu = get_le16(pdu);
	final_mtu = MAX(MIN(client_rx_mtu, server->mtu), BT_ATT_DEFAULT_LE_MTU);

	/* Respond with the server MTU */
	put_le16(server->mtu, rsp_pdu);
	bt_att_send(server->att, BT_ATT_OP_MTU_RSP, rsp_pdu, 2, NULL, NULL,
									NULL);

	/* Set MTU to be the minimum */
	server->mtu = final_mtu;
	bt_att_set_mtu(server->att, final_mtu);

	util_debug(server->debug_callback, server->debug_data,
			"MTU exchange complete, with MTU: %u", final_mtu);
}

static bool gatt_server_register_att_handlers(struct bt_gatt_server *server)
{
	/* Exchange MTU */
	server->mtu_id = bt_att_register(server->att, BT_ATT_OP_MTU_REQ,
								exchange_mtu_cb,
								server, NULL);
	if (!server->mtu_id)
		return false;

	/* Read By Group Type */
	server->read_by_grp_type_id = bt_att_register(server->att,
						BT_ATT_OP_READ_BY_GRP_TYPE_REQ,
						read_by_grp_type_cb,
						server, NULL);
	if (!server->read_by_grp_type_id)
		return false;

	/* Read By Type */
	server->read_by_type_id = bt_att_register(server->att,
						BT_ATT_OP_READ_BY_TYPE_REQ,
						read_by_type_cb,
						server, NULL);
	if (!server->read_by_type_id)
		return false;

	/* Find Information */
	server->find_info_id = bt_att_register(server->att,
							BT_ATT_OP_FIND_INFO_REQ,
							find_info_cb,
							server, NULL);
	if (!server->find_info_id)
		return false;

	/* Write Request */
	server->write_id = bt_att_register(server->att, BT_ATT_OP_WRITE_REQ,
								write_cb,
								server, NULL);
	if (!server->write_id)
		return false;

	/* Write Command */
	server->write_cmd_id = bt_att_register(server->att, BT_ATT_OP_WRITE_CMD,
								write_cb,
								server, NULL);
	if (!server->write_cmd_id)
		return false;

	/* Read Request */
	server->read_id = bt_att_register(server->att, BT_ATT_OP_READ_REQ,
								read_cb,
								server, NULL);
	if (!server->read_id)
		return false;

	return true;
}

struct bt_gatt_server *bt_gatt_server_new(struct gatt_db *db,
					struct bt_att *att, uint16_t mtu)
{
	struct bt_gatt_server *server;

	if (!att)
		return NULL;

	server = new0(struct bt_gatt_server, 1);
	if (!server)
		return NULL;

	server->db = db;
	server->att = bt_att_ref(att);
	server->mtu = MAX(mtu, BT_ATT_DEFAULT_LE_MTU);

	if (!gatt_server_register_att_handlers(server)) {
		bt_gatt_server_free(server);
		return NULL;
	}

	return bt_gatt_server_ref(server);
}

struct bt_gatt_server *bt_gatt_server_ref(struct bt_gatt_server *server)
{
	if (!server)
		return NULL;

	__sync_fetch_and_add(&server->ref_count, 1);

	return server;
}

void bt_gatt_server_unref(struct bt_gatt_server *server)
{
	if (__sync_sub_and_fetch(&server->ref_count, 1))
		return;

	bt_gatt_server_free(server);
}

bool bt_gatt_server_set_debug(struct bt_gatt_server *server,
					bt_gatt_server_debug_func_t callback,
					void *user_data,
					bt_gatt_server_destroy_func_t destroy)
{
	if (!server)
		return false;

	if (server->debug_destroy)
		server->debug_destroy(server->debug_data);

	server->debug_callback = callback;
	server->debug_destroy = destroy;
	server->debug_data = user_data;

	return true;
}
