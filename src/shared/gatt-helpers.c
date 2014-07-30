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

#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "lib/uuid.h"
#include "src/shared/gatt-helpers.h"
#include "src/shared/util.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

struct bt_gatt_result {
	uint8_t opcode;
	void *pdu;
	uint16_t pdu_len;
	uint16_t data_len;

	void *op;  /* Discovery operation data */

	struct bt_gatt_result *next;
};

static struct bt_gatt_result *result_create(uint8_t opcode, const void *pdu,
							uint16_t pdu_len,
							uint16_t data_len,
							void *op)
{
	struct bt_gatt_result *result;

	result = new0(struct bt_gatt_result, 1);
	if (!result)
		return NULL;

	result->pdu = malloc(pdu_len);
	if (!result->pdu) {
		free(result);
		return NULL;
	}

	result->opcode = opcode;
	result->pdu_len = pdu_len;
	result->data_len = data_len;
	result->op = op;

	memcpy(result->pdu, pdu, pdu_len);

	return result;
}

static void result_destroy(struct bt_gatt_result *result)
{
	struct bt_gatt_result *next;

	while (result) {
		next = result->next;

		free(result->pdu);
		free(result);

		result = next;
	}
}

bool bt_gatt_iter_init(struct bt_gatt_iter *iter, struct bt_gatt_result *result)
{
	if (!iter || !result)
		return false;

	iter->result = result;
	iter->pos = 0;

	return true;
}

static const uint8_t bt_base_uuid[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
	0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
};

static bool convert_uuid_le(const uint8_t *src, size_t len, uint8_t dst[16])
{
	if (len == 16) {
		bswap_128(src, dst);
		return true;
	}

	if (len != 2)
		return false;

	memcpy(dst, bt_base_uuid, sizeof(bt_base_uuid));
	dst[2] = src[1];
	dst[3] = src[0];

	return true;
}

struct discovery_op {
	struct bt_att *att;
	uint16_t end_handle;
	int ref_count;
	bt_uuid_t uuid;
	struct bt_gatt_result *result_head;
	struct bt_gatt_result *result_tail;
	bt_gatt_discovery_callback_t callback;
	void *user_data;
	bt_gatt_destroy_func_t destroy;
};

bool bt_gatt_iter_next_service(struct bt_gatt_iter *iter,
						struct bt_gatt_service *service)
{
	struct discovery_op *op;
	const void *pdu_ptr;
	bt_uuid_t uuid;

	if (!iter->result || !service)
		return false;

	op = iter->result->op;
	pdu_ptr = iter->result->pdu + iter->pos;

	switch (iter->result->opcode) {
	case BT_ATT_OP_READ_BY_GRP_TYPE_RSP:
		service->start = get_le16(pdu_ptr);
		service->end = get_le16(pdu_ptr + 2);
		convert_uuid_le(pdu_ptr + 4, iter->result->data_len - 4,
								service->uuid);
		break;
	case BT_ATT_OP_FIND_BY_TYPE_VAL_RSP:
		service->start = get_le16(pdu_ptr);
		service->end = get_le16(pdu_ptr + 2);

		bt_uuid_to_uuid128(&op->uuid, &uuid);
		memcpy(service->uuid, uuid.value.u128.data, 16);
		break;
	default:
		return false;
	}


	iter->pos += iter->result->data_len;
	if (iter->pos == iter->result->pdu_len) {
		iter->result = iter->result->next;
		iter->pos = 0;
	}

	return true;
}

bool bt_gatt_iter_next_characteristic(struct bt_gatt_iter *iter,
					struct bt_gatt_characteristic *chrc)
{
	struct discovery_op *op;
	const void *pdu_ptr;

	if (!iter->result || !chrc)
		return false;

	if (iter->result->opcode != BT_ATT_OP_READ_BY_TYPE_RSP)
		return false;

	op = iter->result->op;
	pdu_ptr = iter->result->pdu + iter->pos;

	chrc->start = get_le16(pdu_ptr);
	chrc->properties = ((uint8_t *) pdu_ptr)[2];
	chrc->value = get_le16(pdu_ptr + 3);
	convert_uuid_le(pdu_ptr + 5, iter->result->data_len - 5, chrc->uuid);

	iter->pos += iter->result->data_len;
	if (iter->pos == iter->result->pdu_len) {
		iter->result = iter->result->next;
		iter->pos = 0;
	}

	if (!iter->result) {
		chrc->end = op->end_handle;
		return true;
	}

	chrc->end = get_le16(iter->result->pdu + iter->pos) - 1;

	return true;
}

bool bt_gatt_iter_next_descriptor(struct bt_gatt_iter *iter,
						struct bt_gatt_descriptor *desc)
{
	const void *pdu_ptr;

	if (!iter->result || !desc)
		return false;

	if (iter->result->opcode != BT_ATT_OP_FIND_INFO_RSP)
		return false;

	pdu_ptr = iter->result->pdu + iter->pos;

	desc->handle = get_le16(pdu_ptr);
	convert_uuid_le(pdu_ptr + 2, iter->result->data_len - 2, desc->uuid);

	iter->pos += iter->result->data_len;
	if (iter->pos == iter->result->pdu_len) {
		iter->result = iter->result->next;
		iter->pos = 0;
	}

	return true;
}

struct mtu_op {
	struct bt_att *att;
	uint16_t client_rx_mtu;
	bt_gatt_result_callback_t callback;
	void *user_data;
	bt_gatt_destroy_func_t destroy;
};

static void destroy_mtu_op(void *user_data)
{
	struct mtu_op *op = user_data;

	if (op->destroy)
		op->destroy(op->user_data);

	free(op);
}

static uint8_t process_error(const void *pdu, uint16_t length)
{
	if (!pdu || length != 4)
		return 0;

	return ((uint8_t *) pdu)[3];
}

static void mtu_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct mtu_op *op = user_data;
	bool success = true;
	uint8_t att_ecode = 0;
	uint16_t server_rx_mtu;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);
		goto done;
	}

	if (opcode != BT_ATT_OP_MTU_RSP || !pdu || length != 2) {
		success = false;
		goto done;
	}

	server_rx_mtu = get_le16(pdu);
	bt_att_set_mtu(op->att, MIN(op->client_rx_mtu, server_rx_mtu));

done:
	if (op->callback)
		op->callback(success, att_ecode, op->user_data);
}

bool bt_gatt_exchange_mtu(struct bt_att *att, uint16_t client_rx_mtu,
					bt_gatt_result_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	struct mtu_op *op;
	uint8_t pdu[2];

	if (!att || !client_rx_mtu)
		return false;

	op = new0(struct mtu_op, 1);
	if (!op)
		return false;

	op->att = att;
	op->client_rx_mtu = client_rx_mtu;
	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	put_le16(client_rx_mtu, pdu);

	if (!bt_att_send(att, BT_ATT_OP_MTU_REQ, pdu, sizeof(pdu),
							mtu_cb, op,
							destroy_mtu_op)) {
		free(op);
		return false;
	}

	return true;
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

static inline int get_uuid_len(const bt_uuid_t *uuid)
{
	return (uuid->type == BT_UUID16) ? 2 : 16;
}

static struct discovery_op* discovery_op_ref(struct discovery_op *op)
{
	__sync_fetch_and_add(&op->ref_count, 1);

	return op;
}

static void discovery_op_unref(void *data)
{
	struct discovery_op *op = data;

	if (__sync_sub_and_fetch(&op->ref_count, 1))
		return;

	if (op->destroy)
		op->destroy(op->user_data);

	result_destroy(op->result_head);

	free(op);
}

static void read_by_grp_type_cb(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct discovery_op *op = user_data;
	bool success;
	uint8_t att_ecode = 0;
	struct bt_gatt_result *final_result = NULL;
	struct bt_gatt_result *cur_result;
	size_t data_length;
	size_t list_length;
	uint16_t last_end;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);

		if (att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND &&
								op->result_head)
			goto success;

		goto done;
	}

	/* PDU must contain at least the following (sans opcode):
	 * - Attr Data Length (1 octet)
	 * - Attr Data List (at least 6 octets):
	 *   -- 2 octets: Attribute handle
	 *   -- 2 octets: End group handle
	 *   -- 2 or 16 octets: service UUID
	 */
	if (opcode != BT_ATT_OP_READ_BY_GRP_TYPE_RSP || !pdu || length < 7) {
		success = false;
		goto done;
	}

	data_length = ((uint8_t *) pdu)[0];
	list_length = length - 1;

	if ((list_length % data_length) ||
				(data_length != 6 && data_length != 20)) {
		success = false;
		goto done;
	}

	/* PDU is correctly formatted. Get the last end handle to process the
	 * next request and store the PDU.
	 */
	cur_result = result_create(opcode, pdu + 1, list_length,
							data_length, op);
	if (!cur_result) {
		success = false;
		goto done;
	}

	if (!op->result_head)
		op->result_head = op->result_tail = cur_result;
	else {
		op->result_tail->next = cur_result;
		op->result_tail = cur_result;
	}

	last_end = get_le16(pdu + length - data_length + 2);
	if (last_end != 0xffff) {
		uint8_t pdu[6];

		put_le16(last_end + 1, pdu);
		put_le16(0xffff, pdu + 2);
		put_le16(GATT_PRIM_SVC_UUID, pdu + 4);

		if (bt_att_send(op->att, BT_ATT_OP_READ_BY_GRP_TYPE_REQ,
							pdu, sizeof(pdu),
							read_by_grp_type_cb,
							discovery_op_ref(op),
							discovery_op_unref))
			return;

		discovery_op_unref(op);
		success = false;
		goto done;
	}

success:
	/* End of procedure */
	final_result = op->result_head;
	success = true;

done:
	if (op->callback)
		op->callback(success, att_ecode, final_result, op->user_data);
}

static void find_by_type_val_cb(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct discovery_op *op = user_data;
	bool success;
	uint8_t att_ecode = 0;
	struct bt_gatt_result *final_result = NULL;
	struct bt_gatt_result *cur_result;
	uint16_t last_end;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);

		if (att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND &&
								op->result_head)
			goto success;

		goto done;
	}

	/* PDU must contain 4 bytes and it must be a multiple of 4, where each
	 * 4 bytes contain the 16-bit attribute and group end handles.
	 */
	if (opcode != BT_ATT_OP_FIND_BY_TYPE_VAL_RSP || !pdu || !length ||
								length % 4) {
		success = false;
		goto done;
	}

	cur_result = result_create(opcode, pdu, length, 4, op);
	if (!cur_result) {
		success = false;
		goto done;
	}

	if (!op->result_head)
		op->result_head = op->result_tail = cur_result;
	else {
		op->result_tail->next = cur_result;
		op->result_tail = cur_result;
	}

	last_end = get_le16(pdu + length - 6);
	if (last_end != 0xffff) {
		uint8_t pdu[6 + get_uuid_len(&op->uuid)];

		put_le16(last_end + 1, pdu);
		put_le16(0xffff, pdu + 2);
		put_le16(GATT_PRIM_SVC_UUID, pdu + 4);
		put_uuid_le(&op->uuid, pdu + 6);

		if (bt_att_send(op->att, BT_ATT_OP_FIND_BY_TYPE_VAL_REQ,
							pdu, sizeof(pdu),
							find_by_type_val_cb,
							discovery_op_ref(op),
							discovery_op_unref))
			return;

		discovery_op_unref(op);
		success = false;
		goto done;
	}

success:
	/* End of procedure */
	final_result = op->result_head;
	success = true;

done:
	if (op->callback)
		op->callback(success, att_ecode, final_result, op->user_data);
}

bool bt_gatt_discover_primary_services(struct bt_att *att,
					bt_uuid_t *uuid,
					bt_gatt_discovery_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	struct discovery_op *op;
	bool result;

	if (!att)
		return false;

	op = new0(struct discovery_op, 1);
	if (!op)
		return false;

	op->att = att;
	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	/* If UUID is NULL, then discover all primary services */
	if (!uuid) {
		uint8_t pdu[6];

		put_le16(0x0001, pdu);
		put_le16(0xffff, pdu + 2);
		put_le16(GATT_PRIM_SVC_UUID, pdu + 4);

		result = bt_att_send(att, BT_ATT_OP_READ_BY_GRP_TYPE_REQ,
							pdu, sizeof(pdu),
							read_by_grp_type_cb,
							discovery_op_ref(op),
							discovery_op_unref);
	} else {
		uint8_t pdu[6 + get_uuid_len(uuid)];

		if (uuid->type == BT_UUID_UNSPEC) {
			free(op);
			return false;
		}

		/* Discover by UUID */
		op->uuid = *uuid;

		put_le16(0x0001, pdu);
		put_le16(0xffff, pdu + 2);
		put_le16(GATT_PRIM_SVC_UUID, pdu + 4);
		put_uuid_le(&op->uuid, pdu + 6);

		result = bt_att_send(att, BT_ATT_OP_FIND_BY_TYPE_VAL_REQ,
							pdu, sizeof(pdu),
							find_by_type_val_cb,
							discovery_op_ref(op),
							discovery_op_unref);
	}

	if (!result)
		free(op);

	return result;
}

bool bt_gatt_discover_included_services(struct bt_att *att,
					uint16_t start, uint16_t end,
					bt_uuid_t *uuid,
					bt_gatt_discovery_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	/* TODO */
	return false;
}

static void discover_chrcs_cb(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct discovery_op *op = user_data;
	bool success;
	uint8_t att_ecode = 0;
	struct bt_gatt_result *final_result = NULL;
	struct bt_gatt_result *cur_result;
	size_t data_length;
	uint16_t last_handle;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);

		if (att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND &&
							op->result_head)
			goto success;

		goto done;
	}

	/* PDU must contain at least the following (sans opcode):
	 * - Attr Data Length (1 octet)
	 * - Attr Data List (at least 7 octets):
	 *   -- 2 octets: Attribute handle
	 *   -- 1 octet: Characteristic properties
	 *   -- 2 octets: Characteristic value handle
	 *   -- 2 or 16 octets: characteristic UUID
	 */
	if (opcode != BT_ATT_OP_READ_BY_TYPE_RSP || !pdu || length < 8) {
		success = false;
		goto done;
	}

	data_length = ((uint8_t *) pdu)[0];

	if (((length - 1) % data_length) ||
			(data_length != 7 && data_length != 21)) {
		success = false;
		goto done;
	}

	cur_result = result_create(opcode, pdu + 1, length - 1,
							data_length, op);
	if (!cur_result) {
		success = false;
		goto done;
	}

	if (!op->result_head)
		op->result_head = op->result_tail = cur_result;
	else {
		op->result_tail->next = cur_result;
		op->result_tail = cur_result;
	}

	last_handle = get_le16(pdu + length - data_length);
	if (last_handle != op->end_handle) {
		uint8_t pdu[6];

		put_le16(last_handle + 1, pdu);
		put_le16(op->end_handle, pdu + 2);
		put_le16(GATT_CHARAC_UUID, pdu + 4);

		if (bt_att_send(op->att, BT_ATT_OP_READ_BY_TYPE_REQ,
						pdu, sizeof(pdu),
						discover_chrcs_cb,
						discovery_op_ref(op),
						discovery_op_unref))
			return;

		discovery_op_unref(op);
		success = false;
		goto done;
	}

success:
	final_result = op->result_head;
	success = true;

done:
	if (op->callback)
		op->callback(success, att_ecode, final_result,
							op->user_data);
}

bool bt_gatt_discover_characteristics(struct bt_att *att,
					uint16_t start, uint16_t end,
					bt_gatt_discovery_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	struct discovery_op *op;
	uint8_t pdu[6];

	if (!att)
		return false;

	op = new0(struct discovery_op, 1);
	if (!op)
		return false;

	op->att = att;
	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;
	op->end_handle = end;

	put_le16(start, pdu);
	put_le16(end, pdu + 2);
	put_le16(GATT_CHARAC_UUID, pdu + 4);

	if (!bt_att_send(att, BT_ATT_OP_READ_BY_TYPE_REQ,
					pdu, sizeof(pdu),
					discover_chrcs_cb,
					discovery_op_ref(op),
					discovery_op_unref)) {
		free(op);
		return false;
	}

	return true;
}

static void discover_descs_cb(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct discovery_op *op = user_data;
	bool success;
	uint8_t att_ecode = 0;
	struct bt_gatt_result *final_result = NULL;
	struct bt_gatt_result *cur_result;
	uint8_t format;
	uint16_t last_handle;
	size_t data_length;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);

		if (att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND &&
								op->result_head)
			goto success;

		goto done;
	}

	/* The PDU should contain the following data (sans opcode):
	 * - Format (1 octet)
	 * - Attr Data List (at least 4 octets):
	 *   -- 2 octets: Attribute handle
	 *   -- 2 or 16 octets: UUID.
	 */
	if (opcode != BT_ATT_OP_FIND_INFO_RSP || !pdu || length < 5) {
		success = false;
		goto done;
	}

	format = ((uint8_t *) pdu)[0];

	if (format == 0x01)
		data_length = 4;
	else if (format == 0x02)
		data_length = 18;
	else {
		success = false;
		goto done;
	}

	if ((length - 1) % data_length) {
		success = false;
		goto done;
	}

	cur_result = result_create(opcode, pdu + 1, length - 1,
							data_length, op);
	if (!cur_result) {
		success = false;
		goto done;
	}

	if (!op->result_head)
		op->result_head = op->result_tail = cur_result;
	else {
		op->result_tail->next = cur_result;
		op->result_tail = cur_result;
	}

	last_handle = get_le16(pdu + length - data_length);
	if (last_handle != op->end_handle) {
		uint8_t pdu[4];

		put_le16(last_handle + 1, pdu);
		put_le16(op->end_handle, pdu + 2);

		if (bt_att_send(op->att, BT_ATT_OP_FIND_INFO_REQ,
						pdu, sizeof(pdu),
						discover_descs_cb,
						discovery_op_ref(op),
						discovery_op_unref))
			return;

		discovery_op_unref(op);
		success = false;
		goto done;
	}

success:
	final_result = op->result_head;
	success = true;

done:
	if (op->callback)
		op->callback(success, att_ecode, final_result, op->user_data);
}

bool bt_gatt_discover_descriptors(struct bt_att *att,
					uint16_t start, uint16_t end,
					bt_gatt_discovery_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	struct discovery_op *op;
	uint8_t pdu[4];

	if (!att)
		return false;

	op = new0(struct discovery_op, 1);
	if (!op)
		return false;

	op->att = att;
	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;
	op->end_handle = end;

	put_le16(start, pdu);
	put_le16(end, pdu + 2);

	if (!bt_att_send(att, BT_ATT_OP_FIND_INFO_REQ, pdu, sizeof(pdu),
						discover_descs_cb,
						discovery_op_ref(op),
						discovery_op_unref)) {
		free(op);
		return false;
	}

	return true;
}

struct read_op {
	bt_gatt_read_callback_t callback;
	void *user_data;
	bt_gatt_destroy_func_t destroy;
};

static void destroy_read_op(void *data)
{
	struct read_op *op = data;

	if (op->destroy)
		op->destroy(op->user_data);

	free(op);
}

static void read_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct read_op *op = user_data;
	bool success;
	uint8_t att_ecode = 0;
	const uint8_t *value = NULL;
	uint16_t value_len = 0;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);
		goto done;
	}

	if (opcode != BT_ATT_OP_READ_RSP || (!pdu && length)) {
		success = false;
		goto done;
	}

	success = true;
	value_len = length;
	if (value_len)
		value = pdu;

done:
	if (op->callback)
		op->callback(success, att_ecode, value, length, op->user_data);
}

bool bt_gatt_read_value(struct bt_att *att, uint16_t value_handle,
					bt_gatt_read_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	struct read_op *op;
	uint8_t pdu[2];

	if (!att)
		return false;

	op = new0(struct read_op, 1);
	if (!op)
		return false;

	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	put_le16(value_handle, pdu);

	if (!bt_att_send(att, BT_ATT_OP_READ_REQ, pdu, sizeof(pdu),
							read_cb, op,
							destroy_read_op)) {
		free(op);
		return false;
	}

	return true;
}

struct read_long_op {
	struct bt_att *att;
	int ref_count;
	uint16_t value_handle;
	size_t orig_offset;
	size_t offset;
	struct queue *blobs;
	bt_gatt_read_callback_t callback;
	void *user_data;
	bt_gatt_destroy_func_t destroy;
};

struct blob {
	uint8_t *data;
	uint16_t offset;
	uint16_t length;
};

static struct blob *create_blob(const uint8_t *data, uint16_t len,
								uint16_t offset)
{
	struct blob *blob;

	blob = new0(struct blob, 1);
	if (!blob)
		return NULL;

	blob->data = malloc(len);
	if (!blob->data) {
		free(blob);
		return NULL;
	}

	memcpy(blob->data, data, len);
	blob->length = len;
	blob->offset = offset;

	return blob;
}

static void destroy_blob(void *data)
{
	struct blob *blob = data;

	free(blob->data);
	free(blob);
}

static struct read_long_op *read_long_op_ref(struct read_long_op *op)
{
	__sync_fetch_and_add(&op->ref_count, 1);

	return op;
}

static void read_long_op_unref(void *data)
{
	struct read_long_op *op = data;

	if (__sync_sub_and_fetch(&op->ref_count, 1))
		return;

	if (op->destroy)
		op->destroy(op->user_data);

	queue_destroy(op->blobs, destroy_blob);

	free(op);
}

static void append_blob(void *data, void *user_data)
{
	struct blob *blob = data;
	uint8_t *value = user_data;

	memcpy(value + blob->offset, blob->data, blob->length);
}

static void complete_read_long_op(struct read_long_op *op, bool success,
							uint8_t att_ecode)
{
	uint8_t *value = NULL;
	uint16_t length = 0;

	if (!success)
		goto done;

	length = op->offset - op->orig_offset;

	if (!length)
		goto done;

	value = malloc(length);
	if (!value) {
		success = false;
		goto done;
	}

	queue_foreach(op->blobs, append_blob, value - op->orig_offset);

done:
	if (op->callback)
		op->callback(success, att_ecode, value, length, op->user_data);

	free(value);
}

static void read_long_cb(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct read_long_op *op = user_data;
	struct blob *blob;
	bool success;
	uint8_t att_ecode = 0;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);
		goto done;
	}

	if (opcode != BT_ATT_OP_READ_BLOB_RSP || (!pdu && length)) {
		success = false;
		goto done;
	}

	if (!length)
		goto success;

	blob = create_blob(pdu, length, op->offset);
	if (!blob) {
		success = false;
		goto done;
	}

	queue_push_tail(op->blobs, blob);
	op->offset += length;
	if (op->offset > UINT16_MAX)
		goto success;

	if (length >= bt_att_get_mtu(op->att) - 1) {
		uint8_t pdu[4];

		put_le16(op->value_handle, pdu);
		put_le16(op->offset, pdu + 2);

		if (bt_att_send(op->att, BT_ATT_OP_READ_BLOB_REQ,
							pdu, sizeof(pdu),
							read_long_cb,
							read_long_op_ref(op),
							read_long_op_unref))
			return;

		read_long_op_unref(op);
		success = false;
		goto done;
	}

success:
	success = true;

done:
	complete_read_long_op(op, success, att_ecode);
}

bool bt_gatt_read_long_value(struct bt_att *att,
					uint16_t value_handle, uint16_t offset,
					bt_gatt_read_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	struct read_long_op *op;
	uint8_t pdu[4];

	if (!att)
		return false;

	op = new0(struct read_long_op, 1);
	if (!op)
		return false;

	op->blobs = queue_new();
	if (!op->blobs) {
		free(op);
		return false;
	}

	op->att = att;
	op->value_handle = value_handle;
	op->orig_offset = offset;
	op->offset = offset;
	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	put_le16(value_handle, pdu);
	put_le16(offset, pdu + 2);

	if (!bt_att_send(att, BT_ATT_OP_READ_BLOB_REQ, pdu, sizeof(pdu),
							read_long_cb,
							read_long_op_ref(op),
							read_long_op_unref)) {
		queue_destroy(op->blobs, free);
		free(op);
		return false;
	}

	return true;
}

bool bt_gatt_write_without_response(struct bt_att *att,
					uint16_t value_handle,
					bool signed_write,
					uint8_t *value, uint16_t length)
{
	uint8_t pdu[2 + length];

	if (!att)
		return 0;

	/* TODO: Support this once bt_att_send supports signed writes. */
	if (signed_write)
		return 0;

	put_le16(value_handle, pdu);
	memcpy(pdu + 2, value, length);

	return bt_att_send(att, BT_ATT_OP_WRITE_CMD, pdu, sizeof(pdu),
							NULL, NULL, NULL);
}

struct write_op {
	bt_gatt_result_callback_t callback;
	void *user_data;
	bt_gatt_destroy_func_t destroy;
};

static void destroy_write_op(void *data)
{
	struct write_op *op = data;

	if (op->destroy)
		op->destroy(op->user_data);

	free(op);
}

static void write_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct write_op *op = user_data;
	bool success = true;
	uint8_t att_ecode = 0;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);
		goto done;
	}

	if (opcode != BT_ATT_OP_WRITE_RSP || pdu || length)
		success = false;

done:
	if (op->callback)
		op->callback(success, att_ecode, op->user_data);
}

bool bt_gatt_write_value(struct bt_att *att, uint16_t value_handle,
					uint8_t *value, uint16_t length,
					bt_gatt_result_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	struct write_op *op;
	uint8_t pdu[2 + length];

	if (!att)
		return false;

	op = new0(struct write_op, 1);
	if (!op)
		return false;

	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	put_le16(value_handle, pdu);
	memcpy(pdu + 2, value, length);

	if (!bt_att_send(att, BT_ATT_OP_WRITE_REQ, pdu, sizeof(pdu),
							write_cb, op,
							destroy_write_op)) {
		free(op);
		return false;
	}

	return true;
}

struct write_long_op {
	struct bt_att *att;
	int ref_count;
	bool reliable;
	bool success;
	uint8_t att_ecode;
	bool reliable_error;
	uint16_t value_handle;
	uint8_t *value;
	uint16_t length;
	uint16_t offset;
	uint16_t index;
	uint16_t cur_length;
	bt_gatt_write_long_callback_t callback;
	void *user_data;
	bt_gatt_destroy_func_t destroy;
};

static struct write_long_op *write_long_op_ref(struct write_long_op *op)
{
	__sync_fetch_and_add(&op->ref_count, 1);

	return op;
}

static void write_long_op_unref(void *data)
{
	struct write_long_op *op = data;

	if (__sync_sub_and_fetch(&op->ref_count, 1))
		return;

	if (op->destroy)
		op->destroy(op->user_data);

	free(op->value);
	free(op);
}

static void execute_write_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct write_long_op *op = user_data;
	bool success = op->success;
	uint8_t att_ecode = op->att_ecode;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);
	} else if (opcode != BT_ATT_OP_EXEC_WRITE_RSP || pdu || length)
		success = false;

	if (op->callback)
		op->callback(success, op->reliable_error, att_ecode,
								op->user_data);
}

static void complete_write_long_op(struct write_long_op *op, bool success,
					uint8_t att_ecode, bool reliable_error)
{
	uint8_t pdu;

	op->success = success;
	op->att_ecode = att_ecode;
	op->reliable_error = reliable_error;

	if (success)
		pdu = 0x01;  /* Write */
	else
		pdu = 0x00;  /* Cancel */

	if (bt_att_send(op->att, BT_ATT_OP_EXEC_WRITE_REQ, &pdu, sizeof(pdu),
						execute_write_cb,
						write_long_op_ref(op),
						write_long_op_unref))
		return;

	write_long_op_unref(op);
	success = false;

	if (op->callback)
		op->callback(success, reliable_error, att_ecode, op->user_data);
}

static void prepare_write_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct write_long_op *op = user_data;
	bool success = true;
	bool reliable_error = false;
	uint8_t att_ecode = 0;
	uint16_t next_index;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);
		goto done;
	}

	if (opcode != BT_ATT_OP_PREP_WRITE_RSP) {
		success = false;
		goto done;
	}

	if (op->reliable) {
		if (!pdu || length != (op->cur_length + 4)) {
			success = false;
			reliable_error = true;
			goto done;
		}

		if (get_le16(pdu) != op->value_handle ||
				get_le16(pdu + 2) != (op->offset + op->index)) {
			success = false;
			reliable_error = true;
			goto done;
		}

		if (memcmp(pdu + 4, op->value + op->index, op->cur_length)) {
			success = false;
			reliable_error = true;
			goto done;
		}
	}

	next_index = op->index + op->cur_length;
	if (next_index == op->length) {
		/* All bytes written */
		goto done;
	}

	/* If the last written length greater than or equal to what can fit
	 * inside a PDU, then there is more data to send.
	 */
	if (op->cur_length >= bt_att_get_mtu(op->att) - 5) {
		uint8_t *pdu;

		op->index = next_index;
		op->cur_length = MIN(op->length - op->index,
						bt_att_get_mtu(op->att) - 5);

		pdu = malloc(op->cur_length + 4);
		if (!pdu) {
			success = false;
			goto done;
		}

		put_le16(op->value_handle, pdu);
		put_le16(op->offset + op->index, pdu + 2);
		memcpy(pdu + 4, op->value + op->index, op->cur_length);

		if (!bt_att_send(op->att, BT_ATT_OP_PREP_WRITE_REQ,
							pdu, op->cur_length + 4,
							prepare_write_cb,
							write_long_op_ref(op),
							write_long_op_unref)) {
			write_long_op_unref(op);
			success = false;
		}

		free(pdu);

		/* If so far successful, then the operation should continue.
		 * Otherwise, there was an error and the procedure should be
		 * completed.
		 */
		if (success)
			return;
	}

done:
	complete_write_long_op(op, success, att_ecode, reliable_error);
}

bool bt_gatt_write_long_value(struct bt_att *att, bool reliable,
					uint16_t value_handle, uint16_t offset,
					uint8_t *value, uint16_t length,
					bt_gatt_write_long_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	struct write_long_op *op;
	uint8_t *pdu;
	bool status;

	if (!att)
		return false;

	if ((size_t)(length + offset) > UINT16_MAX)
		return false;

	/* Don't allow riting a 0-length value using this procedure. The
	 * upper-layer should use bt_gatt_write_value for that instead.
	 */
	if (!length || !value)
		return false;

	op = new0(struct write_long_op, 1);
	if (!op)
		return false;

	op->value = malloc(length);
	if (!op->value) {
		free(op);
		return false;
	}

	memcpy(op->value, value, length);

	op->att = att;
	op->reliable = reliable;
	op->value_handle = value_handle;
	op->length = length;
	op->offset = offset;
	op->cur_length = MIN(length, bt_att_get_mtu(att) - 5);
	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	pdu = malloc(op->cur_length + 4);
	if (!pdu) {
		free(op->value);
		free(op);
		return false;
	}

	put_le16(value_handle, pdu);
	put_le16(offset, pdu + 2);
	memcpy(pdu + 4, op->value, op->cur_length);

	status = bt_att_send(att, BT_ATT_OP_PREP_WRITE_REQ,
							pdu, op->cur_length + 4,
							prepare_write_cb,
							write_long_op_ref(op),
							write_long_op_unref);

	free(pdu);

	if (!status) {
		free(op->value);
		free(op);
		return false;
	}

	return true;
}

struct notify_data {
	struct bt_att *att;
	bt_gatt_notify_callback_t callback;
	void *user_data;
	bt_gatt_destroy_func_t destroy;
};

static void notify_data_destroy(void *data)
{
	struct notify_data *notd = data;

	if (notd->destroy)
		notd->destroy(notd->user_data);

	free(notd);
}

static void notify_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct notify_data *data = user_data;
	uint16_t value_handle;
	const uint8_t *value = NULL;

	value_handle = get_le16(pdu);

	if (length > 2)
		value = pdu + 2;

	if (data->callback)
		data->callback(value_handle, value, length - 2, data->user_data);

	if (opcode == BT_ATT_OP_HANDLE_VAL_IND)
		bt_att_send(data->att, BT_ATT_OP_HANDLE_VAL_CONF, NULL, 0,
							NULL, NULL, NULL);
}

unsigned int bt_gatt_register(struct bt_att *att, bool indications,
					bt_gatt_notify_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	struct notify_data *data;
	uint8_t opcode;
	unsigned int id;

	if (!att)
		return 0;

	data = new0(struct notify_data, 1);
	if (!data)
		return 0;

	data->att = att;
	data->callback = callback;
	data->user_data = user_data;
	data->destroy = destroy;

	opcode = indications ? BT_ATT_OP_HANDLE_VAL_IND : BT_ATT_OP_HANDLE_VAL_NOT;

	id = bt_att_register(att, opcode, notify_cb, data, notify_data_destroy);
	if (!id)
		free(data);

	return id;
}
