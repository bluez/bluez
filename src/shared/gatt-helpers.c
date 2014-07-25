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

struct bt_gatt_list {
	struct bt_gatt_list *next;
	void *data;
};

struct list_ptrs {
	struct bt_gatt_list *head;
	struct bt_gatt_list *tail;
};

struct bt_gatt_list *bt_gatt_list_get_next(struct bt_gatt_list *list)
{
	return list->next;
}

void *bt_gatt_list_get_data(struct bt_gatt_list *list)
{
	return list->data;
}

static inline bool list_isempty(struct list_ptrs *list)
{
	return !list->head && !list->tail;
}

static bool list_add(struct list_ptrs *list, void *data)
{
	struct bt_gatt_list *item = new0(struct bt_gatt_list, 1);
	if (!item)
		return false;

	item->data = data;

	if (list_isempty(list)) {
		list->head = list->tail = item;
		return true;
	}

	list->tail->next = item;
	list->tail = item;

	return true;
}

static void list_free(struct list_ptrs *list, bt_gatt_destroy_func_t destroy)
{
	struct bt_gatt_list *l, *tmp;
	l = list->head;

	while (l) {
		if (destroy)
			destroy(l->data);

		tmp = l->next;
		free(l);
		l = tmp;
	}
}

static const uint8_t bt_base_uuid[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
	0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
};

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

struct discovery_op {
	struct bt_att *att;
	int ref_count;
	bt_uuid_t uuid;
	struct list_ptrs results;
	bt_gatt_discovery_callback_t callback;
	void *user_data;
	bt_gatt_destroy_func_t destroy;
};

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

	list_free(&op->results, free);

	free(op);
}

static void put_uuid_le(const bt_uuid_t *src, void *dst)
{
	if (src->type == BT_UUID16)
		put_le16(src->value.u16, dst);
	else
		bswap_128(&src->value.u128, dst);
}

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

static void read_by_grp_type_cb(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct discovery_op *op = user_data;
	bool success;
	uint8_t att_ecode = 0;
	struct bt_gatt_list *results = NULL;
	size_t data_length;
	size_t list_length;
	uint16_t last_end;
	int i;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);

		if (att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND &&
						!list_isempty(&op->results))
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

	for (i = 1; i < length; i += data_length) {
		struct bt_gatt_service *service;

		service = new0(struct bt_gatt_service, 1);
		if (!service) {
			success = false;
			goto done;
		}

		service->start = get_le16(pdu + i);
		last_end = get_le16(pdu + i + 2);
		service->end = last_end;
		convert_uuid_le(pdu + i + 4, data_length - 4, service->uuid);

		if (!list_add(&op->results, service)) {
			success = false;
			goto done;
		}
	}

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
	results = op->results.head;
	success = true;

done:
	if (op->callback)
		op->callback(success, att_ecode, results, op->user_data);
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
		free(op);
		return false;
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

bool bt_gatt_discover_characteristics(struct bt_att *att,
					uint16_t start, uint16_t end,
					bt_uuid_t *uuid,
					bt_gatt_discovery_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	/* TODO */
	return false;
}

bool bt_gatt_discover_descriptors(struct bt_att *att,
					uint16_t start, uint16_t end,
					bt_gatt_discovery_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	/* TODO */
	return false;
}

bool bt_gatt_read_value(struct bt_att *att, uint16_t value_handle,
					bt_gatt_read_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	/* TODO */
	return false;
}

bool bt_gatt_read_long_value(struct bt_att *att,
					uint16_t value_handle, uint16_t offset,
					bt_gatt_read_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	/* TODO */
	return false;
}

bool bt_gatt_write_without_response(struct bt_att *att,
					uint16_t value_handle,
                                        bool signed_write,
					uint8_t *value, uint16_t length)
{
	/* TODO */
	return false;
}

bool bt_gatt_write_value(struct bt_att *att, uint16_t value_handle,
					uint8_t *value, uint16_t length,
					bt_gatt_result_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	/* TODO */
	return false;
}

bool bt_gatt_write_long_value(struct bt_att *att, bool reliable,
					uint16_t value_handle, uint16_t offset,
					uint8_t *value, uint16_t length,
					bt_gatt_write_long_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	/* TODO */
	return false;
}

unsigned int bt_gatt_register(struct bt_att *att, bool indications,
					bt_gatt_notify_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	/* TODO */
	return false;
}
