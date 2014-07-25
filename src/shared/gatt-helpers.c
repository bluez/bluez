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

bool bt_gatt_discover_primary_services(struct bt_att *att,
					bt_uuid_t *uuid,
					bt_gatt_discovery_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy)
{
	/* TODO */
	return false;
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
