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

struct bt_gatt_server {
	struct gatt_db *db;
	struct bt_att *att;
	int ref_count;
	uint16_t mtu;

	unsigned int mtu_id;
	unsigned int read_by_grp_type_id;

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
	bt_att_unref(server->att);

	free(server);
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
			data_val_len = value.iov_len;
			pdu[0] = data_val_len + 4;
			iter++;
		} else if (value.iov_len != data_val_len)
			break;

		/* Stop if this unit would surpass the MTU */
		if (iter + data_val_len + 4 > mtu)
			break;

		gatt_db_attribute_get_service_handles(attrib, &start_handle,
								&end_handle);

		put_le16(start_handle, pdu + iter);
		put_le16(end_handle, pdu + iter + 2);
		memcpy(pdu + iter + 4, value.iov_base, value.iov_len);

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
