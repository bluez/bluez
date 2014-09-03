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

#include "src/shared/att.h"
#include "src/shared/gatt-client.h"
#include "lib/uuid.h"
#include "src/shared/gatt-helpers.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define UUID_BYTES (BT_GATT_UUID_SIZE * sizeof(uint8_t))

struct service_list {
	bt_gatt_service_t service;
	struct service_list *next;
};

struct bt_gatt_client {
	struct bt_att *att;
	int ref_count;

	bt_gatt_client_callback_t ready_callback;
	bt_gatt_client_destroy_func_t ready_destroy;
	void *ready_data;

	bt_gatt_client_debug_func_t debug_callback;
	bt_gatt_client_destroy_func_t debug_destroy;
	void *debug_data;

	struct service_list *svc_head, *svc_tail;
	bool in_init;
	bool ready;

	/* Queue of long write requests. An error during "prepare write"
	 * requests can result in a cancel through "execute write". To prevent
	 * cancelation of prepared writes to the wrong attribute and multiple
	 * requests to the same attribute that may result in a corrupted final
	 * value, we avoid interleaving prepared writes.
	 */
	struct queue *long_write_queue;
	bool in_long_write;
};

static bool gatt_client_add_service(struct bt_gatt_client *client,
						uint16_t start, uint16_t end,
						uint8_t uuid[BT_GATT_UUID_SIZE])
{
	struct service_list *list;

	list = new0(struct service_list, 1);
	if (!list)
		return false;

	list->service.start_handle = start;
	list->service.end_handle = end;
	memcpy(list->service.uuid, uuid, UUID_BYTES);

	if (!client->svc_head)
		client->svc_head = client->svc_tail = list;
	else {
		client->svc_tail->next = list;
		client->svc_tail = list;
	}

	return true;
}

static void service_destroy_characteristics(bt_gatt_service_t *service)
{
	unsigned int i;

	for (i = 0; i < service->num_chrcs; i++)
		free((bt_gatt_descriptor_t *) service->chrcs[i].descs);

	free((bt_gatt_characteristic_t *) service->chrcs);
}

static void gatt_client_clear_services(struct bt_gatt_client *client)
{
	struct service_list *l, *tmp;

	l = client->svc_head;

	while (l) {
		service_destroy_characteristics(&l->service);
		tmp = l;
		l = tmp->next;
		free(tmp);
	}

	client->svc_head = client->svc_tail = NULL;
}

struct discovery_op {
	struct bt_gatt_client *client;
	struct service_list *cur_service;
	bt_gatt_characteristic_t *cur_chrc;
	int cur_chrc_index;
	int ref_count;
};

static struct discovery_op *discovery_op_ref(struct discovery_op *op)
{
	__sync_fetch_and_add(&op->ref_count, 1);

	return op;
}

static void discovery_op_unref(void *data)
{
	struct discovery_op *op = data;

	if (__sync_sub_and_fetch(&op->ref_count, 1))
		return;

	free(data);
}

static void discovery_op_complete(struct discovery_op *op, bool success,
							uint8_t att_ecode)
{
	struct bt_gatt_client *client = op->client;

	client->in_init = false;

	if (success)
		client->ready = true;
	else
		gatt_client_clear_services(client);

	if (client->ready_callback)
		client->ready_callback(success, att_ecode, client->ready_data);
}

static void uuid_to_string(const uint8_t uuid[BT_GATT_UUID_SIZE],
						char str[MAX_LEN_UUID_STR])
{
	bt_uuid_t tmp;

	tmp.type = BT_UUID128;
	memcpy(tmp.value.u128.data, uuid, UUID_BYTES);
	bt_uuid_to_string(&tmp, str, MAX_LEN_UUID_STR * sizeof(char));
}

static void discover_chrcs_cb(bool success, uint8_t att_ecode,
						struct bt_gatt_result *result,
						void *user_data);

static void discover_descs_cb(bool success, uint8_t att_ecode,
						struct bt_gatt_result *result,
						void *user_data)
{
	struct discovery_op *op = user_data;
	struct bt_gatt_client *client = op->client;
	struct bt_gatt_iter iter;
	char uuid_str[MAX_LEN_UUID_STR];
	unsigned int desc_count;
	uint16_t desc_start;
	unsigned int i;
	bt_gatt_descriptor_t *descs;

	if (!success) {
		if (att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND) {
			success = true;
			goto next;
		}

		goto done;
	}

	if (!result || !bt_gatt_iter_init(&iter, result)) {
		success = false;
		goto done;
	}

	desc_count = bt_gatt_result_descriptor_count(result);
	if (desc_count == 0) {
		success = false;
		goto done;
	}

	util_debug(client->debug_callback, client->debug_data,
					"Descriptors found: %u", desc_count);

	descs = new0(bt_gatt_descriptor_t, desc_count);
	if (!descs) {
		success = false;
		goto done;
	}

	i = 0;
	while (bt_gatt_iter_next_descriptor(&iter, &descs[i].handle,
							descs[i].uuid)) {
		uuid_to_string(descs[i].uuid, uuid_str);
		util_debug(client->debug_callback, client->debug_data,
						"handle: 0x%04x, uuid: %s",
						descs[i].handle, uuid_str);
		i++;
	}

	op->cur_chrc->num_descs = desc_count;
	op->cur_chrc->descs = descs;

	for (i = op->cur_chrc_index + 1;
				i < op->cur_service->service.num_chrcs; i++) {
		op->cur_chrc_index = i;
		op->cur_chrc++;
		desc_start = op->cur_chrc->value_handle + 1;
		if (desc_start > op->cur_chrc->end_handle)
			continue;

		if (bt_gatt_discover_descriptors(client->att,
						desc_start,
						op->cur_chrc->end_handle,
						discover_descs_cb,
						discovery_op_ref(op),
						discovery_op_unref))
			return;

		util_debug(client->debug_callback, client->debug_data,
					"Failed to start descriptor discovery");
		discovery_op_unref(op);
		success = false;

		goto done;
	}

next:
	if (!op->cur_service->next)
		goto done;

	/* Move on to the next service */
	op->cur_service = op->cur_service->next;
	if (bt_gatt_discover_characteristics(client->att,
					op->cur_service->service.start_handle,
					op->cur_service->service.end_handle,
					discover_chrcs_cb,
					discovery_op_ref(op),
					discovery_op_unref))
		return;

	util_debug(client->debug_callback, client->debug_data,
				"Failed to start characteristic discovery");
	discovery_op_unref(op);
	success = false;

done:
	discovery_op_complete(op, success, att_ecode);
}

static void discover_chrcs_cb(bool success, uint8_t att_ecode,
						struct bt_gatt_result *result,
						void *user_data)
{
	struct discovery_op *op = user_data;
	struct bt_gatt_client *client = op->client;
	struct bt_gatt_iter iter;
	char uuid_str[MAX_LEN_UUID_STR];
	unsigned int chrc_count;
	unsigned int i;
	uint16_t desc_start;
	bt_gatt_characteristic_t *chrcs;

	if (!success) {
		if (att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND) {
			success = true;
			goto next;
		}

		goto done;
	}

	if (!result || !bt_gatt_iter_init(&iter, result)) {
		success = false;
		goto done;
	}

	chrc_count = bt_gatt_result_characteristic_count(result);
	util_debug(client->debug_callback, client->debug_data,
				"Characteristics found: %u", chrc_count);

	if (chrc_count == 0)
		goto next;

	chrcs = new0(bt_gatt_characteristic_t, chrc_count);
	if (!chrcs) {
		success = false;
		goto done;
	}

	i = 0;
	while (bt_gatt_iter_next_characteristic(&iter, &chrcs[i].start_handle,
							&chrcs[i].end_handle,
							&chrcs[i].value_handle,
							&chrcs[i].properties,
							chrcs[i].uuid)) {
		uuid_to_string(chrcs[i].uuid, uuid_str);
		util_debug(client->debug_callback, client->debug_data,
				"start: 0x%04x, end: 0x%04x, value: 0x%04x, "
				"props: 0x%02x, uuid: %s",
				chrcs[i].start_handle, chrcs[i].end_handle,
				chrcs[i].value_handle, chrcs[i].properties,
				uuid_str);
		i++;
	}

	op->cur_service->service.chrcs = chrcs;
	op->cur_service->service.num_chrcs = chrc_count;

	for (i = 0; i < chrc_count; i++) {
		op->cur_chrc_index = i;
		op->cur_chrc = chrcs + i;
		desc_start = chrcs[i].value_handle + 1;
		if (desc_start > chrcs[i].end_handle)
			continue;

		if (bt_gatt_discover_descriptors(client->att,
						desc_start, chrcs[i].end_handle,
						discover_descs_cb,
						discovery_op_ref(op),
						discovery_op_unref))
			return;

		util_debug(client->debug_callback, client->debug_data,
					"Failed to start descriptor discovery");
		discovery_op_unref(op);
		success = false;

		goto done;
	}

next:
	if (!op->cur_service->next)
		goto done;

	/* Move on to the next service */
	op->cur_service = op->cur_service->next;
	if (bt_gatt_discover_characteristics(client->att,
					op->cur_service->service.start_handle,
					op->cur_service->service.end_handle,
					discover_chrcs_cb,
					discovery_op_ref(op),
					discovery_op_unref))
		return;

	util_debug(client->debug_callback, client->debug_data,
				"Failed to start characteristic discovery");
	discovery_op_unref(op);
	success = false;

done:
	discovery_op_complete(op, success, att_ecode);
}

static void discover_primary_cb(bool success, uint8_t att_ecode,
						struct bt_gatt_result *result,
						void *user_data)
{
	struct discovery_op *op = user_data;
	struct bt_gatt_client *client = op->client;
	struct bt_gatt_iter iter;
	uint16_t start, end;
	uint8_t uuid[BT_GATT_UUID_SIZE];
	char uuid_str[MAX_LEN_UUID_STR];

	if (!success) {
		util_debug(client->debug_callback, client->debug_data,
					"Primary service discovery failed."
					" ATT ECODE: 0x%02x", att_ecode);
		goto done;
	}

	if (!result || !bt_gatt_iter_init(&iter, result)) {
		success = false;
		goto done;
	}

	util_debug(client->debug_callback, client->debug_data,
					"Primary services found: %u",
					bt_gatt_result_service_count(result));

	while (bt_gatt_iter_next_service(&iter, &start, &end, uuid)) {
		/* Log debug message. */
		uuid_to_string(uuid, uuid_str);
		util_debug(client->debug_callback, client->debug_data,
				"start: 0x%04x, end: 0x%04x, uuid: %s",
				start, end, uuid_str);

		/* Store the service */
		if (!gatt_client_add_service(client, start, end, uuid)) {
			util_debug(client->debug_callback, client->debug_data,
						"Failed to store service");
			success = false;
			goto done;
		}
	}

	/* Complete the process if the service list is empty */
	if (!client->svc_head)
		goto done;

	/* Sequentially discover the characteristics of all services */
	op->cur_service = client->svc_head;
	if (bt_gatt_discover_characteristics(client->att,
					op->cur_service->service.start_handle,
					op->cur_service->service.end_handle,
					discover_chrcs_cb,
					discovery_op_ref(op),
					discovery_op_unref))
		return;

	util_debug(client->debug_callback, client->debug_data,
				"Failed to start characteristic discovery");
	discovery_op_unref(op);
	success = false;

done:
	discovery_op_complete(op, success, att_ecode);
}

static void exchange_mtu_cb(bool success, uint8_t att_ecode, void *user_data)
{
	struct discovery_op *op = user_data;
	struct bt_gatt_client *client = op->client;

	if (!success) {
		util_debug(client->debug_callback, client->debug_data,
				"MTU Exchange failed. ATT ECODE: 0x%02x",
				att_ecode);

		client->in_init = false;

		if (client->ready_callback)
			client->ready_callback(success, att_ecode,
							client->ready_data);

		return;
	}

	util_debug(client->debug_callback, client->debug_data,
					"MTU exchange complete, with MTU: %u",
					bt_att_get_mtu(client->att));

	if (bt_gatt_discover_primary_services(client->att, NULL,
							discover_primary_cb,
							discovery_op_ref(op),
							discovery_op_unref))
		return;

	util_debug(client->debug_callback, client->debug_data,
			"Failed to initiate primary service discovery");

	client->in_init = false;

	if (client->ready_callback)
		client->ready_callback(success, att_ecode, client->ready_data);

	discovery_op_unref(op);
}

static bool gatt_client_init(struct bt_gatt_client *client, uint16_t mtu)
{
	struct discovery_op *op;

	if (client->in_init || client->ready)
		return false;

	op = new0(struct discovery_op, 1);
	if (!op)
		return false;

	op->client = client;

	/* Configure the MTU */
	if (!bt_gatt_exchange_mtu(client->att, MAX(BT_ATT_DEFAULT_LE_MTU, mtu),
							exchange_mtu_cb,
							discovery_op_ref(op),
							discovery_op_unref)) {
		if (client->ready_callback)
			client->ready_callback(false, 0, client->ready_data);

		free(op);
	}

	client->in_init = true;

	return true;
}

struct bt_gatt_client *bt_gatt_client_new(struct bt_att *att, uint16_t mtu)
{
	struct bt_gatt_client *client;

	if (!att)
		return NULL;

	client = new0(struct bt_gatt_client, 1);
	if (!client)
		return NULL;

	client->long_write_queue = queue_new();
	if (!client->long_write_queue) {
		free(client);
		return NULL;
	}

	client->att = bt_att_ref(att);

	gatt_client_init(client, mtu);

	return bt_gatt_client_ref(client);
}

struct bt_gatt_client *bt_gatt_client_ref(struct bt_gatt_client *client)
{
	if (!client)
		return NULL;

	__sync_fetch_and_add(&client->ref_count, 1);

	return client;
}

static void long_write_op_unref(void *data);

void bt_gatt_client_unref(struct bt_gatt_client *client)
{
	if (!client)
		return;

	if (__sync_sub_and_fetch(&client->ref_count, 1))
		return;

	if (client->ready_destroy)
		client->ready_destroy(client->ready_data);

	if (client->debug_destroy)
		client->debug_destroy(client->debug_data);

	queue_destroy(client->long_write_queue, long_write_op_unref);
	bt_att_unref(client->att);
	free(client);
}

bool bt_gatt_client_is_ready(struct bt_gatt_client *client)
{
	return (client && client->ready);
}

bool bt_gatt_client_set_ready_handler(struct bt_gatt_client *client,
					bt_gatt_client_callback_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy)
{
	if (!client)
		return false;

	if (client->ready_destroy)
		client->ready_destroy(client->ready_data);

	client->ready_callback = callback;
	client->ready_destroy = destroy;
	client->ready_data = user_data;

	return true;
}

bool bt_gatt_client_set_debug(struct bt_gatt_client *client,
					bt_gatt_client_debug_func_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy) {
	if (!client)
		return false;

	if (client->debug_destroy)
		client->debug_destroy(client->debug_data);

	client->debug_callback = callback;
	client->debug_destroy = destroy;
	client->debug_data = user_data;

	return true;
}

bool bt_gatt_service_iter_init(struct bt_gatt_service_iter *iter,
						struct bt_gatt_client *client)
{
	if (!iter || !client)
		return false;

	if (client->in_init)
		return false;

	memset(iter, 0, sizeof(*iter));
	iter->client = client;
	iter->ptr = NULL;

	return true;
}

bool bt_gatt_service_iter_next(struct bt_gatt_service_iter *iter,
						bt_gatt_service_t *service)
{
	struct service_list *l;

	if (!iter || !service)
		return false;

	l = iter->ptr;

	if (!l)
		l = iter->client->svc_head;
	else
		l = l->next;

	if (!l)
		return false;

	*service = l->service;
	iter->ptr = l;

	return true;
}

bool bt_gatt_service_iter_next_by_handle(struct bt_gatt_service_iter *iter,
						uint16_t start_handle,
						bt_gatt_service_t *service)
{
	while (bt_gatt_service_iter_next(iter, service)) {
		if (service->start_handle == start_handle)
			return true;
	}

	return false;
}

bool bt_gatt_service_iter_next_by_uuid(struct bt_gatt_service_iter *iter,
					const uint8_t uuid[BT_GATT_UUID_SIZE],
					bt_gatt_service_t *service)
{
	while (bt_gatt_service_iter_next(iter, service)) {
		if (memcmp(service->uuid, uuid, UUID_BYTES) == 0)
			return true;
	}

	return false;
}

struct read_op {
	bt_gatt_client_read_callback_t callback;
	void *user_data;
	bt_gatt_client_destroy_func_t destroy;
};

static void destroy_read_op(void *data)
{
	struct read_op *op = data;

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

bool bt_gatt_client_read_value(struct bt_gatt_client *client,
					uint16_t value_handle,
					bt_gatt_client_read_callback_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy)
{
	struct read_op *op;
	uint8_t pdu[2];

	if (!client)
		return false;

	op = new0(struct read_op, 1);
	if (!op)
		return false;

	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	put_le16(value_handle, pdu);

	if (!bt_att_send(client->att, BT_ATT_OP_READ_REQ, pdu, sizeof(pdu),
							read_cb, op,
							destroy_read_op)) {
		free(op);
		return false;
	}

	return true;
}

struct read_long_op {
	struct bt_gatt_client *client;
	int ref_count;
	uint16_t value_handle;
	size_t orig_offset;
	size_t offset;
	struct queue *blobs;
	bt_gatt_client_read_callback_t callback;
	void *user_data;
	bt_gatt_client_destroy_func_t destroy;
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

	if (length >= bt_att_get_mtu(op->client->att) - 1) {
		uint8_t pdu[4];

		put_le16(op->value_handle, pdu);
		put_le16(op->offset, pdu + 2);

		if (bt_att_send(op->client->att, BT_ATT_OP_READ_BLOB_REQ,
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

bool bt_gatt_client_read_long_value(struct bt_gatt_client *client,
					uint16_t value_handle, uint16_t offset,
					bt_gatt_client_read_callback_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy)
{
	struct read_long_op *op;
	uint8_t pdu[4];

	if (!client)
		return false;

	op = new0(struct read_long_op, 1);
	if (!op)
		return false;

	op->blobs = queue_new();
	if (!op->blobs) {
		free(op);
		return false;
	}

	op->client = client;
	op->value_handle = value_handle;
	op->orig_offset = offset;
	op->offset = offset;
	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	put_le16(value_handle, pdu);
	put_le16(offset, pdu + 2);

	if (!bt_att_send(client->att, BT_ATT_OP_READ_BLOB_REQ, pdu, sizeof(pdu),
							read_long_cb,
							read_long_op_ref(op),
							read_long_op_unref)) {
		queue_destroy(op->blobs, free);
		free(op);
		return false;
	}

	return true;
}

bool bt_gatt_client_write_without_response(struct bt_gatt_client *client,
					uint16_t value_handle,
					bool signed_write,
					uint8_t *value, uint16_t length) {
	uint8_t pdu[2 + length];

	if (!client)
		return 0;

	/* TODO: Support this once bt_att_send supports signed writes. */
	if (signed_write)
		return 0;

	put_le16(value_handle, pdu);
	memcpy(pdu + 2, value, length);

	return bt_att_send(client->att, BT_ATT_OP_WRITE_CMD, pdu, sizeof(pdu),
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

bool bt_gatt_client_write_value(struct bt_gatt_client *client,
					uint16_t value_handle,
					uint8_t *value, uint16_t length,
					bt_gatt_client_callback_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy)
{
	struct write_op *op;
	uint8_t pdu[2 + length];

	if (!client)
		return false;

	op = new0(struct write_op, 1);
	if (!op)
		return false;

	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	put_le16(value_handle, pdu);
	memcpy(pdu + 2, value, length);

	if (!bt_att_send(client->att, BT_ATT_OP_WRITE_REQ, pdu, sizeof(pdu),
							write_cb, op,
							destroy_write_op)) {
		free(op);
		return false;
	}

	return true;
}

struct long_write_op {
	struct bt_gatt_client *client;
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
	bt_gatt_client_write_long_callback_t callback;
	void *user_data;
	bt_gatt_client_destroy_func_t destroy;
};

static struct long_write_op *long_write_op_ref(struct long_write_op *op)
{
	__sync_fetch_and_add(&op->ref_count, 1);

	return op;
}

static void long_write_op_unref(void *data)
{
	struct long_write_op *op = data;

	if (__sync_sub_and_fetch(&op->ref_count, 1))
		return;

	if (op->destroy)
		op->destroy(op->user_data);

	free(op->value);
	free(op);
}

static void prepare_write_cb(uint8_t opcode, const void *pdu, uint16_t length,
							void *user_data);
static void complete_write_long_op(struct long_write_op *op, bool success,
					uint8_t att_ecode, bool reliable_error);

static void handle_next_prep_write(struct long_write_op *op)
{
	bool success = true;
	uint8_t *pdu;

	pdu = malloc(op->cur_length + 4);
	if (!pdu) {
		success = false;
		goto done;
	}

	put_le16(op->value_handle, pdu);
	put_le16(op->offset + op->index, pdu + 2);
	memcpy(pdu + 4, op->value + op->index, op->cur_length);

	if (!bt_att_send(op->client->att, BT_ATT_OP_PREP_WRITE_REQ,
							pdu, op->cur_length + 4,
							prepare_write_cb,
							long_write_op_ref(op),
							long_write_op_unref)) {
		long_write_op_unref(op);
		success = false;
	}

	free(pdu);

	/* If so far successful, then the operation should continue.
	 * Otherwise, there was an error and the procedure should be
	 * completed.
	 */
	if (success)
		return;

done:
	complete_write_long_op(op, success, 0, false);
}

static void start_next_long_write(struct bt_gatt_client *client)
{
	struct long_write_op *op;

	if (queue_isempty(client->long_write_queue)) {
		client->in_long_write = false;
		return;
	}

	op = queue_pop_head(client->long_write_queue);
	if (!op)
		return;

	handle_next_prep_write(op);

	/* send_next_prep_write adds an extra ref. Unref here to clean up if
	 * necessary, since we also added a ref before pushing to the queue.
	 */
	long_write_op_unref(op);
}

static void execute_write_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct long_write_op *op = user_data;
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

	start_next_long_write(op->client);
}

static void complete_write_long_op(struct long_write_op *op, bool success,
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

	if (bt_att_send(op->client->att, BT_ATT_OP_EXEC_WRITE_REQ,
							&pdu, sizeof(pdu),
							execute_write_cb,
							long_write_op_ref(op),
							long_write_op_unref))
		return;

	long_write_op_unref(op);
	success = false;

	if (op->callback)
		op->callback(success, reliable_error, att_ecode, op->user_data);

	start_next_long_write(op->client);
}

static void prepare_write_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct long_write_op *op = user_data;
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

	/* If the last written length was greater than or equal to what can fit
	 * inside a PDU, then there is more data to send.
	 */
	if (op->cur_length >= bt_att_get_mtu(op->client->att) - 5) {
		op->index = next_index;
		op->cur_length = MIN(op->length - op->index,
					bt_att_get_mtu(op->client->att) - 5);
		handle_next_prep_write(op);
		return;
	}

done:
	complete_write_long_op(op, success, att_ecode, reliable_error);
}

bool bt_gatt_client_write_long_value(struct bt_gatt_client *client,
				bool reliable,
				uint16_t value_handle, uint16_t offset,
				uint8_t *value, uint16_t length,
				bt_gatt_client_write_long_callback_t callback,
				void *user_data,
				bt_gatt_client_destroy_func_t destroy)
{
	struct long_write_op *op;
	uint8_t *pdu;
	bool status;

	if (!client)
		return false;

	if ((size_t)(length + offset) > UINT16_MAX)
		return false;

	/* Don't allow writing a 0-length value using this procedure. The
	 * upper-layer should use bt_gatt_write_value for that instead.
	 */
	if (!length || !value)
		return false;

	op = new0(struct long_write_op, 1);
	if (!op)
		return false;

	op->value = malloc(length);
	if (!op->value) {
		free(op);
		return false;
	}

	memcpy(op->value, value, length);

	op->client = client;
	op->reliable = reliable;
	op->value_handle = value_handle;
	op->length = length;
	op->offset = offset;
	op->cur_length = MIN(length, bt_att_get_mtu(client->att) - 5);
	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	if (client->in_long_write) {
		queue_push_tail(client->long_write_queue,
						long_write_op_ref(op));
		return true;
	}

	pdu = malloc(op->cur_length + 4);
	if (!pdu) {
		free(op->value);
		free(op);
		return false;
	}

	put_le16(value_handle, pdu);
	put_le16(offset, pdu + 2);
	memcpy(pdu + 4, op->value, op->cur_length);

	status = bt_att_send(client->att, BT_ATT_OP_PREP_WRITE_REQ,
							pdu, op->cur_length + 4,
							prepare_write_cb,
							long_write_op_ref(op),
							long_write_op_unref);

	free(pdu);

	if (!status) {
		free(op->value);
		free(op);
		return false;
	}

	client->in_long_write = true;

	return true;
}
