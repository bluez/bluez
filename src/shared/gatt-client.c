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

#include <assert.h>
#include <limits.h>

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define UUID_BYTES (BT_GATT_UUID_SIZE * sizeof(uint8_t))

struct chrc_data {
	/* The public characteristic entry. */
	bt_gatt_characteristic_t chrc_external;

	/* The private entries. */
	uint16_t ccc_handle;
	int notify_count;  /* Reference count of registered notify callbacks */

	/* Internal non-const pointer to the descriptor array. We use this
	 * internally to modify/free the array, while we expose it externally
	 * using the const pointer "descs" field in bt_gatt_characteristic_t.
	 */
	bt_gatt_descriptor_t *descs;

	/* Pending calls to register_notify are queued here so that they can be
	 * processed after a write that modifies the CCC descriptor.
	 */
	struct queue *reg_notify_queue;
	unsigned int ccc_write_id;
};

struct service_list {
	bt_gatt_service_t service;
	struct chrc_data *chrcs;
	size_t num_chrcs;
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

	/* List of registered notification/indication callbacks */
	struct queue *notify_list;
	int next_reg_id;
	unsigned int notify_id, ind_id;
	bool in_notify;
	bool need_notify_cleanup;
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

static void notify_data_unref(void *data);

static void service_destroy_characteristics(struct service_list *service)
{
	unsigned int i;

	for (i = 0; i < service->num_chrcs; i++) {
		free(service->chrcs[i].descs);
		queue_destroy(service->chrcs[i].reg_notify_queue,
							notify_data_unref);
	}

	free(service->chrcs);
}

static void gatt_client_clear_services(struct bt_gatt_client *client)
{
	struct service_list *l, *tmp;

	l = client->svc_head;

	while (l) {
		service_destroy_characteristics(l);
		tmp = l;
		l = tmp->next;
		free(tmp);
	}

	client->svc_head = client->svc_tail = NULL;
}

struct discovery_op {
	struct bt_gatt_client *client;
	struct service_list *cur_service;
	struct chrc_data *cur_chrc;
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

static int uuid_cmp(const uint8_t uuid128[16], uint16_t uuid16)
{
	uint8_t rhs_uuid[16] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
		0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
	};

	put_be16(uuid16, rhs_uuid + 2);

	return memcmp(uuid128, rhs_uuid, sizeof(rhs_uuid));
}

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

		if (uuid_cmp(descs[i].uuid, GATT_CLIENT_CHARAC_CFG_UUID) == 0)
			op->cur_chrc->ccc_handle = descs[i].handle;

		i++;
	}

	op->cur_chrc->chrc_external.num_descs = desc_count;
	op->cur_chrc->descs = descs;
	op->cur_chrc->chrc_external.descs = descs;

	for (i = op->cur_chrc_index + 1; i < op->cur_service->num_chrcs; i++) {
		op->cur_chrc_index = i;
		op->cur_chrc++;
		desc_start = op->cur_chrc->chrc_external.value_handle + 1;
		if (desc_start > op->cur_chrc->chrc_external.end_handle)
			continue;

		if (bt_gatt_discover_descriptors(client->att, desc_start,
					op->cur_chrc->chrc_external.end_handle,
					discover_descs_cb, discovery_op_ref(op),
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
	struct chrc_data *chrcs;

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

	chrcs = new0(struct chrc_data, chrc_count);
	if (!chrcs) {
		success = false;
		goto done;
	}

	i = 0;
	while (bt_gatt_iter_next_characteristic(&iter,
					&chrcs[i].chrc_external.start_handle,
					&chrcs[i].chrc_external.end_handle,
					&chrcs[i].chrc_external.value_handle,
					&chrcs[i].chrc_external.properties,
					chrcs[i].chrc_external.uuid)) {
		uuid_to_string(chrcs[i].chrc_external.uuid, uuid_str);
		util_debug(client->debug_callback, client->debug_data,
				"start: 0x%04x, end: 0x%04x, value: 0x%04x, "
				"props: 0x%02x, uuid: %s",
				chrcs[i].chrc_external.start_handle,
				chrcs[i].chrc_external.end_handle,
				chrcs[i].chrc_external.value_handle,
				chrcs[i].chrc_external.properties,
				uuid_str);

		chrcs[i].reg_notify_queue = queue_new();
		if (!chrcs[i].reg_notify_queue) {
			success = false;
			goto done;
		}

		i++;
	}

	op->cur_service->chrcs = chrcs;
	op->cur_service->num_chrcs = chrc_count;

	for (i = 0; i < chrc_count; i++) {
		op->cur_chrc_index = i;
		op->cur_chrc = chrcs + i;
		desc_start = chrcs[i].chrc_external.value_handle + 1;
		if (desc_start > chrcs[i].chrc_external.end_handle)
			continue;

		if (bt_gatt_discover_descriptors(client->att, desc_start,
					chrcs[i].chrc_external.end_handle,
					discover_descs_cb, discovery_op_ref(op),
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

struct notify_data {
	struct bt_gatt_client *client;
	bool removed;
	unsigned int id;
	int ref_count;
	struct chrc_data *chrc;
	bt_gatt_client_notify_id_callback_t callback;
	bt_gatt_client_notify_callback_t notify;
	void *user_data;
	bt_gatt_client_destroy_func_t destroy;
};

static struct notify_data *notify_data_ref(struct notify_data *notify_data)
{
	__sync_fetch_and_add(&notify_data->ref_count, 1);

	return notify_data;
}

static void notify_data_unref(void *data)
{
	struct notify_data *notify_data = data;

	if (__sync_sub_and_fetch(&notify_data->ref_count, 1))
		return;

	if (notify_data->destroy)
		notify_data->destroy(notify_data->user_data);

	free(notify_data);
}

static bool match_notify_data_id(const void *a, const void *b)
{
	const struct notify_data *notify_data = a;
	unsigned int id = PTR_TO_UINT(b);

	return notify_data->id == id;
}

static bool match_notify_data_removed(const void *a, const void *b)
{
	const struct notify_data *notify_data = a;

	return notify_data->removed;
}

struct pdu_data {
	const void *pdu;
	uint16_t length;
};

static void complete_notify_request(void *data)
{
	struct notify_data *notify_data = data;

	/* Increment the per-characteristic ref count of notify handlers */
	__sync_fetch_and_add(&notify_data->chrc->notify_count, 1);

	/* Add the handler to the bt_gatt_client's general list */
	queue_push_tail(notify_data->client->notify_list,
						notify_data_ref(notify_data));

	/* Assign an ID to the handler and notify the caller that it was
	 * successfully registered.
	 */
	if (notify_data->client->next_reg_id < 1)
		notify_data->client->next_reg_id = 1;

	notify_data->id = notify_data->client->next_reg_id++;
	notify_data->callback(notify_data->id, 0, notify_data->user_data);
}

static bool notify_data_write_ccc(struct notify_data *notify_data, bool enable,
						bt_att_response_func_t callback)
{
	uint8_t pdu[4];

	assert(notify_data->chrc->ccc_handle);
	memset(pdu, 0, sizeof(pdu));
	put_le16(notify_data->chrc->ccc_handle, pdu);

	if (enable) {
		/* Try to enable notifications and/or indications based on
		 * whatever the characteristic supports.
		 */
		if (notify_data->chrc->chrc_external.properties &
						BT_GATT_CHRC_PROP_NOTIFY)
			pdu[2] = 0x01;

		if (notify_data->chrc->chrc_external.properties &
						BT_GATT_CHRC_PROP_INDICATE)
			pdu[2] |= 0x02;

		if (!pdu[2])
			return false;
	}

	notify_data->chrc->ccc_write_id = bt_att_send(notify_data->client->att,
						BT_ATT_OP_WRITE_REQ,
						pdu, sizeof(pdu),
						callback,
						notify_data, notify_data_unref);

	return !!notify_data->chrc->ccc_write_id;
}

static uint8_t process_error(const void *pdu, uint16_t length)
{
	if (!pdu || length != 4)
		return 0;

	return ((uint8_t *) pdu)[3];
}

static void enable_ccc_callback(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct notify_data *notify_data = user_data;
	uint16_t att_ecode;

	assert(!notify_data->chrc->notify_count);
	assert(notify_data->chrc->ccc_write_id);

	notify_data->chrc->ccc_write_id = 0;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		att_ecode = process_error(pdu, length);

		/* Failed to enable. Complete the current request and move on to
		 * the next one in the queue. If there was an error sending the
		 * write request, then just move on to the next queued entry.
		 */
		notify_data->callback(0, att_ecode, notify_data->user_data);

		while ((notify_data = queue_pop_head(
					notify_data->chrc->reg_notify_queue))) {

			if (notify_data_write_ccc(notify_data, true,
							enable_ccc_callback))
				return;
		}

		return;
	}

	/* Success! Report success for all remaining requests. */
	complete_notify_request(notify_data);
	queue_remove_all(notify_data->chrc->reg_notify_queue, NULL, NULL,
						complete_notify_request);
}

static void disable_ccc_callback(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct notify_data *notify_data = user_data;
	struct notify_data *next_data;

	assert(!notify_data->chrc->notify_count);
	assert(notify_data->chrc->ccc_write_id);

	notify_data->chrc->ccc_write_id = 0;

	/* This is a best effort procedure, so ignore errors and process any
	 * queued requests.
	 */
	while (1) {
		next_data = queue_pop_head(notify_data->chrc->reg_notify_queue);
		if (!next_data || notify_data_write_ccc(notify_data, true,
							enable_ccc_callback))
			return;
	}
}

static void complete_unregister_notify(void *data)
{
	struct notify_data *notify_data = data;

	if (__sync_sub_and_fetch(&notify_data->chrc->notify_count, 1)) {
		notify_data_unref(notify_data);
		return;
	}

	notify_data_write_ccc(notify_data, false, disable_ccc_callback);
}

static void notify_handler(void *data, void *user_data)
{
	struct notify_data *notify_data = data;
	struct pdu_data *pdu_data = user_data;
	uint16_t value_handle;
	const uint8_t *value = NULL;

	if (notify_data->removed)
		return;

	value_handle = get_le16(pdu_data->pdu);

	if (notify_data->chrc->chrc_external.value_handle != value_handle)
		return;

	if (pdu_data->length > 2)
		value = pdu_data->pdu + 2;

	if (notify_data->notify)
		notify_data->notify(value_handle, value, pdu_data->length - 2,
							notify_data->user_data);
}

static void notify_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct bt_gatt_client *client = user_data;
	struct pdu_data pdu_data;

	bt_gatt_client_ref(client);

	client->in_notify = true;

	memset(&pdu_data, 0, sizeof(pdu_data));
	pdu_data.pdu = pdu;
	pdu_data.length = length;

	queue_foreach(client->notify_list, notify_handler, &pdu_data);

	client->in_notify = false;

	if (client->need_notify_cleanup) {
		queue_remove_all(client->notify_list, match_notify_data_removed,
					NULL, complete_unregister_notify);
		client->need_notify_cleanup = false;
	}

	if (opcode == BT_ATT_OP_HANDLE_VAL_IND)
		bt_att_send(client->att, BT_ATT_OP_HANDLE_VAL_CONF, NULL, 0,
							NULL, NULL, NULL);

	bt_gatt_client_unref(client);
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

	client->notify_list = queue_new();
	if (!client->notify_list) {
		queue_destroy(client->long_write_queue, NULL);
		free(client);
		return NULL;
	}

	client->notify_id = bt_att_register(att, BT_ATT_OP_HANDLE_VAL_NOT,
						notify_cb, client, NULL);
	if (!client->notify_id) {
		queue_destroy(client->long_write_queue, NULL);
		free(client);
		return NULL;
	}

	client->ind_id = bt_att_register(att, BT_ATT_OP_HANDLE_VAL_IND,
						notify_cb, client, NULL);
	if (!client->ind_id) {
		bt_att_unregister(att, client->notify_id);
		queue_destroy(client->long_write_queue, NULL);
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

	bt_att_unregister(client->att, client->notify_id);
	bt_att_unregister(client->att, client->ind_id);

	queue_destroy(client->long_write_queue, long_write_op_unref);
	queue_destroy(client->notify_list, notify_data_unref);

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
					const bt_gatt_service_t **service)
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

	*service = &l->service;
	iter->ptr = l;

	return true;
}

bool bt_gatt_service_iter_next_by_handle(struct bt_gatt_service_iter *iter,
					uint16_t start_handle,
					const bt_gatt_service_t **service)
{
	while (bt_gatt_service_iter_next(iter, service)) {
		if ((*service)->start_handle == start_handle)
			return true;
	}

	return false;
}

bool bt_gatt_service_iter_next_by_uuid(struct bt_gatt_service_iter *iter,
					const uint8_t uuid[BT_GATT_UUID_SIZE],
					const bt_gatt_service_t **service)
{
	while (bt_gatt_service_iter_next(iter, service)) {
		if (memcmp((*service)->uuid, uuid, UUID_BYTES) == 0)
			return true;
	}

	return false;
}

bool bt_gatt_characteristic_iter_init(struct bt_gatt_characteristic_iter *iter,
					const bt_gatt_service_t *service)
{
	if (!iter || !service)
		return false;

	memset(iter, 0, sizeof(*iter));
	iter->service = (struct service_list *) service;

	return true;
}

bool bt_gatt_characteristic_iter_next(struct bt_gatt_characteristic_iter *iter,
					const bt_gatt_characteristic_t **chrc)
{
	struct service_list *service;

	if (!iter || !chrc)
		return false;

	service = iter->service;

	if (iter->pos >= service->num_chrcs)
		return false;

	*chrc = &service->chrcs[iter->pos++].chrc_external;

	return true;
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

bool bt_gatt_client_register_notify(struct bt_gatt_client *client,
				uint16_t chrc_value_handle,
				bt_gatt_client_notify_id_callback_t callback,
				bt_gatt_client_notify_callback_t notify,
				void *user_data,
				bt_gatt_client_destroy_func_t destroy)
{
	struct notify_data *notify_data;
	struct service_list *svc_data = NULL;
	struct chrc_data *chrc = NULL;
	struct bt_gatt_service_iter iter;
	const bt_gatt_service_t *service;
	size_t i;

	if (!client || !chrc_value_handle || !callback)
		return false;

	if (!bt_gatt_client_is_ready(client))
		return false;

	/* Check that chrc_value_handle belongs to a known characteristic */
	if (!bt_gatt_service_iter_init(&iter, client))
		return false;

	while (bt_gatt_service_iter_next(&iter, &service)) {
		if (chrc_value_handle >= service->start_handle &&
				chrc_value_handle <= service->end_handle) {
			svc_data = (struct service_list *) service;
			break;
		}
	}

	if (!svc_data)
		return false;

	for (i = 0; i < svc_data->num_chrcs; i++) {
		if (svc_data->chrcs[i].chrc_external.value_handle ==
							chrc_value_handle) {
			chrc = svc_data->chrcs + i;
			break;
		}
	}

	/* Check that the characteristic supports notifications/indications */
	if (!chrc || !chrc->ccc_handle || chrc->notify_count == INT_MAX)
		return false;

	notify_data = new0(struct notify_data, 1);
	if (!notify_data)
		return false;

	notify_data->client = client;
	notify_data->ref_count = 1;
	notify_data->chrc = chrc;
	notify_data->callback = callback;
	notify_data->notify = notify;
	notify_data->user_data = user_data;
	notify_data->destroy = destroy;

	/* If a write to the CCC descriptor is in progress, then queue this
	 * request.
	 */
	if (chrc->ccc_write_id) {
		queue_push_tail(chrc->reg_notify_queue, notify_data);
		return true;
	}

	/* If the ref count is not zero, then notifications are already enabled.
	 */
	if (chrc->notify_count > 0) {
		complete_notify_request(notify_data);
		return true;
	}

	/* Write to the CCC descriptor */
	if (!notify_data_write_ccc(notify_data, true, enable_ccc_callback)) {
		free(notify_data);
		return false;
	}

	return true;
}

bool bt_gatt_client_unregister_notify(struct bt_gatt_client *client,
							unsigned int id)
{
	struct notify_data *notify_data;

	if (!client || !id)
		return false;

	notify_data = queue_find(client->notify_list, match_notify_data_id,
							UINT_TO_PTR(id));
	if (!notify_data || notify_data->removed)
		return false;

	assert(notify_data->chrc->notify_count > 0);
	assert(!notify_data->chrc->ccc_write_id);

	if (!client->in_notify) {
		queue_remove(client->notify_list, notify_data);
		complete_unregister_notify(notify_data);
		return true;
	}

	notify_data->removed = true;
	client->need_notify_cleanup = true;
	return true;
}
