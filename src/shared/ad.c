/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2015  Google Inc.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */

#include "src/shared/ad.h"

#include "src/shared/queue.h"
#include "src/shared/util.h"

#define MAX_ADV_DATA_LEN 31

struct bt_ad {
	int ref_count;
	struct queue *service_uuids;
	struct queue *manufacturer_data;
	struct queue *solicit_uuids;
	struct queue *service_data;
};

struct uuid_data {
	bt_uuid_t uuid;
	uint8_t *data;
	size_t len;
};

struct manufacturer_data {
	uint16_t manufacturer_id;
	uint8_t *data;
	size_t len;
};

struct bt_ad *bt_ad_new(void)
{
	struct bt_ad *ad;

	ad = new0(struct bt_ad, 1);
	if (!ad)
		return NULL;

	ad->service_uuids = queue_new();
	if (!ad->service_uuids)
		goto fail;

	ad->manufacturer_data = queue_new();
	if (!ad->manufacturer_data)
		goto fail;

	ad->solicit_uuids = queue_new();
	if (!ad->solicit_uuids)
		goto fail;

	ad->service_data = queue_new();
	if (!ad->service_data)
		goto fail;

	return bt_ad_ref(ad);

fail:
	queue_destroy(ad->service_uuids, NULL);
	queue_destroy(ad->manufacturer_data, NULL);
	queue_destroy(ad->solicit_uuids, NULL);
	queue_destroy(ad->service_data, NULL);

	free(ad);

	return NULL;
}

struct bt_ad *bt_ad_ref(struct bt_ad *ad)
{
	if (!ad)
		return NULL;

	ad->ref_count++;
	return ad;
}

static void uuid_destroy(void *data)
{
	struct uuid_data *uuid_data = data;

	free(uuid_data->data);
	free(uuid_data);
}

static bool uuid_data_match(const void *data, const void *elem)
{
	const struct uuid_data *uuid_data = elem;
	const bt_uuid_t *uuid = data;

	return !bt_uuid_cmp(&uuid_data->uuid, uuid);
}

static void manuf_destroy(void *data)
{
	struct manufacturer_data *manuf = data;

	free(manuf->data);
	free(manuf);
}

static bool manuf_match(const void *data, const void *elem)
{
	const struct manufacturer_data *manuf = elem;
	uint16_t manuf_id = PTR_TO_UINT(elem);

	return manuf->manufacturer_id == manuf_id;
}

void bt_ad_unref(struct bt_ad *ad)
{
	if (!ad)
		return;

	if (__sync_sub_and_fetch(&ad->ref_count, 1))
		return;

	queue_destroy(ad->service_uuids, free);

	queue_destroy(ad->manufacturer_data, manuf_destroy);

	queue_destroy(ad->solicit_uuids, free);

	queue_destroy(ad->service_data, uuid_destroy);

	free(ad);
}

uint8_t *bt_ad_generate(struct bt_ad *ad, size_t *length)
{
	/* TODO: implement */
	return NULL;
}

static bool queue_add_uuid(struct queue *queue, const bt_uuid_t *uuid)
{
	bt_uuid_t *new_uuid;

	if (!queue)
		return false;

	new_uuid = new0(bt_uuid_t, 1);
	if (!new_uuid)
		return false;

	bt_uuid_to_uuid128(uuid, new_uuid);

	if (queue_push_tail(queue, new_uuid))
		return true;

	free(new_uuid);

	return false;
}

static bool uuid_match(const void *data, const void *elem)
{
	const bt_uuid_t *match_uuid = data;
	const bt_uuid_t *uuid = elem;

	return bt_uuid_cmp(match_uuid, uuid);
}

static bool queue_remove_uuid(struct queue *queue, bt_uuid_t *uuid)
{
	bt_uuid_t *removed;

	if (!queue || !uuid)
		return false;

	removed = queue_remove_if(queue, uuid_match, uuid);

	if (removed) {
		free(removed);
		return true;
	}

	return false;
}

bool bt_ad_add_service_uuid(struct bt_ad *ad, const bt_uuid_t *uuid)
{
	if (!ad)
		return false;

	return queue_add_uuid(ad->service_uuids, uuid);
}

bool bt_ad_remove_service_uuid(struct bt_ad *ad, bt_uuid_t *uuid)
{
	if (!ad)
		return false;

	return queue_remove_uuid(ad->service_uuids, uuid);
}

void bt_ad_clear_service_uuid(struct bt_ad *ad)
{
	if (!ad)
		return;

	queue_remove_all(ad->service_uuids, NULL, NULL, free);
}

bool bt_ad_add_manufacturer_data(struct bt_ad *ad, uint16_t manufacturer_id,
							void *data, size_t len)
{
	struct manufacturer_data *new_data;

	if (!ad)
		return false;

	if (len > (MAX_ADV_DATA_LEN - 2 - sizeof(uint16_t)))
		return false;

	new_data = new0(struct manufacturer_data, 1);
	if (!new_data)
		return false;

	new_data->manufacturer_id = manufacturer_id;

	new_data->data = malloc(len);
	if (!new_data->data) {
		free(new_data);
		return false;
	}

	memcpy(new_data->data, data, len);

	new_data->len = len;

	if (queue_push_tail(ad->manufacturer_data, new_data))
		return true;

	manuf_destroy(new_data);

	return false;
}

bool bt_ad_remove_manufacturer_data(struct bt_ad *ad, uint16_t manufacturer_id)
{
	struct manufacturer_data *data;

	if (!ad)
		return false;

	data = queue_remove_if(ad->manufacturer_data, manuf_match,
						UINT_TO_PTR(manufacturer_id));

	if (!data)
		return false;

	manuf_destroy(data);

	return true;
}

void bt_ad_clear_manufacturer_data(struct bt_ad *ad)
{
	if (!ad)
		return;

	queue_remove_all(ad->manufacturer_data, NULL, NULL, manuf_destroy);
}

bool bt_ad_add_solicit_uuid(struct bt_ad *ad, const bt_uuid_t *uuid)
{
	if (!ad)
		return false;

	return queue_add_uuid(ad->solicit_uuids, uuid);
}

bool bt_ad_remove_solicit_uuid(struct bt_ad *ad, bt_uuid_t *uuid)
{
	if (!ad)
		return false;

	return queue_remove_uuid(ad->solicit_uuids, uuid);
}

void bt_ad_clear_solicit_uuid(struct bt_ad *ad)
{
	if (!ad)
		return;

	queue_remove_all(ad->solicit_uuids, NULL, NULL, free);
}

bool bt_ad_add_service_data(struct bt_ad *ad, const bt_uuid_t *uuid, void *data,
								size_t len)
{
	struct uuid_data *new_data;

	if (!ad)
		return false;

	if (len > (MAX_ADV_DATA_LEN - 2 - (size_t)bt_uuid_len(uuid)))
		return false;

	new_data = new0(struct uuid_data, 1);
	if (!new_data)
		return false;

	bt_uuid_to_uuid128(uuid, &new_data->uuid);

	new_data->data = malloc(len);
	if (!new_data->data) {
		free(new_data);
		return false;
	}

	memcpy(new_data->data, data, len);

	new_data->len = len;

	if (queue_push_tail(ad->service_data, new_data))
		return true;

	uuid_destroy(new_data);

	return false;
}

bool bt_ad_remove_service_data(struct bt_ad *ad, bt_uuid_t *uuid)
{
	struct uuid_data *data;

	if (!ad)
		return false;

	data = queue_remove_if(ad->service_data, uuid_data_match, uuid);

	if (!data)
		return false;

	uuid_destroy(data);

	return true;
}

void bt_ad_clear_service_data(struct bt_ad *ad)
{
	if (!ad)
		return;

	queue_remove_all(ad->service_data, NULL, NULL, uuid_destroy);
}
