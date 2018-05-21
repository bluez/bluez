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

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"
#include "lib/sdp.h"

#include "adapter.h"
#include "dbus-common.h"
#include "error.h"
#include "log.h"
#include "eir.h"
#include "src/shared/ad.h"
#include "src/shared/mgmt.h"
#include "src/shared/queue.h"
#include "src/shared/util.h"
#include "advertising.h"

#define LE_ADVERTISING_MGR_IFACE "org.bluez.LEAdvertisingManager1"
#define LE_ADVERTISEMENT_IFACE "org.bluez.LEAdvertisement1"

struct btd_adv_manager {
	struct btd_adapter *adapter;
	struct queue *clients;
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	uint8_t max_adv_len;
	uint8_t max_scan_rsp_len;
	uint8_t max_ads;
	uint32_t supported_flags;
	unsigned int instance_bitmap;
};

#define AD_TYPE_BROADCAST 0
#define AD_TYPE_PERIPHERAL 1

struct btd_adv_client {
	struct btd_adv_manager *manager;
	char *owner;
	char *path;
	char *name;
	uint16_t appearance;
	uint16_t duration;
	uint16_t timeout;
	uint16_t discoverable_to;
	unsigned int to_id;
	unsigned int disc_to_id;
	GDBusClient *client;
	GDBusProxy *proxy;
	DBusMessage *reg;
	uint8_t type; /* Advertising type */
	uint32_t flags;
	struct bt_ad *data;
	struct bt_ad *scan;
	uint8_t instance;
};

struct dbus_obj_match {
	const char *owner;
	const char *path;
};

static bool match_client(const void *a, const void *b)
{
	const struct btd_adv_client *client = a;
	const struct dbus_obj_match *match = b;

	if (match->owner && g_strcmp0(client->owner, match->owner))
		return false;

	if (match->path && g_strcmp0(client->path, match->path))
		return false;

	return true;
}

static void client_free(void *data)
{
	struct btd_adv_client *client = data;

	if (client->to_id > 0)
		g_source_remove(client->to_id);

	if (client->disc_to_id > 0)
		g_source_remove(client->disc_to_id);

	if (client->client) {
		g_dbus_client_set_disconnect_watch(client->client, NULL, NULL);
		g_dbus_client_unref(client->client);
	}

	if (client->instance)
		util_clear_uid(&client->manager->instance_bitmap,
						client->instance);

	bt_ad_unref(client->data);
	bt_ad_unref(client->scan);

	g_dbus_proxy_unref(client->proxy);

	if (client->owner)
		g_free(client->owner);

	if (client->path)
		g_free(client->path);

	free(client->name);
	free(client);
}

static gboolean client_free_idle_cb(void *data)
{
	client_free(data);

	return FALSE;
}

static void client_release(void *data)
{
	struct btd_adv_client *client = data;

	DBG("Releasing advertisement %s, %s", client->owner, client->path);

	g_dbus_proxy_method_call(client->proxy, "Release", NULL, NULL, NULL,
									NULL);
}

static void client_destroy(void *data)
{
	client_release(data);
	client_free(data);
}

static void remove_advertising(struct btd_adv_manager *manager,
						uint8_t instance)
{
	struct mgmt_cp_remove_advertising cp;

	if (instance)
		DBG("instance %u", instance);
	else
		DBG("all instances");

	cp.instance = instance;

	mgmt_send(manager->mgmt, MGMT_OP_REMOVE_ADVERTISING,
			manager->mgmt_index, sizeof(cp), &cp, NULL, NULL, NULL);
}

static void client_remove(void *data)
{
	struct btd_adv_client *client = data;
	struct mgmt_cp_remove_advertising cp;

	g_dbus_client_set_disconnect_watch(client->client, NULL, NULL);

	cp.instance = client->instance;

	mgmt_send(client->manager->mgmt, MGMT_OP_REMOVE_ADVERTISING,
			client->manager->mgmt_index, sizeof(cp), &cp,
			NULL, NULL, NULL);

	queue_remove(client->manager->clients, client);

	g_idle_add(client_free_idle_cb, client);

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
				adapter_get_path(client->manager->adapter),
				LE_ADVERTISING_MGR_IFACE, "SupportedInstances");

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
				adapter_get_path(client->manager->adapter),
				LE_ADVERTISING_MGR_IFACE, "ActiveInstances");
}

static void client_disconnect_cb(DBusConnection *conn, void *user_data)
{
	DBG("Client disconnected");

	client_remove(user_data);
}

static bool parse_type(DBusMessageIter *iter, struct btd_adv_client *client)
{
	const char *msg_type;

	if (!iter)
		return true;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING)
		return false;

	dbus_message_iter_get_basic(iter, &msg_type);

	if (!g_strcmp0(msg_type, "broadcast")) {
		client->type = AD_TYPE_BROADCAST;
		return true;
	}

	if (!g_strcmp0(msg_type, "peripheral")) {
		client->type = AD_TYPE_PERIPHERAL;
		return true;
	}

	return false;
}

static bool parse_service_uuids(DBusMessageIter *iter,
					struct btd_adv_client *client)
{
	DBusMessageIter ariter;

	if (!iter) {
		bt_ad_clear_service_uuid(client->data);
		return true;
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return false;

	dbus_message_iter_recurse(iter, &ariter);

	bt_ad_clear_service_uuid(client->data);

	while (dbus_message_iter_get_arg_type(&ariter) == DBUS_TYPE_STRING) {
		const char *uuid_str;
		bt_uuid_t uuid;

		dbus_message_iter_get_basic(&ariter, &uuid_str);

		DBG("Adding ServiceUUID: %s", uuid_str);

		if (bt_string_to_uuid(&uuid, uuid_str) < 0)
			goto fail;

		if (!bt_ad_add_service_uuid(client->data, &uuid))
			goto fail;

		dbus_message_iter_next(&ariter);
	}

	return true;

fail:
	bt_ad_clear_service_uuid(client->data);
	return false;
}

static bool parse_solicit_uuids(DBusMessageIter *iter,
					struct btd_adv_client *client)
{
	DBusMessageIter ariter;

	if (!iter) {
		bt_ad_clear_solicit_uuid(client->data);
		return true;
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return false;

	dbus_message_iter_recurse(iter, &ariter);

	bt_ad_clear_solicit_uuid(client->data);

	while (dbus_message_iter_get_arg_type(&ariter) == DBUS_TYPE_STRING) {
		const char *uuid_str;
		bt_uuid_t uuid;

		dbus_message_iter_get_basic(&ariter, &uuid_str);

		DBG("Adding SolicitUUID: %s", uuid_str);

		if (bt_string_to_uuid(&uuid, uuid_str) < 0)
			goto fail;

		if (!bt_ad_add_solicit_uuid(client->data, &uuid))
			goto fail;

		dbus_message_iter_next(&ariter);
	}

	return true;

fail:
	bt_ad_clear_solicit_uuid(client->data);
	return false;
}

static bool parse_manufacturer_data(DBusMessageIter *iter,
					struct btd_adv_client *client)
{
	DBusMessageIter entries;

	if (!iter) {
		bt_ad_clear_manufacturer_data(client->data);
		return true;
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return false;

	dbus_message_iter_recurse(iter, &entries);

	bt_ad_clear_manufacturer_data(client->data);

	while (dbus_message_iter_get_arg_type(&entries)
						== DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter value, entry, array;
		uint16_t manuf_id;
		uint8_t *manuf_data;
		int len;

		dbus_message_iter_recurse(&entries, &entry);
		dbus_message_iter_get_basic(&entry, &manuf_id);

		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			goto fail;

		dbus_message_iter_recurse(&entry, &value);

		if (dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_ARRAY)
			goto fail;

		dbus_message_iter_recurse(&value, &array);

		if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_BYTE)
			goto fail;

		dbus_message_iter_get_fixed_array(&array, &manuf_data, &len);

		DBG("Adding ManufacturerData for %04x", manuf_id);

		if (!bt_ad_add_manufacturer_data(client->data, manuf_id,
							manuf_data, len))
			goto fail;

		dbus_message_iter_next(&entries);
	}

	return true;

fail:
	bt_ad_clear_manufacturer_data(client->data);
	return false;
}

static bool parse_service_data(DBusMessageIter *iter,
					struct btd_adv_client *client)
{
	DBusMessageIter entries;

	if (!iter) {
		bt_ad_clear_service_data(client->data);
		return true;
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return false;

	dbus_message_iter_recurse(iter, &entries);

	bt_ad_clear_service_data(client->data);

	while (dbus_message_iter_get_arg_type(&entries)
						== DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter value, entry, array;
		const char *uuid_str;
		bt_uuid_t uuid;
		uint8_t *service_data;
		int len;

		dbus_message_iter_recurse(&entries, &entry);
		dbus_message_iter_get_basic(&entry, &uuid_str);

		if (bt_string_to_uuid(&uuid, uuid_str) < 0)
			goto fail;

		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			goto fail;

		dbus_message_iter_recurse(&entry, &value);

		if (dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_ARRAY)
			goto fail;

		dbus_message_iter_recurse(&value, &array);

		if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_BYTE)
			goto fail;

		dbus_message_iter_get_fixed_array(&array, &service_data, &len);

		DBG("Adding ServiceData for %s", uuid_str);

		if (!bt_ad_add_service_data(client->data, &uuid, service_data,
									len))
			goto fail;

		dbus_message_iter_next(&entries);
	}

	return true;

fail:
	bt_ad_clear_service_data(client->data);
	return false;
}

static struct adv_include {
	uint8_t flag;
	const char *name;
} includes[] = {
	{ MGMT_ADV_FLAG_TX_POWER, "tx-power" },
	{ MGMT_ADV_FLAG_APPEARANCE, "appearance" },
	{ MGMT_ADV_FLAG_LOCAL_NAME, "local-name" },
	{ },
};

static bool parse_includes(DBusMessageIter *iter,
					struct btd_adv_client *client)
{
	DBusMessageIter entries;

	if (!iter) {
		client->flags = 0;
		return true;
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return false;

	dbus_message_iter_recurse(iter, &entries);

	/* Reset flags before parsing */
	client->flags = 0;

	while (dbus_message_iter_get_arg_type(&entries) == DBUS_TYPE_STRING) {
		const char *str;
		struct adv_include *inc;

		dbus_message_iter_get_basic(&entries, &str);

		for (inc = includes; inc && inc->name; inc++) {
			if (strcmp(str, inc->name))
				continue;

			if (!(client->manager->supported_flags & inc->flag))
				continue;

			DBG("Including Feature: %s", str);

			client->flags |= inc->flag;
		}

		dbus_message_iter_next(&entries);
	}

	return true;
}

static bool parse_local_name(DBusMessageIter *iter,
					struct btd_adv_client *client)
{
	const char *name;

	if (!iter) {
		free(client->name);
		client->name = NULL;
		return true;
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING)
		return false;

	if (client->flags & MGMT_ADV_FLAG_LOCAL_NAME) {
		error("Local name already included");
		return false;
	}

	dbus_message_iter_get_basic(iter, &name);

	free(client->name);
	client->name = strdup(name);

	return true;
}

static bool parse_appearance(DBusMessageIter *iter,
					struct btd_adv_client *client)
{
	if (!iter) {
		client->appearance = 0;
		return true;
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_UINT16)
		return false;

	if (client->flags & MGMT_ADV_FLAG_APPEARANCE) {
		error("Appearance already included");
		return false;
	}

	dbus_message_iter_get_basic(iter, &client->appearance);

	return true;
}

static bool parse_duration(DBusMessageIter *iter,
					struct btd_adv_client *client)
{
	if (!iter) {
		client->duration = 0;
		return true;
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_UINT16)
		return false;

	dbus_message_iter_get_basic(iter, &client->duration);

	return true;
}

static gboolean client_timeout(void *user_data)
{
	struct btd_adv_client *client = user_data;

	DBG("");

	client->to_id = 0;

	client_release(client);
	client_remove(client);

	return FALSE;
}

static bool parse_timeout(DBusMessageIter *iter,
					struct btd_adv_client *client)
{
	if (!iter) {
		client->timeout = 0;
		g_source_remove(client->to_id);
		client->to_id = 0;
		return true;
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_UINT16)
		return false;

	dbus_message_iter_get_basic(iter, &client->timeout);

	if (client->to_id)
		g_source_remove(client->to_id);

	client->to_id = g_timeout_add_seconds(client->timeout, client_timeout,
								client);

	return true;
}

static bool parse_data(DBusMessageIter *iter, struct btd_adv_client *client)
{
	DBusMessageIter entries;

	if (!iter) {
		bt_ad_clear_data(client->data);
		return true;
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return false;

	dbus_message_iter_recurse(iter, &entries);

	bt_ad_clear_data(client->data);

	while (dbus_message_iter_get_arg_type(&entries)
						== DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter value, entry, array;
		uint8_t type;
		uint8_t *data;
		int len;

		dbus_message_iter_recurse(&entries, &entry);
		dbus_message_iter_get_basic(&entry, &type);

		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			goto fail;

		dbus_message_iter_recurse(&entry, &value);

		if (dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_ARRAY)
			goto fail;

		dbus_message_iter_recurse(&value, &array);

		if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_BYTE)
			goto fail;

		dbus_message_iter_get_fixed_array(&array, &data, &len);

		DBG("Adding Data for type 0x%02x len %u", type, len);

		if (!bt_ad_add_data(client->data, type, data, len))
			goto fail;

		dbus_message_iter_next(&entries);
	}

	return true;

fail:
	bt_ad_clear_data(client->data);
	return false;
}

static bool set_flags(struct btd_adv_client *client, uint8_t flags)
{
	if (!flags) {
		bt_ad_clear_flags(client->data);
		return true;
	}

	/* Set BR/EDR Not Supported for LE only */
	if (!btd_adapter_get_bredr(client->manager->adapter))
		flags |= 0x04;

	if (!bt_ad_add_flags(client->data, &flags, 1))
		return false;

	return true;
}

static bool parse_discoverable(DBusMessageIter *iter,
				struct btd_adv_client *client)
{
	uint8_t flags;
	dbus_bool_t discoverable;

	if (!iter) {
		bt_ad_clear_flags(client->data);
		return true;
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_BOOLEAN)
		return false;

	dbus_message_iter_get_basic(iter, &discoverable);

	if (discoverable)
		flags = 0x02;
	else
		flags = 0x00;

	if (!set_flags(client , flags))
		goto fail;

	DBG("Adding Flags 0x%02x", flags);

	return true;

fail:
	bt_ad_clear_flags(client->data);
	return false;
}

static size_t calc_max_adv_len(struct btd_adv_client *client, uint32_t flags)
{
	size_t max = client->manager->max_adv_len;

	/*
	 * Flags which reduce the amount of space available for advertising.
	 * See doc/mgmt-api.txt
	 */
	if (flags & MGMT_ADV_FLAG_TX_POWER)
		max -= 3;

	if (flags & (MGMT_ADV_FLAG_DISCOV | MGMT_ADV_FLAG_LIMITED_DISCOV |
						MGMT_ADV_FLAG_MANAGED_FLAGS))
		max -= 3;

	if (flags & MGMT_ADV_FLAG_APPEARANCE)
		max -= 4;

	return max;
}

static uint8_t *generate_adv_data(struct btd_adv_client *client,
						uint32_t *flags, size_t *len)
{
	if ((*flags & MGMT_ADV_FLAG_APPEARANCE) ||
					client->appearance != UINT16_MAX) {
		uint16_t appearance;

		appearance = client->appearance;
		if (appearance == UINT16_MAX)
			/* TODO: Get the appearance from the adaptor once
			 * supported.
			 */
			appearance = 0x000;

		bt_ad_add_appearance(client->data, appearance);
	}

	return bt_ad_generate(client->data, len);
}

static uint8_t *generate_scan_rsp(struct btd_adv_client *client,
						uint32_t *flags, size_t *len)
{
	struct btd_adv_manager *manager = client->manager;
	const char *name;

	if (!(*flags & MGMT_ADV_FLAG_LOCAL_NAME) && !client->name) {
		*len = 0;
		return NULL;
	}

	*flags &= ~MGMT_ADV_FLAG_LOCAL_NAME;

	name = client->name;
	if (!name)
		name = btd_adapter_get_name(manager->adapter);

	bt_ad_add_name(client->scan, name);

	return bt_ad_generate(client->scan, len);
}

static int refresh_adv(struct btd_adv_client *client, mgmt_request_func_t func)
{
	struct mgmt_cp_add_advertising *cp;
	uint8_t param_len;
	uint8_t *adv_data;
	size_t adv_data_len;
	uint8_t *scan_rsp;
	size_t scan_rsp_len = -1;
	uint32_t flags = 0;

	DBG("Refreshing advertisement: %s", client->path);

	if (client->type == AD_TYPE_PERIPHERAL) {
		flags = MGMT_ADV_FLAG_CONNECTABLE;

		if (btd_adapter_get_discoverable(client->manager->adapter) &&
				!(bt_ad_has_flags(client->data)))
			flags |= MGMT_ADV_FLAG_DISCOV;
	}

	flags |= client->flags;

	adv_data = generate_adv_data(client, &flags, &adv_data_len);
	if (!adv_data || (adv_data_len > calc_max_adv_len(client, flags))) {
		error("Advertising data too long or couldn't be generated.");
		return -EINVAL;
	}

	scan_rsp = generate_scan_rsp(client, &flags, &scan_rsp_len);
	if (!scan_rsp && scan_rsp_len) {
		error("Scan data couldn't be generated.");
		free(adv_data);
		return -EINVAL;
	}

	param_len = sizeof(struct mgmt_cp_add_advertising) + adv_data_len +
							scan_rsp_len;

	cp = malloc0(param_len);
	if (!cp) {
		error("Couldn't allocate for MGMT!");
		free(adv_data);
		free(scan_rsp);
		return -ENOMEM;
	}

	cp->flags = htobl(flags);
	cp->instance = client->instance;
	cp->duration = client->duration;
	cp->adv_data_len = adv_data_len;
	cp->scan_rsp_len = scan_rsp_len;
	memcpy(cp->data, adv_data, adv_data_len);
	memcpy(cp->data + adv_data_len, scan_rsp, scan_rsp_len);

	free(adv_data);
	free(scan_rsp);

	if (!mgmt_send(client->manager->mgmt, MGMT_OP_ADD_ADVERTISING,
				client->manager->mgmt_index, param_len, cp,
				func, client, NULL)) {
		error("Failed to add Advertising Data");
		free(cp);
		return -EINVAL;
	}

	free(cp);

	return 0;
}

static gboolean client_discoverable_timeout(void *user_data)
{
	struct btd_adv_client *client = user_data;

	DBG("");

	client->disc_to_id = 0;

	bt_ad_clear_flags(client->data);

	refresh_adv(client, NULL);

	return FALSE;
}

static bool parse_discoverable_timeout(DBusMessageIter *iter,
					struct btd_adv_client *client)
{
	if (!iter) {
		client->discoverable_to = 0;
		g_source_remove(client->disc_to_id);
		client->disc_to_id = 0;
		return true;
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_UINT16)
		return false;

	dbus_message_iter_get_basic(iter, &client->discoverable_to);

	if (client->disc_to_id)
		g_source_remove(client->disc_to_id);

	client->disc_to_id = g_timeout_add_seconds(client->discoverable_to,
						client_discoverable_timeout,
						client);

	return true;
}

static struct adv_parser {
	const char *name;
	bool (*func)(DBusMessageIter *iter, struct btd_adv_client *client);
} parsers[] = {
	{ "Type", parse_type },
	{ "ServiceUUIDs", parse_service_uuids },
	{ "SolicitUUIDs", parse_solicit_uuids },
	{ "ManufacturerData", parse_manufacturer_data },
	{ "ServiceData", parse_service_data },
	{ "Includes", parse_includes },
	{ "LocalName", parse_local_name },
	{ "Appearance", parse_appearance },
	{ "Duration", parse_duration },
	{ "Timeout", parse_timeout },
	{ "Data", parse_data },
	{ "Discoverable", parse_discoverable },
	{ "DiscoverableTimeout", parse_discoverable_timeout },
	{ },
};

static void properties_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	struct btd_adv_client *client = user_data;
	struct adv_parser *parser;

	for (parser = parsers; parser && parser->name; parser++) {
		if (strcmp(parser->name, name))
			continue;

		if (parser->func(iter, client)) {
			refresh_adv(client, NULL);
			break;
		}
	}
}

static void add_client_complete(struct btd_adv_client *client, uint8_t status)
{
	DBusMessage *reply;

	if (status) {
		error("Failed to add advertisement: %s (0x%02x)",
						mgmt_errstr(status), status);
		reply = btd_error_failed(client->reg,
					"Failed to register advertisement");
		queue_remove(client->manager->clients, client);
		g_idle_add(client_free_idle_cb, client);

	} else
		reply = dbus_message_new_method_return(client->reg);

	g_dbus_send_message(btd_get_dbus_connection(), reply);
	dbus_message_unref(client->reg);
	client->reg = NULL;
}

static void add_adv_callback(uint8_t status, uint16_t length,
					  const void *param, void *user_data)
{
	struct btd_adv_client *client = user_data;
	const struct mgmt_rp_add_advertising *rp = param;

	if (status)
		goto done;

	if (!param || length < sizeof(*rp)) {
		status = MGMT_STATUS_FAILED;
		goto done;
	}

	client->instance = rp->instance;

	g_dbus_client_set_disconnect_watch(client->client, client_disconnect_cb,
									client);
	DBG("Advertisement registered: %s", client->path);

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
				adapter_get_path(client->manager->adapter),
				LE_ADVERTISING_MGR_IFACE, "SupportedInstances");

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
				adapter_get_path(client->manager->adapter),
				LE_ADVERTISING_MGR_IFACE, "ActiveInstances");

	g_dbus_proxy_set_property_watch(client->proxy, properties_changed,
								client);

done:
	add_client_complete(client, status);
}

static DBusMessage *parse_advertisement(struct btd_adv_client *client)
{
	struct adv_parser *parser;
	int err;

	for (parser = parsers; parser && parser->name; parser++) {
		DBusMessageIter iter;

		if (!g_dbus_proxy_get_property(client->proxy, parser->name,
								&iter))
			continue;

		if (!parser->func(&iter, client)) {
			error("Error parsing %s property", parser->name);
			goto fail;
		}
	}

	if (bt_ad_has_flags(client->data)) {
		/* BLUETOOTH SPECIFICATION Version 5.0 | Vol 3, Part C
		 * page 2042:
		 * A device in the broadcast mode shall not set the
		 * ‘LE General Discoverable Mode’ flag or the
		 * ‘LE Limited Discoverable Mode’ flag in the Flags AD Type
		 * as defined in [Core Specification Supplement], Part A,
		 * Section 1.3.
		 */
		if (client->type == AD_TYPE_BROADCAST) {
			error("Broadcast cannot set flags");
			goto fail;
		}

		/* Set Limited Discoverable if DiscoverableTimeout is set */
		if (client->disc_to_id && !set_flags(client, 0x01)) {
			error("Failed to set Limited Discoverable Flag");
			goto fail;
		}
	} else if (client->disc_to_id) {
		/* Ignore DiscoverableTimeout if not discoverable */
		g_source_remove(client->disc_to_id);
		client->disc_to_id = 0;
		client->discoverable_to = 0;
	}

	if (client->timeout && client->timeout < client->discoverable_to) {
		/* DiscoverableTimeout must not be bigger than Timeout */
		error("DiscoverableTimeout > Timeout");
		goto fail;
	}

	err = refresh_adv(client, add_adv_callback);
	if (!err)
		return NULL;

fail:
	return btd_error_failed(client->reg, "Failed to parse advertisement.");
}

static void client_proxy_added(GDBusProxy *proxy, void *data)
{
	struct btd_adv_client *client = data;
	DBusMessage *reply;
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);
	if (g_str_equal(interface, LE_ADVERTISEMENT_IFACE) == FALSE)
		return;

	reply = parse_advertisement(client);
	if (!reply)
		return;

	/* Failed to publish for some reason, remove. */
	queue_remove(client->manager->clients, client);

	g_idle_add(client_free_idle_cb, client);

	g_dbus_send_message(btd_get_dbus_connection(), reply);

	dbus_message_unref(client->reg);
	client->reg = NULL;
}

static struct btd_adv_client *client_create(struct btd_adv_manager *manager,
					DBusConnection *conn,
					DBusMessage *msg, const char *path)
{
	struct btd_adv_client *client;
	const char *sender = dbus_message_get_sender(msg);

	if (!path || !g_str_has_prefix(path, "/"))
		return NULL;

	client = new0(struct btd_adv_client, 1);
	client->client = g_dbus_client_new_full(conn, sender, path, path);
	if (!client->client)
		goto fail;

	client->owner = g_strdup(sender);
	if (!client->owner)
		goto fail;

	client->path = g_strdup(path);
	if (!client->path)
		goto fail;

	DBG("Adding proxy for %s", path);
	client->proxy = g_dbus_proxy_new(client->client, path,
						LE_ADVERTISEMENT_IFACE);
	if (!client->proxy)
		goto fail;

	g_dbus_client_set_proxy_handlers(client->client, client_proxy_added,
							NULL, NULL, client);

	client->reg = dbus_message_ref(msg);

	client->data = bt_ad_new();
	if (!client->data)
		goto fail;

	client->scan = bt_ad_new();
	if (!client->scan)
		goto fail;

	client->manager = manager;
	client->appearance = UINT16_MAX;

	return client;

fail:
	client_free(client);
	return NULL;
}

static DBusMessage *register_advertisement(DBusConnection *conn,
						DBusMessage *msg,
						void *user_data)
{
	struct btd_adv_manager *manager = user_data;
	DBusMessageIter args;
	struct btd_adv_client *client;
	struct dbus_obj_match match;

	DBG("RegisterAdvertisement");

	if (!dbus_message_iter_init(msg, &args))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&args, &match.path);

	match.owner = dbus_message_get_sender(msg);

	if (queue_find(manager->clients, match_client, &match))
		return btd_error_already_exists(msg);

	dbus_message_iter_next(&args);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		return btd_error_invalid_args(msg);

	client = client_create(manager, conn, msg, match.path);
	if (!client)
		return btd_error_failed(msg,
					"Failed to register advertisement");

	client->instance = util_get_uid(&manager->instance_bitmap,
							manager->max_ads);
	if (!client->instance) {
		client_free(client);
		return btd_error_not_permitted(msg,
					"Maximum advertisements reached");
	}

	DBG("Registered advertisement at path %s", match.path);

	queue_push_tail(manager->clients, client);

	return NULL;
}

static DBusMessage *unregister_advertisement(DBusConnection *conn,
						DBusMessage *msg,
						void *user_data)
{
	struct btd_adv_manager *manager = user_data;
	DBusMessageIter args;
	struct btd_adv_client *client;
	struct dbus_obj_match match;

	DBG("UnregisterAdvertisement");

	if (!dbus_message_iter_init(msg, &args))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&args, &match.path);

	match.owner = dbus_message_get_sender(msg);

	client = queue_find(manager->clients, match_client, &match);
	if (!client)
		return btd_error_does_not_exist(msg);

	client_remove(client);

	return dbus_message_new_method_return(msg);
}

static gboolean get_instances(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_adv_manager *manager = data;
	uint8_t instances;

	instances = manager->max_ads - queue_length(manager->clients);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &instances);

	return TRUE;
}

static gboolean get_active_instances(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_adv_manager *manager = data;
	uint8_t instances;

	instances = queue_length(manager->clients);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &instances);

	return TRUE;
}

static void append_include(struct btd_adv_manager *manager,
						DBusMessageIter *iter)
{
	struct adv_include *inc;

	for (inc = includes; inc && inc->name; inc++) {
		if (manager->supported_flags & inc->flag)
			dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
								&inc->name);
	}
}

static gboolean get_supported_includes(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_adv_manager *manager = data;
	DBusMessageIter entry;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &entry);

	append_include(manager, &entry);

	dbus_message_iter_close_container(iter, &entry);

	return TRUE;
}

static const GDBusPropertyTable properties[] = {
	{ "ActiveInstances", "y", get_active_instances, NULL, NULL },
	{ "SupportedInstances", "y", get_instances, NULL, NULL },
	{ "SupportedIncludes", "as", get_supported_includes, NULL, NULL },
	{ }
};

static const GDBusMethodTable methods[] = {
	{ GDBUS_ASYNC_METHOD("RegisterAdvertisement",
					GDBUS_ARGS({ "advertisement", "o" },
							{ "options", "a{sv}" }),
					NULL, register_advertisement) },
	{ GDBUS_ASYNC_METHOD("UnregisterAdvertisement",
						GDBUS_ARGS({ "service", "o" }),
						NULL,
						unregister_advertisement) },
	{ }
};

static void manager_destroy(void *user_data)
{
	struct btd_adv_manager *manager = user_data;

	queue_destroy(manager->clients, client_destroy);

	mgmt_unref(manager->mgmt);

	free(manager);
}

static void read_adv_features_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct btd_adv_manager *manager = user_data;
	const struct mgmt_rp_read_adv_features *feat = param;

	if (status || !param) {
		error("Failed to read advertising features: %s (0x%02x)",
						mgmt_errstr(status), status);
		return;
	}

	if (length < sizeof(*feat)) {
		error("Wrong size of read adv features response");
		return;
	}

	manager->max_adv_len = feat->max_adv_data_len;
	manager->max_scan_rsp_len = feat->max_scan_rsp_len;
	manager->max_ads = feat->max_instances;
	manager->supported_flags |= feat->supported_flags;

	if (manager->max_ads == 0)
		return;

	/* Reset existing instances */
	if (feat->num_instances)
		remove_advertising(manager, 0);
}

static struct btd_adv_manager *manager_create(struct btd_adapter *adapter,
						struct mgmt *mgmt)
{
	struct btd_adv_manager *manager;

	manager = new0(struct btd_adv_manager, 1);
	manager->adapter = adapter;

	manager->mgmt = mgmt_ref(mgmt);

	if (!manager->mgmt) {
		error("Failed to access management interface");
		free(manager);
		return NULL;
	}

	manager->mgmt_index = btd_adapter_get_index(adapter);
	manager->clients = queue_new();
	manager->supported_flags = MGMT_ADV_FLAG_LOCAL_NAME;

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
					adapter_get_path(manager->adapter),
					LE_ADVERTISING_MGR_IFACE, methods,
					NULL, properties, manager, NULL)) {
		error("Failed to register " LE_ADVERTISING_MGR_IFACE);
		goto fail;
	}

	if (!mgmt_send(manager->mgmt, MGMT_OP_READ_ADV_FEATURES,
				manager->mgmt_index, 0, NULL,
				read_adv_features_callback, manager, NULL)) {
		error("Failed to read advertising features");
		goto fail;
	}

	return manager;

fail:
	manager_destroy(manager);
	return NULL;
}

struct btd_adv_manager *btd_adv_manager_new(struct btd_adapter *adapter,
							struct mgmt *mgmt)
{
	struct btd_adv_manager *manager;

	if (!adapter || !mgmt)
		return NULL;

	manager = manager_create(adapter, mgmt);
	if (!manager)
		return NULL;

	DBG("LE Advertising Manager created for adapter: %s",
						adapter_get_path(adapter));

	return manager;
}

void btd_adv_manager_destroy(struct btd_adv_manager *manager)
{
	if (!manager)
		return;

	g_dbus_unregister_interface(btd_get_dbus_connection(),
					adapter_get_path(manager->adapter),
					LE_ADVERTISING_MGR_IFACE);

	manager_destroy(manager);
}

static void manager_refresh(void *data, void *user_data)
{
	refresh_adv(data, user_data);
}

void btd_adv_manager_refresh(struct btd_adv_manager *manager)
{
	if (!manager)
		return;

	queue_foreach(manager->clients, manager_refresh, NULL);
}
