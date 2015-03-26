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

#include "advertising.h"

#include <stdint.h>
#include <stdbool.h>

#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"

#include "adapter.h"
#include "dbus-common.h"
#include "error.h"
#include "log.h"
#include "src/shared/queue.h"
#include "src/shared/util.h"

#define LE_ADVERTISING_MGR_IFACE "org.bluez.LEAdvertisingManager1"
#define LE_ADVERTISEMENT_IFACE "org.bluez.LEAdvertisement1"

struct btd_advertising {
	struct btd_adapter *adapter;
	struct queue *ads;
};

#define AD_TYPE_BROADCAST 0
#define AD_TYPE_PERIPHERAL 1

struct advertisement {
	struct btd_advertising *manager;
	char *owner;
	char *path;
	GDBusClient *client;
	GDBusProxy *proxy;
	DBusMessage *reg;
	uint8_t type; /* Advertising type */
};

static bool match_advertisement_path(const void *a, const void *b)
{
	const struct advertisement *ad = a;
	const char *path = b;

	return g_strcmp0(ad->path, path);
}

static void advertisement_free(void *data)
{
	struct advertisement *ad = data;

	if (ad->client) {
		g_dbus_client_set_disconnect_watch(ad->client, NULL, NULL);
		g_dbus_client_unref(ad->client);
	}

	if (ad->proxy)
		g_dbus_proxy_unref(ad->proxy);

	if (ad->owner)
		g_free(ad->owner);

	if (ad->path)
		g_free(ad->path);

	free(ad);
}

static gboolean advertisement_free_idle_cb(void *data)
{
	advertisement_free(data);

	return FALSE;
}

static void advertisement_release(void *data)
{
	struct advertisement *ad = data;
	DBusMessage *message;

	DBG("Releasing advertisement %s, %s", ad->owner, ad->path);

	message = dbus_message_new_method_call(ad->owner, ad->path,
							LE_ADVERTISEMENT_IFACE,
							"Release");

	if (!message) {
		error("Couldn't allocate D-Bus message");
		return;
	}

	g_dbus_send_message(btd_get_dbus_connection(), message);
}

static void advertisement_destroy(void *data)
{
	advertisement_release(data);
	advertisement_free(data);
}

static void advertisement_remove(void *data)
{
	struct advertisement *ad = data;

	g_dbus_client_set_disconnect_watch(ad->client, NULL, NULL);

	/* TODO: mgmt API call to remove advert */

	queue_remove(ad->manager->ads, ad);

	g_idle_add(advertisement_free_idle_cb, ad);
}

static void client_disconnect_cb(DBusConnection *conn, void *user_data)
{
	DBG("Client disconnected");

	advertisement_remove(user_data);
}

static bool parse_advertising_type(GDBusProxy *proxy, uint8_t *type)
{
	DBusMessageIter iter;
	const char *msg_type;

	if (!g_dbus_proxy_get_property(proxy, "Type", &iter))
		return false;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return false;

	dbus_message_iter_get_basic(&iter, &msg_type);

	if (!g_strcmp0(msg_type, "broadcast")) {
		*type = AD_TYPE_BROADCAST;
		return true;
	}

	if (!g_strcmp0(msg_type, "peripheral")) {
		*type = AD_TYPE_PERIPHERAL;
		return true;
	}

	return false;
}

static void refresh_advertisement(struct advertisement *ad)
{
	DBG("Refreshing advertisement: %s", ad->path);
}

static bool parse_advertisement(struct advertisement *ad)
{
	if (!parse_advertising_type(ad->proxy, &ad->type)) {
		error("Failed to read \"Type\" property of advertisement");
		return false;
	}

	/* TODO: parse the remaining properties into a shared structure */

	refresh_advertisement(ad);

	return true;
}

static void advertisement_proxy_added(GDBusProxy *proxy, void *data)
{
	struct advertisement *ad = data;
	DBusMessage *reply;

	if (!parse_advertisement(ad)) {
		error("Failed to parse advertisement");

		reply = btd_error_failed(ad->reg,
					"Failed to register advertisement");
		goto done;
	}

	g_dbus_client_set_disconnect_watch(ad->client, client_disconnect_cb,
									ad);

	reply = dbus_message_new_method_return(ad->reg);

	DBG("Advertisement registered: %s", ad->path);

done:
	g_dbus_send_message(btd_get_dbus_connection(), reply);

	dbus_message_unref(ad->reg);
	ad->reg = NULL;
}

static struct advertisement *advertisement_create(DBusConnection *conn,
					DBusMessage *msg, const char *path)
{
	struct advertisement *ad;
	const char *sender = dbus_message_get_sender(msg);

	if (!path || !g_str_has_prefix(path, "/"))
		return NULL;

	ad = new0(struct advertisement, 1);
	if (!ad)
		return NULL;

	ad->client = g_dbus_client_new_full(conn, sender, path, path);
	if (!ad->client)
		goto fail;

	ad->owner = g_strdup(sender);
	if (!ad->owner)
		goto fail;

	ad->path = g_strdup(path);
	if (!ad->path)
		goto fail;

	DBG("Adding proxy for %s", path);
	ad->proxy = g_dbus_proxy_new(ad->client, path, LE_ADVERTISEMENT_IFACE);
	if (!ad->proxy)
		goto fail;

	g_dbus_client_set_proxy_handlers(ad->client, advertisement_proxy_added,
								NULL, NULL, ad);

	ad->reg = dbus_message_ref(msg);

	return ad;

fail:
	advertisement_free(ad);
	return NULL;
}

static DBusMessage *register_advertisement(DBusConnection *conn,
						DBusMessage *msg,
						void *user_data)
{
	struct btd_advertising *manager = user_data;
	DBusMessageIter args;
	const char *path;
	struct advertisement *ad;

	DBG("RegisterAdvertisement");

	if (!dbus_message_iter_init(msg, &args))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&args, &path);

	if (queue_find(manager->ads, match_advertisement_path, path))
		return btd_error_already_exists(msg);

	/* TODO: support more than one advertisement */
	if (!queue_isempty(manager->ads))
		return btd_error_failed(msg, "Already advertising");

	dbus_message_iter_next(&args);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		return btd_error_invalid_args(msg);

	ad = advertisement_create(conn, msg, path);
	if (!ad)
		return btd_error_failed(msg,
					"Failed to register advertisement");

	DBG("Registered advertisement at path %s", path);

	ad->manager = manager;
	queue_push_tail(manager->ads, ad);

	return NULL;
}

static DBusMessage *unregister_advertisement(DBusConnection *conn,
						DBusMessage *msg,
						void *user_data)
{
	struct btd_advertising *manager = user_data;
	DBusMessageIter args;
	const char *path;
	struct advertisement *ad;

	DBG("UnregisterAdvertisement");

	if (!dbus_message_iter_init(msg, &args))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&args, &path);

	ad = queue_find(manager->ads, match_advertisement_path, path);
	if (!ad)
		return btd_error_does_not_exist(msg);

	advertisement_remove(ad);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable methods[] = {
	{ GDBUS_EXPERIMENTAL_ASYNC_METHOD("RegisterAdvertisement",
					GDBUS_ARGS({ "advertisement", "o" },
							{ "options", "a{sv}" }),
					NULL, register_advertisement) },
	{ GDBUS_EXPERIMENTAL_ASYNC_METHOD("UnregisterAdvertisement",
						GDBUS_ARGS({ "service", "o" }),
						NULL,
						unregister_advertisement) },
	{ }
};

static void advertising_manager_destroy(void *user_data)
{
	struct btd_advertising *manager = user_data;

	queue_destroy(manager->ads, advertisement_destroy);

	free(manager);
}

static struct btd_advertising *
advertising_manager_create(struct btd_adapter *adapter)
{
	struct btd_advertising *manager;

	manager = new0(struct btd_advertising, 1);
	if (!manager)
		return NULL;

	manager->adapter = adapter;

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
						adapter_get_path(adapter),
						LE_ADVERTISING_MGR_IFACE,
						methods, NULL, NULL, manager,
						advertising_manager_destroy)) {
		error("Failed to register " LE_ADVERTISING_MGR_IFACE);
		free(manager);
		return NULL;
	}

	manager->ads = queue_new();

	return manager;
}

struct btd_advertising *
btd_advertising_manager_new(struct btd_adapter *adapter)
{
	struct btd_advertising *manager;

	if (!adapter)
		return NULL;

	manager = advertising_manager_create(adapter);
	if (!manager)
		return NULL;

	DBG("LE Advertising Manager created for adapter: %s",
						adapter_get_path(adapter));

	return manager;
}

void btd_advertising_manager_destroy(struct btd_advertising *manager)
{
	if (!manager)
		return;

	g_dbus_unregister_interface(btd_get_dbus_connection(),
					adapter_get_path(manager->adapter),
					LE_ADVERTISING_MGR_IFACE);
}
