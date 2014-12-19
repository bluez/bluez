/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Google Inc.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdint.h>

#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include <bluetooth/bluetooth.h>

#include "log.h"
#include "adapter.h"
#include "device.h"
#include "lib/uuid.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/util.h"
#include "gatt-client.h"
#include "dbus-common.h"

#define GATT_SERVICE_IFACE "org.bluez.GattService1"

struct btd_gatt_client {
	struct btd_device *device;
	char devaddr[18];
	struct gatt_db *db;
	struct bt_gatt_client *gatt;

	struct queue *services;
};

struct service {
	struct btd_gatt_client *client;
	bool primary;
	uint16_t start_handle;
	uint16_t end_handle;
	bt_uuid_t uuid;
	char *path;
};

static gboolean service_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	char uuid[MAX_LEN_UUID_STR + 1];
	const char *ptr = uuid;
	struct service *service = data;

	bt_uuid_to_string(&service->uuid, uuid, sizeof(uuid));
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &ptr);

	return TRUE;
}

static gboolean service_get_device(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct service *service = data;
	const char *str = device_get_path(service->client->device);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &str);

	return TRUE;
}

static gboolean service_get_primary(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct service *service = data;
	dbus_bool_t primary;

	primary = service->primary ? TRUE : FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &primary);

	return TRUE;
}

static gboolean service_get_characteristics(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "o", &array);

	/* TODO: Implement this once characteristics are exported */

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static const GDBusPropertyTable service_properties[] = {
	{ "UUID", "s", service_get_uuid, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Device", "o", service_get_device, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Primary", "b", service_get_primary, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Characteristics", "ao", service_get_characteristics, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};

static void service_free(void *data)
{
	struct service *service = data;

	g_free(service->path);
	free(service);
}

static struct service *service_create(struct gatt_db_attribute *attr,
						struct btd_gatt_client *client)
{
	struct service *service;
	const char *device_path = device_get_path(client->device);
	bt_uuid_t uuid;

	service = new0(struct service, 1);
	if (!service)
		return NULL;

	service->client = client;

	gatt_db_attribute_get_service_data(attr, &service->start_handle,
							&service->end_handle,
							&service->primary,
							&uuid);
	bt_uuid_to_uuid128(&uuid, &service->uuid);

	service->path = g_strdup_printf("%s/service%04x", device_path,
							service->start_handle);

	if (!g_dbus_register_interface(btd_get_dbus_connection(), service->path,
						GATT_SERVICE_IFACE,
						NULL, NULL,
						service_properties,
						service, service_free)) {
		error("Unable to register GATT service with handle 0x%04x for "
							"device %s:",
							service->start_handle,
							client->devaddr);
		service_free(service);

		return NULL;
	}

	DBG("Exported GATT service: %s", service->path);

	return service;
}

static void unregister_service(void *data)
{
	struct service *service = data;

	DBG("Removing GATT service: %s", service->path);

	g_dbus_unregister_interface(btd_get_dbus_connection(), service->path,
							GATT_SERVICE_IFACE);
}

static void export_service(struct gatt_db_attribute *attr, void *user_data)
{
	struct btd_gatt_client *client = user_data;
	struct service *service;

	service = service_create(attr, client);
	if (!service)
		return;

	queue_push_tail(client->services, service);
}

static void create_services(struct btd_gatt_client *client)
{
	DBG("Exporting objects for GATT services: %s", client->devaddr);

	gatt_db_foreach_service(client->db, NULL, export_service, client);
}

struct btd_gatt_client *btd_gatt_client_new(struct btd_device *device)
{
	struct btd_gatt_client *client;
	struct gatt_db *db;

	if (!device)
		return NULL;

	db = btd_device_get_gatt_db(device);
	if (!db)
		return NULL;

	client = new0(struct btd_gatt_client, 1);
	if (!client)
		return NULL;

	client->services = queue_new();
	if (!client->services) {
		free(client);
		return NULL;
	}

	client->device = device;
	ba2str(device_get_address(device), client->devaddr);

	client->db = gatt_db_ref(db);

	return client;
}

void btd_gatt_client_destroy(struct btd_gatt_client *client)
{
	if (!client)
		return;

	queue_destroy(client->services, unregister_service);
	bt_gatt_client_unref(client->gatt);
	gatt_db_unref(client->db);
	free(client);
}

void btd_gatt_client_ready(struct btd_gatt_client *client)
{
	struct bt_gatt_client *gatt;

	if (!client)
		return;

	gatt = btd_device_get_gatt_client(client->device);
	if (!gatt) {
		error("GATT client not initialized");
		return;
	}

	bt_gatt_client_unref(client->gatt);
	client->gatt = bt_gatt_client_ref(gatt);

	create_services(client);
}

void btd_gatt_client_service_added(struct btd_gatt_client *client,
					struct gatt_db_attribute *attrib)
{
	/* TODO */
}

void btd_gatt_client_service_removed(struct btd_gatt_client *client,
					struct gatt_db_attribute *attrib)
{
	/* TODO */
}

void btd_gatt_client_disconnected(struct btd_gatt_client *client)
{
	if (!client)
		return;

	DBG("Device disconnected. Cleaning up");

	/*
	 * Remove all services. We'll recreate them when a new bt_gatt_client
	 * becomes ready.
	 */
	queue_remove_all(client->services, NULL, NULL, unregister_service);

	bt_gatt_client_unref(client->gatt);
	client->gatt = NULL;
}
