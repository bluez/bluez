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
#include "error.h"
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

#define GATT_SERVICE_IFACE		"org.bluez.GattService1"
#define GATT_CHARACTERISTIC_IFACE	"org.bluez.GattCharacteristic1"

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
	struct queue *chrcs;
	bool chrcs_ready;
};

struct characteristic {
	struct service *service;
	uint16_t handle;
	uint16_t value_handle;
	uint8_t props;
	bt_uuid_t uuid;
	char *path;
};

static gboolean characteristic_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	char uuid[MAX_LEN_UUID_STR + 1];
	const char *ptr = uuid;
	struct characteristic *chrc = data;

	bt_uuid_to_string(&chrc->uuid, uuid, sizeof(uuid));
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &ptr);

	return TRUE;
}

static gboolean characteristic_get_service(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct characteristic *chrc = data;
	const char *str = chrc->service->path;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &str);

	return TRUE;
}

static gboolean characteristic_get_value(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "y", &array);

	/* TODO: Implement this once the value is cached */

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean characteristic_get_notifying(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	dbus_bool_t notifying = FALSE;

	/*
	 * TODO: Return the correct value here once StartNotify and StopNotify
	 * methods are implemented.
	 */

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &notifying);

	return TRUE;
}

static struct {
	uint8_t prop;
	char *str;
} properties[] = {
	/* Default Properties */
	{ BT_GATT_CHRC_PROP_BROADCAST,		"broadcast" },
	{ BT_GATT_CHRC_PROP_READ,		"read" },
	{ BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,	"write-without-response" },
	{ BT_GATT_CHRC_PROP_WRITE,		"write" },
	{ BT_GATT_CHRC_PROP_NOTIFY,		"notify" },
	{ BT_GATT_CHRC_PROP_INDICATE,		"indicate" },
	{ BT_GATT_CHRC_PROP_AUTH,		"authenticated-signed-writes" },
	{ },
};

static gboolean characteristic_get_flags(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct characteristic *chrc = data;
	DBusMessageIter array;
	int i;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "s", &array);

	for (i = 0; properties[i].str; i++) {
		if (chrc->props & properties[i].prop)
			dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING,
							&properties[i].str);
	}

	/*
	 * TODO: Handle extended properties if the descriptor is
	 * present.
	 */

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static DBusMessage *characteristic_read_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	/* TODO: Implement */
	return btd_error_failed(msg, "Not implemented");
}

static DBusMessage *characteristic_write_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	/* TODO: Implement */
	return btd_error_failed(msg, "Not implemented");
}

static DBusMessage *characteristic_start_notify(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	/* TODO: Implement */
	return btd_error_failed(msg, "Not implemented");
}

static DBusMessage *characteristic_stop_notify(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	/* TODO: Implement */
	return btd_error_failed(msg, "Not implemented");
}

static gboolean characteristic_get_descriptors(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "o", &array);

	/* TODO: Implement this once descriptors are exported */

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static const GDBusPropertyTable characteristic_properties[] = {
	{ "UUID", "s", characteristic_get_uuid, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Service", "o", characteristic_get_service, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Value", "ay", characteristic_get_value, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Notifying", "b", characteristic_get_notifying, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Flags", "as", characteristic_get_flags, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Descriptors", "ao", characteristic_get_descriptors, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};

static const GDBusMethodTable characteristic_methods[] = {
	{ GDBUS_EXPERIMENTAL_ASYNC_METHOD("ReadValue", NULL,
						GDBUS_ARGS({ "value", "ay" }),
						characteristic_read_value) },
	{ GDBUS_EXPERIMENTAL_ASYNC_METHOD("WriteValue",
						GDBUS_ARGS({ "value", "ay" }),
						NULL,
						characteristic_write_value) },
	{ GDBUS_EXPERIMENTAL_ASYNC_METHOD("StartNotify", NULL, NULL,
						characteristic_start_notify) },
	{ GDBUS_EXPERIMENTAL_METHOD("StopNotify", NULL, NULL,
						characteristic_stop_notify) },
	{ }
};

static void characteristic_free(void *data)
{
	struct characteristic *chrc = data;

	g_free(chrc->path);
	free(chrc);
}

static struct characteristic *characteristic_create(
						struct gatt_db_attribute *attr,
						struct service *service)
{
	struct characteristic *chrc;
	bt_uuid_t uuid;

	chrc = new0(struct characteristic, 1);
	if (!chrc)
		return NULL;

	chrc->service = service;

	gatt_db_attribute_get_char_data(attr, &chrc->handle,
							&chrc->value_handle,
							&chrc->props, &uuid);
	bt_uuid_to_uuid128(&uuid, &chrc->uuid);

	chrc->path = g_strdup_printf("%s/char%04x", service->path,
								chrc->handle);

	if (!g_dbus_register_interface(btd_get_dbus_connection(), chrc->path,
						GATT_CHARACTERISTIC_IFACE,
						characteristic_methods, NULL,
						characteristic_properties,
						chrc, characteristic_free)) {
		error("Unable to register GATT characteristic with handle "
							"0x%04x", chrc->handle);
		characteristic_free(chrc);

		return NULL;
	}

	DBG("Exported GATT characteristic: %s", chrc->path);

	return chrc;
}

static void unregister_characteristic(void *data)
{
	struct characteristic *chrc = data;

	DBG("Removing GATT characteristic: %s", chrc->path);

	g_dbus_unregister_interface(btd_get_dbus_connection(), chrc->path,
						GATT_CHARACTERISTIC_IFACE);
}

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

static void append_chrc_path(void *data, void *user_data)
{
	struct characteristic *chrc = data;
	DBusMessageIter *array = user_data;

	dbus_message_iter_append_basic(array, DBUS_TYPE_OBJECT_PATH,
								&chrc->path);
}

static gboolean service_get_characteristics(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct service *service = data;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "o", &array);

	if (service->chrcs_ready)
		queue_foreach(service->chrcs, append_chrc_path, &array);

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

	queue_destroy(service->chrcs, NULL);  /* List should be empty here */
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

	service->chrcs = queue_new();
	if (!service->chrcs) {
		free(service);
		return NULL;
	}

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

	queue_remove_all(service->chrcs, NULL, NULL, unregister_characteristic);

	g_dbus_unregister_interface(btd_get_dbus_connection(), service->path,
							GATT_SERVICE_IFACE);
}

struct export_data {
	void *root;
	bool failed;
};

static void export_char(struct gatt_db_attribute *attr, void *user_data)
{
	struct characteristic *charac;
	struct export_data *data = user_data;
	struct service *service = data->root;

	if (data->failed)
		return;

	charac = characteristic_create(attr, service);
	if (!charac) {
		data->failed = true;
		return;
	}

	queue_push_tail(service->chrcs, charac);
}

static bool create_characteristics(struct gatt_db_attribute *attr,
						struct service *service)
{
	struct export_data data;

	data.root = service;
	data.failed = false;

	gatt_db_service_foreach_char(attr, export_char, &data);

	return !data.failed;
}

static void notify_chrcs(void *data, void *user_data)
{
	struct service *service = data;

	service->chrcs_ready = true;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), service->path,
							GATT_SERVICE_IFACE,
							"Characteristics");
}

static gboolean set_chrcs_ready(gpointer user_data)
{
	struct btd_gatt_client *client = user_data;

	if (!client->gatt)
		return FALSE;

	queue_foreach(client->services, notify_chrcs, NULL);

	return FALSE;
}

static void export_service(struct gatt_db_attribute *attr, void *user_data)
{
	struct btd_gatt_client *client = user_data;
	struct service *service;

	service = service_create(attr, client);
	if (!service)
		return;

	if (!create_characteristics(attr, service)) {
		error("Exporting characteristics failed");
		unregister_service(service);
		return;
	}

	queue_push_tail(client->services, service);
}

static void create_services(struct btd_gatt_client *client)
{
	DBG("Exporting objects for GATT services: %s", client->devaddr);

	gatt_db_foreach_service(client->db, NULL, export_service, client);

	/*
	 * Asynchronously update the "Characteristics" property of each service.
	 * We do this so that users have a way to know that all characteristics
	 * of a service have been exported.
	 */
	g_idle_add(set_chrcs_ready, client);
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
