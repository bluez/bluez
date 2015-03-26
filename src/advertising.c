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
#include "log.h"
#include "src/shared/util.h"

#define LE_ADVERTISING_MGR_IFACE "org.bluez.LEAdvertisingManager1"
#define LE_ADVERTISEMENT_IFACE "org.bluez.LEAdvertisement1"

struct btd_advertising {
	struct btd_adapter *adapter;
};

static DBusMessage *register_advertisement(DBusConnection *conn,
						DBusMessage *msg,
						void *user_data)
{
	DBG("RegisterAdvertisement");

	/* TODO */
	return NULL;
}

static DBusMessage *unregister_advertisement(DBusConnection *conn,
						DBusMessage *msg,
						void *user_data)
{
	DBG("UnregisterAdvertisement");

	/* TODO */
	return NULL;
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
