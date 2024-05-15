// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2024  Asymptotic Inc.
 *
 *  Author: Arun Raghavan <arun@asymptotic.io>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <stdbool.h>
#include <stdint.h>

#include <dbus/dbus.h>
#include <glib.h>

#include "gdbus/gdbus.h"
#include "lib/bluetooth.h"
#include "lib/uuid.h"

#include "src/dbus-common.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/log.h"
#include "src/plugin.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/shared/asha.h"
#include "src/shared/util.h"

#include "profiles/audio/media.h"
#include "profiles/audio/transport.h"

#define MEDIA_ENDPOINT_INTERFACE "org.bluez.MediaEndpoint1"

static char *make_endpoint_path(struct bt_asha_device *asha)
{
	char *path;
	int err;

	err = asprintf(&path, "%s/asha", device_get_path(asha->device));
	if (err < 0) {
		error("Could not allocate path for remote %s",
				device_get_path(asha->device));
		return NULL;
	}

	return path;

}

static gboolean get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	const char *uuid;

	uuid = ASHA_PROFILE_UUID;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &uuid);

	return TRUE;
}

static gboolean get_side(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bt_asha_device *asha = data;
	const char *side = asha->right_side ? "right" : "left";

	/* Use a string in case we want to support more types in the future */
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &side);

	return TRUE;
}


static gboolean get_binaural(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bt_asha_device *asha = data;
	dbus_bool_t binaural = asha->binaural;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &binaural);

	return TRUE;
}

static gboolean get_hisyncid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bt_asha_device *asha = data;
	DBusMessageIter array;
	uint8_t *hisyncid = asha->hisyncid;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
			&hisyncid, sizeof(asha->hisyncid));

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean get_codecs(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bt_asha_device *asha = data;
	dbus_uint16_t codecs = asha->codec_ids;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &codecs);

	return TRUE;
}

static gboolean get_device(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bt_asha_device *asha = data;
	const char *path;

	path = device_get_path(asha->device);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);

	return TRUE;
}

static gboolean get_transport(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bt_asha_device *asha = data;
	const char *path;

	path = media_transport_get_path(asha->transport);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);

	return TRUE;
}

static int asha_source_device_probe(struct btd_service *service)
{
	struct bt_asha_device *asha;
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("Probing ASHA device %s", addr);

	asha = bt_asha_device_new();
	asha->device = device;

	btd_service_set_user_data(service, asha);

	return 0;
}

static void asha_source_device_remove(struct btd_service *service)
{
	struct bt_asha_device *asha;
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("Removing ASHA device %s", addr);

	asha = btd_service_get_user_data(service);
	if (!asha) {
		/* Can this actually happen? */
		DBG("Not handlihng ASHA profile");
		return;
	}

	bt_asha_device_free(asha);
}

static const GDBusMethodTable asha_ep_methods[] = {
	{ },
};

static const GDBusPropertyTable asha_ep_properties[] = {
	{ "UUID", "s", get_uuid, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Side", "s", get_side, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Binaural", "b", get_binaural, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "HiSyncId", "ay", get_hisyncid, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Codecs", "q", get_codecs, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Device", "o", get_device, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Transport", "o", get_transport, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};

static void asha_source_endpoint_register(struct bt_asha_device *asha)
{
	char *path;
	const struct media_endpoint *asha_ep;

	path = make_endpoint_path(asha);
	if (!path)
		goto error;

	if (g_dbus_register_interface(btd_get_dbus_connection(),
				path, MEDIA_ENDPOINT_INTERFACE,
				asha_ep_methods, NULL,
				asha_ep_properties,
				asha, NULL) == FALSE) {
		error("Could not register remote ep %s", path);
		goto error;
	}

	asha_ep = media_endpoint_get_asha();
	asha->transport = media_transport_create(asha->device, path, NULL, 0,
						(void *) asha_ep, asha);

error:
	if (path)
		free(path);
}

static void asha_source_endpoint_unregister(struct bt_asha_device *asha)
{
	char *path;

	path = make_endpoint_path(asha);
	if (!path)
		goto error;

	g_dbus_unregister_interface(btd_get_dbus_connection(),
				path, MEDIA_ENDPOINT_INTERFACE);

	if (asha->transport) {
		media_transport_destroy(asha->transport);
		asha->transport = NULL;
	}

error:
	if (path)
		free(path);
}

static int asha_source_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_asha_device *asha = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("Accepting ASHA connection on %s", addr);

	if (!asha) {
		/* Can this actually happen? */
		DBG("Not handling ASHA profile");
		return -1;
	}

	if (!bt_asha_device_probe(asha))
		return -1;

	asha_source_endpoint_register(asha);

	btd_service_connecting_complete(service, 0);

	return 0;
}

static int asha_source_disconnect(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_asha_device *asha = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("Disconnecting ASHA on %s", addr);

	if (!asha) {
		/* Can this actually happen? */
		DBG("Not handlihng ASHA profile");
		return -1;
	}

	asha_source_endpoint_unregister(asha);
	bt_asha_device_reset(asha);

	btd_service_disconnecting_complete(service, 0);

	return 0;
}

static struct btd_profile asha_source_profile = {
	.name		= "asha-source",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.remote_uuid	= ASHA_PROFILE_UUID,
	.experimental	= true,

	.device_probe	= asha_source_device_probe,
	.device_remove	= asha_source_device_remove,

	.auto_connect	= true,
	.accept		= asha_source_accept,
	.disconnect	= asha_source_disconnect,
};

static int asha_init(void)
{
	int err;

	err = btd_profile_register(&asha_source_profile);
	if (err)
		return err;

	return 0;
}

static void asha_exit(void)
{
	btd_profile_unregister(&asha_source_profile);
}

BLUETOOTH_PLUGIN_DEFINE(asha, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							asha_init, asha_exit)
