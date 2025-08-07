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
#include <errno.h>

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>

#include <dbus/dbus.h>
#include <glib.h>

#include "btio/btio.h"
#include "gdbus/gdbus.h"
#include "bluetooth/bluetooth.h"
#include "bluetooth/l2cap.h"
#include "bluetooth/uuid.h"

#include "src/dbus-common.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/log.h"
#include "src/plugin.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/shared/util.h"

#include "profiles/audio/asha.h"
#include "profiles/audio/media.h"
#include "profiles/audio/transport.h"

#define MEDIA_ENDPOINT_INTERFACE "org.bluez.MediaEndpoint1"

/* 2 byte SDU length, 1 byte sequence number, and then 20ms of G.722 */
#define ASHA_MIN_MTU 163
/* The default of 672 does not work */
#define ASHA_CONNECTION_MTU 512

struct bt_asha_device {
	struct bt_asha *asha;
	struct btd_device *device;
	struct media_transport *transport;

	GIOChannel *io;
	uint16_t imtu, omtu;

	unsigned int resume_id;
};

static char *make_endpoint_path(struct bt_asha_device *asha_dev)
{
	char *path;
	int err;

	err = asprintf(&path, "%s/asha", device_get_path(asha_dev->device));
	if (err < 0) {
		error("Could not allocate path for remote %s",
				device_get_path(asha_dev->device));
		return NULL;
	}

	return path;
}

struct connect_data {
	struct bt_asha_device *asha_dev;
	bt_asha_cb_t cb;
	void *cb_user_data;
};

static void connect_cb(GIOChannel *io, GError *err, gpointer user_data)
{
	struct connect_data *conn_data = user_data;
	struct bt_asha_device *asha_dev = conn_data->asha_dev;
	GError *gerr = NULL;

	if (err) {
		error("%s", err->message);
		return;
	}

	if (!bt_io_get(io, &gerr,
				BT_IO_OPT_IMTU, &asha_dev->imtu,
				BT_IO_OPT_OMTU, &asha_dev->omtu,
				BT_IO_OPT_INVALID)) {
		/* Let this be non-fatal? */
		asha_dev->omtu = ASHA_MIN_MTU;
		asha_dev->imtu = ASHA_CONNECTION_MTU;
		error("Could not get L2CAP CoC socket MTU: %s", gerr->message);
		g_error_free(gerr);
	}

	asha_dev->io = io;

	bt_asha_start(asha_dev->asha, conn_data->cb,
					conn_data->cb_user_data);
}

static int asha_connect_socket(struct bt_asha_device *asha_dev,
					bt_asha_cb_t cb, void *user_data)
{
	GError *gerr = NULL;
	const bdaddr_t *src_addr;
	struct connect_data *conn_data;

	if (asha_dev->asha->state != ASHA_STOPPED) {
		error("ASHA device connect failed. Bad state %d",
							asha_dev->asha->state);
		return 0;
	}

	conn_data = g_new0(struct connect_data, 1);
	conn_data->asha_dev = asha_dev;
	conn_data->cb = cb;
	conn_data->cb_user_data = user_data;

	src_addr = btd_adapter_get_address(
			device_get_adapter(asha_dev->device));

	if (!bt_io_connect(connect_cb, conn_data,
				g_free, &gerr,
				BT_IO_OPT_MODE, BT_IO_MODE_LE_FLOWCTL,
				BT_IO_OPT_SOURCE_TYPE, BDADDR_LE_PUBLIC,
				BT_IO_OPT_SOURCE_BDADDR, src_addr,
				BT_IO_OPT_DEST_TYPE, BDADDR_LE_PUBLIC,
				BT_IO_OPT_DEST_BDADDR,
				device_get_address(asha_dev->device),
				BT_IO_OPT_PSM, asha_dev->asha->psm,
				BT_IO_OPT_OMTU, ASHA_MIN_MTU,
				BT_IO_OPT_IMTU, ASHA_CONNECTION_MTU,
				BT_IO_OPT_INVALID)) {
		error("Could not open L2CAP CoC socket: %s", gerr->message);
		g_error_free(gerr);
		goto error;
	}

	DBG("L2CAP CoC socket is open");
	return 0;

error:
	return -1;
}

unsigned int bt_asha_device_start(struct bt_asha_device *asha_dev,
					bt_asha_cb_t cb, void *user_data)
{
	int ret;

	btd_device_set_conn_param(asha_dev->device,
			0x0010 /* min interval = 1.25ms intervals => 20ms */,
			0x0010 /* max interval = 1.25ms intervals => 20ms */,
			0x000A /* 10 events' latency */,
			0x0064 /* 1s timeout */);

	ret = asha_connect_socket(asha_dev, cb, user_data);

	if (ret < 0)
		return 0;
	else
		return (++asha_dev->resume_id);
}

unsigned int bt_asha_device_stop(struct bt_asha_device *asha_dev)
{
	bt_asha_stop(asha_dev->asha);

	if (asha_dev->io) {
		g_io_channel_shutdown(asha_dev->io, TRUE, NULL);
		g_io_channel_unref(asha_dev->io);
		asha_dev->io = NULL;
	};

	return asha_dev->resume_id;
}

void bt_asha_device_state_reset(struct bt_asha_device *asha_dev)
{
	if (asha_dev->io) {
		g_io_channel_shutdown(asha_dev->io, TRUE, NULL);
		g_io_channel_unref(asha_dev->io);
		asha_dev->io = NULL;
	};

	bt_asha_state_reset(asha_dev->asha);

	asha_dev->resume_id = 0;
}

unsigned int bt_asha_device_device_get_resume_id(
					struct bt_asha_device *asha_dev)
{
	return asha_dev->resume_id;
}

enum bt_asha_state_t bt_asha_device_get_state(
					struct bt_asha_device *asha_dev)
{
	return asha_dev->asha->state;
}

uint16_t bt_asha_device_get_render_delay(struct bt_asha_device *asha_dev)
{
	return asha_dev->asha->render_delay;
}

int8_t bt_asha_device_get_volume(struct bt_asha_device *asha_dev)
{
	return asha_dev->asha->volume;
}

bool bt_asha_device_set_volume(struct bt_asha_device *asha_dev, int8_t volume)
{
	return bt_asha_set_volume(asha_dev->asha, volume);
}

int bt_asha_device_get_fd(struct bt_asha_device *asha_dev)
{
	return g_io_channel_unix_get_fd(asha_dev->io);
}

uint16_t bt_asha_device_get_imtu(struct bt_asha_device *asha_dev)
{
	return asha_dev->imtu;
}

uint16_t bt_asha_device_get_omtu(struct bt_asha_device *asha_dev)
{
	return asha_dev->omtu;
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
	struct bt_asha_device *asha_dev = data;
	const char *side = asha_dev->asha->right_side ? "right" : "left";

	/* Use a string in case we want to support more types in the future */
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &side);

	return TRUE;
}


static gboolean get_binaural(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bt_asha_device *asha_dev = data;
	dbus_bool_t binaural = asha_dev->asha->binaural;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &binaural);

	return TRUE;
}

static gboolean get_hisyncid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bt_asha_device *asha_dev = data;
	DBusMessageIter array;
	uint8_t *hisyncid = asha_dev->asha->hisyncid;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
			&hisyncid, sizeof(asha_dev->asha->hisyncid));

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean get_codecs(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bt_asha_device *asha_dev = data;
	dbus_uint16_t codecs = asha_dev->asha->codec_ids;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &codecs);

	return TRUE;
}

static gboolean get_device(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bt_asha_device *asha_dev = data;
	const char *path;

	path = device_get_path(asha_dev->device);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);

	return TRUE;
}

static gboolean get_transport(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bt_asha_device *asha_dev = data;
	const char *path;

	path = media_transport_get_path(asha_dev->transport);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);

	return TRUE;
}

static int asha_source_device_probe(struct btd_service *service)
{
	struct bt_asha_device *asha_dev;
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("Probing ASHA device %s", addr);

	asha_dev = g_new0(struct bt_asha_device, 1);

	asha_dev->device = device;
	asha_dev->asha = bt_asha_new();
	asha_dev->io = NULL;

	btd_service_set_user_data(service, asha_dev);

	return 0;
}

static void asha_source_device_remove(struct btd_service *service)
{
	struct bt_asha_device *asha_dev;
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("Removing ASHA device %s", addr);

	asha_dev = btd_service_get_user_data(service);
	if (!asha_dev) {
		/* Can this actually happen? */
		DBG("Not handling ASHA profile");
		return;
	}

	bt_asha_free(asha_dev->asha);
	g_free(asha_dev);
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

static void asha_source_endpoint_register(struct bt_asha_device *asha_dev)
{
	char *path;
	const struct media_endpoint *asha_ep;

	path = make_endpoint_path(asha_dev);
	if (!path)
		goto error;

	if (g_dbus_register_interface(btd_get_dbus_connection(),
				path, MEDIA_ENDPOINT_INTERFACE,
				asha_ep_methods, NULL,
				asha_ep_properties,
				asha_dev, NULL) == FALSE) {
		error("Could not register remote ep %s", path);
		goto error;
	}

	asha_ep = media_endpoint_get_asha();
	asha_dev->transport = media_transport_create(asha_dev->device, path,
					NULL, 0, (void *) asha_ep, asha_dev);

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
	struct gatt_db *db = btd_device_get_gatt_db(device);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct bt_asha_device *asha_dev = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("Accepting ASHA connection on %s", addr);

	if (!asha_dev) {
		/* Can this actually happen? */
		DBG("Not handling ASHA profile");
		return -1;
	}

	if (!bt_asha_attach(asha_dev->asha, db, client,
			(bt_asha_attach_cb_t) asha_source_endpoint_register,
			asha_dev)) {
		return -1;
	}

	btd_service_connecting_complete(service, 0);

	return 0;
}

static int asha_source_disconnect(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_asha_device *asha_dev = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("Disconnecting ASHA on %s", addr);

	if (!asha_dev) {
		/* Can this actually happen? */
		DBG("Not handling ASHA profile");
		return -1;
	}

	asha_source_endpoint_unregister(asha_dev);
	bt_asha_reset(asha_dev->asha);

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
