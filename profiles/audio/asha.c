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
#include "src/shared/queue.h"
#include "src/shared/hci.h"
#include "src/shared/att.h"
#include "src/shared/gatt-client.h"
#include "monitor/bt.h"

#include "profiles/audio/asha.h"
#include "profiles/audio/media.h"
#include "profiles/audio/transport.h"

#define MEDIA_ENDPOINT_INTERFACE "org.bluez.MediaEndpoint1"

/* 2 byte SDU length, 1 byte sequence number, and then 20ms of G.722 */
#define ASHA_MIN_MTU 163
/* The default of 672 does not work */
#define ASHA_CONNECTION_MTU 512

/* HCI connection handles occupy 0x0000 through 0x0eff. Zero is unknown. */
#define ASHA_NUM_HANDLES 0x0f00

struct asha_adapter {
	struct btd_adapter *adapter;
	struct bt_hci *hci;
	uint16_t intervals[ASHA_NUM_HANDLES];
};

static struct queue *asha_adapters;
static struct queue *asha_streams;

struct bt_asha_device {
	struct bt_asha *asha;
	struct btd_device *device;
	struct media_transport *transport;

	GIOChannel *io;
	uint16_t imtu, omtu;

	unsigned int resume_id;
};

static bool match_adapter(const void *data, const void *user_data)
{
	const struct asha_adapter *data_adapter = data;

	return data_adapter->adapter == user_data;
}

static bool asha_get_handle(struct bt_asha_device *asha_dev, uint16_t *handle)
{
	struct bt_att *att;
	struct l2cap_conninfo info;
	socklen_t len = sizeof(info);
	int fd;

	if (!asha_dev->asha->client)
		return false;

	att = bt_gatt_client_get_att(asha_dev->asha->client);
	fd = bt_att_get_fd(att);

	/* The ATT socket identifies this link even when CoC is not open. */
	if (fd < 0 || getsockopt(fd, SOL_L2CAP, L2CAP_CONNINFO,
							&info, &len) < 0) {
		DBG("Could not read ASHA connection handle");
		return false;
	}

	if (len != sizeof(info) || info.hci_handle >= ASHA_NUM_HANDLES)
		return false;

	*handle = info.hci_handle;
	return true;
}

static void asha_notify_interval(struct bt_asha_device *asha_dev,
					uint16_t handle, uint16_t interval)
{
	/* Only announce an interval observed on this connection. */
	if (!interval)
		return;

	DBG("ASHA connection h%u interval %u", handle, interval);

	if (!bt_asha_set_connection_interval(asha_dev->asha, interval))
		DBG("Could not send ASHA connection interval notification");
}

static void asha_send_interval(struct bt_asha_device *asha_dev)
{
	struct asha_adapter *data;
	uint16_t handle;

	data = queue_find(asha_adapters, match_adapter,
					device_get_adapter(asha_dev->device));
	if (!data || !asha_get_handle(asha_dev, &handle))
		return;

	asha_notify_interval(asha_dev, handle, data->intervals[handle]);
}

struct interval_update {
	struct asha_adapter *adapter;
	uint16_t handle;
};

static void asha_update_stream(void *data, void *user_data)
{
	struct bt_asha_device *asha_dev = data;
	struct interval_update *update = user_data;
	uint16_t handle;

	if (device_get_adapter(asha_dev->device) != update->adapter->adapter ||
			!asha_get_handle(asha_dev, &handle) ||
			handle != update->handle)
		return;

	asha_notify_interval(asha_dev, handle,
					update->adapter->intervals[handle]);
}

static void asha_conn_update(const void *param, uint8_t size, void *user_data)
{
	const struct bt_hci_evt_le_conn_update_complete *ev = param;
	struct asha_adapter *data = user_data;
	struct interval_update update;
	uint16_t handle;

	if (size != sizeof(*ev) || ev->status)
		return;

	handle = get_le16(&ev->handle);

	if (handle >= ASHA_NUM_HANDLES)
		return;

	data->intervals[handle] = get_le16(&ev->interval);
	update.adapter = data;
	update.handle = handle;
	queue_foreach(asha_streams, asha_update_stream, &update);
}

static void asha_conn_complete(const void *param, uint8_t size, void *user_data)
{
	const struct bt_hci_evt_le_conn_complete *ev = param;
	struct asha_adapter *data = user_data;
	uint16_t handle;

	if (size != sizeof(*ev) || ev->status)
		return;

	handle = get_le16(&ev->handle);

	if (handle < ASHA_NUM_HANDLES)
		data->intervals[handle] = get_le16(&ev->interval);
}

static void asha_enhanced_conn_complete(const void *param, uint8_t size,
							void *user_data)
{
	const struct bt_hci_evt_le_enhanced_conn_complete *ev = param;
	struct asha_adapter *data = user_data;
	uint16_t handle;

	if (size != sizeof(*ev) || ev->status)
		return;

	handle = get_le16(&ev->handle);

	if (handle < ASHA_NUM_HANDLES)
		data->intervals[handle] = get_le16(&ev->interval);
}

static void asha_disconn_complete(const void *param, uint8_t size,
							void *user_data)
{
	const struct bt_hci_evt_disconnect_complete *ev = param;
	struct asha_adapter *data = user_data;
	uint16_t handle;

	if (size != sizeof(*ev) || ev->status)
		return;

	handle = get_le16(&ev->handle);

	if (handle < ASHA_NUM_HANDLES)
		data->intervals[handle] = 0;
}

static int asha_adapter_probe(struct btd_profile *profile,
						struct btd_adapter *adapter)
{
	struct asha_adapter *data;

	data = new0(struct asha_adapter, 1);
	data->adapter = adapter;
	data->hci = bt_hci_new_raw_device(btd_adapter_get_index(adapter));

	if (!data->hci)
		goto fail;

	if (!bt_hci_register_subevent(data->hci, BT_HCI_EVT_LE_CONN_COMPLETE,
					asha_conn_complete, data, NULL) ||
		!bt_hci_register_subevent(data->hci,
					BT_HCI_EVT_LE_ENHANCED_CONN_COMPLETE,
				asha_enhanced_conn_complete, data, NULL) ||
		!bt_hci_register_subevent(data->hci,
					BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE,
					asha_conn_update, data, NULL) ||
		!bt_hci_register(data->hci, BT_HCI_EVT_DISCONNECT_COMPLETE,
					asha_disconn_complete, data, NULL))
		goto fail;

	if (!asha_adapters)
		asha_adapters = queue_new();

	queue_push_tail(asha_adapters, data);
	return 0;

fail:
	bt_hci_unref(data->hci);
	free(data);
	return -EIO;
}

static void asha_adapter_remove(struct btd_profile *profile,
						struct btd_adapter *adapter)
{
	struct asha_adapter *data;

	data = queue_remove_if(asha_adapters, match_adapter, adapter);

	if (!data)
		return;

	bt_hci_unref(data->hci);
	free(data);

	if (queue_isempty(asha_adapters)) {
		queue_destroy(asha_adapters, NULL);
		asha_adapters = NULL;
	}
}

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

	asha_send_interval(asha_dev);

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

	if (!asha_streams)
		asha_streams = queue_new();

	queue_push_tail(asha_streams, asha_dev);

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

	queue_remove(asha_streams, asha_dev);

	if (queue_isempty(asha_streams)) {
		queue_destroy(asha_streams, NULL);
		asha_streams = NULL;
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
	.bearer		= BTD_PROFILE_BEARER_LE,
	.remote_uuid	= ASHA_PROFILE_UUID,
	.experimental	= true,

	.adapter_probe	= asha_adapter_probe,
	.adapter_remove	= asha_adapter_remove,

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
