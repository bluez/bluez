/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012 Tieto Poland
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gdbus.h>
#include <errno.h>
#include <stdbool.h>
#include <glib.h>
#include <bluetooth/uuid.h>

#include "adapter.h"
#include "dbus-common.h"
#include "device.h"
#include "error.h"
#include "gattrib.h"
#include "att.h"
#include "gatt.h"
#include "attio.h"
#include "log.h"
#include "heartrate.h"

#define HEART_RATE_MANAGER_INTERFACE	"org.bluez.HeartRateManager"

struct heartrate_adapter {
	struct btd_adapter	*adapter;
	GSList			*devices;
	GSList			*watchers;
};

struct heartrate {
	struct btd_device		*dev;
	struct heartrate_adapter	*hradapter;
	GAttrib				*attrib;
	guint				attioid;

	struct att_range		*svc_range;	/* primary svc range */

	uint16_t			measurement_val_handle;
	uint16_t			measurement_ccc_handle;
	uint16_t			hrcp_val_handle;

	gboolean			has_location;
	uint8_t				location;
};

struct watcher {
	struct heartrate_adapter	*hradapter;
	guint				id;
	char				*srv;
	char				*path;
};

static GSList *heartrate_adapters = NULL;

static gint cmp_adapter(gconstpointer a, gconstpointer b)
{
	const struct heartrate_adapter *hradapter = a;
	const struct btd_adapter *adapter = b;

	if (adapter == hradapter->adapter)
		return 0;

	return -1;
}

static gint cmp_device(gconstpointer a, gconstpointer b)
{
	const struct heartrate *hr = a;
	const struct btd_device *dev = b;

	if (dev == hr->dev)
		return 0;

	return -1;
}

static gint cmp_watcher(gconstpointer a, gconstpointer b)
{
	const struct watcher *watcher = a;
	const struct watcher *match = b;
	int ret;

	ret = g_strcmp0(watcher->srv, match->srv);
	if (ret != 0)
		return ret;

	return g_strcmp0(watcher->path, match->path);
}

static struct heartrate_adapter *
find_heartrate_adapter(struct btd_adapter *adapter)
{
	GSList *l = g_slist_find_custom(heartrate_adapters, adapter,
								cmp_adapter);
	if (!l)
		return NULL;

	return l->data;
}

static void destroy_watcher(gpointer user_data)
{
	struct watcher *watcher = user_data;

	g_free(watcher->path);
	g_free(watcher->srv);
	g_free(watcher);
}

static struct watcher *find_watcher(GSList *list, const char *sender,
							const char *path)
{
	struct watcher *match;
	GSList *l;

	match = g_new0(struct watcher, 1);
	match->srv = g_strdup(sender);
	match->path = g_strdup(path);

	l = g_slist_find_custom(list, match, cmp_watcher);
	destroy_watcher(match);

	if (l != NULL)
		return l->data;

	return NULL;
}

static void destroy_heartrate(gpointer user_data)
{
	struct heartrate *hr = user_data;

	if (hr->attioid > 0)
		btd_device_remove_attio_callback(hr->dev, hr->attioid);

	if (hr->attrib != NULL)
		g_attrib_unref(hr->attrib);

	btd_device_unref(hr->dev);
	g_free(hr->svc_range);
	g_free(hr);
}

static void remove_watcher(gpointer user_data)
{
	struct watcher *watcher = user_data;

	g_dbus_remove_watch(btd_get_dbus_connection(), watcher->id);
}

static void destroy_heartrate_adapter(gpointer user_data)
{
	struct heartrate_adapter *hradapter = user_data;

	g_slist_free_full(hradapter->watchers, remove_watcher);

	g_free(hradapter);
}

static void read_sensor_location_cb(guint8 status, const guint8 *pdu,
						guint16 len, gpointer user_data)
{
	struct heartrate *hr = user_data;
	uint8_t value;
	ssize_t vlen;

	if (status != 0) {
		error("Body Sensor Location read failed: %s",
							att_ecode2str(status));
		return;
	}

	vlen = dec_read_resp(pdu, len, &value, sizeof(value));
	if (vlen < 0) {
		error("Protocol error");
		return;
	}

	if (vlen != sizeof(value)) {
		error("Invalid length for Body Sensor Location");
		return;
	}

	hr->has_location = TRUE;
	hr->location = value;
}

static void char_write_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	char *msg = user_data;

	if (status != 0)
		error("%s failed", msg);

	g_free(msg);
}

static void discover_ccc_cb(guint8 status, const guint8 *pdu,
						guint16 len, gpointer user_data)
{
	struct heartrate *hr = user_data;
	struct att_data_list *list;
	uint8_t format;
	int i;

	if (status != 0) {
		error("Discover Heart Rate Measurement descriptors failed: %s",
							att_ecode2str(status));
		return;
	}

	list = dec_find_info_resp(pdu, len, &format);
	if (list == NULL)
		return;

	if (format != ATT_FIND_INFO_RESP_FMT_16BIT)
		goto done;

	for (i = 0; i < list->num; i++) {
		uint8_t *value;
		uint16_t handle, uuid;

		value = list->data[i];
		handle = att_get_u16(value);
		uuid = att_get_u16(value + 2);

		if (uuid == GATT_CLIENT_CHARAC_CFG_UUID) {
			uint8_t value[2];
			char *msg;

			hr->measurement_ccc_handle = handle;

			if (g_slist_length(hr->hradapter->watchers) == 0)
				break;

			att_put_u16(GATT_CLIENT_CHARAC_CFG_NOTIF_BIT, value);
			msg = g_strdup("Enable measurement");

			gatt_write_char(hr->attrib, handle, value,
					sizeof(value), char_write_cb, msg);

			break;
		}
	}

done:
	att_data_list_free(list);
}

static void discover_measurement_ccc(struct heartrate *hr,
				struct gatt_char *c, struct gatt_char *c_next)
{
	uint16_t start, end;

	start = c->value_handle + 1;

	if (c_next != NULL) {
		if (start == c_next->handle)
			return;
		end = c_next->handle - 1;
	} else if (c->value_handle != hr->svc_range->end) {
		end = hr->svc_range->end;
	} else {
		return;
	}

	gatt_find_info(hr->attrib, start, end, discover_ccc_cb, hr);
}

static void discover_char_cb(GSList *chars, guint8 status, gpointer user_data)
{
	struct heartrate *hr = user_data;

	if (status) {
		error("Discover HRS characteristics failed: %s",
							att_ecode2str(status));
		return;
	}

	for (; chars; chars = chars->next) {
		struct gatt_char *c = chars->data;

		if (g_strcmp0(c->uuid, HEART_RATE_MEASUREMENT_UUID) == 0) {
			struct gatt_char *c_next =
				(chars->next ? chars->next->data : NULL);

			hr->measurement_val_handle = c->value_handle;

			discover_measurement_ccc(hr, c, c_next);
		} else if (g_strcmp0(c->uuid, BODY_SENSOR_LOCATION_UUID) == 0) {
			DBG("Body Sensor Location supported");

			gatt_read_char(hr->attrib, c->value_handle, 0,
						read_sensor_location_cb, hr);
		} else if (g_strcmp0(c->uuid,
					HEART_RATE_CONTROL_POINT_UUID) == 0) {
			DBG("Heart Rate Control Point supported");
			hr->hrcp_val_handle = c->value_handle;
		}
	}
}

static void enable_measurement(gpointer data, gpointer user_data)
{
	struct heartrate *hr = data;
	uint16_t handle = hr->measurement_ccc_handle;
	uint8_t value[2];
	char *msg;

	if (hr->attrib == NULL || !handle)
		return;

	att_put_u16(GATT_CLIENT_CHARAC_CFG_NOTIF_BIT, value);
	msg = g_strdup("Enable measurement");

	gatt_write_char(hr->attrib, handle, value, sizeof(value),
							char_write_cb, msg);
}

static void disable_measurement(gpointer data, gpointer user_data)
{
	struct heartrate *hr = data;
	uint16_t handle = hr->measurement_ccc_handle;
	uint8_t value[2];
	char *msg;

	if (hr->attrib == NULL || !handle)
		return;

	att_put_u16(0x0000, value);
	msg = g_strdup("Disable measurement");

	gatt_write_char(hr->attrib, handle, value, sizeof(value),
							char_write_cb, msg);
}

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct heartrate *hr = user_data;

	DBG("");

	hr->attrib = g_attrib_ref(attrib);

	gatt_discover_char(hr->attrib, hr->svc_range->start, hr->svc_range->end,
						NULL, discover_char_cb, hr);
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct heartrate *hr = user_data;

	DBG("");

	g_attrib_unref(hr->attrib);
	hr->attrib = NULL;
}

static void watcher_exit_cb(DBusConnection *conn, void *user_data)
{
	struct watcher *watcher = user_data;
	struct heartrate_adapter *hradapter = watcher->hradapter;

	DBG("heartrate watcher [%s] disconnected", watcher->path);

	hradapter->watchers = g_slist_remove(hradapter->watchers, watcher);
	g_dbus_remove_watch(conn, watcher->id);

	if (g_slist_length(hradapter->watchers) == 0)
		g_slist_foreach(hradapter->devices, disable_measurement, 0);
}

static DBusMessage *register_watcher(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct heartrate_adapter *hradapter = data;
	struct watcher *watcher;
	const char *sender = dbus_message_get_sender(msg);
	char *path;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	watcher = find_watcher(hradapter->watchers, sender, path);
	if (watcher != NULL)
		return btd_error_already_exists(msg);

	watcher = g_new0(struct watcher, 1);
	watcher->hradapter = hradapter;
	watcher->id = g_dbus_add_disconnect_watch(conn, sender, watcher_exit_cb,
						watcher, destroy_watcher);
	watcher->srv = g_strdup(sender);
	watcher->path = g_strdup(path);

	if (g_slist_length(hradapter->watchers) == 0)
		g_slist_foreach(hradapter->devices, enable_measurement, 0);

	hradapter->watchers = g_slist_prepend(hradapter->watchers, watcher);

	DBG("heartrate watcher [%s] registered", path);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_watcher(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct heartrate_adapter *hradapter = data;
	struct watcher *watcher;
	const char *sender = dbus_message_get_sender(msg);
	char *path;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	watcher = find_watcher(hradapter->watchers, sender, path);
	if (watcher == NULL)
		return btd_error_does_not_exist(msg);

	hradapter->watchers = g_slist_remove(hradapter->watchers, watcher);
	g_dbus_remove_watch(conn, watcher->id);

	if (g_slist_length(hradapter->watchers) == 0)
		g_slist_foreach(hradapter->devices, disable_measurement, 0);

	DBG("heartrate watcher [%s] unregistered", path);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable heartrate_manager_methods[] = {
	{ GDBUS_METHOD("RegisterWatcher",
			GDBUS_ARGS({ "agent", "o" }), NULL,
			register_watcher) },
	{ GDBUS_METHOD("UnregisterWatcher",
			GDBUS_ARGS({ "agent", "o" }), NULL,
			unregister_watcher) },
	{ }
};

int heartrate_adapter_register(struct btd_adapter *adapter)
{
	struct heartrate_adapter *hradapter;

	hradapter = g_new0(struct heartrate_adapter, 1);
	hradapter->adapter = adapter;

	heartrate_adapters = g_slist_prepend(heartrate_adapters, hradapter);

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
						adapter_get_path(adapter),
						HEART_RATE_MANAGER_INTERFACE,
						heartrate_manager_methods,
						NULL, NULL, hradapter,
						destroy_heartrate_adapter)) {
		error("D-Bus failed to register %s interface",
						HEART_RATE_MANAGER_INTERFACE);
		destroy_heartrate_adapter(hradapter);
		return -EIO;
	}

	return 0;
}

void heartrate_adapter_unregister(struct btd_adapter *adapter)
{
	struct heartrate_adapter *hradapter;

	hradapter = find_heartrate_adapter(adapter);
	if (hradapter == NULL)
		return;

	heartrate_adapters = g_slist_remove(heartrate_adapters, hradapter);

	g_dbus_unregister_interface(btd_get_dbus_connection(),
					adapter_get_path(hradapter->adapter),
					HEART_RATE_MANAGER_INTERFACE);
}

int heartrate_device_register(struct btd_device *device,
						struct gatt_primary *prim)
{
	struct btd_adapter *adapter;
	struct heartrate_adapter *hradapter;
	struct heartrate *hr;

	adapter = device_get_adapter(device);

	hradapter = find_heartrate_adapter(adapter);

	if (hradapter == NULL)
		return -1;

	hr = g_new0(struct heartrate, 1);
	hr->dev = btd_device_ref(device);
	hr->hradapter = hradapter;

	hr->svc_range = g_new0(struct att_range, 1);
	hr->svc_range->start = prim->range.start;
	hr->svc_range->end = prim->range.end;

	hradapter->devices = g_slist_prepend(hradapter->devices, hr);

	hr->attioid = btd_device_add_attio_callback(device, attio_connected_cb,
						attio_disconnected_cb, hr);

	return 0;
}

void heartrate_device_unregister(struct btd_device *device)
{
	struct btd_adapter *adapter;
	struct heartrate_adapter *hradapter;
	struct heartrate *hr;
	GSList *l;

	adapter = device_get_adapter(device);

	hradapter = find_heartrate_adapter(adapter);
	if (hradapter == NULL)
		return;

	l = g_slist_find_custom(hradapter->devices, device, cmp_device);
	if (l == NULL)
		return;

	hr = l->data;

	hradapter->devices = g_slist_remove(hradapter->devices, hr);

	destroy_heartrate(hr);
}
