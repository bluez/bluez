/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *  Copyright (C) 2011  Marcel Holtmann <marcel@holtmann.org>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <errno.h>
#include <gdbus.h>
#include <glib.h>
#include <bluetooth/uuid.h>

#include "dbus-common.h"
#include "att.h"
#include "adapter.h"
#include "device.h"
#include "att-database.h"
#include "log.h"
#include "gatt-service.h"
#include "gattrib.h"
#include "attrib-server.h"
#include "gatt.h"
#include "server.h"
#include "profile.h"
#include "error.h"

#define PHONE_ALERT_STATUS_SVC_UUID		0x180E
#define ALERT_NOTIF_SVC_UUID			0x1811

#define ALERT_STATUS_CHR_UUID		0x2A3F
#define RINGER_CP_CHR_UUID		0x2A40
#define RINGER_SETTING_CHR_UUID		0x2A41

#define ALERT_NOTIF_CP_CHR_UUID		0x2A44
#define UNREAD_ALERT_CHR_UUID		0x2A45
#define NEW_ALERT_CHR_UUID		0x2A46
#define SUPP_NEW_ALERT_CAT_CHR_UUID	0x2A47
#define SUPP_UNREAD_ALERT_CAT_CHR_UUID	0x2A48

#define ALERT_OBJECT_PATH "/org/bluez"
#define ALERT_INTERFACE   "org.bluez.Alert"

/* Maximum length for "Text String Information" */
#define NEW_ALERT_MAX_INFO_SIZE		18

enum {
	ENABLE_NEW_INCOMING,
	ENABLE_UNREAD_CAT,
	DISABLE_NEW_INCOMING,
	DISABLE_UNREAD_CAT,
	NOTIFY_NEW_INCOMING,
	NOTIFY_UNREAD_CAT,
};

/* Ringer Setting characteristic values */
enum {
	RINGER_SILENT,
	RINGER_NORMAL,
};

struct alert_data {
	const char *category;
	char *srv;
	char *path;
	guint watcher;
};

static GSList *registered_alerts = NULL;
static uint8_t ringer_setting = RINGER_NORMAL;
static uint8_t alert_status = 0;

static const char * const anp_categories[] = {
	"simple",
	"email",
	"news",
	"call",
	"missed-call",
	"sms-mms",
	"voice-mail",
	"schedule",
	"high-priority",
	"instant-message",
};

static const char * const pasp_categories[] = {
	"ringer",
	"vibrate",
	"display",
};

static void alert_data_destroy(gpointer user_data)
{
	struct alert_data *alert = user_data;

	if (alert->watcher)
		g_dbus_remove_watch(btd_get_dbus_connection(), alert->watcher);

	g_free(alert->srv);
	g_free(alert->path);
	g_free(alert);
}

static void alert_destroy(gpointer user_data)
{
	g_slist_free_full(registered_alerts, alert_data_destroy);
	registered_alerts = NULL;
}

static const char *valid_category(const char *category)
{
	unsigned i;

	for (i = 0; i < G_N_ELEMENTS(anp_categories); i++) {
		if (g_str_equal(anp_categories[i], category))
			return anp_categories[i];
	}

	for (i = 0; i < G_N_ELEMENTS(pasp_categories); i++) {
		if (g_str_equal(pasp_categories[i], category))
			return pasp_categories[i];
	}

	return NULL;
}

static struct alert_data *get_alert_data_by_category(const char *category)
{
	GSList *l;
	struct alert_data *alert;

	for (l = registered_alerts; l; l = g_slist_next(l)) {
		alert = l->data;
		if (g_str_equal(alert->category, category))
			return alert;
	}

	return NULL;
}

static gboolean registered_category(const char *category)
{
	struct alert_data *alert;

	alert = get_alert_data_by_category(category);
	if (alert)
		return TRUE;

	return FALSE;
}

static gboolean pasp_category(const char *category)
{
	unsigned i;

	for (i = 0; i < G_N_ELEMENTS(pasp_categories); i++)
		if (g_str_equal(category, pasp_categories[i]))
			return TRUE;

	return FALSE;
}

static gboolean valid_description(const char *category,
							const char *description)
{
	if (!pasp_category(category)) {
		if (strlen(description) >= NEW_ALERT_MAX_INFO_SIZE)
			return FALSE;

		return TRUE;
	}

	if (g_str_equal(description, "active") ||
					g_str_equal(description, "not active"))
		return TRUE;

	if (g_str_equal(category, "ringer"))
		if (g_str_equal(description, "enabled") ||
					g_str_equal(description, "disabled"))
			return TRUE;

	return FALSE;
}

static gboolean valid_count(const char *category, uint16_t count)
{
	if (!pasp_category(category) && count > 0 && count <= 255)
		return TRUE;

	if (pasp_category(category) && count == 1)
		return TRUE;

	return FALSE;
}

static void watcher_disconnect(DBusConnection *conn, void *user_data)
{
	struct alert_data *alert = user_data;

	DBG("Category %s was disconnected", alert->category);

	registered_alerts = g_slist_remove(registered_alerts, alert);
	alert_data_destroy(alert);
}

static DBusMessage *register_alert(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	const char *sender = dbus_message_get_sender(msg);
	char *path;
	const char *category;
	const char *c;
	struct alert_data *alert;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &c,
			DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	category = valid_category(c);
	if (!category) {
		DBG("Invalid category: %s", c);
		return btd_error_invalid_args(msg);
	}

	if (registered_category(category)) {
		DBG("Category %s already registered", category);
		return dbus_message_new_method_return(msg);
	}

	alert = g_new0(struct alert_data, 1);
	alert->srv = g_strdup(sender);
	alert->path = g_strdup(path);
	alert->category = category;
	alert->watcher = g_dbus_add_disconnect_watch(conn, alert->srv,
					watcher_disconnect, alert, NULL);

	if (alert->watcher == 0) {
		alert_data_destroy(alert);
		DBG("Could not register disconnect watcher");
		return btd_error_failed(msg,
				"Could not register disconnect watcher");
	}

	registered_alerts = g_slist_append(registered_alerts, alert);

	DBG("RegisterAlert(\"%s\", \"%s\")", alert->category, alert->path);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *new_alert(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	const char *sender = dbus_message_get_sender(msg);
	const char *category, *description;
	struct alert_data *alert;
	uint16_t count;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &category,
			DBUS_TYPE_UINT16, &count, DBUS_TYPE_STRING,
			&description, DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	alert = get_alert_data_by_category(category);
	if (!alert) {
		DBG("Category %s not registered", category);
		return btd_error_invalid_args(msg);
	}

	if (!g_str_equal(alert->srv, sender)) {
		DBG("Sender %s is not registered in category %s", sender,
								category);
		return btd_error_invalid_args(msg);
	}

	if (!valid_description(category, description)) {
		DBG("Description %s is invalid for %s category",
							description, category);
		return btd_error_invalid_args(msg);
	}

	if (!valid_count(category, count)) {
		DBG("Count %d is invalid for %s category", count, category);
		return btd_error_invalid_args(msg);
	}

	DBG("NewAlert(\"%s\", %d, \"%s\")", category, count, description);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *unread_alert(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	const char *sender = dbus_message_get_sender(msg);
	struct alert_data *alert;
	const char *category;
	uint16_t count;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &category,
						DBUS_TYPE_UINT16, &count,
						DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	alert = get_alert_data_by_category(category);
	if (!alert) {
		DBG("Category %s not registered", category);
		return btd_error_invalid_args(msg);
	}

	if (!g_str_equal(alert->srv, sender)) {
		DBG("Sender %s is not registered in category %s", sender,
								category);
		return btd_error_invalid_args(msg);
	}

	DBG("category %s, count %d", category, count);

	return dbus_message_new_method_return(msg);
}

static uint8_t ringer_cp_write(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	DBG("a = %p", a);

	return 0;
}

static uint8_t alert_status_read(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	struct btd_adapter *adapter = user_data;

	DBG("a = %p", a);

	if (a->data == NULL || a->data[0] != alert_status)
		attrib_db_update(adapter, a->handle, NULL, &alert_status,
						sizeof(alert_status), NULL);

	return 0;
}

static uint8_t ringer_setting_read(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	struct btd_adapter *adapter = user_data;

	DBG("a = %p", a);

	if (a->data == NULL || a->data[0] != ringer_setting)
		attrib_db_update(adapter, a->handle, NULL, &ringer_setting,
						sizeof(ringer_setting), NULL);

	return 0;
}

static void register_phone_alert_service(struct btd_adapter *adapter)
{
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, PHONE_ALERT_STATUS_SVC_UUID);

	/* Phone Alert Status Service */
	gatt_service_add(adapter, GATT_PRIM_SVC_UUID, &uuid,
			/* Alert Status characteristic */
			GATT_OPT_CHR_UUID, ALERT_STATUS_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ |
							ATT_CHAR_PROPER_NOTIFY,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
			alert_status_read, adapter,
			/* Ringer Control Point characteristic */
			GATT_OPT_CHR_UUID, RINGER_CP_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_WRITE_WITHOUT_RESP,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_WRITE,
			ringer_cp_write, NULL,
			/* Ringer Setting characteristic */
			GATT_OPT_CHR_UUID, RINGER_SETTING_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ |
							ATT_CHAR_PROPER_NOTIFY,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
			ringer_setting_read, adapter,
			GATT_OPT_INVALID);
}

static uint8_t supp_new_alert_cat_read(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	struct btd_adapter *adapter = user_data;
	uint8_t value[] = {0x00, 0x00};

	DBG("a = %p", a);

	if (a->data == NULL)
		attrib_db_update(adapter, a->handle, NULL, value, sizeof(value),
									NULL);

	return 0;
}

static uint8_t supp_unread_alert_cat_read(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	struct btd_adapter *adapter = user_data;
	uint8_t value[] = {0x00, 0x00};

	DBG("a = %p", a);

	if (a->data == NULL)
		attrib_db_update(adapter, a->handle, NULL, value, sizeof(value),
									NULL);

	return 0;
}

static uint8_t alert_notif_cp_write(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	DBG("a = %p", a);

	switch (a->data[0]) {
	case ENABLE_NEW_INCOMING:
		DBG("ENABLE_NEW_INCOMING: 0x%02x", a->data[1]);
		break;
	case ENABLE_UNREAD_CAT:
		DBG("ENABLE_UNREAD_CAT: 0x%02x", a->data[1]);
		break;
	case DISABLE_NEW_INCOMING:
		DBG("DISABLE_NEW_INCOMING: 0x%02x", a->data[1]);
		break;
	case DISABLE_UNREAD_CAT:
		DBG("DISABLE_UNREAD_CAT: 0x%02x", a->data[1]);
		break;
	case NOTIFY_NEW_INCOMING:
		DBG("NOTIFY_NEW_INCOMING: 0x%02x", a->data[1]);
		break;
	case NOTIFY_UNREAD_CAT:
		DBG("NOTIFY_UNREAD_CAT: 0x%02x", a->data[1]);
		break;
	default:
		DBG("0x%02x 0x%02x", a->data[0], a->data[1]);
	}

	return 0;
}

static void register_alert_notif_service(struct btd_adapter *adapter)
{
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, ALERT_NOTIF_SVC_UUID);

	/* Alert Notification Service */
	gatt_service_add(adapter, GATT_PRIM_SVC_UUID, &uuid,
			/* Supported New Alert Category */
			GATT_OPT_CHR_UUID, SUPP_NEW_ALERT_CAT_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
			supp_new_alert_cat_read, adapter,
			/* New Alert */
			GATT_OPT_CHR_UUID, NEW_ALERT_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_NOTIFY,
			/* Supported Unread Alert Category */
			GATT_OPT_CHR_UUID, SUPP_UNREAD_ALERT_CAT_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
			supp_unread_alert_cat_read, adapter,
			/* Unread Alert Status */
			GATT_OPT_CHR_UUID, UNREAD_ALERT_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_NOTIFY,
			/* Alert Notification Control Point */
			GATT_OPT_CHR_UUID, ALERT_NOTIF_CP_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_WRITE,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_WRITE,
			alert_notif_cp_write, NULL,
			GATT_OPT_INVALID);
}

static int alert_server_probe(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	register_phone_alert_service(adapter);
	register_alert_notif_service(adapter);

	return 0;
}

static void alert_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
}

static struct btd_profile alert_profile = {
	.name = "gatt-alert-server",
	.adapter_probe = alert_server_probe,
	.adapter_remove = alert_server_remove,
};

static const GDBusMethodTable alert_methods[] = {
	{ GDBUS_METHOD("RegisterAlert",
			GDBUS_ARGS({ "category", "s" },
				   { "agent", "o" }), NULL,
			register_alert) },
	{ GDBUS_METHOD("NewAlert",
			GDBUS_ARGS({ "category", "s" },
				   { "count", "q" },
				   { "description", "s" }), NULL,
			new_alert) },
	{ GDBUS_METHOD("UnreadAlert",
			GDBUS_ARGS({ "category", "s" }, { "count", "q" }), NULL,
			unread_alert) },
	{ }
};

int alert_server_init(void)
{
	if (!g_dbus_register_interface(btd_get_dbus_connection(),
					ALERT_OBJECT_PATH, ALERT_INTERFACE,
					alert_methods, NULL, NULL, NULL,
					alert_destroy)) {
		error("D-Bus failed to register %s interface",
							ALERT_INTERFACE);
		return -EIO;
	}

	btd_profile_register(&alert_profile);

	return 0;
}

void alert_server_exit(void)
{
	btd_profile_unregister(&alert_profile);

	g_dbus_unregister_interface(btd_get_dbus_connection(),
					ALERT_OBJECT_PATH, ALERT_INTERFACE);
}
