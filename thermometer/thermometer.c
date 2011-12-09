/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011 GSyC/LibreSoft, Universidad Rey Juan Carlos.
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
#include <bluetooth/uuid.h>

#include "dbus-common.h"
#include "adapter.h"
#include "device.h"
#include "error.h"
#include "log.h"
#include "gattrib.h"
#include "attio.h"
#include "att.h"
#include "gatt.h"
#include "thermometer.h"
#include "glib-compat.h"

#define THERMOMETER_INTERFACE "org.bluez.Thermometer"

#define TEMPERATURE_MEASUREMENT_UUID	"00002a1c-0000-1000-8000-00805f9b34fb"
#define TEMPERATURE_TYPE_UUID		"00002a1d-0000-1000-8000-00805f9b34fb"
#define INTERMEDIATE_TEMPERATURE_UUID	"00002a1e-0000-1000-8000-00805f9b34fb"
#define MEASUREMENT_INTERVAL_UUID	"00002a21-0000-1000-8000-00805f9b34fb"

/* Temperature measurement flag fields */
#define TEMP_UNITS		0x01
#define TEMP_TIME_STAMP		0x02
#define TEMP_TYPE		0x04

#define FLOAT_MAX_MANTISSA	16777216 /* 2^24 */

struct thermometer {
	DBusConnection		*conn;		/* The connection to the bus */
	struct btd_device	*dev;		/* Device reference */
	GAttrib			*attrib;	/* GATT connection */
	struct att_range	*svc_range;	/* Thermometer range */
	guint			attioid;	/* Att watcher id */
	guint			attindid;	/* Att incications id */
	guint			attnotid;	/* Att notifications id */
	GSList			*chars;		/* Characteristics */
	GSList			*fwatchers;     /* Final measurements */
	GSList			*iwatchers;     /* Intermediate measurements */
	gboolean		intermediate;
	uint8_t			type;
	uint16_t		interval;
	uint16_t		max;
	uint16_t		min;
	gboolean		has_type;
	gboolean		has_interval;
};

struct characteristic {
	struct att_char		attr;	/* Characteristic */
	GSList			*desc;	/* Descriptors */
	struct thermometer	*t;	/* Thermometer where the char belongs */
};

struct descriptor {
	struct characteristic	*ch;
	uint16_t		handle;
	bt_uuid_t		uuid;
};

struct watcher {
	struct thermometer	*t;
	guint			id;
	char			*srv;
	char			*path;
};

struct measurement {
	int16_t		exp;
	int32_t		mant;
	uint64_t	time;
	gboolean	suptime;
	char		*unit;
	char		*type;
	char		*value;
};

struct tmp_interval_data {
	struct thermometer	*thermometer;
	uint16_t		interval;
};

static GSList *thermometers = NULL;

const char *temp_type[] = {
	"<reserved>",
	"Armpit",
	"Body",
	"Ear",
	"Finger",
	"Intestines",
	"Mouth",
	"Rectum",
	"Toe",
	"Tympanum"
};

static const gchar *temptype2str(uint8_t value)
{
	 if (value > 0 && value < G_N_ELEMENTS(temp_type))
		return temp_type[value];

	error("Temperature type %d reserved for future use", value);
	return NULL;
}

static void destroy_watcher(gpointer user_data)
{
	struct watcher *watcher = user_data;

	if (watcher->id > 0)
		g_dbus_remove_watch(watcher->t->conn, watcher->id);

	g_free(watcher->path);
	g_free(watcher->srv);
	g_free(watcher);
}

static void destroy_char(gpointer user_data)
{
	struct characteristic *c = user_data;

	g_slist_free_full(c->desc, g_free);
	g_free(c);
}

static void destroy_thermometer(gpointer user_data)
{
	struct thermometer *t = user_data;

	if (t->attioid > 0)
		btd_device_remove_attio_callback(t->dev, t->attioid);

	if (t->attindid > 0)
		g_attrib_unregister(t->attrib, t->attindid);

	if (t->attnotid > 0)
		g_attrib_unregister(t->attrib, t->attnotid);

	if (t->attrib != NULL)
		g_attrib_unref(t->attrib);

	if (t->chars != NULL)
		g_slist_free_full(t->chars, destroy_char);

	if (t->fwatchers != NULL)
		g_slist_free_full(t->fwatchers, destroy_watcher);

	dbus_connection_unref(t->conn);
	btd_device_unref(t->dev);
	g_free(t->svc_range);
	g_free(t);
}

static gint cmp_device(gconstpointer a, gconstpointer b)
{
	const struct thermometer *t = a;
	const struct btd_device *dev = b;

	if (dev == t->dev)
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

static gint cmp_char_uuid(gconstpointer a, gconstpointer b)
{
	const struct characteristic *ch = a;
	const char *uuid = b;

	return g_strcmp0(ch->attr.uuid, uuid);
}

static gint cmp_char_val_handle(gconstpointer a, gconstpointer b)
{
	const struct characteristic *ch = a;
	const uint16_t *handle = b;

	return ch->attr.value_handle - *handle;
}

static gint cmp_descriptor(gconstpointer a, gconstpointer b)
{
	const struct descriptor *desc = a;
	const bt_uuid_t *uuid = b;

	return bt_uuid_cmp(&desc->uuid, uuid);
}

static struct characteristic *get_characteristic(struct thermometer *t,
							const char *uuid)
{
	GSList *l;

	l = g_slist_find_custom(t->chars, uuid, cmp_char_uuid);
	if (l == NULL)
		return NULL;

	return l->data;
}

static struct descriptor *get_descriptor(struct characteristic *ch,
							const bt_uuid_t *uuid)
{
	GSList *l;

	l = g_slist_find_custom(ch->desc, uuid, cmp_descriptor);
	if (l == NULL)
		return NULL;

	return l->data;
}

static void change_property(struct thermometer *t, const char *name,
							gpointer value) {
	if (g_strcmp0(name, "Intermediate") == 0) {
		gboolean *intermediate = value;
		if (t->intermediate == *intermediate)
			return;

		t->intermediate = *intermediate;
		emit_property_changed(t->conn, device_get_path(t->dev),
					THERMOMETER_INTERFACE, name,
					DBUS_TYPE_BOOLEAN, &t->intermediate);
	} else if (g_strcmp0(name, "Interval") == 0) {
		uint16_t *interval = value;
		if (t->has_interval && t->interval == *interval)
			return;

		t->has_interval = TRUE;
		t->interval = *interval;
		emit_property_changed(t->conn, device_get_path(t->dev),
					THERMOMETER_INTERFACE, name,
					DBUS_TYPE_UINT16, &t->interval);
	} else if (g_strcmp0(name, "Maximum") == 0) {
		uint16_t *max = value;
		if (t->max == *max)
			return;

		t->max = *max;
		emit_property_changed(t->conn, device_get_path(t->dev),
					THERMOMETER_INTERFACE, name,
					DBUS_TYPE_UINT16, &t->max);
	} else if (g_strcmp0(name, "Minimum") == 0) {
		uint16_t *min = value;
		if (t->min == *min)
			return;

		t->min = *min;
		emit_property_changed(t->conn, device_get_path(t->dev),
					THERMOMETER_INTERFACE, name,
					DBUS_TYPE_UINT16, &t->min);
	} else
		DBG("%s is not a thermometer property", name);
}

static void valid_range_desc_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct descriptor *desc = user_data;
	uint8_t value[ATT_MAX_MTU];
	uint16_t max, min;
	int vlen;

	if (status != 0) {
		DBG("Valid Range descriptor read failed: %s",
							att_ecode2str(status));
		return;
	}

	if (!dec_read_resp(pdu, len, value, &vlen)) {
		DBG("Protocol error\n");
		return;
	}

	if (vlen < 4) {
		DBG("Invalid range received");
		return;
	}

	min = att_get_u16(&value[0]);
	max = att_get_u16(&value[2]);

	if (min == 0 || min > max) {
		DBG("Invalid range");
		return;
	}

	change_property(desc->ch->t, "Maximum", &max);
	change_property(desc->ch->t, "Minimum", &min);
}

static void process_thermometer_desc(struct descriptor *desc)
{
	struct characteristic *ch = desc->ch;
	char uuidstr[MAX_LEN_UUID_STR];
	bt_uuid_t btuuid;

	bt_uuid16_create(&btuuid, GATT_CLIENT_CHARAC_CFG_UUID);

	if (bt_uuid_cmp(&desc->uuid, &btuuid) == 0) {
		uint8_t atval[2];
		uint16_t val;

		if (g_strcmp0(ch->attr.uuid,
					TEMPERATURE_MEASUREMENT_UUID) == 0) {
			if (g_slist_length(ch->t->fwatchers) == 0)
				return;

			val = ATT_CLIENT_CHAR_CONF_INDICATION;
		} else if (g_strcmp0(ch->attr.uuid,
					INTERMEDIATE_TEMPERATURE_UUID) == 0) {
			if (g_slist_length(ch->t->iwatchers) == 0)
				return;

			val = ATT_CLIENT_CHAR_CONF_NOTIFICATION;
		} else if (g_strcmp0(ch->attr.uuid,
					MEASUREMENT_INTERVAL_UUID) == 0)
			val = ATT_CLIENT_CHAR_CONF_INDICATION;
		else
			goto done;

		att_put_u16(val, atval);
		gatt_write_char(ch->t->attrib, desc->handle, atval, 2,
								NULL, NULL);
		return;
	}

	bt_uuid16_create(&btuuid, GATT_CHARAC_VALID_RANGE_UUID);

	if (bt_uuid_cmp(&desc->uuid, &btuuid) == 0 && g_strcmp0(ch->attr.uuid,
					MEASUREMENT_INTERVAL_UUID) == 0) {
		gatt_read_char(ch->t->attrib, desc->handle, 0,
						valid_range_desc_cb, desc);
		return;
	}

done:
	bt_uuid_to_string(&desc->uuid, uuidstr, MAX_LEN_UUID_STR);
	DBG("Ignored descriptor %s in characteristic %s", uuidstr,
								ch->attr.uuid);
}

static void discover_desc_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct characteristic *ch = user_data;
	struct att_data_list *list;
	uint8_t format;
	int i;

	if (status != 0) {
		error("Discover all characteristic descriptors failed [%s]: %s",
					ch->attr.uuid, att_ecode2str(status));
		return;
	}

	list = dec_find_info_resp(pdu, len, &format);
	if (list == NULL)
		return;

	for (i = 0; i < list->num; i++) {
		struct descriptor *desc;
		uint8_t *value;

		value = list->data[i];
		desc = g_new0(struct descriptor, 1);
		desc->handle = att_get_u16(value);
		desc->ch = ch;

		if (format == 0x01)
			desc->uuid = att_get_uuid16(&value[2]);
		else
			desc->uuid = att_get_uuid128(&value[2]);

		ch->desc = g_slist_append(ch->desc, desc);
		process_thermometer_desc(desc);
	}

	att_data_list_free(list);
}

static void read_temp_type_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct characteristic *ch = user_data;
	struct thermometer *t = ch->t;
	uint8_t value[ATT_MAX_MTU];
	int vlen;

	if (status != 0) {
		DBG("Temperature Type value read failed: %s",
							att_ecode2str(status));
		return;
	}

	if (!dec_read_resp(pdu, len, value, &vlen)) {
		DBG("Protocol error.");
		return;
	}

	if (vlen != 1) {
		DBG("Invalid length for Temperature type");
		return;
	}

	t->has_type = TRUE;
	t->type = value[0];
}

static void read_interval_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct characteristic *ch = user_data;
	uint8_t value[ATT_MAX_MTU];
	uint16_t interval;
	int vlen;

	if (status != 0) {
		DBG("Measurement Interval value read failed: %s",
							att_ecode2str(status));
		return;
	}

	if (!dec_read_resp(pdu, len, value, &vlen)) {
		DBG("Protocol error\n");
		return;
	}

	if (vlen < 2) {
		DBG("Invalid Interval received");
		return;
	}

	interval = att_get_u16(&value[0]);
	change_property(ch->t, "Interval", &interval);
}

static void process_thermometer_char(struct characteristic *ch)
{
	if (g_strcmp0(ch->attr.uuid, INTERMEDIATE_TEMPERATURE_UUID) == 0) {
		gboolean intermediate = TRUE;
		change_property(ch->t, "Intermediate", &intermediate);
		return;
	} else if (g_strcmp0(ch->attr.uuid, TEMPERATURE_TYPE_UUID) == 0)
		gatt_read_char(ch->t->attrib, ch->attr.value_handle, 0,
							read_temp_type_cb, ch);
	else if (g_strcmp0(ch->attr.uuid, MEASUREMENT_INTERVAL_UUID) == 0)
		gatt_read_char(ch->t->attrib, ch->attr.value_handle, 0,
							read_interval_cb, ch);
}

static void configure_thermometer_cb(GSList *characteristics, guint8 status,
							gpointer user_data)
{
	struct thermometer *t = user_data;
	GSList *l;

	if (status != 0) {
		error("Discover thermometer characteristics: %s",
							att_ecode2str(status));
		return;
	}

	for (l = characteristics; l; l = l->next) {
		struct att_char *c = l->data;
		struct characteristic *ch;
		uint16_t start, end;

		ch = g_new0(struct characteristic, 1);
		ch->attr.handle = c->handle;
		ch->attr.properties = c->properties;
		ch->attr.value_handle = c->value_handle;
		memcpy(ch->attr.uuid, c->uuid, MAX_LEN_UUID_STR + 1);
		ch->t = t;

		t->chars = g_slist_append(t->chars, ch);

		process_thermometer_char(ch);

		start = c->value_handle + 1;

		if (l->next != NULL) {
			struct att_char *c = l->next->data;
			if (start == c->handle)
				continue;
			end = c->handle - 1;
		} else if (c->value_handle != t->svc_range->end)
			end = t->svc_range->end;
		else
			continue;

		gatt_find_info(t->attrib, start, end, discover_desc_cb, ch);
	}
}

static DBusMessage *get_properties(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct thermometer *t = data;
	DBusMessageIter iter;
	DBusMessageIter dict;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dict_append_entry(&dict, "Intermediate", DBUS_TYPE_BOOLEAN,
							&t->intermediate);

	if (t->has_interval) {
		dict_append_entry(&dict, "Interval", DBUS_TYPE_UINT16,
								&t->interval);
		dict_append_entry(&dict, "Maximum", DBUS_TYPE_UINT16, &t->max);
		dict_append_entry(&dict, "Minimum", DBUS_TYPE_UINT16, &t->min);
	}

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static void write_interval_cb (guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct tmp_interval_data *data = user_data;

	if (status != 0) {
		error("Interval Write Request failed %s",
							att_ecode2str(status));
		goto done;
	}

	if (!dec_write_resp(pdu, len)) {
		error("Interval Write Request: protocol error");
		goto done;
	}

	change_property(data->thermometer, "Interval", &data->interval);

done:
	g_free(user_data);
}

static DBusMessage *write_attr_interval(struct thermometer *t, DBusMessage *msg,
								uint16_t value)
{
	struct tmp_interval_data *data;
	struct characteristic *ch;
	uint8_t atval[2];

	if (t->attrib == NULL)
		return btd_error_not_connected(msg);

	ch = get_characteristic(t, MEASUREMENT_INTERVAL_UUID);
	if (ch == NULL)
		return btd_error_not_available(msg);

	if (value < t->min || value > t->max)
		return btd_error_invalid_args(msg);

	att_put_u16(value, &atval[0]);

	data = g_new0(struct tmp_interval_data, 1);
	data->thermometer = t;
	data->interval = value;
	gatt_write_char(t->attrib, ch->attr.value_handle, atval, 2,
						write_interval_cb, data);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *set_property(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct thermometer *t = data;
	const char *property;
	DBusMessageIter iter;
	DBusMessageIter sub;
	uint16_t value;

	if (!dbus_message_iter_init(msg, &iter))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &property);
	if (g_strcmp0("Interval", property) != 0)
		return btd_error_invalid_args(msg);

	if (!t->has_interval)
		return btd_error_not_available(msg);

	dbus_message_iter_next(&iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return btd_error_invalid_args(msg);

	dbus_message_iter_recurse(&iter, &sub);

	if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_UINT16)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&sub, &value);

	return write_attr_interval(t, msg, value);
}

static void measurement_cb(guint8 status, const guint8 *pdu,
						guint16 len, gpointer user_data)
{
	char *msg = user_data;

	if (status != 0)
		error("%s failed", msg);

	g_free(msg);
}

static void enable_final_measurement(struct thermometer *t)
{
	struct characteristic *ch;
	struct descriptor *desc;
	bt_uuid_t btuuid;
	uint8_t atval[2];
	char *msg;

	if (t->attrib == NULL)
		return;

	ch = get_characteristic(t, TEMPERATURE_MEASUREMENT_UUID);
	if (ch == NULL) {
		DBG("Temperature measurement characteristic not found");
		return;
	}

	bt_uuid16_create(&btuuid, GATT_CLIENT_CHARAC_CFG_UUID);
	desc = get_descriptor(ch, &btuuid);
	if (desc == NULL) {
		DBG("Client characteristic configuration descriptor not found");
		return;
	}

	atval[0] = 0x02;
	atval[1] = 0x00;
	msg = g_strdup("Enable final measurement");
	gatt_write_char(t->attrib, desc->handle, atval, 2, measurement_cb, msg);
}

static void enable_intermediate_measurement(struct thermometer *t)
{
	struct characteristic *ch;
	struct descriptor *desc;
	bt_uuid_t btuuid;
	uint8_t atval[2];
	char *msg;

	if (t->attrib == NULL)
		return;

	ch = get_characteristic(t, INTERMEDIATE_TEMPERATURE_UUID);
	if (ch == NULL) {
		DBG("Intermediate measurement characteristic not found");
		return;
	}

	bt_uuid16_create(&btuuid, GATT_CLIENT_CHARAC_CFG_UUID);
	desc = get_descriptor(ch, &btuuid);
	if (desc == NULL) {
		DBG("Client characteristic configuration descriptor not found");
		return;
	}

	atval[0] = 0x01;
	atval[1] = 0x00;
	msg = g_strdup("Enable intermediate measurement");
	gatt_write_char(t->attrib, desc->handle, atval, 2, measurement_cb, msg);
}

static void disable_final_measurement(struct thermometer *t)
{
	struct characteristic *ch;
	struct descriptor *desc;
	bt_uuid_t btuuid;
	uint8_t atval[2];
	char *msg;

	if (t->attrib == NULL)
		return;

	ch = get_characteristic(t, TEMPERATURE_MEASUREMENT_UUID);
	if (ch == NULL) {
		DBG("Temperature measurement characteristic not found");
		return;
	}

	bt_uuid16_create(&btuuid, GATT_CLIENT_CHARAC_CFG_UUID);
	desc = get_descriptor(ch, &btuuid);
	if (desc == NULL) {
		DBG("Client characteristic configuration descriptor not found");
		return;
	}

	atval[0] = 0x00;
	atval[1] = 0x00;
	msg = g_strdup("Disable final measurement");
	gatt_write_char(t->attrib, desc->handle, atval, 2, measurement_cb, msg);
}

static void disable_intermediate_measurement(struct thermometer *t)
{
	struct characteristic *ch;
	struct descriptor *desc;
	bt_uuid_t btuuid;
	uint8_t atval[2];
	char *msg;

	if (t->attrib == NULL)
		return;

	ch = get_characteristic(t, INTERMEDIATE_TEMPERATURE_UUID);
	if (ch == NULL) {
		DBG("Intermediate measurement characteristic not found");
		return;
	}

	bt_uuid16_create(&btuuid, GATT_CLIENT_CHARAC_CFG_UUID);
	desc = get_descriptor(ch, &btuuid);
	if (desc == NULL) {
		DBG("Client characteristic configuration descriptor not found");
		return;
	}

	atval[0] = 0x00;
	atval[1] = 0x00;
	msg = g_strdup("Disable intermediate measurement");
	gatt_write_char(t->attrib, desc->handle, atval, 2, measurement_cb, msg);
}

static void remove_int_watcher(struct thermometer *t, struct watcher *w)
{
	if (!g_slist_find(t->iwatchers, w))
		return;

	t->iwatchers = g_slist_remove(t->iwatchers, w);

	if (g_slist_length(t->iwatchers) == 0)
		disable_intermediate_measurement(t);
}

static void watcher_exit(DBusConnection *conn, void *user_data)
{
	struct watcher *watcher = user_data;
	struct thermometer *t = watcher->t;

	DBG("Thermometer watcher %s disconnected", watcher->path);

	remove_int_watcher(t, watcher);

	t->fwatchers = g_slist_remove(t->fwatchers, watcher);
	watcher->id = 0;

	if (g_slist_length(t->fwatchers) == 0)
		disable_final_measurement(t);
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

static DBusMessage *register_watcher(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	const char *sender = dbus_message_get_sender(msg);
	struct thermometer *t = data;
	struct watcher *watcher;
	char *path;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	watcher = find_watcher(t->fwatchers, sender, path);
	if (watcher != NULL)
		return btd_error_already_exists(msg);

	DBG("Thermometer watcher %s registered", path);

	watcher = g_new0(struct watcher, 1);
	watcher->srv = g_strdup(sender);
	watcher->path = g_strdup(path);
	watcher->t = t;
	watcher->id = g_dbus_add_disconnect_watch(conn, sender, watcher_exit,
						watcher, destroy_watcher);

	if (g_slist_length(t->fwatchers) == 0)
		enable_final_measurement(t);

	t->fwatchers = g_slist_prepend(t->fwatchers, watcher);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_watcher(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	const char *sender = dbus_message_get_sender(msg);
	struct thermometer *t = data;
	struct watcher *watcher;
	char *path;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	watcher = find_watcher(t->fwatchers, sender, path);
	if (watcher == NULL)
		return btd_error_does_not_exist(msg);

	DBG("Thermometer watcher %s unregistered", path);

	remove_int_watcher(t, watcher);

	t->fwatchers = g_slist_remove(t->fwatchers, watcher);
	destroy_watcher(watcher);

	if (g_slist_length(t->fwatchers) == 0)
		disable_final_measurement(t);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *enable_intermediate(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	const char *sender = dbus_message_get_sender(msg);
	struct thermometer *t = data;
	struct watcher *watcher;
	char *path;

	if (!t->intermediate)
		return btd_error_not_supported(msg);

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	watcher = find_watcher(t->fwatchers, sender, path);
	if (watcher == NULL)
		return btd_error_does_not_exist(msg);

	if (find_watcher(t->iwatchers, sender, path))
		return btd_error_already_exists(msg);

	DBG("Intermediate measurement watcher %s registered", path);

	if (g_slist_length(t->iwatchers) == 0)
		enable_intermediate_measurement(t);

	t->iwatchers = g_slist_prepend(t->iwatchers, watcher);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *disable_intermediate(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	const char *sender = dbus_message_get_sender(msg);
	struct thermometer *t = data;
	struct watcher *watcher;
	char *path;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	watcher = find_watcher(t->iwatchers, sender, path);
	if (watcher == NULL)
		return btd_error_does_not_exist(msg);

	DBG("Intermediate measurement %s unregistered", path);

	remove_int_watcher(t, watcher);

	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable thermometer_methods[] = {
	{ "GetProperties",	"",	"a{sv}",	get_properties },
	{ "SetProperty",	"sv",	"",		set_property,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "RegisterWatcher",	"o",	"",		register_watcher },
	{ "UnregisterWatcher",	"o",	"",		unregister_watcher },
	{ "EnableIntermediateMeasurement", "o", "", enable_intermediate },
	{ "DisableIntermediateMeasurement","o",	"", disable_intermediate },
	{ }
};

static GDBusSignalTable thermometer_signals[] = {
	{ "PropertyChanged",	"sv"	},
	{ }
};

static void update_watcher(gpointer data, gpointer user_data)
{
	struct watcher *w = data;
	struct measurement *m = user_data;
	DBusConnection *conn = w->t->conn;
	DBusMessageIter iter;
	DBusMessageIter dict;
	DBusMessage *msg;

	msg = dbus_message_new_method_call(w->srv, w->path,
				"org.bluez.ThermometerWatcher",
				"MeasurementReceived");
	if (msg == NULL)
		return;

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dict_append_entry(&dict, "Exponent", DBUS_TYPE_INT16, &m->exp);
	dict_append_entry(&dict, "Mantissa", DBUS_TYPE_INT32, &m->mant);
	dict_append_entry(&dict, "Unit", DBUS_TYPE_STRING, &m->unit);

	if (m->suptime)
		dict_append_entry(&dict, "Time", DBUS_TYPE_UINT64, &m->time);

	dict_append_entry(&dict, "Type", DBUS_TYPE_STRING, &m->type);
	dict_append_entry(&dict, "Measurement", DBUS_TYPE_STRING, &m->value);

	dbus_message_iter_close_container(&iter, &dict);

	dbus_message_set_no_reply(msg, TRUE);
	g_dbus_send_message(conn, msg);
}

static void recv_measurement(struct thermometer *t, struct measurement *m)
{
	GSList *wlist;

	if (g_strcmp0(m->value, "Intermediate") == 0)
		wlist = t->iwatchers;
	else
		wlist = t->fwatchers;

	g_slist_foreach(wlist, update_watcher, m);
}

static void proc_measurement(struct thermometer *t, const uint8_t *pdu,
						uint16_t len, gboolean final)
{
	struct measurement m;
	const char *type;
	uint8_t flags;
	uint32_t raw;

	if (len < 4) {
		DBG("Mandatory flags are not provided");
		return;
	}

	flags = pdu[3];
	if (flags & TEMP_UNITS)
		m.unit = "Fahrenheit";
	else
		m.unit = "Celsius";

	if (len < 8) {
		DBG("Temperature measurement value is not provided");
		return;
	}

	raw = att_get_u32(&pdu[4]);
	m.mant = raw & 0x00FFFFFF;
	m.exp = ((int32_t) raw) >> 24;

	if (m.mant & 0x00800000) {
		/* convert to C2 negative value */
		m.mant = m.mant - FLOAT_MAX_MANTISSA;
	}

	if (flags & TEMP_TIME_STAMP) {
		struct tm ts;
		time_t time;

		if (len < 15) {
			DBG("Can't get time stamp value");
			return;
		}

		ts.tm_year = att_get_u16(&pdu[8]) - 1900;
		ts.tm_mon = pdu[10] - 1;
		ts.tm_mday = pdu[11];
		ts.tm_hour = pdu[12];
		ts.tm_min = pdu[13];
		ts.tm_sec = pdu[14];
		ts.tm_isdst = -1;

		time = mktime(&ts);
		m.time = (uint64_t) time;
		m.suptime = TRUE;
	} else
		m.suptime = FALSE;

	if (flags & TEMP_TYPE) {
		uint8_t index;

		if (m.suptime && len >= 16)
			index = 15;
		else if (!m.suptime && len >= 9)
			index = 9;
		else {
			DBG("Can't get temperature type");
			return;
		}

		type = temptype2str(pdu[index]);
	} else if (t->has_type)
		type = temptype2str(t->type);
	else {
		DBG("Can't get temperature type");
		return;
	}

	if (type == NULL)
		return;

	m.type = g_strdup(type);
	m.value = final ? "Final" : "Intermediate";

	recv_measurement(t, &m);
	g_free(m.type);
}

static void proc_measurement_interval(struct thermometer *t, const uint8_t *pdu,
								uint16_t len)
{
	uint16_t interval;

	if (len < 5) {
		DBG("Measurement interval value is not provided");
		return;
	}

	interval = att_get_u16(&pdu[3]);

	change_property(t, "Interval", &interval);
}

static void ind_handler(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	struct thermometer *t = user_data;
	const struct characteristic *ch;
	uint8_t opdu[ATT_MAX_MTU];
	uint16_t handle, olen;
	GSList *l;

	if (len < 3) {
		DBG("Bad pdu received");
		return;
	}

	handle = att_get_u16(&pdu[1]);
	l = g_slist_find_custom(t->chars, &handle, cmp_char_val_handle);
	if (l == NULL) {
		DBG("Unexpected handle: 0x%04x", handle);
		return;
	}

	ch = l->data;

	if (g_strcmp0(ch->attr.uuid, TEMPERATURE_MEASUREMENT_UUID) == 0)
		proc_measurement(t, pdu, len, TRUE);
	else if (g_strcmp0(ch->attr.uuid, MEASUREMENT_INTERVAL_UUID) == 0)
		proc_measurement_interval(t, pdu, len);

	olen = enc_confirmation(opdu, sizeof(opdu));

	if (olen > 0)
		g_attrib_send(t->attrib, 0, opdu[0], opdu, olen, NULL, NULL,
									NULL);
}

static void notif_handler(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	struct thermometer *t = user_data;
	const struct characteristic *ch;
	uint16_t handle;
	GSList *l;

	if (len < 3) {
		DBG("Bad pdu received");
		return;
	}

	handle = att_get_u16(&pdu[1]);
	l = g_slist_find_custom(t->chars, &handle, cmp_char_val_handle);
	if (l == NULL) {
		DBG("Unexpected handle: 0x%04x", handle);
		return;
	}

	ch = l->data;
	if (g_strcmp0(ch->attr.uuid, INTERMEDIATE_TEMPERATURE_UUID) == 0)
		proc_measurement(t, pdu, len, FALSE);
}

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct thermometer *t = user_data;

	t->attrib = g_attrib_ref(attrib);

	t->attindid = g_attrib_register(t->attrib, ATT_OP_HANDLE_IND,
							ind_handler, t, NULL);
	t->attnotid = g_attrib_register(t->attrib, ATT_OP_HANDLE_NOTIFY,
							notif_handler, t, NULL);
	gatt_discover_char(t->attrib, t->svc_range->start, t->svc_range->end,
					NULL, configure_thermometer_cb, t);
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct thermometer *t = user_data;

	DBG("GATT Disconnected");

	if (t->attindid > 0) {
		g_attrib_unregister(t->attrib, t->attindid);
		t->attindid = 0;
	}

	if (t->attnotid > 0) {
		g_attrib_unregister(t->attrib, t->attnotid);
		t->attnotid = 0;
	}

	g_attrib_unref(t->attrib);
	t->attrib = NULL;
}

int thermometer_register(DBusConnection *connection, struct btd_device *device,
						struct att_primary *tattr)
{
	const gchar *path = device_get_path(device);
	struct thermometer *t;

	t = g_new0(struct thermometer, 1);
	t->conn = dbus_connection_ref(connection);
	t->dev = btd_device_ref(device);
	t->svc_range = g_new0(struct att_range, 1);
	t->svc_range->start = tattr->start;
	t->svc_range->end = tattr->end;

	if (!g_dbus_register_interface(t->conn, path, THERMOMETER_INTERFACE,
				thermometer_methods, thermometer_signals,
				NULL, t, destroy_thermometer)) {
		error("D-Bus failed to register %s interface",
							THERMOMETER_INTERFACE);
		destroy_thermometer(t);
		return -EIO;
	}

	thermometers = g_slist_prepend(thermometers, t);

	t->attioid = btd_device_add_attio_callback(device, attio_connected_cb,
						attio_disconnected_cb, t);
	return 0;
}

void thermometer_unregister(struct btd_device *device)
{
	struct thermometer *t;
	GSList *l;

	l = g_slist_find_custom(thermometers, device, cmp_device);
	if (l == NULL)
		return;

	t = l->data;
	thermometers = g_slist_remove(thermometers, t);
	g_dbus_unregister_interface(t->conn, device_get_path(t->dev),
							THERMOMETER_INTERFACE);
}
