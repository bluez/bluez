/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <errno.h>
#include <stdlib.h>
#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/uuid.h>

#include "glib-compat.h"
#include "adapter.h"
#include "device.h"
#include "log.h"
#include "gdbus.h"
#include "error.h"
#include "dbus-common.h"
#include "btio.h"
#include "storage.h"

#include "att.h"
#include "gattrib.h"
#include "attio.h"
#include "gatt.h"
#include "client.h"

#define CHAR_INTERFACE "org.bluez.Characteristic"

struct format {
	guint8 format;
	guint8 exponent;
	guint16 unit;
	guint8 namespace;
	guint16 desc;
} __attribute__ ((packed));

struct query {
	DBusMessage *msg;
	guint attioid;
	GSList *list;
};

struct gatt_service {
	struct btd_device *dev;
	struct att_primary *prim;
	DBusConnection *conn;
	GAttrib *attrib;
	guint attioid;
	int psm;
	char *path;
	GSList *chars;
	GSList *offline_chars;
	GSList *watchers;
	struct query *query;
};

struct characteristic {
	struct gatt_service *gatt;
	char *path;
	uint16_t handle;
	uint16_t end;
	uint8_t perm;
	char type[MAX_LEN_UUID_STR + 1];
	char *name;
	char *desc;
	struct format *format;
	uint8_t *value;
	size_t vlen;
};

struct query_data {
	struct gatt_service *gatt;
	struct characteristic *chr;
	uint16_t handle;
};

struct watcher {
	guint id;
	char *name;
	char *path;
	struct gatt_service *gatt;
};

static GSList *gatt_services = NULL;

static void characteristic_free(void *user_data)
{
	struct characteristic *chr = user_data;

	g_free(chr->path);
	g_free(chr->desc);
	g_free(chr->format);
	g_free(chr->value);
	g_free(chr->name);
	g_free(chr);
}

static void watcher_free(void *user_data)
{
	struct watcher *watcher = user_data;

	g_free(watcher->path);
	g_free(watcher->name);
	g_free(watcher);
}

static void gatt_service_free(struct gatt_service *gatt)
{
	g_slist_free_full(gatt->watchers, watcher_free);
	g_slist_free_full(gatt->chars, characteristic_free);
	g_slist_free(gatt->offline_chars);
	g_free(gatt->path);
	btd_device_unref(gatt->dev);
	dbus_connection_unref(gatt->conn);
	g_free(gatt);
}

static void gatt_get_address(struct gatt_service *gatt,
				bdaddr_t *sba, bdaddr_t *dba)
{
	struct btd_device *device = gatt->dev;
	struct btd_adapter *adapter;

	adapter = device_get_adapter(device);
	adapter_get_address(adapter, sba);
	device_get_address(device, dba, NULL);
}

static int characteristic_handle_cmp(gconstpointer a, gconstpointer b)
{
	const struct characteristic *chr = a;
	uint16_t handle = GPOINTER_TO_UINT(b);

	return chr->handle - handle;
}

static int watcher_cmp(gconstpointer a, gconstpointer b)
{
	const struct watcher *watcher = a;
	const struct watcher *match = b;
	int ret;

	ret = g_strcmp0(watcher->name, match->name);
	if (ret != 0)
		return ret;

	return g_strcmp0(watcher->path, match->path);
}

static void append_char_dict(DBusMessageIter *iter, struct characteristic *chr)
{
	DBusMessageIter dict;
	const char *name = "";
	char *uuid;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	uuid = g_strdup(chr->type);
	dict_append_entry(&dict, "UUID", DBUS_TYPE_STRING, &uuid);
	g_free(uuid);

	/* FIXME: Translate UUID to name. */
	dict_append_entry(&dict, "Name", DBUS_TYPE_STRING, &name);

	if (chr->desc)
		dict_append_entry(&dict, "Description", DBUS_TYPE_STRING,
								&chr->desc);

	if (chr->value)
		dict_append_array(&dict, "Value", DBUS_TYPE_BYTE, &chr->value,
								chr->vlen);

	/* FIXME: Missing Format, Value and Representation */

	dbus_message_iter_close_container(iter, &dict);
}

static void watcher_exit(DBusConnection *conn, void *user_data)
{
	struct watcher *watcher = user_data;
	struct gatt_service *gatt = watcher->gatt;

	DBG("%s watcher %s exited", gatt->path, watcher->name);

	gatt->watchers = g_slist_remove(gatt->watchers, watcher);
}

static int characteristic_set_value(struct characteristic *chr,
					const uint8_t *value, size_t vlen)
{
	chr->value = g_try_realloc(chr->value, vlen);
	if (chr->value == NULL)
		return -ENOMEM;

	memcpy(chr->value, value, vlen);
	chr->vlen = vlen;

	return 0;
}

static void update_watchers(gpointer data, gpointer user_data)
{
	struct watcher *w = data;
	struct characteristic *chr = user_data;
	DBusConnection *conn = w->gatt->conn;
	DBusMessage *msg;

	msg = dbus_message_new_method_call(w->name, w->path,
				"org.bluez.Watcher", "ValueChanged");
	if (msg == NULL)
		return;

	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &chr->path,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&chr->value, chr->vlen, DBUS_TYPE_INVALID);

	dbus_message_set_no_reply(msg, TRUE);
	g_dbus_send_message(conn, msg);
}

static void events_handler(const uint8_t *pdu, uint16_t len,
							gpointer user_data)
{
	struct gatt_service *gatt = user_data;
	struct characteristic *chr;
	GSList *l;
	uint8_t opdu[ATT_MAX_MTU];
	guint handle;
	uint16_t olen;

	if (len < 3) {
		DBG("Malformed notification/indication packet (opcode 0x%02x)",
									pdu[0]);
		return;
	}

	handle = att_get_u16(&pdu[1]);

	l = g_slist_find_custom(gatt->chars, GUINT_TO_POINTER(handle),
						characteristic_handle_cmp);
	if (!l)
		return;

	chr = l->data;

	if (chr == NULL) {
		DBG("Attribute handle 0x%02x not found", handle);
		return;
	}

	switch (pdu[0]) {
	case ATT_OP_HANDLE_IND:
		olen = enc_confirmation(opdu, sizeof(opdu));
		g_attrib_send(gatt->attrib, 0, opdu[0], opdu, olen,
						NULL, NULL, NULL);
	case ATT_OP_HANDLE_NOTIFY:
		if (characteristic_set_value(chr, &pdu[3], len - 3) < 0)
			DBG("Can't change Characteristic 0x%02x", handle);

		g_slist_foreach(gatt->watchers, update_watchers, chr);
		break;
	}
}

static void offline_char_written(gpointer user_data)
{
	struct characteristic *chr = user_data;
	struct gatt_service *gatt = chr->gatt;

	gatt->offline_chars = g_slist_remove(gatt->offline_chars, chr);

	if (gatt->offline_chars || gatt->watchers)
		return;

	btd_device_remove_attio_callback(gatt->dev, gatt->attioid);
	gatt->attioid = 0;
}

static void offline_char_write(gpointer data, gpointer user_data)
{
	struct characteristic *chr = data;
	GAttrib *attrib = user_data;

	gatt_write_cmd(attrib, chr->handle, chr->value, chr->vlen,
						offline_char_written, chr);
}

static void attio_connected(GAttrib *attrib, gpointer user_data)
{
	struct gatt_service *gatt = user_data;

	gatt->attrib = g_attrib_ref(attrib);

	g_attrib_register(gatt->attrib, ATT_OP_HANDLE_NOTIFY,
					events_handler, gatt, NULL);
	g_attrib_register(gatt->attrib, ATT_OP_HANDLE_IND,
					events_handler, gatt, NULL);

	g_slist_foreach(gatt->offline_chars, offline_char_write, attrib);
}

static void attio_disconnected(gpointer user_data)
{
	struct gatt_service *gatt = user_data;

	if (gatt->attrib) {
		g_attrib_unref(gatt->attrib);
		gatt->attrib = NULL;
	}
}

static DBusMessage *register_watcher(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *sender = dbus_message_get_sender(msg);
	struct gatt_service *gatt = data;
	struct watcher *watcher;
	char *path;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	watcher = g_new0(struct watcher, 1);
	watcher->name = g_strdup(sender);
	watcher->gatt = gatt;
	watcher->path = g_strdup(path);
	watcher->id = g_dbus_add_disconnect_watch(conn, sender, watcher_exit,
							watcher, watcher_free);

	if (gatt->attioid == 0)
		gatt->attioid = btd_device_add_attio_callback(gatt->dev,
							attio_connected,
							attio_disconnected,
							gatt);

	gatt->watchers = g_slist_append(gatt->watchers, watcher);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_watcher(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *sender = dbus_message_get_sender(msg);
	struct gatt_service *gatt = data;
	struct watcher *watcher, *match;
	GSList *l;
	char *path;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	match = g_new0(struct watcher, 1);
	match->name = g_strdup(sender);
	match->path = g_strdup(path);
	l = g_slist_find_custom(gatt->watchers, match, watcher_cmp);
	watcher_free(match);
	if (!l)
		return btd_error_not_authorized(msg);

	watcher = l->data;
	g_dbus_remove_watch(conn, watcher->id);
	gatt->watchers = g_slist_remove(gatt->watchers, watcher);
	watcher_free(watcher);

	if (gatt->watchers == NULL && gatt->attioid) {
		btd_device_remove_attio_callback(gatt->dev, gatt->attioid);
		gatt->attioid = 0;
	}

	return dbus_message_new_method_return(msg);
}

static DBusMessage *set_value(DBusConnection *conn, DBusMessage *msg,
			DBusMessageIter *iter, struct characteristic *chr)
{
	struct gatt_service *gatt = chr->gatt;
	DBusMessageIter sub;
	uint8_t *value;
	int len;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY ||
			dbus_message_iter_get_element_type(iter) != DBUS_TYPE_BYTE)
		return btd_error_invalid_args(msg);

	dbus_message_iter_recurse(iter, &sub);

	dbus_message_iter_get_fixed_array(&sub, &value, &len);

	characteristic_set_value(chr, value, len);

	if (gatt->attioid == 0)
		gatt->attioid = btd_device_add_attio_callback(gatt->dev,
							attio_connected,
							attio_disconnected,
							gatt);

	if (gatt->attrib)
		gatt_write_cmd(gatt->attrib, chr->handle, value, len,
								NULL, NULL);
	else
		gatt->offline_chars = g_slist_append(gatt->offline_chars, chr);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *get_properties(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct characteristic *chr = data;
	DBusMessage *reply;
	DBusMessageIter iter;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	append_char_dict(&iter, chr);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct characteristic *chr = data;
	DBusMessageIter iter;
	DBusMessageIter sub;
	const char *property;

	if (!dbus_message_iter_init(msg, &iter))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return btd_error_invalid_args(msg);

	dbus_message_iter_recurse(&iter, &sub);

	if (g_str_equal("Value", property))
		return set_value(conn, msg, &sub, chr);

	return btd_error_invalid_args(msg);
}

static GDBusMethodTable char_methods[] = {
	{ "GetProperties",	"",	"a{sv}", get_properties },
	{ "SetProperty",	"sv",	"",	set_property,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ }
};

static char *characteristic_list_to_string(GSList *chars)
{
	GString *characteristics;
	GSList *l;

	characteristics = g_string_new(NULL);

	for (l = chars; l; l = l->next) {
		struct characteristic *chr = l->data;
		char chr_str[64];

		memset(chr_str, 0, sizeof(chr_str));

		snprintf(chr_str, sizeof(chr_str), "%04X#%02X#%04X#%s ",
				chr->handle, chr->perm, chr->end, chr->type);

		characteristics = g_string_append(characteristics, chr_str);
	}

	return g_string_free(characteristics, FALSE);
}

static void store_characteristics(const bdaddr_t *sba, const bdaddr_t *dba,
						uint16_t start, GSList *chars)
{
	char *characteristics;

	characteristics = characteristic_list_to_string(chars);

	write_device_characteristics(sba, dba, start, characteristics);

	g_free(characteristics);
}

static void register_characteristic(gpointer data, gpointer user_data)
{
	struct characteristic *chr = data;
	DBusConnection *conn = chr->gatt->conn;
	const char *gatt_path = user_data;

	chr->path = g_strdup_printf("%s/characteristic%04x", gatt_path,
								chr->handle);

	g_dbus_register_interface(conn, chr->path, CHAR_INTERFACE,
					char_methods, NULL, NULL, chr, NULL);

	DBG("Registered: %s", chr->path);
}

static GSList *string_to_characteristic_list(struct gatt_service *gatt,
							const char *str)
{
	GSList *l = NULL;
	char **chars;
	int i;

	if (str == NULL)
		return NULL;

	chars = g_strsplit(str, " ", 0);
	if (chars == NULL)
		return NULL;

	for (i = 0; chars[i]; i++) {
		struct characteristic *chr;
		int ret;

		chr = g_new0(struct characteristic, 1);

		ret = sscanf(chars[i], "%04hX#%02hhX#%04hX#%s", &chr->handle,
				&chr->perm, &chr->end, chr->type);
		if (ret < 4) {
			g_free(chr);
			continue;
		}

		chr->gatt = gatt;
		l = g_slist_append(l, chr);
	}

	g_strfreev(chars);

	return l;
}

static GSList *load_characteristics(struct gatt_service *gatt, uint16_t start)
{
	GSList *chrs_list;
	bdaddr_t sba, dba;
	char *str;

	gatt_get_address(gatt, &sba, &dba);

	str = read_device_characteristics(&sba, &dba, start);
	if (str == NULL)
		return NULL;

	chrs_list = string_to_characteristic_list(gatt, str);

	free(str);

	return chrs_list;
}

static void store_attribute(struct gatt_service *gatt, uint16_t handle,
				uint16_t type, uint8_t *value, gsize len)
{
	bdaddr_t sba, dba;
	bt_uuid_t uuid;
	char *str, *tmp;
	guint i;

	str = g_malloc0(MAX_LEN_UUID_STR + len * 2 + 1);

	bt_uuid16_create(&uuid, type);
	bt_uuid_to_string(&uuid, str, MAX_LEN_UUID_STR);

	str[MAX_LEN_UUID_STR - 1] = '#';

	for (i = 0, tmp = str + MAX_LEN_UUID_STR; i < len; i++, tmp += 2)
		sprintf(tmp, "%02X", value[i]);

	gatt_get_address(gatt, &sba, &dba);

	write_device_attribute(&sba, &dba, handle, str);

	g_free(str);
}

static void query_list_append(struct gatt_service *gatt, struct query_data *data)
{
	struct query *query = gatt->query;

	query->list = g_slist_append(query->list, data);
}

static void query_list_remove(struct gatt_service *gatt, struct query_data *data)
{
	struct query *query = gatt->query;

	query->list = g_slist_remove(query->list, data);
	if (query->list != NULL)
		return;

	btd_device_remove_attio_callback(gatt->dev, query->attioid);
	g_free(query);

	gatt->query = NULL;
}

static void update_char_desc(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct query_data *current = user_data;
	struct gatt_service *gatt = current->gatt;
	struct characteristic *chr = current->chr;

	if (status == 0) {

		g_free(chr->desc);

		chr->desc = g_malloc(len);
		memcpy(chr->desc, pdu + 1, len - 1);
		chr->desc[len - 1] = '\0';

		store_attribute(gatt, current->handle,
				GATT_CHARAC_USER_DESC_UUID,
				(void *) chr->desc, len);
	} else if (status == ATT_ECODE_INSUFF_ENC) {
		GIOChannel *io = g_attrib_get_channel(gatt->attrib);

		if (bt_io_set(io, BT_IO_L2CAP, NULL,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_HIGH,
				BT_IO_OPT_INVALID)) {
			gatt_read_char(gatt->attrib, current->handle, 0,
					update_char_desc, current);
			return;
		}
	}

	query_list_remove(gatt, current);
	g_free(current);
}

static void update_char_format(guint8 status, const guint8 *pdu, guint16 len,
								gpointer user_data)
{
	struct query_data *current = user_data;
	struct gatt_service *gatt = current->gatt;
	struct characteristic *chr = current->chr;

	if (status != 0)
		goto done;

	if (len < 8)
		goto done;

	g_free(chr->format);

	chr->format = g_new0(struct format, 1);
	memcpy(chr->format, pdu + 1, 7);

	store_attribute(gatt, current->handle, GATT_CHARAC_FMT_UUID,
				(void *) chr->format, sizeof(*chr->format));

done:
	query_list_remove(gatt, current);
	g_free(current);
}

static void update_char_value(guint8 status, const guint8 *pdu,
					guint16 len, gpointer user_data)
{
	struct query_data *current = user_data;
	struct gatt_service *gatt = current->gatt;
	struct characteristic *chr = current->chr;

	if (status == 0)
		characteristic_set_value(chr, pdu + 1, len - 1);
	else if (status == ATT_ECODE_INSUFF_ENC) {
		GIOChannel *io = g_attrib_get_channel(gatt->attrib);

		if (bt_io_set(io, BT_IO_L2CAP, NULL,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_HIGH,
				BT_IO_OPT_INVALID)) {
			gatt_read_char(gatt->attrib, chr->handle, 0,
					update_char_value, current);
			return;
		}
	}

	query_list_remove(gatt, current);
	g_free(current);
}

static int uuid_desc16_cmp(bt_uuid_t *uuid, guint16 desc)
{
	bt_uuid_t u16;

	bt_uuid16_create(&u16, desc);

	return bt_uuid_cmp(uuid, &u16);
}

static void descriptor_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct query_data *current = user_data;
	struct gatt_service *gatt = current->gatt;
	struct att_data_list *list;
	guint8 format;
	int i;

	if (status != 0)
		goto done;

	DBG("Find Information Response received");

	list = dec_find_info_resp(pdu, plen, &format);
	if (list == NULL)
		goto done;

	for (i = 0; i < list->num; i++) {
		guint16 handle;
		bt_uuid_t uuid;
		uint8_t *info = list->data[i];
		struct query_data *qfmt;

		handle = att_get_u16(info);

		if (format == 0x01) {
			uuid = att_get_uuid16(&info[2]);
		} else {
			/* Currently, only "user description" and "presentation
			 * format" descriptors are used, and both have 16-bit
			 * UUIDs. Therefore there is no need to support format
			 * 0x02 yet. */
			continue;
		}
		qfmt = g_new0(struct query_data, 1);
		qfmt->gatt = current->gatt;
		qfmt->chr = current->chr;
		qfmt->handle = handle;

		if (uuid_desc16_cmp(&uuid, GATT_CHARAC_USER_DESC_UUID) == 0) {
			query_list_append(gatt, qfmt);
			gatt_read_char(gatt->attrib, handle, 0, update_char_desc,
									qfmt);
		} else if (uuid_desc16_cmp(&uuid, GATT_CHARAC_FMT_UUID) == 0) {
			query_list_append(gatt, qfmt);
			gatt_read_char(gatt->attrib, handle, 0,
						update_char_format, qfmt);
		} else
			g_free(qfmt);
	}

	att_data_list_free(list);
done:
	query_list_remove(gatt, current);
	g_free(current);
}

static void update_all_chars(gpointer data, gpointer user_data)
{
	struct query_data *qdesc, *qvalue;
	struct characteristic *chr = data;
	struct gatt_service *gatt = user_data;

	qdesc = g_new0(struct query_data, 1);
	qdesc->gatt = gatt;
	qdesc->chr = chr;

	query_list_append(gatt, qdesc);

	gatt_find_info(gatt->attrib, chr->handle + 1, chr->end, descriptor_cb,
									qdesc);

	qvalue = g_new0(struct query_data, 1);
	qvalue->gatt = gatt;
	qvalue->chr = chr;

	query_list_append(gatt, qvalue);

	gatt_read_char(gatt->attrib, chr->handle, 0, update_char_value, qvalue);
}

static void char_discovered_cb(GSList *characteristics, guint8 status,
							gpointer user_data)
{
	DBusMessage *reply;
	DBusMessageIter iter, array_iter;
	struct query_data *current = user_data;
	struct gatt_service *gatt = current->gatt;
	struct att_primary *prim = gatt->prim;
	uint16_t *previous_end = NULL;
	GSList *l;
	bdaddr_t sba, dba;

	if (status != 0) {
		const char *str = att_ecode2str(status);

		DBG("Discover all characteristics failed: %s", str);
		reply = btd_error_failed(gatt->query->msg, str);
		goto fail;
	}

	for (l = characteristics; l; l = l->next) {
		struct att_char *current_chr = l->data;
		struct characteristic *chr;
		guint handle = current_chr->value_handle;
		GSList *lchr;

		lchr = g_slist_find_custom(gatt->chars,
			GUINT_TO_POINTER(handle), characteristic_handle_cmp);
		if (lchr)
			continue;

		chr = g_new0(struct characteristic, 1);
		chr->gatt = gatt;
		chr->perm = current_chr->properties;
		chr->handle = current_chr->value_handle;
		strncpy(chr->type, current_chr->uuid, sizeof(chr->type));

		if (previous_end)
			*previous_end = current_chr->handle;

		previous_end = &chr->end;

		gatt->chars = g_slist_append(gatt->chars, chr);
	}

	if (previous_end)
		*previous_end = prim->end;

	gatt_get_address(gatt, &sba, &dba);
	store_characteristics(&sba, &dba, prim->start, gatt->chars);

	g_slist_foreach(gatt->chars, register_characteristic, gatt->path);

	reply = dbus_message_new_method_return(gatt->query->msg);

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &array_iter);

	for (l = gatt->chars; l; l = l->next) {
		struct characteristic *chr = l->data;

		dbus_message_iter_append_basic(&array_iter,
					DBUS_TYPE_OBJECT_PATH, &chr->path);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	g_slist_foreach(gatt->chars, update_all_chars, gatt);

fail:
	g_dbus_send_message(gatt->conn, reply);
	query_list_remove(gatt, current);
	g_free(current);
}

static void send_discover(GAttrib *attrib, gpointer user_data)
{
	struct query_data *qchr = user_data;
	struct gatt_service *gatt = qchr->gatt;
	struct att_primary *prim = gatt->prim;

	gatt->attrib = g_attrib_ref(attrib);

	gatt_discover_char(gatt->attrib, prim->start, prim->end, NULL,
						char_discovered_cb, qchr);
}

static void cancel_discover(gpointer user_data)
{
	struct query_data *qchr = user_data;
	struct gatt_service *gatt = qchr->gatt;

	g_attrib_unref(gatt->attrib);
	gatt->attrib = NULL;
}

static DBusMessage *discover_char(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct gatt_service *gatt = data;
	struct query *query;
	struct query_data *qchr;

	if (gatt->query)
		return btd_error_busy(msg);

	query = g_new0(struct query, 1);

	qchr = g_new0(struct query_data, 1);
	qchr->gatt = gatt;

	query->msg = dbus_message_ref(msg);
	query->attioid = btd_device_add_attio_callback(gatt->dev,
							send_discover,
							cancel_discover,
							qchr);

	gatt->query = query;

	query_list_append(gatt, qchr);

	return NULL;
}

static DBusMessage *prim_get_properties(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct gatt_service *gatt = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	GSList *l;
	char **chars;
	const char *uuid;
	int i;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	chars = g_new0(char *, g_slist_length(gatt->chars) + 1);

	for (i = 0, l = gatt->chars; l; l = l->next, i++) {
		struct characteristic *chr = l->data;
		chars[i] = chr->path;
	}

	dict_append_array(&dict, "Characteristics", DBUS_TYPE_OBJECT_PATH,
								&chars, i);
	uuid = gatt->prim->uuid;
	dict_append_entry(&dict, "UUID", DBUS_TYPE_STRING, &uuid);

	g_free(chars);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static GDBusMethodTable prim_methods[] = {
	{ "DiscoverCharacteristics",	"",	"ao",	discover_char,
					G_DBUS_METHOD_FLAG_ASYNC	},
	{ "RegisterCharacteristicsWatcher",	"o", "",
						register_watcher	},
	{ "UnregisterCharacteristicsWatcher",	"o", "",
						unregister_watcher	},
	{ "GetProperties",	"",	"a{sv}",prim_get_properties	},
	{ }
};

static struct gatt_service *primary_register(DBusConnection *conn,
						struct btd_device *device,
						struct att_primary *prim,
						int psm)
{
	struct gatt_service *gatt;
	const char *device_path;

	device_path = device_get_path(device);

	gatt = g_new0(struct gatt_service, 1);
	gatt->dev = btd_device_ref(device);
	gatt->prim = prim;
	gatt->psm = psm;
	gatt->conn = dbus_connection_ref(conn);
	gatt->path = g_strdup_printf("%s/service%04x", device_path,
								prim->start);

	g_dbus_register_interface(gatt->conn, gatt->path,
					CHAR_INTERFACE, prim_methods,
					NULL, NULL, gatt, NULL);
	gatt->chars = load_characteristics(gatt, prim->start);
	g_slist_foreach(gatt->chars, register_characteristic, gatt->path);

	return gatt;
}

GSList *attrib_client_register(DBusConnection *connection,
					struct btd_device *device, int psm,
					GAttrib *attrib, GSList *primaries)
{
	GSList *l, *services;

	for (l = primaries, services = NULL; l; l = l->next) {
		struct att_primary *prim = l->data;
		struct gatt_service *gatt;

		gatt = primary_register(connection, device, prim, psm);

		DBG("Registered: %s", gatt->path);

		services = g_slist_append(services, g_strdup(gatt->path));
		gatt_services = g_slist_append(gatt_services, gatt);

	}

	return services;
}

static void primary_unregister(struct gatt_service *gatt)
{
	GSList *l;

	if (gatt->attioid)
		btd_device_remove_attio_callback(gatt->dev, gatt->attioid);

	for (l = gatt->chars; l; l = l->next) {
		struct characteristic *chr = l->data;
		g_dbus_unregister_interface(gatt->conn, chr->path,
							CHAR_INTERFACE);
	}

	g_dbus_unregister_interface(gatt->conn, gatt->path, CHAR_INTERFACE);
}

static int path_cmp(gconstpointer data, gconstpointer user_data)
{
	const char *path = data;
	const char *gatt_path = user_data;

	return g_strcmp0(path, gatt_path);
}

void attrib_client_unregister(GSList *services)
{
	GSList *l, *left;

	for (l = gatt_services, left = NULL; l; l = l->next) {
		struct gatt_service *gatt = l->data;

		if (!g_slist_find_custom(services, gatt->path, path_cmp)) {
			left = g_slist_append(left, gatt);
			continue;
		}

		primary_unregister(gatt);
		gatt_service_free(gatt);
	}

	g_slist_free(gatt_services);
	gatt_services = left;
}
