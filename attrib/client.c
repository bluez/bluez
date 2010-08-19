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

#include <stdlib.h>
#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "log.h"
#include "gdbus.h"
#include "glib-helper.h"
#include "dbus-common.h"
#include "btio.h"
#include "storage.h"

#include "att.h"
#include "gattrib.h"
#include "gatt.h"
#include "client.h"

#define CHAR_INTERFACE "org.bluez.Characteristic"

struct gatt_service {
	bdaddr_t sba;
	bdaddr_t dba;
	char *path;
	GIOChannel *io;
	GSList *primary;
	GAttrib *attrib;
	int psm;
	guint atid;
};

struct format {
	guint8 format;
	guint8 exponent;
	guint16 unit;
	guint8 namespace;
	guint16 desc;
} __attribute__ ((packed));

struct characteristic {
	char *path;
	uint16_t handle;
	uint16_t end;
	uint8_t perm;
	uuid_t type;
	char *name;
	char *desc;
	struct format *format;
	uint8_t *value;
	int vlen;
};

struct primary {
	char *path;
	uuid_t uuid;
	uint16_t start;
	uint16_t end;
	GSList *chars;
};

struct discovered_data {
	struct gatt_service *gatt;
	struct primary *prim;
};

struct descriptor_data {
	struct gatt_service *gatt;
	struct characteristic *chr;
};

static GSList *services = NULL;

static DBusConnection *connection;

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

static void primary_free(void *user_data)
{
	struct primary *prim = user_data;

	g_slist_foreach(prim->chars, (GFunc) characteristic_free, NULL);
	g_free(prim->path);
	g_free(prim);
}

static void gatt_service_free(void *user_data)
{
	struct gatt_service *gatt = user_data;

	g_slist_foreach(gatt->primary, (GFunc) primary_free, NULL);
	g_attrib_unref(gatt->attrib);
	g_free(gatt->path);
	g_free(gatt);
}

static int gatt_path_cmp(const struct gatt_service *gatt, const char *path)
{
	return strcmp(gatt->path, path);
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

	uuid = bt_uuid2string(&chr->type);
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

static DBusMessage *get_characteristics(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct primary *prim = data;
	DBusMessage *reply;
	DBusMessageIter iter, array;
	GSList *l;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_OBJECT_PATH_AS_STRING
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &array);

	for (l = prim->chars; l; l = l->next) {
		struct characteristic *chr = l->data;
		DBusMessageIter sub;

		DBG("path %s", chr->path);

		dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY,
								NULL, &sub);

		dbus_message_iter_append_basic(&sub, DBUS_TYPE_OBJECT_PATH,
								&chr->path);

		append_char_dict(&sub, chr);

		dbus_message_iter_close_container(&array, &sub);
	}

	dbus_message_iter_close_container(&iter, &array);

	return reply;
}

static DBusMessage *register_watcher(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_watcher(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable prim_methods[] = {
	{ "GetCharacteristics",	"",	"a{oa{sv}}", get_characteristics},
	{ "RegisterCharacteristicsWatcher",	"o", "",
						register_watcher	},
	{ "UnregisterCharacteristicsWatcher",	"o", "",
						unregister_watcher	},
	{ }
};

static DBusMessage *get_properties(DBusConnection *conn,
						DBusMessage *msg, void *data)
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

static GDBusMethodTable char_methods[] = {
	{ "GetProperties",	"",	"a{sv}", get_properties },
	{ }
};

static void register_primary(struct gatt_service *gatt)
{
	GSList *l;

	for (l = gatt->primary; l; l = l->next) {
		struct primary *prim = l->data;
		g_dbus_register_interface(connection, prim->path,
				CHAR_INTERFACE, prim_methods,
				NULL, NULL, prim, NULL);
		DBG("Registered: %s", prim->path);
	}
}

static char *characteristic_list_to_string(GSList *chars)
{
	GString *characteristics;
	GSList *l;

	characteristics = g_string_new(NULL);

	for (l = chars; l; l = l->next) {
		struct characteristic *chr = l->data;
		uuid_t *uuid128;
		char chr_str[64];
		char uuidstr[MAX_LEN_UUID_STR];

		memset(chr_str, 0, sizeof(chr_str));

		uuid128 = sdp_uuid_to_uuid128(&chr->type);
		sdp_uuid2strn(uuid128, uuidstr, MAX_LEN_UUID_STR);

		bt_free(uuid128);

		snprintf(chr_str, sizeof(chr_str), "%04X#%02X#%04X#%s ",
				chr->handle, chr->perm, chr->end, uuidstr);

		characteristics = g_string_append(characteristics, chr_str);
	}

	return g_string_free(characteristics, FALSE);
}

static void store_characteristics(struct gatt_service *gatt,
		struct primary *prim)
{
	char *characteristics;

	characteristics = characteristic_list_to_string(prim->chars);

	write_device_characteristics(&gatt->sba, &gatt->dba, prim->start,
							characteristics);

	g_free(characteristics);
}

static void register_characteristics(struct primary *prim)
{
	GSList *lc;

	for (lc = prim->chars; lc; lc = lc->next) {
		struct characteristic *chr = lc->data;
		g_dbus_register_interface(connection, chr->path,
				CHAR_INTERFACE, char_methods,
				NULL, NULL, chr, NULL);
		DBG("Registered: %s", chr->path);
	}
}

static GSList *string_to_characteristic_list(const char *prim_path,
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
		char uuidstr[MAX_LEN_UUID_STR + 1];
		int ret;

		chr = g_new0(struct characteristic, 1);

		ret = sscanf(chars[i], "%04hX#%02hhX#%04hX#%s", &chr->handle,
				&chr->perm, &chr->end, uuidstr);
		if (ret < 4) {
			g_free(chr);
			continue;
		}

		chr->path = g_strdup_printf("%s/characteristic%04x", prim_path,
								chr->handle);

		bt_string2uuid(&chr->type, uuidstr);

		l = g_slist_append(l, chr);
	}

	g_strfreev(chars);

	return l;
}

static void load_characteristics(gpointer data, gpointer user_data)
{
	struct primary *prim = data;
	struct gatt_service *gatt = user_data;
	GSList *chrs_list;
	char *str;

	if (prim->chars) {
		DBG("Characteristics already loaded");
		return;
	}

	str = read_device_characteristics(&gatt->sba, &gatt->dba, prim->start);
	if (str == NULL)
		return;

	chrs_list = string_to_characteristic_list(prim->path, str);

	free(str);

	if (chrs_list == NULL)
		return;

	prim->chars = chrs_list;
	register_characteristics(prim);

	return;
}

static void update_char_desc(guint8 status, const guint8 *pdu,
					guint16 len, gpointer user_data)
{
	struct characteristic *chr = user_data;

	if (status != 0)
		return;

	g_free(chr->desc);

	chr->desc = g_malloc(len);
	memcpy(chr->desc, pdu + 1, len - 1);
	chr->desc[len - 1] = '\0';
}

static void update_char_format(guint8 status, const guint8 *pdu,
					guint16 len, gpointer user_data)
{
	struct characteristic *chr = user_data;

	if (status != 0)
		return;

	if (len < 8)
		return;

	g_free(chr->format);

	chr->format = g_new0(struct format, 1);
	memcpy(chr->format, pdu + 1, 7);
}

static void update_char_value(guint8 status, const guint8 *pdu,
					guint16 len, gpointer user_data)
{
	struct characteristic *chr = user_data;

	if (status != 0)
		return;

	g_free(chr->value);

	chr->vlen = len - 1;
	chr->value = g_malloc(chr->vlen);
	memcpy(chr->value, pdu + 1, chr->vlen);
}

static int uuid_desc16_cmp(uuid_t *uuid, guint16 desc)
{
	uuid_t u16;

	sdp_uuid16_create(&u16, desc);

	return sdp_uuid_cmp(uuid, &u16);
}

static void descriptor_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct descriptor_data *current = user_data;
	struct gatt_service *gatt = current->gatt;
	struct characteristic *chr = current->chr;
	struct att_data_list *list;
	guint8 format;
	int i;

	if (status != 0) {
		g_free(current);
		return;
	}

	DBG("Find Information Response received");

	list = dec_find_info_resp(pdu, plen, &format);
	if (list == NULL) {
		g_free(current);
		return;
	}

	for (i = 0; i < list->num; i++) {
		guint16 handle;
		uuid_t uuid;
		uint8_t *info = list->data[i];

		handle = att_get_u16((uint16_t *) info);

		if (format == 0x01) {
			sdp_uuid16_create(&uuid, att_get_u16((uint16_t *)
								&info[2]));
		} else
			continue;

		if (uuid_desc16_cmp(&uuid, GATT_CHARAC_USER_DESC_UUID) == 0)
			gatt_read_char(gatt->attrib, handle,
					update_char_desc, chr);

		else if (uuid_desc16_cmp(&uuid, GATT_CHARAC_FMT_UUID) == 0)
			gatt_read_char(gatt->attrib, handle,
					update_char_format, chr);
	}

	att_data_list_free(list);
	g_free(current);
}

static void update_all_chars(gpointer data, gpointer user_data)
{
	struct descriptor_data *current;
	struct characteristic *chr = data;
	struct gatt_service *gatt = user_data;

	current = g_new0(struct descriptor_data, 1);
	current->gatt = gatt;
	current->chr = chr;

	gatt_find_info(gatt->attrib, chr->handle + 1, chr->end, descriptor_cb,
								current);
	gatt_read_char(gatt->attrib, chr->handle, update_char_value, chr);
}

static void char_discovered_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct discovered_data *current = user_data;
	struct gatt_service *gatt = current->gatt;
	struct primary *prim = current->prim;
	struct att_data_list *list;
	uint16_t last, *previous_end = NULL;
	int i;

	if (status == ATT_ECODE_ATTR_NOT_FOUND) {
		store_characteristics(gatt, prim);
		register_characteristics(prim);

		g_slist_foreach(prim->chars, update_all_chars, gatt);
		g_free(current);
		return;
	}

	if (status != 0) {
		DBG("Discover all characteristics failed: %s",
						att_ecode2str(status));

		goto fail;
	}

	DBG("Read by Type Response received");

	list = dec_read_by_type_resp(pdu, plen);
	if (list == NULL) {
		g_free(current);
		return;
	}

	for (i = 0, last = 0; i < list->num; i++) {
		uint8_t *decl = list->data[i];
		struct characteristic *chr;

		chr = g_new0(struct characteristic, 1);
		chr->perm = decl[2];
		chr->handle = att_get_u16((uint16_t *) &decl[3]);
		chr->path = g_strdup_printf("%s/characteristic%04x", prim->path,
								chr->handle);
		if (list->len == 7) {
			sdp_uuid16_create(&chr->type,
					att_get_u16((uint16_t *) &decl[5]));
		} else {
			/* FIXME: UUID128 */
		}

		if (previous_end) {
			*previous_end = att_get_u16((uint16_t *) decl);
		}

		last = chr->handle;
		previous_end = &chr->end;

		prim->chars = g_slist_append(prim->chars, chr);
	}

	if (previous_end)
		*previous_end = prim->end;

	att_data_list_free(list);

	/* Fetch remaining characteristics for the CURRENT primary service */
	gatt_discover_char(gatt->attrib, last + 1, prim->end,
						char_discovered_cb, current);

	return;

fail:
	g_free(current);
	gatt_service_free(gatt);
}

static char *primary_list_to_string(GSList *primary_list)
{
	GString *services;
	GSList *l;

	services = g_string_new(NULL);

	for (l = primary_list; l; l = l->next) {
		struct primary *primary = l->data;
		uuid_t *uuid128;
		char service[64];
		char uuidstr[MAX_LEN_UUID_STR];

		memset(service, 0, sizeof(service));

		uuid128 = sdp_uuid_to_uuid128(&primary->uuid);
		sdp_uuid2strn(uuid128, uuidstr, MAX_LEN_UUID_STR);

		bt_free(uuid128);

		snprintf(service, sizeof(service), "%04X#%04X#%s ",
				primary->start, primary->end, uuidstr);

		services = g_string_append(services, service);
	}

	return g_string_free(services, FALSE);
}

static GSList *string_to_primary_list(char *gatt_path, const char *str)
{
	GSList *l = NULL;
	char **services;
	int i;

	if (str == NULL)
		return NULL;

	services = g_strsplit(str, " ", 0);
	if (services == NULL)
		return NULL;

	for (i = 0; services[i]; i++) {
		struct primary *prim;
		char uuidstr[MAX_LEN_UUID_STR + 1];
		int ret;

		prim = g_new0(struct primary, 1);

		ret = sscanf(services[i], "%04hX#%04hX#%s", &prim->start,
							&prim->end, uuidstr);

		if (ret < 3) {
			g_free(prim);
			continue;
		}

		prim->path = g_strdup_printf("%s/service%04x", gatt_path,
								prim->start);

		bt_string2uuid(&prim->uuid, uuidstr);

		l = g_slist_append(l, prim);
	}

	g_strfreev(services);

	return l;
}

static void store_primary_services(struct gatt_service *gatt)
{
       char *services;

       services = primary_list_to_string(gatt->primary);

       write_device_services(&gatt->sba, &gatt->dba, services);

       g_free(services);
}

static gboolean load_primary_services(struct gatt_service *gatt)
{
	GSList *primary_list;
	char *str;

	if (gatt->primary) {
		DBG("Services already loaded");
		return FALSE;
	}

	str = read_device_services(&gatt->sba, &gatt->dba);
	if (str == NULL)
		return FALSE;

	primary_list = string_to_primary_list(gatt->path, str);

	free(str);

	if (primary_list == NULL)
		return FALSE;

	gatt->primary = primary_list;
	register_primary(gatt);

	g_slist_foreach(gatt->primary, load_characteristics, gatt);

	return TRUE;
}

static void discover_all_char(gpointer data, gpointer user_data)
{
	struct discovered_data *current;
	struct gatt_service *gatt = user_data;
	struct primary *prim = data;

	current = g_new0(struct discovered_data, 1);
	current->gatt = gatt;
	current->prim = prim;

	gatt_discover_char(gatt->attrib, prim->start, prim->end,
						char_discovered_cb, current);
}

static void primary_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct gatt_service *gatt = user_data;
	struct att_data_list *list;
	unsigned int i;
	uint16_t end, start;

	if (status == ATT_ECODE_ATTR_NOT_FOUND) {
		if (gatt->primary == NULL)
			return;

		store_primary_services(gatt);
		register_primary(gatt);

		g_slist_foreach(gatt->primary, discover_all_char, gatt);

		return;
	}

	if (status != 0) {
		error("Discover all primary services failed: %s",
						att_ecode2str(status));
		goto fail;
	}

	list = dec_read_by_grp_resp(pdu, plen);
	if (list == NULL) {
		error("Protocol error");
		goto fail;
	}

	DBG("Read by Group Type Response received");

	for (i = 0, end = 0; i < list->num; i++) {
		struct primary *prim;
		uint8_t *info = list->data[i];

		/* Each element contains: attribute handle, end group handle
		 * and attribute value */
		start = att_get_u16((uint16_t *) info);
		end = att_get_u16((uint16_t *) &info[2]);

		prim = g_new0(struct primary, 1);
		prim->start = start;
		prim->end = end;

		if (list->len == 6) {
			sdp_uuid16_create(&prim->uuid,
					att_get_u16((uint16_t *) &info[4]));

		} else if (list->len == 20) {
			/* FIXME: endianness */
			sdp_uuid128_create(&prim->uuid, &info[4]);
		} else {
			DBG("ATT: Invalid Length field");
			g_free(prim);
			att_data_list_free(list);
			goto fail;
		}

		prim->path = g_strdup_printf("%s/service%04x", gatt->path,
								prim->start);

		gatt->primary = g_slist_append(gatt->primary, prim);
	}

	att_data_list_free(list);

	if (end == 0) {
		DBG("ATT: Invalid PDU format");
		goto fail;
	}

	/*
	 * Discover all primary services sub-procedure shall send another
	 * Read by Group Type Request until Error Response is received and
	 * the Error Code is set to Attribute Not Found.
	 */
	gatt->atid = gatt_discover_primary(gatt->attrib,
				end + 1, 0xffff, primary_cb, gatt);
	if (gatt->atid == 0)
		goto fail;

	return;

fail:
	gatt_service_free(gatt);
}

static void connect_cb(GIOChannel *chan, GError *gerr, gpointer user_data)
{
	struct gatt_service *gatt = user_data;
	GAttrib *attrib;
	guint atid;

	if (gerr) {
		error("%s", gerr->message);
		goto fail;
	}

	attrib = g_attrib_new(chan);

	atid = gatt_discover_primary(attrib, 0x0001, 0xffff, primary_cb, gatt);
	if (atid == 0) {
		g_attrib_unref(attrib);
		goto fail;
	}

	gatt->attrib = attrib;
	gatt->atid = atid;

	services = g_slist_append(services, gatt);

	return;
fail:
	g_io_channel_unref(gatt->io);
	gatt_service_free(gatt);
}

int attrib_client_register(bdaddr_t *sba, bdaddr_t *dba, const char *path,
									int psm)
{
	struct gatt_service *gatt;
	GError *gerr = NULL;
	GIOChannel *io;

	/*
	 * Registering fake services/characteristics. The following
	 * paths/interfaces shall be registered after discover primary
	 * services only.
	 */

	gatt = g_new0(struct gatt_service, 1);
	gatt->path = g_strdup(path);
	bacpy(&gatt->sba, sba);
	bacpy(&gatt->dba, dba);
	gatt->psm = psm;

	if (load_primary_services(gatt)) {
		DBG("Primary services loaded");
		return 0;
	}

	if (psm < 0) {
		/*
		 * FIXME: when PSM is not given means that L2CAP fixed
		 * channel shall be used. For this case, ATT CID(0x0004).
		 */

		DBG("GATT over LE");

		return 0;
	}

	io = bt_io_connect(BT_IO_L2CAP, connect_cb, gatt, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, sba,
					BT_IO_OPT_DEST_BDADDR, dba,
					BT_IO_OPT_PSM, psm,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);

	if (!io) {
		error("%s", gerr->message);
		g_error_free(gerr);
		gatt_service_free(gatt);
		return -1;
	}

	gatt->io = io;

	return 0;
}

void attrib_client_unregister(const char *path)
{
	struct gatt_service *gatt;
	GSList *l;

	l = g_slist_find_custom(services, path, (GCompareFunc) gatt_path_cmp);
	if (!l)
		return;

	gatt = l->data;
	services = g_slist_remove(services, gatt);
	gatt_service_free(gatt);
}

int attrib_client_init(DBusConnection *conn)
{

	connection = dbus_connection_ref(conn);

	/*
	 * FIXME: if the adapter supports BLE start scanning. Temporary
	 * solution, this approach doesn't allow to control scanning based
	 * on the discoverable property.
	 */

	return 0;
}

void attrib_client_exit(void)
{
	dbus_connection_unref(connection);
}
