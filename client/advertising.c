/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2016  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <readline/readline.h>
#include <wordexp.h>

#include "gdbus/gdbus.h"
#include "display.h"
#include "advertising.h"

#define AD_PATH "/org/bluez/advertising"
#define AD_IFACE "org.bluez.LEAdvertisement1"

static gboolean registered = FALSE;
static char *ad_type = NULL;
static char **ad_uuids = NULL;
static size_t ad_uuids_len = 0;
static char *ad_service_uuid = NULL;
static uint8_t ad_service_data[25];
static uint8_t ad_service_data_len = 0;
static uint16_t ad_manufacturer_id;
static uint8_t ad_manufacturer_data[25];
static uint8_t ad_manufacturer_data_len = 0;
static gboolean ad_tx_power = FALSE;

static void ad_release(DBusConnection *conn)
{
	registered = FALSE;

	g_dbus_unregister_interface(conn, AD_PATH, AD_IFACE);
}

static DBusMessage *release_advertising(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	rl_printf("Advertising released\n");

	ad_release(conn);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable ad_methods[] = {
	{ GDBUS_METHOD("Release", NULL, NULL, release_advertising) },
	{ }
};

static void register_setup(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	const char *path = AD_PATH;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);
	dbus_message_iter_close_container(iter, &dict);
}

static void register_reply(DBusMessage *message, void *user_data)
{
	DBusConnection *conn = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == FALSE) {
		registered = TRUE;
		rl_printf("Advertising object registered\n");
	} else {
		rl_printf("Failed to register advertisement: %s\n", error.name);
		dbus_error_free(&error);

		if (g_dbus_unregister_interface(conn, AD_PATH,
						AD_IFACE) == FALSE)
			rl_printf("Failed to unregister advertising object\n");
	}
}

static gboolean get_type(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	const char *type = "peripheral";

	if (!ad_type || strlen(ad_type) > 0)
		type = ad_type;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &type);

	return TRUE;
}

static gboolean uuids_exists(const GDBusPropertyTable *property, void *data)
{
	return ad_uuids_len != 0;
}

static gboolean get_uuids(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter array;
	size_t i;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "as", &array);

	for (i = 0; i < ad_uuids_len; i++)
		dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING,
							&ad_uuids[i]);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static void append_array_variant(DBusMessageIter *iter, int type, void *val,
							int n_elements)
{
	DBusMessageIter variant, array;
	char type_sig[2] = { type, '\0' };
	char array_sig[3] = { DBUS_TYPE_ARRAY, type, '\0' };

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
						array_sig, &variant);

	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						type_sig, &array);

	if (dbus_type_is_fixed(type) == TRUE) {
		dbus_message_iter_append_fixed_array(&array, type, val,
							n_elements);
	} else if (type == DBUS_TYPE_STRING || type == DBUS_TYPE_OBJECT_PATH) {
		const char ***str_array = val;
		int i;

		for (i = 0; i < n_elements; i++)
			dbus_message_iter_append_basic(&array, type,
							&((*str_array)[i]));
	}

	dbus_message_iter_close_container(&variant, &array);

	dbus_message_iter_close_container(iter, &variant);
}

static void dict_append_basic_array(DBusMessageIter *dict, int key_type,
					const void *key, int type, void *val,
					int n_elements)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
						NULL, &entry);

	dbus_message_iter_append_basic(&entry, key_type, key);

	append_array_variant(&entry, type, val, n_elements);

	dbus_message_iter_close_container(dict, &entry);
}

static void dict_append_array(DBusMessageIter *dict, const char *key, int type,
				void *val, int n_elements)
{
	dict_append_basic_array(dict, DBUS_TYPE_STRING, &key, type, val,
								n_elements);
}

static gboolean service_data_exists(const GDBusPropertyTable *property,
								void *data)
{
	return ad_service_uuid != NULL;
}

static gboolean get_service_data(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	const uint8_t *data = ad_service_data;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

	dict_append_array(&dict, ad_service_uuid, DBUS_TYPE_BYTE, &data,
							ad_service_data_len);

	dbus_message_iter_close_container(iter, &dict);

	return TRUE;
}

static gboolean manufacturer_data_exists(const GDBusPropertyTable *property,
								void *data)
{
	return ad_manufacturer_id != 0;
}

static gboolean get_manufacturer_data(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	const uint8_t *data = ad_manufacturer_data;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "{qv}", &dict);

	dict_append_basic_array(&dict, DBUS_TYPE_UINT16, &ad_manufacturer_id,
					DBUS_TYPE_BYTE, &data,
					ad_manufacturer_data_len);

	dbus_message_iter_close_container(iter, &dict);

	return TRUE;
}

static gboolean tx_power_exists(const GDBusPropertyTable *property, void *data)
{
	return ad_tx_power;
}

static gboolean get_tx_power(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &ad_tx_power);

	return TRUE;
}

static const GDBusPropertyTable ad_props[] = {
	{ "Type", "s", get_type },
	{ "ServiceUUIDs", "as", get_uuids, NULL, uuids_exists },
	{ "ServiceData", "a{sv}", get_service_data, NULL, service_data_exists },
	{ "ManufacturerData", "a{qv}", get_manufacturer_data, NULL,
						manufacturer_data_exists },
	{ "IncludeTxPower", "b", get_tx_power, NULL, tx_power_exists },
	{ }
};

void ad_register(DBusConnection *conn, GDBusProxy *manager, const char *type)
{
	if (registered == TRUE) {
		rl_printf("Advertisement is already registered\n");
		return;
	}

	ad_type = g_strdup(type);

	if (g_dbus_register_interface(conn, AD_PATH, AD_IFACE, ad_methods,
					NULL, ad_props, NULL, NULL) == FALSE) {
		rl_printf("Failed to register advertising object\n");
		return;
	}

	if (g_dbus_proxy_method_call(manager, "RegisterAdvertisement",
					register_setup, register_reply,
					conn, NULL) == FALSE) {
		rl_printf("Failed to register advertising\n");
		return;
	}
}

static void unregister_setup(DBusMessageIter *iter, void *user_data)
{
	const char *path = AD_PATH;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

static void unregister_reply(DBusMessage *message, void *user_data)
{
	DBusConnection *conn = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == FALSE) {
		registered = FALSE;
		rl_printf("Advertising object unregistered\n");
		if (g_dbus_unregister_interface(conn, AD_PATH,
							AD_IFACE) == FALSE)
			rl_printf("Failed to unregister advertising object\n");
	} else {
		rl_printf("Failed to unregister advertisement: %s\n",
								error.name);
		dbus_error_free(&error);
	}
}

void ad_unregister(DBusConnection *conn, GDBusProxy *manager)
{
	if (!manager)
		ad_release(conn);

	if (g_dbus_proxy_method_call(manager, "UnregisterAdvertisement",
					unregister_setup, unregister_reply,
					conn, NULL) == FALSE) {
		rl_printf("Failed to unregister advertisement method\n");
		return;
	}
}

void ad_advertise_uuids(const char *arg)
{
	g_strfreev(ad_uuids);
	ad_uuids = NULL;
	ad_uuids_len = 0;

	if (!arg || !strlen(arg))
		return;

	ad_uuids = g_strsplit(arg, " ", -1);
	if (!ad_uuids) {
		rl_printf("Failed to parse input\n");
		return;
	}

	ad_uuids_len = g_strv_length(ad_uuids);
}

static void ad_clear_service(void)
{
	g_free(ad_service_uuid);
	ad_service_uuid = NULL;
	memset(ad_service_data, 0, sizeof(ad_service_data));
	ad_service_data_len = 0;
}

void ad_advertise_service(const char *arg)
{
	wordexp_t w;
	unsigned int i;

	if (wordexp(arg, &w, WRDE_NOCMD)) {
		rl_printf("Invalid argument\n");
		return;
	}

	ad_clear_service();

	if (w.we_wordc == 0)
		goto done;

	ad_service_uuid = g_strdup(w.we_wordv[0]);

	for (i = 1; i < w.we_wordc; i++) {
		long int val;
		char *endptr = NULL;

		if (i >= G_N_ELEMENTS(ad_service_data)) {
			rl_printf("Too much data\n");
			goto done;
		}

		val = strtol(w.we_wordv[i], &endptr, 0);
		if (!endptr || *endptr != '\0' || val > UINT8_MAX) {
			rl_printf("Invalid value at index %d\n", i);
			ad_clear_service();
			goto done;
		}

		ad_service_data[ad_service_data_len] = val;
		ad_service_data_len++;
	}

done:
	wordfree(&w);
}

static void ad_clear_manufacturer(void)
{
	ad_manufacturer_id = 0;
	memset(ad_manufacturer_data, 0, sizeof(ad_manufacturer_data));
	ad_manufacturer_data_len = 0;
}

void ad_advertise_manufacturer(const char *arg)
{
	wordexp_t w;
	unsigned int i;
	char *endptr = NULL;
	long int val;

	if (wordexp(arg, &w, WRDE_NOCMD)) {
		rl_printf("Invalid argument\n");
		return;
	}

	ad_clear_manufacturer();

	if (w.we_wordc == 0)
		goto done;

	val = strtol(w.we_wordv[0], &endptr, 0);
	if (!endptr || *endptr != '\0' || val > UINT16_MAX) {
		rl_printf("Invalid manufacture id\n");
		goto done;
	}

	ad_manufacturer_id = val;

	for (i = 1; i < w.we_wordc; i++) {
		if (i >= G_N_ELEMENTS(ad_service_data)) {
			rl_printf("Too much data\n");
			goto done;
		}

		val = strtol(w.we_wordv[i], &endptr, 0);
		if (!endptr || *endptr != '\0' || val > UINT8_MAX) {
			rl_printf("Invalid value at index %d\n", i);
			ad_clear_service();
			goto done;
		}

		ad_manufacturer_data[ad_manufacturer_data_len] = val;
		ad_manufacturer_data_len++;
	}

done:
	wordfree(&w);
}


void ad_advertise_tx_power(gboolean value)
{
	ad_tx_power = value;
}
