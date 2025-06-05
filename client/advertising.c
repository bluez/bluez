// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2016  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include "gdbus/gdbus.h"
#include "src/shared/util.h"
#include "src/shared/shell.h"
#include "advertising.h"

#define AD_PATH "/org/bluez/advertising"
#define AD_IFACE "org.bluez.LEAdvertisement1"

struct ad_data {
	uint8_t data[245];
	uint8_t len;
};

struct service_data {
	char *uuid;
	struct ad_data data;
};

struct manufacturer_data {
	uint16_t id;
	struct ad_data data;
};

struct data {
	bool valid;
	uint8_t type;
	struct ad_data data;
};

static struct ad {
	bool registered;
	char *type;
	char *local_name;
	char *secondary;
	uint32_t min_interval;
	uint32_t max_interval;
	uint16_t local_appearance;
	uint16_t duration;
	uint16_t timeout;
	uint16_t discoverable_to;
	char **uuids[AD_TYPE_COUNT];
	size_t uuids_len[AD_TYPE_COUNT];
	char **solicit[AD_TYPE_COUNT];
	size_t solicit_len[AD_TYPE_COUNT];
	struct service_data service[AD_TYPE_COUNT];
	struct manufacturer_data manufacturer[AD_TYPE_COUNT];
	struct data data[AD_TYPE_COUNT];
	bool discoverable;
	bool tx_power;
	bool name;
	bool appearance;
	bool rsi;
} ad = {
	.local_appearance = UINT16_MAX,
	.discoverable = true,
	.rsi = true,
};

static void ad_release(DBusConnection *conn)
{
	ad.registered = false;

	g_dbus_unregister_interface(conn, AD_PATH, AD_IFACE);
}

static DBusMessage *release_advertising(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	bt_shell_printf("Advertising released\n");

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

static void print_uuid(const char *prefix, const char *uuid)
{
	const char *text;

	text = bt_uuidstr_to_str(uuid);
	if (text) {
		char str[26];
		unsigned int n;

		str[sizeof(str) - 1] = '\0';

		n = snprintf(str, sizeof(str), "%s", text);
		if (n > sizeof(str) - 1) {
			str[sizeof(str) - 2] = '.';
			str[sizeof(str) - 3] = '.';
			if (str[sizeof(str) - 4] == ' ')
				str[sizeof(str) - 4] = '.';
		}

		bt_shell_printf("%s: %s(%s)\n", prefix, str, uuid);
	} else
		bt_shell_printf("%s: (%s)\n", prefix, uuid ? uuid : "");
}

static const struct {
	const char *uuid[AD_TYPE_COUNT];
	const char *solicit[AD_TYPE_COUNT];
	const char *service[AD_TYPE_COUNT];
	const char *manufacturer[AD_TYPE_COUNT];
	const char *data[AD_TYPE_COUNT];
} ad_names = {
	.uuid = { "UUID", "Scan Response UUID" },
	.solicit = { "Solicit UUID", "Scan Response Solicit UUID" },
	.service = { "UUID", "Scan Response UUID" },
	.manufacturer = { "Manufacturer", "Scan Response Manufacturer" },
	.data = { "Data", "Scan Response Data" }
};

static void print_ad_uuids(int type)
{
	char **uuid;

	for (uuid = ad.uuids[type]; uuid && *uuid; uuid++)
		print_uuid(ad_names.uuid[type], *uuid);
}

static void print_ad_solicit(int type)
{
	char **uuid;

	for (uuid = ad.solicit[type]; uuid && *uuid; uuid++)
		print_uuid(ad_names.solicit[type], *uuid);
}

static void print_ad(void)
{
	int type;

	for (type = AD_TYPE_AD; type <= AD_TYPE_SRD; type++) {
		print_ad_uuids(type);
		print_ad_solicit(type);

		if (ad.service[type].uuid) {
			print_uuid(ad_names.service[type],
					ad.service[type].uuid);
			bt_shell_hexdump(ad.service[type].data.data,
						ad.service[type].data.len);
		}

		if (ad.manufacturer[type].data.len) {
			bt_shell_printf("%s: %u\n", ad_names.manufacturer[type],
						ad.manufacturer[type].id);
			bt_shell_hexdump(ad.manufacturer[type].data.data,
						ad.manufacturer[type].data.len);
		}

		if (ad.data[type].valid) {
			bt_shell_printf("%s Type: 0x%02x\n",
						ad_names.data[type],
						ad.data[type].type);
			bt_shell_hexdump(ad.data[type].data.data,
						ad.data[type].data.len);
		}
	}

	bt_shell_printf("Tx Power: %s\n", ad.tx_power ? "on" : "off");

	if (ad.local_name)
		bt_shell_printf("LocalName: %s\n", ad.local_name);
	else
		bt_shell_printf("Name: %s\n", ad.name ? "on" : "off");

	if (ad.local_appearance != UINT16_MAX)
		bt_shell_printf("Appearance: %s (0x%04x)\n",
					bt_appear_to_str(ad.local_appearance),
					ad.local_appearance);
	else
		bt_shell_printf("Appearance: %s\n",
					ad.appearance ? "on" : "off");

	bt_shell_printf("Discoverable: %s\n", ad.discoverable ? "on" : "off");
	bt_shell_printf("RSI: %s\n", ad.rsi ? "on" : "off");

	if (ad.duration)
		bt_shell_printf("Duration: %u sec\n", ad.duration);

	if (ad.timeout)
		bt_shell_printf("Timeout: %u sec\n", ad.timeout);

	if (ad.min_interval)
		bt_shell_printf("Interval: %u-%u msec\n", ad.min_interval,
					ad.max_interval);
}

static void register_reply(DBusMessage *message, void *user_data)
{
	DBusConnection *conn = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == FALSE) {
		ad.registered = true;
		bt_shell_printf("Advertising object registered\n");
		print_ad();
		return bt_shell_noninteractive_quit(-EINPROGRESS);
	} else {
		bt_shell_printf("Failed to register advertisement: %s\n", error.name);
		dbus_error_free(&error);

		if (g_dbus_unregister_interface(conn, AD_PATH,
						AD_IFACE) == FALSE)
			bt_shell_printf("Failed to unregister advertising object\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}
}

static gboolean get_type(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	const char *type = "peripheral";

	if (ad.type && strlen(ad.type) > 0)
		type = ad.type;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &type);

	return TRUE;
}

static gboolean uuids_exists(int type, const GDBusPropertyTable *property,
								void *data)
{
	return ad.uuids_len[type] != 0;
}

static gboolean get_uuids(int type, const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter array;
	size_t i;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "as", &array);

	for (i = 0; i < ad.uuids_len[type]; i++)
		dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING,
						&ad.uuids[type][i]);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean ad_uuids_exists(const GDBusPropertyTable *property, void *data)
{
	return uuids_exists(AD_TYPE_AD, property, data);
}

static gboolean get_ad_uuids(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	return get_uuids(AD_TYPE_AD, property, iter, user_data);
}

static gboolean sr_uuids_exists(const GDBusPropertyTable *property, void *data)
{
	return uuids_exists(AD_TYPE_SRD, property, data);
}

static gboolean get_sr_uuids(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	return get_uuids(AD_TYPE_SRD, property, iter, user_data);
}

static gboolean solicit_uuids_exists(int type,
				const GDBusPropertyTable *property, void *data)
{
	return ad.solicit_len[type] != 0;
}

static gboolean get_solicit_uuids(int type, const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter array;
	size_t i;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "as", &array);

	for (i = 0; i < ad.solicit_len[type]; i++)
		dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING,
						&ad.solicit[type][i]);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean ad_solicit_uuids_exists(const GDBusPropertyTable *property,
								void *data)
{
	return solicit_uuids_exists(AD_TYPE_AD, property, data);
}

static gboolean get_ad_solicit_uuids(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	return get_solicit_uuids(AD_TYPE_AD, property, iter, user_data);
}

static gboolean sr_solicit_uuids_exists(const GDBusPropertyTable *property,
								void *data)
{
	return solicit_uuids_exists(AD_TYPE_SRD, property, data);
}

static gboolean get_sr_solicit_uuids(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	return get_solicit_uuids(AD_TYPE_SRD, property, iter, user_data);
}

static gboolean service_data_exists(int type,
				const GDBusPropertyTable *property, void *data)
{
	return ad.service[type].uuid != NULL;
}

static gboolean get_service_data(int type, const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	struct ad_data *data = &ad.service[type].data;
	uint8_t *val = data->data;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

	g_dbus_dict_append_array(&dict, ad.service[type].uuid, DBUS_TYPE_BYTE,
							&val, data->len);

	dbus_message_iter_close_container(iter, &dict);

	return TRUE;
}

static gboolean ad_service_data_exists(const GDBusPropertyTable *property,
								void *data)
{
	return service_data_exists(AD_TYPE_AD, property, data);
}

static gboolean get_ad_service_data(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	return get_service_data(AD_TYPE_AD, property, iter, user_data);
}

static gboolean sr_service_data_exists(const GDBusPropertyTable *property,
								void *data)
{
	return service_data_exists(AD_TYPE_SRD, property, data);
}

static gboolean get_sr_service_data(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	return get_service_data(AD_TYPE_SRD, property, iter, user_data);
}

static gboolean manufacturer_data_exists(int type,
				const GDBusPropertyTable *property, void *data)
{
	return ad.manufacturer[type].id != 0;
}

static gboolean get_manufacturer_data(int type,
				const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	struct ad_data *data = &ad.manufacturer[type].data;
	uint8_t *val = data->data;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "{qv}", &dict);

	g_dbus_dict_append_basic_array(&dict, DBUS_TYPE_UINT16,
					&ad.manufacturer[type].id,
					DBUS_TYPE_BYTE, &val, data->len);

	dbus_message_iter_close_container(iter, &dict);

	return TRUE;
}

static gboolean ad_manufacturer_data_exists(const GDBusPropertyTable *property,
								void *data)
{
	return manufacturer_data_exists(AD_TYPE_AD, property, data);
}

static gboolean get_ad_manufacturer_data(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	return get_manufacturer_data(AD_TYPE_AD, property, iter, user_data);
}

static gboolean sr_manufacturer_data_exists(const GDBusPropertyTable *property,
								void *data)
{
	return manufacturer_data_exists(AD_TYPE_SRD, property, data);
}

static gboolean get_sr_manufacturer_data(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	return get_manufacturer_data(AD_TYPE_SRD, property, iter, user_data);
}

static gboolean includes_exists(const GDBusPropertyTable *property, void *data)
{
	return ad.tx_power || ad.name || ad.appearance || ad.rsi;
}

static gboolean get_includes(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "as", &array);

	if (ad.tx_power) {
		const char *str = "tx-power";

		dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &str);
	}

	if (ad.name) {
		const char *str = "local-name";

		dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &str);
	}

	if (ad.appearance) {
		const char *str = "appearance";

		dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &str);
	}

	if (ad.rsi) {
		const char *str = "rsi";

		dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &str);
	}

	dbus_message_iter_close_container(iter, &array);


	return TRUE;
}

static gboolean local_name_exists(const GDBusPropertyTable *property,
							void *data)
{
	return ad.local_name ? TRUE : FALSE;
}

static gboolean get_local_name(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &ad.local_name);

	return TRUE;
}

static gboolean appearance_exists(const GDBusPropertyTable *property,
							void *data)
{
	return ad.local_appearance != UINT16_MAX ? TRUE : FALSE;
}

static gboolean get_appearance(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16,
							&ad.local_appearance);

	return TRUE;
}

static gboolean duration_exists(const GDBusPropertyTable *property, void *data)
{
	return ad.duration;
}

static gboolean get_duration(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &ad.duration);

	return TRUE;
}

static gboolean timeout_exists(const GDBusPropertyTable *property, void *data)
{
	return ad.timeout;
}

static gboolean get_timeout(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &ad.timeout);

	return TRUE;
}

static gboolean data_exists(int type, const GDBusPropertyTable *property,
								void *data)
{
	return ad.data[type].valid;
}

static gboolean get_data(int type, const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	struct ad_data *data = &ad.data[type].data;
	uint8_t *val = data->data;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "{yv}", &dict);

	g_dbus_dict_append_basic_array(&dict, DBUS_TYPE_BYTE,
			&ad.data[type].type, DBUS_TYPE_BYTE, &val, data->len);

	dbus_message_iter_close_container(iter, &dict);

	return TRUE;
}

static gboolean ad_data_exists(const GDBusPropertyTable *property, void *data)
{
	return data_exists(AD_TYPE_AD, property, data);
}

static gboolean get_ad_data(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	return get_data(AD_TYPE_AD, property, iter, user_data);
}

static gboolean sr_data_exists(const GDBusPropertyTable *property, void *data)
{
	return data_exists(AD_TYPE_SRD, property, data);
}

static gboolean get_sr_data(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	return get_data(AD_TYPE_SRD, property, iter, user_data);
}

static gboolean get_discoverable(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	dbus_bool_t value = ad.discoverable;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &value);

	return TRUE;
}

static gboolean discoverable_timeout_exists(const GDBusPropertyTable *property,
							void *data)
{
	return ad.discoverable_to;
}

static gboolean get_discoverable_timeout(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16,
							&ad.discoverable_to);

	return TRUE;
}

static gboolean secondary_exists(const GDBusPropertyTable *property, void *data)
{
	return ad.secondary ? TRUE : FALSE;
}

static gboolean get_secondary(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
							&ad.secondary);

	return TRUE;
}

static gboolean min_interval_exists(const GDBusPropertyTable *property,
							void *data)
{
	return ad.min_interval;
}

static gboolean get_min_interval(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32,
						&ad.min_interval);

	return TRUE;
}

static gboolean max_interval_exists(const GDBusPropertyTable *property,
							void *data)
{
	return ad.max_interval;
}

static gboolean get_max_interval(const GDBusPropertyTable *property,
				DBusMessageIter *iter, void *user_data)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32,
						&ad.max_interval);

	return TRUE;
}

static const GDBusPropertyTable ad_props[] = {
	{ "Type", "s", get_type },
	{ "ServiceUUIDs", "as", get_ad_uuids, NULL, ad_uuids_exists },
	{ "SolicitUUIDs", "as", get_ad_solicit_uuids, NULL,
						ad_solicit_uuids_exists },
	{ "ServiceData", "a{sv}", get_ad_service_data, NULL,
						ad_service_data_exists },
	{ "ManufacturerData", "a{qv}", get_ad_manufacturer_data, NULL,
						ad_manufacturer_data_exists },
	{ "Data", "a{yv}", get_ad_data, NULL, ad_data_exists },
	{ "ScanResponseServiceUUIDs", "as", get_sr_uuids, NULL,
						sr_uuids_exists },
	{ "ScanResponseSolicitUUIDs", "as", get_sr_solicit_uuids, NULL,
						sr_solicit_uuids_exists },
	{ "ScanResponseServiceData", "a{sv}", get_sr_service_data, NULL,
						sr_service_data_exists },
	{ "ScanResponseManufacturerData", "a{qv}", get_sr_manufacturer_data,
					NULL, sr_manufacturer_data_exists },
	{ "ScanResponseData", "a{yv}", get_sr_data, NULL, sr_data_exists },
	{ "Discoverable", "b", get_discoverable, NULL, NULL },
	{ "DiscoverableTimeout", "q", get_discoverable_timeout, NULL,
						discoverable_timeout_exists },
	{ "Includes", "as", get_includes, NULL, includes_exists },
	{ "LocalName", "s", get_local_name, NULL, local_name_exists },
	{ "Appearance", "q", get_appearance, NULL, appearance_exists },
	{ "Duration", "q", get_duration, NULL, duration_exists },
	{ "Timeout", "q", get_timeout, NULL, timeout_exists },
	{ "MinInterval", "u", get_min_interval, NULL, min_interval_exists },
	{ "MaxInterval", "u", get_max_interval, NULL, max_interval_exists },
	{ "SecondaryChannel", "s", get_secondary, NULL, secondary_exists },
	{ }
};

void ad_register(DBusConnection *conn, GDBusProxy *manager, const char *type)
{
	if (ad.registered) {
		bt_shell_printf("Advertisement is already registered\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	g_free(ad.type);
	ad.type = g_strdup(type);

	if (!strcasecmp(ad.type, "Broadcast"))
		ad.discoverable = false;

	if (g_dbus_register_interface(conn, AD_PATH, AD_IFACE, ad_methods,
					NULL, ad_props, NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to register advertising object\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (g_dbus_proxy_method_call(manager, "RegisterAdvertisement",
					register_setup, register_reply,
					conn, NULL) == FALSE) {
		bt_shell_printf("Failed to register advertising\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
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
		ad.registered = false;
		bt_shell_printf("Advertising object unregistered\n");
		if (g_dbus_unregister_interface(conn, AD_PATH,
							AD_IFACE) == FALSE)
			bt_shell_printf("Failed to unregister advertising"
					" object\n");
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	} else {
		bt_shell_printf("Failed to unregister advertisement: %s\n",
								error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}
}

void ad_unregister(DBusConnection *conn, GDBusProxy *manager)
{
	if (!manager)
		ad_release(conn);

	if (!ad.registered)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	g_free(ad.type);
	ad.type = NULL;

	if (g_dbus_proxy_method_call(manager, "UnregisterAdvertisement",
					unregister_setup, unregister_reply,
					conn, NULL) == FALSE) {
		bt_shell_printf("Failed to unregister advertisement method\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}
}

static const struct {
	const char *uuid[AD_TYPE_COUNT];
	const char *solicit[AD_TYPE_COUNT];
	const char *service[AD_TYPE_COUNT];
	const char *manufacturer[AD_TYPE_COUNT];
	const char *data[AD_TYPE_COUNT];
} prop_names = {
	.uuid = { "ServiceUUIDs", "ScanResponseServiceUUIDs" },
	.solicit = { "SolicitUUIDs", "ScanResponseSolicitUUIDs" },
	.service = { "ServiceData", "ScanResponseServiceData" },
	.manufacturer = { "ManufacturerData", "ScanResponseManufacturerData" },
	.data = { "Data", "ScanResponseData" }
};

static void ad_clear_uuids(int type)
{
	g_strfreev(ad.uuids[type]);
	ad.uuids[type] = NULL;
	ad.uuids_len[type] = 0;
}

void ad_advertise_uuids(DBusConnection *conn, int type, int argc, char *argv[])
{
	if (argc < 2 || !strlen(argv[1])) {
		print_ad_uuids(type);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	ad_clear_uuids(type);

	ad.uuids[type] = g_strdupv(&argv[1]);
	if (!ad.uuids[type]) {
		bt_shell_printf("Failed to parse input\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	ad.uuids_len[type] = g_strv_length(ad.uuids[type]);

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
							prop_names.uuid[type]);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_disable_uuids(DBusConnection *conn, int type)
{
	if (!ad.uuids[type])
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	ad_clear_uuids(type);
	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
							prop_names.uuid[type]);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void ad_clear_solicit(int type)
{
	g_strfreev(ad.solicit[type]);
	ad.solicit[type] = NULL;
	ad.solicit_len[type] = 0;
}

void ad_advertise_solicit(DBusConnection *conn, int type,
							int argc, char *argv[])
{
	if (argc < 2 || !strlen(argv[1])) {
		print_ad_solicit(type);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	ad_clear_solicit(type);

	ad.solicit[type] = g_strdupv(&argv[1]);
	if (!ad.solicit[type]) {
		bt_shell_printf("Failed to parse input\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	ad.solicit_len[type] = g_strv_length(ad.solicit[type]);

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
						prop_names.solicit[type]);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_disable_solicit(DBusConnection *conn, int type)
{
	if (!ad.solicit[type])
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	ad_clear_solicit(type);
	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
						prop_names.solicit[type]);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void ad_clear_service(int type)
{
	g_free(ad.service[type].uuid);
	memset(&ad.service[type], 0, sizeof(ad.service[type]));
}

static bool ad_add_data(struct ad_data *data, int argc, char *argv[])
{
	unsigned int i;

	memset(data, 0, sizeof(*data));

	for (i = 0; i < (unsigned int) argc; i++) {
		long int val;
		char *endptr = NULL;

		if (i >= G_N_ELEMENTS(data->data)) {
			bt_shell_printf("Too much data\n");
			return false;
		}

		val = strtol(argv[i], &endptr, 0);
		if (!endptr || *endptr != '\0' || val > UINT8_MAX) {
			bt_shell_printf("Invalid value at index %d\n", i);
			return false;
		}

		data->data[data->len] = val;
		data->len++;
	}

	return true;
}

void ad_advertise_service(DBusConnection *conn, int type,
							int argc, char *argv[])
{
	struct ad_data data;

	if (argc < 2 || !strlen(argv[1])) {
		if (ad.service[type].uuid) {
			print_uuid(ad_names.service[type],
						ad.service[type].uuid);
			bt_shell_hexdump(ad.service[type].data.data,
						ad.service[type].data.len);
		}
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	if (!ad_add_data(&data, argc - 2, argv + 2))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	ad_clear_service(type);

	ad.service[type].uuid = g_strdup(argv[1]);
	ad.service[type].data = data;

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
						prop_names.service[type]);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_disable_service(DBusConnection *conn, int type)
{
	if (!ad.service[type].uuid)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	ad_clear_service(type);
	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
						prop_names.service[type]);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void ad_clear_manufacturer(int type)
{
	memset(&ad.manufacturer[type], 0, sizeof(ad.manufacturer[type]));
}

void ad_advertise_manufacturer(DBusConnection *conn, int type,
							int argc, char *argv[])
{
	char *endptr = NULL;
	long int val;
	struct ad_data data;

	if (argc < 2 || !strlen(argv[1])) {
		if (ad.manufacturer[type].data.len) {
			bt_shell_printf("%s: %u\n", ad_names.manufacturer[type],
						ad.manufacturer[type].id);
			bt_shell_hexdump(ad.manufacturer[type].data.data,
						ad.manufacturer[type].data.len);
		}

		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	val = strtol(argv[1], &endptr, 0);
	if (!endptr || *endptr != '\0' || val > UINT16_MAX) {
		bt_shell_printf("Invalid manufacture id\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!ad_add_data(&data, argc - 2, argv + 2))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	ad_clear_manufacturer(type);
	ad.manufacturer[type].id = val;
	ad.manufacturer[type].data = data;

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
						prop_names.manufacturer[type]);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_disable_manufacturer(DBusConnection *conn, int type)
{
	if (!ad.manufacturer[type].id && !ad.manufacturer[type].data.len)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	ad_clear_manufacturer(type);
	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
						prop_names.manufacturer[type]);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void ad_clear_data(int type)
{
	memset(&ad.data[type], 0, sizeof(ad.data[type]));
}

void ad_advertise_data(DBusConnection *conn, int type, int argc, char *argv[])
{
	char *endptr = NULL;
	long int val;
	struct ad_data data;

	if (argc < 2 || !strlen(argv[1])) {
		if (ad.data[type].data.len) {
			bt_shell_printf("%s Type: 0x%02x\n",
							ad_names.data[type],
							ad.data[type].type);
			bt_shell_hexdump(ad.data[type].data.data,
							ad.data[type].data.len);
		}

		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	val = strtol(argv[1], &endptr, 0);
	if (!endptr || *endptr != '\0' || val > UINT8_MAX) {
		bt_shell_printf("Invalid type\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!ad_add_data(&data, argc - 2, argv + 2))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	ad_clear_data(type);
	ad.data[type].valid = true;
	ad.data[type].type = val;
	ad.data[type].data = data;

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
							prop_names.data[type]);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_disable_data(DBusConnection *conn, int type)
{
	if (!ad.data[type].type && !ad.data[type].data.len)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	ad_clear_data(type);
	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
							prop_names.data[type]);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_advertise_discoverable(DBusConnection *conn, dbus_bool_t *value)
{
	if (!value) {
		bt_shell_printf("Discoverable: %s\n",
				ad.discoverable ? "on" : "off");
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	if (ad.discoverable == *value)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	ad.discoverable = *value;

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE, "Discoverable");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_advertise_discoverable_timeout(DBusConnection *conn, long int *value)
{
	if (!value) {
		if (ad.discoverable_to)
			bt_shell_printf("Timeout: %u sec\n",
					ad.discoverable_to);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	if (ad.discoverable_to == *value)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	ad.discoverable_to = *value;

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
					"DiscoverableTimeout");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_advertise_tx_power(DBusConnection *conn, dbus_bool_t *value)
{
	if (!value) {
		bt_shell_printf("Tx Power: %s\n", ad.tx_power ? "on" : "off");
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	if (ad.tx_power == *value)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	ad.tx_power = *value;

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE, "Includes");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_advertise_name(DBusConnection *conn, bool value)
{
	if (ad.name == value)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	ad.name = value;

	if (!value) {
		free(ad.local_name);
		ad.local_name = NULL;
	}

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE, "Includes");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_advertise_local_name(DBusConnection *conn, const char *name)
{
	if (!name) {
		if (ad.local_name)
			bt_shell_printf("LocalName: %s\n", ad.local_name);
		else
			bt_shell_printf("Name: %s\n", ad.name ? "on" : "off");

		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	if (ad.local_name && !strcmp(name, ad.local_name))
		return;

	g_free(ad.local_name);
	ad.local_name = strdup(name);

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE, "LocalName");

	/* Remove local-name from Includes since LocalName would be set */
	if (ad.name) {
		ad.name = false;
		g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
							"Includes");
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_advertise_appearance(DBusConnection *conn, bool value)
{
	if (ad.appearance == value)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	ad.appearance = value;

	if (!value)
		ad.local_appearance = UINT16_MAX;

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE, "Includes");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_advertise_local_appearance(DBusConnection *conn, long int *value)
{
	if (!value) {
		if (ad.local_appearance != UINT16_MAX)
			bt_shell_printf("Appearance: %s (0x%04x)\n",
					bt_appear_to_str(ad.local_appearance),
					ad.local_appearance);
		else
			bt_shell_printf("Appearance: %s\n",
					ad.appearance ? "on" : "off");

		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	if (ad.local_appearance == *value)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	ad.local_appearance = *value;

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE, "Appearance");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_advertise_duration(DBusConnection *conn, long int *value)
{
	if (!value) {
		if (ad.duration)
			bt_shell_printf("Duration: %u sec\n", ad.duration);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	if (ad.duration == *value)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	ad.duration = *value;

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE, "Duration");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_advertise_timeout(DBusConnection *conn, long int *value)
{
	if (!value) {
		if (ad.timeout)
			bt_shell_printf("Timeout: %u sec\n", ad.timeout);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	if (ad.timeout == *value)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	ad.timeout = *value;

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE, "Timeout");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_advertise_secondary(DBusConnection *conn, const char *value)
{
	if (!value) {
		if (ad.secondary)
			 bt_shell_printf("Secondary Channel: %s\n",
							ad.secondary);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	if (ad.secondary && !strcmp(value, ad.secondary))
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	free(ad.secondary);

	if (value[0] == '\0') {
		ad.secondary = NULL;
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	ad.secondary = strdup(value);

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
							"SecondaryChannel");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_advertise_interval(DBusConnection *conn, uint32_t *min, uint32_t *max)
{
	if (!min && !max) {
		if (ad.min_interval && ad.max_interval)
			bt_shell_printf("Interval: %u-%u msec\n",
					ad.min_interval, ad.max_interval);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	if (min && ad.min_interval != *min) {
		ad.min_interval = *min;
		g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
							"MinInterval");
	}

	if (max && ad.max_interval != *max) {
		ad.max_interval = *max;
		g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE,
							"MaxInterval");
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void ad_advertise_rsi(DBusConnection *conn, dbus_bool_t *value)
{
	if (!value) {
		bt_shell_printf("RSI: %s\n", ad.rsi ? "on" : "off");
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	if (ad.rsi == *value)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	ad.rsi = *value;

	g_dbus_emit_property_changed(conn, AD_PATH, AD_IFACE, "Includes");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}
