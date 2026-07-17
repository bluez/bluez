// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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

#include <glib.h>

#include "gdbus/gdbus.h"
#include "src/shared/shell.h"
#include "src/shared/util.h"
#include "cs.h"

static GList * cs_proxies;
static GList **cs_device_list;

/* ---- Per-device active session ---- */

struct cs_session {
	GDBusProxy *proxy;
};

static GList *cs_sessions;

static struct cs_session *cs_find_session(GDBusProxy *proxy);

/* ---- Parameter state (used to build the StartMeasurement dict) ---- */

static uint8_t cs_role        = 0x03;
static uint8_t cs_sync_ant    = 0xFF;
static int8_t  cs_max_tx_power = 0x14;

static struct {
	uint8_t create_context;
	uint8_t config_id;
	uint8_t main_mode_type;
	uint8_t sub_mode_type;
	uint8_t main_mode_min_steps;
	uint8_t main_mode_max_steps;
	uint8_t main_mode_repetition;
	uint8_t mode0_steps;
	uint8_t role;
	uint8_t rtt_types;
	uint8_t cs_sync_phy;
	uint8_t channel_map[10];
	uint8_t channel_map_repetition;
	uint8_t channel_selection_type;
	uint8_t channel_shape;
	uint8_t channel_jump;
	uint8_t companion_signal_enable;
} cs_cfg = {
	.create_context          = 0x01,
	.config_id               = 0x00,
	.main_mode_type          = 0x01,
	.sub_mode_type           = 0xFF,
	.main_mode_min_steps     = 0x02,
	.main_mode_max_steps     = 0x03,
	.main_mode_repetition    = 0x01,
	.mode0_steps             = 0x02,
	.role                    = 0x00,
	.rtt_types               = 0x00,
	.cs_sync_phy             = 0x01,
	.channel_map             = { 0xFC, 0xFF, 0x7F, 0xFC, 0xFF,
				     0xFF, 0xFF, 0xFF, 0xFF, 0x1F },
	.channel_map_repetition  = 0x01,
	.channel_selection_type  = 0x00,
	.channel_shape           = 0x00,
	.channel_jump            = 0x02,
	.companion_signal_enable = 0x00,
};

static struct {
	uint16_t max_procedure_duration;
	uint16_t min_period_between_procedures;
	uint16_t max_period_between_procedures;
	uint16_t max_procedure_count;
	uint8_t  min_sub_event_len[3];
	uint8_t  max_sub_event_len[3];
	uint8_t  tone_antenna_config_selection;
	uint8_t  phy;
	uint8_t  tx_power_delta;
	uint8_t  preferred_peer_antenna;
	uint8_t  snr_control_initiator;
	uint8_t  snr_control_reflector;
} cs_freq = {
	.max_procedure_duration        = 0x0640,
	.min_period_between_procedures = 0x001E,
	.max_period_between_procedures = 0x0096,
	.max_procedure_count           = 0x0000,
	.min_sub_event_len             = { 0x00, 0x20, 0x00 },
	.max_sub_event_len             = { 0x03, 0x20, 0x00 },
	.tone_antenna_config_selection = 0x07,
	.phy                           = 0x01,
	.tx_power_delta                = 0x80,
	.preferred_peer_antenna        = 0x03,
	.snr_control_initiator         = 0xFF,
	.snr_control_reflector         = 0xFF,
};

enum cs_param_type {
	CS_PARAM_U8,
	CS_PARAM_U8_RANGE,
	CS_PARAM_U16,
};

struct cs_param_desc {
	const char *name;
	enum cs_param_type type;
	void *field;
	unsigned long min;
	unsigned long max;
	const char *range_error;
};

static const struct cs_param_desc cs_param_table[] = {
	{ .name = "create_context", .type = CS_PARAM_U8_RANGE,
		.field = &cs_cfg.create_context, .min = 0, .max = 1,
		.range_error = "create_context: 0x00=local only"
				" 0x01=local and remote\n" },
	{ .name = "sync_ant_sel", .type = CS_PARAM_U8, .field = &cs_sync_ant },
	{ .name = "config_id", .type = CS_PARAM_U8,
		.field = &cs_cfg.config_id },
	{ .name = "main_mode_type", .type = CS_PARAM_U8,
		.field = &cs_cfg.main_mode_type },
	{ .name = "sub_mode_type", .type = CS_PARAM_U8,
		.field = &cs_cfg.sub_mode_type },
	{ .name = "main_mode_min_steps", .type = CS_PARAM_U8,
		.field = &cs_cfg.main_mode_min_steps },
	{ .name = "main_mode_max_steps", .type = CS_PARAM_U8,
		.field = &cs_cfg.main_mode_max_steps },
	{ .name = "main_mode_repetition", .type = CS_PARAM_U8,
		.field = &cs_cfg.main_mode_repetition },
	{ .name = "mode0_steps", .type = CS_PARAM_U8,
		.field = &cs_cfg.mode0_steps },
	{ .name = "rtt_types", .type = CS_PARAM_U8,
		.field = &cs_cfg.rtt_types },
	{ .name = "role", .type = CS_PARAM_U8_RANGE, .field = &cs_role,
		.min = 0x01, .max = 0x03,
		.range_error = "role: 01=Initiator 02=Reflector 03=Both\n" },
	{ .name = "sync_phy", .type = CS_PARAM_U8_RANGE,
		.field = &cs_cfg.cs_sync_phy, .min = 0x01, .max = 0x02,
		.range_error = "sync_phy: 0x01=LE 1M 0x02=LE 2M\n" },
	{ .name = "channel_map_repetition", .type = CS_PARAM_U8,
		.field = &cs_cfg.channel_map_repetition },
	{ .name = "channel_selection_type", .type = CS_PARAM_U8,
		.field = &cs_cfg.channel_selection_type },
	{ .name = "channel_shape", .type = CS_PARAM_U8,
		.field = &cs_cfg.channel_shape },
	{ .name = "channel_jump", .type = CS_PARAM_U8,
		.field = &cs_cfg.channel_jump },
	{ .name = "companion_signal_enable", .type = CS_PARAM_U8_RANGE,
		.field = &cs_cfg.companion_signal_enable, .min = 0, .max = 1,
		.range_error = "companion_signal_enable: 0 or 1\n" },
	{ .name = "max_procedure_duration", .type = CS_PARAM_U16,
		.field = &cs_freq.max_procedure_duration },
	{ .name = "min_period_between_procedures", .type = CS_PARAM_U16,
		.field = &cs_freq.min_period_between_procedures },
	{ .name = "max_period_between_procedures", .type = CS_PARAM_U16,
		.field = &cs_freq.max_period_between_procedures },
	{ .name = "max_procedure_count", .type = CS_PARAM_U16,
		.field = &cs_freq.max_procedure_count },
	{ .name = "tone_antenna_config_selection", .type = CS_PARAM_U8,
		.field = &cs_freq.tone_antenna_config_selection },
	{ .name = "phy", .type = CS_PARAM_U8_RANGE, .field = &cs_freq.phy,
		.min = 0x01, .max = 0x02,
		.range_error = "phy: 0x01=LE 1M  0x02=LE 2M\n" },
	{ .name = "tx_power_delta", .type = CS_PARAM_U8,
		.field = &cs_freq.tx_power_delta },
	{ .name = "preferred_peer_antenna", .type = CS_PARAM_U8,
		.field = &cs_freq.preferred_peer_antenna },
	{ .name = "snr_control_initiator", .type = CS_PARAM_U8,
		.field = &cs_freq.snr_control_initiator },
	{ .name = "snr_control_reflector", .type = CS_PARAM_U8,
		.field = &cs_freq.snr_control_reflector },
};

void cs_proxy_added(GDBusProxy *proxy)
{
	cs_proxies = g_list_append(cs_proxies, proxy);
}

void cs_proxy_removed(GDBusProxy *proxy)
{
	struct cs_session *s;
	GList *list;

	cs_proxies = g_list_remove(cs_proxies, proxy);

	for (list = g_list_first(cs_sessions); list;
	     list = g_list_next(list)) {
		s = list->data;

		if (s->proxy == proxy) {
			cs_sessions = g_list_remove(cs_sessions, s);
			g_free(s);
			break;
		}
	}
}

/* Drop any active CS session for a device proxy path on disconnect. */
void cs_device_disconnected(const char *dev_path)
{
	struct cs_session *s;
	GList *list;

	for (list = g_list_first(cs_sessions); list;
	     list = g_list_next(list)) {
		s = list->data;

		if (!strcmp(g_dbus_proxy_get_path(s->proxy), dev_path)) {
			bt_shell_printf("Measurement stopped (disconnected)"
					" on %s\n", dev_path);
			cs_sessions = g_list_remove(cs_sessions, s);
			g_free(s);
			break;
		}
	}
}

/* Drop active CS session when the daemon reports the measurement stopped. */
void cs_measurement_stopped(GDBusProxy *proxy)
{
	struct cs_session *s = cs_find_session(proxy);

	if (!s)
		return;

	bt_shell_printf("Measurement stopped (timer expired) on %s\n",
			g_dbus_proxy_get_path(proxy));
	cs_sessions = g_list_remove(cs_sessions, s);
	g_free(s);
}

/* Record a measurement started by the remote side (Reflector role). */
void cs_measurement_started(GDBusProxy *proxy)
{
	struct cs_session *s;

	if (cs_find_session(proxy))
		return;

	s = g_new0(struct cs_session, 1);
	s->proxy = proxy;
	cs_sessions = g_list_append(cs_sessions, s);

	bt_shell_printf("Measurement started on %s\n",
			g_dbus_proxy_get_path(proxy));
}

void cs_set_device_list(GList **devices)
{
	cs_device_list = devices;
}

/* Resolve a Bluetooth address to the device's D-Bus object path. */
static const char *cs_resolve_address(const char *address)
{
	GDBusProxy *proxy;
	DBusMessageIter iter;
	const char *str;
	GList *list;

	if (!cs_device_list) {
		bt_shell_printf("DBG: cs_device_list is NULL\n");
		return NULL;
	}

	if (!*cs_device_list) {
		bt_shell_printf("DBG: *cs_device_list is empty\n");
		return NULL;
	}

	for (list = g_list_first(*cs_device_list); list;
	     list = g_list_next(list)) {
		proxy = list->data;

		if (!g_dbus_proxy_get_property(proxy, "Address", &iter)) {
			bt_shell_printf("DBG: proxy %s has no Address\n",
					g_dbus_proxy_get_path(proxy));
			continue;
		}

		dbus_message_iter_get_basic(&iter, &str);

		if (!strcasecmp(str, address))
			return g_dbus_proxy_get_path(proxy);
	}

	return NULL;
}

/* Find the ChannelSounding1 proxy for the device at the given object path. */
static GDBusProxy *cs_find_proxy(const char *dev_path)
{
	GDBusProxy *proxy;
	const char *path;
	GList *list;

	if (!cs_proxies) {
		bt_shell_printf("DBG: cs_proxies is empty\n");
		return NULL;
	}

	for (list = g_list_first(cs_proxies); list;
	     list = g_list_next(list)) {
		proxy = list->data;
		path = g_dbus_proxy_get_path(proxy);

		if (!strcmp(path, dev_path))
			return proxy;
	}

	return NULL;
}

static struct cs_session *cs_find_session(GDBusProxy *proxy)
{
	struct cs_session *s;
	GList *list;

	for (list = g_list_first(cs_sessions); list;
	     list = g_list_next(list)) {
		s = list->data;

		if (s->proxy == proxy)
			return s;
	}

	return NULL;
}

/* ---- dict helpers ---- */

static void dict_append_byte(DBusMessageIter *dict, const char *key,
			     uint8_t val)
{
	DBusMessageIter entry, variant;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
					 NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
					 DBUS_TYPE_BYTE_AS_STRING, &variant);
	dbus_message_iter_append_basic(&variant, DBUS_TYPE_BYTE, &val);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(dict, &entry);
}

static void dict_append_uint16(DBusMessageIter *dict, const char *key,
			       uint16_t val)
{
	DBusMessageIter entry, variant;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
					 NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
					 "q", &variant);
	dbus_message_iter_append_basic(&variant, DBUS_TYPE_UINT16, &val);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(dict, &entry);
}

static void dict_append_uint32(DBusMessageIter *dict, const char *key,
			       uint32_t val)
{
	DBusMessageIter entry, variant;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
					 NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
					 "u", &variant);
	dbus_message_iter_append_basic(&variant, DBUS_TYPE_UINT32, &val);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(dict, &entry);
}

static void dict_append_byte_array(DBusMessageIter *dict, const char *key,
				   const uint8_t *bytes, int len)
{
	DBusMessageIter entry, variant, array;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
					 NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
					 "ay", &variant);
	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
					 DBUS_TYPE_BYTE_AS_STRING, &array);
	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
					     &bytes, len);
	dbus_message_iter_close_container(&variant, &array);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(dict, &entry);
}

/* ---- start ---- */

static uint32_t pending_duration_secs;
static const char *pending_dev_path;

static void start_measurement_setup(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	uint8_t tx = (uint8_t)cs_max_tx_power;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					 "{sv}", &dict);

	/* timing */
	dict_append_uint32(&dict, "duration_secs", pending_duration_secs);

	/* default settings */
	dict_append_byte(&dict, "role",            cs_role);
	dict_append_byte(&dict, "sync_ant_sel", cs_sync_ant);
	dict_append_byte(&dict, "max_tx_power",    tx);

	/* CS config */
	dict_append_byte(&dict, "create_context",
			 cs_cfg.create_context);
	dict_append_byte(&dict, "config_id",
			 cs_cfg.config_id);
	dict_append_byte(&dict, "main_mode_type",
			 cs_cfg.main_mode_type);
	dict_append_byte(&dict, "sub_mode_type",
			 cs_cfg.sub_mode_type);
	dict_append_byte(&dict, "main_mode_min_steps",
			 cs_cfg.main_mode_min_steps);
	dict_append_byte(&dict, "main_mode_max_steps",
			 cs_cfg.main_mode_max_steps);
	dict_append_byte(&dict, "main_mode_repetition",
			 cs_cfg.main_mode_repetition);
	dict_append_byte(&dict, "mode0_steps",
			 cs_cfg.mode0_steps);
	dict_append_byte(&dict, "rtt_types",
			 cs_cfg.rtt_types);
	dict_append_byte(&dict, "sync_phy",
			 cs_cfg.cs_sync_phy);
	dict_append_byte_array(&dict, "channel_map",
			       cs_cfg.channel_map, 10);
	dict_append_byte(&dict, "channel_map_repetition",
			 cs_cfg.channel_map_repetition);
	dict_append_byte(&dict, "channel_selection_type",
			 cs_cfg.channel_selection_type);
	dict_append_byte(&dict, "channel_shape",
			 cs_cfg.channel_shape);
	dict_append_byte(&dict, "channel_jump",
			 cs_cfg.channel_jump);
	dict_append_byte(&dict, "companion_signal_enable",
			 cs_cfg.companion_signal_enable);

	/* CS frequency */
	dict_append_uint16(&dict, "max_procedure_duration",
			   cs_freq.max_procedure_duration);
	dict_append_uint16(&dict, "min_period_between_procedures",
			   cs_freq.min_period_between_procedures);
	dict_append_uint16(&dict, "max_period_between_procedures",
			   cs_freq.max_period_between_procedures);
	dict_append_uint16(&dict, "max_procedure_count",
			   cs_freq.max_procedure_count);
	dict_append_byte_array(&dict, "min_sub_event_len",
			       cs_freq.min_sub_event_len, 3);
	dict_append_byte_array(&dict, "max_sub_event_len",
			       cs_freq.max_sub_event_len, 3);
	dict_append_byte(&dict, "tone_antenna_config_selection",
			 cs_freq.tone_antenna_config_selection);
	dict_append_byte(&dict, "phy",
			 cs_freq.phy);
	dict_append_byte(&dict, "tx_power_delta",
			 cs_freq.tx_power_delta);
	dict_append_byte(&dict, "preferred_peer_antenna",
			 cs_freq.preferred_peer_antenna);
	dict_append_byte(&dict, "snr_control_initiator",
			 cs_freq.snr_control_initiator);
	dict_append_byte(&dict, "snr_control_reflector",
			 cs_freq.snr_control_reflector);

	dbus_message_iter_close_container(iter, &dict);
}

/* ---- cs_set_param: apply name=value to the local parameter state ---- */
static bool parse_hex_bytes(const char *name, const char *valstr,
					uint8_t *out, unsigned int count)
{
	const char *str = valstr;
	char *endptr;
	unsigned long uval;
	unsigned int i = 0;

	while (i < count) {
		uval = strtoul(str, &endptr, 16);
		if (endptr == str || uval > 0xFF) {
			bt_shell_printf("%s: invalid byte at index %u\n",
					name, i);
			return false;
		}
		out[i++] = (uint8_t)uval;
		if (*endptr == '\0')
			break;
		if (*endptr != ':') {
			bt_shell_printf("%s: expected ':' separator\n", name);
			return false;
		}
		str = endptr + 1;
	}

	if (i != count) {
		bt_shell_printf("%s: need exactly %u colon-separated hex"
				" bytes\n", name, count);
		return false;
	}

	return true;
}

static const struct cs_param_desc *cs_find_param_desc(const char *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cs_param_table); i++) {
		if (!strcmp(cs_param_table[i].name, name))
			return &cs_param_table[i];
	}

	return NULL;
}

static bool cs_set_param(const char *name, const char *valstr)
{
	const struct cs_param_desc *desc;
	char *endptr;
	unsigned long uval;
	long sval;

	/* Byte-array: channel_map — 10 colon-separated hex bytes */
	if (strcmp(name, "channel_map") == 0) {
		if (!parse_hex_bytes(name, valstr, cs_cfg.channel_map, 10))
			return false;
		return true;
	}

	/* Byte-array: min/max_sub_event_len — 3 colon-separated hex bytes */
	if (strcmp(name, "min_sub_event_len") == 0)
		return parse_hex_bytes(name, valstr,
					cs_freq.min_sub_event_len, 3);
	if (strcmp(name, "max_sub_event_len") == 0)
		return parse_hex_bytes(name, valstr,
					cs_freq.max_sub_event_len, 3);

	/* max_tx_power is signed (-127 to +20 dBm) */
	if (strcmp(name, "max_tx_power") == 0) {
		sval = strtol(valstr, &endptr, 0);

		if (*endptr != '\0' || sval < -127 || sval > 20) {
			bt_shell_printf("max_tx_power: valid range -127"
					" to 20 dBm\n");
			return false;
		}
		cs_max_tx_power = (int8_t)sval;
		return true;
	}

	desc = cs_find_param_desc(name);
	if (!desc) {
		bt_shell_printf("Unknown parameter: %s\n", name);
		return false;
	}

	/* All remaining parameters are unsigned */
	uval = strtoul(valstr, &endptr, 0);
	if (*endptr != '\0') {
		bt_shell_printf("%s: invalid value '%s'\n", name, valstr);
		return false;
	}

	if (desc->type == CS_PARAM_U8_RANGE &&
			(uval < desc->min || uval > desc->max)) {
		bt_shell_printf("%s", desc->range_error);
		return false;
	}

	if (desc->type == CS_PARAM_U16)
		*(uint16_t *)desc->field = (uint16_t)uval;
	else
		*(uint8_t *)desc->field = (uint8_t)uval;

	return true;
}

static void start_measurement_reply(DBusMessage *message, void *user_data)
{
	GDBusProxy *proxy = user_data;
	struct cs_session *s;
	DBusError error;

	dbus_error_init(&error);
	if (dbus_set_error_from_message(&error, message)) {
		bt_shell_printf("StartMeasurement failed: %s\n", error.message);
		dbus_error_free(&error);
		return;
	}

	if (cs_role == 0x02) {
		bt_shell_printf("Default settings applied on %s;"
				" Reflector role does not start a local"
				" measurement\n",
				g_dbus_proxy_get_path(proxy));
		return;
	}

	s = g_new0(struct cs_session, 1);
	s->proxy    = proxy;
	cs_sessions = g_list_append(cs_sessions, s);

	bt_shell_printf("Measurement started on %s\n",
			g_dbus_proxy_get_path(proxy));
}

static void cs_print_role_hint(uint8_t role)
{
	if (role == 0x02)
		bt_shell_printf("Note: Reflector role only uses"
				" role/cs_sync_ant_sel/max_tx_power;"
				" other CS config/frequency parameters"
				" are ignored.\n");
	else
		bt_shell_printf("Note: Initiator role requires dev_addr"
				" and duration_secs; CS config/frequency"
				" parameters configure the measurement"
				" procedure.\n");
}

/* Generic handler for the per-parameter set commands (cs.role,
 * cs.main_mode_type, ...); argv[0] is the parameter name (the command
 * itself), argv[1] is the value.
 */
static void cmd_cs_set(int argc, char *argv[])
{
	if (argc < 2) {
		bt_shell_printf("Usage: %s <value>\n", argv[0]);
		return;
	}

	if (!cs_set_param(argv[0], argv[1]))
		return;

	if (!strcmp(argv[0], "role"))
		cs_print_role_hint(cs_role);
}

/* Tab completion for params whose only legal values are a small fixed
 * enum, so users don't need to consult documentation to know what's
 * valid.
 */
static char *cs_value_generator(const char *text, int state,
					const char * const values[])
{
	static unsigned int index, len;
	const char *value;

	if (!state) {
		index = 0;
		len = strlen(text);
	}

	while ((value = values[index])) {
		index++;

		if (!strncmp(value, text, len))
			return strdup(value);
	}

	return NULL;
}

static const char * const cs_role_values[] = { "0x01", "0x02", "0x03", NULL };

static char *cs_role_generator(const char *text, int state)
{
	return cs_value_generator(text, state, cs_role_values);
}

static const char * const cs_main_mode_type_values[] = { "1", "2", "3", NULL };

static char *cs_main_mode_type_generator(const char *text, int state)
{
	return cs_value_generator(text, state, cs_main_mode_type_values);
}

static const char * const cs_phy_values[] = { "0x01", "0x02", NULL };

static char *cs_phy_generator(const char *text, int state)
{
	return cs_value_generator(text, state, cs_phy_values);
}

static const char * const cs_bool_values[] = { "0", "1", NULL };

static char *cs_bool_generator(const char *text, int state)
{
	return cs_value_generator(text, state, cs_bool_values);
}

static const char * const cs_sub_mode_type_values[] = { "0x01", "0x02",
							"0x03", "0xFF", NULL };

static char *cs_sub_mode_type_generator(const char *text, int state)
{
	return cs_value_generator(text, state, cs_sub_mode_type_values);
}

static void cmd_cs_start(int argc, char *argv[])
{
	GDBusProxy *proxy;
	char *endptr;
	unsigned long val;

	pending_duration_secs = 0;
	pending_dev_path = NULL;

	if (argc >= 2) {
		pending_dev_path = cs_resolve_address(argv[1]);
		if (!pending_dev_path) {
			bt_shell_printf("Device %s not found\n", argv[1]);
			return;
		}
	}

	if (argc >= 3) {
		val = strtoul(argv[2], &endptr, 0);

		if (*endptr != '\0') {
			bt_shell_printf("Invalid duration: %s\n", argv[2]);
			return;
		}
		pending_duration_secs = (uint32_t)val;
	}

	if (argc > 3) {
		bt_shell_printf("Too many arguments\n");
		return;
	}

	cs_print_role_hint(cs_role);

	if (pending_dev_path) {
		proxy = cs_find_proxy(pending_dev_path);
		if (!proxy) {
			bt_shell_printf("No ChannelSounding1 interface for"
					" that device\n");
			return;
		}
	} else {
		if (!cs_proxies) {
			bt_shell_printf("No ChannelSounding1 interface"
					" available\n");
			return;
		}
		proxy = cs_proxies->data;
	}

	if (cs_find_session(proxy)) {
		bt_shell_printf("Measurement already active on %s\n",
				g_dbus_proxy_get_path(proxy));
		return;
	}

	if (!g_dbus_proxy_method_call(proxy, "StartMeasurement",
				      start_measurement_setup,
				      start_measurement_reply, proxy, NULL))
		bt_shell_printf("Failed to send StartMeasurement\n");
}

/* ---- stop ---- */

static void stop_measurement_reply(DBusMessage *message, void *user_data)
{
	struct cs_session *s = user_data;
	DBusError error;

	dbus_error_init(&error);
	if (dbus_set_error_from_message(&error, message)) {
		bt_shell_printf("StopMeasurement failed: %s\n", error.message);
		dbus_error_free(&error);
		return;
	}

	bt_shell_printf("Measurement stopped on %s\n",
			g_dbus_proxy_get_path(s->proxy));
	cs_sessions = g_list_remove(cs_sessions, s);
	g_free(s);
}

static void cmd_cs_stop(int argc, char *argv[])
{
	const char *dev_path;
	struct cs_session *s;
	GDBusProxy *proxy;

	if (argc >= 2) {
		dev_path = cs_resolve_address(argv[1]);

		if (!dev_path) {
			bt_shell_printf("Device %s not found\n", argv[1]);
			return;
		}
		proxy = cs_find_proxy(dev_path);
		if (!proxy) {
			bt_shell_printf("No ChannelSounding1 interface for"
					" that device\n");
			return;
		}
		s = cs_find_session(proxy);
		if (!s) {
			bt_shell_printf("No active measurement on %s\n",
					argv[1]);
			return;
		}
	} else {
		if (!cs_sessions) {
			bt_shell_printf("No active measurements\n");
			return;
		}
		if (g_list_length(cs_sessions) > 1) {
			bt_shell_printf("Multiple active measurements —"
					" specify device address\n");
			return;
		}
		s = cs_sessions->data;
	}

	if (!g_dbus_proxy_method_call(s->proxy, "StopMeasurement",
				      NULL,
				      stop_measurement_reply, s, NULL))
		bt_shell_printf("Failed to send StopMeasurement\n");
}

/* ---- show ---- */

static void cmd_cs_show(int argc, char *argv[])
{
	struct cs_session *s;
	size_t j;
	GList *list;

	bt_shell_printf("Active measurements:\n");
	if (!cs_sessions) {
		bt_shell_printf("  none\n");
	} else {
		for (list = g_list_first(cs_sessions); list;
		     list = g_list_next(list)) {
			s = list->data;

			bt_shell_printf("  %s\n",
					g_dbus_proxy_get_path(s->proxy));
		}
	}

	bt_shell_printf("\n=== Default Settings ===\n");
	bt_shell_printf("  role           : %u"
			" (1=Initiator 2=Reflector 3=Both)\n", cs_role);
	bt_shell_printf("  sync_ant_sel   : 0x%02x\n", cs_sync_ant);
	bt_shell_printf("  max_tx_power   : %d dBm\n", cs_max_tx_power);

	bt_shell_printf("\n=== CS Config Params ===\n");
	bt_shell_printf("  create_context          : %u"
			" (0=local only 1=local+remote)\n",
			cs_cfg.create_context);
	bt_shell_printf("  config_id               : %u\n",
			cs_cfg.config_id);
	bt_shell_printf("  main_mode_type          : 0x%02x\n",
			cs_cfg.main_mode_type);
	bt_shell_printf("  sub_mode_type           : 0x%02x\n",
			cs_cfg.sub_mode_type);
	bt_shell_printf("  main_mode_min_steps     : %u\n",
			cs_cfg.main_mode_min_steps);
	bt_shell_printf("  main_mode_max_steps     : %u\n",
			cs_cfg.main_mode_max_steps);
	bt_shell_printf("  main_mode_repetition    : %u\n",
			cs_cfg.main_mode_repetition);
	bt_shell_printf("  mode0_steps             : %u\n",
			cs_cfg.mode0_steps);
	bt_shell_printf("  configured role         : %u\n",
			cs_cfg.role);
	bt_shell_printf("  rtt_types               : %u\n",
			cs_cfg.rtt_types);
	bt_shell_printf("  sync_phy                : %u\n",
			cs_cfg.cs_sync_phy);
	bt_shell_printf("  channel_map             :");
	for (j = 0; j < 10; j++)
		bt_shell_printf(" %02x", cs_cfg.channel_map[j]);
	bt_shell_printf("\n");
	bt_shell_printf("  channel_map_repetition  : %u\n",
			cs_cfg.channel_map_repetition);
	bt_shell_printf("  channel_selection_type  : %u\n",
			cs_cfg.channel_selection_type);
	bt_shell_printf("  channel_shape           : %u\n",
			cs_cfg.channel_shape);
	bt_shell_printf("  channel_jump            : %u\n",
			cs_cfg.channel_jump);
	bt_shell_printf("  companion_signal_enable : %u\n",
			cs_cfg.companion_signal_enable);

	bt_shell_printf("\n=== CS Frequency Params ===\n");
	bt_shell_printf("  max_procedure_duration        : %u\n",
			cs_freq.max_procedure_duration);
	bt_shell_printf("  min_period_between_procedures : %u\n",
			cs_freq.min_period_between_procedures);
	bt_shell_printf("  max_period_between_procedures : %u\n",
			cs_freq.max_period_between_procedures);
	bt_shell_printf("  max_procedure_count           : %u\n",
			cs_freq.max_procedure_count);
	bt_shell_printf("  min_sub_event_len             : %02x %02x %02x\n",
			cs_freq.min_sub_event_len[0],
			cs_freq.min_sub_event_len[1],
			cs_freq.min_sub_event_len[2]);
	bt_shell_printf("  max_sub_event_len             : %02x %02x %02x\n",
			cs_freq.max_sub_event_len[0],
			cs_freq.max_sub_event_len[1],
			cs_freq.max_sub_event_len[2]);
	bt_shell_printf("  tone_antenna_config_selection : 0x%02x\n",
			cs_freq.tone_antenna_config_selection);
	bt_shell_printf("  phy                           : 0x%02x\n",
			cs_freq.phy);
	bt_shell_printf("  tx_power_delta                : 0x%02x\n",
			cs_freq.tx_power_delta);
	bt_shell_printf("  preferred_peer_antenna        : 0x%02x\n",
			cs_freq.preferred_peer_antenna);
	bt_shell_printf("  snr_control_initiator         : 0x%02x\n",
			cs_freq.snr_control_initiator);
	bt_shell_printf("  snr_control_reflector         : 0x%02x\n",
			cs_freq.snr_control_reflector);
}

static const struct bt_shell_menu cs_menu = {
	.name = "cs",
	.desc = "Channel Sounding Submenu",
	.entries = {
	{ "start",  "[dev_addr] [duration_secs]",
				cmd_cs_start,
				"Start distance measurement using the"
				" current parameters (see cs.<param>"
				" commands below).\n"
				"\t\t\t\t\t\tInitiator (role 0x01/0x03): requires"
				" dev_addr and duration_secs.\n"
				"\t\t\t\t\t\tReflector (role 0x02): dev_addr/"
				"duration_secs are ignored, and no local"
				" measurement is started.",
				NULL },
	{ "stop",   "[dev_addr]",
				cmd_cs_stop,
				"Stop the active distance measurement;"
				" address required when multiple are active" },
	{ "show",   NULL,
				cmd_cs_show,
				"Show active session id and current"
				" CS parameters" },
	{ "role", "<0x01|0x02|0x03>", cmd_cs_set,
				"CS role: 0x01 Initiator, 0x02 Reflector,"
				" 0x03 Both (default 0x03)",
				cs_role_generator },
	{ "sync_ant_sel", "<value>", cmd_cs_set,
				"CS sync antenna selection; 0xFE/0xFF"
				" reserved (default 0xFF)" },
	{ "max_tx_power", "<-127..20>", cmd_cs_set,
				"Max TX power in dBm, signed (default 20)" },
	{ "config_id", "<value>", cmd_cs_set,
				"CS configuration identifier (default 0)" },
	{ "create_context", "<0|1>", cmd_cs_set,
				"0x00 writes the CS config to the local"
				" Controller only; 0x01 also writes it to"
				" the remote Controller via the CS"
				" Configuration procedure (default 1)",
				cs_bool_generator },
	{ "main_mode_type", "<1|2|3>", cmd_cs_set,
				"1 Mode 1 (RTT), 2 Mode 2 (PBR), 3 Both"
				" (default 1)",
				cs_main_mode_type_generator },
	{ "sub_mode_type", "<0x01|0x02|0x03|0xFF>", cmd_cs_set,
				"Sub-mode within main mode; 0xFF = unused"
				" (default 0xFF)",
				cs_sub_mode_type_generator },
	{ "main_mode_min_steps", "<value>", cmd_cs_set,
				"Min CS main mode steps per subevent"
				" (default 2)" },
	{ "main_mode_max_steps", "<value>", cmd_cs_set,
				"Max CS main mode steps per subevent"
				" (default 3)" },
	{ "main_mode_repetition", "<value>", cmd_cs_set,
				"Times main mode steps are repeated in a"
				" subevent (default 1)" },
	{ "mode0_steps", "<value>", cmd_cs_set,
				"CS Mode 0 steps at the beginning of each"
				" subevent (default 2)" },
	{ "rtt_types", "<value>", cmd_cs_set,
				"RTT measurement types bitmask (default 0)" },
	{ "sync_phy", "<0x01|0x02>", cmd_cs_set,
				"PHY for CS sync: 0x01 LE 1M, 0x02 LE 2M"
				" (default 0x01)",
				cs_phy_generator },
	{ "channel_map", "<10 colon-separated hex bytes>", cmd_cs_set,
				"10-byte channel map bitmap"
				" (default FC:FF:7F:FC:FF:FF:FF:FF:FF:1F)" },
	{ "channel_map_repetition", "<value>", cmd_cs_set,
				"Consecutive repetitions of the channel map"
				" (default 1)" },
	{ "channel_selection_type", "<value>", cmd_cs_set,
				"CS channel selection algorithm (default 0)" },
	{ "channel_shape", "<value>", cmd_cs_set,
				"Shape used in channel selection algorithm"
				" (default 0)" },
	{ "channel_jump", "<value>", cmd_cs_set,
				"Channel jump size (default 2)" },
	{ "companion_signal_enable", "<0|1>", cmd_cs_set,
				"1 to transmit companion signal, 0 to disable"
				" (default 0)",
				cs_bool_generator },
	{ "min_sub_event_len", "<3 colon-separated hex bytes>", cmd_cs_set,
				"Min CS subevent length, 3-byte LE"
				" (default 00:20:00)" },
	{ "max_sub_event_len", "<3 colon-separated hex bytes>", cmd_cs_set,
				"Max CS subevent length, 3-byte LE"
				" (default 03:20:00)" },
	{ "max_procedure_duration", "<value>", cmd_cs_set,
				"Maximum duration of one CS measurement"
				" procedure (default 1600)" },
	{ "min_period_between_procedures", "<value>", cmd_cs_set,
				"Minimum time between consecutive procedures"
				" (default 30)" },
	{ "max_period_between_procedures", "<value>", cmd_cs_set,
				"Maximum time between consecutive procedures"
				" (default 150)" },
	{ "max_procedure_count", "<value>", cmd_cs_set,
				"Max number of procedures; 0 = no limit"
				" (default 0)" },
	{ "tone_antenna_config_selection", "<value>", cmd_cs_set,
				"Antenna config for CS tone exchanges"
				" (default 0x07)" },
	{ "phy", "<0x01|0x02>", cmd_cs_set,
				"PHY for CS procedures: 0x01 LE 1M, 0x02 LE 2M"
				" (default 0x01)",
				cs_phy_generator },
	{ "tx_power_delta", "<value>", cmd_cs_set,
				"Remote vs local TX power delta; 0x80 = not"
				" applicable (default 0x80)" },
	{ "preferred_peer_antenna", "<value>", cmd_cs_set,
				"Preferred antenna for the peer device"
				" (default 0x03)" },
	{ "snr_control_initiator", "<value>", cmd_cs_set,
				"SNR control for initiator; 0xFF = no"
				" preference (default 0xFF)" },
	{ "snr_control_reflector", "<value>", cmd_cs_set,
				"SNR control for reflector; 0xFF = no"
				" preference (default 0xFF)" },
	{ NULL } },
};

void cs_add_submenu(void)
{
	bt_shell_add_submenu(&cs_menu);
}

void cs_remove_submenu(void)
{
	g_list_free_full(cs_sessions, g_free);
	cs_sessions = NULL;

	g_list_free(cs_proxies);
	cs_proxies = NULL;
}
