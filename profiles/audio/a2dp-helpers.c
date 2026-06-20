// SPDX-License-Identifier: GPL-2.0-or-later

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <dbus/dbus.h>
#include <glib.h>

#include "a2dp-helpers.h"

static bool parse_hex_byte(const char **value, uint8_t *byte)
{
	int high;
	int low;

	if ((*value)[0] == '\0' || (*value)[1] == '\0')
		return false;

	high = g_ascii_xdigit_value((*value)[0]);
	low = g_ascii_xdigit_value((*value)[1]);
	if (high < 0 || low < 0)
		return false;

	*byte = high << 4 | low;
	*value += 2;

	return true;
}

static bool parse_colon(const char **value)
{
	if (**value != ':')
		return false;

	(*value)++;

	return true;
}

static bool parse_caps(const char *value, uint8_t *caps, size_t caps_len,
								size_t *size)
{
	size_t len;
	size_t i;

	if (!value || !caps || !size)
		return false;

	*size = 0;

	len = strlen(value);
	if (!len || len % 2 || len / 2 > caps_len)
		return false;

	for (i = 0; i < len; i++) {
		if (!g_ascii_isxdigit(value[i]))
			return false;
	}

	for (i = 0; i < len; i += 2) {
		const char *pos = value + i;

		parse_hex_byte(&pos, &caps[i / 2]);
	}

	*size = len / 2;

	return true;
}

bool a2dp_parse_capabilities_array(DBusMessageIter *value,
					uint8_t **caps, int *size)
{
	DBusMessageIter array;

	if (!value || !caps || !size)
		return false;

	*caps = NULL;
	*size = 0;

	if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_ARRAY)
		return false;

	if (dbus_message_iter_get_element_type(value) != DBUS_TYPE_BYTE)
		return false;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, caps, size);

	return *caps && *size > 0;
}

bool a2dp_parse_persisted_endpoint(const char *value, uint8_t *type,
					uint8_t *codec,
					bool *delay_reporting,
					uint8_t *caps, size_t caps_len,
					size_t *size)
{
	const char *pos;
	uint8_t delay = 0;

	if (!value || !type || !codec || !delay_reporting || !size)
		return false;

	*size = 0;

	pos = value;
	if (!parse_hex_byte(&pos, type) || !parse_colon(&pos))
		return false;

	if (!parse_hex_byte(&pos, codec) || !parse_colon(&pos))
		return false;

	if (pos[0] != '\0' && pos[1] != '\0' &&
			g_ascii_isxdigit(pos[0]) && g_ascii_isxdigit(pos[1]) &&
			pos[2] == ':') {
		parse_hex_byte(&pos, &delay);
		parse_colon(&pos);
		if (delay > 1)
			return false;
	}

	if (!parse_caps(pos, caps, caps_len, size))
		return false;

	*delay_reporting = delay;

	return true;
}
