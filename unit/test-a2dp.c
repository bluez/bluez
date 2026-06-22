// SPDX-License-Identifier: GPL-2.0-or-later

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <dbus/dbus.h>
#include <glib.h>

#include "profiles/audio/a2dp-helpers.h"

static DBusMessage *new_method_call(void)
{
	return dbus_message_new_method_call("org.bluez.test",
						"/org/bluez/test",
						"org.bluez.test",
						"Test");
}

static void append_byte_array(DBusMessage *msg, const uint8_t *data, int size)
{
	DBusMessageIter iter;
	DBusMessageIter array;

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
						DBUS_TYPE_BYTE_AS_STRING,
						&array);
	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&data, size);
	dbus_message_iter_close_container(&iter, &array);
}

static void append_string_array(DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessageIter array;
	const char *value = "not-bytes";

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
						DBUS_TYPE_STRING_AS_STRING,
						&array);
	dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &value);
	dbus_message_iter_close_container(&iter, &array);
}

static void test_capabilities_array_accepts_byte_array(void)
{
	DBusMessage *msg = new_method_call();
	DBusMessageIter iter;
	const uint8_t bytes[] = { 0x11, 0x22, 0x33 };
	uint8_t *caps = NULL;
	int size = 0;

	g_assert_nonnull(msg);

	append_byte_array(msg, bytes, sizeof(bytes));
	g_assert_true(dbus_message_iter_init(msg, &iter));
	g_assert_true(a2dp_parse_capabilities_array(&iter, &caps, &size));
	g_assert_cmpint(size, ==, 3);
	g_assert_nonnull(caps);
	g_assert_cmpint(memcmp(caps, bytes, sizeof(bytes)), ==, 0);

	dbus_message_unref(msg);
}

static void test_capabilities_array_rejects_wrong_element_type(void)
{
	DBusMessage *msg = new_method_call();
	DBusMessageIter iter;
	uint8_t *caps = (void *) 0x01;
	int size = 1;

	g_assert_nonnull(msg);

	append_string_array(msg);
	g_assert_true(dbus_message_iter_init(msg, &iter));
	g_assert_false(a2dp_parse_capabilities_array(&iter, &caps, &size));
	g_assert_null(caps);
	g_assert_cmpint(size, ==, 0);

	dbus_message_unref(msg);
}

static void test_capabilities_array_rejects_empty_array(void)
{
	DBusMessage *msg = new_method_call();
	DBusMessageIter iter;
	uint8_t *caps = (void *) 0x01;
	int size = 1;

	g_assert_nonnull(msg);

	append_byte_array(msg, NULL, 0);
	g_assert_true(dbus_message_iter_init(msg, &iter));
	g_assert_false(a2dp_parse_capabilities_array(&iter, &caps, &size));
	g_assert_cmpint(size, ==, 0);

	dbus_message_unref(msg);
}

static void test_capabilities_array_rejects_missing_iter(void)
{
	uint8_t *caps = (void *) 0x01;
	int size = 1;

	g_assert_false(a2dp_parse_capabilities_array(NULL, &caps, &size));
}

static void test_capabilities_array_rejects_non_array(void)
{
	DBusMessage *msg = new_method_call();
	DBusMessageIter iter;
	const char *value = "not-array";
	uint8_t *caps = (void *) 0x01;
	int size = 1;

	g_assert_nonnull(msg);

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &value);
	g_assert_true(dbus_message_iter_init(msg, &iter));
	g_assert_false(a2dp_parse_capabilities_array(&iter, &caps, &size));
	g_assert_null(caps);
	g_assert_cmpint(size, ==, 0);

	dbus_message_unref(msg);
}

static void assert_endpoint(const char *value, uint8_t expected_type,
				uint8_t expected_codec,
				bool expected_delay,
				const uint8_t *expected_caps,
				size_t expected_size)
{
	uint8_t type = 0xff;
	uint8_t codec = 0xff;
	bool delay_reporting = true;
	uint8_t caps[128];
	size_t size = 0;

	memset(caps, 0xa5, sizeof(caps));

	g_assert_true(a2dp_parse_persisted_endpoint(value, &type, &codec,
							&delay_reporting,
							caps, sizeof(caps),
							&size));
	g_assert_cmpint(type, ==, expected_type);
	g_assert_cmpint(codec, ==, expected_codec);
	g_assert_cmpint(delay_reporting, ==, expected_delay);
	g_assert_cmpuint(size, ==, expected_size);
	g_assert_cmpint(memcmp(caps, expected_caps, expected_size), ==, 0);
}

static void test_endpoint_parser_accepts_current_format(void)
{
	const uint8_t caps[] = { 0x11, 0x22, 0x33 };

	assert_endpoint("00:40:01:112233", 0x00, 0x40, true, caps,
							sizeof(caps));
}

static void test_endpoint_parser_accepts_old_format(void)
{
	const uint8_t caps[] = { 0xaa, 0xbb };

	assert_endpoint("01:02:aabb", 0x01, 0x02, false, caps, sizeof(caps));
}

static void assert_endpoint_rejected(const char *value)
{
	uint8_t type = 0xff;
	uint8_t codec = 0xff;
	bool delay_reporting = true;
	uint8_t caps[4] = { 0xa5, 0xa5, 0xa5, 0xa5 };
	size_t size = 7;

	g_assert_false(a2dp_parse_persisted_endpoint(value, &type, &codec,
							&delay_reporting,
							caps, sizeof(caps),
							&size));
	g_assert_cmpint(caps[0], ==, 0xa5);
	g_assert_cmpint(caps[1], ==, 0xa5);
	g_assert_cmpint(caps[2], ==, 0xa5);
	g_assert_cmpint(caps[3], ==, 0xa5);
}

static void test_endpoint_parser_rejects_invalid_fields(void)
{
	assert_endpoint_rejected(NULL);
	assert_endpoint_rejected("");
	assert_endpoint_rejected("00:40");
	assert_endpoint_rejected("00:40:");
	assert_endpoint_rejected("00:40:01:");
	assert_endpoint_rejected("00:40:02:aabb");
	assert_endpoint_rejected("00:40:01:aab");
	assert_endpoint_rejected("00:40:01:aazz");
	assert_endpoint_rejected("00:40:01:aa:bb");
	assert_endpoint_rejected("00:40:aabb:");
	assert_endpoint_rejected("xx:40:01:aabb");
}

static void test_endpoint_parser_rejects_missing_output_buffer(void)
{
	uint8_t type;
	uint8_t codec;
	bool delay_reporting;
	size_t size;

	g_assert_false(a2dp_parse_persisted_endpoint("00:40:01:aabb",
							&type, &codec,
							&delay_reporting,
							NULL, 0, &size));
}

static void test_endpoint_parser_rejects_oversized_caps(void)
{
	char value[sizeof("00:40:01:") + 16];

	memset(value, 'a', sizeof(value));
	memcpy(value, "00:40:01:", strlen("00:40:01:"));
	value[sizeof(value) - 1] = '\0';

	assert_endpoint_rejected(value);
}

static void test_endpoint_parser_fuzz_cases_keep_bounds(void)
{
	static const char alphabet[] = "0123456789abcdefABCDEF:gZ";
	unsigned int i;

	for (i = 0; i < 4096; i++) {
		char value[16];
		uint8_t type;
		uint8_t codec;
		bool delay_reporting;
		uint8_t caps[6] = { 0, 0, 0, 0, 0xcc, 0xdd };
		size_t size;
		size_t len = i % (sizeof(value) - 1);
		size_t j;

		for (j = 0; j < len; j++)
			value[j] = alphabet[(i + j * 7) %
						(sizeof(alphabet) - 1)];
		value[len] = '\0';

		a2dp_parse_persisted_endpoint(value, &type, &codec,
						&delay_reporting, caps, 4,
						&size);
		g_assert_cmpint(caps[4], ==, 0xcc);
		g_assert_cmpint(caps[5], ==, 0xdd);
	}
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/a2dp/capabilities/byte-array",
			test_capabilities_array_accepts_byte_array);
	g_test_add_func("/a2dp/capabilities/wrong-element-type",
			test_capabilities_array_rejects_wrong_element_type);
	g_test_add_func("/a2dp/capabilities/empty-array",
			test_capabilities_array_rejects_empty_array);
	g_test_add_func("/a2dp/capabilities/missing-iter",
			test_capabilities_array_rejects_missing_iter);
	g_test_add_func("/a2dp/capabilities/non-array",
			test_capabilities_array_rejects_non_array);
	g_test_add_func("/a2dp/endpoint/current-format",
			test_endpoint_parser_accepts_current_format);
	g_test_add_func("/a2dp/endpoint/old-format",
			test_endpoint_parser_accepts_old_format);
	g_test_add_func("/a2dp/endpoint/invalid-fields",
			test_endpoint_parser_rejects_invalid_fields);
	g_test_add_func("/a2dp/endpoint/missing-output-buffer",
			test_endpoint_parser_rejects_missing_output_buffer);
	g_test_add_func("/a2dp/endpoint/oversized-caps",
			test_endpoint_parser_rejects_oversized_caps);
	g_test_add_func("/a2dp/endpoint/fuzz-bounds",
			test_endpoint_parser_fuzz_cases_keep_bounds);

	return g_test_run();
}
