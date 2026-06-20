// SPDX-License-Identifier: GPL-2.0-or-later

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>

#include "src/shared/btsnoop.h"

#define PKLG_PAYLOAD_OFFSET 9

struct test_pklg_pkt {
	uint32_t len;
	uint64_t ts;
	uint8_t type;
} __attribute__ ((packed));

struct read_result {
	uint8_t data[BTSNOOP_MAX_PACKET_SIZE];
	uint16_t size;
	uint16_t index;
	uint16_t opcode;
	struct timeval tv;
};

static void read_result_init(struct read_result *result)
{
	memset(result->data, 0xa5, sizeof(result->data));
	result->size = 0;
	result->index = 0xffff;
	result->opcode = 0xffff;
	memset(&result->tv, 0, sizeof(result->tv));
}

static void append_bytes(GByteArray *array, const void *data, size_t size)
{
	if (size)
		g_byte_array_append(array, data, size);
}

static void append_pklg_packet(GByteArray *array, bool little_endian,
				uint32_t payload_len, uint64_t ts,
				uint8_t type, const void *data, size_t data_len)
{
	struct test_pklg_pkt pkt;
	uint32_t len = PKLG_PAYLOAD_OFFSET + payload_len;

	pkt.len = little_endian ? htole32(len) : htobe32(len);
	pkt.ts = little_endian ? htole64(ts) : htobe64(ts);
	pkt.type = type;

	append_bytes(array, &pkt, sizeof(pkt));
	append_bytes(array, data, data_len);
}

static char *write_tmp_trace(const void *data, size_t size)
{
	char *path = NULL;
	ssize_t written;
	int fd;

	fd = g_file_open_tmp("bluez-btsnoop-XXXXXX", &path, NULL);
	g_assert(fd >= 0);
	written = write(fd, data, size);
	g_assert_cmpint(written, ==, (ssize_t) size);
	g_assert_cmpint(close(fd), ==, 0);

	return path;
}

static bool read_tmp_trace(const void *trace, size_t trace_len,
				uint16_t data_size, struct read_result *result)
{
	struct btsnoop *btsnoop;
	char *path;
	bool ok;

	read_result_init(result);
	path = write_tmp_trace(trace, trace_len);
	btsnoop = btsnoop_open(path, BTSNOOP_FLAG_PKLG_SUPPORT);
	unlink(path);
	g_free(path);

	if (!btsnoop)
		return false;

	ok = btsnoop_read_hci(btsnoop, &result->tv, &result->index,
				&result->opcode, result->data, data_size,
				&result->size);
	btsnoop_unref(btsnoop);

	return ok;
}

static void test_pklg_big_endian_valid(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x0e, 0x01, 0x00 };
	struct read_result result;

	append_pklg_packet(trace, false, sizeof(payload),
			((uint64_t) 123 << 32) | 456, 0x01, payload,
			sizeof(payload));

	g_assert_true(read_tmp_trace(trace->data, trace->len, sizeof(payload),
								&result));
	g_assert_cmpint(result.index, ==, 0);
	g_assert_cmpint(result.opcode, ==, BTSNOOP_OPCODE_EVENT_PKT);
	g_assert_cmpint(result.size, ==, sizeof(payload));
	g_assert_cmpint(memcmp(result.data, payload, sizeof(payload)), ==, 0);
	g_assert_cmpint(result.tv.tv_sec, ==, 123);
	g_assert_cmpint(result.tv.tv_usec, ==, 456);

	g_byte_array_unref(trace);
}

static void test_pklg_little_endian_valid(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };
	struct read_result result;

	append_pklg_packet(trace, true, sizeof(payload),
			((uint64_t) 456 << 32) | 123, 0x00, payload,
			sizeof(payload));

	g_assert_true(read_tmp_trace(trace->data, trace->len, sizeof(payload),
								&result));
	g_assert_cmpint(result.index, ==, 0);
	g_assert_cmpint(result.opcode, ==, BTSNOOP_OPCODE_COMMAND_PKT);
	g_assert_cmpint(result.size, ==, sizeof(payload));
	g_assert_cmpint(result.data[0], ==, payload[0]);
	g_assert_cmpint(result.tv.tv_sec, ==, 123);
	g_assert_cmpint(result.tv.tv_usec, ==, 456);

	g_byte_array_unref(trace);
}

static void test_pklg_rejects_short_length(void)
{
	GByteArray *trace = g_byte_array_new();
	struct test_pklg_pkt pkt;
	const uint8_t padding[] = { 0x00, 0x00, 0x00 };
	struct read_result result;

	pkt.len = htobe32(PKLG_PAYLOAD_OFFSET - 1);
	pkt.ts = 0;
	pkt.type = 0x01;

	append_bytes(trace, &pkt, sizeof(pkt));
	append_bytes(trace, padding, sizeof(padding));

	g_assert_false(read_tmp_trace(trace->data, trace->len, 0, &result));

	g_byte_array_unref(trace);
}

static void test_pklg_rejects_small_capacity(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };
	struct read_result result;

	append_pklg_packet(trace, false, sizeof(payload), 0, 0x01, payload,
							sizeof(payload));

	g_assert_false(read_tmp_trace(trace->data, trace->len, 2, &result));
	g_assert_cmpint(result.data[0], ==, 0xa5);
	g_assert_cmpint(result.data[1], ==, 0xa5);
	g_assert_cmpint(result.data[2], ==, 0xa5);
	g_assert_cmpint(result.data[3], ==, 0xa5);

	g_byte_array_unref(trace);
}

static void test_pklg_rejects_short_payload(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };
	struct read_result result;

	append_pklg_packet(trace, false, 4, 0, 0x01, payload,
							sizeof(payload));

	g_assert_false(read_tmp_trace(trace->data, trace->len, 4, &result));

	g_byte_array_unref(trace);
}

static void test_pklg_type_map(void)
{
	static const struct {
		uint8_t type;
		uint16_t index;
		uint16_t opcode;
	} cases[] = {
		{ 0x02, 0x0000, BTSNOOP_OPCODE_ACL_TX_PKT },
		{ 0x03, 0x0000, BTSNOOP_OPCODE_ACL_RX_PKT },
		{ 0x08, 0x0000, BTSNOOP_OPCODE_SCO_TX_PKT },
		{ 0x09, 0x0000, BTSNOOP_OPCODE_SCO_RX_PKT },
		{ 0x12, 0x0000, BTSNOOP_OPCODE_ISO_TX_PKT },
		{ 0x13, 0x0000, BTSNOOP_OPCODE_ISO_RX_PKT },
		{ 0x0b, 0x0000, BTSNOOP_OPCODE_VENDOR_DIAG },
		{ 0xfc, 0xffff, BTSNOOP_OPCODE_SYSTEM_NOTE },
		{ 0xaa, 0xffff, 0xffff },
	};
	const uint8_t payload[] = { 0x00, 0x01, 0x02 };
	unsigned int i;

	for (i = 0; i < G_N_ELEMENTS(cases); i++) {
		GByteArray *trace = g_byte_array_new();
		struct read_result result;

		append_pklg_packet(trace, false, sizeof(payload), 0,
						cases[i].type, payload,
						sizeof(payload));

		g_assert_true(read_tmp_trace(trace->data, trace->len,
						sizeof(payload), &result));
		g_assert_cmpint(result.index, ==, cases[i].index);
		g_assert_cmpint(result.opcode, ==, cases[i].opcode);
		g_byte_array_unref(trace);
	}
}

static void test_pklg_truncation_fuzz(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };
	size_t len;

	append_pklg_packet(trace, false, sizeof(payload), 0, 0x01, payload,
							sizeof(payload));

	for (len = 0; len < trace->len; len++) {
		struct read_result result;

		g_assert_false(read_tmp_trace(trace->data, len, sizeof(payload),
								&result));
	}

	g_byte_array_unref(trace);
}

void add_pklg_tests(void)
{
	g_test_add_func("/pklg/big-endian/valid", test_pklg_big_endian_valid);
	g_test_add_func("/pklg/little-endian/valid",
			test_pklg_little_endian_valid);
	g_test_add_func("/pklg/length/short", test_pklg_rejects_short_length);
	g_test_add_func("/pklg/capacity/reject",
			test_pklg_rejects_small_capacity);
	g_test_add_func("/pklg/payload/short", test_pklg_rejects_short_payload);
	g_test_add_func("/pklg/type-map", test_pklg_type_map);
	g_test_add_func("/pklg/fuzz/truncation", test_pklg_truncation_fuzz);
}
