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

#define BTSNOOP_EPOCH_OFFSET 0x00E03AB44A676000ull
#define PKLG_PAYLOAD_OFFSET 9

struct test_btsnoop_hdr {
	uint8_t id[8];
	uint32_t version;
	uint32_t type;
} __attribute__ ((packed));

struct test_btsnoop_pkt {
	uint32_t size;
	uint32_t len;
	uint32_t flags;
	uint32_t drops;
	uint64_t ts;
} __attribute__ ((packed));

struct test_pklg_pkt {
	uint32_t len;
	uint64_t ts;
	uint8_t type;
} __attribute__ ((packed));

static const uint8_t btsnoop_id[] = {
	0x62, 0x74, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x00
};

static void append_bytes(GByteArray *array, const void *data, size_t size)
{
	if (!size)
		return;

	g_byte_array_append(array, data, size);
}

static void append_btsnoop_header(GByteArray *array, uint32_t format)
{
	struct test_btsnoop_hdr hdr;

	memcpy(hdr.id, btsnoop_id, sizeof(btsnoop_id));
	hdr.version = htobe32(1);
	hdr.type = htobe32(format);

	append_bytes(array, &hdr, sizeof(hdr));
}

static void append_btsnoop_packet(GByteArray *array, uint32_t len,
					uint32_t flags, uint64_t ts,
					const void *data, size_t data_len)
{
	struct test_btsnoop_pkt pkt;

	pkt.size = htobe32(len);
	pkt.len = htobe32(len);
	pkt.flags = htobe32(flags);
	pkt.drops = 0;
	pkt.ts = htobe64(ts);

	append_bytes(array, &pkt, sizeof(pkt));
	append_bytes(array, data, data_len);
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

static char *new_tmp_path(void)
{
	char *path = NULL;
	int fd;

	fd = g_file_open_tmp("bluez-btsnoop-XXXXXX", &path, NULL);
	g_assert(fd >= 0);
	g_assert_cmpint(close(fd), ==, 0);
	unlink(path);

	return path;
}

static void unlink_rotated(const char *path, unsigned int count)
{
	unsigned int i;

	for (i = 0; i <= count; i++) {
		char *name;

		name = g_strdup_printf("%s.%u", path, i);
		unlink(name);
		g_free(name);
	}
}

static bool read_tmp_trace(const void *trace, size_t trace_len,
				unsigned long flags, uint16_t data_size,
				uint8_t *data, uint16_t *size,
				uint16_t *index, uint16_t *opcode,
				struct timeval *tv)
{
	struct btsnoop *btsnoop;
	char *path;
	bool result;

	path = write_tmp_trace(trace, trace_len);
	btsnoop = btsnoop_open(path, flags);
	unlink(path);
	g_free(path);

	if (!btsnoop)
		return false;

	result = btsnoop_read_hci(btsnoop, tv, index, opcode, data,
							data_size, size);
	btsnoop_unref(btsnoop);

	return result;
}

static bool read_trace_file(const char *path, unsigned long flags,
				uint8_t *data, uint16_t data_size,
				uint16_t *size, uint16_t *index,
				uint16_t *opcode, struct timeval *tv)
{
	struct btsnoop *btsnoop;
	bool result;

	btsnoop = btsnoop_open(path, flags);
	g_assert_nonnull(btsnoop);

	result = btsnoop_read_hci(btsnoop, tv, index, opcode, data,
							data_size, size);
	btsnoop_unref(btsnoop);

	return result;
}

static void test_btsnoop_hci_valid(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };
	uint8_t data[sizeof(payload)];
	struct timeval tv;
	uint16_t size = 0;
	uint16_t index = 0xffff;
	uint16_t opcode = 0xffff;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_HCI);
	append_btsnoop_packet(trace, sizeof(payload), 0x02,
			BTSNOOP_EPOCH_OFFSET + 1234567, payload,
			sizeof(payload));

	g_assert_true(read_tmp_trace(trace->data, trace->len, 0, sizeof(data),
					data, &size, &index, &opcode, &tv));
	g_assert_cmpint(index, ==, 0);
	g_assert_cmpint(opcode, ==, BTSNOOP_OPCODE_COMMAND_PKT);
	g_assert_cmpint(size, ==, sizeof(payload));
	g_assert_cmpint(memcmp(data, payload, sizeof(payload)), ==, 0);
	g_assert_cmpint(tv.tv_sec, ==, 946684801);
	g_assert_cmpint(tv.tv_usec, ==, 234567);

	g_byte_array_unref(trace);
}

static void test_btsnoop_create_invalid_args(void)
{
	char *path = new_tmp_path();

	g_assert_null(btsnoop_create(path, 0, 1, BTSNOOP_FORMAT_HCI));
	g_assert_null(btsnoop_create("/tmp/bluez/no/such/path", 0, 0,
							BTSNOOP_FORMAT_HCI));
	g_assert_null(btsnoop_ref(NULL));
	btsnoop_unref(NULL);
	g_assert_cmpint(btsnoop_get_format(NULL), ==, BTSNOOP_FORMAT_INVALID);

	g_free(path);
}

static void test_btsnoop_open_invalid_headers(void)
{
	GByteArray *trace = g_byte_array_new();
	struct test_btsnoop_hdr hdr;
	char *path;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_HCI);
	((struct test_btsnoop_hdr *) trace->data)->version = htobe32(2);
	path = write_tmp_trace(trace->data, trace->len);
	g_assert_null(btsnoop_open(path, 0));
	unlink(path);
	g_free(path);
	g_byte_array_set_size(trace, 0);

	memset(&hdr, 0x55, sizeof(hdr));
	append_bytes(trace, &hdr, sizeof(hdr));
	path = write_tmp_trace(trace->data, trace->len);
	g_assert_null(btsnoop_open(path, 0));
	g_assert_null(btsnoop_open(path, BTSNOOP_FLAG_PKLG_SUPPORT));
	unlink(path);
	g_free(path);
	g_byte_array_unref(trace);
}

static void test_btsnoop_write_hci_roundtrip(void)
{
	const uint8_t command[] = { 0x01, 0x02, 0x03 };
	const uint8_t event[] = { 0x04, 0x05 };
	uint8_t data[sizeof(command)];
	struct btsnoop *btsnoop;
	struct timeval tv = { .tv_sec = 946684802, .tv_usec = 345678 };
	uint16_t size = 0;
	uint16_t index = 0;
	uint16_t opcode = 0;
	char *path = new_tmp_path();

	btsnoop = btsnoop_create(path, 0, 0, BTSNOOP_FORMAT_HCI);
	g_assert_nonnull(btsnoop);
	g_assert_cmpint(btsnoop_get_format(btsnoop), ==, BTSNOOP_FORMAT_HCI);
	g_assert_true(btsnoop_write_hci(btsnoop, &tv, 0,
					BTSNOOP_OPCODE_COMMAND_PKT, 0,
					command, sizeof(command)));
	g_assert_true(btsnoop_write_hci(btsnoop, &tv, 0,
					BTSNOOP_OPCODE_EVENT_PKT, 0,
					event, sizeof(event)));
	g_assert_false(btsnoop_write_hci(btsnoop, &tv, 1,
					BTSNOOP_OPCODE_COMMAND_PKT, 0,
					command, sizeof(command)));
	g_assert_false(btsnoop_write_hci(btsnoop, &tv, 0,
					BTSNOOP_OPCODE_NEW_INDEX, 0,
					command, sizeof(command)));
	btsnoop_unref(btsnoop);

	g_assert_true(read_trace_file(path, 0, data, sizeof(data), &size,
						&index, &opcode, &tv));
	g_assert_cmpint(index, ==, 0);
	g_assert_cmpint(opcode, ==, BTSNOOP_OPCODE_COMMAND_PKT);
	g_assert_cmpint(size, ==, sizeof(command));
	g_assert_cmpint(memcmp(data, command, sizeof(command)), ==, 0);

	btsnoop = btsnoop_open(path, 0);
	g_assert_nonnull(btsnoop);
	g_assert_true(btsnoop_read_hci(btsnoop, &tv, &index, &opcode, data,
							sizeof(data), &size));
	g_assert_true(btsnoop_read_hci(btsnoop, &tv, &index, &opcode, data,
							sizeof(data), &size));
	g_assert_cmpint(opcode, ==, BTSNOOP_OPCODE_EVENT_PKT);
	g_assert_cmpint(size, ==, sizeof(event));
	g_assert_cmpint(memcmp(data, event, sizeof(event)), ==, 0);
	g_assert_false(btsnoop_read_hci(btsnoop, &tv, &index, &opcode, data,
							sizeof(data), &size));
	btsnoop_unref(btsnoop);

	unlink(path);
	g_free(path);
}

static void test_btsnoop_write_monitor_roundtrip(void)
{
	const uint8_t payload[] = { 0xaa, 0xbb };
	uint8_t data[sizeof(payload)];
	struct btsnoop *btsnoop;
	struct timeval tv = { .tv_sec = 946684800, .tv_usec = 0 };
	uint16_t size = 0;
	uint16_t index = 0;
	uint16_t opcode = 0;
	char *path = new_tmp_path();

	btsnoop = btsnoop_create(path, 0, 0, BTSNOOP_FORMAT_MONITOR);
	g_assert_nonnull(btsnoop);
	g_assert_true(btsnoop_write_hci(btsnoop, &tv, 7, 0x1234, 0,
						payload, sizeof(payload)));
	btsnoop_unref(btsnoop);

	g_assert_true(read_trace_file(path, 0, data, sizeof(data), &size,
						&index, &opcode, &tv));
	g_assert_cmpint(index, ==, 7);
	g_assert_cmpint(opcode, ==, 0x1234);
	g_assert_cmpint(size, ==, sizeof(payload));
	g_assert_cmpint(memcmp(data, payload, sizeof(payload)), ==, 0);

	unlink(path);
	g_free(path);
}

static void test_btsnoop_write_phy_and_rotate(void)
{
	const uint8_t payload[] = { 0x01 };
	struct btsnoop *btsnoop;
	struct timeval tv = { .tv_sec = 946684800, .tv_usec = 0 };
	char *path = new_tmp_path();

	g_assert_false(btsnoop_write(NULL, &tv, 0, 0, payload,
							sizeof(payload)));

	btsnoop = btsnoop_create(path, 24, 1, BTSNOOP_FORMAT_SIMULATOR);
	g_assert_nonnull(btsnoop);
	g_assert_true(btsnoop_write_phy(btsnoop, &tv, 2402, payload,
							sizeof(payload)));
	btsnoop_unref(btsnoop);

	btsnoop = btsnoop_create(path, 0, 0, BTSNOOP_FORMAT_HCI);
	g_assert_nonnull(btsnoop);
	g_assert_false(btsnoop_write_phy(btsnoop, &tv, 2402, payload,
							sizeof(payload)));
	btsnoop_unref(btsnoop);

	unlink(path);
	unlink_rotated(path, 1);
	g_free(path);
}

static void test_btsnoop_monitor_valid(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0xaa, 0xbb };
	uint8_t data[sizeof(payload)];
	struct timeval tv;
	uint16_t size = 0;
	uint16_t index = 0xffff;
	uint16_t opcode = 0xffff;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_MONITOR);
	append_btsnoop_packet(trace, sizeof(payload), 0x00051234,
			BTSNOOP_EPOCH_OFFSET, payload, sizeof(payload));

	g_assert_true(read_tmp_trace(trace->data, trace->len, 0, sizeof(data),
					data, &size, &index, &opcode, &tv));
	g_assert_cmpint(index, ==, 5);
	g_assert_cmpint(opcode, ==, 0x1234);
	g_assert_cmpint(size, ==, sizeof(payload));
	g_assert_cmpint(memcmp(data, payload, sizeof(payload)), ==, 0);

	g_byte_array_unref(trace);
}

static void test_btsnoop_uart_valid(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x04, 0x0e, 0x01, 0x00 };
	uint8_t data[sizeof(payload) - 1];
	struct timeval tv;
	uint16_t size = 0;
	uint16_t index = 0xffff;
	uint16_t opcode = 0xffff;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_UART);
	append_btsnoop_packet(trace, sizeof(payload), 0,
			BTSNOOP_EPOCH_OFFSET, payload, sizeof(payload));

	g_assert_true(read_tmp_trace(trace->data, trace->len, 0, sizeof(data),
					data, &size, &index, &opcode, &tv));
	g_assert_cmpint(index, ==, 0);
	g_assert_cmpint(opcode, ==, BTSNOOP_OPCODE_EVENT_PKT);
	g_assert_cmpint(size, ==, sizeof(payload) - 1);
	g_assert_cmpint(memcmp(data, payload + 1, sizeof(data)), ==, 0);

	g_byte_array_unref(trace);
}

static void test_btsnoop_uart_opcode_map(void)
{
	static const struct {
		uint8_t type;
		uint32_t flags;
		uint16_t opcode;
	} cases[] = {
		{ 0x01, 0x00, BTSNOOP_OPCODE_COMMAND_PKT },
		{ 0x02, 0x00, BTSNOOP_OPCODE_ACL_TX_PKT },
		{ 0x02, 0x01, BTSNOOP_OPCODE_ACL_RX_PKT },
		{ 0x03, 0x00, BTSNOOP_OPCODE_SCO_TX_PKT },
		{ 0x03, 0x01, BTSNOOP_OPCODE_SCO_RX_PKT },
		{ 0x05, 0x00, BTSNOOP_OPCODE_ISO_TX_PKT },
		{ 0x05, 0x01, BTSNOOP_OPCODE_ISO_RX_PKT },
		{ 0x99, 0x00, 0xffff },
	};
	unsigned int i;

	for (i = 0; i < G_N_ELEMENTS(cases); i++) {
		GByteArray *trace = g_byte_array_new();
		const uint8_t payload[] = { cases[i].type, 0x00 };
		uint8_t data[1];
		struct timeval tv;
		uint16_t size = 0;
		uint16_t index = 0;
		uint16_t opcode = 0;

		append_btsnoop_header(trace, BTSNOOP_FORMAT_UART);
		append_btsnoop_packet(trace, sizeof(payload), cases[i].flags,
				BTSNOOP_EPOCH_OFFSET, payload, sizeof(payload));

		g_assert_true(read_tmp_trace(trace->data, trace->len, 0,
						sizeof(data), data, &size,
						&index, &opcode, &tv));
		g_assert_cmpint(opcode, ==, cases[i].opcode);
		g_byte_array_unref(trace);
	}
}

static void test_btsnoop_rejects_small_capacity(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };
	uint8_t data[4] = { 0xa5, 0xa5, 0xa5, 0xa5 };
	struct timeval tv;
	uint16_t size = 0;
	uint16_t index = 0;
	uint16_t opcode = 0;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_HCI);
	append_btsnoop_packet(trace, sizeof(payload), 0x02,
			BTSNOOP_EPOCH_OFFSET, payload, sizeof(payload));

	g_assert_false(read_tmp_trace(trace->data, trace->len, 0, 2, data,
						&size, &index, &opcode, &tv));
	g_assert_cmpint(data[0], ==, 0xa5);
	g_assert_cmpint(data[1], ==, 0xa5);
	g_assert_cmpint(data[2], ==, 0xa5);
	g_assert_cmpint(data[3], ==, 0xa5);

	g_byte_array_unref(trace);
}

static void test_btsnoop_rejects_timestamp_underflow(void)
{
	GByteArray *trace = g_byte_array_new();
	struct timeval tv;
	uint16_t size = 0;
	uint16_t index = 0;
	uint16_t opcode = 0;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_HCI);
	append_btsnoop_packet(trace, 0, 0x02, BTSNOOP_EPOCH_OFFSET - 1,
								NULL, 0);

	g_assert_false(read_tmp_trace(trace->data, trace->len, 0, 0, NULL,
						&size, &index, &opcode, &tv));

	g_byte_array_unref(trace);
}

static void test_btsnoop_rejects_uart_zero_length(void)
{
	GByteArray *trace = g_byte_array_new();
	struct timeval tv;
	uint16_t size = 0;
	uint16_t index = 0;
	uint16_t opcode = 0;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_UART);
	append_btsnoop_packet(trace, 0, 0, BTSNOOP_EPOCH_OFFSET, NULL, 0);

	g_assert_false(read_tmp_trace(trace->data, trace->len, 0, 0, NULL,
						&size, &index, &opcode, &tv));

	g_byte_array_unref(trace);
}

static void test_btsnoop_rejects_uart_short_type(void)
{
	GByteArray *trace = g_byte_array_new();
	struct timeval tv;
	uint16_t size = 0;
	uint16_t index = 0;
	uint16_t opcode = 0;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_UART);
	append_btsnoop_packet(trace, 1, 0, BTSNOOP_EPOCH_OFFSET, NULL, 0);

	g_assert_false(read_tmp_trace(trace->data, trace->len, 0, 0, NULL,
						&size, &index, &opcode, &tv));

	g_byte_array_unref(trace);
}

static void test_btsnoop_rejects_short_payload(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02 };
	uint8_t data[3];
	struct timeval tv;
	uint16_t size = 0;
	uint16_t index = 0;
	uint16_t opcode = 0;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_HCI);
	append_btsnoop_packet(trace, 3, 0x02, BTSNOOP_EPOCH_OFFSET,
							payload, sizeof(payload));

	g_assert_false(read_tmp_trace(trace->data, trace->len, 0, sizeof(data),
						data, &size, &index, &opcode, &tv));

	g_byte_array_unref(trace);
}

static void test_pklg_big_endian_valid(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x0e, 0x01, 0x00 };
	uint8_t data[sizeof(payload)];
	struct timeval tv;
	uint16_t size = 0;
	uint16_t index = 0xffff;
	uint16_t opcode = 0xffff;

	append_pklg_packet(trace, false, sizeof(payload),
			((uint64_t) 123 << 32) | 456, 0x01, payload,
			sizeof(payload));

	g_assert_true(read_tmp_trace(trace->data, trace->len,
					BTSNOOP_FLAG_PKLG_SUPPORT, sizeof(data),
					data, &size, &index, &opcode, &tv));
	g_assert_cmpint(index, ==, 0);
	g_assert_cmpint(opcode, ==, BTSNOOP_OPCODE_EVENT_PKT);
	g_assert_cmpint(size, ==, sizeof(payload));
	g_assert_cmpint(memcmp(data, payload, sizeof(payload)), ==, 0);
	g_assert_cmpint(tv.tv_sec, ==, 123);
	g_assert_cmpint(tv.tv_usec, ==, 456);

	g_byte_array_unref(trace);
}

static void test_pklg_little_endian_valid(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };
	uint8_t data[sizeof(payload)];
	struct timeval tv;
	uint16_t size = 0;
	uint16_t index = 0xffff;
	uint16_t opcode = 0xffff;

	append_pklg_packet(trace, true, sizeof(payload),
			((uint64_t) 456 << 32) | 123, 0x00, payload,
			sizeof(payload));

	g_assert_true(read_tmp_trace(trace->data, trace->len,
					BTSNOOP_FLAG_PKLG_SUPPORT, sizeof(data),
					data, &size, &index, &opcode, &tv));
	g_assert_cmpint(index, ==, 0);
	g_assert_cmpint(opcode, ==, BTSNOOP_OPCODE_COMMAND_PKT);
	g_assert_cmpint(size, ==, sizeof(payload));
	g_assert_cmpint(data[0], ==, payload[0]);
	g_assert_cmpint(tv.tv_sec, ==, 123);
	g_assert_cmpint(tv.tv_usec, ==, 456);

	g_byte_array_unref(trace);
}

static void test_pklg_rejects_short_length(void)
{
	GByteArray *trace = g_byte_array_new();
	struct test_pklg_pkt pkt;
	const uint8_t padding[] = { 0x00, 0x00, 0x00 };
	struct timeval tv;
	uint16_t size = 0;
	uint16_t index = 0;
	uint16_t opcode = 0;

	pkt.len = htobe32(PKLG_PAYLOAD_OFFSET - 1);
	pkt.ts = 0;
	pkt.type = 0x01;

	append_bytes(trace, &pkt, sizeof(pkt));
	append_bytes(trace, padding, sizeof(padding));

	g_assert_false(read_tmp_trace(trace->data, trace->len,
					BTSNOOP_FLAG_PKLG_SUPPORT, 0, NULL,
					&size, &index, &opcode, &tv));

	g_byte_array_unref(trace);
}

static void test_pklg_rejects_small_capacity(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };
	uint8_t data[4] = { 0xa5, 0xa5, 0xa5, 0xa5 };
	struct timeval tv;
	uint16_t size = 0;
	uint16_t index = 0;
	uint16_t opcode = 0;

	append_pklg_packet(trace, false, sizeof(payload), 0, 0x01, payload,
							sizeof(payload));

	g_assert_false(read_tmp_trace(trace->data, trace->len,
					BTSNOOP_FLAG_PKLG_SUPPORT, 2, data,
					&size, &index, &opcode, &tv));
	g_assert_cmpint(data[0], ==, 0xa5);
	g_assert_cmpint(data[1], ==, 0xa5);
	g_assert_cmpint(data[2], ==, 0xa5);
	g_assert_cmpint(data[3], ==, 0xa5);

	g_byte_array_unref(trace);
}

static void test_pklg_rejects_short_payload(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };
	uint8_t data[4];
	struct timeval tv;
	uint16_t size = 0;
	uint16_t index = 0;
	uint16_t opcode = 0;

	append_pklg_packet(trace, false, 4, 0, 0x01, payload,
							sizeof(payload));

	g_assert_false(read_tmp_trace(trace->data, trace->len,
					BTSNOOP_FLAG_PKLG_SUPPORT, sizeof(data),
					data, &size, &index, &opcode, &tv));

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
		uint8_t data[sizeof(payload)];
		struct timeval tv;
		uint16_t size = 0;
		uint16_t index = 0;
		uint16_t opcode = 0;

		append_pklg_packet(trace, false, sizeof(payload), 0,
						cases[i].type, payload,
						sizeof(payload));

		g_assert_true(read_tmp_trace(trace->data, trace->len,
						BTSNOOP_FLAG_PKLG_SUPPORT,
						sizeof(data), data, &size,
						&index, &opcode, &tv));
		g_assert_cmpint(index, ==, cases[i].index);
		g_assert_cmpint(opcode, ==, cases[i].opcode);
		g_byte_array_unref(trace);
	}
}

static void test_btsnoop_truncation_fuzz(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };
	size_t len;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_HCI);
	append_btsnoop_packet(trace, sizeof(payload), 0x02,
			BTSNOOP_EPOCH_OFFSET, payload, sizeof(payload));

	for (len = 0; len < trace->len; len++) {
		uint8_t data[sizeof(payload)];
		struct timeval tv;
		uint16_t size = 0;
		uint16_t index = 0;
		uint16_t opcode = 0;

		g_assert_false(read_tmp_trace(trace->data, len, 0,
						sizeof(data), data, &size,
						&index, &opcode, &tv));
	}

	g_byte_array_unref(trace);
}

static void test_pklg_truncation_fuzz(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };
	size_t len;

	append_pklg_packet(trace, false, sizeof(payload), 0, 0x01, payload,
							sizeof(payload));

	for (len = 0; len < trace->len; len++) {
		uint8_t data[sizeof(payload)];
		struct timeval tv;
		uint16_t size = 0;
		uint16_t index = 0;
		uint16_t opcode = 0;

		g_assert_false(read_tmp_trace(trace->data, len,
						BTSNOOP_FLAG_PKLG_SUPPORT,
						sizeof(data), data, &size,
						&index, &opcode, &tv));
	}

	g_byte_array_unref(trace);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/btsnoop/hci/valid", test_btsnoop_hci_valid);
	g_test_add_func("/btsnoop/create/invalid",
			test_btsnoop_create_invalid_args);
	g_test_add_func("/btsnoop/open/invalid",
			test_btsnoop_open_invalid_headers);
	g_test_add_func("/btsnoop/write/hci-roundtrip",
			test_btsnoop_write_hci_roundtrip);
	g_test_add_func("/btsnoop/write/monitor-roundtrip",
			test_btsnoop_write_monitor_roundtrip);
	g_test_add_func("/btsnoop/write/phy-and-rotate",
			test_btsnoop_write_phy_and_rotate);
	g_test_add_func("/btsnoop/monitor/valid", test_btsnoop_monitor_valid);
	g_test_add_func("/btsnoop/uart/valid", test_btsnoop_uart_valid);
	g_test_add_func("/btsnoop/uart/opcode-map",
			test_btsnoop_uart_opcode_map);
	g_test_add_func("/btsnoop/capacity/reject",
			test_btsnoop_rejects_small_capacity);
	g_test_add_func("/btsnoop/timestamp/underflow",
			test_btsnoop_rejects_timestamp_underflow);
	g_test_add_func("/btsnoop/uart/zero-length",
			test_btsnoop_rejects_uart_zero_length);
	g_test_add_func("/btsnoop/uart/short-type",
			test_btsnoop_rejects_uart_short_type);
	g_test_add_func("/btsnoop/payload/short",
			test_btsnoop_rejects_short_payload);
	g_test_add_func("/pklg/big-endian/valid", test_pklg_big_endian_valid);
	g_test_add_func("/pklg/little-endian/valid",
			test_pklg_little_endian_valid);
	g_test_add_func("/pklg/length/short", test_pklg_rejects_short_length);
	g_test_add_func("/pklg/capacity/reject",
			test_pklg_rejects_small_capacity);
	g_test_add_func("/pklg/payload/short", test_pklg_rejects_short_payload);
	g_test_add_func("/pklg/type-map", test_pklg_type_map);
	g_test_add_func("/btsnoop/fuzz/truncation",
			test_btsnoop_truncation_fuzz);
	g_test_add_func("/pklg/fuzz/truncation", test_pklg_truncation_fuzz);

	return g_test_run();
}
