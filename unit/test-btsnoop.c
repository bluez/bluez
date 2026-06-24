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

#include "src/shared/att-types.h"
#include "src/shared/btsnoop.h"
#include "unit/test-btsnoop.h"

#define BTSNOOP_EPOCH_OFFSET 0x00E03AB44A676000ull

struct test_btsnoop_hdr {
	uint8_t id[8];
	uint32_t version;
	uint32_t type;
} __packed;

struct test_btsnoop_pkt {
	uint32_t size;
	uint32_t len;
	uint32_t flags;
	uint32_t drops;
	uint64_t ts;
} __packed;

struct read_result {
	uint8_t data[BTSNOOP_MAX_PACKET_SIZE];
	uint16_t size;
	uint16_t index;
	uint16_t opcode;
	struct timeval tv;
};

static const uint8_t btsnoop_id[] = {
	0x62, 0x74, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x00
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
		char *name = g_strdup_printf("%s.%u", path, i);

		unlink(name);
		g_free(name);
	}
}

static bool read_tmp_trace(const void *trace, size_t trace_len,
				unsigned long flags, uint16_t data_size,
				struct read_result *result)
{
	struct btsnoop *btsnoop;
	char *path;
	bool ok;

	read_result_init(result);
	path = write_tmp_trace(trace, trace_len);
	btsnoop = btsnoop_open(path, flags);
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

static bool read_trace_file(const char *path, unsigned long flags,
				uint16_t data_size, struct read_result *result)
{
	struct btsnoop *btsnoop;
	bool ok;

	read_result_init(result);
	btsnoop = btsnoop_open(path, flags);
	g_assert_nonnull(btsnoop);

	ok = btsnoop_read_hci(btsnoop, &result->tv, &result->index,
				&result->opcode, result->data, data_size,
				&result->size);
	btsnoop_unref(btsnoop);

	return ok;
}

static void test_btsnoop_hci_valid(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };
	struct read_result result;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_HCI);
	append_btsnoop_packet(trace, sizeof(payload), 0x02,
			BTSNOOP_EPOCH_OFFSET + 1234567, payload,
			sizeof(payload));

	g_assert_true(read_tmp_trace(trace->data, trace->len, 0,
						sizeof(payload), &result));
	g_assert_cmpint(result.index, ==, 0);
	g_assert_cmpint(result.opcode, ==, BTSNOOP_OPCODE_COMMAND_PKT);
	g_assert_cmpint(result.size, ==, sizeof(payload));
	g_assert_cmpint(memcmp(result.data, payload, sizeof(payload)), ==, 0);
	g_assert_cmpint(result.tv.tv_sec, ==, 946684801);
	g_assert_cmpint(result.tv.tv_usec, ==, 234567);

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
	struct btsnoop *btsnoop;
	struct read_result result;
	struct timeval tv = { .tv_sec = 946684802, .tv_usec = 345678 };
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

	g_assert_true(read_trace_file(path, 0, sizeof(command), &result));
	g_assert_cmpint(result.index, ==, 0);
	g_assert_cmpint(result.opcode, ==, BTSNOOP_OPCODE_COMMAND_PKT);
	g_assert_cmpint(result.size, ==, sizeof(command));
	g_assert_cmpint(memcmp(result.data, command, sizeof(command)), ==, 0);

	btsnoop = btsnoop_open(path, 0);
	g_assert_nonnull(btsnoop);
	read_result_init(&result);
	g_assert_true(btsnoop_read_hci(btsnoop, &result.tv,
				&result.index, &result.opcode,
				result.data, sizeof(result.data),
				&result.size));
	g_assert_true(btsnoop_read_hci(btsnoop, &result.tv,
				&result.index, &result.opcode,
				result.data, sizeof(result.data),
				&result.size));
	g_assert_cmpint(result.opcode, ==, BTSNOOP_OPCODE_EVENT_PKT);
	g_assert_cmpint(result.size, ==, sizeof(event));
	g_assert_cmpint(memcmp(result.data, event, sizeof(event)), ==, 0);
	g_assert_false(btsnoop_read_hci(btsnoop, &result.tv,
				&result.index, &result.opcode,
				result.data, sizeof(result.data),
				&result.size));
	btsnoop_unref(btsnoop);

	unlink(path);
	g_free(path);
}

static void test_btsnoop_write_monitor_roundtrip(void)
{
	const uint8_t payload[] = { 0xaa, 0xbb };
	struct btsnoop *btsnoop;
	struct read_result result;
	struct timeval tv = { .tv_sec = 946684800, .tv_usec = 0 };
	char *path = new_tmp_path();

	btsnoop = btsnoop_create(path, 0, 0, BTSNOOP_FORMAT_MONITOR);
	g_assert_nonnull(btsnoop);
	g_assert_true(btsnoop_write_hci(btsnoop, &tv, 7, 0x1234, 0,
						payload, sizeof(payload)));
	btsnoop_unref(btsnoop);

	g_assert_true(read_trace_file(path, 0, sizeof(payload), &result));
	g_assert_cmpint(result.index, ==, 7);
	g_assert_cmpint(result.opcode, ==, 0x1234);
	g_assert_cmpint(result.size, ==, sizeof(payload));
	g_assert_cmpint(memcmp(result.data, payload, sizeof(payload)), ==, 0);

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
	struct read_result result;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_MONITOR);
	append_btsnoop_packet(trace, sizeof(payload), 0x00051234,
			BTSNOOP_EPOCH_OFFSET, payload, sizeof(payload));

	g_assert_true(read_tmp_trace(trace->data, trace->len, 0,
						sizeof(payload), &result));
	g_assert_cmpint(result.index, ==, 5);
	g_assert_cmpint(result.opcode, ==, 0x1234);
	g_assert_cmpint(result.size, ==, sizeof(payload));
	g_assert_cmpint(memcmp(result.data, payload, sizeof(payload)), ==, 0);

	g_byte_array_unref(trace);
}

static void test_btsnoop_uart_valid(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x04, 0x0e, 0x01, 0x00 };
	struct read_result result;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_UART);
	append_btsnoop_packet(trace, sizeof(payload), 0,
			BTSNOOP_EPOCH_OFFSET, payload, sizeof(payload));

	g_assert_true(read_tmp_trace(trace->data, trace->len, 0,
						sizeof(payload) - 1, &result));
	g_assert_cmpint(result.index, ==, 0);
	g_assert_cmpint(result.opcode, ==, BTSNOOP_OPCODE_EVENT_PKT);
	g_assert_cmpint(result.size, ==, sizeof(payload) - 1);
	g_assert_cmpint(memcmp(result.data, payload + 1, result.size), ==, 0);

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
		struct read_result result;

		append_btsnoop_header(trace, BTSNOOP_FORMAT_UART);
		append_btsnoop_packet(trace, sizeof(payload), cases[i].flags,
				BTSNOOP_EPOCH_OFFSET, payload, sizeof(payload));

		g_assert_true(read_tmp_trace(trace->data, trace->len, 0, 1,
								&result));
		g_assert_cmpint(result.opcode, ==, cases[i].opcode);
		g_byte_array_unref(trace);
	}
}

static void test_btsnoop_rejects_small_capacity(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };
	struct read_result result;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_HCI);
	append_btsnoop_packet(trace, sizeof(payload), 0x02,
			BTSNOOP_EPOCH_OFFSET, payload, sizeof(payload));

	g_assert_false(read_tmp_trace(trace->data, trace->len, 0, 2, &result));
	g_assert_cmpint(result.data[0], ==, 0xa5);
	g_assert_cmpint(result.data[1], ==, 0xa5);
	g_assert_cmpint(result.data[2], ==, 0xa5);
	g_assert_cmpint(result.data[3], ==, 0xa5);

	g_byte_array_unref(trace);
}

static void test_btsnoop_rejects_timestamp_underflow(void)
{
	GByteArray *trace = g_byte_array_new();
	struct read_result result;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_HCI);
	append_btsnoop_packet(trace, 0, 0x02, BTSNOOP_EPOCH_OFFSET - 1,
								NULL, 0);

	g_assert_false(read_tmp_trace(trace->data, trace->len, 0, 0, &result));

	g_byte_array_unref(trace);
}

static void test_btsnoop_rejects_uart_zero_length(void)
{
	GByteArray *trace = g_byte_array_new();
	struct read_result result;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_UART);
	append_btsnoop_packet(trace, 0, 0, BTSNOOP_EPOCH_OFFSET, NULL, 0);

	g_assert_false(read_tmp_trace(trace->data, trace->len, 0, 0, &result));

	g_byte_array_unref(trace);
}

static void test_btsnoop_rejects_uart_short_type(void)
{
	GByteArray *trace = g_byte_array_new();
	struct read_result result;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_UART);
	append_btsnoop_packet(trace, 1, 0, BTSNOOP_EPOCH_OFFSET, NULL, 0);

	g_assert_false(read_tmp_trace(trace->data, trace->len, 0, 0, &result));

	g_byte_array_unref(trace);
}

static void test_btsnoop_rejects_short_payload(void)
{
	GByteArray *trace = g_byte_array_new();
	const uint8_t payload[] = { 0x01, 0x02 };
	struct read_result result;

	append_btsnoop_header(trace, BTSNOOP_FORMAT_HCI);
	append_btsnoop_packet(trace, 3, 0x02, BTSNOOP_EPOCH_OFFSET,
					payload, sizeof(payload));

	g_assert_false(read_tmp_trace(trace->data, trace->len, 0, 3, &result));

	g_byte_array_unref(trace);
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
		struct read_result result;

		g_assert_false(read_tmp_trace(trace->data, len, 0,
						sizeof(payload), &result));
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
	g_test_add_func("/btsnoop/fuzz/truncation",
			test_btsnoop_truncation_fuzz);

	add_pklg_tests();

	return g_test_run();
}
