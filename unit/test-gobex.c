/*
 *
 *  OBEX library with GLib integration
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <gobex/gobex.h>

#define FINAL_BIT 0x80

static GMainLoop *mainloop = NULL;

static uint8_t pkt_connect_req[] = { G_OBEX_OP_CONNECT | FINAL_BIT,
					0x00, 0x07, 0x10, 0x00, 0x10, 0x00 };

static uint8_t hdr_connid[] = { G_OBEX_HDR_ID_CONNECTION, 1, 2, 3, 4 };
static uint8_t hdr_name_ascii[] = { G_OBEX_HDR_ID_NAME, 0x00, 0x0b,
				0x00, 'f', 0x00, 'o', 0x00, 'o',
				0x00, 0x00 };
static uint8_t hdr_name_umlaut[] = { G_OBEX_HDR_ID_NAME, 0x00, 0x0b,
				0x00, 0xe5, 0x00, 0xe4, 0x00, 0xf6,
				0x00, 0x00 };
static uint8_t hdr_body[] = { G_OBEX_HDR_ID_BODY, 0x00, 0x07, 1, 2, 3, 4 };
static uint8_t hdr_actionid[] = { G_OBEX_HDR_ID_ACTION, 0x00 };

enum {
	TEST_ERROR_TIMEOUT,
	TEST_ERROR_UNEXPECTED,
};

static GQuark test_error_quark(void)
{
	return g_quark_from_static_string("test-error-quark");
}
#define TEST_ERROR test_error_quark()

static GObex *create_gobex(int fd)
{
	GIOChannel *io;

	io = g_io_channel_unix_new(fd);
	g_assert(io != NULL);

	return g_obex_new(io);
}

static void dump_bytes(uint8_t *buf, size_t buf_len)
{
	size_t i;

	for (i = 0; i < buf_len; i++)
		g_printerr("%02x ", buf[i]);

	g_printerr("\n");
}

static void assert_memequal(void *mem1, size_t len1, void *mem2, size_t len2)
{
	if (len1 == len2 && memcmp(mem1, mem2, len1) == 0)
		return;

	g_printerr("\nExpected: ");
	dump_bytes(mem1, len1);
	g_printerr("Got:      ");
	dump_bytes(mem2, len2);

	g_assert(0);
}

static gboolean test_timeout(gpointer user_data)
{
	GError **err = user_data;

	if (!g_main_loop_is_running(mainloop))
		return FALSE;

	g_set_error(err, TEST_ERROR, TEST_ERROR_TIMEOUT, "Timed out");

	g_main_loop_quit(mainloop);

	return FALSE;
}

static void handle_connect_request(GObex *obex, GObexPacket *pkt,
							gpointer user_data)
{
	GError **err = user_data;

	switch (g_obex_packet_get_operation(pkt, NULL)) {
	case G_OBEX_OP_CONNECT:
		break;
	default:
		g_set_error(err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
						"Unexpected operation");
		break;
	}

	g_main_loop_quit(mainloop);
}

static void test_recv_connect_stream(void)
{
	GError *gerr = NULL;
	GObex *obex;
	ssize_t err;
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) < 0) {
		g_printerr("socketpair: %s", strerror(errno));
		abort();
	}

	obex = create_gobex(sv[0]);
	g_assert(obex != NULL);

	g_obex_set_request_function(obex, handle_connect_request, &gerr);

	err = write(sv[1], pkt_connect_req, sizeof(pkt_connect_req));
	g_assert_cmpint(err, ==, sizeof(pkt_connect_req));

	mainloop = g_main_loop_new(NULL, FALSE);

	g_timeout_add_seconds(1, test_timeout, &gerr);

	g_main_loop_run(mainloop);

	g_assert_no_error(gerr);
}

static void test_header_name_ascii(void)
{
	GObexHeader *header;
	uint8_t buf[1024];
	size_t len;

	header = g_obex_header_unicode(G_OBEX_HDR_ID_NAME, "foo");

	g_assert(header != NULL);

	len = g_obex_header_encode(header, buf, sizeof(buf));

	assert_memequal(hdr_name_ascii, sizeof(hdr_name_ascii), buf, len);

	g_obex_header_free(header);
}

static void test_header_name_umlaut(void)
{
	GObexHeader *header;
	uint8_t buf[1024];
	size_t len;

	header = g_obex_header_unicode(G_OBEX_HDR_ID_NAME, "åäö");

	g_assert(header != NULL);

	len = g_obex_header_encode(header, buf, sizeof(buf));

	assert_memequal(hdr_name_umlaut, sizeof(hdr_name_umlaut), buf, len);

	g_obex_header_free(header);
}

static void test_header_bytes(void)
{
	GObexHeader *header;
	uint8_t buf[1024], data[] = { 1, 2, 3, 4 };
	size_t len;

	header = g_obex_header_bytes(G_OBEX_HDR_ID_BODY, data, sizeof(data),
							G_OBEX_DATA_REF);

	g_assert(header != NULL);

	len = g_obex_header_encode(header, buf, sizeof(buf));

	assert_memequal(hdr_body, sizeof(hdr_body), buf, len);

	g_obex_header_free(header);
}

static void test_header_uint8(void)
{
	GObexHeader *header;
	uint8_t buf[1024];
	size_t len;

	header = g_obex_header_uint8(G_OBEX_HDR_ID_ACTION, 0x00);

	g_assert(header != NULL);

	len = g_obex_header_encode(header, buf, sizeof(buf));

	assert_memequal(hdr_actionid, sizeof(hdr_actionid), buf, len);

	g_obex_header_free(header);
}

static void test_header_uint32(void)
{
	GObexHeader *header;
	uint8_t buf[1024];
	size_t len;

	header = g_obex_header_uint32(G_OBEX_HDR_ID_CONNECTION, 0x01020304);

	len = g_obex_header_encode(header, buf, sizeof(buf));

	assert_memequal(hdr_connid, sizeof(hdr_connid), buf, len);

	g_obex_header_free(header);
}

static void test_decode_pkt(void)
{
	GObexPacket *pkt;
	uint8_t buf[] = { G_OBEX_OP_PUT, 0x00, 0x03 };

	pkt = g_obex_packet_decode(buf, sizeof(buf), G_OBEX_DATA_REF);
	g_assert(pkt != NULL);

	g_obex_packet_free(pkt);
}

static void parse_and_encode(uint8_t *buf, size_t buf_len)
{
	GObexHeader *header;
	uint8_t encoded[1024];
	size_t len;

	header = g_obex_header_decode(buf, buf_len, G_OBEX_DATA_REF, &len);
	g_assert(header != NULL);
	g_assert_cmpuint(len, ==, buf_len);

	len = g_obex_header_encode(header, encoded, sizeof(encoded));

	assert_memequal(buf, buf_len, encoded, len);

	g_obex_header_free(header);
}

static void test_header_encode_connid(void)
{
	parse_and_encode(hdr_connid, sizeof(hdr_connid));
}

static void test_header_encode_name_ascii(void)
{
	parse_and_encode(hdr_name_ascii, sizeof(hdr_name_ascii));
}

static void test_header_encode_name_umlaut(void)
{
	parse_and_encode(hdr_name_umlaut, sizeof(hdr_name_umlaut));
}

static void test_header_encode_body(void)
{
	parse_and_encode(hdr_body, sizeof(hdr_body));
}

static void test_header_encode_actionid(void)
{
	parse_and_encode(hdr_actionid, sizeof(hdr_actionid));
}

static void test_decode_header_connid(void)
{
	GObexHeader *header;
	size_t parsed;

	header = g_obex_header_decode(hdr_connid, sizeof(hdr_connid),
						G_OBEX_DATA_REF, &parsed);
	g_assert(header != NULL);

	g_assert_cmpuint(parsed, ==, sizeof(hdr_connid));

	g_obex_header_free(header);
}

static void test_decode_header_name_ascii(void)
{
	GObexHeader *header;
	size_t parsed;

	header = g_obex_header_decode(hdr_name_ascii, sizeof(hdr_name_ascii),
						G_OBEX_DATA_REF, &parsed);
	g_assert(header != NULL);

	g_assert_cmpuint(parsed, ==, sizeof(hdr_name_ascii));

	g_obex_header_free(header);
}

static void test_decode_header_name_umlaut(void)
{
	GObexHeader *header;
	size_t parsed;

	header = g_obex_header_decode(hdr_name_umlaut, sizeof(hdr_name_umlaut),
						G_OBEX_DATA_REF, &parsed);
	g_assert(header != NULL);

	g_assert_cmpuint(parsed, ==, sizeof(hdr_name_umlaut));

	g_obex_header_free(header);
}

static void test_decode_header_body(void)
{
	GObexHeader *header;
	size_t parsed;

	header = g_obex_header_decode(hdr_body, sizeof(hdr_body),
						G_OBEX_DATA_COPY, &parsed);
	g_assert(header != NULL);

	g_assert_cmpuint(parsed, ==, sizeof(hdr_body));

	g_obex_header_free(header);
}

static void test_decode_header_body_extdata(void)
{
	GObexHeader *header;
	size_t parsed;

	header = g_obex_header_decode(hdr_body, sizeof(hdr_body),
						G_OBEX_DATA_REF, &parsed);
	g_assert(header != NULL);

	g_assert_cmpuint(parsed, ==, sizeof(hdr_body));

	g_obex_header_free(header);
}

static void test_decode_header_actionid(void)
{
	GObexHeader *header;
	size_t parsed;

	header = g_obex_header_decode(hdr_actionid, sizeof(hdr_actionid),
						G_OBEX_DATA_REF, &parsed);
	g_assert(header != NULL);

	g_assert_cmpuint(parsed, ==, sizeof(hdr_actionid));

	g_obex_header_free(header);
}

static void test_decode_header_multi(void)
{
	GObexHeader *header;
	GByteArray *buf;
	size_t parsed;

	buf = g_byte_array_sized_new(sizeof(hdr_connid) +
					sizeof(hdr_name_ascii) +
					sizeof(hdr_actionid) +
					sizeof(hdr_body));

	g_byte_array_append(buf, hdr_connid, sizeof(hdr_connid));
	g_byte_array_append(buf, hdr_name_ascii, sizeof(hdr_name_ascii));
	g_byte_array_append(buf, hdr_actionid, sizeof(hdr_actionid));
	g_byte_array_append(buf, hdr_body, sizeof(hdr_body));

	header = g_obex_header_decode(buf->data, buf->len, G_OBEX_DATA_REF,
								&parsed);
	g_assert(header != NULL);
	g_assert_cmpuint(parsed, ==, sizeof(hdr_connid));
	g_byte_array_remove_range(buf, 0, parsed);
	g_obex_header_free(header);

	header = g_obex_header_decode(buf->data, buf->len, G_OBEX_DATA_REF,
								&parsed);
	g_assert(header != NULL);
	g_assert_cmpuint(parsed, ==, sizeof(hdr_name_ascii));
	g_byte_array_remove_range(buf, 0, parsed);
	g_obex_header_free(header);

	header = g_obex_header_decode(buf->data, buf->len, G_OBEX_DATA_REF,
								&parsed);
	g_assert(header != NULL);
	g_assert_cmpuint(parsed, ==, sizeof(hdr_actionid));
	g_byte_array_remove_range(buf, 0, parsed);
	g_obex_header_free(header);

	header = g_obex_header_decode(buf->data, buf->len, G_OBEX_DATA_REF,
								&parsed);
	g_assert(header != NULL);
	g_assert_cmpuint(parsed, ==, sizeof(hdr_body));
	g_byte_array_remove_range(buf, 0, parsed);
	g_obex_header_free(header);

	g_byte_array_unref(buf);
}

static void test_pkt(void)
{
	GObexPacket *pkt;

	pkt = g_obex_packet_new(G_OBEX_OP_PUT, TRUE);

	g_assert(pkt != NULL);

	g_obex_packet_free(pkt);
}

static void test_ref_unref(void)
{
	GObex *obex;

	obex = create_gobex(STDIN_FILENO);

	g_assert(obex != NULL);

	obex = g_obex_ref(obex);

	g_obex_unref(obex);
	g_obex_unref(obex);
}

static void test_basic(void)
{
	GObex *obex;

	obex = create_gobex(STDIN_FILENO);

	g_assert(obex != NULL);

	g_obex_unref(obex);
}

static void test_null_io(void)
{
	GObex *obex;

	obex = g_obex_new(NULL);

	g_assert(obex == NULL);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/gobex/null_io", test_null_io);
	g_test_add_func("/gobex/basic", test_basic);
	g_test_add_func("/gobex/ref_unref", test_ref_unref);

	g_test_add_func("/gobex/test_pkt", test_pkt);

	g_test_add_func("/gobex/test_decode_header_connid",
						test_decode_header_connid);
	g_test_add_func("/gobex/test_decode_header_name_ascii",
					test_decode_header_name_ascii);
	g_test_add_func("/gobex/test_decode_header_name_umlaut",
					test_decode_header_name_umlaut);
	g_test_add_func("/gobex/test_decode_header_body",
						test_decode_header_body);
	g_test_add_func("/gobex/test_decode_header_body_extdata",
					test_decode_header_body_extdata);
	g_test_add_func("/gobex/test_decode_header_actionid",
						test_decode_header_actionid);
	g_test_add_func("/gobex/test_decode_header_multi",
						test_decode_header_multi);

	g_test_add_func("/gobex/test_header_encode_connid",
						test_header_encode_connid);
	g_test_add_func("/gobex/test_header_encode_name_ascii",
					test_header_encode_name_ascii);
	g_test_add_func("/gobex/test_header_encode_name_umlaut",
					test_header_encode_name_umlaut);
	g_test_add_func("/gobex/test_header_encode_body",
						test_header_encode_body);
	g_test_add_func("/gobex/test_header_encode_connid",
						test_header_encode_actionid);

	g_test_add_func("/gobex/test_header_name_ascii",
						test_header_name_ascii);
	g_test_add_func("/gobex/test_header_name_umlaut",
						test_header_name_umlaut);
	g_test_add_func("/gobex/test_header_bytes", test_header_bytes);
	g_test_add_func("/gobex/test_header_uint8", test_header_uint8);
	g_test_add_func("/gobex/test_header_uint32", test_header_uint32);

	g_test_add_func("/gobex/test_decode_pkt", test_decode_pkt);

	g_test_add_func("/gobex/test_recv_connect_stream",
						test_recv_connect_stream);

	g_test_run();

	return 0;
}
