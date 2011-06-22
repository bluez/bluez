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

#include <unistd.h>
#include <string.h>

#include <gobex/gobex.h>

static uint8_t hdr_connid[] = { G_OBEX_HDR_ID_CONNECTION, 1, 2, 3, 4 };
static uint8_t hdr_name[] = { G_OBEX_HDR_ID_NAME, 0x00, 0x0b,
				0x00, 'f', 0x00, 'o', 0x00, 'o', 0x00, 0x00 };
static uint8_t hdr_body[] = { G_OBEX_HDR_ID_BODY, 0x00, 0x07, 1, 2, 3, 4 };
static uint8_t hdr_actionid[] = { G_OBEX_HDR_ID_ACTION, 0x00 };

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
		g_print("%02x ", buf[i]);

	g_print("\n");
}

static void parse_and_decode(uint8_t *buf, size_t buf_len)
{
	GObexHeader *header;
	uint8_t encoded[1024];
	size_t len;

	header = g_obex_header_parse(buf, buf_len, FALSE, &len);
	g_assert(header != NULL);
	g_assert_cmpuint(len, ==, buf_len);

	len = g_obex_header_encode(header, encoded, sizeof(encoded));

	g_obex_header_free(header);

	if (len != buf_len)
		goto failed;

	if (memcmp(encoded, buf, len) != 0)
		goto failed;

	return;

failed:
	g_print("\nIn:  ");
	dump_bytes(buf, buf_len);
	g_print("Out: ");
	dump_bytes(encoded, len);
	g_assert(0);
}

static void test_header_encode_connid(void)
{
	parse_and_decode(hdr_connid, sizeof(hdr_connid));
}

static void test_header_encode_name(void)
{
	parse_and_decode(hdr_name, sizeof(hdr_name));
}

static void test_header_encode_body(void)
{
	parse_and_decode(hdr_body, sizeof(hdr_body));
}

static void test_header_encode_actionid(void)
{
	parse_and_decode(hdr_actionid, sizeof(hdr_actionid));
}

static void test_parse_header_connid(void)
{
	GObexHeader *header;
	size_t parsed;

	header = g_obex_header_parse(hdr_connid, sizeof(hdr_connid),
							FALSE, &parsed);
	g_assert(header != NULL);

	g_assert_cmpuint(parsed, ==, sizeof(hdr_connid));

	g_obex_header_free(header);
}

static void test_parse_header_name(void)
{
	GObexHeader *header;
	size_t parsed;

	header = g_obex_header_parse(hdr_name, sizeof(hdr_name),
							FALSE, &parsed);
	g_assert(header != NULL);

	g_assert_cmpuint(parsed, ==, sizeof(hdr_name));

	g_obex_header_free(header);
}

static void test_parse_header_body(void)
{
	GObexHeader *header;
	size_t parsed;

	header = g_obex_header_parse(hdr_body, sizeof(hdr_body),
							FALSE, &parsed);
	g_assert(header != NULL);

	g_assert_cmpuint(parsed, ==, sizeof(hdr_body));

	g_obex_header_free(header);
}

static void test_parse_header_body_extdata(void)
{
	GObexHeader *header;
	size_t parsed;

	header = g_obex_header_parse(hdr_body, sizeof(hdr_body),
							TRUE, &parsed);
	g_assert(header != NULL);

	g_assert_cmpuint(parsed, ==, sizeof(hdr_body));

	g_obex_header_free(header);
}

static void test_parse_header_actionid(void)
{
	GObexHeader *header;
	size_t parsed;

	header = g_obex_header_parse(hdr_actionid, sizeof(hdr_actionid),
							FALSE, &parsed);
	g_assert(header != NULL);

	g_assert_cmpuint(parsed, ==, sizeof(hdr_actionid));

	g_obex_header_free(header);
}

static void test_parse_header_multi(void)
{
	GObexHeader *header;
	GByteArray *buf;
	size_t parsed;

	buf = g_byte_array_sized_new(sizeof(hdr_connid) +
					sizeof(hdr_name) +
					sizeof(hdr_actionid) +
					sizeof(hdr_body));

	g_byte_array_append(buf, hdr_connid, sizeof(hdr_connid));
	g_byte_array_append(buf, hdr_name, sizeof(hdr_name));
	g_byte_array_append(buf, hdr_actionid, sizeof(hdr_actionid));
	g_byte_array_append(buf, hdr_body, sizeof(hdr_body));

	header = g_obex_header_parse(buf->data, buf->len, FALSE, &parsed);
	g_assert(header != NULL);
	g_assert_cmpuint(parsed, ==, sizeof(hdr_connid));
	g_byte_array_remove_range(buf, 0, parsed);
	g_obex_header_free(header);

	header = g_obex_header_parse(buf->data, buf->len, FALSE, &parsed);
	g_assert(header != NULL);
	g_assert_cmpuint(parsed, ==, sizeof(hdr_name));
	g_byte_array_remove_range(buf, 0, parsed);
	g_obex_header_free(header);

	header = g_obex_header_parse(buf->data, buf->len, FALSE, &parsed);
	g_assert(header != NULL);
	g_assert_cmpuint(parsed, ==, sizeof(hdr_actionid));
	g_byte_array_remove_range(buf, 0, parsed);
	g_obex_header_free(header);

	header = g_obex_header_parse(buf->data, buf->len, FALSE, &parsed);
	g_assert(header != NULL);
	g_assert_cmpuint(parsed, ==, sizeof(hdr_body));
	g_byte_array_remove_range(buf, 0, parsed);
	g_obex_header_free(header);

	g_byte_array_unref(buf);
}

static void test_req(void)
{
	GObexRequest *req;

	req = g_obex_request_new(G_OBEX_OP_PUT);

	g_assert(req != NULL);

	g_obex_request_free(req);
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

	g_test_add_func("/gobex/test_req", test_req);

	g_test_add_func("/gobex/test_parse_header_connid",
						test_parse_header_connid);
	g_test_add_func("/gobex/test_parse_header_name",
						test_parse_header_name);
	g_test_add_func("/gobex/test_parse_header_body",
						test_parse_header_body);
	g_test_add_func("/gobex/test_parse_header_body_extdata",
					test_parse_header_body_extdata);
	g_test_add_func("/gobex/test_parse_header_actionid",
						test_parse_header_actionid);
	g_test_add_func("/gobex/test_parse_header_multi",
						test_parse_header_multi);

	g_test_add_func("/gobex/test_header_encode_connid",
						test_header_encode_connid);
	g_test_add_func("/gobex/test_header_encode_name",
						test_header_encode_name);
	g_test_add_func("/gobex/test_header_encode_body",
						test_header_encode_body);
	g_test_add_func("/gobex/test_header_encode_connid",
						test_header_encode_actionid);
	g_test_run();

	return 0;
}
