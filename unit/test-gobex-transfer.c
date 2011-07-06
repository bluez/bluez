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
#include <stdint.h>

#include <gobex/gobex.h>
#include <gobex/gobex-transfer.h>

#include "util.h"

#define FINAL_BIT 0x80

static GMainLoop *mainloop = NULL;

static guint8 put_req_first[] = { G_OBEX_OP_PUT | FINAL_BIT, 0x00, 0x30,
	G_OBEX_HDR_ID_TYPE, 0x00, 0x0b,
	'f', 'o', 'o', '/', 'b', 'a', 'r', '\0',
	G_OBEX_HDR_ID_NAME, 0x00, 0x15,
	0, 'f', 0, 'i', 0, 'l', 0, 'e', 0, '.', 0, 't', 0, 'x', 0, 't', 0, 0,
	G_OBEX_HDR_ID_BODY, 0x00, 0x0d,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

static guint8 put_req_last[] = { G_OBEX_OP_PUT | FINAL_BIT, 0x00, 0x06,
					G_OBEX_HDR_ID_BODY_END, 0x00, 0x03 };

static guint8 put_rsp_first[] = { G_OBEX_RSP_CONTINUE | FINAL_BIT,
								0x00, 0x03 };
static guint8 put_rsp_last[] = { G_OBEX_RSP_SUCCESS | FINAL_BIT, 0x00, 0x03 };

static guint8 get_req_first[] = { G_OBEX_OP_GET | FINAL_BIT, 0x00, 0x23,
	G_OBEX_HDR_ID_TYPE, 0x00, 0x0b,
	'f', 'o', 'o', '/', 'b', 'a', 'r', '\0',
	G_OBEX_HDR_ID_NAME, 0x00, 0x15,
	0, 'f', 0, 'i', 0, 'l', 0, 'e', 0, '.', 0, 't', 0, 'x', 0, 't', 0, 0 };

static guint8 get_req_last[] = { G_OBEX_OP_GET | FINAL_BIT, 0x00, 0x03, };

static guint8 get_rsp_first[] = { G_OBEX_RSP_CONTINUE | FINAL_BIT, 0x00, 0x10,
					G_OBEX_HDR_ID_BODY, 0x00, 0x0d,
					0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
static guint8 get_rsp_last[] = { G_OBEX_RSP_SUCCESS | FINAL_BIT, 0x00, 0x06,
					G_OBEX_HDR_ID_BODY_END, 0x00, 0x03 };

static guint8 body_data[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

static gboolean test_timeout(gpointer user_data)
{
	GError **err = user_data;

	if (!g_main_loop_is_running(mainloop))
		return FALSE;

	g_set_error(err, TEST_ERROR, TEST_ERROR_TIMEOUT, "Timed out");

	g_main_loop_quit(mainloop);

	return FALSE;
}

struct test_data {
	guint count;
	GError *err;
};

static gboolean put_srv(GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	struct test_data *d = user_data;
	GIOStatus status;
	gsize bytes_written, rbytes, send_buf_len, expect_len;
	char buf[255];
	const char *send_buf, *expect;

	d->count++;

	if (d->count > 1) {
		send_buf = (const char *) put_rsp_last;
		send_buf_len = sizeof(put_rsp_last);
		expect = (const char *) put_req_last;
		expect_len = sizeof(put_req_last);
	} else {
		send_buf = (const char *) put_rsp_first;
		send_buf_len = sizeof(put_rsp_first);
		expect = (const char *) put_req_first;
		expect_len = sizeof(put_req_first);
	}

	status = g_io_channel_read_chars(io, buf, sizeof(buf), &rbytes, NULL);
	if (status != G_IO_STATUS_NORMAL) {
		g_print("put_srv count %u\n", d->count);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Reading data failed with status %d", status);
		goto failed;
	}

	if (rbytes < expect_len) {
		g_print("put_srv count %u\n", d->count);
		dump_bufs(expect, expect_len, buf, rbytes);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"Not enough data from socket");
		goto failed;
	}

	if (memcmp(buf, expect, expect_len) != 0) {
		g_print("put_srv count %u\n", d->count);
		dump_bufs(expect, expect_len, buf, rbytes);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"Received data is not correct");
		goto failed;
	}

	g_io_channel_write_chars(io, send_buf, send_buf_len, &bytes_written,
									NULL);
	if (bytes_written != send_buf_len) {
		g_print("put_srv count %u\n", d->count);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
						"Unable to write to socket");
		goto failed;
	}

	return TRUE;

failed:
	g_main_loop_quit(mainloop);
	return FALSE;
}

static void transfer_complete(GObex *obex, GError *err, gpointer user_data)
{
	struct test_data *d = user_data;

	if (err != NULL)
		d->err = g_error_copy(err);

	g_main_loop_quit(mainloop);
}

static gssize provide_data(void *buf, gsize len, gpointer user_data)
{
	struct test_data *d = user_data;

	if (d->count > 0)
		return 0;

	if (len < sizeof(body_data)) {
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Got data request for only %zu bytes", len);
		g_main_loop_quit(mainloop);
		return -1;
	}

	memcpy(buf, body_data, sizeof(body_data));

	return sizeof(body_data);
}

static void test_put_req(void)
{
	GIOChannel *io;
	GIOCondition cond;
	guint io_id, timer_id;
	GObex *obex;
	struct test_data d = { 0, NULL };

	create_endpoints(&obex, &io, SOCK_STREAM);

	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	io_id = g_io_add_watch(io, cond, put_srv, &d);

	mainloop = g_main_loop_new(NULL, FALSE);

	timer_id = g_timeout_add_seconds(1, test_timeout, &d);

	g_obex_put_req(obex, "foo/bar", "file.txt", provide_data,
						transfer_complete, &d, &d.err);
	g_assert_no_error(d.err);

	g_main_loop_run(mainloop);

	g_main_loop_unref(mainloop);
	mainloop = NULL;

	g_source_remove(timer_id);
	g_io_channel_unref(io);
	g_source_remove(io_id);
	g_obex_unref(obex);

	g_assert_no_error(d.err);
}

static gboolean rcv_data(const void *buf, gsize len, gpointer user_data)
{
	struct test_data *d = user_data;

	if (len != sizeof(body_data))
		d->err = g_error_new(TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"Unexpected byte count %zu", len);

	if (memcmp(buf, body_data, sizeof(body_data)) != 0) {
		dump_bufs(body_data, sizeof(body_data), buf, len);
		d->err = g_error_new(TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"Unexpected byte count %zu", len);
	}

	return TRUE;
}

static void handle_put(GObex *obex, GObexPacket *req, gpointer user_data)
{
	struct test_data *d = user_data;
	guint8 op = g_obex_packet_get_operation(req, NULL);
	guint id;

	if (op != G_OBEX_OP_PUT) {
		d->err = g_error_new(TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"Unexpected opcode 0x%02x", op);
		g_main_loop_quit(mainloop);
		return;
	}

	id = g_obex_put_rsp(obex, req, rcv_data, transfer_complete, d,
								&d->err);
	if (id == 0)
		g_main_loop_quit(mainloop);
}

static gboolean put_cli(GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	struct test_data *d = user_data;
	GIOStatus status;
	gsize bytes_written, rbytes, send_buf_len, expect_len;
	char buf[255];
	const char *send_buf, *expect;

	d->count++;

	if (d->count > 1) {
		expect = (const char *) put_rsp_last;
		expect_len = sizeof(put_rsp_last);
		send_buf = NULL;
		send_buf_len = 0;
	} else {
		expect = (const char *) put_rsp_first;
		expect_len = sizeof(put_rsp_first);
		send_buf = (const char *) put_req_last;
		send_buf_len = sizeof(put_req_last);
	}

	status = g_io_channel_read_chars(io, buf, sizeof(buf), &rbytes, NULL);
	if (status != G_IO_STATUS_NORMAL) {
		g_print("put_cli count %u\n", d->count);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Reading data failed with status %d", status);
		goto failed;
	}

	if (rbytes < expect_len) {
		g_print("put_cli count %u\n", d->count);
		dump_bufs(expect, expect_len, buf, rbytes);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"Not enough data from socket");
		goto failed;
	}

	if (memcmp(buf, expect, expect_len) != 0) {
		g_print("put_cli count %u\n", d->count);
		dump_bufs(expect, expect_len, buf, rbytes);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"Received data is not correct");
		goto failed;
	}

	if (send_buf == NULL)
		return TRUE;

	g_io_channel_write_chars(io, send_buf, send_buf_len, &bytes_written,
									NULL);
	if (bytes_written != send_buf_len) {
		g_print("put_cli count %u\n", d->count);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
						"Unable to write to socket");
		goto failed;
	}

	return TRUE;

failed:
	g_main_loop_quit(mainloop);
	return FALSE;
}

static void test_put_rsp(void)
{
	GIOChannel *io;
	GIOCondition cond;
	guint io_id, timer_id;
	GObex *obex;
	struct test_data d = { 0, NULL };

	create_endpoints(&obex, &io, SOCK_STREAM);

	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	io_id = g_io_add_watch(io, cond, put_cli, &d);

	mainloop = g_main_loop_new(NULL, FALSE);

	timer_id = g_timeout_add_seconds(1, test_timeout, &d);

	g_obex_add_request_function(obex, G_OBEX_OP_PUT, handle_put, &d);

	g_io_channel_write_chars(io, (char *) put_req_first,
					sizeof(put_req_first), NULL, &d.err);
	g_assert_no_error(d.err);

	g_main_loop_run(mainloop);

	g_main_loop_unref(mainloop);
	mainloop = NULL;

	g_source_remove(timer_id);
	g_io_channel_unref(io);
	g_source_remove(io_id);
	g_obex_unref(obex);

	g_assert_no_error(d.err);
}

static gboolean get_srv(GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	struct test_data *d = user_data;
	GIOStatus status;
	gsize bytes_written, rbytes, send_buf_len, expect_len;
	char buf[255];
	const char *send_buf, *expect;

	d->count++;

	if (d->count > 1) {
		send_buf = (const char *) get_rsp_last;
		send_buf_len = sizeof(get_rsp_last);
		expect = (const char *) get_req_last;
		expect_len = sizeof(get_req_last);
	} else {
		send_buf = (const char *) get_rsp_first;
		send_buf_len = sizeof(get_rsp_first);
		expect = (const char *) get_req_first;
		expect_len = sizeof(get_req_first);
	}

	status = g_io_channel_read_chars(io, buf, sizeof(buf), &rbytes, NULL);
	if (status != G_IO_STATUS_NORMAL) {
		g_print("put_srv count %u\n", d->count);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Reading data failed with status %d", status);
		goto failed;
	}

	if (rbytes < expect_len) {
		g_print("put_srv count %u\n", d->count);
		dump_bufs(expect, expect_len, buf, rbytes);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"Not enough data from socket");
		goto failed;
	}

	if (memcmp(buf, expect, expect_len) != 0) {
		g_print("put_srv count %u\n", d->count);
		dump_bufs(expect, expect_len, buf, rbytes);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"Received data is not correct");
		goto failed;
	}

	g_io_channel_write_chars(io, send_buf, send_buf_len, &bytes_written,
									NULL);
	if (bytes_written != send_buf_len) {
		g_print("put_srv count %u\n", d->count);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
						"Unable to write to socket");
		goto failed;
	}

	return TRUE;

failed:
	g_main_loop_quit(mainloop);
	return FALSE;
}

static void test_get_req(void)
{
	GIOChannel *io;
	GIOCondition cond;
	guint io_id, timer_id;
	GObex *obex;
	struct test_data d = { 0, NULL };

	create_endpoints(&obex, &io, SOCK_STREAM);

	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	io_id = g_io_add_watch(io, cond, get_srv, &d);

	mainloop = g_main_loop_new(NULL, FALSE);

	timer_id = g_timeout_add_seconds(1, test_timeout, &d);

	g_obex_get_req(obex, "foo/bar", "file.txt", rcv_data,
						transfer_complete, &d, &d.err);
	g_assert_no_error(d.err);

	g_main_loop_run(mainloop);

	g_main_loop_unref(mainloop);
	mainloop = NULL;

	g_source_remove(timer_id);
	g_io_channel_unref(io);
	g_source_remove(io_id);
	g_obex_unref(obex);

	g_assert_no_error(d.err);
}

static gboolean get_cli(GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	struct test_data *d = user_data;
	GIOStatus status;
	gsize bytes_written, rbytes, send_buf_len, expect_len;
	char buf[255];
	const char *send_buf, *expect;

	d->count++;

	if (d->count > 1) {
		expect = (const char *) get_rsp_last;
		expect_len = sizeof(get_rsp_last);
		send_buf = NULL;
		send_buf_len = 0;
	} else {
		expect = (const char *) get_rsp_first;
		expect_len = sizeof(get_rsp_first);
		send_buf = (const char *) get_req_last;
		send_buf_len = sizeof(get_req_last);
	}

	status = g_io_channel_read_chars(io, buf, sizeof(buf), &rbytes, NULL);
	if (status != G_IO_STATUS_NORMAL) {
		g_print("get_cli count %u\n", d->count);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Reading data failed with status %d", status);
		goto failed;
	}

	if (rbytes < expect_len) {
		g_print("get_cli count %u\n", d->count);
		dump_bufs(expect, expect_len, buf, rbytes);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"Not enough data from socket");
		goto failed;
	}

	if (memcmp(buf, expect, expect_len) != 0) {
		g_print("get_cli count %u\n", d->count);
		dump_bufs(expect, expect_len, buf, rbytes);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"Received data is not correct");
		goto failed;
	}

	if (send_buf == NULL)
		return TRUE;

	g_io_channel_write_chars(io, send_buf, send_buf_len, &bytes_written,
									NULL);
	if (bytes_written != send_buf_len) {
		g_print("get_cli count %u\n", d->count);
		g_set_error(&d->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
						"Unable to write to socket");
		goto failed;
	}

	return TRUE;

failed:
	g_main_loop_quit(mainloop);
	return FALSE;
}

static void handle_get(GObex *obex, GObexPacket *req, gpointer user_data)
{
	struct test_data *d = user_data;
	guint8 op = g_obex_packet_get_operation(req, NULL);
	guint id;

	if (op != G_OBEX_OP_GET) {
		d->err = g_error_new(TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"Unexpected opcode 0x%02x", op);
		g_main_loop_quit(mainloop);
		return;
	}

	id = g_obex_get_rsp(obex, req, provide_data, transfer_complete,
								d, &d->err);
	if (id == 0)
		g_main_loop_quit(mainloop);
}

static void test_get_rsp(void)
{
	GIOChannel *io;
	GIOCondition cond;
	guint io_id, timer_id;
	GObex *obex;
	struct test_data d = { 0, NULL };

	create_endpoints(&obex, &io, SOCK_STREAM);

	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	io_id = g_io_add_watch(io, cond, get_cli, &d);

	mainloop = g_main_loop_new(NULL, FALSE);

	timer_id = g_timeout_add_seconds(1, test_timeout, &d);

	g_obex_add_request_function(obex, G_OBEX_OP_GET, handle_get, &d);

	g_io_channel_write_chars(io, (char *) get_req_first,
					sizeof(get_req_first), NULL, &d.err);
	g_assert_no_error(d.err);

	g_main_loop_run(mainloop);

	g_main_loop_unref(mainloop);
	mainloop = NULL;

	g_source_remove(timer_id);
	g_io_channel_unref(io);
	g_source_remove(io_id);
	g_obex_unref(obex);

	g_assert_no_error(d.err);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/gobex/test_put_req", test_put_req);
	g_test_add_func("/gobex/test_put_rsp", test_put_rsp);

	g_test_add_func("/gobex/test_get_req", test_get_req);
	g_test_add_func("/gobex/test_get_rsp", test_get_rsp);

	g_test_run();

	return 0;
}
