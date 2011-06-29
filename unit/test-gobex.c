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

#include "util.h"

#define FINAL_BIT 0x80

static GMainLoop *mainloop = NULL;

static uint8_t pkt_connect_req[] = { G_OBEX_OP_CONNECT | FINAL_BIT,
					0x00, 0x07, 0x10, 0x00, 0x10, 0x00 };
static uint8_t pkt_connect_rsp[] = { 0x10 | FINAL_BIT, 0x00, 0x07,
					0x10, 0x00, 0x10, 0x00 };
static uint8_t pkt_nval_connect_rsp[] = { 0x10 | FINAL_BIT, 0x00, 0x05,
					0x10, 0x00, };

static gboolean test_timeout(gpointer user_data)
{
	GError **err = user_data;

	if (!g_main_loop_is_running(mainloop))
		return FALSE;

	g_set_error(err, TEST_ERROR, TEST_ERROR_TIMEOUT, "Timed out");

	g_main_loop_quit(mainloop);

	return FALSE;
}

static gboolean handle_connect_data(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	GError **err = user_data;
	GIOStatus status;
	gsize rbytes;
	char buf[255];

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		g_set_error(err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Unexpected condition %d on socket", cond);
		goto done;
	}

	status = g_io_channel_read_chars(io, buf, sizeof(buf), &rbytes, NULL);
	if (status != G_IO_STATUS_NORMAL) {
		g_set_error(err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Reading data failed with status %d", status);
		goto done;
	}

	if (rbytes != sizeof(pkt_connect_req)) {
		g_set_error(err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Got %zu bytes instead of %zu",
				rbytes, sizeof(pkt_connect_req));
		dump_bufs(pkt_connect_req, sizeof(pkt_connect_req),
								buf, rbytes);
		goto done;
	}

	if (memcmp(buf, pkt_connect_req, rbytes) != 0) {
		g_set_error(err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Mismatch with received data");
		dump_bufs(pkt_connect_req, sizeof(pkt_connect_req),
								buf, rbytes);
		goto done;
	}

done:
	g_main_loop_quit(mainloop);
	return FALSE;
}

static GObex *create_gobex(int fd, GObexTransportType transport_type,
						gboolean close_on_unref)
{
	GIOChannel *io;

	io = g_io_channel_unix_new(fd);
	g_assert(io != NULL);

	g_io_channel_set_close_on_unref(io, close_on_unref);

	return g_obex_new(io, transport_type);
}

static void create_endpoints(GObex **obex, GIOChannel **io, int sock_type)
{
	GObexTransportType transport_type;
	int sv[2];

	if (socketpair(AF_UNIX, sock_type | SOCK_NONBLOCK, 0, sv) < 0) {
		g_printerr("socketpair: %s", strerror(errno));
		abort();
	}

	if (sock_type == SOCK_STREAM)
		transport_type = G_OBEX_TRANSPORT_STREAM;
	else
		transport_type = G_OBEX_TRANSPORT_PACKET;

	*obex = create_gobex(sv[0], transport_type, TRUE);
	g_assert(*obex != NULL);

	*io = g_io_channel_unix_new(sv[1]);
	g_assert(*io != NULL);

	g_io_channel_set_encoding(*io, NULL, NULL);
	g_io_channel_set_buffered(*io, FALSE);
	g_io_channel_set_close_on_unref(*io, TRUE);
}

static void connect_rsp(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	guint8 rsp_code;
	gboolean final;
	GError **test_err = user_data;

	if (err != NULL) {
		g_assert(*test_err == NULL);
		*test_err = g_error_copy(err);
		goto done;
	}

	rsp_code = g_obex_packet_get_operation(rsp, &final);
	if (rsp_code != 0x10) {
		g_set_error(test_err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Unexpected response 0x%02x", rsp_code);
		goto done;
	}

	if (!final) {
		g_set_error(test_err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Connect response didn't have final bit");
		goto done;
	}

done:
	g_main_loop_quit(mainloop);
}

static void nval_connect_rsp(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	GError **test_err = user_data;

	if (!g_error_matches(err, G_OBEX_ERROR, G_OBEX_ERROR_PARSE_ERROR))
		g_set_error(test_err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Did not get expected parse error");

	g_main_loop_quit(mainloop);
}

static void timeout_rsp(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	GError **test_err = user_data;

	if (!g_error_matches(err, G_OBEX_ERROR, G_OBEX_ERROR_TIMEOUT))
		g_set_error(test_err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Did not get expected timeout error");

	g_main_loop_quit(mainloop);
}

static gboolean recv_and_send(GIOChannel *io, void *data, gsize len,
								GError **err)
{
	gsize bytes_written, rbytes;
	char buf[255];
	GIOStatus status;

	status = g_io_channel_read_chars(io, buf, sizeof(buf), &rbytes, NULL);
	if (status != G_IO_STATUS_NORMAL) {
		g_set_error(err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"read failed with status %d", status);
		return FALSE;
	}

	if (data == NULL)
		return TRUE;

	g_io_channel_write_chars(io, data, len, &bytes_written, NULL);
	if (bytes_written != len) {
		g_set_error(err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
						"Unable to write to socket");
		return FALSE;
	}

	return TRUE;
}

static gboolean send_connect_rsp(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	GError **err = user_data;

	if (!recv_and_send(io, pkt_connect_rsp, sizeof(pkt_connect_rsp), err))
		g_main_loop_quit(mainloop);

	return FALSE;
}

static gboolean send_nval_connect_rsp(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	GError **err = user_data;

	if (!recv_and_send(io, pkt_nval_connect_rsp,
					sizeof(pkt_nval_connect_rsp), err))
		g_main_loop_quit(mainloop);

	return FALSE;
}

static gboolean send_nothing(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	GError **err = user_data;

	if (!recv_and_send(io, NULL, 0, err))
		g_main_loop_quit(mainloop);

	return FALSE;
}

static void send_connect(GObexResponseFunc rsp_func, GIOFunc send_rsp_func,
							gint req_timeout)
{
	guint8 connect_data[] = { 0x10, 0x00, 0x10, 0x00 };
	GError *gerr = NULL;
	GIOChannel *io;
	GIOCondition cond;
	GObexPacket *req;
	guint io_id, timer_id, test_time;
	GObex *obex;

	create_endpoints(&obex, &io, SOCK_STREAM);

	req = g_obex_packet_new(G_OBEX_OP_CONNECT, TRUE);
	g_assert(req != NULL);

	g_obex_packet_set_data(req, connect_data, sizeof(connect_data),
							G_OBEX_DATA_REF);

	g_obex_send_req(obex, req, req_timeout, rsp_func, &gerr, &gerr);
	g_assert_no_error(gerr);

	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	io_id = g_io_add_watch(io, cond, send_rsp_func, &gerr);

	mainloop = g_main_loop_new(NULL, FALSE);

	if (req_timeout > 0)
		test_time = req_timeout + 1;
	else
		test_time = 1;

	timer_id = g_timeout_add_seconds(test_time, test_timeout, &gerr);

	g_main_loop_run(mainloop);

	g_main_loop_unref(mainloop);
	mainloop = NULL;

	g_source_remove(timer_id);
	g_io_channel_unref(io);
	g_source_remove(io_id);
	g_obex_unref(obex);

	g_assert_no_error(gerr);
}

static void test_send_connect_req_stream(void)
{
	send_connect(connect_rsp, send_connect_rsp, -1);
}

static void test_send_nval_connect_req_stream(void)
{
	send_connect(nval_connect_rsp, send_nval_connect_rsp, -1);
}

static void test_send_connect_req_timeout_stream(void)
{
	send_connect(timeout_rsp, send_nothing, 1);
}

static void test_send_connect_stream(void)
{
	guint8 connect_data[] = { 0x10, 0x00, 0x10, 0x00 };
	GError *gerr = NULL;
	GIOChannel *io;
	GIOCondition cond;
	GObexPacket *req;
	guint io_id, timer_id;
	GObex *obex;

	create_endpoints(&obex, &io, SOCK_STREAM);

	req = g_obex_packet_new(G_OBEX_OP_CONNECT, TRUE);
	g_assert(req != NULL);

	g_obex_packet_set_data(req, connect_data, sizeof(connect_data),
							G_OBEX_DATA_REF);
	g_obex_send(obex, req, &gerr);
	g_assert_no_error(gerr);

	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	io_id = g_io_add_watch(io, cond, handle_connect_data, &gerr);

	mainloop = g_main_loop_new(NULL, FALSE);

	timer_id = g_timeout_add_seconds(1, test_timeout, &gerr);

	g_main_loop_run(mainloop);

	g_main_loop_unref(mainloop);
	mainloop = NULL;

	g_source_remove(timer_id);
	g_io_channel_unref(io);
	g_source_remove(io_id);
	g_obex_unref(obex);

	g_assert_no_error(gerr);
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
	guint timer_id;
	GObex *obex;
	GIOChannel *io;
	GIOStatus status;
	gsize bytes_written;

	create_endpoints(&obex, &io, SOCK_STREAM);

	g_obex_set_request_function(obex, handle_connect_request, &gerr);

	status = g_io_channel_write_chars(io, (gchar *) pkt_connect_req,
						sizeof(pkt_connect_req),
						&bytes_written, NULL);
	g_assert_cmpint(status, ==, G_IO_STATUS_NORMAL);
	g_assert_cmpuint(bytes_written, ==, sizeof(pkt_connect_req));

	mainloop = g_main_loop_new(NULL, FALSE);

	timer_id = g_timeout_add_seconds(1, test_timeout, &gerr);

	g_main_loop_run(mainloop);

	g_source_remove(timer_id);
	g_obex_unref(obex);
	g_io_channel_unref(io);

	g_main_loop_unref(mainloop);
	mainloop = NULL;

	g_assert_no_error(gerr);
}

static void disconnected(GObex *obex, gpointer user_data)
{
	g_main_loop_quit(mainloop);
}

static void test_disconnect(void)
{
	GError *gerr = NULL;
	guint timer_id;
	GObex *obex;
	GIOChannel *io;

	create_endpoints(&obex, &io, SOCK_STREAM);

	g_obex_set_disconnect_function(obex, disconnected, NULL);

	timer_id = g_timeout_add_seconds(1, test_timeout, &gerr);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_io_channel_shutdown(io, FALSE, NULL);

	g_main_loop_run(mainloop);

	g_assert_no_error(gerr);

	g_source_remove(timer_id);
	g_io_channel_unref(io);
	g_obex_unref(obex);

	g_main_loop_unref(mainloop);
	mainloop = NULL;
}

static void test_ref_unref(void)
{
	GObex *obex;

	obex = create_gobex(STDIN_FILENO, G_OBEX_TRANSPORT_STREAM, FALSE);

	g_assert(obex != NULL);

	obex = g_obex_ref(obex);

	g_obex_unref(obex);
	g_obex_unref(obex);
}

static void test_basic(void)
{
	GObex *obex;

	obex = create_gobex(STDIN_FILENO, G_OBEX_TRANSPORT_STREAM, FALSE);

	g_assert(obex != NULL);

	g_obex_unref(obex);
}

static void test_null_io(void)
{
	GObex *obex;

	obex = g_obex_new(NULL, 0);

	g_assert(obex == NULL);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/gobex/null_io", test_null_io);
	g_test_add_func("/gobex/basic", test_basic);
	g_test_add_func("/gobex/ref_unref", test_ref_unref);

	g_test_add_func("/gobex/test_disconnect", test_disconnect);

	g_test_add_func("/gobex/test_recv_connect_stream",
						test_recv_connect_stream);
	g_test_add_func("/gobex/test_send_connect_stream",
						test_send_connect_stream);
	g_test_add_func("/gobex/test_send_connect_req_stream",
					test_send_connect_req_stream);
	g_test_add_func("/gobex/test_send_nval_connect_req_stream",
					test_send_nval_connect_req_stream);
	g_test_add_func("/gobex/test_send_connect_req_timeout_stream",
					test_send_connect_req_timeout_stream);

	g_test_run();

	return 0;
}
