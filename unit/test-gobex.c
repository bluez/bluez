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
static uint8_t pkt_abort_rsp[] = { 0x90, 0x00, 0x03 };
static uint8_t pkt_nval_short_rsp[] = { 0x10 | FINAL_BIT, 0x12 };

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

	if (io == NULL) {
		close(sv[1]);
		return;
	}

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

static gboolean send_nval_short_rsp(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	GError **err = user_data;

	if (!recv_and_send(io, pkt_nval_short_rsp,
					sizeof(pkt_nval_short_rsp), err))
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
					gint req_timeout, int transport_type)
{
	guint8 connect_data[] = { 0x10, 0x00, 0x10, 0x00 };
	GError *gerr = NULL;
	GIOChannel *io;
	GIOCondition cond;
	GObexPacket *req;
	guint io_id, timer_id, test_time;
	GObex *obex;

	create_endpoints(&obex, &io, transport_type);

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
	send_connect(connect_rsp, send_connect_rsp, -1, SOCK_STREAM);
}

static void test_send_connect_req_pkt(void)
{
	send_connect(connect_rsp, send_connect_rsp, -1, SOCK_SEQPACKET);
}

static void test_send_nval_connect_req_stream(void)
{
	send_connect(nval_connect_rsp, send_nval_connect_rsp, -1, SOCK_STREAM);
}

static void test_send_nval_connect_req_pkt(void)
{
	send_connect(nval_connect_rsp, send_nval_connect_rsp, -1,
							SOCK_SEQPACKET);
}

static void test_send_nval_connect_req_short_pkt(void)
{
	send_connect(nval_connect_rsp, send_nval_short_rsp, -1,
							SOCK_SEQPACKET);
}

static void test_send_connect_req_timeout_stream(void)
{
	send_connect(timeout_rsp, send_nothing, 1, SOCK_STREAM);
}

static void test_send_connect_req_timeout_pkt(void)
{
	send_connect(timeout_rsp, send_nothing, 1, SOCK_SEQPACKET);
}

struct req_info {
	GObex *obex;
	guint id;
	GError *err;
};

static void req_done(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	struct req_info *r = user_data;

	if (!g_error_matches(err, G_OBEX_ERROR, G_OBEX_ERROR_CANCELLED))
		g_set_error(&r->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Did not get expected cancelled error");

	g_main_loop_quit(mainloop);
}

static void test_cancel_req_immediate(void)
{
	GObexPacket *req;
	struct req_info r;
	gboolean ret;

	create_endpoints(&r.obex, NULL, SOCK_STREAM);

	r.err = NULL;

	req = g_obex_packet_new(G_OBEX_OP_PUT, TRUE);
	r.id = g_obex_send_req(r.obex, req, -1, req_done, &r, &r.err);
	g_assert_no_error(r.err);
	g_assert(r.id != 0);

	ret = g_obex_cancel_req(r.obex, r.id, FALSE);
	g_assert(ret == TRUE);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(mainloop);

	g_assert_no_error(r.err);

	g_obex_unref(r.obex);
	g_main_loop_unref(mainloop);
}

static gboolean cancel_server(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct req_info *r = user_data;
	GIOStatus status;
	gsize bytes_written, rbytes;
	char buf[255];

	status = g_io_channel_read_chars(io, buf, sizeof(buf), &rbytes, NULL);
	if (status != G_IO_STATUS_NORMAL) {
		g_set_error(&r->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Reading data failed with status %d", status);
		goto failed;
	}

	if (rbytes < 3) {
		g_set_error(&r->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"Not enough data from socket");
		goto failed;
	}

	if ((uint8_t) buf[0] == (G_OBEX_OP_PUT | FINAL_BIT)) {
		if (!g_obex_cancel_req(r->obex, r->id, FALSE)) {
			g_set_error(&r->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
					"Cancelling request failed");
			goto failed;
		}
		return TRUE;
	}

	if ((uint8_t) buf[0] != (G_OBEX_OP_ABORT | FINAL_BIT)) {
		g_set_error(&r->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Neither Put nor Abort packet received");
		goto failed;
	}

	g_io_channel_write_chars(io, (gchar *) pkt_abort_rsp,
				sizeof(pkt_abort_rsp), &bytes_written, NULL);
	if (bytes_written != sizeof(pkt_abort_rsp)) {
		g_set_error(&r->err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
						"Unable to write to socket");
		goto failed;
	}

	return TRUE;

failed:
	g_main_loop_quit(mainloop);
	return FALSE;
}

static void test_cancel_req_delay(int transport_type)
{
	GIOChannel *io;
	guint io_id, timer_id;
	struct req_info r;
	GObexPacket *req;
	GIOCondition cond;

	create_endpoints(&r.obex, &io, transport_type);

	r.err = NULL;

	req = g_obex_packet_new(G_OBEX_OP_PUT, TRUE);
	r.id = g_obex_send_req(r.obex, req, -1, req_done, &r, &r.err);
	g_assert_no_error(r.err);
	g_assert(r.id != 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	io_id = g_io_add_watch(io, cond, cancel_server, &r);

	timer_id = g_timeout_add_seconds(2, test_timeout, &r.err);

	g_main_loop_run(mainloop);

	g_assert_no_error(r.err);

	g_source_remove(timer_id);
	g_io_channel_unref(io);
	g_source_remove(io_id);
	g_obex_unref(r.obex);
	g_main_loop_unref(mainloop);
}

static void test_cancel_req_delay_stream(void)
{
	test_cancel_req_delay(SOCK_STREAM);
}

static void test_cancel_req_delay_pkt(void)
{
	test_cancel_req_delay(SOCK_SEQPACKET);
}

static void test_send_connect(int transport_type)
{
	guint8 connect_data[] = { 0x10, 0x00, 0x10, 0x00 };
	GError *gerr = NULL;
	GIOChannel *io;
	GIOCondition cond;
	GObexPacket *req;
	guint io_id, timer_id;
	GObex *obex;

	create_endpoints(&obex, &io, transport_type);

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

static void test_send_connect_stream(void)
{
	test_send_connect(SOCK_STREAM);
}

static void test_send_connect_pkt(void)
{
	test_send_connect(SOCK_SEQPACKET);
}

static void handle_connect_event(GObex *obex, GError *err, GObexPacket *pkt,
							gpointer user_data)
{
	GError **test_err = user_data;

	g_main_loop_quit(mainloop);

	if (err != NULL) {
		*test_err = g_error_copy(err);
		return;
	}

	if (g_obex_packet_get_operation(pkt, NULL) != G_OBEX_OP_CONNECT)
		g_set_error(test_err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
						"Unexpected operation");
}

static void recv_connect(int transport_type)
{
	GError *gerr = NULL;
	guint timer_id;
	GObex *obex;
	GIOChannel *io;
	GIOStatus status;
	gsize bytes_written;

	create_endpoints(&obex, &io, transport_type);

	g_obex_set_event_function(obex, handle_connect_event, &gerr);

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

static void test_recv_connect_stream(void)
{
	recv_connect(SOCK_STREAM);
}

static void test_recv_connect_pkt(void)
{
	recv_connect(SOCK_SEQPACKET);
}

static void disconn_ev(GObex *obex, GError *err, GObexPacket *req,
							gpointer user_data)
{
	GError **test_err = user_data;

	if (!g_error_matches(err, G_OBEX_ERROR, G_OBEX_ERROR_DISCONNECTED))
		g_set_error(test_err, TEST_ERROR, TEST_ERROR_UNEXPECTED,
				"Did not get expected disconnect error");

	g_main_loop_quit(mainloop);
}

static void test_disconnect(void)
{
	GError *gerr = NULL;
	guint timer_id;
	GObex *obex;
	GIOChannel *io;

	create_endpoints(&obex, &io, SOCK_STREAM);

	g_obex_set_event_function(obex, disconn_ev, &gerr);

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
	g_test_add_func("/gobex/test_recv_connect_pkt",
						test_recv_connect_pkt);
	g_test_add_func("/gobex/test_send_connect_stream",
						test_send_connect_stream);
	g_test_add_func("/gobex/test_send_connect_pkt",
						test_send_connect_pkt);
	g_test_add_func("/gobex/test_send_connect_req_stream",
					test_send_connect_req_stream);
	g_test_add_func("/gobex/test_send_connect_req_pkt",
					test_send_connect_req_pkt);
	g_test_add_func("/gobex/test_send_nval_connect_req_stream",
					test_send_nval_connect_req_stream);
	g_test_add_func("/gobex/test_send_nval_connect_req_pkt",
					test_send_nval_connect_req_pkt);
	g_test_add_func("/gobex/test_send_nval_connect_req_short_pkt",
					test_send_nval_connect_req_short_pkt);
	g_test_add_func("/gobex/test_send_connect_req_timeout_stream",
					test_send_connect_req_timeout_stream);
	g_test_add_func("/gobex/test_send_connect_req_timeout_pkt",
					test_send_connect_req_timeout_pkt);

	g_test_add_func("/gobex/test_cancel_req_immediate",
					test_cancel_req_immediate);
	g_test_add_func("/gobex/test_cancel_req_delay_stream",
					test_cancel_req_delay_stream);
	g_test_add_func("/gobex/test_cancel_req_delay_pkt",
					test_cancel_req_delay_pkt);

	g_test_run();

	return 0;
}
