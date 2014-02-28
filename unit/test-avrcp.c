/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <glib.h>

#include "src/shared/util.h"
#include "src/log.h"
#include "lib/bluetooth.h"

#include "android/avctp.h"
#include "android/avrcp-lib.h"

struct test_pdu {
	bool valid;
	bool fragmented;
	const uint8_t *data;
	size_t size;
};

struct test_data {
	char *test_name;
	struct test_pdu *pdu_list;
};

struct context {
	GMainLoop *main_loop;
	struct avrcp *session;
	guint source;
	guint process;
	int fd;
	unsigned int pdu_offset;
	const struct test_data *data;
};

#define data(args...) ((const unsigned char[]) { args })

#define raw_pdu(args...)					\
	{							\
		.valid = true,					\
		.data = data(args),				\
		.size = sizeof(data(args)),			\
	}

#define frg_pdu(args...)					\
	{							\
		.valid = true,					\
		.fragmented = true,				\
		.data = data(args),				\
		.size = sizeof(data(args)),			\
	}

#define define_test(name, function, args...)				\
	do {								\
		const struct test_pdu pdus[] = {			\
			args, { }					\
		};							\
		static struct test_data data;				\
		data.test_name = g_strdup(name);			\
		data.pdu_list = g_malloc(sizeof(pdus));			\
		memcpy(data.pdu_list, pdus, sizeof(pdus));		\
		g_test_add_data_func(name, &data, function);		\
	} while (0)

#if __BYTE_ORDER == __LITTLE_ENDIAN

static inline void hton24(uint8_t dst[3], uint32_t src)
{
	dst[0] = (src >> 16) & 0xff;
	dst[1] = (src >> 8) & 0xff;
	dst[2] = src & 0xff;
}

#elif __BYTE_ORDER == __BIG_ENDIAN

static inline void hton24(uint8_t dst[3], uint32_t src)
{
	memcpy(&dst, src, sizeof(dst));
}

#else
#error "Unknown byte order"
#endif

static void test_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	g_print("%s%s\n", prefix, str);
}

static void test_free(gconstpointer user_data)
{
	const struct test_data *data = user_data;

	g_free(data->test_name);
	g_free(data->pdu_list);
}

static gboolean context_quit(gpointer user_data)
{
	struct context *context = user_data;

	if (context->process > 0)
		g_source_remove(context->process);

	g_main_loop_quit(context->main_loop);

	return FALSE;
}

static gboolean send_pdu(gpointer user_data)
{
	struct context *context = user_data;
	const struct test_pdu *pdu;
	ssize_t len;

	pdu = &context->data->pdu_list[context->pdu_offset++];

	len = write(context->fd, pdu->data, pdu->size);

	if (g_test_verbose())
		util_hexdump('<', pdu->data, len, test_debug, "AVRCP: ");

	g_assert_cmpint(len, ==, pdu->size);

	if (pdu->fragmented)
		return send_pdu(user_data);

	context->process = 0;
	return FALSE;
}

static void context_process(struct context *context)
{
	if (!context->data->pdu_list[context->pdu_offset].valid) {
		context_quit(context);
		return;
	}

	context->process = g_idle_add(send_pdu, context);
}

static gboolean test_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct context *context = user_data;
	const struct test_pdu *pdu;
	unsigned char buf[512];
	ssize_t len;
	int fd;

	pdu = &context->data->pdu_list[context->pdu_offset++];

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		context->source = 0;
		g_print("%s: cond %x\n", __func__, cond);
		return FALSE;
	}

	fd = g_io_channel_unix_get_fd(channel);

	len = read(fd, buf, sizeof(buf));

	g_assert(len > 0);

	if (g_test_verbose())
		util_hexdump('>', buf, len, test_debug, "AVRCP: ");

	g_assert_cmpint(len, ==, pdu->size);

	g_assert(memcmp(buf, pdu->data, pdu->size) == 0);

	if (!pdu->fragmented)
		context_process(context);

	return TRUE;
}

static struct context *create_context(uint16_t version, gconstpointer data)
{
	struct context *context = g_new0(struct context, 1);
	GIOChannel *channel;
	int err, sv[2];

	context->main_loop = g_main_loop_new(NULL, FALSE);
	g_assert(context->main_loop);

	err = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
	g_assert(err == 0);

	context->session = avrcp_new(sv[0], 672, 672, version);
	g_assert(context->session != NULL);

	channel = g_io_channel_unix_new(sv[1]);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	context->source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				test_handler, context);
	g_assert(context->source > 0);

	g_io_channel_unref(channel);

	context->fd = sv[1];
	context->data = data;

	return context;
}

static void destroy_context(struct context *context)
{
	if (context->source > 0)
		g_source_remove(context->source);

	avrcp_shutdown(context->session);

	g_main_loop_unref(context->main_loop);

	test_free(context->data);
	g_free(context);
}

static void test_dummy(gconstpointer data)
{
	struct context *context =  create_context(0x0100, data);

	destroy_context(context);
}

static void execute_context(struct context *context)
{
	g_main_loop_run(context->main_loop);

	destroy_context(context);
}

static bool handle_play(struct avrcp *session)
{
	DBG("");

	return true;
}

static bool handle_volume_up(struct avrcp *session)
{
	DBG("");

	return true;
}

static bool handle_channel_up(struct avrcp *session)
{
	DBG("");

	return true;
}

static bool handle_select(struct avrcp *session)
{
	DBG("");

	return true;
}

static const struct avrcp_passthrough_handler passthrough_handlers[] = {
		{ AVC_PLAY, handle_play },
		{ AVC_VOLUME_UP, handle_volume_up },
		{ AVC_CHANNEL_UP, handle_channel_up },
		{ AVC_SELECT, handle_select },
		{ },
};

static uint8_t avrcp_handle_get_capabilities(struct avrcp *session,
				uint8_t transaction, uint16_t *params_len,
				uint8_t *params, void *user_data)
{
	uint32_t id = 0x001958;

	DBG("params[0] %d params_len %d", params[0], *params_len);

	if (*params_len != 1)
		goto fail;

	switch (params[0]) {
	case CAP_COMPANY_ID:
		*params_len = 5;
		params[1] = 1;
		hton24(&params[2], id);
		return AVC_CTYPE_STABLE;
	}

fail:
	*params_len = 1;
	params[0] = AVRCP_STATUS_INVALID_PARAM;

	return AVC_CTYPE_REJECTED;
}

static const struct avrcp_control_handler control_handlers[] = {
		{ AVRCP_GET_CAPABILITIES, AVC_CTYPE_STATUS,
					avrcp_handle_get_capabilities },
		{ },
};

static void test_server(gconstpointer data)
{
	struct context *context = create_context(0x0100, data);

	avrcp_set_passthrough_handlers(context->session, passthrough_handlers,
								context);
	avrcp_set_control_handlers(context->session, control_handlers, NULL);

	g_idle_add(send_pdu, context);

	execute_context(context);
}

static void test_client(gconstpointer data)
{
	struct context *context = create_context(0x0100, data);

	if (g_str_equal(context->data->test_name, "/TP/CFG/BV-01-C"))
		avrcp_get_capabilities(context->session, CAP_EVENTS_SUPPORTED,
								NULL, NULL);

	if (g_str_equal(context->data->test_name, "/TP/PAS/BV-01-C"))
		avrcp_list_player_attributes(context->session, NULL, NULL);

	execute_context(context);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	if (g_test_verbose())
		__btd_log_init("*", 0);

	/* Connection Establishment for Control tests */

	/*
	 * Tests are checking connection establishement and release
	 * for control channel. Since we are connected through socketpair
	 * the tests are dummy
	 */
	define_test("/TP/CEC/BV-01-I", test_dummy, raw_pdu(0x00));
	define_test("/TP/CEC/BV-02-I", test_dummy, raw_pdu(0x00));
	define_test("/TP/CRC/BV-01-I", test_dummy, raw_pdu(0x00));
	define_test("/TP/CRC/BV-02-I", test_dummy, raw_pdu(0x00));

	/* Information collection for control tests */

	define_test("/TP/ICC/BV-01-I", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0xf8, 0x30,
				0xff, 0xff, 0xff, 0xff, 0xff),
			raw_pdu(0x02, 0x11, 0x0e, 0x0c, 0xf8, 0x30,
				0x07, 0x48, 0xff, 0xff, 0xff));

	define_test("/TP/ICC/BV-02-I", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0xf8, 0x31,
				0x07, 0xff, 0xff, 0xff, 0xff),
			raw_pdu(0x02, 0x11, 0x0e, 0x0c, 0xf8, 0x31,
				0x07, 0x48, 0xff, 0xff, 0xff));

	define_test("/TP/PTT/BV-01-I", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48, 0x7c,
				0x44, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, 0x09, 0x48, 0x7c,
				0x44, 0x00));

	define_test("/TP/PTT/BV-02-I", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48, 0x7c,
				AVC_VOLUME_UP, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, 0x09, 0x48, 0x7c,
				AVC_VOLUME_UP, 0x00));

	define_test("/TP/PTT/BV-03-I", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48, 0x7c,
				AVC_CHANNEL_UP, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, 0x09, 0x48, 0x7c,
				AVC_CHANNEL_UP, 0x00));

	define_test("/TP/PTT/BV-04-I", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48, 0x7c,
				AVC_SELECT, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, 0x09, 0x48, 0x7c,
				AVC_SELECT, 0x00));

	define_test("/TP/PTT/BV-05-I", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48, 0x7c,
				AVC_PLAY, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, 0x09, 0x48, 0x7c,
				AVC_PLAY, 0x00),
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48, 0x7c,
				AVC_PLAY | 0x80, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, 0x09, 0x48, 0x7c,
				AVC_PLAY | 0x80, 0x00));

	/* Metadata transfer tests */

	define_test("/TP/CFG/BV-01-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58, 0x10, 0x00, 0x00,
				0x01, 0x03));

	define_test("/TP/CFG/BV-02-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58, 0x10, 0x00, 0x00,
				0x01, 0x02),
			raw_pdu(0x02, 0x11, 0x0e, 0x0c, 0x48, 0x00,
				0x00, 0x19, 0x58, 0x10, 0x00, 0x00,
				0x05, 0x02, 0x01, 0x00, 0x19, 0x58));

	define_test("/TP/CFG/BI-01-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58, 0x10, 0x00, 0x00,
				0x01, 0x7f),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_REJECTED,
				0x48, 0x00, 0x00, 0x19, 0x58, 0x10,
				0x00, 0x00, 0x01,
				AVRCP_STATUS_INVALID_PARAM));

	/* Player Application Settings tests */

	define_test("/TP/PAS/BV-01-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58, 0x11, 0x00, 0x00,
				0x00));

	return g_test_run();
}
