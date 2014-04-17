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

#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <glib.h>
#include "src/shared/hfp.h"

struct context {
	GMainLoop *main_loop;
	guint watch_id;
	int fd_server;
	int fd_client;
	struct hfp_gw *hfp;
	const struct test_data *data;
	unsigned int pdu_offset;
};

struct test_pdu {
	bool valid;
	const uint8_t *data;
	size_t size;
	enum hfp_gw_cmd_type type;
	bool fragmented;
};

struct test_data {
	char *test_name;
	struct test_pdu *pdu_list;
	hfp_result_func_t result_func;
};

#define data(args...) ((const unsigned char[]) { args })

#define raw_pdu(args...)					\
	{							\
		.valid = true,					\
		.data = data(args),				\
		.size = sizeof(data(args)),			\
	}

#define data_end()						\
	{							\
		.valid = false,					\
	}

#define type_pdu(cmd_type, args...)				\
	{							\
		.valid = true,					\
		.data = data(args),				\
		.size = sizeof(data(args)),			\
		.type = cmd_type,				\
	}

#define frg_pdu(args...)					\
	{							\
		.valid = true,					\
		.data = data(args),				\
		.size = sizeof(data(args)),			\
		.fragmented = true,				\
	}

#define define_test(name, function, result_function, args...)		\
	do {								\
		const struct test_pdu pdus[] = {			\
			args, { }					\
		};							\
		static struct test_data data;				\
		data.test_name = g_strdup(name);			\
		data.pdu_list = g_malloc(sizeof(pdus));			\
		data.result_func = result_function;			\
		memcpy(data.pdu_list, pdus, sizeof(pdus));		\
		g_test_add_data_func(name, &data, function);		\
	} while (0)

static void context_quit(struct context *context)
{
	g_main_loop_quit(context->main_loop);
}

static void test_free(gconstpointer user_data)
{
	const struct test_data *data = user_data;

	g_free(data->test_name);
	g_free(data->pdu_list);
}

static gboolean test_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct context *context = user_data;
	const struct test_pdu *pdu;

	pdu = &context->data->pdu_list[context->pdu_offset++];

	g_assert(!pdu->valid);
	context_quit(context);

	context->watch_id = 0;

	return FALSE;
}

static void cmd_handler(const char *command, void *user_data)
{
	struct context *context = user_data;
	const struct test_pdu *pdu;
	unsigned int cmd_len = strlen(command);

	pdu = &context->data->pdu_list[context->pdu_offset++];

	g_assert(cmd_len == pdu->size);
	g_assert(!memcmp(command, pdu->data, cmd_len));

	hfp_gw_send_result(context->hfp, HFP_RESULT_ERROR);
}

static void prefix_handler(struct hfp_gw_result *result,
				enum hfp_gw_cmd_type type, void *user_data)
{
	struct context *context = user_data;
	const struct test_pdu *pdu;

	pdu = &context->data->pdu_list[context->pdu_offset++];

	g_assert(type == pdu->type);

	hfp_gw_send_result(context->hfp, HFP_RESULT_ERROR);
}

static struct context *create_context(gconstpointer data)
{
	struct context *context = g_new0(struct context, 1);
	GIOChannel *channel;
	int err, sv[2];

	context->main_loop = g_main_loop_new(NULL, FALSE);
	g_assert(context->main_loop);

	err = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
	g_assert(err == 0);

	channel = g_io_channel_unix_new(sv[1]);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	context->watch_id = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				test_handler, context);
	g_assert(context->watch_id > 0);

	g_io_channel_unref(channel);

	context->fd_server = sv[1];
	context->fd_client = sv[0];
	context->data = data;

	return context;
}

static void execute_context(struct context *context)
{
	g_main_loop_run(context->main_loop);

	if (context->watch_id)
		g_source_remove(context->watch_id);

	g_main_loop_unref(context->main_loop);

	test_free(context->data);

	if (context->hfp)
		hfp_gw_unref(context->hfp);

	g_free(context);
}

static void test_init(gconstpointer data)
{
	struct context *context = create_context(data);

	context->hfp = hfp_gw_new(context->fd_client);

	g_assert(context->hfp);
	g_assert(hfp_gw_set_close_on_unref(context->hfp, true));

	hfp_gw_unref(context->hfp);
	context->hfp = NULL;

	execute_context(context);
}

static void test_command_handler(gconstpointer data)
{
	struct context *context = create_context(data);
	const struct test_pdu *pdu;
	ssize_t len;
	bool ret;

	context->hfp = hfp_gw_new(context->fd_client);
	g_assert(context->hfp);

	pdu = &context->data->pdu_list[context->pdu_offset++];

	ret = hfp_gw_set_close_on_unref(context->hfp, true);
	g_assert(ret);

	ret = hfp_gw_set_command_handler(context->hfp, cmd_handler,
								context, NULL);
	g_assert(ret);

	len = write(context->fd_server, pdu->data, pdu->size);
	g_assert_cmpint(len, ==, pdu->size);

	execute_context(context);
}

static void test_register(gconstpointer data)
{
	struct context *context = create_context(data);
	const struct test_pdu *pdu;
	ssize_t len;
	bool ret;

	context->hfp = hfp_gw_new(context->fd_client);
	g_assert(context->hfp);

	pdu = &context->data->pdu_list[context->pdu_offset++];

	ret = hfp_gw_set_close_on_unref(context->hfp, true);
	g_assert(ret);

	if (context->data->result_func) {
		ret = hfp_gw_register(context->hfp, context->data->result_func,
					(char *)pdu->data, context, NULL);
		g_assert(ret);
	}

	pdu = &context->data->pdu_list[context->pdu_offset++];

	len = write(context->fd_server, pdu->data, pdu->size);
	g_assert_cmpint(len, ==, pdu->size);

	execute_context(context);
}

static gboolean send_pdu(gpointer user_data)
{
	struct context *context = user_data;
	const struct test_pdu *pdu;
	ssize_t len;

	pdu = &context->data->pdu_list[context->pdu_offset++];

	len = write(context->fd_server, pdu->data, pdu->size);
	g_assert_cmpint(len, ==, pdu->size);

	pdu = &context->data->pdu_list[context->pdu_offset];
	if (pdu->fragmented)
		g_idle_add(send_pdu, context);

	return FALSE;
}

static void test_fragmented(gconstpointer data)
{
	struct context *context = create_context(data);
	bool ret;

	context->hfp = hfp_gw_new(context->fd_client);
	g_assert(context->hfp);

	ret = hfp_gw_set_close_on_unref(context->hfp, true);
	g_assert(ret);

	g_idle_add(send_pdu, context);

	execute_context(context);
}

static void check_ustring_1(struct hfp_gw_result *result,
				enum hfp_gw_cmd_type type, void *user_data)
{
	struct context *context = user_data;
	const struct test_pdu *pdu;
	unsigned int i = 3, j = 0;
	char str[10];

	pdu = &context->data->pdu_list[context->pdu_offset++];

	g_assert(type == pdu->type);

	g_assert(hfp_gw_result_get_unquoted_string(result, str, sizeof(str)));

	while (context->data->pdu_list[1].data[i] != '\r') {
		g_assert(j < sizeof(str));
		g_assert(str[j] == context->data->pdu_list[1].data[i]);

		i++;
		j++;
	}

	g_assert(str[j] == '\0');

	hfp_gw_send_result(context->hfp, HFP_RESULT_ERROR);
}

static void check_ustring_2(struct hfp_gw_result *result,
				enum hfp_gw_cmd_type type, void *user_data)
{
	struct context *context = user_data;
	const struct test_pdu *pdu;
	char str[10];

	memset(str, 'X', sizeof(str));

	pdu = &context->data->pdu_list[context->pdu_offset++];

	g_assert(type == pdu->type);

	g_assert(!hfp_gw_result_get_unquoted_string(result, str, 3));

	g_assert(str[3] == 'X');

	hfp_gw_send_result(context->hfp, HFP_RESULT_ERROR);
}

static void check_string_1(struct hfp_gw_result *result,
				enum hfp_gw_cmd_type type, void *user_data)
{
	struct context *context = user_data;
	const struct test_pdu *pdu;
	unsigned int i = 4, j = 0;
	char str[10];

	pdu = &context->data->pdu_list[context->pdu_offset++];

	g_assert(type == pdu->type);

	g_assert(hfp_gw_result_get_string(result, str, sizeof(str)));

	while (context->data->pdu_list[1].data[i] != '\"') {
		g_assert(j < sizeof(str));
		g_assert(str[j] == context->data->pdu_list[1].data[i]);

		i++;
		j++;
	}

	g_assert(context->data->pdu_list[1].data[i] == '\"');
	g_assert(str[j] == '\0');

	hfp_gw_send_result(context->hfp, HFP_RESULT_ERROR);
}

static void check_string_2(struct hfp_gw_result *result,
				enum hfp_gw_cmd_type type, void *user_data)
{
	struct context *context = user_data;
	const struct test_pdu *pdu;
	char str[10];

	memset(str, 'X', sizeof(str));

	pdu = &context->data->pdu_list[context->pdu_offset++];

	g_assert(type == pdu->type);

	g_assert(!hfp_gw_result_get_string(result, str, 3));

	g_assert(str[3] == 'X');

	hfp_gw_send_result(context->hfp, HFP_RESULT_ERROR);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	define_test("/hfp/test_init", test_init, NULL, data_end());
	define_test("/hfp/test_cmd_handler_1", test_command_handler, NULL,
			raw_pdu('A', 'T', '+', 'B', 'R', 'S', 'F', '\r'),
			raw_pdu('A', 'T', '+', 'B', 'R', 'S', 'F'),
			data_end());
	define_test("/hfp/test_cmd_handler_2", test_command_handler, NULL,
			raw_pdu('A', 'T', 'D', '1', '2', '3', '4', '\r'),
			raw_pdu('A', 'T', 'D', '1', '2', '3', '4'),
			data_end());
	define_test("/hfp/test_register_1", test_register, prefix_handler,
			raw_pdu('+', 'B', 'R', 'S', 'F', '\0'),
			raw_pdu('A', 'T', '+', 'B', 'R', 'S', 'F', '\r'),
			type_pdu(HFP_GW_CMD_TYPE_COMMAND, 0),
			data_end());
	define_test("/hfp/test_register_2", test_register, prefix_handler,
			raw_pdu('+', 'B', 'R', 'S', 'F', '\0'),
			raw_pdu('A', 'T', '+', 'B', 'R', 'S', 'F', '=', '\r'),
			type_pdu(HFP_GW_CMD_TYPE_SET, 0),
			data_end());
	define_test("/hfp/test_register_3", test_register, prefix_handler,
			raw_pdu('+', 'B', 'R', 'S', 'F', '\0'),
			raw_pdu('A', 'T', '+', 'B', 'R', 'S', 'F', '?', '\r'),
			type_pdu(HFP_GW_CMD_TYPE_READ, 0),
			data_end());
	define_test("/hfp/test_register_4", test_register, prefix_handler,
			raw_pdu('+', 'B', 'R', 'S', 'F', '\0'),
			raw_pdu('A', 'T', '+', 'B', 'R', 'S', 'F', '=', '?',
									'\r'),
			type_pdu(HFP_GW_CMD_TYPE_TEST, 0),
			data_end());
	define_test("/hfp/test_register_5", test_register, prefix_handler,
			raw_pdu('D', '\0'),
			raw_pdu('A', 'T', 'D', '1', '2', '3', '4', '5', '\r'),
			type_pdu(HFP_GW_CMD_TYPE_SET, 0),
			data_end());
	define_test("/hfp/test_fragmented_1", test_fragmented, NULL,
			frg_pdu('A'), frg_pdu('T'), frg_pdu('+'), frg_pdu('B'),
			frg_pdu('R'), frg_pdu('S'), frg_pdu('F'), frg_pdu('\r'),
			data_end());
	define_test("/hfp/test_ustring_1", test_register, check_ustring_1,
			raw_pdu('D', '\0'),
			raw_pdu('A', 'T', 'D', '0', '1', '2', '3', '\r'),
			type_pdu(HFP_GW_CMD_TYPE_SET, 0),
			data_end());
	define_test("/hfp/test_ustring_2", test_register, check_ustring_2,
			raw_pdu('D', '\0'),
			raw_pdu('A', 'T', 'D', '0', '1', '2', '3', '\r'),
			type_pdu(HFP_GW_CMD_TYPE_SET, 0),
			data_end());
	define_test("/hfp/test_string_1", test_register, check_string_1,
			raw_pdu('D', '\0'),
			raw_pdu('A', 'T', 'D', '\"', '0', '1', '2', '3', '\"',
									'\r'),
			type_pdu(HFP_GW_CMD_TYPE_SET, 0),
			data_end());
	define_test("/hfp/test_string_2", test_register, check_string_2,
			raw_pdu('D', '\0'),
			raw_pdu('A', 'T', 'D', '\"', '0', '1', '2', '3', '\"',
									'\r'),
			type_pdu(HFP_GW_CMD_TYPE_SET, 0),
			data_end());

	return g_test_run();
}
