// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/mgmt.h"

#include "src/shared/mgmt.h"

struct context {
	GMainLoop *main_loop;
	int fd;
	struct mgmt *mgmt_client;
	guint server_source;
	GList *handler_list;
};

enum action {
	ACTION_PASSED,
	ACTION_IGNORE,
	ACTION_RESPOND,
};

struct handler {
	const void *cmd_data;
	uint16_t cmd_size;
	const void *rsp_data;
	uint16_t rsp_size;
	uint8_t rsp_status;
	bool match_prefix;
	enum action action;
};

static void mgmt_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	g_print("%s%s\n", prefix, str);
}

static void context_quit(struct context *context)
{
	g_main_loop_quit(context->main_loop);
}

static void check_actions(struct context *context, int fd,
					const void *data, uint16_t size)
{
	GList *list;

	for (list = g_list_first(context->handler_list); list;
						list = g_list_next(list)) {
		struct handler *handler = list->data;
		int ret;

		if (handler->match_prefix) {
			if (size < handler->cmd_size)
				continue;
		} else {
			if (size != handler->cmd_size)
				continue;
		}

		if (memcmp(data, handler->cmd_data, handler->cmd_size))
			continue;

		switch (handler->action) {
		case ACTION_PASSED:
			context_quit(context);
			return;
		case ACTION_RESPOND:
			ret = write(fd, handler->rsp_data, handler->rsp_size);
			g_assert(ret >= 0);
			return;
		case ACTION_IGNORE:
			return;
		}
	}

	g_test_message("Command not handled\n");
	g_assert_not_reached();
}

static gboolean server_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct context *context = user_data;
	unsigned char buf[512];
	ssize_t result;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, buf, sizeof(buf));
	if (result < 0)
		return FALSE;

	check_actions(context, fd, buf, result);

	return TRUE;
}

static struct context *create_context(void)
{
	struct context *context = g_new0(struct context, 1);
	GIOChannel *channel;
	int err, sv[2];

	context->main_loop = g_main_loop_new(NULL, FALSE);
	g_assert(context->main_loop);

	err = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
	g_assert(err == 0);

	context->fd = sv[0];
	channel = g_io_channel_unix_new(sv[0]);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	context->server_source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				server_handler, context);
	g_assert(context->server_source > 0);

	g_io_channel_unref(channel);

	context->mgmt_client = mgmt_new(sv[1]);
	g_assert(context->mgmt_client);

	if (g_test_verbose() == TRUE)
		mgmt_set_debug(context->mgmt_client,
					mgmt_debug, "mgmt: ", NULL);

	mgmt_set_close_on_unref(context->mgmt_client, true);

	return context;
}

static void execute_context(struct context *context)
{
	g_main_loop_run(context->main_loop);

	g_list_free_full(context->handler_list, g_free);

	g_source_remove(context->server_source);

	mgmt_unref(context->mgmt_client);

	g_main_loop_unref(context->main_loop);

	g_free(context);
}

static void add_action(struct context *context,
				const void *cmd_data, uint16_t cmd_size,
				const void *rsp_data, uint16_t rsp_size,
				uint8_t rsp_status, bool match_prefix,
				enum action action)
{
	struct handler *handler = g_new0(struct handler, 1);

	handler->cmd_data = cmd_data;
	handler->cmd_size = cmd_size;
	handler->rsp_data = rsp_data;
	handler->rsp_size = rsp_size;
	handler->rsp_status = rsp_status;
	handler->match_prefix = match_prefix;
	handler->action = action;

	context->handler_list = g_list_append(context->handler_list, handler);
}

struct command_test_data {
	uint16_t opcode;
	uint16_t index;
	uint16_t length;
	const void *param;
	const void *cmd_data;
	uint16_t cmd_size;
	const void *rsp_data;
	uint16_t rsp_size;
	uint8_t rsp_status;
};

static const unsigned char read_version_command[] =
				{ 0x01, 0x00, 0xff, 0xff, 0x00, 0x00 };
static const unsigned char read_version_response[] =
				{ 0x01, 0x00, 0xff, 0xff, 0x06, 0x00,
				0x01, 0x00, 0x00, 0x01, 0x06, 0x00 };

static const struct command_test_data command_test_1 = {
	.opcode = MGMT_OP_READ_VERSION,
	.index = MGMT_INDEX_NONE,
	.cmd_data = read_version_command,
	.cmd_size = sizeof(read_version_command),
	.rsp_data = read_version_response,
	.rsp_size = sizeof(read_version_response),
	.rsp_status = MGMT_STATUS_SUCCESS,
};

static const unsigned char read_info_command[] =
				{ 0x04, 0x00, 0x00, 0x02, 0x00, 0x00 };

static const struct command_test_data command_test_2 = {
	.opcode = MGMT_OP_READ_INFO,
	.index = 512,
	.cmd_data = read_info_command,
	.cmd_size = sizeof(read_info_command),
};

static const unsigned char invalid_index_response[] =
				{ 0x02, 0x00, 0xff, 0xff, 0x03, 0x00,
				0x01, 0x00, 0x11 };

static const struct command_test_data command_test_3 = {
	.opcode = MGMT_OP_READ_VERSION,
	.index = MGMT_INDEX_NONE,
	.cmd_data = read_version_command,
	.cmd_size = sizeof(read_version_command),
	.rsp_data = invalid_index_response,
	.rsp_size = sizeof(invalid_index_response),
	.rsp_status = MGMT_STATUS_INVALID_INDEX,
};

static const unsigned char event_index_added[] =
				{ 0x04, 0x00, 0x01, 0x00, 0x00, 0x00 };

static const struct command_test_data event_test_1 = {
	.opcode = MGMT_EV_INDEX_ADDED,
	.index = MGMT_INDEX_NONE,
	.cmd_data = event_index_added,
	.cmd_size = sizeof(event_index_added),
};

static void test_command(gconstpointer data)
{
	const struct command_test_data *test = data;
	struct context *context = create_context();

	add_action(context, test->cmd_data, test->cmd_size,
			test->rsp_data, test->rsp_size, test->rsp_status,
			false, ACTION_PASSED);

	mgmt_send(context->mgmt_client, test->opcode, test->index,
					test->length, test->param,
						NULL ,NULL, NULL);

	execute_context(context);
}

static void response_cb(uint8_t status, uint16_t length, const void *param,
							void *user_data)
{
	struct context *context = user_data;
	struct handler *handler = context->handler_list->data;

	g_assert_cmpint(status, ==, handler->rsp_status);

	context_quit(context);
}

static void test_response(gconstpointer data)
{
	const struct command_test_data *test = data;
	struct context *context = create_context();

	add_action(context, test->cmd_data, test->cmd_size,
			test->rsp_data, test->rsp_size, test->rsp_status,
			false, ACTION_RESPOND);

	mgmt_send(context->mgmt_client, test->opcode, test->index,
					test->length, test->param,
					response_cb, context, NULL);

	execute_context(context);
}

static void event_cb(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	struct context *context = user_data;

	if (g_test_verbose())
		printf("Event received\n");

	context_quit(context);
}

static void test_event(gconstpointer data)
{
	const struct command_test_data *test = data;
	struct context *context = create_context();

	mgmt_register(context->mgmt_client, test->opcode, test->index,
						event_cb, context, NULL);

	g_assert_cmpint(write(context->fd, test->cmd_data, test->cmd_size), ==,
								test->cmd_size);

	execute_context(context);
}

static void test_event2(gconstpointer data)
{
	const struct command_test_data *test = data;
	struct context *context = create_context();

	mgmt_register(context->mgmt_client, test->opcode, test->index,
						event_cb, context, NULL);
	mgmt_register(context->mgmt_client, test->opcode, test->index,
						event_cb, context, NULL);

	g_assert_cmpint(write(context->fd, test->cmd_data, test->cmd_size), ==,
								test->cmd_size);

	execute_context(context);
}

static void unregister_all_cb(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct context *context = user_data;

	mgmt_unregister_all(context->mgmt_client);

	context_quit(context);
}

static void test_unregister_all(gconstpointer data)
{
	const struct command_test_data *test = data;
	struct context *context = create_context();

	mgmt_register(context->mgmt_client, test->opcode, test->index,
					unregister_all_cb, context, NULL);
	mgmt_register(context->mgmt_client, test->opcode, test->index,
						event_cb, context, NULL);

	g_assert_cmpint(write(context->fd, test->cmd_data, test->cmd_size), ==,
								test->cmd_size);

	execute_context(context);
}

static void unregister_index_cb(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct context *context = user_data;

	mgmt_unregister_index(context->mgmt_client, index);

	context_quit(context);
}

static void destroy_cb(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	struct context *context = user_data;

	mgmt_unref(context->mgmt_client);
	context->mgmt_client = NULL;

	context_quit(context);
}

static void test_unregister_index(gconstpointer data)
{
	const struct command_test_data *test = data;
	struct context *context = create_context();

	mgmt_register(context->mgmt_client, test->opcode, test->index,
					unregister_index_cb, context, NULL);
	mgmt_register(context->mgmt_client, test->opcode, test->index,
						event_cb, context, NULL);

	g_assert_cmpint(write(context->fd, test->cmd_data, test->cmd_size), ==,
								test->cmd_size);

	execute_context(context);
}

static void test_destroy(gconstpointer data)
{
	const struct command_test_data *test = data;
	struct context *context = create_context();

	mgmt_register(context->mgmt_client, test->opcode, test->index,
					destroy_cb, context, NULL);
	mgmt_register(context->mgmt_client, test->opcode, test->index,
						event_cb, context, NULL);

	g_assert_cmpint(write(context->fd, test->cmd_data, test->cmd_size), ==,
								test->cmd_size);

	execute_context(context);
}

struct unregister_test;

struct unregister_entry {
	struct unregister_test *test;
	unsigned int n;
};

/*
 * An entry unregistered from a notification callback must not be notified
 * again, must not be destroyed while the notification is dispatched, and
 * must have been destroyed, once, by the next idle callback.
 */
struct unregister_test {
	struct context *context;
	unsigned int entries;
	unsigned int events;
	struct unregister_entry entry[3];
	unsigned int id[3];
	bool removed[3];
	unsigned int called[3];
	unsigned int expected[3];
	unsigned int destroyed[3];
};

static void unregister_destroy(void *user_data)
{
	struct unregister_entry *entry = user_data;

	entry->test->destroyed[entry->n]++;
	g_assert_cmpuint(entry->test->destroyed[entry->n], ==, 1);
}

static void unregister_add(struct unregister_test *test,
				const struct command_test_data *data,
				mgmt_notify_func_t callback)
{
	unsigned int n = test->entries++;

	test->entry[n].test = test;
	test->entry[n].n = n;
	test->id[n] = mgmt_register(test->context->mgmt_client, data->opcode,
					data->index, callback, &test->entry[n],
					unregister_destroy);
	g_assert_cmpuint(test->id[n], !=, 0);
}

static void unregister_check_alive(struct unregister_test *test)
{
	unsigned int i;

	for (i = 0; i < test->entries; i++)
		g_assert_cmpuint(test->destroyed[i], ==, 0);
}

static gboolean unregister_check_idle(gpointer user_data)
{
	struct unregister_test *test = user_data;
	unsigned int i;

	/* Entries unregistered while notifying are freed by now */
	for (i = 0; i < test->entries; i++)
		g_assert_cmpuint(test->destroyed[i], ==, test->removed[i]);

	context_quit(test->context);

	return FALSE;
}

static void unregister_from_cb(struct unregister_test *test, unsigned int n)
{
	struct mgmt *mgmt = test->context->mgmt_client;

	g_assert_cmpint(mgmt_unregister(mgmt, test->id[n]), ==, true);
	g_assert_cmpint(mgmt_unregister(mgmt, test->id[n]), ==, false);
	test->removed[n] = true;

	unregister_check_alive(test);
}

static void count_cb(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	struct unregister_entry *entry = user_data;

	entry->test->called[entry->n]++;
}

static void unregister_self_cb(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct unregister_entry *entry = user_data;

	if (!entry->test->called[entry->n]++)
		unregister_from_cb(entry->test, entry->n);
}

static void unregister_next_cb(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct unregister_entry *entry = user_data;

	if (!entry->test->called[entry->n]++)
		unregister_from_cb(entry->test, entry->n + 1);
}

static void unregister_all_from_cb(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct unregister_entry *entry = user_data;
	struct unregister_test *test = entry->test;
	struct mgmt *mgmt = test->context->mgmt_client;
	unsigned int i;

	test->called[entry->n]++;

	unregister_from_cb(test, 1);
	g_assert_cmpint(mgmt_unregister_all(mgmt), ==, true);

	for (i = 0; i < test->entries; i++)
		test->removed[i] = true;

	g_assert_cmpint(mgmt_unregister(mgmt, test->id[2]), ==, false);

	unregister_check_alive(test);

	/* No registered entry is left to schedule the check */
	g_idle_add(unregister_check_idle, test);
}

static void unregister_quit_cb(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct unregister_entry *entry = user_data;
	struct unregister_test *test = entry->test;

	if (++test->called[entry->n] < test->events) {
		unregister_check_alive(test);
		return;
	}

	g_idle_add(unregister_check_idle, test);
}

static void unregister_run(struct unregister_test *test,
				const struct command_test_data *data)
{
	unsigned int i;

	for (i = 0; i < test->events; i++)
		g_assert_cmpint(write(test->context->fd, data->cmd_data,
					data->cmd_size), ==, data->cmd_size);

	execute_context(test->context);

	for (i = 0; i < test->entries; i++) {
		g_assert_cmpuint(test->called[i], ==, test->expected[i]);
		g_assert_cmpuint(test->destroyed[i], ==, 1);
	}
}

static void test_unregister_self(gconstpointer data)
{
	/* Calls per entry over two events; the first unregisters itself */
	struct unregister_test test = { .context = create_context(),
					.events = 2, .expected = { 1, 2, 2 } };

	unregister_add(&test, data, unregister_self_cb);
	unregister_add(&test, data, count_cb);
	unregister_add(&test, data, unregister_quit_cb);

	unregister_run(&test, data);
}

static void test_unregister_next(gconstpointer data)
{
	/* Calls per entry over two events; the first unregisters the second */
	struct unregister_test test = { .context = create_context(),
					.events = 2, .expected = { 2, 0, 2 } };

	unregister_add(&test, data, unregister_next_cb);
	unregister_add(&test, data, count_cb);
	unregister_add(&test, data, unregister_quit_cb);

	unregister_run(&test, data);
}

static void test_unregister_id_all(gconstpointer data)
{
	/* Calls per entry; the first unregisters the second, then all */
	struct unregister_test test = { .context = create_context(),
					.events = 1, .expected = { 1, 0, 0 } };

	unregister_add(&test, data, unregister_all_from_cb);
	unregister_add(&test, data, count_cb);
	unregister_add(&test, data, count_cb);

	unregister_run(&test, data);
}

static void test_unregister_direct(gconstpointer data)
{
	/* Calls per entry; the first is unregistered before the event */
	struct unregister_test test = { .context = create_context(),
					.events = 1, .expected = { 0, 1 } };
	struct mgmt *mgmt = test.context->mgmt_client;

	unregister_add(&test, data, count_cb);
	unregister_add(&test, data, unregister_quit_cb);

	g_assert_cmpint(mgmt_unregister(mgmt, test.id[0]), ==, true);
	g_assert_cmpuint(test.destroyed[0], ==, 1);
	g_assert_cmpint(mgmt_unregister(mgmt, test.id[0]), ==, false);
	test.removed[0] = true;

	unregister_run(&test, data);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_data_func("/mgmt/command/1", &command_test_1, test_command);
	g_test_add_data_func("/mgmt/command/2", &command_test_2, test_command);

	g_test_add_data_func("/mgmt/response/1", &command_test_1,
								test_response);
	g_test_add_data_func("/mgmt/response/2", &command_test_3,
								test_response);

	g_test_add_data_func("/mgmt/event/1", &event_test_1, test_event);
	g_test_add_data_func("/mgmt/event/2", &event_test_1, test_event2);

	g_test_add_data_func("/mgmt/unregister/1", &event_test_1,
							test_unregister_all);
	g_test_add_data_func("/mgmt/unregister/2", &event_test_1,
							test_unregister_index);
	g_test_add_data_func("/mgmt/unregister/3", &event_test_1,
							test_unregister_self);
	g_test_add_data_func("/mgmt/unregister/4", &event_test_1,
							test_unregister_next);
	g_test_add_data_func("/mgmt/unregister/5", &event_test_1,
							test_unregister_id_all);
	g_test_add_data_func("/mgmt/unregister/6", &event_test_1,
							test_unregister_direct);

	g_test_add_data_func("/mgmt/destroy/1", &event_test_1, test_destroy);

	return g_test_run();
}
