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
#include <errno.h>
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
	bool browse;
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
	guint browse_source;
	guint process;
	int fd;
	int browse_fd;
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

#define brs_pdu(args...)					\
	{							\
		.valid = true,					\
		.browse = true,					\
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

	if (pdu->browse)
		len = write(context->browse_fd, pdu->data, pdu->size);
	else
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

	DBG("");

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

static gboolean browse_test_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct context *context = user_data;
	const struct test_pdu *pdu;
	unsigned char buf[512];
	ssize_t len;
	int fd;

	DBG("");

	pdu = &context->data->pdu_list[context->pdu_offset++];

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		context->browse_source = 0;
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

	DBG("");

	context->main_loop = g_main_loop_new(NULL, FALSE);
	g_assert(context->main_loop);

	/* Control channel setup */

	err = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
	g_assert(!err);

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

	/* Browsing channel setup */

	err = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
	g_assert(!err);

	err = avrcp_connect_browsing(context->session, sv[0], 672, 672);
	g_assert(!err);

	channel = g_io_channel_unix_new(sv[1]);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	context->browse_source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				browse_test_handler, context);
	g_assert(context->browse_source > 0);

	g_io_channel_unref(channel);

	context->browse_fd = sv[1];

	context->data = data;

	return context;
}

static void destroy_context(struct context *context)
{
	if (context->source > 0)
		g_source_remove(context->source);

	avrcp_shutdown(context->session);

	if (context->browse_source > 0)
		g_source_remove(context->browse_source);

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

static bool handle_play(struct avrcp *session, bool pressed, void *user_data)
{
	DBG("");

	return true;
}

static bool handle_volume_up(struct avrcp *session, bool pressed,
							void *user_data)
{
	DBG("");

	return true;
}

static bool handle_channel_up(struct avrcp *session, bool pressed,
							void *user_data)
{
	DBG("");

	return true;
}

static bool handle_select(struct avrcp *session, bool pressed, void *user_data)
{
	DBG("");

	return true;
}

static bool handle_vendor_uniq(struct avrcp *session, bool pressed,
								void *user_data)
{
	DBG("");

	return true;
}

static const struct avrcp_passthrough_handler passthrough_handlers[] = {
		{ AVC_PLAY, handle_play },
		{ AVC_VOLUME_UP, handle_volume_up },
		{ AVC_CHANNEL_UP, handle_channel_up },
		{ AVC_SELECT, handle_select },
		{ AVC_VENDOR_UNIQUE, handle_vendor_uniq },
		{ },
};

static int get_capabilities(struct avrcp *session, uint8_t transaction,
							void *user_data)
{
	return -EINVAL;
}

static int list_attributes(struct avrcp *session, uint8_t transaction,
							void *user_data)
{
	DBG("");

	avrcp_list_player_attributes_rsp(session, transaction, 0, NULL);

	return -EAGAIN;
}

static int get_attribute_text(struct avrcp *session, uint8_t transaction,
					uint8_t number, uint8_t *attrs,
					void *user_data)
{
	const char *text[number];

	DBG("");

	if (number) {
		memset(text, 0, number);
		text[0] = "equalizer";
	}

	avrcp_get_player_attribute_text_rsp(session, transaction, number, attrs,
									text);

	return -EAGAIN;
}

static int list_values(struct avrcp *session, uint8_t transaction,
						uint8_t attr, void *user_data)
{
	DBG("");

	avrcp_list_player_values_rsp(session, transaction, 0, NULL);

	return -EINVAL;
}

static int get_value_text(struct avrcp *session, uint8_t transaction,
				uint8_t attr, uint8_t number, uint8_t *values,
				void *user_data)
{
	const char *text[number];

	DBG("");

	if (number) {
		memset(text, 0, number);
		text[0] = "on";
	}

	avrcp_get_player_values_text_rsp(session, transaction, number,
								values, text);

	return -EINVAL;
}

static int get_value(struct avrcp *session, uint8_t transaction,
			uint8_t number, uint8_t *attrs, void *user_data)
{
	uint8_t values[number];

	DBG("");

	memset(values, 0, number);

	avrcp_get_current_player_value_rsp(session, transaction, number, attrs,
									values);

	return -EAGAIN;
}

static int set_value(struct avrcp *session, uint8_t transaction,
			uint8_t number, uint8_t *attrs, void *user_data)
{
	DBG("");

	avrcp_set_player_value_rsp(session, transaction);

	return -EAGAIN;
}

static int get_play_status(struct avrcp *session, uint8_t transaction,
							void *user_data)
{
	DBG("");

	avrcp_get_play_status_rsp(session, transaction, 0xaaaaaaaa, 0xbbbbbbbb,
									0x00);

	return -EAGAIN;
}

static int get_element_attributes(struct avrcp *session, uint8_t transaction,
					uint64_t uid, uint8_t number,
					uint32_t *attrs, void *user_data)
{
	DBG("");

	avrcp_get_element_attrs_rsp(session, transaction, NULL, 0);

	return -EAGAIN;
}

static int register_notification(struct avrcp *session, uint8_t transaction,
					uint8_t event, uint32_t interval,
					void *user_data)
{
	struct context *context = user_data;
	uint8_t pdu[9];
	size_t pdu_len;

	DBG("");

	pdu[0] = event;
	pdu_len = 1;

	switch (event) {
	case AVRCP_EVENT_TRACK_CHANGED:
		if (g_str_equal(context->data->test_name, "/TP/NFY/BV-05-C") ||
			g_str_equal(context->data->test_name,
							"/TP/NFY/BV-08-C"))
			memset(&pdu[1], 0, 8);
		else
			memset(&pdu[1], 0xff, 8);

		pdu_len += 8;
		break;
	case AVRCP_EVENT_SETTINGS_CHANGED:
		pdu[1] = 0x01;
		pdu[2] = 0x01;
		pdu[3] = 0x02;
		pdu_len = 4;
		break;
	default:
		return -EINVAL;
	}

	avrcp_register_notification_rsp(session, transaction, AVC_CTYPE_INTERIM,
						pdu, pdu_len);

	avrcp_register_notification_rsp(session, transaction, AVC_CTYPE_CHANGED,
						pdu, pdu_len);

	return -EAGAIN;
}

static int set_volume(struct avrcp *session, uint8_t transaction,
					uint8_t volume, void *user_data)
{
	DBG("");

	avrcp_set_volume_rsp(session, transaction, volume);

	return -EAGAIN;
}

static int set_addressed(struct avrcp *session, uint8_t transaction,
						uint16_t id, void *user_data)
{
	DBG("");


	avrcp_set_addressed_player_rsp(session, transaction,
							AVRCP_STATUS_SUCCESS);

	return -EAGAIN;
}

static int get_folder_items(struct avrcp *session, uint8_t transaction,
				uint8_t scope, uint32_t start, uint32_t end,
				uint16_t number, uint32_t *attrs,
				void *user_data)
{
	struct context *context = user_data;

	DBG("");

	if (g_str_equal(context->data->test_name, "/TP/MCN/CB/BI-02-C"))
		return -ERANGE;

	if (start > 1)
		return -ERANGE;

	avrcp_get_folder_items_rsp(session, transaction, 0xabcd, 0, NULL, NULL,
									NULL);

	return -EAGAIN;
}

static int change_path(struct avrcp *session, uint8_t transaction,
					uint16_t counter, uint8_t direction,
					uint64_t uid, void *user_data)
{
	DBG("");

	if (!uid)
		return -ENOTDIR;

	avrcp_change_path_rsp(session, transaction, 0);

	return -EAGAIN;
}

static int get_item_attributes(struct avrcp *session, uint8_t transaction,
					uint8_t scope, uint64_t uid,
					uint16_t counter, uint8_t number,
					uint32_t *attrs, void *user_data)
{
	DBG("");

	avrcp_get_item_attributes_rsp(session, transaction, 0, NULL, NULL);

	return -EAGAIN;
}

static int play_item(struct avrcp *session, uint8_t transaction, uint8_t scope,
			uint64_t uid, uint16_t counter, void *user_data)
{
	DBG("");

	if (!uid)
		return -ENOENT;

	avrcp_play_item_rsp(session, transaction);

	return -EAGAIN;
}

static int search(struct avrcp *session, uint8_t transaction,
					const char *string, void *user_data)
{
	DBG("");

	avrcp_search_rsp(session, transaction, 0xaabb, 0);

	return -EAGAIN;
}

static int add_to_now_playing(struct avrcp *session, uint8_t transaction,
				uint8_t scope, uint64_t uid, uint16_t counter,
				void *user_data)
{
	DBG("");

	if (!uid)
		return -ENOENT;

	avrcp_add_to_now_playing_rsp(session, transaction);

	return -EAGAIN;
}

static const struct avrcp_control_ind control_ind = {
	.get_capabilities = get_capabilities,
	.list_attributes = list_attributes,
	.get_attribute_text = get_attribute_text,
	.list_values = list_values,
	.get_value_text = get_value_text,
	.get_value = get_value,
	.set_value = set_value,
	.get_play_status = get_play_status,
	.get_element_attributes = get_element_attributes,
	.register_notification = register_notification,
	.set_volume = set_volume,
	.set_addressed = set_addressed,
	.get_folder_items = get_folder_items,
	.change_path = change_path,
	.get_item_attributes = get_item_attributes,
	.play_item = play_item,
	.search = search,
	.add_to_now_playing = add_to_now_playing,
};

static void test_server(gconstpointer data)
{
	struct context *context = create_context(0x0100, data);

	avrcp_set_passthrough_handlers(context->session, passthrough_handlers,
								context);
	avrcp_register_player(context->session, &control_ind, NULL, context);

	g_idle_add(send_pdu, context);

	execute_context(context);
}

static void test_client(gconstpointer data)
{
	struct context *context = create_context(0x0100, data);

	if (g_str_equal(context->data->test_name, "/TP/MPS/BV-01-C"))
		avrcp_set_addressed_player(context->session, 0xabcd);

	if (g_str_equal(context->data->test_name, "/TP/MPS/BV-03-C"))
		avrcp_set_browsed_player(context->session, 0xabcd);

	if (g_str_equal(context->data->test_name, "/TP/MPS/BV-08-C"))
		avrcp_get_folder_items(context->session,
					AVRCP_MEDIA_PLAYER_LIST, 0, 2, 0, NULL);

	if (g_str_equal(context->data->test_name, "/TP/MPS/BV-01-I"))
		avrcp_get_folder_items(context->session,
					AVRCP_MEDIA_PLAYER_LIST, 0, 2, 0, NULL);

	if (g_str_equal(context->data->test_name, "/TP/MCN/CB/BV-01-C"))
		avrcp_get_folder_items(context->session,
					AVRCP_MEDIA_PLAYER_VFS, 0, 2, 0, NULL);

	if (g_str_equal(context->data->test_name, "/TP/MCN/CB/BV-04-C"))
		avrcp_change_path(context->session, 0x01, 0x01, 0xaabb);

	if (g_str_equal(context->data->test_name, "/TP/MCN/CB/BV-07-C"))
		avrcp_get_item_attributes(context->session,
					AVRCP_MEDIA_PLAYER_VFS, 0x01, 0xaabb,
					0, NULL);

	if (g_str_equal(context->data->test_name, "/TP/MCN/SRC/BV-01-C"))
		avrcp_search(context->session, "Country");

	if (g_str_equal(context->data->test_name, "/TP/MCN/SRC/BV-03-C"))
		avrcp_get_folder_items(context->session, AVRCP_MEDIA_SEARCH,
						0, 2, 0, NULL);

	if (g_str_equal(context->data->test_name, "/TP/MCN/SRC/BV-05-C"))
		avrcp_get_item_attributes(context->session,
					AVRCP_MEDIA_SEARCH, 0x01, 0xaabb,
					0, NULL);

	if (g_str_equal(context->data->test_name, "/TP/MCN/NP/BV-01-C"))
		avrcp_play_item(context->session, AVRCP_MEDIA_NOW_PLAYING, 1,
									1);

	if (g_str_equal(context->data->test_name, "/TP/MCN/NP/BV-03-C"))
		avrcp_add_to_now_playing(context->session,
					AVRCP_MEDIA_NOW_PLAYING, 0x01, 0xaabb);

	if (g_str_equal(context->data->test_name, "/TP/MCN/NP/BV-05-C"))
		avrcp_get_folder_items(context->session,
					AVRCP_MEDIA_NOW_PLAYING, 0, 2, 0, NULL);

	if (g_str_equal(context->data->test_name, "/TP/MCN/NP/BV-08-C"))
		avrcp_get_item_attributes(context->session,
					AVRCP_MEDIA_NOW_PLAYING, 0x01, 0xaabb,
					0, NULL);

	if (g_str_equal(context->data->test_name, "/TP/CFG/BV-01-C"))
		avrcp_get_capabilities(context->session, CAP_EVENTS_SUPPORTED);

	if (g_str_equal(context->data->test_name, "/TP/PAS/BV-01-C"))
		avrcp_list_player_attributes(context->session);

	if (g_str_equal(context->data->test_name, "/TP/PAS/BV-03-C")) {
		uint8_t attrs[2] = { AVRCP_ATTRIBUTE_EQUALIZER,
						AVRCP_ATTRIBUTE_REPEAT_MODE };

		avrcp_get_player_attribute_text(context->session, sizeof(attrs),
									attrs);
	}

	if (g_str_equal(context->data->test_name, "/TP/PAS/BV-05-C"))
		avrcp_list_player_values(context->session,
						AVRCP_ATTRIBUTE_EQUALIZER);

	if (g_str_equal(context->data->test_name, "/TP/PAS/BV-07-C")) {
		uint8_t values[2] = { AVRCP_EQUALIZER_OFF, AVRCP_EQUALIZER_ON };

		avrcp_get_player_value_text(context->session,
						AVRCP_ATTRIBUTE_EQUALIZER,
						sizeof(values), values);
	}

	if (g_str_equal(context->data->test_name, "/TP/PAS/BV-09-C")) {
		uint8_t attrs[2] = { AVRCP_ATTRIBUTE_EQUALIZER,
						AVRCP_ATTRIBUTE_REPEAT_MODE };

		avrcp_get_current_player_value(context->session, sizeof(attrs),
									attrs);
	}

	if (g_str_equal(context->data->test_name, "/TP/PAS/BV-11-C")) {
		uint8_t attrs[2] = { AVRCP_ATTRIBUTE_EQUALIZER,
						AVRCP_ATTRIBUTE_REPEAT_MODE };
		uint8_t values[2] = { 0xaa, 0xff };

		avrcp_set_player_value(context->session, sizeof(attrs), attrs,
								values);
	}

	if (g_str_equal(context->data->test_name, "/TP/MDI/BV-01-C"))
		avrcp_get_play_status(context->session);

	if (g_str_equal(context->data->test_name, "/TP/MDI/BV-03-C"))
		avrcp_get_element_attributes(context->session);

	if (g_str_equal(context->data->test_name, "/TP/NFY/BV-01-C"))
		avrcp_register_notification(context->session,
						AVRCP_EVENT_STATUS_CHANGED, 0);

	if (g_str_equal(context->data->test_name, "/TP/BGN/BV-01-I"))
		avrcp_send_passthrough(context->session, IEEEID_BTSIG,
						AVC_VENDOR_NEXT_GROUP);

	if (g_str_equal(context->data->test_name, "/TP/BGN/BV-02-I"))
		avrcp_send_passthrough(context->session, IEEEID_BTSIG,
						AVC_VENDOR_PREV_GROUP);

	if (g_str_equal(context->data->test_name, "/TP/VLH/BV-01-C"))
		avrcp_set_volume(context->session, 0x00);

	execute_context(context);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	if (g_test_verbose())
		__btd_log_init("*", 0);

	/* Media Player Selection Commands and Notifications */

	/* SetAddressedPlayer - CT */
	define_test("/TP/MPS/BV-01-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48, 0x00,
				0x00, 0x19, 0x58, 0x60, 0x00, 0x00,
				0x02, 0xab, 0xcd));

	/* SetAddressedPlayer - TG */
	define_test("/TP/MPS/BV-02-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_SET_ADDRESSED_PLAYER,
				0x00, 0x00, 0x02, 0xab, 0xcd),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_STABLE,
				0x48, 0x00, 0x00, 0x19, 0x58,
				AVRCP_SET_ADDRESSED_PLAYER,
				0x00, 0x00, 0x01, 0x04));

	/* SetBrowsedPlayer - CT */
	define_test("/TP/MPS/BV-03-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x70, 0x00, 0x02,
				0xab, 0xcd));

	/* GetFolderItems - CT */
	define_test("/TP/MPS/BV-08-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x0a, AVRCP_MEDIA_PLAYER_LIST,
				0x00, 0x00, 0x00, 0x00, /* start */
				0x00, 0x00, 0x00, 0x02, /* end */
				0x00));

	/* GetFolderItems - TG */
	define_test("/TP/MPS/BV-09-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x0a, AVRCP_MEDIA_PLAYER_LIST,
				0x00, 0x00, 0x00, 0x00, /* start */
				0x00, 0x00, 0x00, 0x02, /* end */
				0x00),
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x05, 0x04, 0xab, 0xcd, 0x00, 0x00));

	/*
	 * Media Content Navigation Commands and Notifications for Content
	 * Browsing.
	 */

	/* GetFolderItems - Virtual FS - CT */
	define_test("/TP/MCN/CB/BV-01-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x0a, AVRCP_MEDIA_PLAYER_VFS,
				0x00, 0x00, 0x00, 0x00, /* start */
				0x00, 0x00, 0x00, 0x02, /* end */
				0x00));

	/* GetFolderItems - Virtual FS - TG */
	define_test("/TP/MCN/CB/BV-02-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x0a, AVRCP_MEDIA_PLAYER_VFS,
				0x00, 0x00, 0x00, 0x00, /* start */
				0x00, 0x00, 0x00, 0x02, /* end */
				0x00),
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x05, 0x04, 0xab, 0xcd, 0x00, 0x00));

	/* ChangePath - CT */
	define_test("/TP/MCN/CB/BV-04-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, AVRCP_CHANGE_PATH,
				0x00, 0x0b,
				0xaa, 0xbb,		/* counter */
				0x01,			/* direction */
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01	/* Folder UID */));

	/* ChangePath - TG */
	define_test("/TP/MCN/CB/BV-05-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_CHANGE_PATH,
				0x00, 0x0b,
				0xaa, 0xbb,		/* counter */
				0x01,			/* direction */
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01	/* Folder UID */),
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_CHANGE_PATH,
				0x00, 0x05, 0x04, 0x00, 0x00, 0x00, 0x00));

	/* ChangePath - TG */
	define_test("/TP/MCN/CB/BV-06-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_CHANGE_PATH,
				0x00, 0x0b,
				0xaa, 0xbb,		/* counter */
				0x00,			/* direction */
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01	/* Folder UID */),
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_CHANGE_PATH,
				0x00, 0x05, 0x04, 0x00, 0x00, 0x00, 0x00));

	/* GetItemAttributes - CT */
	define_test("/TP/MCN/CB/BV-07-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, AVRCP_GET_ITEM_ATTRIBUTES,
				0x00, 0x0c, AVRCP_MEDIA_PLAYER_VFS,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,	/* uuid */
				0xaa, 0xbb,		/* counter */
				0x00));			/* num attr */

	/* GetItemAttributes - TG */
	define_test("/TP/MCN/CB/BV-08-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_GET_ITEM_ATTRIBUTES,
				0x00, 0x0c, AVRCP_MEDIA_PLAYER_VFS,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,	/* uuid */
				0xaa, 0xbb,		/* counter */
				0x00),			/* num attr */
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_GET_ITEM_ATTRIBUTES,
				0x00, 0x02, 0x04, 0x00));

	/* GetFolderItems - Virtual FS - TG */
	define_test("/TP/MCN/CB/BI-01-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x0a, AVRCP_MEDIA_PLAYER_VFS,
				0x00, 0x00, 0x00, 0x01, /* start */
				0x00, 0x00, 0x00, 0x00, /* end */
				0x00),
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x01, 0x0b));

	/* GetFolderItems - Virtual FS - TG */
	define_test("/TP/MCN/CB/BI-02-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x0a, AVRCP_MEDIA_PLAYER_VFS,
				0x00, 0x00, 0x00, 0x00, /* start */
				0x00, 0x00, 0x00, 0x01, /* end */
				0x00),
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x01, 0x0b));

	/* GetFolderItems - Virtual FS - TG */
	define_test("/TP/MCN/CB/BI-03-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x0a, AVRCP_MEDIA_PLAYER_VFS,
				0x00, 0x00, 0x00, 0x02, /* start */
				0x00, 0x00, 0x00, 0x03, /* end */
				0x00),
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x01, 0x0b));

	/* ChangePath - TG */
	define_test("/TP/MCN/CB/BI-04-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_CHANGE_PATH,
				0x00, 0x0b,
				0xaa, 0xbb,		/* counter */
				0x01,			/* direction */
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00	/* Folder UID */),
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_CHANGE_PATH,
				0x00, 0x01, 0x08));

	/* Media Content Navigation Commands and Notifications for Search */

	/* Search - CT */
	define_test("/TP/MCN/SRC/BV-01-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, AVRCP_SEARCH,
				0x00, 0x0b, 0x00, 0x6a,
				0x00, 0x07,
				0x43, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79));

	define_test("/TP/MCN/SRC/BV-02-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_SEARCH,
				0x00, 0x0b, 0x00, 0x6a,
				0x00, 0x07,
				0x43, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79),
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_SEARCH,
				0x00, 0x07, 0x04,
				0xaa, 0xbb,		/* counter */
				0x00, 0x00, 0x00, 0x00));

	/* GetFolderItems - CT */
	define_test("/TP/MCN/SRC/BV-03-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x0a, AVRCP_MEDIA_SEARCH,
				0x00, 0x00, 0x00, 0x00, /* start */
				0x00, 0x00, 0x00, 0x02, /* end */
				0x00));

	/* GetFolderItems - NowPlaying - TG */
	define_test("/TP/MCN/SCR/BV-04-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x0a, AVRCP_MEDIA_SEARCH,
				0x00, 0x00, 0x00, 0x00, /* start */
				0x00, 0x00, 0x00, 0x02, /* end */
				0x00),
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x05, 0x04, 0xab, 0xcd, 0x00, 0x00));

	/* GetItemAttributes - CT */
	define_test("/TP/MCN/SRC/BV-05-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, AVRCP_GET_ITEM_ATTRIBUTES,
				0x00, 0x0c, AVRCP_MEDIA_SEARCH,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,	/* uuid */
				0xaa, 0xbb,		/* counter */
				0x00));			/* num attr */

	/* GetItemAttributes - TG */
	define_test("/TP/MCN/SRC/BV-06-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_GET_ITEM_ATTRIBUTES,
				0x00, 0x0c, AVRCP_MEDIA_SEARCH,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,	/* uid */
				0xaa, 0xbb,		/* counter */
				0x00),			/* num attr */
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_GET_ITEM_ATTRIBUTES,
				0x00, 0x02, 0x04, 0x00));

	/* Media Content Navigation Commands and Notifications for NowPlaying */

	/* PlayItem - NowPlaying - CT */
	define_test("/TP/MCN/NP/BV-01-C", test_client,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_PLAY_ITEM,
				0x00, 0x0b, AVRCP_MEDIA_NOW_PLAYING,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x01));

	/* PlayItem - NowPlaying - TG */
	define_test("/TP/MCN/NP/BV-02-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_PLAY_ITEM,
				0x00, 0x0b, AVRCP_MEDIA_NOW_PLAYING,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x01),
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_PLAY_ITEM,
				0x00, 0x01, 0x04));

	/* AddToNowPlaying - NowPlaying - CT */
	define_test("/TP/MCN/NP/BV-03-C", test_client,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_ADD_TO_NOW_PLAYING,
				0x00, 0x0b, AVRCP_MEDIA_NOW_PLAYING,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01, /* uid */
				0xaa, 0xbb));

	/* AddToNowPlaying - NowPlaying - TG */
	define_test("/TP/MCN/NP/BV-04-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_ADD_TO_NOW_PLAYING,
				0x00, 0x0b, AVRCP_MEDIA_NOW_PLAYING,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01, /* uid */
				0xaa, 0xbb),
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_ADD_TO_NOW_PLAYING,
				0x00, 0x01, 0x04));

	/* GetFolderItems - NowPlaying - CT */
	define_test("/TP/MCN/NP/BV-05-C", test_client,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x0a, AVRCP_MEDIA_NOW_PLAYING,
				0x00, 0x00, 0x00, 0x00, /* start */
				0x00, 0x00, 0x00, 0x02, /* end */
				0x00));

	/* GetFolderItems - NowPlaying - TG */
	define_test("/TP/MCN/NP/BV-06-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x0a, AVRCP_MEDIA_NOW_PLAYING,
				0x00, 0x00, 0x00, 0x00, /* start */
				0x00, 0x00, 0x00, 0x02, /* end */
				0x00),
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x05, 0x04, 0xab, 0xcd, 0x00, 0x00));

	/* GetItemAttributes - CT */
	define_test("/TP/MCN/NP/BV-08-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, AVRCP_GET_ITEM_ATTRIBUTES,
				0x00, 0x0c, AVRCP_MEDIA_NOW_PLAYING,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,	/* uid */
				0xaa, 0xbb,		/* counter */
				0x00));			/* num attr */

	/* GetItemAttributes - TG */
	define_test("/TP/MCN/CB/BV-09-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_GET_ITEM_ATTRIBUTES,
				0x00, 0x0c, AVRCP_MEDIA_NOW_PLAYING,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,	/* uid */
				0xaa, 0xbb,		/* counter */
				0x00),			/* num attr */
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_GET_ITEM_ATTRIBUTES,
				0x00, 0x02, 0x04, 0x00));

	/* PlayItem - NowPlaying - TG */
	define_test("/TP/MCN/NP/BI-01-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_PLAY_ITEM,
				0x00, 0x0b, AVRCP_MEDIA_NOW_PLAYING,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, /* uid */
				0xaa, 0xbb),		/* counter */
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_PLAY_ITEM,
				0x00, 0x01, 0x09));

	/* AddToNowPlaying - NowPlaying - TG */
	define_test("/TP/MCN/NP/BI-02-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, AVRCP_ADD_TO_NOW_PLAYING,
				0x00, 0x0b, AVRCP_MEDIA_NOW_PLAYING,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, /* uid */
				0xaa, 0xbb),		/* counter */
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_ADD_TO_NOW_PLAYING,
				0x00, 0x01, 0x09));

	/* Media Player Selection IOP tests */

	/* Listing of available media players */
	define_test("/TP/MPS/BV-01-I", test_client,
			raw_pdu(0x00, 0x11, 0x0e, AVRCP_GET_FOLDER_ITEMS,
				0x00, 0x0a, AVRCP_MEDIA_PLAYER_LIST,
				0x00, 0x00, 0x00, 0x00, /* start */
				0x00, 0x00, 0x00, 0x02, /* end */
				0x00));

	/* Connection Establishment for Browsing tests */

	/*
	 * Tests are checking connection establishment and release
	 * for browsing channel. Since we are connected through socketpair
	 * the tests are dummy
	 */
	define_test("/TP/CON/BV-01-C", test_dummy, raw_pdu(0x00));
	define_test("/TP/CON/BV-02-C", test_dummy, raw_pdu(0x00));
	define_test("/TP/CON/BV-03-C", test_dummy, raw_pdu(0x00));
	define_test("/TP/CON/BV-04-C", test_dummy, raw_pdu(0x00));
	define_test("/TP/CON/BV-05-C", test_dummy, raw_pdu(0x00));

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

	define_test("/TP/PAS/BV-02-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58, 0x11, 0x00, 0x00,
				0x00),
			raw_pdu(0x02, 0x11, 0x0e, 0x0c, 0x48, 0x00,
				0x00, 0x19, 0x58, 0x11, 0x00, 0x00,
				0x01, 0x00));

	define_test("/TP/PAS/BV-03-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
				0x00, 0x00, 0x03, 0x02,
				AVRCP_ATTRIBUTE_EQUALIZER,
				AVRCP_ATTRIBUTE_REPEAT_MODE));

	define_test("/TP/PAS/BV-04-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
				0x00, 0x00, 0x02, 0x01, 0x01),
			raw_pdu(0x02, 0x11, 0x0e, 0x0c, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
				0x00, 0x00, 0x0e, 0x01, 0x01, 0x00,
				0x6a, 0x09, 0x65, 0x71, 0x75, 0x61,
				0x6c, 0x69, 0x7a, 0x65, 0x72));

	define_test("/TP/PAS/BV-05-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_LIST_PLAYER_VALUES,
				0x00, 0x00, 0x01,
				AVRCP_ATTRIBUTE_EQUALIZER));

	define_test("/TP/PAS/BV-06-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_LIST_PLAYER_VALUES,
				0x00, 0x00, 0x01, AVRCP_ATTRIBUTE_EQUALIZER),
			raw_pdu(0x02, 0x11, 0x0e, 0x0c, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_LIST_PLAYER_VALUES,
				0x00, 0x00, 0x01, 0x00));

	define_test("/TP/PAS/BV-07-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_GET_PLAYER_VALUE_TEXT,
				0x00, 0x00, 0x04,
				AVRCP_ATTRIBUTE_EQUALIZER, 0x02,
				AVRCP_EQUALIZER_OFF,
				AVRCP_EQUALIZER_ON));

	define_test("/TP/PAS/BV-08-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_GET_PLAYER_VALUE_TEXT,
				0x00, 0x00, 0x03, AVRCP_ATTRIBUTE_EQUALIZER,
				0x01, 0x01),
			raw_pdu(0x02, 0x11, 0x0e, 0x0c, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_GET_PLAYER_VALUE_TEXT,
				0x00, 0x00, 0x07, 0x01, 0x01, 0x00,
				0x6a, 0x02, 0x6f, 0x6e));

	define_test("/TP/PAS/BV-09-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_GET_CURRENT_PLAYER_VALUE,
				0x00, 0x00, 0x03, 0x02,
				AVRCP_ATTRIBUTE_EQUALIZER,
				AVRCP_ATTRIBUTE_REPEAT_MODE));

	define_test("/TP/PAS/BV-10-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_GET_CURRENT_PLAYER_VALUE,
				0x00, 0x00, 0x03, 0x02,
				AVRCP_ATTRIBUTE_EQUALIZER,
				AVRCP_ATTRIBUTE_REPEAT_MODE),
			raw_pdu(0x02, 0x11, 0x0e, 0x0c, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_GET_CURRENT_PLAYER_VALUE,
				0x00, 0x00, 0x05, 0x02,
				AVRCP_ATTRIBUTE_EQUALIZER, 0x00,
				AVRCP_ATTRIBUTE_REPEAT_MODE, 0x00));

	define_test("/TP/PAS/BV-11-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_SET_PLAYER_VALUE,
				0x00, 0x00, 0x05, 0x02,
				AVRCP_ATTRIBUTE_EQUALIZER, 0xaa,
				AVRCP_ATTRIBUTE_REPEAT_MODE, 0xff));

	/* Get player app setting attribute text invalid behavior - TG */
	define_test("/TP/PAS/BI-01-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
				0x00, 0x00, 0x02, 0x01,
				/* Invalid attribute id */
				0x7f),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_REJECTED,
				0x48, 0x00, 0x00, 0x19, 0x58,
				AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
				0x00, 0x00, 0x01, AVRCP_STATUS_INVALID_PARAM));

	/* List player application setting values invalid behavior - TG */
	define_test("/TP/PAS/BI-02-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_LIST_PLAYER_VALUES,
				0x00, 0x00, 0x01,
				/* Invalid attribute id */
				0x7f),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_REJECTED,
				0x48, 0x00, 0x00, 0x19, 0x58,
				AVRCP_LIST_PLAYER_VALUES,
				0x00, 0x00, 0x01, AVRCP_STATUS_INVALID_PARAM));

	/* Get player application setting value text invalid behavior - TG */
	define_test("/TP/PAS/BI-03-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_GET_PLAYER_VALUE_TEXT,
				0x00, 0x00, 0x03, AVRCP_ATTRIBUTE_EQUALIZER,
				0x01,
				/* Invalid setting value */
				0x7f),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_REJECTED,
				0x48, 0x00, 0x00, 0x19, 0x58,
				AVRCP_GET_PLAYER_VALUE_TEXT,
				0x00, 0x00, 0x01, AVRCP_STATUS_INVALID_PARAM));

	/* Get current player application setting value invalid behavior - TG */
	define_test("/TP/PAS/BI-04-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_GET_CURRENT_PLAYER_VALUE,
				0x00, 0x00, 0x02, 0x01,
				/* Invalid attribute */
				0x7f),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_REJECTED,
				0x48, 0x00, 0x00, 0x19, 0x58,
				AVRCP_GET_CURRENT_PLAYER_VALUE,
				0x00, 0x00, 0x01, AVRCP_STATUS_INVALID_PARAM));

	/* Set player application setting value invalid behavior - TG */
	define_test("/TP/PAS/BI-05-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48, 0x00,
				0x00, 0x19, 0x58,
				AVRCP_SET_PLAYER_VALUE,
				0x00, 0x00, 0x03, 0x01,
				AVRCP_ATTRIBUTE_REPEAT_MODE, 0x7f),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_REJECTED,
				0x48, 0x00, 0x00, 0x19, 0x58,
				AVRCP_SET_PLAYER_VALUE,
				0x00, 0x00, 0x01, AVRCP_STATUS_INVALID_PARAM));

	/* Media Information Commands */

	/* Get play status - CT */
	define_test("/TP/MDI/BV-01-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_GET_PLAY_STATUS,
				0x00, 0x00, 0x00));

	/* Get play status - TG */
	define_test("/TP/MDI/BV-02-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_GET_PLAY_STATUS,
				0x00, 0x00, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, 0x0c, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_GET_PLAY_STATUS,
				0x00, 0x00, 0x09,
				0xbb, 0xbb, 0xbb, 0xbb, /* duration */
				0xaa, 0xaa, 0xaa, 0xaa, /* position */
				0x00));

	/* Get element attributes - CT */
	define_test("/TP/MDI/BV-03-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_GET_ELEMENT_ATTRIBUTES,
				0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00));

	/* Get element attributes - TG */
	define_test("/TP/MDI/BV-04-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_GET_ELEMENT_ATTRIBUTES,
				0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, 0x0c, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_GET_ELEMENT_ATTRIBUTES,
				0x00, 0x00, 0x00));

	/* Get element attributes - TG */
	define_test("/TP/MDI/BV-05-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x01, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_GET_ELEMENT_ATTRIBUTES,
				0x00, 0x00, 0x0d, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x01),
			raw_pdu(0x02, 0x11, 0x0e, 0x0c, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_GET_ELEMENT_ATTRIBUTES,
				0x00, 0x00, 0x00));

	/* Notification Commands */

	/* Register notification - CT */
	define_test("/TP/NFY/BV-01-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x03, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x05, AVRCP_EVENT_STATUS_CHANGED,
				0x00, 0x00, 0x00, 0x00));

	/* Register notification - TG */
	define_test("/TP/NFY/BV-02-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x03, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x05, AVRCP_EVENT_TRACK_CHANGED,
				0x00, 0x00, 0x00, 0x00),
			frg_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_INTERIM, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x09, AVRCP_EVENT_TRACK_CHANGED,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_CHANGED, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x09, AVRCP_EVENT_TRACK_CHANGED,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff));

	/* Register notification - TG */
	define_test("/TP/NFY/BV-03-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x03, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x05,
				AVRCP_EVENT_SETTINGS_CHANGED,
				0x00, 0x00, 0x00, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_INTERIM, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x04,
				AVRCP_EVENT_SETTINGS_CHANGED,
				0x01, 0x01, 0x02),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_CHANGED, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x04,
				AVRCP_EVENT_SETTINGS_CHANGED,
				0x01, 0x01, 0x02));

	/* Register notification - Track Changed - No Selected Track - TG */
	define_test("/TP/NFY/BV-04-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x03, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x05, AVRCP_EVENT_TRACK_CHANGED,
				0x00, 0x00, 0x00, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_INTERIM, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x09, AVRCP_EVENT_TRACK_CHANGED,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff));

	/* Register notification - Track Changed - Track Playing - TG */
	define_test("/TP/NFY/BV-05-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x03, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x05, AVRCP_EVENT_TRACK_CHANGED,
				0x00, 0x00, 0x00, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_INTERIM, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x09, AVRCP_EVENT_TRACK_CHANGED,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00));

	/* Register notification - Track Changed - Selected Track - TG */
	define_test("/TP/NFY/BV-08-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x03, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x05, AVRCP_EVENT_TRACK_CHANGED,
				0x00, 0x00, 0x00, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_INTERIM, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x09, AVRCP_EVENT_TRACK_CHANGED,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00));

	/* Register notification - Register for events invalid behavior - TG */
	define_test("/TP/NFY/BI-01-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x03, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x05,
				/* Invalid event id */
				0xff,
				0x00, 0x00, 0x00, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_REJECTED,
				0x48, 0x00, 0x00, 0x19, 0x58,
				AVRCP_REGISTER_NOTIFICATION,
				0x00, 0x00, 0x01, AVRCP_STATUS_INVALID_PARAM));

	/* Invalid commands */

	/* Invalid PDU ID - TG */
	define_test("/TP/INV/BI-01-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x03, 0x48, 0x00,
				0x00, 0x19, 0x58,
				/* Invalid PDU ID */
				0xff,
				0x00, 0x00, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_REJECTED,
				0x48, 0x00, 0x00, 0x19, 0x58,
				0xff, 0x00, 0x00, 0x01,
				AVRCP_STATUS_INVALID_COMMAND));

	/* Invalid PDU ID - Browsing TG */
	define_test("/TP/INV/BI-02-C", test_server,
			brs_pdu(0x00, 0x11, 0x0e, 0xff, 0x00, 0x00),
			brs_pdu(0x02, 0x11, 0x0e, AVRCP_GENERAL_REJECT,
				0x00, 0x01, AVRCP_STATUS_INVALID_COMMAND));

	/* Next Group command transfer - CT */
	define_test("/TP/BGN/BV-01-I", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48,
				AVC_OP_PASSTHROUGH,
				AVC_VENDOR_UNIQUE, 0x05, 0x00, 0x19,
				0x58, 0x00, AVC_VENDOR_NEXT_GROUP));

	/* Next Group command transfer - TG */
	define_test("/TP/BGN/BV-01-I", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48,
				AVC_OP_PASSTHROUGH,
				AVC_VENDOR_UNIQUE, 0x05, 0x00, 0x19,
				0x58, 0x00, AVC_VENDOR_NEXT_GROUP),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_ACCEPTED,
				0x48, AVC_OP_PASSTHROUGH,
				AVC_VENDOR_UNIQUE, 0x05, 0x00, 0x19,
				0x58, 0x00, AVC_VENDOR_NEXT_GROUP));

	/* Previous Group command transfer - CT */
	define_test("/TP/BGN/BV-02-I", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48,
				AVC_OP_PASSTHROUGH,
				AVC_VENDOR_UNIQUE, 0x05, 0x00, 0x19,
				0x58, 0x00, AVC_VENDOR_PREV_GROUP));

	/* Previous Group command transfer - TG */
	define_test("/TP/BGN/BV-02-I", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48,
				AVC_OP_PASSTHROUGH,
				AVC_VENDOR_UNIQUE, 0x05, 0x00, 0x19,
				0x58, 0x00, AVC_VENDOR_PREV_GROUP),
			raw_pdu(0x02, 0x11, 0x0e, AVC_CTYPE_ACCEPTED,
				0x48, AVC_OP_PASSTHROUGH,
				AVC_VENDOR_UNIQUE, 0x05, 0x00, 0x19,
				0x58, 0x00, AVC_VENDOR_PREV_GROUP));

	/* Volume Level Handling */

	/* Set absolute volume – CT */
	define_test("/TP/VLH/BV-01-C", test_client,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_SET_ABSOLUTE_VOLUME,
				0x00, 0x00, 0x01, 0x00));

	/* Set absolute volume – TG */
	define_test("/TP/VLH/BV-02-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_SET_ABSOLUTE_VOLUME,
				0x00, 0x00, 0x01, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, 0x0c, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_SET_ABSOLUTE_VOLUME,
				0x00, 0x00, 0x01, 0x00));

	/* Set absolute volume – TG */
	define_test("/TP/VLH/BI-01-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_SET_ABSOLUTE_VOLUME,
				0x00, 0x00, 0x00),
			raw_pdu(0x02, 0x11, 0x0e, 0x0a, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_SET_ABSOLUTE_VOLUME,
				0x00, 0x00, 0x01, 0x01));

	/* Set absolute volume – TG */
	define_test("/TP/VLH/BI-02-C", test_server,
			raw_pdu(0x00, 0x11, 0x0e, 0x00, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_SET_ABSOLUTE_VOLUME,
				0x00, 0x00, 0x01, 0x80),
			raw_pdu(0x02, 0x11, 0x0e, 0x0c, 0x48, 0x00,
				0x00, 0x19, 0x58, AVRCP_SET_ABSOLUTE_VOLUME,
				0x00, 0x00, 0x01, 0x00));

	return g_test_run();
}
