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

#include "lib/uuid.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/gatt-helpers.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/gatt-client.h"

struct test_pdu {
	bool valid;
	const uint8_t *data;
	size_t size;
};

enum context_type {
	ATT,
	CLIENT,
	SERVER
};

struct test_data {
	char *test_name;
	struct test_pdu *pdu_list;
	enum context_type context_type;
	bt_uuid_t *uuid;
	struct gatt_db *source_db;
	const void *step;
};

struct context {
	GMainLoop *main_loop;
	struct bt_gatt_client *client;
	struct bt_gatt_server *server;
	struct bt_att *att;
	struct gatt_db *client_db;
	struct gatt_db *server_db;
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

#define define_test(name, function, type, bt_uuid, db,			\
		test_step, args...)					\
	do {								\
		const struct test_pdu pdus[] = {			\
			args, { }					\
		};							\
		static struct test_data data;				\
		data.test_name = g_strdup(name);			\
		data.context_type = type;				\
		data.uuid = bt_uuid;					\
		data.step = test_step;					\
		data.source_db = db;					\
		data.pdu_list = g_malloc(sizeof(pdus));			\
		memcpy(data.pdu_list, pdus, sizeof(pdus));		\
		g_test_add_data_func(name, &data, function);		\
	} while (0)

#define define_test_att(name, function, bt_uuid, test_step, args...)	\
	define_test(name, function, ATT, bt_uuid, NULL, test_step, args)

#define define_test_client(name, function, source_db, test_step, args...)\
	define_test(name, function, CLIENT, NULL, source_db, test_step, args)

#define define_test_server(name, function, source_db, test_step, args...)\
	define_test(name, function, SERVER, NULL, source_db, test_step, args)

#define MTU_EXCHANGE_CLIENT_PDUS					\
		raw_pdu(0x02, 0x00, 0x02),				\
		raw_pdu(0x03, 0x00, 0x02)

#define SERVICE_DATA_1_PDUS						\
		MTU_EXCHANGE_CLIENT_PDUS,				\
		raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),	\
		raw_pdu(0x11, 0x06, 0x01, 0x00, 0x04, 0x00, 0x01, 0x18),\
		raw_pdu(0x10, 0x05, 0x00, 0xff, 0xff, 0x00, 0x28),	\
		raw_pdu(0x11, 0x06, 0x05, 0x00, 0x08, 0x00, 0x0d, 0x18),\
		raw_pdu(0x10, 0x09, 0x00, 0xff, 0xff, 0x00, 0x28),	\
		raw_pdu(0x01, 0x10, 0x09, 0x00, 0x0a),			\
		raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x01, 0x28),	\
		raw_pdu(0x01, 0x10, 0x01, 0x00, 0x0a),			\
		raw_pdu(0x08, 0x01, 0x00, 0x04, 0x00, 0x02, 0x28),	\
		raw_pdu(0x01, 0x08, 0x01, 0x00, 0x0a),			\
		raw_pdu(0x08, 0x05, 0x00, 0x08, 0x00, 0x02, 0x28),	\
		raw_pdu(0x01, 0x08, 0x05, 0x00, 0x0a),			\
		raw_pdu(0x08, 0x01, 0x00, 0x04, 0x00, 0x03, 0x28),	\
		raw_pdu(0x09, 0x07, 0x02, 0x00, 0x02, 0x03, 0x00, 0x00,	\
				0x2a),					\
		raw_pdu(0x08, 0x03, 0x00, 0x04, 0x00, 0x03, 0x28),	\
		raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),			\
		raw_pdu(0x04, 0x04, 0x00, 0x04, 0x00),			\
		raw_pdu(0x05, 0x01, 0x04, 0x00, 0x01, 0x29),		\
		raw_pdu(0x08, 0x05, 0x00, 0x08, 0x00, 0x03, 0x28),	\
		raw_pdu(0x09, 0x07, 0x06, 0x00, 0x02, 0x07, 0x00, 0x29,	\
				0x2a),					\
		raw_pdu(0x08, 0x07, 0x00, 0x08, 0x00, 0x03, 0x28),	\
		raw_pdu(0x01, 0x08, 0x07, 0x00, 0x0a),			\
		raw_pdu(0x04, 0x08, 0x00, 0x08, 0x00),			\
		raw_pdu(0x05, 0x01, 0x08, 0x00, 0x01, 0x29)

#define PRIMARY_DISC_SMALL_DB						\
		raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),	\
		raw_pdu(0x11, 0x06, 0x10, 0xF0, 0x15, 0xF0, 0x00, 0x18,	\
				0xFF, 0xFF, 0xFF, 0xFF, 0x0a, 0x18)

#define SECONDARY_DISC_SMALL_DB						\
		raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x01, 0x28),	\
		raw_pdu(0x11, 0x06, 0x01, 0x00, 0x0F, 0x00, 0x0a, 0x18),\
		raw_pdu(0x10, 0x10, 0x00, 0xff, 0xff, 0x01, 0x28),	\
		raw_pdu(0x01, 0x10, 0x10, 0x00, 0x0a)

#define SERVER_MTU_EXCHANGE_PDU raw_pdu(0x02, 0x17, 0x00)

static bt_uuid_t uuid_16 = {
	.type = BT_UUID16,
	.value.u16 = 0x1800
};

static bt_uuid_t uuid_char_16 = {
	.type = BT_UUID16,
	.value.u16 = 0x2a0d
};

static bt_uuid_t uuid_128 = {
	.type = BT_UUID128,
	.value.u128.data = {0x00, 0x00, 0x18, 0x0d, 0x00, 0x00, 0x10, 0x00,
				0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb}
};

static bt_uuid_t uuid_char_128 = {
	.type = BT_UUID128,
	.value.u128.data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
};

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
		util_hexdump('<', pdu->data, len, test_debug, "GATT: ");

	g_assert_cmpint(len, ==, pdu->size);

	context->process = 0;
	return FALSE;
}

static void context_process(struct context *context)
{
	/* Quit the context if we processed the last PDU */
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
		util_hexdump('>', buf, len, test_debug, "GATT: ");

	g_assert_cmpint(len, ==, pdu->size);

	g_assert(memcmp(buf, pdu->data, pdu->size) == 0);

	context_process(context);

	return TRUE;
}

static void print_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	g_print("%s%s\n", prefix, str);
}

typedef void (*test_step_t)(struct context *context);

struct test_step {
	test_step_t func;
	uint16_t handle;
	uint16_t end_handle;
	uint8_t uuid[16];
	uint8_t expected_att_ecode;
	const uint8_t *value;
	uint16_t length;
};

struct db_attribute_test_data {
	struct gatt_db_attribute *match;
	bool found;
};

static bool matching_desc_data(struct gatt_db_attribute *a,
						struct gatt_db_attribute *b)
{
	uint16_t a_handle, b_handle;
	const bt_uuid_t *a_uuid, *b_uuid;

	a_handle = gatt_db_attribute_get_handle(a);
	b_handle = gatt_db_attribute_get_handle(b);

	a_uuid = gatt_db_attribute_get_type(a);
	b_uuid = gatt_db_attribute_get_type(b);

	return a_handle == b_handle && !bt_uuid_cmp(a_uuid, b_uuid);
}

static void find_matching_desc(struct gatt_db_attribute *source_desc_attr,
								void *user_data)
{
	struct db_attribute_test_data *desc_test_data = user_data;

	if (desc_test_data->found)
		return;

	desc_test_data->found = matching_desc_data(desc_test_data->match,
							source_desc_attr);
}

static void match_descs(struct gatt_db_attribute *client_desc_attr,
								void *user_data)
{
	struct gatt_db_attribute *source_char_attr = user_data;
	struct db_attribute_test_data desc_test_data;

	desc_test_data.match = client_desc_attr;
	desc_test_data.found = false;

	gatt_db_service_foreach_desc(source_char_attr, find_matching_desc,
							&desc_test_data);

	g_assert(desc_test_data.found);
}

static bool matching_char_data(struct gatt_db_attribute *a,
						struct gatt_db_attribute *b)
{
	uint16_t a_handle, b_handle, a_value_handle, b_value_handle;
	uint8_t a_properties, b_properties;
	bt_uuid_t a_uuid, b_uuid;

	gatt_db_attribute_get_char_data(a, &a_handle, &a_value_handle,
							&a_properties, &a_uuid);
	gatt_db_attribute_get_char_data(b, &b_handle, &b_value_handle,
							&b_properties, &b_uuid);

	return a_handle == b_handle && a_value_handle == b_value_handle &&
						a_properties == b_properties &&
						!bt_uuid_cmp(&a_uuid, &b_uuid);
}

static void find_matching_char(struct gatt_db_attribute *source_char_attr,
								void *user_data)
{
	struct db_attribute_test_data *char_test_data = user_data;

	if (char_test_data->found)
		return;

	if (matching_char_data(char_test_data->match, source_char_attr)) {

		gatt_db_service_foreach_desc(char_test_data->match, match_descs,
							source_char_attr);
		char_test_data->found = true;
	}
}

static void match_chars(struct gatt_db_attribute *client_char_attr,
								void *user_data)
{
	struct gatt_db_attribute *source_serv_attr = user_data;
	struct db_attribute_test_data char_test_data;

	char_test_data.match = client_char_attr;
	char_test_data.found = false;

	gatt_db_service_foreach_char(source_serv_attr, find_matching_char,
							&char_test_data);

	g_assert(char_test_data.found);
}

static bool matching_service_data(struct gatt_db_attribute *a,
						struct gatt_db_attribute *b)
{
	uint16_t a_start, b_start, a_end, b_end;
	bool a_primary, b_primary;
	bt_uuid_t a_uuid, b_uuid;

	gatt_db_attribute_get_service_data(a, &a_start, &a_end, &a_primary,
								&a_uuid);
	gatt_db_attribute_get_service_data(b, &b_start, &b_end, &b_primary,
								&b_uuid);

	return a_start == b_start && a_end == b_end && a_primary == b_primary &&
						!bt_uuid_cmp(&a_uuid, &b_uuid);
}

static void find_matching_service(struct gatt_db_attribute *source_serv_attr,
								void *user_data)
{
	struct db_attribute_test_data *serv_test_data = user_data;

	if (serv_test_data->found)
		return;

	if (matching_service_data(serv_test_data->match, source_serv_attr)) {
		gatt_db_service_foreach_char(serv_test_data->match, match_chars,
							source_serv_attr);
		serv_test_data->found = true;
	}
}

static void match_services(struct gatt_db_attribute *client_serv_attr,
								void *user_data)
{
	struct gatt_db *source_db = user_data;
	struct db_attribute_test_data serv_test_data;

	serv_test_data.match = client_serv_attr;
	serv_test_data.found = false;

	gatt_db_foreach_service(source_db, NULL,
					find_matching_service, &serv_test_data);

	g_assert(serv_test_data.found);
}

static void client_ready_cb(bool success, uint8_t att_ecode, void *user_data)
{
	struct context *context = user_data;

	g_assert(success);

	if (!context->data->source_db) {
		context_quit(context);
		return;
	}

	g_assert(context->client);
	g_assert(context->client_db);

	gatt_db_foreach_service(context->client_db, NULL, match_services,
						context->data->source_db);

	if (context->data->step) {
		const struct test_step *step = context->data->step;

		step->func(context);
		return;
	}

	context_quit(context);
}

static struct context *create_context(uint16_t mtu, gconstpointer data)
{
	struct context *context = g_new0(struct context, 1);
	const struct test_data *test_data = data;
	GIOChannel *channel;
	int err, sv[2];
	struct bt_att *att;

	context->main_loop = g_main_loop_new(NULL, FALSE);
	g_assert(context->main_loop);

	err = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
	g_assert(err == 0);

	att = bt_att_new(sv[0]);
	g_assert(att);

	switch (test_data->context_type) {
	case ATT:
		context->att = att;

		if (g_test_verbose())
			bt_att_set_debug(context->att, print_debug, "bt_att:",
									NULL);

		bt_gatt_exchange_mtu(context->att, mtu, NULL, NULL, NULL);
		break;
	case SERVER:
		context->server_db = gatt_db_ref(test_data->source_db);
		g_assert(context->server_db);

		context->server = bt_gatt_server_new(context->server_db, att,
									mtu);
		g_assert(context->server);

		if (g_test_verbose())
			bt_gatt_server_set_debug(context->server, print_debug,
						"bt_gatt_server:", NULL);
		bt_att_unref(att);
		break;
	case CLIENT:
		context->client_db = gatt_db_new();
		g_assert(context->client_db);

		context->client = bt_gatt_client_new(context->client_db, att,
									mtu);
		g_assert(context->client);

		if (g_test_verbose())
			bt_gatt_client_set_debug(context->client, print_debug,
						"bt_gatt_client:", NULL);

		bt_gatt_client_set_ready_handler(context->client,
						client_ready_cb, context, NULL);

		bt_att_unref(att);
		break;
	default:
		break;
	}

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

static void generic_search_cb(bool success, uint8_t att_ecode,
						struct bt_gatt_result *result,
						void *user_data)
{
	struct context *context = user_data;

	g_assert(success);

	context_quit(context);
}

static void destroy_context(struct context *context)
{
	if (context->source > 0)
		g_source_remove(context->source);

	bt_gatt_client_unref(context->client);
	bt_gatt_server_unref(context->server);
	gatt_db_unref(context->client_db);
	gatt_db_unref(context->server_db);

	if (context->att)
		bt_att_unref(context->att);

	g_main_loop_unref(context->main_loop);

	test_free(context->data);
	g_free(context);
}

static void execute_context(struct context *context)
{
	g_main_loop_run(context->main_loop);

	destroy_context(context);
}

static void test_read_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct context *context = user_data;
	const struct test_step *step = context->data->step;

	g_assert(att_ecode == step->expected_att_ecode);

	if (success) {
		g_assert(length == step->length);
		g_assert(memcmp(value, step->value, length) == 0);
	}

	context_quit(context);
}

static void test_read(struct context *context)
{
	const struct test_step *step = context->data->step;

	g_assert(bt_gatt_client_read_value(context->client, step->handle,
						test_read_cb, context, NULL));
}

const uint8_t read_data_1[] = {0x01, 0x02, 0x03};

const struct test_step test_read_1 = {
	.handle = 0x0003,
	.func = test_read,
	.expected_att_ecode = 0,
	.value = read_data_1,
	.length = 0x03
};

const struct test_step test_read_2 = {
	.handle = 0x0000,
	.func = test_read,
	.expected_att_ecode = 0x01,
};

const struct test_step test_read_3 = {
	.handle = 0x0003,
	.func = test_read,
	.expected_att_ecode = 0x02,
};

const struct test_step test_read_4 = {
	.handle = 0x0003,
	.func = test_read,
	.expected_att_ecode = 0x08,
};

static void att_write_cb(struct gatt_db_attribute *att, int err,
								void *user_data)
{
	g_assert(!err);
}

static struct gatt_db_attribute *add_char_with_value(struct gatt_db *db,
					struct gatt_db_attribute *service_att,
					bt_uuid_t *uuid,
					uint32_t att_permissions,
					uint8_t char_properties,
					const void *value, size_t len)
{
	struct gatt_db_attribute *attrib;

	attrib = gatt_db_service_add_characteristic(service_att, uuid,
								att_permissions,
								char_properties,
								NULL, NULL,
								NULL);

	gatt_db_attribute_write(attrib, 0, value, len, 0x00, NULL, att_write_cb,
									NULL);

	return attrib;
}

static struct gatt_db_attribute *add_ccc(struct gatt_db_attribute *chrc_att,
								bool writable)
{
	struct gatt_db_attribute *desc_att;
	bt_uuid_t uuid;
	uint32_t permissions = BT_ATT_PERM_READ;
	uint16_t tmp;

	if (writable)
		permissions |= BT_ATT_PERM_WRITE;

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	desc_att = gatt_db_service_add_descriptor(chrc_att, &uuid, permissions,
							NULL, NULL, NULL);

	tmp = 0x0000;
	gatt_db_attribute_write(desc_att, 0, (uint8_t *)&tmp, sizeof(uint16_t),
						0x00, NULL, att_write_cb, NULL);

	return desc_att;
}

static struct gatt_db_attribute *
add_user_description(struct gatt_db_attribute *chrc_att, const char *desc,
								bool writable)
{
	struct gatt_db_attribute *desc_att;
	bt_uuid_t uuid;
	uint32_t permissions = BT_ATT_PERM_READ;

	if (writable)
		permissions |= BT_ATT_PERM_WRITE;

	bt_uuid16_create(&uuid, GATT_CHARAC_USER_DESC_UUID);
	desc_att = gatt_db_service_add_descriptor(chrc_att, &uuid, permissions,
							NULL, NULL, NULL);

	gatt_db_attribute_write(desc_att, 0, (uint8_t *)desc, strlen(desc),
						0x00, NULL, att_write_cb, NULL);

	return desc_att;
}


typedef struct gatt_db_attribute (*add_service_func) (struct gatt_db *db,
							uint16_t handle,
							bool primary,
							uint16_t extra_handles);

static struct gatt_db_attribute *
add_device_information_service(struct gatt_db *db, uint16_t handle,
					bool primary, uint16_t extra_handles)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *serv_att;

	bt_string_to_uuid(&uuid, DEVICE_INFORMATION_UUID);
	serv_att = gatt_db_insert_service(db, handle, &uuid, primary,
							1 + extra_handles);

	return serv_att;
}

static struct gatt_db_attribute *add_gap(struct gatt_db *db, uint16_t handle,
							bool primary,
							uint16_t extra_handles)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *serv_att;

	bt_string_to_uuid(&uuid, GAP_UUID);
	serv_att = gatt_db_insert_service(db, handle, &uuid, primary,
							1 + extra_handles);

	return serv_att;
}

static struct gatt_db *make_service_data_1_db(void)
{
	struct gatt_db *db = gatt_db_new();
	struct gatt_db_attribute *serv_att, *chrc_att;
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, 0x1801);
	serv_att = gatt_db_insert_service(db, 0x0001, &uuid, true, 4);

	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	chrc_att = add_char_with_value(db, serv_att, &uuid, BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ, "BlueZ", 5);

	add_user_description(chrc_att, "Device Name", false);

	gatt_db_service_set_active(serv_att, true);

	bt_uuid16_create(&uuid, 0x180d);
	serv_att = gatt_db_insert_service(db, 0x0005, &uuid, true, 4);

	bt_uuid16_create(&uuid, GATT_CHARAC_MANUFACTURER_NAME_STRING);
	chrc_att = gatt_db_service_add_characteristic(serv_att, &uuid,
							BT_ATT_PERM_READ,
							BT_GATT_CHRC_PROP_READ,
							NULL, NULL, NULL);

	add_user_description(chrc_att, "Manufacturer Name", false);

	gatt_db_service_set_active(serv_att, true);

	return db;
}

/*
 * Defined Test database 1:
 * Tiny database fits into a single minimum sized-pdu.
 * Satisfies:
 * 3. At least one primary seervice at the MAX handle
 * For each / all databases:
 * X 7. at least one service uuid with multiple instances
 * X 8. Some simple services, some with included services
 * X 9. an instance where handle of included service comes before the including
 * service
 * X 11. Simple characteristics (no desc) and complex characteristics
 *       (multiple descriptors)
 * X 12. Instances of complex chars with 16-bit and 128-bit uuids
 * (although not in scrambled order)
 */

static struct gatt_db *make_test_spec_small_db(void)
{
	struct gatt_db *db;
	struct gatt_db_attribute *serv_att, *dis_att;
	bt_uuid_t uuid;
	const char *manuf_device_string = "BlueZ";
	const char *device_name_string = "BlueZ Unit Tester";
	const char *user_desc_manuf_name = "Manufacturer Name";
	uint16_t u16_value;
	uint8_t u8_value;

	db = gatt_db_new();

	dis_att = add_device_information_service(db, 0x0001, false, 15);

	bt_uuid16_create(&uuid, GATT_CHARAC_MANUFACTURER_NAME_STRING);
	add_char_with_value(db, dis_att, &uuid, BT_ATT_PERM_READ,
						BT_GATT_CHRC_PROP_READ,
						manuf_device_string,
						strlen(manuf_device_string));
	add_ccc(dis_att, false);
	add_user_description(dis_att, user_desc_manuf_name, false);

	gatt_db_service_set_active(dis_att, true);

	serv_att = add_gap(db, 0xF010, true, 5);

	gatt_db_service_add_included(serv_att, dis_att);

	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	add_char_with_value(db, serv_att, &uuid, BT_ATT_PERM_READ,
						BT_GATT_CHRC_PROP_READ,
						device_name_string,
						strlen(device_name_string));

	bt_string_to_uuid(&uuid, "0000B009-0000-0000-0123-456789abcdef");
	u8_value = 0x09;
	add_char_with_value(db, serv_att, &uuid, BT_ATT_PERM_READ,
						BT_GATT_CHRC_PROP_READ,
						&u8_value, sizeof(uint8_t));

	gatt_db_service_set_active(serv_att, true);

	u16_value = 0x0000; /* "Unknown" Appearance */
	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	add_char_with_value(db, serv_att, &uuid, BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ, &u16_value,
					sizeof(uint16_t));


	serv_att = add_device_information_service(db, 0xFFFF, true, 0);

	gatt_db_service_set_active(serv_att, true);

	return db;
}

static void test_client(gconstpointer data)
{
	struct context *context = create_context(512, data);

	execute_context(context);
}

static void test_server(gconstpointer data)
{
	struct context *context = create_context(512, data);
	ssize_t len;
	const struct test_pdu pdu = SERVER_MTU_EXCHANGE_PDU;

	len = write(context->fd, pdu.data, pdu.size);

	g_assert_cmpint(len, ==, pdu.size);

	if (g_test_verbose())
		util_hexdump('<', pdu.data, len, test_debug, "GATT: ");

	execute_context(context);
}

static void test_search_primary(gconstpointer data)
{
	struct context *context = create_context(512, data);
	const struct test_data *test_data = data;

	bt_gatt_discover_all_primary_services(context->att, test_data->uuid,
							generic_search_cb,
							context, NULL);

	execute_context(context);
}

static void test_search_included(gconstpointer data)
{
	struct context *context = create_context(512, data);

	bt_gatt_discover_included_services(context->att, 0x0001, 0xffff,
							generic_search_cb,
							context, NULL);

	execute_context(context);
}

static void test_search_chars(gconstpointer data)
{
	struct context *context = create_context(512, data);

	g_assert(bt_gatt_discover_characteristics(context->att, 0x0010, 0x0020,
							generic_search_cb,
							context, NULL));

	execute_context(context);
}

static void test_search_descs(gconstpointer data)
{
	struct context *context = create_context(512, data);

	g_assert(bt_gatt_discover_descriptors(context->att, 0x0013, 0x0016,
							generic_search_cb,
							context, NULL));

	execute_context(context);
}

const struct test_step test_read_by_type_1 = {
	.handle = 0x0001,
	.end_handle = 0xffff,
	.expected_att_ecode = 0x0a,
	.value = read_data_1,
	.length = 0x03
};

const struct test_step test_read_by_type_2 = {
	.handle = 0x0001,
	.end_handle = 0xffff,
	.expected_att_ecode = 0x02,
};

const struct test_step test_read_by_type_3 = {
	.handle = 0x0001,
	.end_handle = 0xffff,
	.expected_att_ecode = 0x0a,
};

const struct test_step test_read_by_type_4 = {
	.handle = 0x0001,
	.end_handle = 0xffff,
	.expected_att_ecode = 0x08,
};

const struct test_step test_read_by_type_5 = {
	.handle = 0x0001,
	.end_handle = 0xffff,
	.expected_att_ecode = 0x05,
};

const struct test_step test_read_by_type_6 = {
	.handle = 0x0001,
	.end_handle = 0xffff,
	.expected_att_ecode = 0x0c,
};

static void multiple_read_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct context *context = user_data;
	const struct test_step *step = context->data->step;

	g_assert(att_ecode == step->expected_att_ecode);

	if (success) {
		g_assert(length == step->length);
		g_assert(memcmp(value, step->value, length) == 0);
	}

	context_quit(context);
}

static void test_multiple_read(struct context *context)
{
	const struct test_step *step = context->data->step;
	uint16_t handles[2];

	handles[0] = step->handle;
	handles[1] = step->end_handle;

	g_assert(bt_gatt_client_read_multiple(context->client, handles, 2,
						multiple_read_cb, context,
						NULL));
}

const struct test_step test_multiple_read_1 = {
	.handle = 0x0003,
	.end_handle = 0x0007,
	.func = test_multiple_read,
	.value = read_data_1,
	.length = 0x03
};

const struct test_step test_multiple_read_2 = {
	.handle = 0x0003,
	.end_handle = 0x0007,
	.func = test_multiple_read,
	.expected_att_ecode = 0x02
};

const struct test_step test_multiple_read_3 = {
	.handle = 0x0003,
	.end_handle = 0x0007,
	.func = test_multiple_read,
	.expected_att_ecode = 0x01
};

const struct test_step test_multiple_read_4 = {
	.handle = 0x0003,
	.end_handle = 0x0007,
	.func = test_multiple_read,
	.expected_att_ecode = 0x08
};

const struct test_step test_multiple_read_5 = {
	.handle = 0x0003,
	.end_handle = 0x0007,
	.func = test_multiple_read,
	.expected_att_ecode = 0x05
};

const struct test_step test_multiple_read_6 = {
	.handle = 0x0003,
	.end_handle = 0x0007,
	.func = test_multiple_read,
	.expected_att_ecode = 0x0c
};

static void read_by_type_cb(bool success, uint8_t att_ecode,
						struct bt_gatt_result *result,
						void *user_data)
{
	struct context *context = user_data;
	const struct test_step *step = context->data->step;
	struct bt_gatt_iter iter;

	g_assert(att_ecode == step->expected_att_ecode);

	if (success) {
		uint16_t length, handle;
		const uint8_t *value;

		g_assert(bt_gatt_iter_init(&iter, result));
		g_assert(bt_gatt_iter_next_read_by_type(&iter, &handle, &length,
								&value));
		g_assert(length == step->length);
		g_assert(!memcmp(value, step->value, length));

		g_assert(!bt_gatt_iter_next_read_by_type(&iter, &handle,
							&length, &value));
	}

	context_quit(context);
}

static void test_read_by_type(gconstpointer data)
{
	struct context *context = create_context(512, data);
	const struct test_data *test_data = data;
	const struct test_step *step = context->data->step;

	g_assert(bt_gatt_read_by_type(context->att, step->handle,
					step->end_handle, test_data->uuid,
					read_by_type_cb, context, NULL));

	execute_context(context);
}

int main(int argc, char *argv[])
{
	struct gatt_db *service_db_1, *ts_small_db;

	g_test_init(&argc, &argv, NULL);

	service_db_1 = make_service_data_1_db();
	ts_small_db = make_test_spec_small_db();

	/*
	 * Server Configuration
	 *
	 * The test group objective is to verify Generic Attribute Profile
	 * Server Configuration.
	 */

	define_test_client("/TP/GAC/CL/BV-01-C", test_client, NULL, NULL,
						raw_pdu(0x02, 0x00, 0x02));

	define_test_server("/TP/GAC/SR/BV-01-C", test_server, service_db_1,
					NULL,
					raw_pdu(0x03, 0x00, 0x02));

	/*
	 * Discovery
	 *
	 * The test group objective is to verify Generic Attribute Profile
	 * Discovery of Services and Service Characteristics.
	 */
	define_test_att("/TP/GAD/CL/BV-01-C", test_search_primary, NULL, NULL,
			raw_pdu(0x02, 0x00, 0x02),
			raw_pdu(0x03, 0x00, 0x02),
			raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
			raw_pdu(0x11, 0x06, 0x10, 0x00, 0x13, 0x00, 0x00, 0x18,
					0x20, 0x00, 0x29, 0x00, 0xb0, 0x68,
					0x30, 0x00, 0x32, 0x00, 0x19, 0x18),
			raw_pdu(0x10, 0x33, 0x00, 0xff, 0xff, 0x00, 0x28),
			raw_pdu(0x11, 0x14, 0x90, 0x00, 0x96, 0x00, 0xef, 0xcd,
					0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
					0x00, 0x00, 0x00, 0x00, 0x85, 0x60,
					0x00, 0x00),
			raw_pdu(0x10, 0x97, 0x00, 0xff, 0xff, 0x00, 0x28),
			raw_pdu(0x01, 0x10, 0x97, 0x00, 0x0a));

	define_test_att("/TP/GAD/CL/BV-01-C-small", test_search_primary, NULL,
			NULL,
			MTU_EXCHANGE_CLIENT_PDUS,
			PRIMARY_DISC_SMALL_DB);

	define_test_server("/TP/GAD/SR/BV-01-C", test_server, service_db_1,
			NULL,
			raw_pdu(0x03, 0x00, 0x02),
			raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
			raw_pdu(0x11, 0x06, 0x01, 0x00, 0x04, 0x00, 0x01, 0x18,
					0x05, 0x00, 0x08, 0x00, 0x0d, 0x18),
			raw_pdu(0x10, 0x06, 0x00, 0xff, 0xff, 0x00, 0x28),
			raw_pdu(0x01, 0x10, 0x06, 0x00, 0x0a));

	define_test_server("/TP/GAD/SR/BV-01-C-small", test_server, ts_small_db,
			NULL,
			raw_pdu(0x03, 0x00, 0x02),
			PRIMARY_DISC_SMALL_DB);

	define_test_att("/TP/GAD/CL/BV-02-C-1", test_search_primary, &uuid_16,
			NULL,
			MTU_EXCHANGE_CLIENT_PDUS,
			raw_pdu(0x06, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28, 0x00,
					0x18),
			raw_pdu(0x07, 0x01, 0x00, 0x07, 0x00),
			raw_pdu(0x06, 0x08, 0x00, 0xff, 0xff, 0x00, 0x28, 0x00,
					0x18),
			raw_pdu(0x01, 0x06, 0x08, 0x00, 0x0a));

	define_test_att("/TP/GAD/CL/BV-02-C-2", test_search_primary, &uuid_128,
			NULL,
			MTU_EXCHANGE_CLIENT_PDUS,
			raw_pdu(0x06, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28, 0xfb,
					0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00,
					0x80, 0x00, 0x10, 0x00, 0x00, 0x0d,
					0x18, 0x00, 0x00),
			raw_pdu(0x07, 0x10, 0x00, 0x17, 0x00),
			raw_pdu(0x06, 0x18, 0x00, 0xff, 0xff, 0x00, 0x28, 0xfb,
					0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00,
					0x80, 0x00, 0x10, 0x00, 0x00, 0x0d,
					0x18, 0x00, 0x00),
			raw_pdu(0x01, 0x06, 0x08, 0x00, 0x0a));

	define_test_att("/TP/GAD/CL/BV-03-C", test_search_included, NULL,
			NULL,
			MTU_EXCHANGE_CLIENT_PDUS,
			raw_pdu(0x08, 0x01, 0x00, 0xff, 0xff, 0x02, 0x28),
			raw_pdu(0x09, 0x08, 0x02, 0x00, 0x10, 0x00, 0x1f, 0x00,
					0x0f, 0x18),
			raw_pdu(0x08, 0x03, 0x00, 0xff, 0xff, 0x02, 0x28),
			raw_pdu(0x09, 0x06, 0x03, 0x00, 0x20, 0x00, 0x2f, 0x00,
					0x04, 0x00, 0x30, 0x00, 0x3f, 0x00),
			raw_pdu(0x0a, 0x20, 0x00),
			raw_pdu(0x0b, 0x00, 0x00, 0x3e, 0x39, 0x00, 0x00, 0x00,
					0x00, 0x01, 0x23, 0x45, 0x67, 0x89,
					0xab, 0xcd, 0xef),
			raw_pdu(0x0a, 0x30, 0x00),
			raw_pdu(0x0b, 0x00, 0x00, 0x3b, 0x39, 0x00, 0x00, 0x00,
					0x00, 0x01, 0x23, 0x45, 0x67, 0x89,
					0xab, 0xcd, 0xef),
			raw_pdu(0x08, 0x05, 0x00, 0xff, 0xff, 0x02, 0x28),
			raw_pdu(0x09, 0x08, 0x05, 0x00, 0x40, 0x00, 0x4f, 0x00,
								0x0a, 0x18),
			raw_pdu(0x08, 0x06, 0x00, 0xff, 0xff, 0x02, 0x28),
			raw_pdu(0x01, 0x08, 0x06, 0x00, 0x0a));

	define_test_att("/TP/GAD/CL/BV-04-C", test_search_chars, NULL,
			NULL,
			MTU_EXCHANGE_CLIENT_PDUS,
			raw_pdu(0x08, 0x10, 0x00, 0x20, 0x00, 0x03, 0x28),
			raw_pdu(0x09, 0x07, 0x11, 0x00, 02, 0x12, 0x00, 0x25,
					0x2a),
			raw_pdu(0x08, 0x12, 0x00, 0x20, 0x00, 0x03, 0x28),
			raw_pdu(0x09, 0x15, 0x13, 0x00, 0x02, 0x14, 0x00, 0x85,
					0x00, 0xef, 0xcd, 0xab, 0x89, 0x67,
					0x45, 0x23, 0x01, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00),
			raw_pdu(0x08, 0x14, 0x00, 0x20, 0x00, 0x03, 0x28),
			raw_pdu(0x01, 0x08, 0x12, 0x00, 0x0a));

	define_test_att("/TP/GAD/CL/BV-06-C", test_search_descs, NULL, NULL,
			MTU_EXCHANGE_CLIENT_PDUS,
			raw_pdu(0x04, 0x13, 0x00, 0x16, 0x00),
			raw_pdu(0x05, 0x01, 0x13, 0x00, 0x02, 0x29, 0x14, 0x00,
					0x03, 0x29),
			raw_pdu(0x04, 0x15, 0x00, 0x16, 0x00),
			raw_pdu(0x05, 0x01, 0x15, 0x00, 0x04, 0x29, 0x16, 0x00,
					0x05, 0x29));

	define_test_client("/TP/GAR/CL/BV-01-C", test_client, service_db_1,
			&test_read_1,
			SERVICE_DATA_1_PDUS,
			raw_pdu(0x0a, 0x03, 0x00),
			raw_pdu(0x0b, 0x01, 0x02, 0x03));

	define_test_client("/TP/GAR/CL/BI-01-C", test_client, service_db_1,
			&test_read_2,
			SERVICE_DATA_1_PDUS,
			raw_pdu(0x0a, 0x00, 0x00),
			raw_pdu(0x01, 0x0a, 0x00, 0x00, 0x01));

	define_test_client("/TP/GAR/CL/BI-02-C", test_client, service_db_1,
			&test_read_3,
			SERVICE_DATA_1_PDUS,
			raw_pdu(0x0a, 0x03, 0x00),
			raw_pdu(0x01, 0x0a, 0x03, 0x00, 0x02));

	define_test_client("/TP/GAR/CL/BI-03-C", test_client, service_db_1,
			&test_read_4,
			SERVICE_DATA_1_PDUS,
			raw_pdu(0x0a, 0x03, 0x00),
			raw_pdu(0x01, 0x0a, 0x03, 0x00, 0x08));

	define_test_att("/TP/GAR/CL/BV-03-C-1", test_read_by_type,
			&uuid_char_16, &test_read_by_type_1,
			raw_pdu(0x02, 0x00, 0x02),
			raw_pdu(0x03, 0x00, 0x02),
			raw_pdu(0x08, 0x01, 0x00, 0xff, 0xff, 0x0d, 0x2a),
			raw_pdu(0x09, 0x05, 0x0a, 0x00, 0x01, 0x02, 0x03),
			raw_pdu(0x08, 0x0b, 0x00, 0xff, 0xff, 0x0d, 0x2a),
			raw_pdu(0x01, 0x08, 0x0b, 0x00, 0x0a));

	define_test_att("/TP/GAR/CL/BV-03-C-2", test_read_by_type,
			&uuid_char_128, &test_read_by_type_1,
			raw_pdu(0x02, 0x00, 0x02),
			raw_pdu(0x03, 0x00, 0x02),
			raw_pdu(0x08, 0x01, 0x00, 0xff, 0xff, 0x0f, 0x0e, 0x0d,
					0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07,
					0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
					0x00),
			raw_pdu(0x09, 0x05, 0x0a, 0x00, 0x01, 0x02, 0x03),
			raw_pdu(0x08, 0x0b, 0x00, 0xff, 0xff, 0x0f, 0x0e, 0x0d,
					0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07,
					0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
					0x00),
			raw_pdu(0x01, 0x08, 0x0b, 0x00, 0x0a));

	define_test_att("/TP/GAR/CL/BI-06-C", test_read_by_type, &uuid_char_16,
			&test_read_by_type_2,
			MTU_EXCHANGE_CLIENT_PDUS,
			raw_pdu(0x08, 0x01, 0x00, 0xff, 0xff, 0x0d, 0x2a),
			raw_pdu(0x01, 0x08, 0x0b, 0x00, 0x02));

	define_test_att("/TP/GAR/CL/BI-07-C", test_read_by_type, &uuid_char_16,
			&test_read_by_type_3,
			MTU_EXCHANGE_CLIENT_PDUS,
			raw_pdu(0x08, 0x01, 0x00, 0xff, 0xff, 0x0d, 0x2a),
			raw_pdu(0x01, 0x08, 0x0b, 0x00, 0x0a));

	define_test_att("/TP/GAR/CL/BI-09-C", test_read_by_type, &uuid_char_16,
			&test_read_by_type_4,
			MTU_EXCHANGE_CLIENT_PDUS,
			raw_pdu(0x08, 0x01, 0x00, 0xff, 0xff, 0x0d, 0x2a),
			raw_pdu(0x01, 0x08, 0x0b, 0x00, 0x08));

	define_test_att("/TP/GAR/CL/BI-10-C", test_read_by_type, &uuid_char_16,
			&test_read_by_type_5,
			MTU_EXCHANGE_CLIENT_PDUS,
			raw_pdu(0x08, 0x01, 0x00, 0xff, 0xff, 0x0d, 0x2a),
			raw_pdu(0x01, 0x08, 0x0b, 0x00, 0x05));

	define_test_att("/TP/GAR/CL/BI-11-C", test_read_by_type, &uuid_char_16,
			&test_read_by_type_6,
			MTU_EXCHANGE_CLIENT_PDUS,
			raw_pdu(0x08, 0x01, 0x00, 0xff, 0xff, 0x0d, 0x2a),
			raw_pdu(0x01, 0x08, 0x0b, 0x00, 0x0c));

	define_test_client("/TP/GAR/CL/BV-05-C", test_client, service_db_1,
			&test_multiple_read_1,
			SERVICE_DATA_1_PDUS,
			raw_pdu(0x0e, 0x03, 0x00, 0x07, 0x00),
			raw_pdu(0x0f, 0x01, 0x02, 0x03));

	define_test_client("/TP/GAR/CL/BI-18-C", test_client, service_db_1,
			&test_multiple_read_2,
			SERVICE_DATA_1_PDUS,
			raw_pdu(0x0e, 0x03, 0x00, 0x07, 0x00),
			raw_pdu(0x01, 0x0e, 0x03, 0x00, 0x02));

	define_test_client("/TP/GAR/CL/BI-19-C", test_client, service_db_1,
			&test_multiple_read_3,
			SERVICE_DATA_1_PDUS,
			raw_pdu(0x0e, 0x03, 0x00, 0x07, 0x00),
			raw_pdu(0x01, 0x0e, 0x03, 0x00, 0x01));

	define_test_client("/TP/GAR/CL/BI-20-C", test_client, service_db_1,
			&test_multiple_read_4,
			SERVICE_DATA_1_PDUS,
			raw_pdu(0x0e, 0x03, 0x00, 0x07, 0x00),
			raw_pdu(0x01, 0x0e, 0x03, 0x00, 0x08));

	define_test_client("/TP/GAR/CL/BI-21-C", test_client, service_db_1,
			&test_multiple_read_5,
			SERVICE_DATA_1_PDUS,
			raw_pdu(0x0e, 0x03, 0x00, 0x07, 0x00),
			raw_pdu(0x01, 0x0e, 0x03, 0x00, 0x05));

	define_test_client("/TP/GAR/CL/BI-21-C", test_client, service_db_1,
			&test_multiple_read_6,
			SERVICE_DATA_1_PDUS,
			raw_pdu(0x0e, 0x03, 0x00, 0x07, 0x00),
			raw_pdu(0x01, 0x0e, 0x03, 0x00, 0x0c));

	return g_test_run();
}
