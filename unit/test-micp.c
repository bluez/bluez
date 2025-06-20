// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2023  NXP Semiconductors. All rights reserved.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>


#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/uuid.h"
#include "src/shared/util.h"
#include "src/shared/tester.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/gatt-helpers.h"
#include "src/shared/micp.h"

struct test_data_mics {
	struct gatt_db *db;
	struct bt_gatt_server *server;
	struct bt_gatt_client *client;
	struct queue *ccc_states;
	size_t iovcnt;
	struct iovec *iov;
	unsigned int micp_id;
};

struct test_data_micp {
	struct gatt_db *db;
	struct bt_micp *micp;
	struct bt_gatt_client *client;
	size_t iovcnt;
	struct iovec *iov;
};

struct ccc_state {
	uint16_t handle;
	uint16_t value;
};

struct notify {
	uint16_t handle, ccc_handle;
	uint8_t *value;
	uint16_t len;
	bt_gatt_server_conf_func_t conf;
	void *user_data;
};

#define MICP_GATT_CLIENT_MTU	64

#define iov_data(args...) ((const struct iovec[]) { args })

#define define_test_mics(name, function, _cfg, args...)		\
	do {							\
		const struct iovec iov[] = { args };		\
		static struct test_data_mics data;			\
		data.iovcnt = ARRAY_SIZE(iov_data(args));	\
		data.iov = util_iov_dup(iov, ARRAY_SIZE(iov_data(args))); \
		tester_add(name, &data, NULL, function,	\
				test_teardown_mics);			\
	} while (0)

#define define_test_micp(name, function, _cfg, args...)		\
	do {							\
		const struct iovec iov[] = { args };		\
		static struct test_data_micp data;			\
		data.iovcnt = ARRAY_SIZE(iov_data(args));	\
		data.iov = util_iov_dup(iov, ARRAY_SIZE(iov_data(args))); \
		tester_add(name, &data, test_setup, function,	\
				test_teardown_micp);			\
	} while (0)

static void print_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	if (tester_use_debug())
		tester_debug("%s%s", prefix, str);
}

static void test_teardown_mics(const void *user_data)
{
	struct test_data_mics *data = (void *)user_data;

	bt_gatt_server_unref(data->server);
	util_iov_free(data->iov, data->iovcnt);
	gatt_db_unref(data->db);
	bt_micp_unregister(data->micp_id);

	queue_destroy(data->ccc_states, free);

	tester_teardown_complete();
}

static void test_teardown_micp(const void *user_data)
{
	struct test_data_micp *data = (void *)user_data;

	bt_micp_unref(data->micp);
	bt_gatt_client_unref(data->client);
	util_iov_free(data->iov, data->iovcnt);
	gatt_db_unref(data->db);

	tester_teardown_complete();
}

static void test_complete_cb(const void *user_data)
{
	tester_test_passed();
}

static void client_ready_cb(bool success, uint8_t att_ecode, void *user_data)
{

	if (!success)
		tester_setup_failed();
	else
		tester_setup_complete();
}

static void micp_write_cb(bool success, uint8_t att_ecode, void *user_data)
{
	if (success)
		printf("MICP Write successful\n");
	else
		printf("\nWrite failed: 0x%02x\n", att_ecode);
}

static void micp_write_value(struct bt_micp *micp, void *user_data)
{
	struct bt_mics *mics = micp_get_mics(micp);
	uint16_t	value_handle;
	int ret;
	uint16_t value = cpu_to_le16(0x0001);

	gatt_db_attribute_get_char_data(mics->ms, NULL, &value_handle,
							NULL, NULL, NULL);

	printf("%s handle: %x\n", __func__, value_handle);
	ret = bt_gatt_client_write_value(micp->client, value_handle,
		(void *)&value, sizeof(value), micp_write_cb, NULL, NULL);

	if (!ret)
		printf("bt_gatt_client_write_value() : Write FAILED");
}

static void micp_ready(struct bt_micp *micp, void *user_data)
{
	micp_write_value(micp, user_data);
}

static void test_client(const void *user_data)
{
	struct test_data_micp *data = (void *)user_data;
	struct io *io;

	io = tester_setup_io(data->iov, data->iovcnt);
	g_assert(io);

	tester_io_set_complete_func(test_complete_cb);

	data->db = gatt_db_new();
	g_assert(data->db);

	data->micp = bt_micp_new(data->db, bt_gatt_client_get_db(data->client));
	g_assert(data->micp);

	bt_micp_set_debug(data->micp, print_debug, "bt_micp: ", NULL);

	bt_micp_ready_register(data->micp, micp_ready, data, NULL);

	bt_micp_attach(data->micp, data->client);
}

static bool ccc_state_match(const void *a, const void *b)
{
	const struct ccc_state *ccc = a;
	uint16_t handle = PTR_TO_UINT(b);

	return ccc->handle == handle;
}

static struct ccc_state *find_ccc_state(struct test_data_mics *data,
			uint16_t handle)
{
	return queue_find(data->ccc_states, ccc_state_match,
				UINT_TO_PTR(handle));
}

static struct ccc_state *get_ccc_state(struct test_data_mics *data,
			uint16_t handle)
{
	struct ccc_state *ccc;

	ccc = find_ccc_state(data, handle);
	if (ccc)
		return ccc;

	ccc = new0(struct ccc_state, 1);
	ccc->handle = handle;
	queue_push_tail(data->ccc_states, ccc);

	return ccc;
}

static void gatt_notify_cb(struct gatt_db_attribute *attrib,
					struct gatt_db_attribute *ccc,
					const uint8_t *value, size_t len,
					struct bt_att *att, void *user_data)
{
	struct test_data_mics *data = user_data;
	struct notify notify;

	memset(&notify, 0, sizeof(notify));

	notify.handle = gatt_db_attribute_get_handle(attrib);
	notify.ccc_handle = gatt_db_attribute_get_handle(ccc);
	notify.value = (void *) value;
	notify.len = len;

	printf("%s: notify.value:%d notify->len:%d\n", __func__,
		(int)*(notify.value), notify.len);
	if (!bt_gatt_server_send_notification(data->server,
			notify.handle, notify.value,
			notify.len, false))
		printf("%s: Failed to send notification\n", __func__);
}

static void gatt_ccc_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct test_data_mics *data = user_data;
	struct ccc_state *ccc;
	uint16_t handle;
	uint8_t ecode = 0;
	const uint8_t *value = NULL;
	size_t len = 0;

	handle = gatt_db_attribute_get_handle(attrib);

	ccc = get_ccc_state(data, handle);
	if (!ccc) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto done;
	}

	len = sizeof(ccc->value);
	value = (void *) &ccc->value;

done:
	gatt_db_attribute_read_result(attrib, id, ecode, value, len);
}

static void micp_attached(struct bt_micp *micp, void *user_data)
{
}

static void micp_detached(struct bt_micp *micp, void *user_data)
{
	bt_micp_unref(micp);
}

static void test_server(const void *user_data)
{
	struct test_data_mics *data = (void *)user_data;
	struct bt_att *att;
	struct io *io;

	io = tester_setup_io(data->iov, data->iovcnt);
	g_assert(io);

	tester_io_set_complete_func(test_complete_cb);

	att = bt_att_new(io_get_fd(io), false);
	g_assert(att);

	bt_att_set_debug(att, BT_ATT_DEBUG, print_debug, "bt_att:", NULL);

	data->db = gatt_db_new();
	g_assert(data->db);

	gatt_db_ccc_register(data->db, gatt_ccc_read_cb, NULL,
					gatt_notify_cb, data);

	bt_micp_add_db(data->db);

	data->micp_id = bt_micp_register(micp_attached, micp_detached, NULL);

	data->server = bt_gatt_server_new(data->db, att, 64, 0);
	g_assert(data->server);

	bt_gatt_server_set_debug(data->server, print_debug, "bt_gatt_server:",
					NULL);

	data->ccc_states = queue_new();

	tester_io_send();

	bt_att_unref(att);
}

/*
 *  ATT: Exchange MTU Request (0x02) len 2
 *       Client RX MTU: 64
 *
 *  ATT: Exchange MTU Response (0x03) len 2
 *        Server RX MTU: 64
 */
#define ATT_EXCHANGE_MTU	IOV_DATA(0x02, 0x40, 0x00), \
	IOV_DATA(0x03, 0x40, 0x00)

/*
 *  ATT: Read By Type Request (0x08) len 6
 *       Handle range: 0x0001-0xffff
 *       Attribute type: Server Supported Features (0x2b3a)
 *
 *  ATT: Error Response (0x01) len 4
 *       Read By Type Request (0x08)
 *       Handle: 0x0001
 *       Error: Attribute Not Found (0x0a)
 */
#define MICP_READ_SR_FEATURE	IOV_DATA(0x08, 0x01, 0x00, 0Xff, 0xff, \
	0x3a, 0x2b), \
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a)

/*
 *  ATT: Read By Group Type Request (0x10) len 6
 *       Handle range: 0x0001-0xffff
 *       Attribute group type: Primary Service (0x2800)
 *
 *  ATT: Read By Group Type Response (0x11) len 7
 *       Attribute data length: 6
 *       Attribute group list: 1 entry
 *       Handle range: 0x0001-0x0004
 *       UUID: Microphone Control (0x184d)
 *
 *  ATT: Read By Group Type Request (0x10) len 6
 *       Handle range: 0x0005-0xffff
 *       Attribute group type: Primary Service (0x2800)
 *
 *  ATT: Error Response (0x01) len 4
 *       Read By Group Type Request (0x10)
 *       Handle: 0x0006
 *       Error: Attribute Not Found (0x0a)
 */
#define MICP_READ_GROUP_TYPE	\
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28), \
	IOV_DATA(0x11, 0x06, \
	0x01, 0x00, 0x04, 0x00, 0x4d, 0x18), \
	IOV_DATA(0x10, 0x05, 0x00, 0xff, 0xff, 0x00, 0x28), \
	IOV_DATA(0x01, 0x10, 0x06, 0x00, 0x0a)

/*
 *  ATT: Read By Group Type Request (0x10) len 6
 *       Handle range: 0x0001-0xffff
 *       Attribute group type: Secondary Service (0x2801)
 *
 *  ATT: Error Response (0x01) len 4
 *       Read By Group Type Request (0x10)
 *       Handle: 0x0001
 *       Error: Attribute Not Found (0x0a)
 */
#define MICP_READ_REQ_SECOND_SERVICE	\
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x01, 0x28), \
	IOV_DATA(0x01, 0x10, 0x01, 0x00, 0x0a)

/*
 *  ATT: Read By Type Request (0x08) len 6
 *       Handle range: 0x0001-0x0004
 *       Attribute type: Include (0x2802)
 *
 *  ATT: Error Response (0x01) len 4
 *       Read By Type Request (0x08)
 *       Handle: 0x0001
 *       Error: Attribute Not Found (0x0a)
 */
#define MICP_READ_REQ_INCLUDE_SERVICE	\
	IOV_DATA(0x08, 0x01, 0x00, 0x04, 0x00, 0x02, 0x28), \
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a)

/*  ATT: Find Information Request (0x04) len 4
 *      Handle range: 0x0004-0x0004
 */
#define	MICP_FIND_INFO_REQ	\
	IOV_DATA(0x04, 0x04, 0x00, 0x04, 0x00), \
	IOV_DATA(0x05, 0x01, 0x04, 0x00, 0x02, 0x29)

/*
 *  ATT: Read By Type Request (0x08) len 6
 *       Handle range: 0x0001-0x0004
 *       Attribute type: Characteristic (0x2803)
 *
 *  ATT: Read By Type Response (0x09) len 8
 *       Attribute data length: 7
 *       Attribute data list: 1 entry
 *       Handle: 0x0002
 *       Value: 1a0300c32b
 *
 *  ATT: Read By Type Request (0x08) len 6
 *       Handle range: 0x0003-0x0004
 *       Attribute type: Characteristic (0x2803)
 *
 *  ATT: Error Response (0x01) len 4
 *       Read By Type Request (0x08)
 *       Handle: 0x0004
 *       Error: Attribute Not Found (0x0a)
 */
#define	MICP_READ_REQ_CHAR	\
	IOV_DATA(0x08, 0x01, 0x00, 0x04, 0x00, 0x03, 0x28),\
	IOV_DATA(0x09, 0x07, \
	0x02, 0x00, 0x1a, 0x03, 0x00, 0xc3, 0x2b), \
	IOV_DATA(0x08, 0x03, 0x00, 0x04, 0x00, 0x03, 0x28), \
	IOV_DATA(0x01, 0x08, 0x04, 0x00, 0x0a)
/*
 *  ATT: Read Request (0x0a) len 2
 *       Handle: 0x0003
 *
 *  ATT: Read Response (0x0b) len 1
 */
#define	MICS_MUTE_READ \
	IOV_DATA(0x0a, 0x03, 0x00), \
	IOV_DATA(0x0b, 0x01)

/*
 *  ATT: Write Request (0x12) len 4
 *       Handle: 0x0004
 *       Data: 0100
 *  ATT: Write Response (0x13) len 0
 */
#define	MICS_EN_MUTE_DISCPTR	\
	IOV_DATA(0x12, 0x04, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13)

#define	MICS_MUTE_WRITE	\
	IOV_DATA(0x12, 0x03, 0x00, 0x01),\
	IOV_DATA(0x13)

#define MICP_CL_CGGIT_SER_BV_01_C \
	MICS_MUTE_READ, \
	MICS_EN_MUTE_DISCPTR, \
	IOV_DATA(0x12, 0x03, 0x00, 0x01, 0x00), \
	IOV_DATA(0x01, 0x12, 0x03, 0x00, 0x013)

#define	MICP_CL_CGGIT_CHA_BV_01_C	\
	MICS_MUTE_READ, \
	MICS_EN_MUTE_DISCPTR, \
	IOV_DATA(0x12, 0x03, 0x00, 0x01, 0x00), \
	IOV_DATA(0x013)

#define MICP_CL_SPE_BI_01_C	\
	MICS_MUTE_READ, \
	MICS_EN_MUTE_DISCPTR, \
	IOV_DATA(0x12, 0x03, 0x00, 0x01, 0x00), \
	IOV_DATA(0x01, 0x12, 0x03, 0x00, 0x80)

/* GATT Discover All procedure */
static const struct iovec setup_data[] = {
				ATT_EXCHANGE_MTU,
				MICP_READ_SR_FEATURE,
				MICP_READ_GROUP_TYPE,
				MICP_READ_REQ_SECOND_SERVICE,
				MICP_READ_REQ_INCLUDE_SERVICE,
				MICP_READ_REQ_CHAR,
				MICP_FIND_INFO_REQ
};

static void test_setup(const void *user_data)
{
	struct test_data_micp *data = (void *)user_data;
	struct bt_att *att;
	struct gatt_db *db;
	struct io *io;

	io = tester_setup_io(setup_data, ARRAY_SIZE(setup_data));
	g_assert(io);

	att = bt_att_new(io_get_fd(io), false);
	g_assert(att);

	bt_att_set_debug(att, BT_ATT_DEBUG, print_debug, "bt_att:", NULL);

	db = gatt_db_new();
	g_assert(db);

	data->client = bt_gatt_client_new(db, att, MICP_GATT_CLIENT_MTU, 0);
	g_assert(data->client);

	bt_gatt_client_set_debug(data->client, print_debug, "bt_gatt_client:",
						NULL);

	bt_gatt_client_ready_register(data->client, client_ready_cb, data,
						NULL);

	bt_att_unref(att);
	gatt_db_unref(db);
}

/*
 *  ATT: Write Request (0x12) len 3
 *       Handle: 0x0003
 *       Data: 00
 *
 *  ATT: Write Response (0x13) len 0
 */
#define	MICS_MUTE_WRITE_VAL_00 \
	IOV_DATA(0x12, 0x03, 0x00, 0x00), \
	IOV_DATA(0x13)

/*
 *  ATT: Write Request (0x12) len 3
 *       Handle: 0x0003
 *       Data: 01
 *
 *  ATT: Write Response (0x13) len 0
 */
#define	MICS_MUTE_WRITE_VAL_01 \
	IOV_DATA(0x12, 0x03, 0x00, 0x01), \
	IOV_DATA(0x13)
/*
 *  ATT: Read Request (0x0a) len 2
 *       Handle: 0x0003
 *
 *  ATT: Read Response (0x0b) len 1
 */
#define	MICS_MUTE_READ \
	IOV_DATA(0x0a, 0x03, 0x00), \
	IOV_DATA(0x0b, 0x01)

/*
 *  ATT: Read By Group Type Request (0x10) len 6
 *       Handle range: 0x0001-0xffff
 *       Attribute group type: Primary Service (0x2800)
 *
 *  ATT: Read By Group Type Response (0x11) len 7
 *       Attribute data length: 6
 *       Attribute group list: 1 entry
 *       Handle range: 0x0001-0x0004
 *       UUID: Microphone Control (0x184d)
 *
 *  ATT: Read By Group Type Request (0x10) len 6
 *      Handle range: 0x0005-0xffff
 *      Attribute group type: Primary Service (0x2800)
 *
 *  ATT: Error Response (0x01) len 4
 *      Read By Group Type Request (0x10)
 *      Handle: 0x0005
 *      Error: Attribute Not Found (0x0a)
 */
#define DISCOVER_PRIM_SERV_NOTIF \
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28), \
	IOV_DATA(0x11, 0x06, 0x01, 0x00, 0x04, 0x00, 0x4d, 0x18), \
	IOV_DATA(0x10, 0x05, 0x00, 0xff, 0xff, 0x00, 0x28), \
	IOV_DATA(0x01, 0x10, 0x05, 0x00, 0x0a)

/*
 *  ATT: Read By Type Request (0x08) len 6
 *       Handle range: 0x0001-0x0005
 *       Attribute type: Characteristic (0x2803)
 *
 *  ATT: Read By Type Response (0x09) len 8
 *       Attribute data length: 7
 *       Attribute data list: 1 entry
 *       Handle: 0x0002
 *       Value: 1a0300c32b
 *
 *  ATT: Read By Type Request (0x08) len 6
 *       Handle range: 0x0005-0x0005
 *       Attribute type: Characteristic (0x2803)
 *
 *  ATT: Error Response (0x01) len 4
 *       Read By Type Request (0x08)
 *       Handle: 0x0005
 *       Error: Attribute Not Found (0x0a)
 */
#define DISC_MICS_CHAR_1 \
	IOV_DATA(0x08, 0x01, 0x00, 0x05, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		0x02, 0x00, 0x1a, 0x03, 0x00, 0xc3, 0x2b), \
	IOV_DATA(0x08, 0x05, 0x00, 0x05, 0x00, 0x03, 0x28), \
	IOV_DATA(0x01, 0x08, 0x05, 0x00, 0x0a)

/*
 *  ATT: Find By Type Value Request (0x06) len 8
 *       Handle range: 0x0001-0xffff
 *       Attribute type: Primary Service (0x2800)
 *       UUID: Microphone Control (0x184d)
 *
 *  ATT: Find By Type Value Response (0x07) len 4
 *       Handle range: 0x0001-0x0004
 *
 *  ATT: Find By Type Value Request (0x06) len 8
 *       Handle range: 0x0005-0xffff
 *       Attribute type: Primary Service (0x2800)
 *       UUID: Microphone Control (0x184d)
 *
 *  ATT: Error Response (0x01) len 4
 *       Find By Type Value Request (0x06)
 *       Handle: 0x0005
 *       Error: Attribute Not Found (0x0a)
 */
#define MICS_FIND_BY_TYPE_VALUE \
	IOV_DATA(0x06, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28, 0x4d, 0x18), \
	IOV_DATA(0x07, 0x01, 0x00, 0x04, 0x00), \
	IOV_DATA(0x06, 0x05, 0x00, 0xff, 0xff, 0x00, 0x28, 0x4d, 0x18), \
	IOV_DATA(0x01, 0x06, 0x05, 0x00, 0x0a)

/*
 *  ATT: Read By Type Request (0x08) len 6
 *       Handle range: 0x0001-0x0005
 *       Attribute type: Characteristic (0x2803)
 *
 *  ATT: Read By Type Response (0x09) len 8
 *       Attribute data length: 7
 *       Attribute data list: 1 entry
 *       Handle: 0x0002
 *       Value: 1a0300c32b
 *
 *  ATT: Read By Type Request (0x08) len 6
 *       Handle range: 0x0003-0x0005
 *       Attribute type: Characteristic (0x2803)
 *
 *  ATT: Error Response (0x01) len 4
 *       Read By Type Request (0x08)
 *       Handle: 0x0003
 *       Error: Attribute Not Found (0x0a)
 */
#define DISC_MICS_CHAR_AFTER_TYPE \
	IOV_DATA(0x08, 0x01, 0x00, 0x05, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		0x02, 0x00, 0x1a, 0x03, 0x00, 0xc3, 0x2b), \
	IOV_DATA(0x08, 0x03, 0x00, 0x05, 0x00, 0x03, 0x28), \
	IOV_DATA(0x01, 0x08, 0x03, 0x00, 0x0a)

/*
 *  ATT: Write Request (0x12) len 4
 *       Handle: 0x0004
 *       Data: 0000
 *
 *  ATT: Write Response (0x13) len 0
 *
 *  ATT: Write Request (0x12) len 4
 *       Handle: 0x0004
 *       Data: 0100
 *
 *  ATT: Write Response (0x13) len 0
 */
#define MICS_WRITE_CCD \
	IOV_DATA(0x12, 0x04, 0x00, 0x00, 0x00), \
	IOV_DATA(0x13), \
	IOV_DATA(0x12, 0x04, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13)

/*
 *  ATT: Find Information Request (0x04) len 4
 *       Handle range: 0x0004-0x0005
 *
 *  ATT: Find Information Response (0x05) len 5
 *       Format: UUID-16 (0x01)
 *       Handle: 0x0004
 *       UUID: Client Characteristic Configuration (0x2902)
 *
 *  ATT: Find Information Request (0x04) len 4
 *       Handle range: 0x0005-0x0005
 *
 *  ATT: Error Response (0x01) len 4
 *       Find Information Request (0x04)
 *       Handle: 0x0005
 *       Error: Attribute Not Found (0x0a)
 */
#define MICS_FIND_INFO \
	IOV_DATA(0x04, 0x04, 0x00, 0x05, 0x00), \
	IOV_DATA(0x05, 0x01, 0x04, 0x00, 0x02, 0x29), \
	IOV_DATA(0x04, 0x05, 0x00, 0x05, 0x00), \
	IOV_DATA(0x01, 0x04, 0x05, 0x00, 0x0a)

/*
 * 1.reads the characteristic value for the
 *  Mute characteristic
 * 2.update the Mute characteristic to 0 or 1
 * 3.sends a notification containing the updated value
 *  of the Mute characteristic
 * 4.update the Mute characteristic to 0 or 1 which ever
 *  different than step 2
 * 5.sends a notification containing the updated value of
 *  the Mute characteristic
 */
#define MICS_SR_SPN_BV_01_C \
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	DISC_MICS_CHAR_1, \
	MICS_FIND_BY_TYPE_VALUE, \
	DISC_MICS_CHAR_AFTER_TYPE, \
	MICS_FIND_INFO, \
	MICS_WRITE_CCD, \
	IOV_DATA(0x0a, 0x03, 0x00), \
	IOV_DATA(0x0b, 0x01), \
	MICS_MUTE_WRITE_VAL_00, \
	IOV_DATA(0x1b, 0x03, 0x00, 0x00), \
	MICS_MUTE_WRITE_VAL_01, \
	IOV_DATA(0x1b, 0x03, 0x00, 0x01), \
	IOV_DATA(0x0a, 0x03, 0x00), \
	IOV_DATA(0x0b, 0x01)

#define MICS_SR_SGGIT_SER_BV_01_C \
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	MICS_FIND_BY_TYPE_VALUE

#define MICS_SR_SGGIT_CHA_BV_01_C \
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	MICS_FIND_BY_TYPE_VALUE, \
	DISC_MICS_CHAR_AFTER_TYPE

/*
 *  ATT: Write Request (0x12) len 3
 *       Handle: 0x0003
 *       Data: 02
 *
 *  ATT: Error Response (0x01) len 4
 *       Write Request (0x12)
 *       Handle: 0x0003
 *       Error: Value Not Allowed (0x13)
 *
 *  ATT: Write Request (0x12) len 3
 *       Handle: 0x0003
 *       Data: 05
 *
 *  ATT: Error Response (0x01) len 4
 *       Write Request (0x12)
 *       Handle: 0x0003
 *       Error: Value Not Allowed (0x13)
 */
#define MICS_WRITE_MUTE_CHAR_INVALID \
	IOV_DATA(0x12, 0x03, 0x00, 0x02), \
	IOV_DATA(0x01, 0x12, 0x03, 0x00, 0x13), \
	IOV_DATA(0x12, 0x03, 0x00, 0x05), \
	IOV_DATA(0x01, 0x12, 0x03, 0x00, 0x13)

#define MICS_SR_SPE_BI_1_C	\
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	MICS_FIND_BY_TYPE_VALUE, \
	MICS_WRITE_MUTE_CHAR_INVALID

/*
 *  ATT: Read Request (0x0a) len 2
 *       Handle: 0x0003
 *
 *  ATT: Read Response (0x0b) len 1
 */
#define	MICS_MUTE_READ_INVALID \
	IOV_DATA(0x0a, 0x03, 0x00), \
	IOV_DATA(0x0b, 0x02)

/*
 *  ATT: Write Request (0x12) len 3
 *       Handle: 0x0003
 *       Data: 01
 *
 *  ATT: Error Response (0x01) len 4
 *       Write Request (0x12)
 *       Handle: 0x0003
 *       Error: Reserved (0x80)
 */
#define	MICS_MUTE_WRITE_1 \
	IOV_DATA(0x12, 0x03, 0x00, 0x01), \
	IOV_DATA(0x01, 0x12, 0x03, 0x00, 0x80)

/*
 *  ATT: Write Request (0x12) len 3
 *       Handle: 0x0003
 *       Data: 00
 *
 *  ATT: Error Response (0x01) len 4
 *       Write Request (0x12)
 *       Handle: 0x0003
 *       Error: Reserved (0x80)
 */
#define	MICS_MUTE_WRITE_0 \
	IOV_DATA(0x12, 0x03, 0x00, 0x00), \
	IOV_DATA(0x01, 0x12, 0x03, 0x00, 0x80)

#define MICS_SR_SPE_BI_02_C	\
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	MICS_FIND_BY_TYPE_VALUE, \
	MICS_MUTE_READ_INVALID, \
	MICS_MUTE_WRITE_0, \
	MICS_MUTE_WRITE_1

int main(int argc, char *argv[])
{

	tester_init(&argc, &argv);

    /* MICS Testcases */
	define_test_mics("MICS/SR/SGGIT/SER/BV-01-C", test_server, NULL,
					MICS_SR_SGGIT_SER_BV_01_C);
	define_test_mics("MICS/SR/SGGIT/CHA/BV-01-C", test_server, NULL,
					MICS_SR_SGGIT_CHA_BV_01_C);
	define_test_mics("MICS/SR/SPE/BI-01-C", test_server, NULL,
					MICS_SR_SPE_BI_1_C);

	/* MICS/SR/SPE/BI-02-C:
	 * In function *mics_new(struct gatt_db *db)[src/shared/micp.c]
	 * by default the mics->mute_stat is set to MICS_MUTED[0x01].
	 * As per test specs, Testcase MICS/SR/SPE/BI-02-C, Initial
	 * condition of mute state should be MICS_DISABLED[0x02].
	 * To verify this Unit test case we have to modify the initial
	 * state of mics->mute_stat to MICS_DISABLED in code
	 * [in func mics_new()], build it and run bluetoothd. Then run
	 * this unit test case and this test case will Pass.
	 */
	/* define_test_mics("MICS/SR/SPE/BI-02-C", test_server, NULL,
	 *				MICS_SR_SPE_BI_02_C);
	 */
	define_test_mics("MICS/SR/SPN/BV-01-C", test_server, NULL,
					MICS_SR_SPN_BV_01_C);

    /* MICP Testcases */
	define_test_micp("MICP/CL/CGGIT/SER/BV-01-C", test_client, NULL,
					MICP_CL_CGGIT_SER_BV_01_C);
	define_test_micp("MICP/CL/CGGIT/CHA/BV-01-C", test_client, NULL,
					MICP_CL_CGGIT_CHA_BV_01_C);
	define_test_micp("MICP/CL/SPE/BI-01-C", test_client, NULL,
					MICP_CL_SPE_BI_01_C);

	return tester_run();
}
