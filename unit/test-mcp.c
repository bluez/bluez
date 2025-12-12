// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation.
 *  Copyright 2024 NXP
 *  Copyright (C) 2025  Pauli Virtanen.
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

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"
#include "src/shared/util.h"
#include "src/shared/tester.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gatt-server.h"
#include "src/shared/io.h"
#include "src/shared/mcp.h"
#include "src/shared/mcs.h"

struct test_config {
	bool gmcs;
	const struct bt_mcs_callback *mcs_cb;
	const struct bt_mcp_callback *mcp_cb;
	const struct bt_mcp_listener_callback *listener_cb;
	const struct iovec *setup_data;
	const size_t setup_data_len;
	uint8_t expect_cmd;
	uint8_t expect_cmd_result;
	uint8_t state;
};

struct test_data {
	struct gatt_db *db;
	struct bt_gatt_server *server;
	struct bt_gatt_client *client;
	struct queue *ccc_states;
	struct bt_mcp *mcp;
	struct bt_mcs *mcs;
	unsigned int id;
	unsigned int step;
	size_t iovcnt;
	struct iovec *iov;
	const struct test_config *cfg;
};

struct ccc_state {
	uint16_t handle;
	uint16_t value;
};

#define FAIL_TEST() \
	do { tester_warn("%s:%d: failed in %s", __FILE__, __LINE__, __func__); \
		tester_test_failed(); } while (0)

#define iov_data(args...) ((const struct iovec[]) { args })

#define define_test(name, setup, function, _cfg, args...)	\
	do {							\
		const struct iovec iov[] = { args };		\
		static struct test_data data;			\
		data.iovcnt = ARRAY_SIZE(iov);			\
		data.iov = data.iovcnt ?			\
			util_iov_dup(iov, data.iovcnt) : NULL;	\
		data.cfg = _cfg;				\
		tester_add(name, &data, setup, function,	\
				test_teardown);			\
	} while (0)

static void print_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	if (tester_use_debug())
		tester_debug("%s%s", prefix, str);
}

static void mcp_debug(void *data, const char *str)
{
	print_debug(str, "mcp: ");
}

static void mcs_debug(void *data, const char *str)
{
	print_debug(str, "mcs: ");
}

static void test_teardown(const void *user_data)
{
	struct test_data *data = (void *)user_data;

	bt_gatt_client_unref(data->client);

	bt_gatt_server_unref(data->server);
	util_iov_free(data->iov, data->iovcnt);

	gatt_db_unref(data->db);

	bt_mcp_detach(data->mcp);

	bt_mcs_unregister(data->mcs);

	queue_destroy(data->ccc_states, free);

	tester_teardown_complete();
}

/* ATT: Exchange MTU Response (0x03) len 2
 *   Server RX MTU: 64
 * ATT: Exchange MTU Request (0x02) len 2
 *    Client RX MTU: 64
 * ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0001-0xffff
 *   Attribute type: Server Supported Features (0x2b3a)
 * ATT: Error Response (0x01) len 4
 *   Read By Type Request (0x08)
 *   Handle: 0x0001
 *   Error: Attribute Not Found (0x0a)
 */
#define MCS_MTU_FEAT \
	IOV_DATA(0x02, 0x40, 0x00), \
	IOV_DATA(0x03, 0x40, 0x00), \
	IOV_DATA(0x08, 0x01, 0x00, 0xff, 0xff, 0x3a, 0x2b), \
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a)

/* ATT: Read By Group Type Request (0x10) len 6
 *   Handle range: 0x0001-0xffff
 *   Attribute group type: Primary Service (0x2800)
 * ATT: Read By Group Type Response (0x11) len 37
 *   Attribute data length: 6
 *   Attribute group list: 1 entries
 *   Handle range: 0x0001-0x0026
 *   UUID: (Generic) Media Control Service (0x1849 / 0x1848)
 * ATT: Read By Group Type Request (0x10) len 6
 *   Handle range: 0x0027-0xffff
 *   Attribute group type: Primary Service (0x2800)
 * ATT: Error Response (0x01) len 4
 *   Read By Group Type Request (0x10)
 *   Handle: 0x0004
 *   Error: Attribute Not Found (0x0a)
 */
#define MCS_PRIMARY_SERVICE(base, uuid...) \
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28), \
	IOV_DATA(0x11, 0x06, \
		base + 0x01, 0x00, base + 0x26, 0x00, uuid), \
	IOV_DATA(0x10, base + 0x27, 0x00, 0xff, 0xff, 0x00, 0x28), \
	IOV_DATA(0x01, 0x10, base + 0x27, 0x00, 0x0a)

#define MCS_SERVICE	0x48, 0x18
#define GMCS_SERVICE	0x49, 0x18

/* ATT: Read By Group Type Request (0x10) len 6
 *   Handle range: 0x0001-0xffff
 *   Attribute group type: Secondary Service (0x2801)
 * ATT: Error Response (0x01) len 4
 *   Read By Group Type Request (0x10)
 *   Handle: 0x0001
 *   Error: Attribute Not Found (0x0a)
 */
#define NO_SECONDARY_SERVICE \
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x01, 0x28), \
	IOV_DATA(0x01, 0x10, 0x01, 0x00, 0x0a)

/* ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0001-0x0026
 *   Attribute group type: Include (0x2802)
 * ATT: Error Response (0x01) len 4
 *   Read By Group Type Request (0x10)
 *   Handle: 0x0001
 *   Error: Attribute Not Found (0x0a)
 */
#define NO_INCLUDE(base) \
	IOV_DATA(0x08, 0x01+base, 0x00, 0x26+base, 0x00, 0x02, 0x28), \
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a)

/* ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0001-0x0003
 *   Attribute type: Characteristic (0x2803)
 * ATT: Read By Type Response (0x09) len 57
 *   ...
 * ATT: Read By Type Request (0x08) len 6
 *   ...
 *   Attribute type: Characteristic (0x2803)
 * ATT: Read By Type Response (0x09) len 57
 *   ...
 * ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0026-0x0026
 *   Attribute type: Characteristic (0x2803)
 * ATT: Error Response (0x01) len 4
 *   Read By Type Request (0x08)
 *   Handle: 0x0026
 *   Error: Attribute Not Found (0x0a)
 * ATT: Find Information Request (0x04)
 * ATT: Error Response
 */
#define IOV_CONTENT(data...)	data

#define HND(value)			((value) & 0xff), ((value) >> 8)
#define FIND_CHRC(vhnd, prop, uuid...)	HND(vhnd-1), prop, HND(vhnd), uuid

#define NAME			0x03
#define NAME_CCC		0x04
#define TRACK_CHG		0x06
#define TRACK_CHG_CCC		0x07
#define TRACK_TITLE		0x09
#define TRACK_TITLE_CCC		0x0a
#define TRACK_DUR		0x0c
#define TRACK_DUR_CCC		0x0d
#define TRACK_POS		0x0f
#define TRACK_POS_CCC		0x10
#define PLAY_SPEED		0x12
#define PLAY_SPEED_CCC		0x13
#define SEEK_SPEED		0x15
#define SEEK_SPEED_CCC		0x16
#define PLAY_ORDER		0x18
#define PLAY_ORDER_CCC		0x19
#define PLAY_ORDER_SUPP		0x1b
#define STATE			0x1d
#define STATE_CCC		0x1e
#define CP			0x20
#define CP_CCC			0x21
#define CP_SUPP			0x23
#define CP_SUPP_CCC		0x24
#define CCID			0x26

#define PROP_R			0x02
#define PROP_N			0x10
#define PROP_RN			0x12
#define PROP_RW			0x0e
#define PROP_WN			0x1c
#define PROP_RWN		0x1e

#define GMCS_FIND_CHRC(base) \
	IOV_DATA(0x08, 0x01+base, 0x00, 0x26+base, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		FIND_CHRC(NAME+base, PROP_RN, 0x93, 0x2b), \
		FIND_CHRC(TRACK_CHG+base, PROP_N, 0x96, 0x2b), \
		FIND_CHRC(TRACK_TITLE+base, PROP_RN, 0x97, 0x2b), \
		FIND_CHRC(TRACK_DUR+base, PROP_RN, 0x98, 0x2b), \
		FIND_CHRC(TRACK_POS+base, PROP_RWN, 0x99, 0x2b), \
		FIND_CHRC(PLAY_SPEED+base, PROP_RWN, 0x9a, 0x2b), \
		FIND_CHRC(SEEK_SPEED+base, PROP_RN, 0x9b, 0x2b), \
		FIND_CHRC(PLAY_ORDER+base, PROP_RWN, 0xa1, 0x2b)), \
	IOV_DATA(0x08, PLAY_ORDER+base, 0x00, 0x26+base, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		FIND_CHRC(PLAY_ORDER_SUPP+base, PROP_R, 0xa2, 0x2b), \
		FIND_CHRC(STATE+base, PROP_RN, 0xa3, 0x2b), \
		FIND_CHRC(CP+base, PROP_WN, 0xa4, 0x2b), \
		FIND_CHRC(CP_SUPP+base, PROP_RN, 0xa5, 0x2b), \
		FIND_CHRC(CCID+base, PROP_R, 0xba, 0x2b)), \
	IOV_DATA(0x08, CCID+base, 0x00, CCID+base, 0x00, 0x03, 0x28), \
	IOV_DATA(0x01, 0x08, CCID+base, 0x00, 0x0a)

/* As above but without optional Notify properties, and
 * ATT: Find Information Request (0x04)
 * ATT: Error Response (0x01) Attribute Not Found (0x0a)
 * for each missing CCC HND to keep handles the same.
 * Not valid for GMCS!
 */
#define MCS_FIND_CHRC(base) \
	IOV_DATA(0x08, 0x01+base, 0x00, 0x26+base, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		FIND_CHRC(NAME+base, PROP_R, 0x93, 0x2b), \
		FIND_CHRC(TRACK_CHG+base, PROP_N, 0x96, 0x2b), \
		FIND_CHRC(TRACK_TITLE+base, PROP_R, 0x97, 0x2b), \
		FIND_CHRC(TRACK_DUR+base, PROP_R, 0x98, 0x2b), \
		FIND_CHRC(TRACK_POS+base, PROP_RW, 0x99, 0x2b), \
		FIND_CHRC(PLAY_SPEED+base, PROP_RW, 0x9a, 0x2b), \
		FIND_CHRC(SEEK_SPEED+base, PROP_R, 0x9b, 0x2b), \
		FIND_CHRC(PLAY_ORDER+base, PROP_RW, 0xa1, 0x2b)), \
	IOV_DATA(0x08, PLAY_ORDER+base, 0x00, 0x26+base, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		FIND_CHRC(PLAY_ORDER_SUPP+base, PROP_R, 0xa2, 0x2b), \
		FIND_CHRC(STATE+base, PROP_RN, 0xa3, 0x2b), \
		FIND_CHRC(CP+base, PROP_WN, 0xa4, 0x2b), \
		FIND_CHRC(CP_SUPP+base, PROP_R, 0xa5, 0x2b), \
		FIND_CHRC(CCID+base, PROP_R, 0xba, 0x2b)), \
	IOV_DATA(0x08, CCID+base, 0x00, CCID+base, 0x00, 0x03, 0x28), \
	IOV_DATA(0x01, 0x08, CCID+base, 0x00, 0x0a), \
	IOV_DATA(0x04, HND(NAME_CCC), HND(NAME_CCC)), \
	IOV_DATA(0x01, 0x04, HND(NAME_CCC), 0x0a), \
	IOV_DATA(0x04, HND(TRACK_TITLE_CCC), HND(TRACK_TITLE_CCC)), \
	IOV_DATA(0x01, 0x04, HND(TRACK_TITLE_CCC), 0x0a), \
	IOV_DATA(0x04, HND(TRACK_DUR_CCC), HND(TRACK_DUR_CCC)), \
	IOV_DATA(0x01, 0x04, HND(TRACK_DUR_CCC), 0x0a), \
	IOV_DATA(0x04, HND(TRACK_POS_CCC), HND(TRACK_POS_CCC)), \
	IOV_DATA(0x01, 0x04, HND(TRACK_POS_CCC), 0x0a), \
	IOV_DATA(0x04, HND(PLAY_SPEED_CCC), HND(PLAY_SPEED_CCC)), \
	IOV_DATA(0x01, 0x04, HND(PLAY_SPEED_CCC), 0x0a), \
	IOV_DATA(0x04, HND(SEEK_SPEED_CCC), HND(SEEK_SPEED_CCC)), \
	IOV_DATA(0x01, 0x04, HND(SEEK_SPEED_CCC), 0x0a), \
	IOV_DATA(0x04, HND(PLAY_ORDER_CCC), HND(PLAY_ORDER_CCC)), \
	IOV_DATA(0x01, 0x04, HND(PLAY_ORDER_CCC), 0x0a), \
	IOV_DATA(0x04, HND(CP_SUPP_CCC), HND(CP_SUPP_CCC)), \
	IOV_DATA(0x01, 0x04, HND(CP_SUPP_CCC), 0x0a)

/* ACL Data TX: Handle 42 flags 0x00 dlen 11
 *   ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0001-0xffff
 *   Attribute type: Database Hash (0x2b2a)
 * ATT: Error Response (0x01) len 4
 *   Read By Type Request (0x08)
 *   Handle: 0x0001
 *   Error: Attribute Not Found (0x0a)
 */
#define NO_DATABASE_HASH \
	IOV_DATA(0x08, 0x01, 0x00, 0xff, 0xff, 0x2a, 0x2b), \
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a)

/* GATT Discover All procedure */
#define GMCS_SETUP(base, uuid...) \
	MCS_MTU_FEAT, \
	MCS_PRIMARY_SERVICE(base, uuid), \
	NO_SECONDARY_SERVICE, \
	NO_INCLUDE(base), \
	GMCS_FIND_CHRC(base)

#define MCS_SETUP(base, uuid...) \
	MCS_MTU_FEAT, \
	MCS_PRIMARY_SERVICE(base, uuid), \
	NO_SECONDARY_SERVICE, \
	NO_INCLUDE(base), \
	MCS_FIND_CHRC(base)

static bool ccc_state_match(const void *a, const void *b)
{
	const struct ccc_state *ccc = a;
	uint16_t handle = PTR_TO_UINT(b);

	return ccc->handle == handle;
}

static struct ccc_state *find_ccc_state(struct test_data *data,
				uint16_t handle)
{
	return queue_find(data->ccc_states, ccc_state_match,
				UINT_TO_PTR(handle));
}

static struct ccc_state *get_ccc_state(struct test_data *data,
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
	struct test_data *data = user_data;
	uint16_t handle = gatt_db_attribute_get_handle(attrib);

	if (tester_use_debug())
		tester_debug("handle 0x%04x len %zd", handle, len);

	if (!data->server) {
		if (tester_use_debug())
			tester_debug("data->server %p", data->server);
		return;
	}

	if (!bt_gatt_server_send_notification(data->server,
			handle, value, len, false))
		tester_debug("%s: Failed to send notification", __func__);
}

static void gatt_ccc_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct test_data *data = user_data;
	struct ccc_state *ccc;
	uint16_t handle;
	uint8_t ecode = 0;
	uint16_t value = 0;

	handle = gatt_db_attribute_get_handle(attrib);

	ccc = get_ccc_state(data, handle);
	if (!ccc) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto done;
	}

	value = cpu_to_le16(ccc->value);

done:
	gatt_db_attribute_read_result(attrib, id, ecode, (void *)&value,
							sizeof(value));
}

static void setup_complete_cb(const void *user_data)
{
	tester_setup_complete();
}

static void test_setup_server(const void *user_data)
{
	struct test_data *data = (void *)user_data;
	const struct test_config *cfg = data->cfg;
	struct bt_att *att;
	struct gatt_db *db;
	struct io *io;

	bt_mcs_test_util_reset_ccid();

	io = tester_setup_io(cfg->setup_data, cfg->setup_data_len);
	g_assert(io);

	tester_io_set_complete_func(setup_complete_cb);

	db = gatt_db_new();
	g_assert(db);

	gatt_db_ccc_register(db, gatt_ccc_read_cb, NULL, gatt_notify_cb, data);

	data->ccc_states = queue_new();

	data->mcs = bt_mcs_register(db, data->cfg->gmcs, data->cfg->mcs_cb,
									data);

	att = bt_att_new(io_get_fd(io), false);
	g_assert(att);
	bt_att_set_debug(att, BT_ATT_DEBUG, print_debug, "bt_att:", NULL);

	data->server = bt_gatt_server_new(db, att, 64, 0);
	g_assert(data->server);
	bt_gatt_server_set_debug(data->server, print_debug, "bt_gatt_server:",
						NULL);

	tester_io_send();

	bt_att_unref(att);
	gatt_db_unref(db);
}

static void test_complete_cb(const void *user_data)
{
	struct test_data *data = (void *)user_data;

	if (!data->step)
		tester_test_passed();
}

static void test_server(const void *user_data)
{
	struct test_data *data = (void *)user_data;
	struct io *io;

	io = tester_setup_io(data->iov, data->iovcnt);
	g_assert(io);

	tester_io_set_complete_func(test_complete_cb);

	tester_io_send();
}

static void setup_ready_cb(bool success, uint8_t att_ecode, void *user_data)
{
	if (!success)
		tester_setup_failed();
	else
		tester_setup_complete();
}

static void test_setup(const void *user_data)
{
	struct test_data *data = (void *)user_data;
	const struct test_config *cfg = data->cfg;
	struct bt_att *att;
	struct gatt_db *db;
	struct io *io;

	io = tester_setup_io(cfg->setup_data, cfg->setup_data_len);
	g_assert(io);

	att = bt_att_new(io_get_fd(io), false);
	g_assert(att);

	bt_att_set_debug(att, BT_ATT_DEBUG, print_debug, "bt_att:", NULL);

	db = gatt_db_new();
	g_assert(db);

	data->client = bt_gatt_client_new(db, att, 64, 0);
	g_assert(data->client);

	bt_gatt_client_set_debug(data->client, print_debug, "bt_gatt_client:",
						NULL);

	bt_gatt_client_ready_register(data->client, setup_ready_cb, data,
						NULL);

	bt_att_unref(att);
	gatt_db_unref(db);
}

static void mcp_ccid(void *user_data, uint8_t ccid, bool gmcs)
{
	struct test_data *data = user_data;

	bt_mcp_add_listener(data->mcp, ccid, data->cfg->listener_cb, data);
}

static const struct bt_mcp_callback mcp_cb = {
	.ccid = mcp_ccid,
	.debug = mcp_debug,
};

static void test_client_start_io_cb(const void *user_data)
{
	struct test_data *data = (void *)user_data;
	struct io *io;
	struct iovec *iov = data->iov;
	size_t iovcnt = data->iovcnt;
	bool io_send = iovcnt && !iov[0].iov_base;

	if (io_send) {
		iovcnt--;
		iov++;
	}

	io = tester_setup_io(iov, iovcnt);
	g_assert(io);

	if (io_send)
		tester_io_send();
}

static void test_client(const void *user_data)
{
	struct test_data *data = (void *)user_data;
	const struct bt_mcp_callback *cb = data->cfg->mcp_cb;

	tester_io_set_complete_func(test_client_start_io_cb);

	if (!cb)
		cb = &mcp_cb;
	data->mcp = bt_mcp_attach(data->client, data->cfg->gmcs, cb, data);
	g_assert(data->mcp);
}

/* ATT: Write Request (0x12)
 *   Handle: {ccc_hnd}
 *   Value: 0x0001 (Notification enabled)
 */
#define NOTIFY_ENABLE(ccc_hnd) \
	IOV_DATA(0x12, HND(ccc_hnd), 0x01, 0x00), \
	IOV_DATA(0x13)

/* ATT: Read Request (0x0a) len 2
 *   Handle: 0x0003 Type: GMAP Role (0x2c00)
 * ATT: Read Response (0x0b) len 24
 *   Value: _value
 *   Handle: 0x0003 Type: GMAP Role (0x2c00)
 */

#define READ_CHRC(hnd, value...) \
	IOV_DATA(0x0a, HND(hnd)), \
	IOV_DATA(0x0b, value)

/* ATT: Write Command (0x52) len 2
 */

#define WRITE_NORESP_CHRC(hnd, value...) \
	IOV_DATA(0x52, HND(hnd), value), \
	IOV_NULL

/* ATT: Write Request (0x12) len 2
 * ATT: Write Response (0x13) len 1
 */

#define WRITE_CHRC(hnd, value...) \
	IOV_DATA(0x12, HND(hnd), value), \
	IOV_DATA(0x13)

/* ATT: Write Request (0x12) len 2
 * ATT: Error Response (0x01) len 1
 */

#define WRITE_ERR_CHRC(hnd, err, value...) \
	IOV_DATA(0x12, HND(hnd), value), \
	IOV_DATA(0x01, 0x12, HND(hnd), err)

/* ATT: Handle Value Notification (0x1b) len 7
 *   Handle: {hnd}
 *     Data: {value}
 */
#define NOTIFY_CHRC(hnd, value...) \
	IOV_NULL, \
	IOV_DATA(0x1b, HND(hnd), value)

#define SPLIT_INT32(value) \
	(value & 0xff), ((value >> 8) & 0xff), \
	((value >> 16) & 0xff), ((value >> 24) & 0xff)

#define MCS_MINIMAL_INIT_ALL(ops) \
	READ_CHRC(CCID, 0x01), \
	READ_CHRC(NAME, 'B', 'l', 'u', 'e', 'Z'), \
	NOTIFY_ENABLE(TRACK_CHG_CCC), \
	READ_CHRC(TRACK_TITLE, 'T', 'i', 't', 'l', 'e'), \
	READ_CHRC(TRACK_DUR, 0xff, 0xff, 0xff, 0xff), \
	READ_CHRC(TRACK_POS, 0xff, 0xff, 0xff, 0xff), \
	READ_CHRC(PLAY_SPEED, 0x00), \
	READ_CHRC(SEEK_SPEED, 0x00), \
	READ_CHRC(PLAY_ORDER, 0x04 /* in order repeat */), \
	READ_CHRC(PLAY_ORDER_SUPP, 0x18, 0x00  /* in order + oldest */), \
	READ_CHRC(STATE, 0x00 /* inactive */), \
	NOTIFY_ENABLE(STATE_CCC), \
	NOTIFY_ENABLE(CP_CCC), \
	READ_CHRC(CP_SUPP, SPLIT_INT32(ops))

#define GMCS_INIT_ALL(ops) \
	READ_CHRC(CCID, 0x01), \
	READ_CHRC(NAME, 'B', 'l', 'u', 'e', 'Z'), \
	NOTIFY_ENABLE(NAME_CCC), \
	NOTIFY_ENABLE(TRACK_CHG_CCC), \
	READ_CHRC(TRACK_TITLE, 'T', 'i', 't', 'l', 'e'), \
	NOTIFY_ENABLE(TRACK_TITLE_CCC), \
	READ_CHRC(TRACK_DUR, 0xff, 0xff, 0xff, 0xff), \
	NOTIFY_ENABLE(TRACK_DUR_CCC), \
	READ_CHRC(TRACK_POS, 0xff, 0xff, 0xff, 0xff), \
	NOTIFY_ENABLE(TRACK_POS_CCC), \
	READ_CHRC(PLAY_SPEED, 0x00), \
	NOTIFY_ENABLE(PLAY_SPEED_CCC), \
	READ_CHRC(SEEK_SPEED, 0x00), \
	NOTIFY_ENABLE(SEEK_SPEED_CCC), \
	READ_CHRC(PLAY_ORDER, 0x04 /* in order repeat */), \
	NOTIFY_ENABLE(PLAY_ORDER_CCC), \
	READ_CHRC(PLAY_ORDER_SUPP, 0x18, 0x00 /* in order + oldest */), \
	READ_CHRC(STATE, 0x00 /* inactive */), \
	NOTIFY_ENABLE(STATE_CCC), \
	NOTIFY_ENABLE(CP_CCC), \
	READ_CHRC(CP_SUPP, SPLIT_INT32(ops)), \
	NOTIFY_ENABLE(CP_SUPP_CCC)


/*
 * Client tests
 */

#define CGGIT_MCS_ALL \
	MCS_MINIMAL_INIT_ALL(0x001fffff)

#define CGGIT_GMCS_ALL \
	GMCS_INIT_ALL(0x001fffff)

static const struct iovec setup_data_mcs[] = {
	MCS_SETUP(0, MCS_SERVICE),
	CGGIT_MCS_ALL
};

static const struct iovec setup_data_gmcs[] = {
	GMCS_SETUP(0, GMCS_SERVICE),
	CGGIT_GMCS_ALL
};

static void cggit_player_name(void *data, const uint8_t *value, uint16_t length)
{
	if (strncmp((void *)value, "BlueZ", length) == 0) {
		tester_test_passed();
		return;
	}
	FAIL_TEST();
}

static void cggit_track_changed(void *data)
{
	tester_test_passed();
}

static void cggit_track_title(void *data, const uint8_t *value, uint16_t length)
{
	if (strncmp((void *)value, "Title", length) == 0) {
		tester_test_passed();
		return;
	}
	FAIL_TEST();
}

static void cggit_track_duration(void *data, int32_t value)
{
	if ((uint32_t)value == 0xffffffff)
		tester_test_passed();
	else
		FAIL_TEST();
}

static void cggit_track_position(void *user_data, int32_t value)
{
	struct test_data *data = user_data;

	tester_debug("position %d", value);
	if ((uint32_t)value == 0xffffffff && data->step == 0)
		; /* ok */
	else if (value == -777 && data->step == 1)
		tester_test_passed();
	else
		FAIL_TEST();
}

static void cggit_play_speed(void *user_data, int8_t value)
{
	struct test_data *data = user_data;

	tester_debug("play speed %d", value);

	if (value == 0 && data->step == 0)
		; /* ok */
	else if (value == 0x07 && data->step == 1)
		tester_test_passed();
	else
		FAIL_TEST();
}

static void cggit_seek_speed(void *data, int8_t value)
{
	if (value == 0)
		tester_test_passed();
	else
		FAIL_TEST();
}

static void cggit_play_order(void *user_data, uint8_t value)
{
	struct test_data *data = user_data;

	tester_debug("play order %u", value);

	if (value == 0x04 && data->step == 0)
		; /* ok */
	else if (value == 0x05 && data->step == 1)
		tester_test_passed();
	else
		FAIL_TEST();
}

static void cggit_media_state(void *data, uint8_t value)
{
	if (value == 0x00)
		tester_test_passed();
	else
		FAIL_TEST();
}

static void cggit_complete(void *user_data, unsigned int id, uint8_t res)
{
	struct test_data *data = user_data;

	if (!res || id != data->id) {
		FAIL_TEST();
		return;
	}

	data->step--;
}

#define CGGIT_CHA_BV_01_C

const struct test_config cfg_cggit_cha_bv_01_c = {
	.listener_cb = &(struct bt_mcp_listener_callback) {
		.media_player_name = cggit_player_name,
	},
	.mcp_cb = &mcp_cb,
	.setup_data = setup_data_mcs,
	.setup_data_len = ARRAY_SIZE(setup_data_mcs),
	.gmcs = false,
};

#define CGGIT_CHA_BV_23_C

const struct test_config cfg_cggit_cha_bv_23_c = {
	.listener_cb = &(struct bt_mcp_listener_callback) {
		.media_player_name = cggit_player_name,
	},
	.mcp_cb = &mcp_cb,
	.setup_data = setup_data_gmcs,
	.setup_data_len = ARRAY_SIZE(setup_data_gmcs),
	.gmcs = true,
};

#define CGGIT_CHA_BV_04_C \
	NOTIFY_CHRC(TRACK_CHG), \
	IOV_NULL

const struct test_config cfg_cggit_cha_bv_04_c = {
	.listener_cb = &(struct bt_mcp_listener_callback) {
		.track_changed = cggit_track_changed,
	},
	.mcp_cb = &mcp_cb,
	.setup_data = setup_data_mcs,
	.setup_data_len = ARRAY_SIZE(setup_data_mcs),
	.gmcs = false,
};

#define CGGIT_CHA_BV_05_C

const struct test_config cfg_cggit_cha_bv_05_c = {
	.listener_cb = &(struct bt_mcp_listener_callback) {
		.track_title = cggit_track_title,
	},
	.mcp_cb = &mcp_cb,
	.setup_data = setup_data_gmcs,
	.setup_data_len = ARRAY_SIZE(setup_data_gmcs),
	.gmcs = true,
};

#define CGGIT_CHA_BV_06_C

const struct test_config cfg_cggit_cha_bv_06_c = {
	.listener_cb = &(struct bt_mcp_listener_callback) {
		.track_duration = cggit_track_duration,
	},
	.mcp_cb = &mcp_cb,
	.setup_data = setup_data_mcs,
	.setup_data_len = ARRAY_SIZE(setup_data_mcs),
	.gmcs = false,
};

#define CGGIT_CHA_BV_07_C \
	WRITE_CHRC(TRACK_POS, 0xf7, 0xfc, 0xff, 0xff), \
	NOTIFY_CHRC(TRACK_POS, 0xf7, 0xfc, 0xff, 0xff)

static void cggit_ready_cha_bv_07_c(void *user_data)
{
	struct test_data *data = user_data;
	uint8_t ccid = 0x01;

	data->step = 2;
	data->id = bt_mcp_set_track_position(data->mcp, ccid, -777);
}

const struct test_config cfg_cggit_cha_bv_07_c = {
	.listener_cb = &(struct bt_mcp_listener_callback) {
		.track_position = cggit_track_position,
	},
	.mcp_cb = &(struct bt_mcp_callback) {
		.ccid = mcp_ccid,
		.debug = mcp_debug,
		.ready = cggit_ready_cha_bv_07_c,
		.complete = cggit_complete,
	},
	.setup_data = setup_data_gmcs,
	.setup_data_len = ARRAY_SIZE(setup_data_gmcs),
	.gmcs = true,
};

#define CGGIT_CHA_BV_08_C \
	WRITE_CHRC(PLAY_SPEED, 0x07), \
	NOTIFY_CHRC(PLAY_SPEED, 0x07)

static void cggit_ready_cha_bv_08_c(void *user_data)
{
	struct test_data *data = user_data;
	uint8_t ccid = 0x01;

	data->step = 2;
	data->id = bt_mcp_set_playback_speed(data->mcp, ccid, 7);
}

const struct test_config cfg_cggit_cha_bv_08_c = {
	.listener_cb = &(struct bt_mcp_listener_callback) {
		.playback_speed = cggit_play_speed,
	},
	.mcp_cb = &(struct bt_mcp_callback) {
		.ccid = mcp_ccid,
		.debug = mcp_debug,
		.ready = cggit_ready_cha_bv_08_c,
		.complete = cggit_complete,
	},
	.setup_data = setup_data_gmcs,
	.setup_data_len = ARRAY_SIZE(setup_data_gmcs),
	.gmcs = true,
};

#define CGGIT_CHA_BV_09_C

const struct test_config cfg_cggit_cha_bv_09_c = {
	.listener_cb = &(struct bt_mcp_listener_callback) {
		.seeking_speed = cggit_seek_speed,
	},
	.mcp_cb = &mcp_cb,
	.setup_data = setup_data_mcs,
	.setup_data_len = ARRAY_SIZE(setup_data_mcs),
	.gmcs = false,
};

#define CGGIT_CHA_BV_15_C \
	WRITE_CHRC(PLAY_ORDER, 0x05), \
	READ_CHRC(PLAY_ORDER, 0x05)	/* no notify, so bt_mcp reads */

static void cggit_ready_cha_bv_15_c(void *user_data)
{
	struct test_data *data = user_data;
	uint8_t ccid = 0x01;

	/* check not supported order */
	if (bt_mcp_set_playing_order(data->mcp, ccid, 0x06)) {
		FAIL_TEST();
		return;
	}

	data->step = 2;
	data->id = bt_mcp_set_playing_order(data->mcp, ccid, 0x05);
}

const struct test_config cfg_cggit_cha_bv_15_c = {
	.listener_cb = &(struct bt_mcp_listener_callback) {
		.playing_order = cggit_play_order,
	},
	.mcp_cb = &(struct bt_mcp_callback) {
		.ccid = mcp_ccid,
		.debug = mcp_debug,
		.ready = cggit_ready_cha_bv_15_c,
		.complete = cggit_complete,
	},
	.setup_data = setup_data_mcs,
	.setup_data_len = ARRAY_SIZE(setup_data_mcs),
	.gmcs = false,
};

#define CGGIT_CHA_BV_16_C

static void cggit_ready_cha_bv_16_c(void *user_data)
{
	struct test_data *data = user_data;
	uint8_t ccid = 0x01;
	uint8_t order = bt_mcp_get_supported_playing_order(data->mcp, ccid);

	tester_debug("0x%x", order);

	if (order == 0x18)
		tester_test_passed();
	else
		FAIL_TEST();
}

const struct test_config cfg_cggit_cha_bv_16_c = {
	.mcp_cb = &(struct bt_mcp_callback) {
		.ready = cggit_ready_cha_bv_16_c,
		.ccid = mcp_ccid,
		.debug = mcp_debug,
	},
	.setup_data = setup_data_mcs,
	.setup_data_len = ARRAY_SIZE(setup_data_mcs),
	.gmcs = false,
};

#define CGGIT_CHA_BV_17_C

const struct test_config cfg_cggit_cha_bv_17_c = {
	.listener_cb = &(struct bt_mcp_listener_callback) {
		.media_state = cggit_media_state,
	},
	.mcp_cb = &mcp_cb,
	.setup_data = setup_data_mcs,
	.setup_data_len = ARRAY_SIZE(setup_data_mcs),
	.gmcs = false,
};

#define CGGIT_CHA_BV_18_C \
	WRITE_NORESP_CHRC(CP, 0x01), \
	NOTIFY_CHRC(CP, 0x01, 0x01)

static void cggit_complete_cha_bv_18_c(void *user_data, unsigned int id,
								uint8_t result)
{
	struct test_data *data = user_data;

	tester_debug("complete %d expect %d result %u", id, data->id, result);

	if (id == data->id && result == 0x01)
		tester_test_passed();
	else
		FAIL_TEST();
}

static void cggit_ready_cha_bv_18_c(void *user_data)
{
	struct test_data *data = user_data;
	uint8_t ccid = 0x01;

	data->id = bt_mcp_play(data->mcp, ccid);
}

const struct test_config cfg_cggit_cha_bv_18_c = {
	.mcp_cb = &(struct bt_mcp_callback) {
		.ready = cggit_ready_cha_bv_18_c,
		.complete = cggit_complete_cha_bv_18_c,
		.ccid = mcp_ccid,
		.debug = mcp_debug,
	},
	.setup_data = setup_data_mcs,
	.setup_data_len = ARRAY_SIZE(setup_data_mcs),
	.gmcs = false,
};

#define CGGIT_CHA_BV_19_C

static void cggit_ready_cha_bv_19_c(void *user_data)
{
	struct test_data *data = user_data;
	uint8_t ccid = 0x01;
	uint32_t support = bt_mcp_get_supported_commands(data->mcp, ccid);

	if (support == 0x001fffff)
		tester_test_passed();
	else
		FAIL_TEST();
}

const struct test_config cfg_cggit_cha_bv_19_c = {
	.mcp_cb = &(struct bt_mcp_callback) {
		.ready = cggit_ready_cha_bv_19_c,
		.ccid = mcp_ccid,
		.debug = mcp_debug,
	},
	.setup_data = setup_data_mcs,
	.setup_data_len = ARRAY_SIZE(setup_data_mcs),
	.gmcs = false,
};

#define MCCP_BASIC(op, result, data...) \
	WRITE_NORESP_CHRC(CP, op, data), \
	NOTIFY_CHRC(CP, op, result)

static void mccp_basic_complete(void *user_data, unsigned int id,
								uint8_t result)
{
	struct test_data *data = user_data;

	tester_debug("complete %d expect %d result %u", id, data->id, result);

	if (id == data->id && result == 0x01)
		tester_test_passed();
	else
		FAIL_TEST();
}

static void mccp_basic_ready(void *user_data)
{
	struct test_data *data = user_data;
	uint8_t ccid = 0x01;

	switch (data->cfg->expect_cmd) {
	case 0x01:
		data->id = bt_mcp_play(data->mcp, ccid);
		break;
	case 0x02:
		data->id = bt_mcp_pause(data->mcp, ccid);
		break;
	case 0x03:
		data->id = bt_mcp_fast_rewind(data->mcp, ccid);
		break;
	case 0x04:
		data->id = bt_mcp_fast_forward(data->mcp, ccid);
		break;
	case 0x05:
		data->id = bt_mcp_stop(data->mcp, ccid);
		break;
	case 0x10:
		data->id = bt_mcp_move_relative(data->mcp, ccid, 0x42);
		break;
	case 0x20:
		data->id = bt_mcp_previous_segment(data->mcp, ccid);
		break;
	case 0x21:
		data->id = bt_mcp_next_segment(data->mcp, ccid);
		break;
	case 0x22:
		data->id = bt_mcp_first_segment(data->mcp, ccid);
		break;
	case 0x23:
		data->id = bt_mcp_last_segment(data->mcp, ccid);
		break;
	case 0x24:
		data->id = bt_mcp_goto_segment(data->mcp, ccid,
							(int32_t)0xfffffff0u);
		break;
	case 0x30:
		data->id = bt_mcp_previous_track(data->mcp, ccid);
		break;
	case 0x31:
		data->id = bt_mcp_next_track(data->mcp, ccid);
		break;
	case 0x32:
		data->id = bt_mcp_first_track(data->mcp, ccid);
		break;
	case 0x33:
		data->id = bt_mcp_last_track(data->mcp, ccid);
		break;
	case 0x34:
		data->id = bt_mcp_goto_track(data->mcp, ccid,
							(int32_t)0xfffffff1u);
		break;
	case 0x40:
		data->id = bt_mcp_previous_group(data->mcp, ccid);
		break;
	case 0x41:
		data->id = bt_mcp_next_group(data->mcp, ccid);
		break;
	case 0x42:
		data->id = bt_mcp_first_group(data->mcp, ccid);
		break;
	case 0x43:
		data->id = bt_mcp_last_group(data->mcp, ccid);
		break;
	case 0x44:
		data->id = bt_mcp_goto_group(data->mcp, ccid,
							(int32_t)0xfffffff2u);
		break;
	}
}

static const struct bt_mcp_callback mccp_basic_mcp_cb = {
	.ready = mccp_basic_ready,
	.complete = mccp_basic_complete,
	.debug = mcp_debug,
};

#define MCCP_BASIC_CFG(name_, cmd) \
	const struct test_config name_ = { \
		.expect_cmd = cmd, \
		.expect_cmd_result = 0x01, \
		.mcp_cb = &mccp_basic_mcp_cb, \
		.setup_data = setup_data_mcs, \
		.setup_data_len = ARRAY_SIZE(setup_data_mcs), \
		.gmcs = false, \
	}

#define MCCP_BV_01_C	MCCP_BASIC(0x01, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_01_c, 0x01);

#define MCCP_BV_02_C	MCCP_BASIC(0x02, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_02_c, 0x02);

#define MCCP_BV_03_C	MCCP_BASIC(0x03, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_03_c, 0x03);

#define MCCP_BV_04_C	MCCP_BASIC(0x04, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_04_c, 0x04);

#define MCCP_BV_05_C	MCCP_BASIC(0x05, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_05_c, 0x05);

#define MCCP_BV_06_C	MCCP_BASIC(0x10, 0x01, 0x42, 0x00, 0x00, 0x00)
MCCP_BASIC_CFG(cfg_mccp_bv_06_c, 0x10);

#define MCCP_BV_07_C	MCCP_BASIC(0x20, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_07_c, 0x20);

#define MCCP_BV_08_C	MCCP_BASIC(0x21, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_08_c, 0x21);

#define MCCP_BV_09_C	MCCP_BASIC(0x22, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_09_c, 0x22);

#define MCCP_BV_10_C	MCCP_BASIC(0x23, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_10_c, 0x23);

#define MCCP_BV_11_C	MCCP_BASIC(0x24, 0x01, 0xf0, 0xff, 0xff, 0xff)
MCCP_BASIC_CFG(cfg_mccp_bv_11_c, 0x24);

#define MCCP_BV_12_C	MCCP_BASIC(0x30, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_12_c, 0x30);

#define MCCP_BV_13_C	MCCP_BASIC(0x31, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_13_c, 0x31);

#define MCCP_BV_14_C	MCCP_BASIC(0x32, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_14_c, 0x32);

#define MCCP_BV_15_C	MCCP_BASIC(0x33, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_15_c, 0x33);

#define MCCP_BV_16_C	MCCP_BASIC(0x34, 0x01, 0xf1, 0xff, 0xff, 0xff)
MCCP_BASIC_CFG(cfg_mccp_bv_16_c, 0x34);

#define MCCP_BV_17_C	MCCP_BASIC(0x40, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_17_c, 0x40);

#define MCCP_BV_18_C	MCCP_BASIC(0x41, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_18_c, 0x41);

#define MCCP_BV_19_C	MCCP_BASIC(0x42, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_19_c, 0x42);

#define MCCP_BV_20_C	MCCP_BASIC(0x43, 0x01)
MCCP_BASIC_CFG(cfg_mccp_bv_20_c, 0x43);

#define MCCP_BV_21_C	MCCP_BASIC(0x44, 0x01, 0xf2, 0xff, 0xff, 0xff)
MCCP_BASIC_CFG(cfg_mccp_bv_21_c, 0x44);

static void testgroup_cl_cggit(void)
{
	/* MCP.TS Sec. 4.3 Generic GATT Integration Tests */
	define_test("MCP/CL/CGGIT/CHA/BV-01-C [Characteristic GGIT - Media "
								"Player Name]",
		test_setup, test_client,
		&cfg_cggit_cha_bv_01_c, CGGIT_CHA_BV_01_C);
	define_test("MCP/CL/CGGIT/CHA/BV-23-C [Characteristic GGIT - Media "
							"Player Name - GMCS]",
		test_setup, test_client,
		&cfg_cggit_cha_bv_23_c, CGGIT_CHA_BV_23_C);
	define_test("MCP/CL/CGGIT/CHA/BV-04-C [Characteristic GGIT - Track "
								"Changed]",
		test_setup, test_client,
		&cfg_cggit_cha_bv_04_c, CGGIT_CHA_BV_04_C);
	define_test("MCP/CL/CGGIT/CHA/BV-05-C [Characteristic GGIT - Track "
								"Title]",
		test_setup, test_client,
		&cfg_cggit_cha_bv_05_c, CGGIT_CHA_BV_05_C);
	define_test("MCP/CL/CGGIT/CHA/BV-06-C [Characteristic GGIT - Track "
								"Duration]",
		test_setup, test_client,
		&cfg_cggit_cha_bv_06_c, CGGIT_CHA_BV_06_C);
	define_test("MCP/CL/CGGIT/CHA/BV-07-C [Characteristic GGIT - Track "
								"Position]",
		test_setup, test_client,
		&cfg_cggit_cha_bv_07_c, CGGIT_CHA_BV_07_C);
	define_test("MCP/CL/CGGIT/CHA/BV-08-C [Characteristic GGIT - Playback "
								"Speed]",
		test_setup, test_client,
		&cfg_cggit_cha_bv_08_c, CGGIT_CHA_BV_08_C);
	define_test("MCP/CL/CGGIT/CHA/BV-09-C [Characteristic GGIT - Seeking "
								"Speed]",
		test_setup, test_client,
		&cfg_cggit_cha_bv_09_c, CGGIT_CHA_BV_09_C);
	define_test("MCP/CL/CGGIT/CHA/BV-15-C [Characteristic GGIT - Playing "
								"Order]",
		test_setup, test_client,
		&cfg_cggit_cha_bv_15_c, CGGIT_CHA_BV_15_C);
	define_test("MCP/CL/CGGIT/CHA/BV-16-C [Characteristic GGIT - Playing "
							"Order Supported]",
		test_setup, test_client,
		&cfg_cggit_cha_bv_16_c, CGGIT_CHA_BV_16_C);
	define_test("MCP/CL/CGGIT/CHA/BV-17-C [Characteristic GGIT - Media "
								"State]",
		test_setup, test_client,
		&cfg_cggit_cha_bv_17_c, CGGIT_CHA_BV_17_C);
	define_test("MCP/CL/CGGIT/CHA/BV-18-C [Characteristic GGIT - Media "
							"Control Point]",
		test_setup, test_client,
		&cfg_cggit_cha_bv_18_c, CGGIT_CHA_BV_18_C);
	define_test("MCP/CL/CGGIT/CHA/BV-19-C [Characteristic GGIT - Media "
						"Control Opcodes Supported]",
		test_setup, test_client,
		&cfg_cggit_cha_bv_19_c, CGGIT_CHA_BV_19_C);
}

static void testgroup_cl_mccp(void)
{
	/* MCP.TS Sec. 4.5 Service Procedure - Media Control Point */
	define_test("MCP/CL/MCCP/BV-01-C [Media Control Point - Play]",
		test_setup, test_client, &cfg_mccp_bv_01_c, MCCP_BV_01_C);
	define_test("MCP/CL/MCCP/BV-02-C [Media Control Point - Pause]",
		test_setup, test_client, &cfg_mccp_bv_02_c, MCCP_BV_02_C);
	define_test("MCP/CL/MCCP/BV-03-C [Media Control Point - Fast Rewind]",
		test_setup, test_client, &cfg_mccp_bv_03_c, MCCP_BV_03_C);
	define_test("MCP/CL/MCCP/BV-04-C [Media Control Point - Fast Forward]",
		test_setup, test_client, &cfg_mccp_bv_04_c, MCCP_BV_04_C);
	define_test("MCP/CL/MCCP/BV-05-C [Media Control Point - Stop]",
		test_setup, test_client, &cfg_mccp_bv_05_c, MCCP_BV_05_C);
	define_test("MCP/CL/MCCP/BV-06-C [Media Control Point - Move Relative]",
		test_setup, test_client, &cfg_mccp_bv_06_c, MCCP_BV_06_C);
	define_test("MCP/CL/MCCP/BV-07-C [Media Control Point - Previous "
								"Segment]",
		test_setup, test_client, &cfg_mccp_bv_07_c, MCCP_BV_07_C);
	define_test("MCP/CL/MCCP/BV-08-C [Media Control Point - Next Segment]",
		test_setup, test_client, &cfg_mccp_bv_08_c, MCCP_BV_08_C);
	define_test("MCP/CL/MCCP/BV-09-C [Media Control Point - First Segment]",
		test_setup, test_client, &cfg_mccp_bv_09_c, MCCP_BV_09_C);
	define_test("MCP/CL/MCCP/BV-10-C [Media Control Point - Last Segment]",
		test_setup, test_client, &cfg_mccp_bv_10_c, MCCP_BV_10_C);
	define_test("MCP/CL/MCCP/BV-11-C [Media Control Point - Goto Segment]",
		test_setup, test_client, &cfg_mccp_bv_11_c, MCCP_BV_11_C);
	define_test("MCP/CL/MCCP/BV-12-C [Media Control Point - Previous "
								"Track]",
		test_setup, test_client, &cfg_mccp_bv_12_c, MCCP_BV_12_C);
	define_test("MCP/CL/MCCP/BV-13-C [Media Control Point - Next Track]",
		test_setup, test_client, &cfg_mccp_bv_13_c, MCCP_BV_13_C);
	define_test("MCP/CL/MCCP/BV-14-C [Media Control Point - First Track]",
		test_setup, test_client, &cfg_mccp_bv_14_c, MCCP_BV_14_C);
	define_test("MCP/CL/MCCP/BV-15-C [Media Control Point - Last Track]",
		test_setup, test_client, &cfg_mccp_bv_15_c, MCCP_BV_15_C);
	define_test("MCP/CL/MCCP/BV-16-C [Media Control Point - Goto Track]",
		test_setup, test_client, &cfg_mccp_bv_16_c, MCCP_BV_16_C);
	define_test("MCP/CL/MCCP/BV-17-C [Media Control Point - Previous "
								"Group]",
		test_setup, test_client, &cfg_mccp_bv_17_c, MCCP_BV_17_C);
	define_test("MCP/CL/MCCP/BV-18-C [Media Control Point - Next Group]",
		test_setup, test_client, &cfg_mccp_bv_18_c, MCCP_BV_18_C);
	define_test("MCP/CL/MCCP/BV-19-C [Media Control Point - First Group]",
		test_setup, test_client, &cfg_mccp_bv_19_c, MCCP_BV_19_C);
	define_test("MCP/CL/MCCP/BV-20-C [Media Control Point - Last Group]",
		test_setup, test_client, &cfg_mccp_bv_20_c, MCCP_BV_20_C);
	define_test("MCP/CL/MCCP/BV-21-C [Media Control Point - Goto Group]",
		test_setup, test_client, &cfg_mccp_bv_21_c, MCCP_BV_21_C);
}

#define CL_BLUEZ_1_REREAD \
	NOTIFY_CHRC(TRACK_CHG), \
	READ_CHRC(TRACK_TITLE, 'N', 'e', 'w'), \
	READ_CHRC(TRACK_DUR, 0xff, 0xff, 0xff, 0xff), \
	READ_CHRC(TRACK_POS, 0xff, 0xff, 0xff, 0xff), \
	READ_CHRC(PLAY_SPEED, 0x00), \
	READ_CHRC(SEEK_SPEED, 0x00), \
	READ_CHRC(PLAY_ORDER, 0x04), \
	READ_CHRC(PLAY_ORDER_SUPP, 0x18, 0x00), \
	READ_CHRC(CP_SUPP, SPLIT_INT32(0x01))

static void cl_reread_complete_cb(const void *user_data)
{
	struct test_data *data = (void *)user_data;

	if (data->step == 2)
		tester_test_passed();
}

static void cl_reread_track_title(void *user_data, const uint8_t *value,
								uint16_t length)
{
	struct test_data *data = user_data;

	if (strncmp((void *)value, "Title", length) == 0 && data->step == 0) {
		data->step++;
	} else if (strncmp((void *)value, "New", length) == 0 &&
							data->step == 1) {
		data->step++;
		tester_io_set_complete_func(cl_reread_complete_cb);
	} else {
		FAIL_TEST();
	}
}

const struct test_config cfg_cl_bluez_1_reread = {
	.listener_cb = &(struct bt_mcp_listener_callback) {
		.track_title = cl_reread_track_title,
	},
	.setup_data = setup_data_mcs,
	.setup_data_len = ARRAY_SIZE(setup_data_mcs),
	.gmcs = false,
};

static void testgroup_cl_extra(void)
{
	define_test("MCP/CL/BLUEZ-1 [Reread On Track Change, No Notify]",
		test_setup, test_client,
		&cfg_cl_bluez_1_reread, CL_BLUEZ_1_REREAD);
}

/*
 * Server tests
 */

static const struct iovec setup_data_server_mcs[] = {
	GMCS_SETUP(0, MCS_SERVICE),
};

static const struct iovec setup_data_server_gmcs[] = {
	GMCS_SETUP(0, GMCS_SERVICE),
};

static void sggit_player_name(void *data, struct iovec *buf, size_t size)
{
	util_iov_push_mem(buf, 5, "BlueZ");
}

static void sggit_track_title(void *data, struct iovec *buf, size_t size)
{
	util_iov_push_mem(buf, 5, "Title");
}

static int32_t sggit_track_duration(void *data)
{
	return 0x00004321;
}

static int32_t sggit_track_position(void *data)
{
	return 0x00001234;
}

static int8_t sggit_playback_speed(void *data)
{
	return 0x03;
}

static int8_t sggit_seeking_speed(void *data)
{
	return 0x05;
}

static uint8_t sggit_playing_order(void *data)
{
	return 0x04;
}

static uint16_t sggit_playing_order_supported(void *data)
{
	return 0x18;
}

static uint32_t sggit_media_cp_op_supported(void *data)
{
	return 0x11;
}

static bool sggit_set_track_position(void *user_data, int32_t value)
{
	struct test_data *data = user_data;

	if (value == 0x5678)
		data->step--;
	return false;
}

static bool sggit_set_playback_speed(void *user_data, int8_t value)
{
	struct test_data *data = user_data;

	if (value == 0x42)
		data->step--;
	return true;
}

static bool sggit_set_playing_order(void *user_data, uint8_t value)
{
	struct test_data *data = user_data;

	if (value == 0x05)
		data->step--;
	return false;
}

static bool sggit_play(void *user_data)
{
	struct test_data *data = user_data;

	data->step--;
	return false;
}

const struct bt_mcs_callback sggit_cha_mcs = {
	.media_player_name = sggit_player_name,
	.track_title = sggit_track_title,
	.track_duration = sggit_track_duration,
	.track_position = sggit_track_position,
	.playback_speed = sggit_playback_speed,
	.seeking_speed = sggit_seeking_speed,
	.playing_order = sggit_playing_order,
	.playing_order_supported = sggit_playing_order_supported,
	.media_cp_op_supported = sggit_media_cp_op_supported,
	.set_track_position = sggit_set_track_position,
	.set_playback_speed = sggit_set_playback_speed,
	.set_playing_order = sggit_set_playing_order,
	.play = sggit_play,
	.debug = mcs_debug,
};

const struct test_config cfg_sggit_mcs = {
	.mcs_cb = &sggit_cha_mcs,
	.setup_data = setup_data_server_mcs,
	.setup_data_len = ARRAY_SIZE(setup_data_server_mcs),
	.gmcs = false,
};

const struct test_config cfg_sggit_gmcs = {
	.mcs_cb = &sggit_cha_mcs,
	.setup_data = setup_data_server_gmcs,
	.setup_data_len = ARRAY_SIZE(setup_data_server_gmcs),
	.gmcs = true,
};

#define SGGIT_CHA_BV_01_C \
	READ_CHRC(NAME, 'B', 'l', 'u', 'e', 'Z')

#define SGGIT_CHA_BV_04_C \
	NOTIFY_CHRC(TRACK_CHG)

static void test_sggit_cha_bv_04_c(const void *user_data)
{
	struct test_data *data = (void *)user_data;

	test_server(data);
	bt_mcs_changed(data->mcs, MCS_TRACK_CHANGED_CHRC_UUID);
}

#define SGGIT_CHA_BV_05_C \
	READ_CHRC(TRACK_TITLE, 'T', 'i', 't', 'l', 'e')

#define SGGIT_CHA_BV_06_C \
	READ_CHRC(TRACK_DUR, 0x21, 0x43, 0x00, 0x00)

#define SGGIT_CHA_BV_07_C \
	READ_CHRC(TRACK_POS, 0x34, 0x12, 0x00, 0x00), \
	WRITE_ERR_CHRC(TRACK_POS, 0x13, 0x78, 0x56, 0x00, 0x00)

static void test_sggit_step(const void *user_data)
{
	struct test_data *data = (void *)user_data;

	data->step++;
	test_server(data);
}

#define SGGIT_CHA_BV_08_C \
	READ_CHRC(PLAY_SPEED, 0x03), \
	WRITE_CHRC(PLAY_SPEED, 0x42)

#define SGGIT_CHA_BV_09_C \
	READ_CHRC(SEEK_SPEED, 0x05)

#define SGGIT_CHA_BV_15_C \
	READ_CHRC(PLAY_ORDER, 0x04), \
	WRITE_ERR_CHRC(PLAY_ORDER, 0x13, 0x05)

#define SGGIT_CHA_BV_16_C \
	READ_CHRC(PLAY_ORDER_SUPP, 0x18, 0x00)

#define SGGIT_CHA_BV_17_C \
	READ_CHRC(STATE, 0x00)

#define SGGIT_CHA_BV_18_C \
	WRITE_CHRC(CP, 0x01), \
	NOTIFY_CHRC(CP, 0x01, 0x03 /* inactive */), \
	WRITE_CHRC(CP, 0x10), \
	NOTIFY_CHRC(CP, 0x10, 0x02 /* not supp */)

#define SGGIT_CHA_BV_19_C \
	READ_CHRC(CP_SUPP, 0x01, 0x00, 0x00, 0x00)

#define SGGIT_CHA_BV_22_C \
	READ_CHRC(CCID, 0x00)

static void testgroup_sr_sggit(void)
{
	/* MCS.TS Sec 4.3 Generic GATT Integrated Tests (MCS) */
	define_test("MCS/SR/SGGIT/CHA/BV-01-C [Characteristic GGIT - Media "
							"Player Name, MCS]",
		test_setup_server, test_server,
		&cfg_sggit_mcs, SGGIT_CHA_BV_01_C);
	define_test("MCS/SR/SGGIT/CHA/BV-04-C [Characteristic GGIT - Track "
								"Changed]",
		test_setup_server, test_sggit_cha_bv_04_c,
		&cfg_sggit_mcs, SGGIT_CHA_BV_04_C);
	define_test("MCS/SR/SGGIT/CHA/BV-05-C [Characteristic GGIT - Track "
								"Title]",
		test_setup_server, test_server,
		&cfg_sggit_mcs, SGGIT_CHA_BV_05_C);
	define_test("MCS/SR/SGGIT/CHA/BV-06-C [Characteristic GGIT - Track "
								"Duration]",
		test_setup_server, test_server,
		&cfg_sggit_mcs, SGGIT_CHA_BV_06_C);
	define_test("MCS/SR/SGGIT/CHA/BV-07-C [Characteristic GGIT - Track "
								"Position]",
		test_setup_server, test_sggit_step,
		&cfg_sggit_mcs, SGGIT_CHA_BV_07_C);
	define_test("MCS/SR/SGGIT/CHA/BV-08-C [Characteristic GGIT - Playback "
								"Speed]",
		test_setup_server, test_sggit_step,
		&cfg_sggit_mcs, SGGIT_CHA_BV_08_C);
	define_test("MCS/SR/SGGIT/CHA/BV-09-C [Characteristic GGIT - Seeking "
								"Speed]",
		test_setup_server, test_server,
		&cfg_sggit_mcs, SGGIT_CHA_BV_09_C);
	define_test("MCS/SR/SGGIT/CHA/BV-15-C [Characteristic GGIT - Playing "
								"Order]",
		test_setup_server, test_sggit_step,
		&cfg_sggit_mcs, SGGIT_CHA_BV_15_C);
	define_test("MCS/SR/SGGIT/CHA/BV-16-C [Characteristic GGIT - Playing "
							"Order Supported]",
		test_setup_server, test_server,
		&cfg_sggit_mcs, SGGIT_CHA_BV_16_C);
	define_test("MCS/SR/SGGIT/CHA/BV-17-C [Characteristic GGIT - Media "
								"State]",
		test_setup_server, test_server,
		&cfg_sggit_mcs, SGGIT_CHA_BV_17_C);
	define_test("MCS/SR/SGGIT/CHA/BV-18-C [Characteristic GGIT - Media "
							"Control Point]",
		test_setup_server, test_sggit_step,
		&cfg_sggit_mcs, SGGIT_CHA_BV_18_C);
	define_test("MCS/SR/SGGIT/CHA/BV-19-C [Characteristic GGIT - Media "
					"Control Point Opcodes Supported]",
		test_setup_server, test_server,
		&cfg_sggit_mcs, SGGIT_CHA_BV_19_C);
	define_test("MCS/SR/SGGIT/CHA/BV-22-C [Characteristic GGIT - Content "
								"Control ID]",
		test_setup_server, test_server,
		&cfg_sggit_mcs, SGGIT_CHA_BV_22_C);

	/* MCS.TS Sec 4.3 Generic GATT Integrated Tests (GMCS) */
	define_test("GMCS/SR/SGGIT/CHA/BV-01-C [Characteristic GGIT - Media "
							"Player Name, GMCS]",
		test_setup_server, test_server,
		&cfg_sggit_gmcs, SGGIT_CHA_BV_01_C);
	define_test("GMCS/SR/SGGIT/CHA/BV-04-C [Characteristic GGIT - Track "
								"Changed]",
		test_setup_server, test_sggit_cha_bv_04_c,
		&cfg_sggit_gmcs, SGGIT_CHA_BV_04_C);
	define_test("GMCS/SR/SGGIT/CHA/BV-05-C [Characteristic GGIT - Track "
								"Title]",
		test_setup_server, test_server,
		&cfg_sggit_gmcs, SGGIT_CHA_BV_05_C);
	define_test("GMCS/SR/SGGIT/CHA/BV-06-C [Characteristic GGIT - Track "
								"Duration]",
		test_setup_server, test_server,
		&cfg_sggit_gmcs, SGGIT_CHA_BV_06_C);
	define_test("GMCS/SR/SGGIT/CHA/BV-07-C [Characteristic GGIT - Track "
								"Position]",
		test_setup_server, test_sggit_step,
		&cfg_sggit_gmcs, SGGIT_CHA_BV_07_C);
	define_test("GMCS/SR/SGGIT/CHA/BV-08-C [Characteristic GGIT - Playback "
								"Speed]",
		test_setup_server, test_sggit_step,
		&cfg_sggit_gmcs, SGGIT_CHA_BV_08_C);
	define_test("GMCS/SR/SGGIT/CHA/BV-09-C [Characteristic GGIT - Seeking "
								"Speed]",
		test_setup_server, test_server,
		&cfg_sggit_gmcs, SGGIT_CHA_BV_09_C);
	define_test("GMCS/SR/SGGIT/CHA/BV-15-C [Characteristic GGIT - Playing "
								"Order]",
		test_setup_server, test_sggit_step,
		&cfg_sggit_gmcs, SGGIT_CHA_BV_15_C);
	define_test("GMCS/SR/SGGIT/CHA/BV-16-C [Characteristic GGIT - Playing "
							"Order Supported]",
		test_setup_server, test_server,
		&cfg_sggit_gmcs, SGGIT_CHA_BV_16_C);
	define_test("GMCS/SR/SGGIT/CHA/BV-17-C [Characteristic GGIT - Media "
								"State]",
		test_setup_server, test_server,
		&cfg_sggit_gmcs, SGGIT_CHA_BV_17_C);
	define_test("GMCS/SR/SGGIT/CHA/BV-18-C [Characteristic GGIT - Media "
							"Control Point]",
		test_setup_server, test_sggit_step,
		&cfg_sggit_gmcs, SGGIT_CHA_BV_18_C);
	define_test("GMCS/SR/SGGIT/CHA/BV-19-C [Characteristic GGIT - Media "
					"Control Point Opcodes Supported]",
		test_setup_server, test_server,
		&cfg_sggit_gmcs, SGGIT_CHA_BV_19_C);
	define_test("GMCS/SR/SGGIT/CHA/BV-22-C [Characteristic GGIT - Content "
								"Control ID]",
		test_setup_server, test_server,
		&cfg_sggit_gmcs, SGGIT_CHA_BV_22_C);
}

static uint32_t sr_mcp_media_cp_op_supported(void *data)
{
	return 0x001fffff;  /* everything supported */
}

static bool sr_mcp_op_success(void *user_data)
{
	struct test_data *data = user_data;

	tester_debug("Command OK");
	data->step--;
	return true;
}

static bool sr_mcp_op_success_inactive(void *user_data)
{
	struct test_data *data = user_data;

	tester_debug("Command OK");
	data->step--;
	return bt_mcs_get_media_state(data->mcs) != BT_MCS_STATE_INACTIVE;
}

static int32_t sr_mcp_track_position(void *user_data)
{
	struct test_data *data = user_data;

	return 71 - data->id;
}

static bool sr_mcp_set_track_position(void *user_data, int32_t value)
{
	struct test_data *data = user_data;

	data->id = 71 - value;
	return true;
}

const struct bt_mcs_callback sr_mcp_mcs = {
	.media_cp_op_supported = sr_mcp_media_cp_op_supported,
	.play = sr_mcp_op_success,
	.pause = sr_mcp_op_success,
	.fast_rewind = sr_mcp_op_success,
	.fast_forward = sr_mcp_op_success,
	.stop = sr_mcp_op_success_inactive,
	.track_position = sr_mcp_track_position,
	.set_track_position = sr_mcp_set_track_position,
	.debug = mcs_debug,
};

#define MCS_SR_MCP_CFG(name, initial) \
	const struct test_config cfg_mcs_sr_mcp_ ## name = { \
		.mcs_cb = &sr_mcp_mcs, \
		.setup_data = setup_data_server_mcs, \
		.setup_data_len = ARRAY_SIZE(setup_data_server_mcs), \
		.gmcs = false, \
		.state = initial, \
	}

#define SR_MCP_CMD(cmd, initial, end_state) \
	NOTIFY_CHRC(STATE, initial), \
	WRITE_CHRC(CP, cmd), \
	NOTIFY_CHRC(STATE, end_state), \
	NOTIFY_CHRC(CP, cmd, 0x01)

#define SR_MCP_CMD_INACTIVE(cmd, end_state) \
	WRITE_CHRC(CP, cmd), \
	NOTIFY_CHRC(STATE, end_state), \
	NOTIFY_CHRC(CP, cmd, 0x01)

MCS_SR_MCP_CFG(bv_01_c, BT_MCS_STATE_PAUSED);
#define MCS_SR_MCP_BV_01_C \
	SR_MCP_CMD(BT_MCS_CMD_PLAY, BT_MCS_STATE_PAUSED, BT_MCS_STATE_PLAYING)

MCS_SR_MCP_CFG(bv_02_c, BT_MCS_STATE_SEEKING);
#define MCS_SR_MCP_BV_02_C \
	SR_MCP_CMD(BT_MCS_CMD_PLAY, BT_MCS_STATE_SEEKING, BT_MCS_STATE_PLAYING)

MCS_SR_MCP_CFG(bv_70_c, BT_MCS_STATE_INACTIVE);
#define MCS_SR_MCP_BV_70_C \
	SR_MCP_CMD_INACTIVE(BT_MCS_CMD_PLAY, BT_MCS_STATE_PLAYING)

MCS_SR_MCP_CFG(bv_03_c, BT_MCS_STATE_PLAYING);
#define MCS_SR_MCP_BV_03_C \
	SR_MCP_CMD(BT_MCS_CMD_PAUSE, BT_MCS_STATE_PLAYING, BT_MCS_STATE_PAUSED)

MCS_SR_MCP_CFG(bv_04_c, BT_MCS_STATE_SEEKING);
#define MCS_SR_MCP_BV_04_C \
	SR_MCP_CMD(BT_MCS_CMD_PAUSE, BT_MCS_STATE_SEEKING, BT_MCS_STATE_PAUSED)

MCS_SR_MCP_CFG(bv_71_c, BT_MCS_STATE_INACTIVE);
#define MCS_SR_MCP_BV_71_C \
	SR_MCP_CMD_INACTIVE(BT_MCS_CMD_PAUSE, BT_MCS_STATE_PAUSED)

#define SR_MCP_STOP(initial) \
	NOTIFY_CHRC(STATE, initial), \
	WRITE_CHRC(CP, BT_MCS_CMD_STOP), \
	NOTIFY_CHRC(STATE, BT_MCS_STATE_PAUSED), \
	NOTIFY_CHRC(TRACK_POS, 0x00, 0x00, 0x00, 0x00), \
	NOTIFY_CHRC(CP, BT_MCS_CMD_STOP, 0x01)

#define SR_MCP_STOP_PAUSED \
	NOTIFY_CHRC(STATE, BT_MCS_STATE_PAUSED), \
	WRITE_CHRC(CP, BT_MCS_CMD_STOP), \
	NOTIFY_CHRC(TRACK_POS, 0x00, 0x00, 0x00, 0x00), \
	NOTIFY_CHRC(CP, BT_MCS_CMD_STOP, 0x01)

#define SR_MCP_STOP_INACTIVE \
	WRITE_CHRC(CP, BT_MCS_CMD_STOP), \
	NOTIFY_CHRC(CP, BT_MCS_CMD_STOP, 0x03 /* inactive */)

MCS_SR_MCP_CFG(bv_09_c, BT_MCS_STATE_PLAYING);
#define MCS_SR_MCP_BV_09_C SR_MCP_STOP(BT_MCS_STATE_PLAYING)

MCS_SR_MCP_CFG(bv_10_c, BT_MCS_STATE_PAUSED);
#define MCS_SR_MCP_BV_10_C SR_MCP_STOP_PAUSED

MCS_SR_MCP_CFG(bv_11_c, BT_MCS_STATE_SEEKING);
#define MCS_SR_MCP_BV_11_C SR_MCP_STOP(BT_MCS_STATE_SEEKING)

MCS_SR_MCP_CFG(bv_74_c, BT_MCS_STATE_INACTIVE);
#define MCS_SR_MCP_BV_74_C SR_MCP_STOP_INACTIVE

static void test_sr_mcp(const void *user_data)
{
	struct test_data *data = (void *)user_data;

	bt_mcs_set_media_state(data->mcs, data->cfg->state);
	data->step++;
	test_server(data);
}

static void testgroup_sr_mcp(void)
{
	/* Only the MCS tests. No point in GMCS as only svc uuid changes */

	/* MCS.TS Sec 4.4.1 Play and Pause */
	define_test("MCS/SR/MCP/BV-01-C [Play from Paused]",
		test_setup_server, test_sr_mcp,
		&cfg_mcs_sr_mcp_bv_01_c, MCS_SR_MCP_BV_01_C);
	define_test("MCS/SR/MCP/BV-02-C [Play from Seeking]",
		test_setup_server, test_sr_mcp,
		&cfg_mcs_sr_mcp_bv_02_c, MCS_SR_MCP_BV_02_C);
	define_test("MCS/SR/MCP/BV-70-C [Play from Inactive]",
		test_setup_server, test_sr_mcp,
		&cfg_mcs_sr_mcp_bv_70_c, MCS_SR_MCP_BV_70_C);
	define_test("MCS/SR/MCP/BV-03-C [Pause from Playing]",
		test_setup_server, test_sr_mcp,
		&cfg_mcs_sr_mcp_bv_03_c, MCS_SR_MCP_BV_03_C);
	define_test("MCS/SR/MCP/BV-04-C [Pause from Seeking]",
		test_setup_server, test_sr_mcp,
		&cfg_mcs_sr_mcp_bv_04_c, MCS_SR_MCP_BV_04_C);
	define_test("MCS/SR/MCP/BV-71-C [Pause from Inactive]",
		test_setup_server, test_sr_mcp,
		&cfg_mcs_sr_mcp_bv_71_c, MCS_SR_MCP_BV_71_C);

	/* MCS.TS Sec 4.4.3 Stop */
	define_test("MCS/SR/MCP/BV-09-C [Stop from Playing]",
		test_setup_server, test_sr_mcp,
		&cfg_mcs_sr_mcp_bv_09_c, MCS_SR_MCP_BV_09_C);
	define_test("MCS/SR/MCP/BV-10-C [Stop from Paused]",
		test_setup_server, test_sr_mcp,
		&cfg_mcs_sr_mcp_bv_10_c, MCS_SR_MCP_BV_10_C);
	define_test("MCS/SR/MCP/BV-11-C [Stop from Seeking]",
		test_setup_server, test_sr_mcp,
		&cfg_mcs_sr_mcp_bv_11_c, MCS_SR_MCP_BV_11_C);
	define_test("MCS/SR/MCP/BV-74-C [Stop from Inactive]",
		test_setup_server, test_sr_mcp,
		&cfg_mcs_sr_mcp_bv_74_c, MCS_SR_MCP_BV_74_C);

	/* TODO: other state transition tests. They largely test the profile
	 * upper layer, so do not add much here.
	 */
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);
	testgroup_cl_cggit();
	testgroup_cl_mccp();
	testgroup_cl_extra();
	testgroup_sr_sggit();
	testgroup_sr_mcp();

	return tester_run();
}
