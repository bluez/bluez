// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  Pauli Virtanen. All rights reserved.
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
#include "src/shared/gmap.h"

struct test_config {
	uint8_t role;
	uint8_t old_role;
	uint32_t features;
	const struct iovec *setup_data;
	const size_t setup_data_len;
};

struct test_data {
	struct gatt_db *db;
	struct bt_gatt_server *server;
	struct bt_gatt_client *client;
	struct bt_gmap *gmap;
	size_t iovcnt;
	struct iovec *iov;
	const struct test_config *cfg;
};

#define iov_data(args...) ((const struct iovec[]) { args })

#define define_test(name, setup, function, _cfg, args...)	\
	do {							\
		const struct iovec iov[] = { args };		\
		static struct test_data data;			\
		data.iovcnt = ARRAY_SIZE(iov);			\
		data.iov = util_iov_dup(iov, ARRAY_SIZE(iov));	\
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

static void test_teardown(const void *user_data)
{
	struct test_data *data = (void *)user_data;

	bt_gatt_client_unref(data->client);

	bt_gatt_server_unref(data->server);
	util_iov_free(data->iov, data->iovcnt);

	gatt_db_unref(data->db);

	bt_gmap_unref(data->gmap);
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
#define GMAS_MTU_FEAT \
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
 *   Handle range: 0x0001-0x000b
 *   UUID: Gaming Audio Service (0x1858)
 * ATT: Read By Group Type Request (0x10) len 6
 *   Handle range: 0x000c-0xffff
 *   Attribute group type: Primary Service (0x2800)
 * ATT: Error Response (0x01) len 4
 *   Read By Group Type Request (0x10)
 *   Handle: 0x0004
 *   Error: Attribute Not Found (0x0a)
 */
#define GMAS_PRIMARY_SERVICE(base) \
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28), \
	IOV_DATA(0x11, 0x06, \
		0x01 + base, 0x00, 0x0b + base, 0x00, 0x58, 0x18), \
	IOV_DATA(0x10, 0x0c + base, 0x00, 0xff, 0xff, 0x00, 0x28), \
	IOV_DATA(0x01, 0x10, 0x0c + base, 0x00, 0x0a)


/* ATT: Read By Group Type Request (0x10) len 6
 *   Handle range: 0x0001-0xffff
 *   Attribute group type: Secondary Service (0x2801)
 * ATT: Error Response (0x01) len 4
 *   Read By Group Type Request (0x10)
 *   Handle: 0x0001
 *   Error: Attribute Not Found (0x0a)
 */
#define GMAS_SECONDARY_SERVICE \
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x01, 0x28), \
	IOV_DATA(0x01, 0x10, 0x01, 0x00, 0x0a)

/* ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0001-0x0005
 *   Attribute group type: Include (0x2802)
 * ATT: Error Response (0x01) len 4
 *   Read By Group Type Request (0x10)
 *   Handle: 0x0001
 *   Error: Attribute Not Found (0x0a)
 */
#define GMAS_INCLUDE(base) \
	IOV_DATA(0x08, 0x01 + base, 0x00, 0x0b + base, 0x00, 0x02, 0x28), \
	IOV_DATA(0x01, 0x08, 0x01 + base, 0x00, 0x0a)

/* ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0001-0x0003
 *   Attribute type: Characteristic (0x2803)
 * ATT: Read By Type Response (0x09) len 57
 *   Attribute data length: 7
 *   Attribute data list: 8 entries
 *     Handle: 0x0002
 *     Value: 020300512b
 *     Properties: 0x02
 *       Read (0x02)
 *     Value Handle: 0x0003
 *     Value UUID: GMAP Role (0x2c00)
 * ATT: Read By Type Response (0x09) len 57
 *   Attribute data length: 7
 *   Attribute data list: 8 entries
 *     Handle: 0x0004
 *     Value: 020300512b
 *     Properties: 0x02
 *       Read (0x02)
 *     Value Handle: 0x0005
 *     Value UUID: GMAP Features ({uuid})
 * ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0003-0x0004
 *   Attribute type: Characteristic (0x2803)
 * ATT: Error Response (0x01) len 4
 *   Read By Type Request (0x08)
 *   Handle: 0x0022
 *   Error: Attribute Not Found (0x0a)
 * ATT: Find Information Request (0x04)
 * ATT: Error Response
 */
#define IOV_CONTENT(data...)	data

#define GMAS_FIND_CHRC(uuid, base) \
	IOV_DATA(0x08, 0x01 + base, 0x00, 0x0b + base, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		0x02 + base, 0x00, 0x02, 0x03 + base, 0x00, 0x00, 0x2c, \
		0x04 + base, 0x00, 0x02, 0x05 + base, 0x00, uuid), \
	IOV_DATA(0x08, 0x05 + base, 0x00, 0x0b + base, 0x00, 0x03, 0x28), \
	IOV_DATA(0x01, 0x08, 0x05 + base, 0x00, 0x0a), \
	IOV_DATA(0x04, 0x06 + base, 0x00, 0x0b + base, 0x00), \
	IOV_DATA(0x01, 0x04, 0x06 + base, 0x00, 0x0a)

#define UGG_UUID	0x01, 0x2c
#define UGT_UUID	0x02, 0x2c
#define BGS_UUID	0x03, 0x2c
#define BGR_UUID	0x04, 0x2c

#define ROLE_HND	0x03, 0x00
#define FEAT_HND	0x05, 0x00

/* ACL Data TX: Handle 42 flags 0x00 dlen 11
 *   ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0001-0xffff
 *   Attribute type: Database Hash (0x2b2a)
 * ATT: Error Response (0x01) len 4
 *   Read By Type Request (0x08)
 *   Handle: 0x0001
 *   Error: Attribute Not Found (0x0a)
 */
#define GMAS_DATABASE_HASH \
	IOV_DATA(0x08, 0x01, 0x00, 0xff, 0xff, 0x2a, 0x2b), \
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a)


#define GMAS_SETUP(uuid, base) \
	GMAS_MTU_FEAT, \
	GMAS_PRIMARY_SERVICE(base), \
	GMAS_SECONDARY_SERVICE, \
	GMAS_INCLUDE(base), \
	GMAS_FIND_CHRC(IOV_CONTENT(uuid), base), \
	GMAS_DATABASE_HASH

/* GATT Discover All procedure */
static const struct iovec setup_data_ugg[] = { GMAS_SETUP(UGG_UUID, 0) };
static const struct iovec setup_data_ugt[] = { GMAS_SETUP(UGT_UUID, 0) };
static const struct iovec setup_data_bgs[] = { GMAS_SETUP(BGS_UUID, 0) };
static const struct iovec setup_data_bgr[] = { GMAS_SETUP(BGR_UUID, 0) };

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

	io = tester_setup_io(cfg->setup_data, cfg->setup_data_len);
	g_assert(io);

	tester_io_set_complete_func(setup_complete_cb);

	db = gatt_db_new();
	g_assert(db);

	data->gmap = bt_gmap_add_db(db);
	bt_gmap_set_debug(data->gmap, print_debug, "gmap:", NULL);

	if (data->cfg->old_role) {
		bt_gmap_set_role(data->gmap, data->cfg->old_role);
		bt_gmap_set_features(data->gmap, 0xffffffff);
		bt_gmap_set_role(data->gmap, data->cfg->role);
		bt_gmap_set_role(data->gmap, 0);
	}

	bt_gmap_set_role(data->gmap, data->cfg->role);
	bt_gmap_set_features(data->gmap, data->cfg->features);

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

static void client_ready_cb(struct bt_gmap *gmap, void *user_data)
{
	struct test_data *data = (void *)user_data;

	if (bt_gmap_get_role(gmap) != data->cfg->role) {
		tester_test_failed();
		return;
	}

	if (bt_gmap_get_features(gmap) != data->cfg->features) {
		tester_test_failed();
		return;
	}

	tester_test_passed();
}

static void test_client(const void *user_data)
{
	struct test_data *data = (void *)user_data;
	struct io *io;

	io = tester_setup_io(data->iov, data->iovcnt);
	g_assert(io);

	tester_io_set_complete_func(NULL);

	data->gmap = bt_gmap_attach(data->client, client_ready_cb, data);
	g_assert(data->gmap);

	bt_gmap_set_debug(data->gmap, print_debug, "gmap:", NULL);
}

/* ATT: Read Request (0x0a) len 2
 *   Handle: 0x0003 Type: GMAP Role (0x2c00)
 * ATT: Read Response (0x0b) len 24
 *   Value: _value
 *   Handle: 0x0003 Type: GMAP Role (0x2c00)
 */

#define READ_CHRC(hnd, value...) \
	IOV_DATA(0x0a, hnd), \
	IOV_DATA(0x0b, value)

#define READ_ROLE(value...)	READ_CHRC(IOV_CONTENT(ROLE_HND), value)
#define READ_FEAT(value...)	READ_CHRC(IOV_CONTENT(FEAT_HND), value)

#define CGGIT_CHA(role, value)	READ_ROLE(role), READ_FEAT(value)

#define CGGIT_ROLE	CGGIT_CHA(0x01, 0x00)
#define CGGIT_ROLE_RFU	CGGIT_CHA(0xf1, 0x00)

const struct test_config cfg_read_role = {
	.role = BT_GMAP_ROLE_UGG,
	.setup_data = setup_data_ugg,
	.setup_data_len = ARRAY_SIZE(setup_data_ugg),
};

#define CGGIT_UGG	CGGIT_CHA(0x01, 0x01)
#define CGGIT_UGG_RFU	CGGIT_CHA(0x01, 0xf1)

const struct test_config cfg_read_ugg = {
	.role = BT_GMAP_ROLE_UGG,
	.features = BT_GMAP_UGG_MULTIPLEX,
	.setup_data = setup_data_ugg,
	.setup_data_len = ARRAY_SIZE(setup_data_ugg),
};

#define CGGIT_UGT	CGGIT_CHA(0x02, 0x01)
#define CGGIT_UGT_RFU	CGGIT_CHA(0x02, 0x81)

const struct test_config cfg_read_ugt = {
	.role = BT_GMAP_ROLE_UGT,
	.features = BT_GMAP_UGT_SOURCE,
	.setup_data = setup_data_ugt,
	.setup_data_len = ARRAY_SIZE(setup_data_ugt),
};

#define CGGIT_BGS	CGGIT_CHA(0x04, 0x01)
#define CGGIT_BGS_RFU	CGGIT_CHA(0x04, 0x81)

const struct test_config cfg_read_bgs = {
	.role = BT_GMAP_ROLE_BGS,
	.features = BT_GMAP_BGS_96KBPS,
	.setup_data = setup_data_bgs,
	.setup_data_len = ARRAY_SIZE(setup_data_bgs),
};

#define CGGIT_BGR	CGGIT_CHA(0x08, 0x01)
#define CGGIT_BGR_RFU	CGGIT_CHA(0x08, 0x81)

const struct test_config cfg_read_bgr = {
	.role = BT_GMAP_ROLE_BGR,
	.features = BT_GMAP_BGR_MULTISINK,
	.setup_data = setup_data_bgr,
	.setup_data_len = ARRAY_SIZE(setup_data_bgr),
};

static void test_gmap_cl(void)
{
	/* Sec. 4.5.1 TMA Client */
	define_test("GMAP/CL/CGGIT/CHA/BV-01-C [GMAP Role Read Characteristic, "
						"Client]",
		test_setup, test_client, &cfg_read_role, CGGIT_ROLE);
	define_test("GMAP/CL/CGGIT/CHA/BV-03-C [UGG Features Read "
						"Characteristic, Client]",
		test_setup, test_client, &cfg_read_ugg, CGGIT_UGG);
	define_test("GMAP/CL/CGGIT/CHA/BV-02-C [UGT Features Read "
						"Characteristic, Client]",
		test_setup, test_client, &cfg_read_ugt, CGGIT_UGT);
	define_test("GMAP/CL/CGGIT/CHA/BV-04-C [BGS Features Read "
						"Characteristic, Client]",
		test_setup, test_client, &cfg_read_bgs, CGGIT_BGS);
	define_test("GMAP/CL/CGGIT/CHA/BV-05-C [BGR Features Read "
						"Characteristic, Client]",
		test_setup, test_client, &cfg_read_bgr, CGGIT_BGR);

	define_test("GMAP/CL/GMAS/BI-01-C [Client Ignores RFU Bits in GMAP "
						"Role Characteristic]",
		test_setup, test_client, &cfg_read_role, CGGIT_ROLE_RFU);
	define_test("GMAP/CL/GMAS/BI-03-C [Client Ignores RFU Bits in UGG "
						"Features Characteristic]",
		test_setup, test_client, &cfg_read_ugg, CGGIT_UGG_RFU);
	define_test("GMAP/CL/GMAS/BI-02-C [Client Ignores RFU Bit in UGT "
						"Features Characteristic]",
		test_setup, test_client, &cfg_read_ugt, CGGIT_UGT_RFU);
	define_test("GMAP/CL/GMAS/BI-04-C [Client Ignores RFU Bits in BGS "
						"Features Characteristic]",
		test_setup, test_client, &cfg_read_bgs, CGGIT_BGS_RFU);
	define_test("GMAP/CL/GMAS/BI-05-C [Client Ignores RFU Bits in BGR "
						"Features Characteristic]",
		test_setup, test_client, &cfg_read_bgr, CGGIT_BGR_RFU);
}

/* Step 1. in CGGIT/CHA skipped, should be unnecessary */
#define SGGIT_CHA_ROLE	READ_ROLE(0x01)
#define SGGIT_CHA_FEAT	READ_FEAT(0x01)

const struct test_config cfg_read_ugg_re_add = {
	.old_role = BT_GMAP_ROLE_UGG,
	.role = BT_GMAP_ROLE_UGG,
	.features = BT_GMAP_UGG_MULTIPLEX,
	.setup_data = setup_data_ugg,
	.setup_data_len = ARRAY_SIZE(setup_data_ugg),
};

#define SGGIT_CHA_FEAT_CHANGE \
	READ_CHRC(IOV_CONTENT(0x0b + FEAT_HND), 0x01)

static const struct iovec setup_data_ugg_change[] = {
	GMAS_SETUP(UGG_UUID, 0x0b)
};

const struct test_config cfg_read_ugg_change = {
	.old_role = BT_GMAP_ROLE_UGT,
	.role = BT_GMAP_ROLE_UGG,
	.features = BT_GMAP_UGG_MULTIPLEX,
	.setup_data = setup_data_ugg_change,
	.setup_data_len = ARRAY_SIZE(setup_data_ugg_change),
};

static void test_gmap_sr(void)
{
	/* Sec. 4.6.2 GMA Server */
	define_test("GMAP/SR/SGGIT/CHA/BV-01-C [Characteristic GGIT - GMAP "
						"Role]",
		test_setup_server, test_server, &cfg_read_role, SGGIT_CHA_ROLE);
	define_test("GMAP/SR/SGGIT/CHA/BV-03-C [Characteristic GGIT - UGG "
						"Features]",
		test_setup_server, test_server, &cfg_read_ugg, SGGIT_CHA_FEAT);
	define_test("GMAP/SR/SGGIT/CHA/BV-02-C [Characteristic GGIT - UGT "
						"Features]",
		test_setup_server, test_server, &cfg_read_ugt, SGGIT_CHA_FEAT);
	define_test("GMAP/SR/SGGIT/CHA/BV-04-C [Characteristic GGIT - BGS "
						"Features]",
		test_setup_server, test_server, &cfg_read_bgs, SGGIT_CHA_FEAT);
	define_test("GMAP/SR/SGGIT/CHA/BV-05-C [Characteristic GGIT - BGR "
						"Features]",
		test_setup_server, test_server, &cfg_read_bgr, SGGIT_CHA_FEAT);

	define_test("GMAP/SR/SGGIT/CHA/BLUEZ-01-C [Re-add UGG Features]",
		test_setup_server, test_server, &cfg_read_ugg_re_add,
		SGGIT_CHA_FEAT);

	define_test("GMAP/SR/SGGIT/CHA/BLUEZ-02-C [Change UGT -> UGG]",
		test_setup_server, test_server, &cfg_read_ugg_change,
		SGGIT_CHA_FEAT_CHANGE);
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);
	test_gmap_cl();
	test_gmap_sr();

	return tester_run();
}
