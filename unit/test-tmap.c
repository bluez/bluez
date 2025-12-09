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
#include "src/shared/tmap.h"

struct test_config {
	uint16_t role;
	uint16_t old_role;
};

struct test_data {
	struct gatt_db *db;
	struct bt_gatt_server *server;
	struct bt_gatt_client *client;
	struct bt_tmap *tmap;
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

	bt_tmap_unref(data->tmap);
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
#define TMAS_MTU_FEATURES \
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
 *   Handle range: 0x0001-0x0003
 *   UUID: Telephony and Media Audio (0x1855)
 * ATT: Read By Group Type Request (0x10) len 6
 *   Handle range: 0x0004-0xffff
 *   Attribute group type: Primary Service (0x2800)
 * ATT: Error Response (0x01) len 4
 *   Read By Group Type Request (0x10)
 *   Handle: 0x0004
 *   Error: Attribute Not Found (0x0a)
 */
#define TMAS_PRIMARY_SERVICE \
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28), \
	IOV_DATA(0x11, 0x06, \
		0x01, 0x00, 0x03, 0x00, 0x55, 0x18), \
	IOV_DATA(0x10, 0x04, 0x00, 0xff, 0xff, 0x00, 0x28), \
	IOV_DATA(0x01, 0x10, 0x04, 0x00, 0x0a)


/* ATT: Read By Group Type Request (0x10) len 6
 *   Handle range: 0x0001-0xffff
 *   Attribute group type: Secondary Service (0x2801)
 * ATT: Error Response (0x01) len 4
 *   Read By Group Type Request (0x10)
 *   Handle: 0x0001
 *   Error: Attribute Not Found (0x0a)
 */
#define TMAS_SECONDARY_SERVICE \
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x01, 0x28), \
	IOV_DATA(0x01, 0x10, 0x01, 0x00, 0x0a)

/* ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0001-0x0003
 *   Attribute group type: Include (0x2802)
 * ATT: Error Response (0x01) len 4
 *   Read By Group Type Request (0x10)
 *   Handle: 0x0001
 *   Error: Attribute Not Found (0x0a)
 */
#define TMAS_INCLUDE \
	IOV_DATA(0x08, 0x01, 0x00, 0x03, 0x00, 0x02, 0x28), \
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a)

/* ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0001-0x0003
 *   Attribute type: Characteristic (0x2803)
 * ATT: Read By Type Response (0x09) len 57
 * Attribute data length: 7
 * Attribute data list: 8 entries
 *   Handle: 0x0002
 *   Value: 020300512b
 *   Properties: 0x02
 *     Read (0x02)
 *   Value Handle: 0x0003
 *   Value UUID: TMAP Role (0x2b51)
 * ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0003-0x0004
 *   Attribute type: Characteristic (0x2803)
 * ATT: Error Response (0x01) len 4
 *   Read By Type Request (0x08)
 *   Handle: 0x0022
 *   Error: Attribute Not Found (0x0a)
 */
#define TMAS_FIND_CHRC \
	IOV_DATA(0x08, 0x01, 0x00, 0x03, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		0x02, 0x00, 0x02, 0x03, 0x00, 0x51, 0x2b), \
	IOV_DATA(0x08, 0x03, 0x00, 0x03, 0x00, 0x03, 0x28), \
	IOV_DATA(0x01, 0x08, 0x03, 0x00, 0x0a)

#define ROLE_HND	0x03, 0x00

/* ACL Data TX: Handle 42 flags 0x00 dlen 11
 *   ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0001-0xffff
 *   Attribute type: Database Hash (0x2b2a)
 * ATT: Error Response (0x01) len 4
 *   Read By Type Request (0x08)
 *   Handle: 0x0001
 *   Error: Attribute Not Found (0x0a)
 */
#define TMAS_DATABASE_HASH \
	IOV_DATA(0x08, 0x01, 0x00, 0xff, 0xff, 0x2a, 0x2b), \
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a)

/* GATT Discover All procedure */
static const struct iovec setup_data[] = {
	TMAS_MTU_FEATURES,
	TMAS_PRIMARY_SERVICE,
	TMAS_SECONDARY_SERVICE,
	TMAS_INCLUDE,
	TMAS_FIND_CHRC,
	TMAS_DATABASE_HASH,
};

static void setup_complete_cb(const void *user_data)
{
	tester_setup_complete();
}

static void test_setup_server(const void *user_data)
{
	struct test_data *data = (void *)user_data;
	struct bt_att *att;
	struct gatt_db *db;
	struct io *io;

	io = tester_setup_io(setup_data, ARRAY_SIZE(setup_data));
	g_assert(io);

	tester_io_set_complete_func(setup_complete_cb);

	db = gatt_db_new();
	g_assert(db);

	data->tmap = bt_tmap_add_db(db);
	bt_tmap_set_debug(data->tmap, print_debug, "tmap:", NULL);

	if (data->cfg->old_role) {
		bt_tmap_set_role(data->tmap, data->cfg->old_role);
		bt_tmap_set_role(data->tmap, 0);
	}

	bt_tmap_set_role(data->tmap, data->cfg->role);

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

	data->client = bt_gatt_client_new(db, att, 64, 0);
	g_assert(data->client);

	bt_gatt_client_set_debug(data->client, print_debug, "bt_gatt_client:",
						NULL);

	bt_gatt_client_ready_register(data->client, setup_ready_cb, data,
						NULL);

	bt_att_unref(att);
	gatt_db_unref(db);
}

static void client_ready_cb(struct bt_tmap *tmap, void *user_data)
{
	struct test_data *data = (void *)user_data;

	if (bt_tmap_get_role(tmap) != data->cfg->role) {
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

	data->tmap = bt_tmap_attach(data->client, client_ready_cb, data);
	g_assert(data->tmap);

	bt_tmap_set_debug(data->tmap, print_debug, "tmap:", NULL);
}

/* ATT: Read Request (0x0a) len 2
 *   Handle: 0x0003 Type: TMAP Role (0x2b51)
 * ATT: Read Response (0x0b) len 24
 *   Value: _value
 *   Handle: 0x0003 Type: TMAP Role (0x2b51)
 */
#define READ_ROLE(value...) \
	IOV_DATA(0x0a, ROLE_HND), \
	IOV_DATA(0x0b, value)

#define CGGIT_CHA \
	/* Step 1. in CGGIT/CHA skipped, should be unnecessary */ \
	READ_ROLE(0x24, 0x00)
#define CGGIT_CHA_RFU \
	/* Step 1. in SGGIT/CHA skipped, should be unnecessary */ \
	READ_ROLE(0x24, 0xff)

const struct test_config cfg_read_role = {
	.role = BT_TMAP_ROLE_UMS | BT_TMAP_ROLE_BMR,
};

const struct test_config cfg_read_role_re_add = {
	.role = BT_TMAP_ROLE_UMS | BT_TMAP_ROLE_BMR,
	.old_role = BT_TMAP_ROLE_CT,
};

static void test_tmap_cl(void)
{
	/* Sec. 4.5.1 TMA Client */
	define_test("TMAP/CL/CGGIT/CHA/BV-01-C [TMAP Role Read Characteristic, "
						"Client]",
		test_setup, test_client, &cfg_read_role, CGGIT_CHA);
	define_test("TMAP/CL/TMAS/BI-01-C [Client Ignores RFU Bits in TMAP "
						"Role Characteristic]",
		test_setup, test_client, &cfg_read_role, CGGIT_CHA_RFU);
}

#define SGGIT_CHA \
	/* Step 1. in CGGIT/CHA skipped, should be unnecessary */ \
	READ_ROLE(0x24, 0x00)

static void test_tmap_sr(void)
{
	/* Sec. 4.5.2 TMA Server */
	define_test("TMAP/SR/SGGIT/CHA/BV-01-C [Characteristic GGIT - "
								"TMAP Role]",
		test_setup_server, test_server, &cfg_read_role,
		SGGIT_CHA);

	define_test("TMAP/SR/SGGIT/CHA/BLUEZ-01-C [Re-add Role]",
		test_setup_server, test_server, &cfg_read_role_re_add,
		SGGIT_CHA);
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);
	test_tmap_cl();
	test_tmap_sr();

	return tester_run();
}
