// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation.
 *
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
#include "src/shared/io.h"
#include "src/shared/tester.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/bap.h"

struct test_data {
	struct bt_gatt_client *client;
	struct bt_bap *bap;
	size_t iovcnt;
	struct iovec *iov;
};

#define iov_data(args...) ((const struct iovec[]) { args })

#define define_test(name, function, args...)			\
	do {							\
		const struct iovec iov[] = { args };		\
		static struct test_data data;			\
		data.iovcnt = ARRAY_SIZE(iov_data(args));	\
		data.iov = util_iov_dup(iov, ARRAY_SIZE(iov_data(args))); \
		tester_add(name, &data, test_setup, function,	\
				test_teardown);			\
	} while (0)

static void client_ready_cb(bool success, uint8_t att_ecode, void *user_data)
{
	if (!success)
		tester_setup_failed();
	else
		tester_setup_complete();
}

/* GATT Discover All procedure */
static const struct iovec setup_data[] = {
	/* ATT: Exchange MTU Response (0x03) len 2
	 *   Server RX MTU: 64
	 */
	IOV_DATA(0x02, 0x40, 0x00),
	/* ATT: Exchange MTU Request (0x02) len 2
	 *    Client RX MTU: 64
	 */
	IOV_DATA(0x03, 0x40, 0x00),
	/* ATT: Read By Type Request (0x08) len 6
	 *   Handle range: 0x0001-0xffff
	 *   Attribute type: Server Supported Features (0x2b3a)
	 */
	IOV_DATA(0x08, 0x01, 0x00, 0xff, 0xff, 0x3a, 0x2b),
	/* ATT: Error Response (0x01) len 4
	 *   Read By Type Request (0x08)
	 *   Handle: 0x0001
	 *   Error: Attribute Not Found (0x0a)
	 */
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a),
	/*
	 * ATT: Read By Group Type Request (0x10) len 6
	 *   Handle range: 0x0001-0xffff
	 *   Attribute group type: Primary Service (0x2800)
	 */
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	/*
	 * ATT: Read By Group Type Response (0x11) len 37
	 *   Attribute data length: 6
	 *   Attribute group list: 2 entries
	 *   Handle range: 0x0001-0x0013
	 *   UUID: Published Audio Capabilities (0x1850)
	 *   Handle range: 0x0014-0x0023
	 *   UUID: Audio Stream Control (0x184e)
	 */
	IOV_DATA(0x11, 0x06,
		0x01, 0x00, 0x13, 0x00, 0x50, 0x18,
		0x14, 0x00, 0x23, 0x00, 0x4e, 0x18),
	/* ATT: Read By Group Type Request (0x10) len 6
	 *   Handle range: 0x0024-0xffff
	 *   Attribute group type: Primary Service (0x2800)
	 */
	IOV_DATA(0x10, 0x24, 0x00, 0xff, 0xff, 0x00, 0x28),
	/* ATT: Error Response (0x01) len 4
	 *   Read By Group Type Request (0x10)
	 *   Handle: 0x0024
	 *   Error: Attribute Not Found (0x0a)
	 */
	IOV_DATA(0x01, 0x10, 0x24, 0x00, 0x0a),
	/* ATT: Read By Group Type Request (0x10) len 6
	 *   Handle range: 0x0001-0xffff
	 *   Attribute group type: Secondary Service (0x2801)
	 */
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x01, 0x28),
	/* ATT: Error Response (0x01) len 4
	 *   Read By Group Type Request (0x10)
	 *   Handle: 0x0001
	 *   Error: Attribute Not Found (0x0a)
	 */
	IOV_DATA(0x01, 0x10, 0x01, 0x00, 0x0a),
	/* ATT: Read By Type Request (0x08) len 6
	 *   Handle range: 0x0001-0x0023
	 *   Attribute group type: Include (0x2802)
	 */
	IOV_DATA(0x08, 0x01, 0x00, 0x23, 0x00, 0x02, 0x28),
	/* ATT: Error Response (0x01) len 4
	 *   Read By Group Type Request (0x10)
	 *   Handle: 0x0001
	 *   Error: Attribute Not Found (0x0a)
	 */
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a),
	/* ATT: Read By Type Request (0x08) len 6
	 *   Handle range: 0x0001-0x0023
	 *   Attribute type: Characteristic (0x2803)
	 */
	IOV_DATA(0x08, 0x01, 0x00, 0x23, 0x00, 0x03, 0x28),
	/* ATT: Read By Type Response (0x09) len 57
	 * Attribute data length: 7
	 * Attribute data list: 8 entries
	 *   Handle: 0x0002
	 *   Value: 120300c92b
	 *   Properties: 0x12
	 *     Read (0x02)
	 *     Notify (0x10)
	 *   Value Handle: 0x0003
	 *   Value UUID: Sink PAC (0x2bc9)
	 *   Handle: 0x0005
	 *   Value: 120600ca2b
	 *   Properties: 0x12
	 *     Read (0x02)
	 *     Notify (0x10)
	 *   Value Handle: 0x0006
	 *   Value UUID: Sink Audio Locations (0x2bca)
	 *   Handle: 0x0008
	 *   Value: 120900cb2b
	 *   Properties: 0x12
	 *     Read (0x02)
	 *     Notify (0x10)
	 *   Value Handle: 0x0009
	 *   Value UUID: Source PAC (0x2bcb)
	 *   Handle: 0x000b
	 *   Value: 120c00cc2b
	 *   Properties: 0x12
	 *     Read (0x02)
	 *     Notify (0x10)
	 *  Value Handle: 0x000c
	 *  Value UUID: Source Audio Locations (0x2bcc)
	 *  Handle: 0x000e
	 *  Value: 120f00cd2b
	 *  Properties: 0x12
	 *    Read (0x02)
	 *    Notify (0x10)
	 *  Value Handle: 0x000f
	 *  Value UUID: Available Audio Contexts (0x2bcd)
	 *  Handle: 0x0011
	 *  Value: 121200ce2b
	 *  Properties: 0x12
	 *    Read (0x02)
	 *    Notify (0x10)
	 *  Value Handle: 0x0012
	 *  Value UUID: Supported Audio Contexts (0x2bce)
	 *  Handle: 0x0015
	 *  Value: 121600c42b
	 *  Properties: 0x12
	 *    Read (0x02)
	 *    Notify (0x10)
	 *  Value Handle: 0x0016
	 *  Value UUID: Sink ASE (0x2bc4)
	 *  Handle: 0x0018
	 *  Value: 121900c42b
	 *  Properties: 0x12
	 *    Read (0x02)
	 *    Notify (0x10)
	 *  Value Handle: 0x0019
	 *  Value UUID: Sink ASE (0x2bc4)
	 */
	IOV_DATA(0x09, 0x07,
		0x02, 0x00, 0x12, 0x03, 0x00, 0xc9, 0x2b,
		0x05, 0x00, 0x12, 0x06, 0x00, 0xca, 0x2b,
		0x08, 0x00, 0x12, 0x09, 0x00, 0xcb, 0x2b,
		0x0b, 0x00, 0x12, 0x0c, 0x00, 0xcc, 0x2b,
		0x0e, 0x00, 0x12, 0x0f, 0x00, 0xcd, 0x2b,
		0x11, 0x00, 0x12, 0x12, 0x00, 0xce, 0x2b,
		0x15, 0x00, 0x12, 0x16, 0x00, 0xc4, 0x2b,
		0x18, 0x00, 0x12, 0x19, 0x00, 0xc4, 0x2b),
	/* ATT: Read By Type Request (0x08) len 6
	 *   Handle range: 0x0001-0x0023
	 *   Attribute type: Characteristic (0x2803)
	 */
	IOV_DATA(0x08, 0x19, 0x00, 0x23, 0x00, 0x03, 0x28),
	/* ATT: Read By Type Response (0x09) len 22
	 * Attribute data length: 7
	 * Attribute data list: 3 entries
	 *   Handle: 0x001b
	 *   Value: 121c00c52b
	 *   Properties: 0x12
	 *     Read (0x02)
	 *     Notify (0x10)
	 *   Value Handle: 0x001c
	 *   Value UUID: Source ASE (0x2bc5)
	 *   Handle: 0x001e
	 *   Value: 121f00c52b
	 *   Properties: 0x12
	 *     Read (0x02)
	 *     Notify (0x10)
	 *   Value Handle: 0x001f
	 *   Value UUID: Source ASE (0x2bc5)
	 *   Handle: 0x0021
	 *   Value: 182200c62b
	 *   Properties: 0x18
	 *     Write (0x08)
	 *     Notify (0x10)
	 *   Value Handle: 0x0022
	 *   Value UUID: ASE Control Point (0x2bc6)
	 */
	IOV_DATA(0x09, 0x07,
		0x1b, 0x00, 0x12, 0x1c, 0x00, 0xc5, 0x2b,
		0x1e, 0x00, 0x12, 0x1f, 0x00, 0xc5, 0x2b,
		0x21, 0x00, 0x18, 0x22, 0x00, 0xc6, 0x2b),
	/* ATT: Read By Type Request (0x08) len 6
	 *   Handle range: 0x0022-0x0023
	 *   Attribute type: Characteristic (0x2803)
	 */
	IOV_DATA(0x08, 0x22, 0x00, 0x23, 0x00, 0x03, 0x28),
	/* ATT: Error Response (0x01) len 4
	 *   Read By Type Request (0x08)
	 *   Handle: 0x0022
	 *   Error: Attribute Not Found (0x0a)
	 */
	IOV_DATA(0x01, 0x08, 0x23, 0x00, 0x0a),
	/* ACL Data TX: Handle 42 flags 0x00 dlen 11
	 *   ATT: Read By Type Request (0x08) len 6
	 *   Handle range: 0x0001-0xffff
	 *   Attribute type: Database Hash (0x2b2a)
	 */
	IOV_DATA(0x08, 0x01, 0x00, 0xff, 0xff, 0x2a, 0x2b),
	/* ATT: Error Response (0x01) len 4
	 *   Read By Type Request (0x08)
	 *   Handle: 0x0001
	 *   Error: Attribute Not Found (0x0a)
	 */
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a),
};

static void print_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	if (tester_use_debug())
		tester_debug("%s%s", prefix, str);
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

	bt_gatt_client_ready_register(data->client, client_ready_cb, data,
						NULL);

	bt_att_unref(att);
	gatt_db_unref(db);
}

static void test_complete_cb(const void *user_data)
{
	tester_test_passed();
}

static void test_client(const void *user_data)
{
	struct test_data *data = (void *)user_data;
	struct io *io;
	struct gatt_db *db;

	io = tester_setup_io(data->iov, data->iovcnt);
	g_assert(io);

	tester_io_set_complete_func(test_complete_cb);

	db = gatt_db_new();
	g_assert(db);

	data->bap = bt_bap_new(db, bt_gatt_client_get_db(data->client));
	g_assert(data->bap);

	bt_bap_set_debug(data->bap, print_debug, "bt_bap:", NULL);

	bt_bap_attach(data->bap, data->client);
}

static void test_teardown(const void *user_data)
{
	struct test_data *data = (void *)user_data;

	bt_bap_unref(data->bap);
	bt_gatt_client_unref(data->client);
	util_iov_free(data->iov, data->iovcnt);

	tester_teardown_complete();
}

/* ATT: Read Request (0x0a) len 2
 *   Handle: 0x0003 Type: Sink PAC (0x2bc9)
 * ATT: Read Response (0x0b) len 24
 *   Value: 010600000000100301ff0002020302030305041e00f00000
 *   Handle: 0x0003 Type: Sink PAC (0x2bc9)
 *     Number of PAC(s): 1
 *       PAC #0:
 *         Codec: LC3 (0x06)
 *         Codec Specific Capabilities #0: len 0x03 type 0x01
 *         Sampling Frequencies: 0x00ff
 *           8 Khz (0x0001)
 *           11.25 Khz (0x0002)
 *           16 Khz (0x0004)
 *           22.05 Khz (0x0008)
 *           24 Khz (0x0010)
 *           32 Khz (0x0020)
 *           44.1 Khz (0x0040)
 *           48 Khz (0x0080)
 *       Codec Specific Capabilities #1: len 0x02 type 0x02
 *         Frame Duration: 0x0003
 *           7.5 ms (0x01)
 *           10 ms (0x02)
 *       Codec Specific Capabilities #2: len 0x02 type 0x03
 *         Audio Channel Count: 0x03
 *           1 channel (0x01)
 *           2 channels (0x02)
 *       Codec Specific Capabilities #3: len 0x05 type 0x04
 *         Frame Length: 30 (0x001e) - 240 (0x00f0)
 * ATT: Read Request (0x0a) len 2
 *   Handle: 0x0006 Type: Sink Audio Location (0x2bca)
 * ATT: Read Response (0x0b) len 4
 *   Value: 03000000
 *   Handle: 0x0006 Type: Sink Audio Locations (0x2bca)
 *     Location: 0x00000003
 *       Front Left (0x00000001)
 *       Front Right (0x00000002)
 */
#define DISC_SINK_PAC \
	IOV_DATA(0x0a, 0x03, 0x00), \
	IOV_DATA(0x0b, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x03, 0x01, \
		0xff, 0x00, 0x02, 0x02, 0x03, 0x02, 0x03, 0x03, 0x05, 0x04, \
		0x1e, 0x00, 0xf0, 0x00, 0x00), \
	IOV_DATA(0x0a, 0x06, 0x00), \
	IOV_DATA(0x0b, 0x03, 0x00, 0x00, 0x00)

/* ATT: Read Request (0x0a) len 2
 *   Handle: 0x0009 Type: Source PAC (0x2bcb)
 * ATT: Read Response (0x0b) len 24
 *   Value: 010600000000100301ff0002020302030305041e00f00000
 *   Handle: 0x0009 Type: Source PAC (0x2bcb)
 *     Number of PAC(s): 1
 *       PAC #0:
 *         Codec: LC3 (0x06)
 *         Codec Specific Capabilities #0: len 0x03 type 0x01
 *         Sampling Frequencies: 0x00ff
 *           8 Khz (0x0001)
 *           11.25 Khz (0x0002)
 *           16 Khz (0x0004)
 *           22.05 Khz (0x0008)
 *           24 Khz (0x0010)
 *           32 Khz (0x0020)
 *           44.1 Khz (0x0040)
 *           48 Khz (0x0080)
 *       Codec Specific Capabilities #1: len 0x02 type 0x02
 *         Frame Duration: 0x0003
 *           7.5 ms (0x01)
 *           10 ms (0x02)
 *       Codec Specific Capabilities #2: len 0x02 type 0x03
 *         Audio Channel Count: 0x03
 *           1 channel (0x01)
 *           2 channels (0x02)
 *       Codec Specific Capabilities #3: len 0x05 type 0x04
 *         Frame Length: 30 (0x001e) - 240 (0x00f0)
 * ATT: Read Request (0x0a) len 2
 *   Handle: 0x000c Type: Source Audio Location (0x2bcc)
 * ATT: Read Response (0x0b) len 4
 *   Value: 03000000
 *   Handle: 0x000c Type: Source Audio Locations (0x2bcc)
 *     Location: 0x00000003
 *       Front Left (0x00000001)
 *       Front Right (0x00000002)
 */
#define DISC_SOURCE_PAC \
	DISC_SINK_PAC, \
	IOV_DATA(0x0a, 0x09, 0x00), \
	IOV_DATA(0x0b, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x03, 0x01, \
		0xff, 0x00, 0x02, 0x02, 0x03, 0x02, 0x03, 0x03, 0x05, 0x04, \
		0x1e, 0x00, 0xf0, 0x00, 0x00), \
	IOV_DATA(0x0a, 0x0c, 0x00), \
	IOV_DATA(0x0b, 0x03, 0x00, 0x00, 0x00)

/* ATT: Read Request (0x0a) len 2
 *   Handle: 0x000f Type: Available Audio Contexts (0x2bcd)
 * ATT: Read Response (0x0b) len 4
 *   Value: ff0f0e00
 *   Handle: 0x000f Type: Available Audio Contexts (0x2bcd)
 */
#define DISC_CTX \
	DISC_SOURCE_PAC, \
	IOV_DATA(0x0a, 0x0f, 0x00), \
	IOV_DATA(0x0b, 0xff, 0x0f, 0x0e, 0x00)

/* ATT: Read Request (0x0a) len 2
 *   Handle: 0x0012 Type: Supported Audio Contexts (0x2bce)
 * ATT: Read Response (0x0b) len 4
 *   Value: ff0f0e00
 *   Handle: 0x0012 Type: Supported Audio Contexts (0x2bce)
 */
#define DISC_SUP_CTX \
	DISC_CTX, \
	IOV_DATA(0x0a, 0x12, 0x00), \
	IOV_DATA(0x0b, 0xff, 0x0f, 0x0e, 0x00)

/* ATT: Read Request (0x0a) len 2
 *   Handle: 0x0016 Type: Sink ASE (0x2bc4)
 * ATT: Read Response (0x0b) len 4
 *   Value: 0100
 *   Handle: 0x0016 Type: Sink ASE (0x2bc4)
 * ATT: Write Request (0x12) len 4
 *   Handle: 0x0017 Type: Client Characteristic Configuration (0x2902)
 *     Data: 0100
 *       Notification (0x01)
 * ATT: Write Response (0x13) len 0
 * ATT: Read Request (0x0a) len 2
 *   Handle: 0x0019 Type: Sink ASE (0x2bc4)
 * ATT: Read Response (0x0b) len 4
 *   Value: 0200
 *   Handle: 0x0019 Type: Sink ASE (0x2bc4)
 * ATT: Write Request (0x12) len 4
 *   Handle: 0x001a Type: Client Characteristic Configuration (0x2902)
 *     Data: 0100
 *       Notification (0x01)
 * ATT: Write Response (0x13) len 0
 */
#define DISC_SINK_ASE \
	DISC_SUP_CTX, \
	IOV_DATA(0x0a, 0x16, 0x00), \
	IOV_DATA(0x0b, 0x01, 0x00), \
	IOV_DATA(0x12, 0x17, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	IOV_DATA(0x0a, 0x19, 0x00), \
	IOV_DATA(0x0b, 0x02, 0x00), \
	IOV_DATA(0x12, 0x1a, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13)

/* ATT: Read Request (0x0a) len 2
 *   Handle: 0x001c Type: Source ASE (0x2bc5)
 * ATT: Read Response (0x0b) len 4
 *   Value: 0300
 *   Handle: 0x001c Type: Source ASE (0x2bc5)
 * ATT: Write Request (0x12) len 4
 *   Handle: 0x001d Type: Client Characteristic Configuration (0x2902)
 *     Data: 0100
 *       Notification (0x01)
 * ATT: Write Response (0x13) len 0
 * ATT: Read Request (0x0a) len 2
 *   Handle: 0x001f Type: Source ASE (0x2bc5)
 * ATT: Read Response (0x0b) len 4
 *   Value: 0400
 *   Handle: 0x001f Type: Source ASE (0x2bc5)
 * ATT: Write Request (0x12) len 4
 *   Handle: 0x0020 Type: Client Characteristic Configuration (0x2902)
 *     Data: 0100
 *       Notification (0x01)
 * ATT: Write Response (0x13) len 0
 * ATT: Write Request (0x12) len 4
 *   Handle: 0x0023 Type: Client Characteristic Configuration (0x2902)
 *     Data: 0100
 *       Notification (0x01)
 * ATT: Write Response (0x13) len 0
 */
#define DISC_SOURCE_ASE \
	DISC_SINK_ASE, \
	IOV_DATA(0x0a, 0x1c, 0x00), \
	IOV_DATA(0x0b, 0x03, 0x00), \
	IOV_DATA(0x12, 0x1d, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	IOV_DATA(0x0a, 0x1f, 0x00), \
	IOV_DATA(0x0b, 0x04, 0x00), \
	IOV_DATA(0x12, 0x20, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	IOV_DATA(0x12, 0x23, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13)

static void test_disc(void)
{
	/* The IUT discovers the characteristics specified in the PAC
	 * Characteristic and Location Characteristic columns in Table 4.4.
	 * The IUT reads the values of the characteristics specified in the PAC
	 * Characteristic and Location Characteristic columns.
	 */
	define_test("BAP/UCL/DISC/BV-01-C", test_client, DISC_SINK_PAC);
	define_test("BAP/UCL/DISC/BV-02-C", test_client, DISC_SOURCE_PAC);

	/* BAP/UCL/DISC/BV-06-C [Discover Available Audio Contexts]
	 *
	 * The IUT successfully reads the value of the Available Audio Contexts
	 * characteristic on the LowerTester.
	 */
	define_test("BAP/UCL/DISC/BV-06-C", test_client, DISC_CTX);

	/* BAP/UCL/DISC/BV-05-C [Discover Supported Audio Contexts]
	 *
	 * The IUT successfully reads the value of the Supported Audio Contexts
	 * characteristic on the Lower Tester.
	 */
	define_test("BAP/UCL/DISC/BV-05-C", test_client, DISC_SUP_CTX);

	/* BAP/UCL/DISC/BV-03-C [Discover Sink ASE_ID]
	 * BAP/UCL/DISC/BV-04-C [Discover Source ASE_ID]
	 *
	 * The IUT successfully reads the ASE_ID values of each discovered ASE
	 * characteristic on the LowerTester.
	 */
	define_test("BAP/UCL/DISC/BV-03-C", test_client, DISC_SINK_ASE);
	define_test("BAP/UCL/DISC/BV-04-C", test_client, DISC_SOURCE_ASE);
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_disc();

	return tester_run();
}
