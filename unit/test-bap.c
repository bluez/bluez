// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation.
 *  Copyright 2024 NXP
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

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"
#include "src/shared/util.h"
#include "src/shared/io.h"
#include "src/shared/tester.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gatt-server.h"
#include "src/shared/bap.h"
#include "src/shared/lc3.h"

struct test_config {
	struct bt_bap_pac_qos pqos;
	struct iovec cc;
	struct iovec base;
	struct bt_bap_qos qos;
	bool snk;
	bool src;
	bool vs;
	uint8_t state;
	bt_bap_state_func_t state_func;
	uint8_t streams;
};

struct test_data {
	struct bt_gatt_client *client;
	struct bt_gatt_server *server;
	struct gatt_db *db;
	struct queue *ccc_states;
	struct bt_bap *bap;
	unsigned int id;
	struct bt_bap_pac *snk;
	struct bt_bap_pac *src;
	struct bt_bap_pac *bsrc;
	struct bt_bap_pac *bsnk;
	struct bt_bap_pac_qos *qos;
	struct iovec *base;
	struct iovec *caps;
	struct test_config *cfg;
	struct queue *streams;
	size_t iovcnt;
	struct iovec *iov;
};

struct notify {
	uint16_t handle, ccc_handle;
	uint8_t *value;
	uint16_t len;
	bt_gatt_server_conf_func_t conf;
	void *user_data;
};

struct ccc_state {
	uint16_t handle;
	uint16_t value;
};

/*
 * Frequencies: 8Khz 11Khz 16Khz 22Khz 24Khz 32Khz 44.1Khz 48Khz
 * Duration: 7.5 ms 10 ms
 * Channel count: 3
 * Frame length: 26-240
 */
static struct iovec lc3_caps = LC3_CAPABILITIES(LC3_FREQ_ANY, LC3_DURATION_ANY,
								3u, 26, 240);

static struct bt_bap_pac_qos lc3_qos = {
	.phy = 0x02,
	.rtn = 0x01,
	.location = 0x00000003,
	.supported_context = 0x0fff,
	.context = 0x0fff,
};

#define iov_data(args...) ((const struct iovec[]) { args })

#define define_test(name, setup, function, _cfg, args...)		\
	do {							\
		const struct iovec iov[] = { args };		\
		static struct test_data data;			\
		data.caps = &lc3_caps;				\
		data.qos = &lc3_qos;				\
		data.cfg = _cfg;				\
		data.iovcnt = ARRAY_SIZE(iov_data(args));	\
		data.iov = util_iov_dup(iov, ARRAY_SIZE(iov_data(args))); \
		data.streams = queue_new(); \
		tester_add(name, &data, setup, function,	\
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
	IOV_DATA(0x01, 0x08, 0x22, 0x00, 0x0a),
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

static void test_setup_pacs(struct test_data *data)
{
	if (!data->cfg)
		return;

	if (data->cfg->src) {
		if (data->cfg->vs)
			data->snk = bt_bap_add_vendor_pac(data->db,
							"test-bap-snk",
							BT_BAP_SINK, 0x0ff,
							0x0001, 0x0001,
							NULL, data->caps, NULL);
		else
			data->snk = bt_bap_add_pac(data->db, "test-bap-snk",
							BT_BAP_SINK, LC3_ID,
							NULL, data->caps, NULL);
		g_assert(data->snk);
	}

	if (data->cfg->snk) {
		if (data->cfg->vs)
			data->src = bt_bap_add_vendor_pac(data->db,
							"test-bap-src",
							BT_BAP_SOURCE, 0x0ff,
							0x0001, 0x0001,
							NULL, data->caps, NULL);
		else
			data->src = bt_bap_add_pac(data->db, "test-bap-src",
							BT_BAP_SOURCE, LC3_ID,
							NULL, data->caps, NULL);
		g_assert(data->src);
	}
}

static void setup_complete_cb(const void *user_data)
{
	tester_setup_complete();
}

static int pac_config(struct bt_bap_stream *stream, struct iovec *cfg,
			struct bt_bap_qos *qos, bt_bap_pac_config_t cb,
			void *user_data)
{
	cb(stream, 0);

	return 0;
}

static struct bt_bap_pac_ops ucast_pac_ops = {
	.config = pac_config,
};

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

	gatt_db_ccc_register(db, gatt_ccc_read_cb, NULL, gatt_notify_cb, data);

	data->ccc_states = queue_new();

	if (data->cfg && data->cfg->vs)
		data->snk = bt_bap_add_vendor_pac(db, "test-bap-snk",
							BT_BAP_SINK, 0x0ff,
							0x0001, 0x0001,
							data->qos, NULL,
							NULL);
	else
		data->snk = bt_bap_add_pac(db, "test-bap-snk", BT_BAP_SINK,
							LC3_ID, data->qos,
							data->caps, NULL);
	g_assert(data->snk);

	bt_bap_pac_set_ops(data->snk, &ucast_pac_ops, NULL);

	if (data->cfg && data->cfg->vs)
		data->src = bt_bap_add_vendor_pac(db, "test-bap-snk",
							BT_BAP_SOURCE, 0x0ff,
							0x0001, 0x0001,
							data->qos, NULL,
							NULL);
	else
		data->src = bt_bap_add_pac(db, "test-bap-src", BT_BAP_SOURCE,
							LC3_ID, data->qos,
							data->caps, NULL);
	g_assert(data->src);

	bt_bap_pac_set_ops(data->src, &ucast_pac_ops, NULL);

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

static void bap_disable(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	if (code)
		tester_test_failed();
}

static void bap_start(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	if (code)
		tester_test_failed();
}

static void bap_enable(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	struct test_data *data = user_data;
	unsigned int id = 0;

	if (code) {
		tester_test_failed();
		return;
	}

	switch (data->cfg->state) {
	case BT_BAP_STREAM_STATE_ENABLING:
		return;
	case BT_BAP_STREAM_STATE_DISABLING:
		id = bt_bap_stream_disable(stream, true, bap_disable,
						data);
		break;
	case BT_BAP_STREAM_STATE_STREAMING:
		if (data->cfg->snk)
			return;
		id = bt_bap_stream_start(stream, bap_start, data);
		break;
	}

	g_assert(id);
}

static void bap_qos(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	struct test_data *data = user_data;

	if (code) {
		tester_test_failed();
		return;
	}

	if (data->cfg->state > BT_BAP_STREAM_STATE_QOS) {
		unsigned int qos_id;

		qos_id = bt_bap_stream_enable(stream, true, NULL,
							bap_enable, data);
		g_assert(qos_id);
	}
}

static void bap_config(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	struct test_data *data = user_data;

	if (code) {
		tester_test_failed();
		return;
	}

	if (data->cfg->state > BT_BAP_STREAM_STATE_CONFIG) {
		unsigned int qos_id;

		qos_id = bt_bap_stream_qos(stream, &data->cfg->qos,
					   bap_qos, data);
		g_assert(qos_id);
	}
}

static bool pac_found(struct bt_bap_pac *lpac, struct bt_bap_pac *rpac,
							void *user_data)
{
	struct test_data *data = user_data;
	unsigned int config_id;
	struct bt_bap_stream *stream;

	stream = bt_bap_stream_new(data->bap, lpac, rpac,
						&data->cfg->qos,
						&data->cfg->cc);
	g_assert(stream);

	queue_push_tail(data->streams, stream);

	config_id = bt_bap_stream_config(stream, &data->cfg->qos,
					&data->cfg->cc, bap_config, data);
	g_assert(config_id);

	return true;
}

static void bap_ready(struct bt_bap *bap, void *user_data)
{
	bt_bap_foreach_pac(bap, BT_BAP_SINK, pac_found, user_data);
	bt_bap_foreach_pac(bap, BT_BAP_SOURCE, pac_found, user_data);
}

static void test_client(const void *user_data)
{
	struct test_data *data = (void *)user_data;
	struct io *io;

	io = tester_setup_io(data->iov, data->iovcnt);
	g_assert(io);

	tester_io_set_complete_func(test_complete_cb);

	data->db = gatt_db_new();
	g_assert(data->db);

	test_setup_pacs(data);

	data->bap = bt_bap_new(data->db, bt_gatt_client_get_db(data->client));
	g_assert(data->bap);

	bt_bap_set_debug(data->bap, print_debug, "bt_bap:", NULL);

	bt_bap_ready_register(data->bap, bap_ready, data, NULL);

	if (data->cfg && data->cfg->state_func)
		bt_bap_state_register(data->bap, data->cfg->state_func, NULL,
						data, NULL);

	bt_bap_attach(data->bap, data->client);
}

static struct bt_bap_pac_ops bcast_pac_ops = {
	.config = pac_config,
};

static void bsrc_pac_added(struct bt_bap_pac *pac, void *user_data)
{
	struct test_data *data = user_data;
	struct bt_bap_stream *stream;

	bt_bap_pac_set_ops(pac, &bcast_pac_ops, NULL);

	for (uint8_t i = 0; i < data->cfg->streams; i++) {
		stream = bt_bap_stream_new(data->bap, pac, NULL,
							&data->cfg->qos,
							&data->cfg->cc);
		g_assert(stream);

		queue_push_tail(data->streams, stream);

		bt_bap_stream_config(stream, &data->cfg->qos,
						&data->cfg->cc, NULL, data);
	}
}

static void bsrc_state_cfg(struct bt_bap_stream *stream, uint8_t old_state,
				uint8_t new_state, void *user_data)
{
	struct test_data *data = user_data;

	switch (new_state) {
	case BT_BAP_STREAM_STATE_CONFIG:
		data->base = bt_bap_stream_get_base(stream);

		g_assert(data->base);
		g_assert(data->base->iov_len == data->cfg->base.iov_len);
		g_assert(memcmp(data->base->iov_base, data->cfg->base.iov_base,
				data->base->iov_len) == 0);

		tester_test_passed();
		break;
	}
}

static void bsnk_pac_added(struct bt_bap_pac *pac, void *user_data)
{
	struct test_data *data = user_data;
	struct bt_bap_pac *lpac;
	struct iovec *cc;
	struct bt_bap_stream *stream;
	uint8_t bis_idx = 1;

	bt_bap_pac_set_ops(pac, &bcast_pac_ops, NULL);

	for (uint8_t i = 0; i < data->cfg->streams; i++) {
		cc = bt_bap_merge_caps(&data->cfg->cc, NULL);
		g_assert(cc);

		bt_bap_verify_bis(data->bap, bis_idx++, cc, &lpac);

		g_assert(lpac);
		g_assert(pac == lpac);

		stream = bt_bap_stream_new(data->bap,
			pac, NULL, &data->cfg->qos, cc);

		g_assert(stream);

		queue_push_tail(data->streams, stream);

		bt_bap_stream_config(stream, &data->cfg->qos,
				cc, NULL, NULL);

		util_iov_free(cc, 1);
	}
}

static void bsnk_state(struct bt_bap_stream *stream, uint8_t old_state,
				uint8_t new_state, void *user_data)
{
	struct test_data *data = user_data;
	struct iovec *cc;

	switch (new_state) {
	case BT_BAP_STREAM_STATE_CONFIG:
		/* Check that stream has been configured as expected */
		cc = bt_bap_stream_get_config(stream);

		g_assert(cc);
		g_assert(cc->iov_len == data->cfg->cc.iov_len);
		g_assert(memcmp(cc->iov_base, data->cfg->cc.iov_base,
				cc->iov_len) == 0);

		tester_test_passed();
		break;
	}
}

static void test_bcast_config(struct test_data *data)
{
	if (!data->cfg)
		return;

	if (data->cfg->src) {
		bt_bap_pac_register(data->bap, bsrc_pac_added,
						NULL, data, NULL);

		if (data->cfg->vs)
			data->bsrc = bt_bap_add_vendor_pac(data->db,
							"test-bap-bsrc",
							BT_BAP_BCAST_SOURCE,
							0x0ff, 0x0000, 0x0000,
							NULL, data->caps,
							NULL);
		else
			data->bsrc = bt_bap_add_pac(data->db, "test-bap-bsrc",
							BT_BAP_BCAST_SOURCE,
							LC3_ID,
							NULL, data->caps,
							NULL);

		g_assert(data->bsrc);
	}

	if (data->cfg->snk) {
		bt_bap_pac_register(data->bap, bsnk_pac_added,
						NULL, data, NULL);

		if (data->cfg->vs)
			data->bsnk = bt_bap_add_vendor_pac(data->db,
							"test-bap-bsnk",
							BT_BAP_BCAST_SINK,
							0xff, 0x0000, 0x0000,
							NULL, data->caps,
							NULL);
		else
			data->bsnk = bt_bap_add_pac(data->db, "test-bap-bsnk",
							BT_BAP_BCAST_SINK,
							LC3_ID,
							NULL, data->caps,
							NULL);

		g_assert(data->bsnk);
	}
}

static void test_bcast(const void *user_data)
{
	struct test_data *data = (void *)user_data;

	data->db = gatt_db_new();
	g_assert(data->db);

	data->bap = bt_bap_new(data->db, data->db);
	g_assert(data->bap);

	bt_bap_set_debug(data->bap, print_debug, "bt_bap:", NULL);

	bt_bap_attach_broadcast(data->bap);

	if (data->cfg && data->cfg->state_func)
		bt_bap_state_register(data->bap, data->cfg->state_func, NULL,
						data, NULL);

	test_bcast_config(data);
}

static void test_teardown(const void *user_data)
{
	struct test_data *data = (void *)user_data;

	bt_bap_unregister(data->id);
	bt_bap_unref(data->bap);
	bt_gatt_client_unref(data->client);
	util_iov_free(data->iov, data->iovcnt);

	util_iov_free(data->base, 1);

	bt_bap_remove_pac(data->snk);
	bt_bap_remove_pac(data->src);
	bt_bap_remove_pac(data->bsrc);
	bt_bap_remove_pac(data->bsnk);
	gatt_db_unref(data->db);
	bt_gatt_server_unref(data->server);
	data->server = NULL;

	queue_destroy(data->streams, NULL);

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
 *         Frame Length: 26 (0x001a) - 240 (0x00f0)
 * ATT: Read Request (0x0a) len 2
 *   Handle: 0x0006 Type: Sink Audio Location (0x2bca)
 * ATT: Read Response (0x0b) len 4
 *   Value: 03000000
 *   Handle: 0x0006 Type: Sink Audio Locations (0x2bca)
 *     Location: 0x00000003
 *       Front Left (0x00000001)
 *       Front Right (0x00000002)
 */
#define DISC_SNK_PAC(_caps...) \
	IOV_DATA(0x0a, 0x03, 0x00), \
	IOV_DATA(0x0b, 0x01, _caps), \
	IOV_DATA(0x0a, 0x06, 0x00), \
	IOV_DATA(0x0b, 0x03, 0x00, 0x00, 0x00)

#define DISC_SNK_LC3 \
	DISC_SNK_PAC(0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x03, 0x01, \
		0xff, 0x00, 0x02, 0x02, 0x03, 0x02, 0x03, 0x03, 0x05, 0x04, \
		0x1a, 0x00, 0xf0, 0x00, 0x00)

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
 *         Frame Length: 26 (0x001e) - 240 (0x00f0)
 * ATT: Read Request (0x0a) len 2
 *   Handle: 0x000c Type: Source Audio Location (0x2bcc)
 * ATT: Read Response (0x0b) len 4
 *   Value: 03000000
 *   Handle: 0x000c Type: Source Audio Locations (0x2bcc)
 *     Location: 0x00000003
 *       Front Left (0x00000001)
 *       Front Right (0x00000002)
 */
#define DISC_SRC_PAC(_caps...) \
	DISC_SNK_PAC(_caps), \
	IOV_DATA(0x0a, 0x09, 0x00), \
	IOV_DATA(0x0b, 0x01, _caps), \
	IOV_DATA(0x0a, 0x0c, 0x00), \
	IOV_DATA(0x0b, 0x03, 0x00, 0x00, 0x00)

#define DISC_SRC_LC3 \
	DISC_SRC_PAC(0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x03, 0x01, \
		0xff, 0x00, 0x02, 0x02, 0x03, 0x02, 0x03, 0x03, 0x05, 0x04, \
		0x1a, 0x00, 0xf0, 0x00, 0x00)

/* ATT: Read Request (0x0a) len 2
 *   Handle: 0x000f Type: Available Audio Contexts (0x2bcd)
 * ATT: Read Response (0x0b) len 4
 *   Value: ff0fff0f
 *   Handle: 0x000f Type: Available Audio Contexts (0x2bcd)
 */
#define DISC_CTX(_caps...) \
	DISC_SRC_PAC(_caps), \
	IOV_DATA(0x0a, 0x0f, 0x00), \
	IOV_DATA(0x0b, 0xff, 0x0f, 0xff, 0x0f)

#define DISC_CTX_LC3 \
	DISC_CTX(0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x03, 0x01, \
		0xff, 0x00, 0x02, 0x02, 0x03, 0x02, 0x03, 0x03, 0x05, 0x04, \
		0x1a, 0x00, 0xf0, 0x00, 0x00)

/* ATT: Read Request (0x0a) len 2
 *   Handle: 0x0012 Type: Supported Audio Contexts (0x2bce)
 * ATT: Read Response (0x0b) len 4
 *   Value: ff0fff0f
 *   Handle: 0x0012 Type: Supported Audio Contexts (0x2bce)
 */
#define DISC_SUP_CTX(_caps...) \
	DISC_CTX(_caps), \
	IOV_DATA(0x0a, 0x12, 0x00), \
	IOV_DATA(0x0b, 0xff, 0x0f, 0xff, 0x0f)

#define DISC_SUP_CTX_LC3 \
	DISC_SUP_CTX(0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x03, 0x01, \
		0xff, 0x00, 0x02, 0x02, 0x03, 0x02, 0x03, 0x03, 0x05, 0x04, \
		0x1a, 0x00, 0xf0, 0x00, 0x00)

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
#define DISC_SNK_ASE(_caps...) \
	DISC_SUP_CTX(_caps), \
	IOV_DATA(0x0a, 0x16, 0x00), \
	IOV_DATA(0x0b, 0x01, 0x00), \
	IOV_DATA(0x12, 0x17, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	IOV_DATA(0x0a, 0x19, 0x00), \
	IOV_DATA(0x0b, 0x02, 0x00), \
	IOV_DATA(0x12, 0x1a, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13)

#define DISC_SNK_ASE_LC3 \
	DISC_SNK_ASE(0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x03, 0x01, \
		0xff, 0x00, 0x02, 0x02, 0x03, 0x02, 0x03, 0x03, 0x05, 0x04, \
		0x1a, 0x00, 0xf0, 0x00, 0x00)

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
#define DISC_SRC_ASE(_cfg...) \
	DISC_SNK_ASE(_cfg), \
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

#define DISC_SRC_ASE_LC3 \
	DISC_SRC_ASE(0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x03, 0x01, \
		0xff, 0x00, 0x02, 0x02, 0x03, 0x02, 0x03, 0x03, 0x05, 0x04, \
		0x1a, 0x00, 0xf0, 0x00, 0x00)

#define DISC_ASE_LC3 \
	DISC_SNK_ASE_LC3, \
	DISC_SRC_ASE_LC3

static void test_ucl_disc(void)
{
	/* The IUT discovers the characteristics specified in the PAC
	 * Characteristic and Location Characteristic columns in Table 4.4.
	 * The IUT reads the values of the characteristics specified in the PAC
	 * Characteristic and Location Characteristic columns.
	 */
	define_test("BAP/UCL/DISC/BV-01-C", test_setup, test_client, NULL,
						DISC_SNK_LC3);
	define_test("BAP/UCL/DISC/BV-02-C", test_setup, test_client, NULL,
						DISC_SRC_LC3);

	/* BAP/UCL/DISC/BV-06-C [Discover Available Audio Contexts]
	 *
	 * The IUT successfully reads the value of the Available Audio Contexts
	 * characteristic on the LowerTester.
	 */
	define_test("BAP/UCL/DISC/BV-06-C", test_setup, test_client, NULL,
						DISC_CTX_LC3);

	/* BAP/UCL/DISC/BV-05-C [Discover Supported Audio Contexts]
	 *
	 * The IUT successfully reads the value of the Supported Audio Contexts
	 * characteristic on the Lower Tester.
	 */
	define_test("BAP/UCL/DISC/BV-05-C", test_setup, test_client, NULL,
						DISC_SUP_CTX_LC3);

	/* BAP/UCL/DISC/BV-03-C [Discover Sink ASE_ID]
	 * BAP/UCL/DISC/BV-04-C [Discover Source ASE_ID]
	 *
	 * The IUT successfully reads the ASE_ID values of each discovered ASE
	 * characteristic on the LowerTester.
	 */
	define_test("BAP/UCL/DISC/BV-03-C", test_setup, test_client, NULL,
						DISC_SNK_ASE_LC3);
	define_test("BAP/UCL/DISC/BV-04-C", test_setup, test_client, NULL,
						DISC_SRC_ASE_LC3);
}

static void server_state_changed(struct bt_bap_stream *stream,
					uint8_t old_state, uint8_t new_state,
					void *user_data)
{
	if (new_state == BT_BAP_STREAM_STATE_ENABLING)
		bt_bap_stream_start(stream, NULL, NULL);
}

static void bap_attached(struct bt_bap *bap, void *user_data)
{
	struct test_data *data = (void *)user_data;

	if (tester_use_debug())
		tester_debug("bap %p session attached", bap);

	data->bap = bap;

	bt_bap_set_debug(data->bap, print_debug, "bt_bap:", NULL);

	if (data->cfg && data->cfg->state == BT_BAP_STREAM_STATE_STREAMING)
		bt_bap_state_register(data->bap, server_state_changed, NULL,
						data, NULL);
}

static void test_server(const void *user_data)
{
	struct test_data *data = (void *)user_data;
	struct io *io;

	io = tester_setup_io(data->iov, data->iovcnt);
	g_assert(io);

	tester_io_set_complete_func(test_complete_cb);

	data->id = bt_bap_register(bap_attached, NULL, data);
	g_assert(data->id);

	tester_io_send();
}

static void test_usr_disc(void)
{
	/* BAP/USR/DISC/BV-01-C [Expose Audio Sink Capabilities]
	 * BAP/USR/DISC/BV-02-C [Expose Audio Source Capabilities]
	 *
	 * The specified PAC Characteristic and the Location Characteristic,
	 * if supported, are read on the IUT.
	 */
	define_test("BAP/USR/DISC/BV-01-C", test_setup_server, test_server,
						NULL, DISC_SNK_LC3);
	define_test("BAP/USR/DISC/BV-02-C", test_setup_server, test_server,
						NULL, DISC_SRC_LC3);

	/* BAP/UCL/DISC/BV-06-C [Discover Available Audio Contexts]
	 *
	 * The IUT successfully reads the value of the Available Audio Contexts
	 * characteristic on the Lower Tester.
	 */
	define_test("BAP/USR/DISC/BV-06-C", test_setup_server, test_server,
						NULL, DISC_CTX_LC3);

	/* BAP/USR/DISC/BV-07-C [Expose Supported Audio Contexts]
	 *
	 * The IUT successfully returns the value of its Supported Audio
	 * Contexts characteristic when read by the Lower Tester.
	 */
	define_test("BAP/USR/DISC/BV-07-C", test_setup_server, test_server,
						NULL, DISC_SUP_CTX_LC3);

	/* BAP/USR/DISC/BV-03-C [Expose Sink ASE_ID]
	 * BAP/USR/DISC/BV-04-C [Expose Source ASE_ID]
	 * BAP/USR/DISC/BV-05-C [Expose Sink and Source ASE_ID]
	 *
	 * The IUT successfully returns the values of each ASE characteristic
	 * read by the Lower Tester. The value of the ASE_ID field is unique
	 * for each ASE characteristic.
	 */
	define_test("BAP/USR/DISC/BV-03-C", test_setup_server, test_server,
						NULL, DISC_SNK_ASE_LC3);
	define_test("BAP/USR/DISC/BV-04-C", test_setup_server, test_server,
						NULL, DISC_SRC_ASE_LC3);
	define_test("BAP/USR/DISC/BV-05-C", test_setup_server, test_server,
						NULL, DISC_ASE_LC3);
}

static void test_disc(void)
{
	test_ucl_disc();
	test_usr_disc();
}

/* ATT: Write Command (0x52) len 23
 *  Handle: 0x0022
 *    Data: 0101010202_cfg
 * ATT: Handle Value Notification (0x1b) len 7
 *   Handle: 0x0022
 *     Data: 0101010000
 * ATT: Handle Value Notification (0x1b) len 37
 *   Handle: 0x0016
 *     Data: 01010002010a00204e00409c00204e00409c00_cfg
 */
#define SCC_SNK(_cfg...) \
	IOV_DATA(0x52, 0x22, 0x00, 0x01, 0x01, 0x01, 0x02, 0x02, _cfg), \
	IOV_DATA(0x1b, 0x22, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00), \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x16, 0x00, 0x01, 0x01, 0x00, 0x02, 0x01, 0x0a, 0x00, \
			0x20, 0x4e, 0x00, 0x40, 0x9c, 0x00, 0x20, 0x4e, 0x00, \
			0x40, 0x9c, 0x00, _cfg)

#define SCC_SNK_LC3(_cc...) \
	DISC_SRC_ASE_LC3, \
	SCC_SNK(0x06, 0x00, 0x00, 0x00, 0x00, _cc)

#define QOS_BALANCED_2M \
	{ \
		.target_latency = BT_BAP_CONFIG_LATENCY_BALANCED, \
		.io_qos.phy = BT_BAP_CONFIG_PHY_2M, \
	}
#define QOS_UCAST \
{\
	.ucast = QOS_BALANCED_2M, \
}
static struct test_config cfg_snk_8_1 = {
	.cc = LC3_CONFIG_8_1,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_8_1 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x1a, 0x00)

static struct test_config cfg_snk_8_2 = {
	.cc = LC3_CONFIG_8_2,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_8_2 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x01, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x1e, 0x00)

static struct test_config cfg_snk_16_1 = {
	.cc = LC3_CONFIG_16_1,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_16_1 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x03, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x1e, 0x00)

static struct test_config cfg_snk_16_2 = {
	.cc = LC3_CONFIG_16_2,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_16_2 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x03, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x28, 0x00)

static struct test_config cfg_snk_24_1 = {
	.cc = LC3_CONFIG_24_1,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_24_1 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x05, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x2d, 0x00)

static struct test_config cfg_snk_24_2 = {
	.cc = LC3_CONFIG_24_2,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_24_2 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x05, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x3c, 0x00)

static struct test_config cfg_snk_32_1 = {
	.cc = LC3_CONFIG_32_1,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_32_1 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x06, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x3c, 0x00)

static struct test_config cfg_snk_32_2 = {
	.cc = LC3_CONFIG_32_2,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_32_2 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x06, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x50, 0x00)

static struct test_config cfg_snk_44_1 = {
	.cc = LC3_CONFIG_44_1,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_44_1 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x07, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x62, 0x00)

static struct test_config cfg_snk_44_2 = {
	.cc = LC3_CONFIG_44_2,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_44_2 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x07, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x82, 0x00)

static struct test_config cfg_snk_48_1 = {
	.cc = LC3_CONFIG_48_1,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_48_1 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x08, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x4b, 0x00)

static struct test_config cfg_snk_48_2 = {
	.cc = LC3_CONFIG_48_2,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_48_2 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x08, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x64, 0x00)

static struct test_config cfg_snk_48_3 = {
	.cc = LC3_CONFIG_48_3,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_48_3 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x08, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x5a, 0x00)

static struct test_config cfg_snk_48_4 = {
	.cc = LC3_CONFIG_48_4,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_48_4 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x08, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x78, 0x00)

static struct test_config cfg_snk_48_5 = {
	.cc = LC3_CONFIG_48_5,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_48_5 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x08, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x75, 0x00)

static struct test_config cfg_snk_48_6 = {
	.cc = LC3_CONFIG_48_6,
	.qos = QOS_UCAST,
	.snk = true,
};

#define SCC_SNK_48_6 \
	SCC_SNK_LC3(0x0a, 0x02, 0x01, 0x08, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x9b, 0x00)

/* ATT: Write Command (0x52) len 23
 *  Handle: 0x0022
 *    Data: 0101030202_cfg
 * ATT: Handle Value Notification (0x1b) len 7
 *   Handle: 0x0022
 *     Data: 0101030000
 * ATT: Handle Value Notification (0x1b) len 37
 *   Handle: 0x001c
 *     Data: 03010002010a00204e00409c00204e00409c00_cfg
 */
#define SCC_SRC(_cfg...) \
	IOV_DATA(0x52, 0x22, 0x00, 0x01, 0x01, 0x03, 0x02, 0x02, _cfg), \
	IOV_DATA(0x1b, 0x22, 0x00, 0x01, 0x01, 0x03, 0x00, 0x00), \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x1c, 0x00, 0x03, 0x01, 0x00, 0x02, 0x01, 0x0a, 0x00, \
			0x20, 0x4e, 0x00, 0x40, 0x9c, 0x00, 0x20, 0x4e, 0x00, \
			0x40, 0x9c, 0x00, _cfg)

#define SCC_SRC_LC3(_cc...) \
	DISC_SRC_ASE_LC3, \
	SCC_SRC(0x06, 0x00, 0x00, 0x00, 0x00, _cc)

static struct test_config cfg_src_8_1 = {
	.cc = LC3_CONFIG_8_1,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_8_1 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x03, 0x04, \
			    0x1a, 0x00)

static struct test_config cfg_src_8_2 = {
	.cc = LC3_CONFIG_8_2,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_8_2 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x01, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x1e, 0x00)

static struct test_config cfg_src_16_1 = {
	.cc = LC3_CONFIG_16_1,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_16_1 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x03, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x1e, 0x00)

static struct test_config cfg_src_16_2 = {
	.cc = LC3_CONFIG_16_2,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_16_2 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x03, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x28, 0x00)

static struct test_config cfg_src_24_1 = {
	.cc = LC3_CONFIG_24_1,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_24_1 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x05, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x2d, 0x00)

static struct test_config cfg_src_24_2 = {
	.cc = LC3_CONFIG_24_2,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_24_2 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x05, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x3c, 0x00)

static struct test_config cfg_src_32_1 = {
	.cc = LC3_CONFIG_32_1,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_32_1 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x06, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x3c, 0x00)

static struct test_config cfg_src_32_2 = {
	.cc = LC3_CONFIG_32_2,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_32_2 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x06, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x50, 0x00)

static struct test_config cfg_src_44_1 = {
	.cc = LC3_CONFIG_44_1,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_44_1 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x07, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x62, 0x00)

static struct test_config cfg_src_44_2 = {
	.cc = LC3_CONFIG_44_2,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_44_2 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x07, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x82, 0x00)

static struct test_config cfg_src_48_1 = {
	.cc = LC3_CONFIG_48_1,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_48_1 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x08, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x4b, 0x00)

static struct test_config cfg_src_48_2 = {
	.cc = LC3_CONFIG_48_2,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_48_2 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x08, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x64, 0x00)

static struct test_config cfg_src_48_3 = {
	.cc = LC3_CONFIG_48_3,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_48_3 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x08, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x5a, 0x00)

static struct test_config cfg_src_48_4 = {
	.cc = LC3_CONFIG_48_4,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_48_4 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x08, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x78, 0x00)

static struct test_config cfg_src_48_5 = {
	.cc = LC3_CONFIG_48_5,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_48_5 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x08, 0x02, 0x02, 0x00, 0x03, 0x04, \
			0x75, 0x00)

static struct test_config cfg_src_48_6 = {
	.cc = LC3_CONFIG_48_6,
	.qos = QOS_UCAST,
	.src = true,
};

#define SCC_SRC_48_6 \
	SCC_SRC_LC3(0x0a, 0x02, 0x01, 0x08, 0x02, 0x02, 0x01, 0x03, 0x04, \
			0x9b, 0x00)

/* Test Purpose:
 * Verify that a Unicast Client IUT can initiate a Config Codec
 * operation for an LC3 codec.
 *
 * Pass verdict:
 * The IUT successfully writes to the ASE Control point with the opcode
 * set to 0x01 (Config Codec) and correctly formatted parameter values
 * from Table 4.9. The Codec_ID field is a 5-octet field with octet 0
 * set to the LC3 Coding_Format value defined in Bluetooth Assigned
 * Numbers, octets 1–4 set to 0x0000. Each parameter (if present)
 * included in the data sent in Codec_Specific_Configuration is
 * formatted in an LTV structure with the length, type, and value
 * specified in Table 4.10.
 */
static void test_ucl_scc_cc_lc3(void)
{
	define_test("BAP/UCL/SCC/BV-001-C [UCL SRC Config Codec, LC3 8_1]",
			test_setup, test_client, &cfg_snk_8_1, SCC_SNK_8_1);
	define_test("BAP/UCL/SCC/BV-002-C [UCL SRC Config Codec, LC3 8_2]",
			test_setup, test_client, &cfg_snk_8_2, SCC_SNK_8_2);
	define_test("BAP/UCL/SCC/BV-003-C [UCL SRC Config Codec, LC3 16_1]",
			test_setup, test_client, &cfg_snk_16_1, SCC_SNK_16_1);
	define_test("BAP/UCL/SCC/BV-004-C [UCL SRC Config Codec, LC3 16_2]",
			test_setup, test_client, &cfg_snk_16_2, SCC_SNK_16_2);
	define_test("BAP/UCL/SCC/BV-005-C [UCL SRC Config Codec, LC3 24_1]",
			test_setup, test_client, &cfg_snk_24_1, SCC_SNK_24_1);
	define_test("BAP/UCL/SCC/BV-006-C [UCL SRC Config Codec, LC3 24_2]",
			test_setup, test_client, &cfg_snk_24_2, SCC_SNK_24_2);
	define_test("BAP/UCL/SCC/BV-007-C [UCL SRC Config Codec, LC3 32_1]",
			test_setup, test_client, &cfg_snk_32_1, SCC_SNK_32_1);
	define_test("BAP/UCL/SCC/BV-008-C [UCL SRC Config Codec, LC3 32_2]",
			test_setup, test_client, &cfg_snk_32_2, SCC_SNK_32_2);
	define_test("BAP/UCL/SCC/BV-009-C [UCL SRC Config Codec, LC3 44.1_1]",
			test_setup, test_client, &cfg_snk_44_1, SCC_SNK_44_1);
	define_test("BAP/UCL/SCC/BV-010-C [UCL SRC Config Codec, LC3 44.1_2]",
			test_setup, test_client, &cfg_snk_44_2, SCC_SNK_44_2);
	define_test("BAP/UCL/SCC/BV-011-C [UCL SRC Config Codec, LC3 48_1]",
			test_setup, test_client, &cfg_snk_48_1, SCC_SNK_48_1);
	define_test("BAP/UCL/SCC/BV-012-C [UCL SRC Config Codec, LC3 48_2]",
			test_setup, test_client, &cfg_snk_48_2, SCC_SNK_48_2);
	define_test("BAP/UCL/SCC/BV-013-C [UCL SRC Config Codec, LC3 48_3]",
			test_setup, test_client, &cfg_snk_48_3, SCC_SNK_48_3);
	define_test("BAP/UCL/SCC/BV-014-C [UCL SRC Config Codec, LC3 48_4]",
			test_setup, test_client, &cfg_snk_48_4, SCC_SNK_48_4);
	define_test("BAP/UCL/SCC/BV-015-C [UCL SRC Config Codec, LC3 48_5]",
			test_setup, test_client, &cfg_snk_48_5, SCC_SNK_48_5);
	define_test("BAP/UCL/SCC/BV-016-C [UCL SRC Config Codec, LC3 48_6]",
			test_setup, test_client, &cfg_snk_48_6, SCC_SNK_48_6);
	define_test("BAP/UCL/SCC/BV-017-C [UCL SNK Config Codec, LC3 8_1]",
			test_setup, test_client, &cfg_src_8_1, SCC_SRC_8_1);
	define_test("BAP/UCL/SCC/BV-018-C [UCL SNK Config Codec, LC3 8_2]",
			test_setup, test_client, &cfg_src_8_2, SCC_SRC_8_2);
	define_test("BAP/UCL/SCC/BV-019-C [UCL SNK Config Codec, LC3 16_1]",
			test_setup, test_client, &cfg_src_16_1, SCC_SRC_16_1);
	define_test("BAP/UCL/SCC/BV-020-C [UCL SNK Config Codec, LC3 16_2]",
			test_setup, test_client, &cfg_src_16_2, SCC_SRC_16_2);
	define_test("BAP/UCL/SCC/BV-021-C [UCL SNK Config Codec, LC3 24_1]",
			test_setup, test_client, &cfg_src_24_1, SCC_SRC_24_1);
	define_test("BAP/UCL/SCC/BV-022-C [UCL SNK Config Codec, LC3 24_2]",
			test_setup, test_client, &cfg_src_24_2, SCC_SRC_24_2);
	define_test("BAP/UCL/SCC/BV-023-C [UCL SNK Config Codec, LC3 32_1]",
			test_setup, test_client, &cfg_src_32_1, SCC_SRC_32_1);
	define_test("BAP/UCL/SCC/BV-024-C [UCL SNK Config Codec, LC3 32_2]",
			test_setup, test_client, &cfg_src_32_2, SCC_SRC_32_2);
	define_test("BAP/UCL/SCC/BV-025-C [UCL SNK Config Codec, LC3 44.1_1]",
			test_setup, test_client, &cfg_src_44_1, SCC_SRC_44_1);
	define_test("BAP/UCL/SCC/BV-026-C [UCL SNK Config Codec, LC3 44.1_2]",
			test_setup, test_client, &cfg_src_44_2, SCC_SRC_44_2);
	define_test("BAP/UCL/SCC/BV-027-C [UCL SNK Config Codec, LC3 48_1]",
			test_setup, test_client, &cfg_src_48_1, SCC_SRC_48_1);
	define_test("BAP/UCL/SCC/BV-028-C [UCL SNK Config Codec, LC3 48_2]",
			test_setup, test_client, &cfg_src_48_2, SCC_SRC_48_2);
	define_test("BAP/UCL/SCC/BV-029-C [UCL SNK Config Codec, LC3 48_3]",
			test_setup, test_client, &cfg_src_48_3, SCC_SRC_48_3);
	define_test("BAP/UCL/SCC/BV-030-C [UCL SNK Config Codec, LC3 48_4]",
			test_setup, test_client, &cfg_src_48_4, SCC_SRC_48_4);
	define_test("BAP/UCL/SCC/BV-031-C [UCL SNK Config Codec, LC3 48_5]",
			test_setup, test_client, &cfg_src_48_5, SCC_SRC_48_5);
	define_test("BAP/UCL/SCC/BV-032-C [UCL SNK Config Codec, LC3 48_6]",
			test_setup, test_client, &cfg_src_48_6, SCC_SRC_48_6);
}


/* 4.9 Unicast Server Configuration */
static void test_usr_scc_cc_lc3(void)
{
	/* 4.9.1 Unicast Server as Audio Sink Performs Config Codec – LC3
	 *
	 * Test Purpose:
	 * Verify that a Unicast Server Audio Sink IUT can perform a Config
	 * Codec operation initiated by a Unicast Client for an ASE in the Idle
	 * state, the Codec Configured state.
	 *
	 * Pass Veridict:
	 * The IUT sends a Response_Code of 0x00 (Success) in response to each
	 * Config Codec operation.
	 *
	 * BAP/USR/SCC/BV-001-C [USR SNK Config Codec, LC3 8_1]
	 * BAP/USR/SCC/BV-002-C [USR SNK Config Codec, LC3 8_2]
	 * BAP/USR/SCC/BV-003-C [USR SNK Config Codec, LC3 16_1]
	 * BAP/USR/SCC/BV-004-C [USR SNK Config Codec, LC3 16_2]
	 * BAP/USR/SCC/BV-005-C [USR SNK Config Codec, LC3 24_1]
	 * BAP/USR/SCC/BV-006-C [USR SNK Config Codec, LC3 24_2]
	 * BAP/USR/SCC/BV-007-C [USR SNK Config Codec, LC3 32_1]
	 * BAP/USR/SCC/BV-008-C [USR SNK Config Codec, LC3 32_2]
	 * BAP/USR/SCC/BV-009-C [USR SNK Config Codec, LC3 44.1_1]
	 * BAP/USR/SCC/BV-010-C [USR SNK Config Codec, LC3 44.1_2]
	 * BAP/USR/SCC/BV-011-C [USR SNK Config Codec, LC3 48_1]
	 * BAP/USR/SCC/BV-012-C [USR SNK Config Codec, LC3 48_2]
	 * BAP/USR/SCC/BV-013-C [USR SNK Config Codec, LC3 48_3]
	 * BAP/USR/SCC/BV-014-C [USR SNK Config Codec, LC3 48_4]
	 * BAP/USR/SCC/BV-015-C [USR SNK Config Codec, LC3 48_5]
	 * BAP/USR/SCC/BV-016-C [USR SNK Config Codec, LC3 48_6]
	 */
	define_test("BAP/USR/SCC/BV-001-C [USR SNK Config Codec, LC3 8_1]",
			test_setup_server, test_server, &cfg_snk_8_1,
			SCC_SNK_8_1);
	define_test("BAP/USR/SCC/BV-002-C [USR SNK Config Codec, LC3 8_2]",
			test_setup_server, test_server, &cfg_snk_8_2,
			SCC_SNK_8_2);
	define_test("BAP/USR/SCC/BV-003-C [USR SNK Config Codec, LC3 16_1]",
			test_setup_server, test_server, &cfg_snk_16_1,
			SCC_SNK_16_1);
	define_test("BAP/USR/SCC/BV-004-C [USR SNK Config Codec, LC3 16_2]",
			test_setup_server, test_server, &cfg_snk_16_2,
			SCC_SNK_16_2);
	define_test("BAP/USR/SCC/BV-005-C [USR SNK Config Codec, LC3 24_1]",
			test_setup_server, test_server, &cfg_snk_24_1,
			SCC_SNK_24_1);
	define_test("BAP/USR/SCC/BV-006-C [USR SNK Config Codec, LC3 24_2]",
			test_setup_server, test_server, &cfg_snk_24_2,
			SCC_SNK_24_2);
	define_test("BAP/USR/SCC/BV-007-C [USR SNK Config Codec, LC3 32_1]",
			test_setup_server, test_server, &cfg_snk_32_1,
			SCC_SNK_32_1);
	define_test("BAP/USR/SCC/BV-008-C [USR SNK Config Codec, LC3 32_2]",
			test_setup_server, test_server, &cfg_snk_32_2,
			SCC_SNK_32_2);
	define_test("BAP/USR/SCC/BV-009-C [USR SNK Config Codec, LC3 44.1_1]",
			test_setup_server, test_server, &cfg_snk_44_1,
			SCC_SNK_44_1);
	define_test("BAP/USR/SCC/BV-010-C [USR SNK Config Codec, LC3 44.1_2]",
			test_setup_server, test_server, &cfg_snk_44_2,
			SCC_SNK_44_2);
	define_test("BAP/USR/SCC/BV-011-C [USR SNK Config Codec, LC3 48_1]",
			test_setup_server, test_server, &cfg_snk_48_1,
			SCC_SNK_48_1);
	define_test("BAP/USR/SCC/BV-012-C [USR SNK Config Codec, LC3 48_2]",
			test_setup_server, test_server, &cfg_snk_48_2,
			SCC_SNK_48_2);
	define_test("BAP/USR/SCC/BV-013-C [USR SNK Config Codec, LC3 48_3]",
			test_setup_server, test_server, &cfg_snk_48_3,
			SCC_SNK_48_3);
	define_test("BAP/USR/SCC/BV-014-C [USR SNK Config Codec, LC3 48_4]",
			test_setup_server, test_server, &cfg_snk_48_4,
			SCC_SNK_48_4);
	define_test("BAP/USR/SCC/BV-015-C [USR SNK Config Codec, LC3 48_5]",
			test_setup_server, test_server, &cfg_snk_48_5,
			SCC_SNK_48_5);
	define_test("BAP/USR/SCC/BV-016-C [USR SNK Config Codec, LC3 48_6]",
			test_setup_server, test_server, &cfg_snk_48_6,
			SCC_SNK_48_6);
	/* 4.9.2 Unicast Server as Audio Source Performs Config Codec – LC3
	 *
	 * Test Purpose:
	 * Verify that a Unicast Server Audio Source IUT can perform a Config
	 * Codec operation initiated by a Unicast Client for an ASE in the Idle
	 * state, the Codec Configured state.
	 *
	 * Pass verdict:
	 * The IUT sends a Response_Code of 0x00 (Success) in response to each
	 * Config Codec operation.
	 *
	 * BAP/USR/SCC/BV-017-C [USR SRC Config Codec, LC3 8_1]
	 * BAP/USR/SCC/BV-018-C [USR SRC Config Codec, LC3 8_2]
	 * BAP/USR/SCC/BV-019-C [USR SRC Config Codec, LC3 16_1]
	 * BAP/USR/SCC/BV-020-C [USR SRC Config Codec, LC3 16_2]
	 * BAP/USR/SCC/BV-021-C [USR SRC Config Codec, LC3 24_1]
	 * BAP/USR/SCC/BV-022-C [USR SRC Config Codec, LC3 24_2]
	 * BAP/USR/SCC/BV-023-C [USR SRC Config Codec, LC3 32_1]
	 * BAP/USR/SCC/BV-024-C [USR SRC Config Codec, LC3 32_2]
	 * BAP/USR/SCC/BV-025-C [USR SRC Config Codec, LC3 44.1_1]
	 * BAP/USR/SCC/BV-026-C [USR SRC Config Codec, LC3 44.1_2]
	 * BAP/USR/SCC/BV-027-C [USR SRC Config Codec, LC3 48_1]
	 * BAP/USR/SCC/BV-028-C [USR SRC Config Codec, LC3 48_2]
	 * BAP/USR/SCC/BV-029-C [USR SRC Config Codec, LC3 48_3]
	 * BAP/USR/SCC/BV-030-C [USR SRC Config Codec, LC3 48_4]
	 * BAP/USR/SCC/BV-031-C [USR SRC Config Codec, LC3 48_5]
	 * BAP/USR/SCC/BV-032-C [USR SRC Config Codec, LC3 48_6]
	 */
	define_test("BAP/USR/SCC/BV-017-C [USR SRC Config Codec, LC3 8_1]",
			test_setup_server, test_server, &cfg_src_8_1,
			SCC_SRC_8_1);
	define_test("BAP/USR/SCC/BV-018-C [USR SRC Config Codec, LC3 8_2]",
			test_setup_server, test_server, &cfg_src_8_2,
			SCC_SRC_8_2);
	define_test("BAP/USR/SCC/BV-019-C [USR SRC Config Codec, LC3 16_1]",
			test_setup_server, test_server, &cfg_src_16_1,
			SCC_SRC_16_1);
	define_test("BAP/USR/SCC/BV-020-C [USR SRC Config Codec, LC3 16_2]",
			test_setup_server, test_server, &cfg_src_16_2,
			SCC_SRC_16_2);
	define_test("BAP/USR/SCC/BV-021-C [USR SRC Config Codec, LC3 24_1]",
			test_setup_server, test_server, &cfg_src_24_1,
			SCC_SRC_24_1);
	define_test("BAP/USR/SCC/BV-022-C [USR SRC Config Codec, LC3 24_2]",
			test_setup_server, test_server, &cfg_src_24_2,
			SCC_SRC_24_2);
	define_test("BAP/USR/SCC/BV-023-C [USR SRC Config Codec, LC3 32_1]",
			test_setup_server, test_server, &cfg_src_32_1,
			SCC_SRC_32_1);
	define_test("BAP/USR/SCC/BV-024-C [USR SRC Config Codec, LC3 32_2]",
			test_setup_server, test_server, &cfg_src_32_2,
			SCC_SRC_32_2);
	define_test("BAP/USR/SCC/BV-025-C [USR SRC Config Codec, LC3 44.1_1]",
			test_setup_server, test_server, &cfg_src_44_1,
			SCC_SRC_44_1);
	define_test("BAP/USR/SCC/BV-026-C [USR SRC Config Codec, LC3 44.1_2]",
			test_setup_server, test_server, &cfg_src_44_2,
			SCC_SRC_44_2);
	define_test("BAP/USR/SCC/BV-027-C [USR SRC Config Codec, LC3 48_1]",
			test_setup_server, test_server, &cfg_src_48_1,
			SCC_SRC_48_1);
	define_test("BAP/USR/SCC/BV-028-C [USR SRC Config Codec, LC3 48_2]",
			test_setup_server, test_server, &cfg_src_48_2,
			SCC_SRC_48_2);
	define_test("BAP/USR/SCC/BV-029-C [USR SRC Config Codec, LC3 48_3]",
			test_setup_server, test_server, &cfg_src_48_3,
			SCC_SRC_48_3);
	define_test("BAP/USR/SCC/BV-030-C [USR SRC Config Codec, LC3 48_4]",
			test_setup_server, test_server, &cfg_src_48_4,
			SCC_SRC_48_4);
	define_test("BAP/USR/SCC/BV-031-C [USR SRC Config Codec, LC3 48_5]",
			test_setup_server, test_server, &cfg_src_48_5,
			SCC_SRC_48_5);
	define_test("BAP/USR/SCC/BV-032-C [USR SRC Config Codec, LC3 48_6]",
			test_setup_server, test_server, &cfg_src_48_6,
			SCC_SRC_48_6);
}

static void test_scc_cc_lc3(void)
{
	test_ucl_scc_cc_lc3();
	test_usr_scc_cc_lc3();
}

static struct test_config cfg_snk_vs = {
	.cc = IOV_NULL,
	.qos = QOS_UCAST,
	.snk = true,
	.vs = true,
};

#define DISC_SRC_ASE_VS \
	DISC_SRC_ASE(0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00)

#define SCC_SNK_VS \
	DISC_SRC_ASE_VS,  \
	SCC_SNK(0xff, 0x01, 0x00, 0x01, 0x00, 0x00)

static struct test_config cfg_src_vs = {
	.cc = IOV_NULL,
	.qos = QOS_UCAST,
	.src = true,
	.vs = true,
};

#define SCC_SRC_VS \
	DISC_SRC_ASE_VS,  \
	SCC_SRC(0xff, 0x01, 0x00, 0x01, 0x00, 0x00)

/* Test Purpose:
 * Verify that a Unicast Client IUT can initiate a Config Codec operation for a
 * vendor-specific codec.
 *
 * Pass verdict:
 * The IUT successfully writes to the ASE Control Point characteristic with the
 * opcode set to 0x01 (Config Codec) and the specified parameters. The Codec_ID
 * parameter is formatted with octet 0 set to 0xFF, octets 1–2 set to
 * TSPX_VS_Company_ID, and octets 3–4 set to TSPX_VS_Codec_ID.
 */
static void test_ucl_scc_cc_vs(void)
{
	define_test("BAP/UCL/SCC/BV-033-C [UCL SRC Config Codec, VS]",
			test_setup, test_client, &cfg_snk_vs, SCC_SNK_VS);
	define_test("BAP/UCL/SCC/BV-034-C [UCL SNK Config Codec, VS]",
			test_setup, test_client, &cfg_src_vs, SCC_SRC_VS);
}

static void test_usr_scc_cc_vs(void)
{
	/* BAP/USR/SCC/BV-033-C [USR SNK Config Codec, VS]
	 *
	 * Test Purpose:
	 * Verify that a Unicast Server Audio Sink IUT can perform a Config
	 * Codec operation initiated by a Unicast Client for a vendor-specific
	 * codec for an ASE in the Idle state, the Codec Configured state, and
	 * the QoS Configured state.
	 *
	 * Pass verdict:
	 * The IUT sends a notification of the ASE Control Point characteristic
	 * with the Response_Code field set to 0x00 (Success) for the requested
	 * ASE_ID and opcode.
	 */
	define_test("BAP/USR/SCC/BV-033-C [USR SNK Config Codec, VS]",
			test_setup_server, test_server, &cfg_snk_vs,
			SCC_SNK_VS);
	/* BAP/USR/SCC/BV-034-C [USR SRC Config Codec, VS]
	 *
	 * Test Purpose:
	 * Verify that a Unicast Server Audio Source IUT can perform a Config
	 * Codec operation initiated by a Unicast Client for a vendor-specific
	 * codec for a Source ASE in the Idle state.
	 *
	 * Pass verdict:
	 * The IUT sends a notification of the ASE Control Point characteristic
	 * with the Response_Code field set to 0x00 (Success) for the requested
	 * ASE_ID and opcode.
	 */
	define_test("BAP/USR/SCC/BV-034-C [USR SRC Config Codec, VS]",
			test_setup_server, test_server, &cfg_src_vs,
			SCC_SRC_VS);
}

static void test_scc_cc_vs(void)
{
	test_ucl_scc_cc_vs();
	test_usr_scc_cc_vs();
}

static struct test_config cfg_snk_8_1_1 = {
	.cc = LC3_CONFIG_8_1,
	.qos = LC3_QOS_8_1_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_8_2_1 = {
	.cc = LC3_CONFIG_8_2,
	.qos = LC3_QOS_8_2_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_16_1_1 = {
	.cc = LC3_CONFIG_16_1,
	.qos = LC3_QOS_16_1_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_16_2_1 = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_24_1_1 = {
	.cc = LC3_CONFIG_24_1,
	.qos = LC3_QOS_24_1_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_24_2_1 = {
	.cc = LC3_CONFIG_24_2,
	.qos = LC3_QOS_24_2_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_32_1_1 = {
	.cc = LC3_CONFIG_32_1,
	.qos = LC3_QOS_32_1_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_32_2_1 = {
	.cc = LC3_CONFIG_32_2,
	.qos = LC3_QOS_32_2_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_44_1_1 = {
	.cc = LC3_CONFIG_44_1,
	.qos = LC3_QOS_44_1_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_44_2_1 = {
	.cc = LC3_CONFIG_44_2,
	.qos = LC3_QOS_44_2_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_48_1_1 = {
	.cc = LC3_CONFIG_48_1,
	.qos = LC3_QOS_48_1_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_48_2_1 = {
	.cc = LC3_CONFIG_48_2,
	.qos = LC3_QOS_48_2_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_48_3_1 = {
	.cc = LC3_CONFIG_48_3,
	.qos = LC3_QOS_48_3_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_48_4_1 = {
	.cc = LC3_CONFIG_48_4,
	.qos = LC3_QOS_48_4_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_48_5_1 = {
	.cc = LC3_CONFIG_48_5,
	.qos = LC3_QOS_48_5_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_48_6_1 = {
	.cc = LC3_CONFIG_48_6,
	.qos = LC3_QOS_48_6_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

/* ATT: Write Command (0x52) len 23
 *  Handle: 0x0022
 *    Data: 02010000_qos
 * ATT: Handle Value Notification (0x1b) len 7
 *  Handle: 0x0022
 *    Data: 0201010000
 * ATT: Handle Value Notification (0x1b) len 37
 *   Handle: 0x0016
 *     Data: 01010102010a00204e00409c00204e00409c00_qos
 */
#define QOS_SNK(_qos...) \
	IOV_DATA(0x52, 0x22, 0x00, 0x02, 0x01, 0x01, 0x00, 0x00, _qos), \
	IOV_DATA(0x1b, 0x22, 0x00, 0x02, 0x01, 0x01, 0x00, 0x00), \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x16, 0x00, 0x01, 0x02, 0x00, 0x00, _qos)

#define SCC_SNK_8_1_1 \
	SCC_SNK_8_1, \
	QOS_SNK(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x1a, 0x00, 0x02, 0x08, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_8_2_1 \
	SCC_SNK_8_2, \
	QOS_SNK(0x10, 0x27, 0x00, 0x00, 0x02, 0x1e, 0x00, 0x02, 0x0a, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_16_1_1 \
	SCC_SNK_16_1, \
	QOS_SNK(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x1e, 0x00, 0x02, 0x08, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_16_2_1 \
	SCC_SNK_16_2, \
	QOS_SNK(0x10, 0x27, 0x00, 0x00, 0x02, 0x28, 0x00, 0x02, 0x0a, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_24_1_1 \
	SCC_SNK_24_1, \
	QOS_SNK(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x2d, 0x00, 0x02, 0x08, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_24_2_1 \
	SCC_SNK_24_2, \
	QOS_SNK(0x10, 0x27, 0x00, 0x00, 0x02, 0x3c, 0x00, 0x02, 0x0a, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_32_1_1 \
	SCC_SNK_32_1, \
	QOS_SNK(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x3c, 0x00, 0x02, 0x08, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_32_2_1 \
	SCC_SNK_32_2, \
	QOS_SNK(0x10, 0x27, 0x00, 0x00, 0x02, 0x50, 0x00, 0x02, 0x0a, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_44_1_1 \
	SCC_SNK_44_1, \
	QOS_SNK(0xe3, 0x1f, 0x00, 0x01, 0x02, 0x62, 0x00, 0x05, 0x18, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_44_2_1 \
	SCC_SNK_44_2, \
	QOS_SNK(0x84, 0x2a, 0x00, 0x01, 0x02, 0x82, 0x00, 0x05, 0x1f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_48_1_1 \
	SCC_SNK_48_1, \
	QOS_SNK(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x4b, 0x00, 0x05, 0x0f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_48_2_1 \
	SCC_SNK_48_2, \
	QOS_SNK(0x10, 0x27, 0x00, 0x00, 0x02, 0x64, 0x00, 0x05, 0x14, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_48_3_1 \
	SCC_SNK_48_3, \
	QOS_SNK(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x5a, 0x00, 0x05, 0x0f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_48_4_1 \
	SCC_SNK_48_4, \
	QOS_SNK(0x10, 0x27, 0x00, 0x00, 0x02, 0x78, 0x00, 0x05, 0x14, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_48_5_1 \
	SCC_SNK_48_5, \
	QOS_SNK(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x75, 0x00, 0x05, 0x0f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_48_6_1 \
	SCC_SNK_48_6, \
	QOS_SNK(0x10, 0x27, 0x00, 0x00, 0x02, 0x9b, 0x00, 0x05, 0x14, 0x00, \
		0x40, 0x9c, 0x00)

static struct test_config cfg_src_8_1_1 = {
	.cc = LC3_CONFIG_8_1,
	.qos = LC3_QOS_8_1_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_8_2_1 = {
	.cc = LC3_CONFIG_8_2,
	.qos = LC3_QOS_8_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_16_1_1 = {
	.cc = LC3_CONFIG_16_1,
	.qos = LC3_QOS_16_1_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_16_2_1 = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_24_1_1 = {
	.cc = LC3_CONFIG_24_1,
	.qos = LC3_QOS_24_1_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_24_2_1 = {
	.cc = LC3_CONFIG_24_2,
	.qos = LC3_QOS_24_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_32_1_1 = {
	.cc = LC3_CONFIG_32_1,
	.qos = LC3_QOS_32_1_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_32_2_1 = {
	.cc = LC3_CONFIG_32_2,
	.qos = LC3_QOS_32_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_44_1_1 = {
	.cc = LC3_CONFIG_44_1,
	.qos = LC3_QOS_44_1_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_44_2_1 = {
	.cc = LC3_CONFIG_44_2,
	.qos = LC3_QOS_44_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_48_1_1 = {
	.cc = LC3_CONFIG_48_1,
	.qos = LC3_QOS_48_1_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_48_2_1 = {
	.cc = LC3_CONFIG_48_2,
	.qos = LC3_QOS_48_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_48_3_1 = {
	.cc = LC3_CONFIG_48_3,
	.qos = LC3_QOS_48_3_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_48_4_1 = {
	.cc = LC3_CONFIG_48_4,
	.qos = LC3_QOS_48_4_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_48_5_1 = {
	.cc = LC3_CONFIG_48_5,
	.qos = LC3_QOS_48_5_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_48_6_1 = {
	.cc = LC3_CONFIG_48_6,
	.qos = LC3_QOS_48_6_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

/* ATT: Write Command (0x52) len 23
 *  Handle: 0x0022
 *    Data: 02030000_qos
 * ATT: Handle Value Notification (0x1b) len 7
 *  Handle: 0x0022
 *    Data: 0201030000
 * ATT: Handle Value Notification (0x1b) len 37
 *   Handle: 0x001c
 *     Data: 03010102010a00204e00409c00204e00409c00_qos
 */
#define QOS_SRC(_qos...) \
	IOV_DATA(0x52, 0x22, 0x00, 0x02, 0x01, 0x03, 0x00, 0x00, _qos), \
	IOV_DATA(0x1b, 0x22, 0x00, 0x02, 0x01, 0x03, 0x00, 0x00), \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x1c, 0x00, 0x03, 0x02, 0x00, 0x00, _qos)

#define SCC_SRC_8_1_1 \
	SCC_SRC_8_1, \
	QOS_SRC(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x1a, 0x00, 0x02, 0x08, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_8_2_1 \
	SCC_SRC_8_2, \
	QOS_SRC(0x10, 0x27, 0x00, 0x00, 0x02, 0x1e, 0x00, 0x02, 0x0a, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_16_1_1 \
	SCC_SRC_16_1, \
	QOS_SRC(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x1e, 0x00, 0x02, 0x08, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_16_2_1 \
	SCC_SRC_16_2, \
	QOS_SRC(0x10, 0x27, 0x00, 0x00, 0x02, 0x28, 0x00, 0x02, 0x0a, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_24_1_1 \
	SCC_SRC_24_1, \
	QOS_SRC(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x2d, 0x00, 0x02, 0x08, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_24_2_1 \
	SCC_SRC_24_2, \
	QOS_SRC(0x10, 0x27, 0x00, 0x00, 0x02, 0x3c, 0x00, 0x02, 0x0a, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_32_1_1 \
	SCC_SRC_32_1, \
	QOS_SRC(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x3c, 0x00, 0x02, 0x08, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_32_2_1 \
	SCC_SRC_32_2, \
	QOS_SRC(0x10, 0x27, 0x00, 0x00, 0x02, 0x50, 0x00, 0x02, 0x0a, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_44_1_1 \
	SCC_SRC_44_1, \
	QOS_SRC(0xe3, 0x1f, 0x00, 0x01, 0x02, 0x62, 0x00, 0x05, 0x18, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_44_2_1 \
	SCC_SRC_44_2, \
	QOS_SRC(0x84, 0x2a, 0x00, 0x01, 0x02, 0x82, 0x00, 0x05, 0x1f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_48_1_1 \
	SCC_SRC_48_1, \
	QOS_SRC(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x4b, 0x00, 0x05, 0x0f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_48_2_1 \
	SCC_SRC_48_2, \
	QOS_SRC(0x10, 0x27, 0x00, 0x00, 0x02, 0x64, 0x00, 0x05, 0x14, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_48_3_1 \
	SCC_SRC_48_3, \
	QOS_SRC(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x5a, 0x00, 0x05, 0x0f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_48_4_1 \
	SCC_SRC_48_4, \
	QOS_SRC(0x10, 0x27, 0x00, 0x00, 0x02, 0x78, 0x00, 0x05, 0x14, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_48_5_1 \
	SCC_SRC_48_5, \
	QOS_SRC(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x75, 0x00, 0x05, 0x0f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_48_6_1 \
	SCC_SRC_48_6, \
	QOS_SRC(0x10, 0x27, 0x00, 0x00, 0x02, 0x9b, 0x00, 0x05, 0x14, 0x00, \
		0x40, 0x9c, 0x00)

static struct test_config cfg_snk_8_1_2 = {
	.cc = LC3_CONFIG_8_1,
	.qos = LC3_QOS_8_1_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_8_2_2 = {
	.cc = LC3_CONFIG_8_2,
	.qos = LC3_QOS_8_2_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_16_1_2 = {
	.cc = LC3_CONFIG_16_1,
	.qos = LC3_QOS_16_1_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_16_2_2 = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_24_1_2 = {
	.cc = LC3_CONFIG_24_1,
	.qos = LC3_QOS_24_1_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_24_2_2 = {
	.cc = LC3_CONFIG_24_2,
	.qos = LC3_QOS_24_2_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_32_1_2 = {
	.cc = LC3_CONFIG_32_1,
	.qos = LC3_QOS_32_1_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_32_2_2 = {
	.cc = LC3_CONFIG_32_2,
	.qos = LC3_QOS_32_2_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_44_1_2 = {
	.cc = LC3_CONFIG_44_1,
	.qos = LC3_QOS_44_1_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_44_2_2 = {
	.cc = LC3_CONFIG_44_2,
	.qos = LC3_QOS_44_2_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_48_1_2 = {
	.cc = LC3_CONFIG_48_1,
	.qos = LC3_QOS_48_1_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_48_2_2 = {
	.cc = LC3_CONFIG_48_2,
	.qos = LC3_QOS_48_2_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_48_3_2 = {
	.cc = LC3_CONFIG_48_3,
	.qos = LC3_QOS_48_3_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_48_4_2 = {
	.cc = LC3_CONFIG_48_4,
	.qos = LC3_QOS_48_4_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_48_5_2 = {
	.cc = LC3_CONFIG_48_5,
	.qos = LC3_QOS_48_5_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_snk_48_6_2 = {
	.cc = LC3_CONFIG_48_6,
	.qos = LC3_QOS_48_6_2,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

#define SCC_SNK_8_1_2 \
	SCC_SNK_8_1, \
	QOS_SNK(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x1a, 0x00, 0x0d, 0x4b, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_8_2_2 \
	SCC_SNK_8_2, \
	QOS_SNK(0x10, 0x27, 0x00, 0x00, 0x02, 0x1e, 0x00, 0x0d, 0x5f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_16_1_2 \
	SCC_SNK_16_1, \
	QOS_SNK(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x1e, 0x00, 0x0d, 0x4b, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_16_2_2 \
	SCC_SNK_16_2, \
	QOS_SNK(0x10, 0x27, 0x00, 0x00, 0x02, 0x28, 0x00, 0x0d, 0x5f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_24_1_2 \
	SCC_SNK_24_1, \
	QOS_SNK(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x2d, 0x00, 0x0d, 0x4b, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_24_2_2 \
	SCC_SNK_24_2, \
	QOS_SNK(0x10, 0x27, 0x00, 0x00, 0x02, 0x3c, 0x00, 0x0d, 0x5f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_32_1_2 \
	SCC_SNK_32_1, \
	QOS_SNK(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x3c, 0x00, 0x0d, 0x4b, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_32_2_2 \
	SCC_SNK_32_2, \
	QOS_SNK(0x10, 0x27, 0x00, 0x00, 0x02, 0x50, 0x00, 0x0d, 0x5f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_44_1_2 \
	SCC_SNK_44_1, \
	QOS_SNK(0xe3, 0x1f, 0x00, 0x01, 0x02, 0x62, 0x00, 0x0d, 0x50, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_44_2_2 \
	SCC_SNK_44_2, \
	QOS_SNK(0x84, 0x2a, 0x00, 0x01, 0x02, 0x82, 0x00, 0x0d, 0x55, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_48_1_2 \
	SCC_SNK_48_1, \
	QOS_SNK(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x4b, 0x00, 0x0d, 0x4b, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_48_2_2 \
	SCC_SNK_48_2, \
	QOS_SNK(0x10, 0x27, 0x00, 0x00, 0x02, 0x64, 0x00, 0x0d, 0x5f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_48_3_2 \
	SCC_SNK_48_3, \
	QOS_SNK(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x5a, 0x00, 0x0d, 0x4b, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_48_4_2 \
	SCC_SNK_48_4, \
	QOS_SNK(0x10, 0x27, 0x00, 0x00, 0x02, 0x78, 0x00, 0x0d, 0x64, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_48_5_2 \
	SCC_SNK_48_5, \
	QOS_SNK(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x75, 0x00, 0x0d, 0x4b, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SNK_48_6_2 \
	SCC_SNK_48_6, \
	QOS_SNK(0x10, 0x27, 0x00, 0x00, 0x02, 0x9b, 0x00, 0x0d, 0x64, 0x00, \
		0x40, 0x9c, 0x00)

static struct test_config cfg_src_8_1_2 = {
	.cc = LC3_CONFIG_8_1,
	.qos = LC3_QOS_8_1_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_8_2_2 = {
	.cc = LC3_CONFIG_8_2,
	.qos = LC3_QOS_8_2_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_16_1_2 = {
	.cc = LC3_CONFIG_16_1,
	.qos = LC3_QOS_16_1_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_16_2_2 = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_24_1_2 = {
	.cc = LC3_CONFIG_24_1,
	.qos = LC3_QOS_24_1_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_24_2_2 = {
	.cc = LC3_CONFIG_24_2,
	.qos = LC3_QOS_24_2_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_32_1_2 = {
	.cc = LC3_CONFIG_32_1,
	.qos = LC3_QOS_32_1_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_32_2_2 = {
	.cc = LC3_CONFIG_32_2,
	.qos = LC3_QOS_32_2_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_44_1_2 = {
	.cc = LC3_CONFIG_44_1,
	.qos = LC3_QOS_44_1_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_44_2_2 = {
	.cc = LC3_CONFIG_44_2,
	.qos = LC3_QOS_44_2_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_48_1_2 = {
	.cc = LC3_CONFIG_48_1,
	.qos = LC3_QOS_48_1_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_48_2_2 = {
	.cc = LC3_CONFIG_48_2,
	.qos = LC3_QOS_48_2_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_48_3_2 = {
	.cc = LC3_CONFIG_48_3,
	.qos = LC3_QOS_48_3_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_48_4_2 = {
	.cc = LC3_CONFIG_48_4,
	.qos = LC3_QOS_48_4_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_48_5_2 = {
	.cc = LC3_CONFIG_48_5,
	.qos = LC3_QOS_48_5_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

static struct test_config cfg_src_48_6_2 = {
	.cc = LC3_CONFIG_48_6,
	.qos = LC3_QOS_48_6_2,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
};

#define SCC_SRC_8_1_2 \
	SCC_SRC_8_1, \
	QOS_SRC(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x1a, 0x00, 0x0d, 0x4b, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_8_2_2 \
	SCC_SRC_8_2, \
	QOS_SRC(0x10, 0x27, 0x00, 0x00, 0x02, 0x1e, 0x00, 0x0d, 0x5f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_16_1_2 \
	SCC_SRC_16_1, \
	QOS_SRC(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x1e, 0x00, 0x0d, 0x4b, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_16_2_2 \
	SCC_SRC_16_2, \
	QOS_SRC(0x10, 0x27, 0x00, 0x00, 0x02, 0x28, 0x00, 0x0d, 0x5f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_24_1_2 \
	SCC_SRC_24_1, \
	QOS_SRC(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x2d, 0x00, 0x0d, 0x4b, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_24_2_2 \
	SCC_SRC_24_2, \
	QOS_SRC(0x10, 0x27, 0x00, 0x00, 0x02, 0x3c, 0x00, 0x0d, 0x5f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_32_1_2 \
	SCC_SRC_32_1, \
	QOS_SRC(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x3c, 0x00, 0x0d, 0x4b, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_32_2_2 \
	SCC_SRC_32_2, \
	QOS_SRC(0x10, 0x27, 0x00, 0x00, 0x02, 0x50, 0x00, 0x0d, 0x5f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_44_1_2 \
	SCC_SRC_44_1, \
	QOS_SRC(0xe3, 0x1f, 0x00, 0x01, 0x02, 0x62, 0x00, 0x0d, 0x50, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_44_2_2 \
	SCC_SRC_44_2, \
	QOS_SRC(0x84, 0x2a, 0x00, 0x01, 0x02, 0x82, 0x00, 0x0d, 0x55, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_48_1_2 \
	SCC_SRC_48_1, \
	QOS_SRC(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x4b, 0x00, 0x0d, 0x4b, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_48_2_2 \
	SCC_SRC_48_2, \
	QOS_SRC(0x10, 0x27, 0x00, 0x00, 0x02, 0x64, 0x00, 0x0d, 0x5f, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_48_3_2 \
	SCC_SRC_48_3, \
	QOS_SRC(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x5a, 0x00, 0x0d, 0x4b, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_48_4_2 \
	SCC_SRC_48_4, \
	QOS_SRC(0x10, 0x27, 0x00, 0x00, 0x02, 0x78, 0x00, 0x0d, 0x64, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_48_5_2 \
	SCC_SRC_48_5, \
	QOS_SRC(0x4c, 0x1d, 0x00, 0x00, 0x02, 0x75, 0x00, 0x0d, 0x4b, 0x00, \
		0x40, 0x9c, 0x00)

#define SCC_SRC_48_6_2 \
	SCC_SRC_48_6, \
	QOS_SRC(0x10, 0x27, 0x00, 0x00, 0x02, 0x9b, 0x00, 0x0d, 0x64, 0x00, \
		0x40, 0x9c, 0x00)

/* Test Purpose:
 * Verify that a Unicast Client IUT can initiate a Config QoS operation for the
 * LC3 codec.
 *
 * Pass verdict:
 * The IUT successfully writes to the ASE Control Point characteristic with the
 * opcode set to 0x02 (Config QoS) and the specified parameters.
 */
static void test_ucl_scc_qos_lc3(void)
{
	define_test("BAP/UCL/SCC/BV-035-C [UCL SRC Config QoS, LC3 8_1_1]",
			test_setup, test_client, &cfg_snk_8_1_1,
			SCC_SNK_8_1_1);
	define_test("BAP/UCL/SCC/BV-036-C [UCL SRC Config QoS, LC3 8_2_1]",
			test_setup, test_client, &cfg_snk_8_2_1,
			SCC_SNK_8_2_1);
	define_test("BAP/UCL/SCC/BV-037-C [UCL SRC Config QoS, LC3 16_1_1]",
			test_setup, test_client, &cfg_snk_16_1_1,
			SCC_SNK_16_1_1);
	define_test("BAP/UCL/SCC/BV-038-C [UCL SRC Config QoS, LC3 16_2_1]",
			test_setup, test_client, &cfg_snk_16_2_1,
			SCC_SNK_16_2_1);
	define_test("BAP/UCL/SCC/BV-039-C [UCL SRC Config QoS, LC3 24_1_1]",
			test_setup, test_client, &cfg_snk_24_1_1,
			SCC_SNK_24_1_1);
	define_test("BAP/UCL/SCC/BV-040-C [UCL SRC Config QoS, LC3 24_2_1]",
			test_setup, test_client, &cfg_snk_24_2_1,
			SCC_SNK_24_2_1);
	define_test("BAP/UCL/SCC/BV-041-C [UCL SRC Config QoS, LC3 32_1_1]",
			test_setup, test_client, &cfg_snk_32_1_1,
			SCC_SNK_32_1_1);
	define_test("BAP/UCL/SCC/BV-042-C [UCL SRC Config QoS, LC3 32_2_1]",
			test_setup, test_client, &cfg_snk_32_2_1,
			SCC_SNK_32_2_1);
	define_test("BAP/UCL/SCC/BV-043-C [UCL SRC Config QoS, LC3 44.1_1_1]",
			test_setup, test_client, &cfg_snk_44_1_1,
			SCC_SNK_44_1_1);
	define_test("BAP/UCL/SCC/BV-044-C [UCL SRC Config QoS, LC3 44.1_2_1]",
			test_setup, test_client, &cfg_snk_44_2_1,
			SCC_SNK_44_2_1);
	define_test("BAP/UCL/SCC/BV-045-C [UCL SRC Config QoS, LC3 48_1_1]",
			test_setup, test_client, &cfg_snk_48_1_1,
			SCC_SNK_48_1_1);
	define_test("BAP/UCL/SCC/BV-046-C [UCL SRC Config QoS, LC3 48_2_1]",
			test_setup, test_client, &cfg_snk_48_2_1,
			SCC_SNK_48_2_1);
	define_test("BAP/UCL/SCC/BV-047-C [UCL SRC Config QoS, LC3 48_3_1]",
			test_setup, test_client, &cfg_snk_48_3_1,
			SCC_SNK_48_3_1);
	define_test("BAP/UCL/SCC/BV-048-C [UCL SRC Config QoS, LC3 48_4_1]",
			test_setup, test_client, &cfg_snk_48_4_1,
			SCC_SNK_48_4_1);
	define_test("BAP/UCL/SCC/BV-049-C [UCL SRC Config QoS, LC3 48_5_1]",
			test_setup, test_client, &cfg_snk_48_5_1,
			SCC_SNK_48_5_1);
	define_test("BAP/UCL/SCC/BV-050-C [UCL SRC Config QoS, LC3 48_6_1]",
			test_setup, test_client, &cfg_snk_48_6_1,
			SCC_SNK_48_6_1);
	define_test("BAP/UCL/SCC/BV-051-C [UCL SNK Config QoS, LC3 8_1_1]",
			test_setup, test_client, &cfg_src_8_1_1,
			SCC_SRC_8_1_1);
	define_test("BAP/UCL/SCC/BV-052-C [UCL SNK Config QoS, LC3 8_2_1]",
			test_setup, test_client, &cfg_src_8_2_1,
			SCC_SRC_8_2_1);
	define_test("BAP/UCL/SCC/BV-053-C [UCL SNK Config QoS, LC3 16_1_1]",
			test_setup, test_client, &cfg_src_16_1_1,
			SCC_SRC_16_1_1);
	define_test("BAP/UCL/SCC/BV-054-C [UCL SNK Config QoS, LC3 16_2_1]",
			test_setup, test_client, &cfg_src_16_2_1,
			SCC_SRC_16_2_1);
	define_test("BAP/UCL/SCC/BV-055-C [UCL SNK Config QoS, LC3 24_1_1]",
			test_setup, test_client, &cfg_src_24_1_1,
			SCC_SRC_24_1_1);
	define_test("BAP/UCL/SCC/BV-056-C [UCL SNK Config QoS, LC3 24_2_1]",
			test_setup, test_client, &cfg_src_24_2_1,
			SCC_SRC_24_2_1);
	define_test("BAP/UCL/SCC/BV-057-C [UCL SNK Config QoS, LC3 32_1_1]",
			test_setup, test_client, &cfg_src_32_1_1,
			SCC_SRC_32_1_1);
	define_test("BAP/UCL/SCC/BV-058-C [UCL SNK Config QoS, LC3 32_2_1]",
			test_setup, test_client, &cfg_src_32_2_1,
			SCC_SRC_32_2_1);
	define_test("BAP/UCL/SCC/BV-059-C [UCL SNK Config QoS, LC3 44.1_1_1]",
			test_setup, test_client, &cfg_src_44_1_1,
			SCC_SRC_44_1_1);
	define_test("BAP/UCL/SCC/BV-060-C [UCL SNK Config QoS, LC3 44.1_2_1]",
			test_setup, test_client, &cfg_src_44_2_1,
			SCC_SRC_44_2_1);
	define_test("BAP/UCL/SCC/BV-061-C [UCL SNK Config QoS, LC3 48_1_1]",
			test_setup, test_client, &cfg_src_48_1_1,
			SCC_SRC_48_1_1);
	define_test("BAP/UCL/SCC/BV-062-C [UCL SNK Config QoS, LC3 48_2_1]",
			test_setup, test_client, &cfg_src_48_2_1,
			SCC_SRC_48_2_1);
	define_test("BAP/UCL/SCC/BV-063-C [UCL SNK Config QoS, LC3 48_3_1]",
			test_setup, test_client, &cfg_src_48_3_1,
			SCC_SRC_48_3_1);
	define_test("BAP/UCL/SCC/BV-064-C [UCL SNK Config QoS, LC3 48_4_1]",
			test_setup, test_client, &cfg_src_48_4_1,
			SCC_SRC_48_4_1);
	define_test("BAP/UCL/SCC/BV-065-C [UCL SNK Config QoS, LC3 48_5_1]",
			test_setup, test_client, &cfg_src_48_5_1,
			SCC_SRC_48_5_1);
	define_test("BAP/UCL/SCC/BV-066-C [UCL SNK Config QoS, LC3 48_6_1]",
			test_setup, test_client, &cfg_src_48_6_1,
			SCC_SRC_48_6_1);
	define_test("BAP/UCL/SCC/BV-067-C [UCL SRC Config QoS, LC3 8_1_2]",
			test_setup, test_client, &cfg_snk_8_1_2,
			SCC_SNK_8_1_2);
	define_test("BAP/UCL/SCC/BV-068-C [UCL SRC Config QoS, LC3 8_2_2]",
			test_setup, test_client, &cfg_snk_8_2_2,
			SCC_SNK_8_2_2);
	define_test("BAP/UCL/SCC/BV-069-C [UCL SRC Config QoS, LC3 16_1_2]",
			test_setup, test_client, &cfg_snk_16_1_2,
			SCC_SNK_16_1_2);
	define_test("BAP/UCL/SCC/BV-070-C [UCL SRC Config QoS, LC3 16_2_2]",
			test_setup, test_client, &cfg_snk_16_2_2,
			SCC_SNK_16_2_2);
	define_test("BAP/UCL/SCC/BV-071-C [UCL SRC Config QoS, LC3 24_1_2]",
			test_setup, test_client, &cfg_snk_24_1_2,
			SCC_SNK_24_1_2);
	define_test("BAP/UCL/SCC/BV-072-C [UCL SRC Config QoS, LC3 24_2_2]",
			test_setup, test_client, &cfg_snk_24_2_2,
			SCC_SNK_24_2_2);
	define_test("BAP/UCL/SCC/BV-073-C [UCL SRC Config QoS, LC3 32_1_2]",
			test_setup, test_client, &cfg_snk_32_1_2,
			SCC_SNK_32_1_2);
	define_test("BAP/UCL/SCC/BV-074-C [UCL SRC Config QoS, LC3 32_2_2]",
			test_setup, test_client, &cfg_snk_32_2_2,
			SCC_SNK_32_2_2);
	define_test("BAP/UCL/SCC/BV-075-C [UCL SRC Config QoS, LC3 44.1_1_2]",
			test_setup, test_client, &cfg_snk_44_1_2,
			SCC_SNK_44_1_2);
	define_test("BAP/UCL/SCC/BV-076-C [UCL SRC Config QoS, LC3 44.1_2_2]",
			test_setup, test_client, &cfg_snk_44_2_2,
			SCC_SNK_44_2_2);
	define_test("BAP/UCL/SCC/BV-077-C [UCL SRC Config QoS, LC3 48_1_2]",
			test_setup, test_client, &cfg_snk_48_1_2,
			SCC_SNK_48_1_2);
	define_test("BAP/UCL/SCC/BV-078-C [UCL SRC Config QoS, LC3 48_2_2]",
			test_setup, test_client, &cfg_snk_48_2_2,
			SCC_SNK_48_2_2);
	define_test("BAP/UCL/SCC/BV-079-C [UCL SRC Config QoS, LC3 48_3_2]",
			test_setup, test_client, &cfg_snk_48_3_2,
			SCC_SNK_48_3_2);
	define_test("BAP/UCL/SCC/BV-080-C [UCL SRC Config QoS, LC3 48_4_2]",
			test_setup, test_client, &cfg_snk_48_4_2,
			SCC_SNK_48_4_2);
	define_test("BAP/UCL/SCC/BV-081-C [UCL SRC Config QoS, LC3 48_5_2]",
			test_setup, test_client, &cfg_snk_48_5_2,
			SCC_SNK_48_5_2);
	define_test("BAP/UCL/SCC/BV-082-C [UCL SRC Config QoS, LC3 48_6_2]",
			test_setup, test_client, &cfg_snk_48_6_2,
			SCC_SNK_48_6_2);
	define_test("BAP/UCL/SCC/BV-083-C [UCL SNK Config QoS, LC3 8_1_2]",
			test_setup, test_client, &cfg_src_8_1_2,
			SCC_SRC_8_1_2);
	define_test("BAP/UCL/SCC/BV-084-C [UCL SNK Config QoS, LC3 8_2_2]",
			test_setup, test_client, &cfg_src_8_2_2,
			SCC_SRC_8_2_2);
	define_test("BAP/UCL/SCC/BV-085-C [UCL SNK Config QoS, LC3 16_1_2]",
			test_setup, test_client, &cfg_src_16_1_2,
			SCC_SRC_16_1_2);
	define_test("BAP/UCL/SCC/BV-086-C [UCL SNK Config QoS, LC3 16_2_2]",
			test_setup, test_client, &cfg_src_16_2_2,
			SCC_SRC_16_2_2);
	define_test("BAP/UCL/SCC/BV-087-C [UCL SNK Config QoS, LC3 24_1_2]",
			test_setup, test_client, &cfg_src_24_1_2,
			SCC_SRC_24_1_2);
	define_test("BAP/UCL/SCC/BV-088-C [UCL SNK Config QoS, LC3 24_2_2]",
			test_setup, test_client, &cfg_src_24_2_2,
			SCC_SRC_24_2_2);
	define_test("BAP/UCL/SCC/BV-089-C [UCL SNK Config QoS, LC3 32_1_2]",
			test_setup, test_client, &cfg_src_32_1_2,
			SCC_SRC_32_1_2);
	define_test("BAP/UCL/SCC/BV-090-C [UCL SNK Config QoS, LC3 32_2_2]",
			test_setup, test_client, &cfg_src_32_2_2,
			SCC_SRC_32_2_2);
	define_test("BAP/UCL/SCC/BV-091-C [UCL SNK Config QoS, LC3 44.1_1_2]",
			test_setup, test_client, &cfg_src_44_1_2,
			SCC_SRC_44_1_2);
	define_test("BAP/UCL/SCC/BV-092-C [UCL SNK Config QoS, LC3 44.1_2_2]",
			test_setup, test_client, &cfg_src_44_2_2,
			SCC_SRC_44_2_2);
	define_test("BAP/UCL/SCC/BV-093-C [UCL SNK Config QoS, LC3 48_1_2]",
			test_setup, test_client, &cfg_src_48_1_2,
			SCC_SRC_48_1_2);
	define_test("BAP/UCL/SCC/BV-094-C [UCL SNK Config QoS, LC3 48_2_2]",
			test_setup, test_client, &cfg_src_48_2_2,
			SCC_SRC_48_2_2);
	define_test("BAP/UCL/SCC/BV-095-C [UCL SNK Config QoS, LC3 48_3_2]",
			test_setup, test_client, &cfg_src_48_3_2,
			SCC_SRC_48_3_2);
	define_test("BAP/UCL/SCC/BV-096-C [UCL SNK Config QoS, LC3 48_4_2]",
			test_setup, test_client, &cfg_src_48_4_2,
			SCC_SRC_48_4_2);
	define_test("BAP/UCL/SCC/BV-097-C [UCL SNK Config QoS, LC3 48_5_2]",
			test_setup, test_client, &cfg_src_48_5_2,
			SCC_SRC_48_5_2);
	define_test("BAP/UCL/SCC/BV-098-C [UCL SNK Config QoS, LC3 48_6_2]",
			test_setup, test_client, &cfg_src_48_6_2,
			SCC_SRC_48_6_2);
}

/* Unicast Server Performs Config QoS – LC3
 *
 * Test Purpose:
 * Verify that a Unicast Server IUT can perform a Config QoS operation
 * initiated by a Unicast Client for the LC3 codec.
 *.
 * Pass verdict:
 * In step 2, the IUT sends a notification of the ASE Control Point
 * characteristic with Response_Code set to Success (0x00) for the requested
 * ASE_ID and opcode.
 * In step 3, the notified ASE characteristic value is correctly formatted, has
 * the ASE_ID field set to Test_ASE_ID, the ASE_State field set to 0x02
 * (QoS Configured), and the Additional_ASE_Parameters field containing the
 * CIG_ID, CIS_ID, and QoS configuration values requested in step 2.
 */
static void test_usr_scc_qos_lc3(void)
{
	define_test("BAP/USR/SCC/BV-069-C [USR SNK Config QoS, LC3 8_1_1]",
			test_setup_server, test_server, &cfg_snk_8_1_1,
			SCC_SNK_8_1_1);
	define_test("BAP/USR/SCC/BV-070-C [USR SNK Config QoS, LC3 8_2_1]",
			test_setup_server, test_server, &cfg_snk_8_2_1,
			SCC_SNK_8_2_1);
	define_test("BAP/USR/SCC/BV-071-C [USR SNK Config QoS, LC3 16_1_1]",
			test_setup_server, test_server, &cfg_snk_16_1_1,
			SCC_SNK_16_1_1);
	define_test("BAP/USR/SCC/BV-072-C [USR SNK Config QoS, LC3 16_2_1]",
			test_setup_server, test_server, &cfg_snk_16_2_1,
			SCC_SNK_16_2_1);
	define_test("BAP/USR/SCC/BV-073-C [USR SNK Config QoS, LC3 24_1_1]",
			test_setup_server, test_server, &cfg_snk_24_1_1,
			SCC_SNK_24_1_1);
	define_test("BAP/USR/SCC/BV-074-C [USR SNK Config QoS, LC3 24_2_1]",
			test_setup_server, test_server, &cfg_snk_24_2_1,
			SCC_SNK_24_2_1);
	define_test("BAP/USR/SCC/BV-075-C [USR SNK Config QoS, LC3 32_1_1]",
			test_setup_server, test_server, &cfg_snk_32_1_1,
			SCC_SNK_32_1_1);
	define_test("BAP/USR/SCC/BV-076-C [USR SNK Config QoS, LC3 32_2_1]",
			test_setup_server, test_server, &cfg_snk_32_2_1,
			SCC_SNK_32_2_1);
	define_test("BAP/USR/SCC/BV-077-C [USR SNK Config QoS, LC3 44.1_1_1]",
			test_setup_server, test_server, &cfg_snk_44_1_1,
			SCC_SNK_44_1_1);
	define_test("BAP/USR/SCC/BV-078-C [USR SNK Config QoS, LC3 44.1_2_1]",
			test_setup_server, test_server, &cfg_snk_44_2_1,
			SCC_SNK_44_2_1);
	define_test("BAP/USR/SCC/BV-079-C [USR SNK Config QoS, LC3 48_1_1]",
			test_setup_server, test_server, &cfg_snk_48_1_1,
			SCC_SNK_48_1_1);
	define_test("BAP/USR/SCC/BV-080-C [USR SNK Config QoS, LC3 48_2_1]",
			test_setup_server, test_server, &cfg_snk_48_2_1,
			SCC_SNK_48_2_1);
	define_test("BAP/USR/SCC/BV-081-C [USR SNK Config QoS, LC3 48_3_1]",
			test_setup_server, test_server, &cfg_snk_48_3_1,
			SCC_SNK_48_3_1);
	define_test("BAP/USR/SCC/BV-082-C [USR SNK Config QoS, LC3 48_4_1]",
			test_setup_server, test_server, &cfg_snk_48_4_1,
			SCC_SNK_48_4_1);
	define_test("BAP/USR/SCC/BV-083-C [USR SNK Config QoS, LC3 48_5_1]",
			test_setup_server, test_server, &cfg_snk_48_5_1,
			SCC_SNK_48_5_1);
	define_test("BAP/USR/SCC/BV-084-C [USR SNK Config QoS, LC3 48_6_1]",
			test_setup_server, test_server, &cfg_snk_48_6_1,
			SCC_SNK_48_6_1);
	define_test("BAP/USR/SCC/BV-085-C [USR SRC Config QoS, LC3 8_1_1]",
			test_setup_server, test_server, &cfg_src_8_1_1,
			SCC_SRC_8_1_1);
	define_test("BAP/USR/SCC/BV-086-C [USR SRC Config QoS, LC3 8_2_1]",
			test_setup_server, test_server, &cfg_src_8_2_1,
			SCC_SRC_8_2_1);
	define_test("BAP/USR/SCC/BV-087-C [USR SRC Config QoS, LC3 16_1_1]",
			test_setup_server, test_server, &cfg_src_16_1_1,
			SCC_SRC_16_1_1);
	define_test("BAP/USR/SCC/BV-088-C [USR SRC Config QoS, LC3 16_2_1]",
			test_setup_server, test_server, &cfg_src_16_2_1,
			SCC_SRC_16_2_1);
	define_test("BAP/USR/SCC/BV-089-C [USR SRC Config QoS, LC3 24_1_1]",
			test_setup_server, test_server, &cfg_src_24_1_1,
			SCC_SRC_24_1_1);
	define_test("BAP/USR/SCC/BV-090-C [USR SRC Config QoS, LC3 24_2_1]",
			test_setup_server, test_server, &cfg_src_24_2_1,
			SCC_SRC_24_2_1);
	define_test("BAP/USR/SCC/BV-091-C [USR SRC Config QoS, LC3 32_1_1]",
			test_setup_server, test_server, &cfg_src_32_1_1,
			SCC_SRC_32_1_1);
	define_test("BAP/USR/SCC/BV-092-C [USR SRC Config QoS, LC3 32_2_1]",
			test_setup_server, test_server, &cfg_src_32_2_1,
			SCC_SRC_32_2_1);
	define_test("BAP/USR/SCC/BV-093-C [USR SRC Config QoS, LC3 44.1_1_1]",
			test_setup_server, test_server, &cfg_src_44_1_1,
			SCC_SRC_44_1_1);
	define_test("BAP/USR/SCC/BV-094-C [USR SRC Config QoS, LC3 44.1_2_1]",
			test_setup_server, test_server, &cfg_src_44_2_1,
			SCC_SRC_44_2_1);
	define_test("BAP/USR/SCC/BV-095-C [USR SRC Config QoS, LC3 48_1_1]",
			test_setup_server, test_server, &cfg_src_48_1_1,
			SCC_SRC_48_1_1);
	define_test("BAP/USR/SCC/BV-096-C [USR SRC Config QoS, LC3 48_2_1]",
			test_setup_server, test_server, &cfg_src_48_2_1,
			SCC_SRC_48_2_1);
	define_test("BAP/USR/SCC/BV-097-C [USR SRC Config QoS, LC3 48_3_1]",
			test_setup_server, test_server, &cfg_src_48_3_1,
			SCC_SRC_48_3_1);
	define_test("BAP/USR/SCC/BV-098-C [USR SRC Config QoS, LC3 48_4_1]",
			test_setup_server, test_server, &cfg_src_48_4_1,
			SCC_SRC_48_4_1);
	define_test("BAP/USR/SCC/BV-099-C [USR SRC Config QoS, LC3 48_5_1]",
			test_setup_server, test_server, &cfg_src_48_5_1,
			SCC_SRC_48_5_1);
	define_test("BAP/USR/SCC/BV-100-C [USR SRC Config QoS, LC3 48_6_1]",
			test_setup_server, test_server, &cfg_src_48_6_1,
			SCC_SRC_48_6_1);
	define_test("BAP/USR/SCC/BV-101-C [USR SNK Config QoS, LC3 8_1_2]",
			test_setup_server, test_server, &cfg_snk_8_1_2,
			SCC_SNK_8_1_2);
	define_test("BAP/USR/SCC/BV-102-C [USR SNK Config QoS, LC3 8_2_2]",
			test_setup_server, test_server, &cfg_snk_8_2_2,
			SCC_SNK_8_2_2);
	define_test("BAP/USR/SCC/BV-103-C [USR SNK Config QoS, LC3 16_1_2]",
			test_setup_server, test_server, &cfg_snk_16_1_2,
			SCC_SNK_16_1_2);
	define_test("BAP/USR/SCC/BV-104-C [USR SNK Config QoS, LC3 16_2_2]",
			test_setup_server, test_server, &cfg_snk_16_2_2,
			SCC_SNK_16_2_2);
	define_test("BAP/USR/SCC/BV-105-C [USR SNK Config QoS, LC3 24_1_2]",
			test_setup_server, test_server, &cfg_snk_24_1_2,
			SCC_SNK_24_1_2);
	define_test("BAP/USR/SCC/BV-106-C [USR SNK Config QoS, LC3 24_2_2]",
			test_setup_server, test_server, &cfg_snk_24_2_2,
			SCC_SNK_24_2_2);
	define_test("BAP/USR/SCC/BV-107-C [USR SNK Config QoS, LC3 32_1_2]",
			test_setup_server, test_server, &cfg_snk_32_1_2,
			SCC_SNK_32_1_2);
	define_test("BAP/USR/SCC/BV-108-C [USR SNK Config QoS, LC3 32_2_2]",
			test_setup_server, test_server, &cfg_snk_32_2_2,
			SCC_SNK_32_2_2);
	define_test("BAP/USR/SCC/BV-109-C [USR SNK Config QoS, LC3 44.1_1_2]",
			test_setup_server, test_server, &cfg_snk_44_1_2,
			SCC_SNK_44_1_2);
	define_test("BAP/USR/SCC/BV-110-C [USR SNK Config QoS, LC3 44.1_2_2]",
			test_setup_server, test_server, &cfg_snk_44_2_2,
			SCC_SNK_44_2_2);
	define_test("BAP/USR/SCC/BV-111-C [USR SNK Config QoS, LC3 48_1_2]",
			test_setup_server, test_server, &cfg_snk_48_1_2,
			SCC_SNK_48_1_2);
	define_test("BAP/USR/SCC/BV-112-C [USR SNK Config QoS, LC3 48_2_2]",
			test_setup_server, test_server, &cfg_snk_48_2_2,
			SCC_SNK_48_2_2);
	define_test("BAP/USR/SCC/BV-113-C [USR SNK Config QoS, LC3 48_3_2]",
			test_setup_server, test_server, &cfg_snk_48_3_2,
			SCC_SNK_48_3_2);
	define_test("BAP/USR/SCC/BV-114-C [USR SNK Config QoS, LC3 48_4_2]",
			test_setup_server, test_server, &cfg_snk_48_4_2,
			SCC_SNK_48_4_2);
	define_test("BAP/USR/SCC/BV-115-C [USR SNK Config QoS, LC3 48_5_2]",
			test_setup_server, test_server, &cfg_snk_48_5_2,
			SCC_SNK_48_5_2);
	define_test("BAP/USR/SCC/BV-116-C [USR SNK Config QoS, LC3 48_6_2]",
			test_setup_server, test_server, &cfg_snk_48_6_2,
			SCC_SNK_48_6_2);
	define_test("BAP/USR/SCC/BV-117-C [USR SRC Config QoS, LC3 8_1_2]",
			test_setup_server, test_server, &cfg_src_8_1_2,
			SCC_SRC_8_1_2);
	define_test("BAP/USR/SCC/BV-118-C [USR SRC Config QoS, LC3 8_2_2]",
			test_setup_server, test_server, &cfg_src_8_2_2,
			SCC_SRC_8_2_2);
	define_test("BAP/USR/SCC/BV-119-C [USR SRC Config QoS, LC3 16_1_2]",
			test_setup_server, test_server, &cfg_src_16_1_2,
			SCC_SRC_16_1_2);
	define_test("BAP/USR/SCC/BV-120-C [USR SRC Config QoS, LC3 16_2_2]",
			test_setup_server, test_server, &cfg_src_16_2_2,
			SCC_SRC_16_2_2);
	define_test("BAP/USR/SCC/BV-121-C [USR SRC Config QoS, LC3 24_1_2]",
			test_setup_server, test_server, &cfg_src_24_1_2,
			SCC_SRC_24_1_2);
	define_test("BAP/USR/SCC/BV-122-C [USR SRC Config QoS, LC3 24_2_2]",
			test_setup_server, test_server, &cfg_src_24_2_2,
			SCC_SRC_24_2_2);
	define_test("BAP/USR/SCC/BV-123-C [USR SRC Config QoS, LC3 32_1_2]",
			test_setup_server, test_server, &cfg_src_32_1_2,
			SCC_SRC_32_1_2);
	define_test("BAP/USR/SCC/BV-124-C [USR SRC Config QoS, LC3 32_2_2]",
			test_setup_server, test_server, &cfg_src_32_2_2,
			SCC_SRC_32_2_2);
	define_test("BAP/USR/SCC/BV-125-C [USR SRC Config QoS, LC3 44.1_1_2]",
			test_setup_server, test_server, &cfg_src_44_1_2,
			SCC_SRC_44_1_2);
	define_test("BAP/USR/SCC/BV-126-C [USR SRC Config QoS, LC3 44.1_2_2]",
			test_setup_server, test_server, &cfg_src_44_2_2,
			SCC_SRC_44_2_2);
	define_test("BAP/USR/SCC/BV-127-C [USR SRC Config QoS, LC3 48_1_2]",
			test_setup_server, test_server, &cfg_src_48_1_2,
			SCC_SRC_48_1_2);
	define_test("BAP/USR/SCC/BV-128-C [USR SRC Config QoS, LC3 48_2_2]",
			test_setup_server, test_server, &cfg_src_48_2_2,
			SCC_SRC_48_2_2);
	define_test("BAP/USR/SCC/BV-129-C [USR SRC Config QoS, LC3 48_3_2]",
			test_setup_server, test_server, &cfg_src_48_3_2,
			SCC_SRC_48_3_2);
	define_test("BAP/USR/SCC/BV-130-C [USR SRC Config QoS, LC3 48_4_2]",
			test_setup_server, test_server, &cfg_src_48_4_2,
			SCC_SRC_48_4_2);
	define_test("BAP/USR/SCC/BV-131-C [USR SRC Config QoS, LC3 48_5_2]",
			test_setup_server, test_server, &cfg_src_48_5_2,
			SCC_SRC_48_5_2);
	define_test("BAP/USR/SCC/BV-132-C [USR SRC Config QoS, LC3 48_6_2]",
			test_setup_server, test_server, &cfg_src_48_6_2,
			SCC_SRC_48_6_2);
}

static void test_scc_qos_lc3(void)
{
	test_ucl_scc_qos_lc3();
	test_usr_scc_qos_lc3();
}

static struct test_config cfg_snk_qos_vs = {
	.cc = IOV_NULL,
	.qos = QOS_UCAST,
	.snk = true,
	.vs = true,
	.state = BT_BAP_STREAM_STATE_QOS
};

#define SCC_SNK_QOS_VS \
	SCC_SNK_VS, \
	QOS_SNK(0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, \
		0x00, 0x00, 0x00)

static struct test_config cfg_src_qos_vs = {
	.cc = IOV_NULL,
	.qos = QOS_UCAST,
	.src = true,
	.vs = true,
	.state = BT_BAP_STREAM_STATE_QOS
};

#define SCC_SRC_QOS_VS \
	SCC_SRC_VS, \
	QOS_SRC(0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, \
		0x00, 0x00, 0x00)

/* Test Purpose:
 * Verify that a Unicast Client IUT can initiate a Config QoS operation for a
 * vendor-specific codec.
 *
 * Pass verdict:
 * The IUT successfully writes to the ASE Control Point characteristic with the
 * opcode set to 0x02 (Config QoS) and the specified parameters.
 */
static void test_ucl_scc_qos_vs(void)
{
	define_test("BAP/UCL/SCC/BV-099-C [UCL SNK Config QoS, VS]",
			test_setup, test_client, &cfg_src_qos_vs,
			SCC_SRC_QOS_VS);
	define_test("BAP/UCL/SCC/BV-100-C [UCL SRC Config QoS, VS]",
			test_setup, test_client, &cfg_snk_qos_vs,
			SCC_SNK_QOS_VS);
}

/* Unicast Server Performs Config QoS – Vendor-Specific
 *
 * Test Purpose:
 * Verify that a Unicast Server IUT can handle a Config QoS operation for a
 * vendor-specific codec.
 *
 * Pass verdict:
 * The IUT sends a notification of the ASE Control Point characteristic with
 * Response_Code set to Success (0x00) for the requested ASE_ID and opcode.
 */
static void test_usr_scc_qos_vs(void)
{
	define_test("BAP/USR/SCC/BV-133-C [USR SNK Config QoS, VS]",
			test_setup_server, test_server, &cfg_snk_qos_vs,
			SCC_SNK_QOS_VS);
	define_test("BAP/USR/SCC/BV-134-C [USR SRC Config QoS, VS]",
			test_setup, test_client, &cfg_src_qos_vs,
			SCC_SRC_QOS_VS);
}

static void test_scc_qos_vs(void)
{
	test_ucl_scc_qos_vs();
	test_usr_scc_qos_vs();
}

static struct test_config cfg_snk_enable = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_ENABLING
};

/* ATT: Write Command (0x52) len 23
 *  Handle: 0x0022
 *    Data: 03010104030201
 * ATT: Handle Value Notification (0x1b) len 7
 *  Handle: 0x0022
 *    Data: 0301010000
 * ATT: Handle Value Notification (0x1b) len 37
 *   Handle: 0x0016
 *     Data: 0101010300403020100
 */
#define SCC_SNK_ENABLE \
	SCC_SNK_16_2_1, \
	IOV_DATA(0x52, 0x22, 0x00, 0x03, 0x01, 0x01, 0x04, 0x03, 0x02, 0x01, \
			00), \
	IOV_DATA(0x1b, 0x22, 0x00, 0x03, 0x01, 0x01, 0x00, 0x00), \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x16, 0x00, 0x01, 0x03, 0x00, 0x00, 0x04, 0x03, 0x02, \
			0x01, 0x00)

static struct test_config cfg_src_enable = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_ENABLING
};

/* ATT: Write Command (0x52) len 23
 *  Handle: 0x0022
 *    Data: 0301030403020100
 * ATT: Handle Value Notification (0x1b) len 7
 *  Handle: 0x0022
 *    Data: 0301030000
 * ATT: Handle Value Notification (0x1b) len 37
 *   Handle: 0x001c
 *     Data: 030300000403020100
 */
#define SRC_ENABLE \
	IOV_DATA(0x52, 0x22, 0x00, 0x03, 0x01, 0x03, 0x04, 0x03, 0x02, 0x01, \
			00), \
	IOV_DATA(0x1b, 0x22, 0x00, 0x03, 0x01, 0x03, 0x00, 0x00), \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x1c, 0x00, 0x03, 0x03, 0x00, 0x00, 0x04, 0x03, 0x02, \
			0x01, 0x00)

#define SCC_SRC_ENABLE \
	SCC_SRC_16_2_1, \
	SRC_ENABLE

/* Test Purpose:
 * Verify that a Unicast Client IUT can initiate an Enable operation for an ASE
 * with a Unicast Server that is either in the Audio Sink role or the Audio
 * Source role.
 *
 * Pass verdict:
 * The IUT successfully writes to the ASE Control Point characteristic with the
 * opcode set to 0x03 (Enable) and the specified parameters.
 */
static void test_ucl_scc_enable(void)
{
	define_test("BAP/UCL/SCC/BV-101-C [UCL SRC Enable]",
			test_setup, test_client, &cfg_snk_enable,
			SCC_SNK_ENABLE);
	define_test("BAP/UCL/SCC/BV-102-C [UCL SNK Enable]",
			test_setup, test_client, &cfg_src_enable,
			SCC_SRC_ENABLE);
}

/* Unicast Server Performs Client-Initiated Enable Operation
 *
 * Test Purpose:
 * Verify that a Unicast Server IUT can handle a client-initiated Enable
 * operation for an ASE with a Unicast Client that is either in the Audio Sink
 * role or the Audio Source role.
 *
 * Pass verdict:
 * The IUT sends a notification of the ASE Control Point characteristic with
 * Response_Code set to 0x00 (Success) for the requested ASE_ID and opcode.
 */
static void test_usr_scc_enable(void)
{
	define_test("BAP/USR/SCC/BV-135-C [USR SNK Enable]",
			test_setup_server, test_server, &cfg_snk_enable,
			SCC_SNK_ENABLE);
	define_test("BAP/USR/SCC/BV-136-C [UCL SRC Enable]",
			test_setup_server, test_server, &cfg_src_enable,
			SCC_SRC_ENABLE);
}

static void test_scc_enable(void)
{
	test_ucl_scc_enable();
	test_usr_scc_enable();
}

static struct test_config cfg_snk_disable = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_DISABLING
};

/* ATT: Write Command (0x52) len 23
 *  Handle: 0x0022
 *    Data: 050101
 * ATT: Handle Value Notification (0x1b) len 7
 *  Handle: 0x0022
 *    Data: 0501010000
 * ATT: Handle Value Notification (0x1b) len 37
 *   Handle: 0x0016
 *     Data: 01010102010a00204e00409c00204e00409c00_qos
 */
#define ASE_SNK_DISABLE \
	IOV_DATA(0x52, 0x22, 0x00, 0x05, 0x01, 0x01), \
	IOV_DATA(0x1b, 0x22, 0x00, 0x05, 0x01, 0x01, 0x00, 0x00), \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x16, 0x00, 0x01, 0x02, 0x00, 0x00, 0x10, 0x27, 0x00, \
			0x00, 0x02, 0x28, 0x00, 0x02, 0x0a, 0x00, 0x40, 0x9c, \
			0x00)

#define SCC_SNK_DISABLE \
	SCC_SNK_ENABLE, \
	ASE_SNK_DISABLE

static struct test_config cfg_src_disable = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_DISABLING
};

/* ATT: Write Command (0x52) len 23
 *  Handle: 0x0022
 *    Data: 050103
 * ATT: Handle Value Notification (0x1b) len 7
 *  Handle: 0x0022
 *    Data: 0301030000
 * ATT: Handle Value Notification (0x1b) len 37
 *   Handle: 0x001c
 *     Data: 030300000403020100
 */
#define ASE_SRC_DISABLE \
	IOV_DATA(0x52, 0x22, 0x00, 0x05, 0x01, 0x03), \
	IOV_DATA(0x1b, 0x22, 0x00, 0x05, 0x01, 0x03, 0x00, 0x00), \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x1c, 0x00, 0x03, 0x05, 0x00, 0x00, 0x04, 0x03, 0x02, \
		 0x01, 0x00)
#define SCC_SRC_DISABLE \
	SCC_SRC_ENABLE, \
	ASE_SRC_DISABLE

static void state_start_disable(struct bt_bap_stream *stream,
					uint8_t old_state, uint8_t new_state,
					void *user_data)
{
	struct test_data *data = user_data;
	uint8_t id;

	switch (new_state) {
	case BT_BAP_STREAM_STATE_STREAMING:
		id = bt_bap_stream_disable(stream, true, bap_disable,
						data);
		g_assert(id);
		break;
	}
}

static struct test_config cfg_src_disable_streaming = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
	.state_func = state_start_disable
};

/* ATT: Write Command (0x52) len 23
 *  Handle: 0x0022
 *    Data: 040101
 * ATT: Handle Value Notification (0x1b) len 7
 *  Handle: 0x0022
 *    Data: 0401010000
 * ATT: Handle Value Notification (0x1b) len 37
 *   Handle: 0x0016
 *     Data: 0101010400403020100
 */
#define SRC_START \
	IOV_DATA(0x52, 0x22, 0x00, 0x04, 0x01, 0x03), \
	IOV_DATA(0x1b, 0x22, 0x00, 0x04, 0x01, 0x03, 0x00, 0x00), \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x1c, 0x00, 0x03, 0x04, 0x00, 0x00, 0x04, 0x03, 0x02, \
			0x01, 0x00)

#define SCC_SRC_DISABLE_STREAMING \
	SCC_SRC_ENABLE, \
	SRC_START, \
	ASE_SRC_DISABLE

/* Test Purpose:
 * Verify that a Unicast Client IUT can initiate a Disable operation for an ASE
 * in the Enabling or Streaming state.
 *
 * Pass verdict:
 * The IUT successfully writes to the ASE Control Point characteristic with the
 * opcode set to 0x05 (Disable) and the specified parameters.
 */
static void test_ucl_scc_disable(void)
{
	define_test("BAP/UCL/SCC/BV-103-C [UCL SNK Disable in Enabling State]",
			test_setup, test_client, &cfg_src_disable,
			SCC_SRC_DISABLE);
	define_test("BAP/UCL/SCC/BV-104-C [UCL SRC Disable in Enabling or "
			"Streaming state]",
			test_setup, test_client, &cfg_snk_disable,
			SCC_SNK_DISABLE);
	define_test("BAP/UCL/SCC/BV-105-C [UCL SNK Disable in Streaming State]",
			test_setup, test_client, &cfg_src_disable_streaming,
			SCC_SRC_DISABLE_STREAMING);
}

/* Unicast Server Performs Client-Initiated Disable Operation
 *
 * Test Purpose:
 * Verify that a Unicast Server IUT can perform a client-initiated Disable
 * operation for an ASE in the Enabling or Streaming state.
 *
 * Pass verdict:
 * The IUT sends a notification of the ASE Control Point characteristic.
 */
static void test_usr_scc_disable(void)
{
	define_test("BAP/USR/SCC/BV-137-C [USR SRC Disable in Enabling State]",
			test_setup_server, test_server, &cfg_src_disable,
			SCC_SRC_DISABLE);
	define_test("BAP/USR/SCC/BV-138-C [USR SNK Disable in Enabling or "
			"Streaming state]",
			test_setup_server, test_server, &cfg_snk_disable,
			SCC_SNK_DISABLE);
	define_test("BAP/USR/SCC/BV-139-C [USR SRC Disable in Streaming State]",
			test_setup, test_client, &cfg_src_disable_streaming,
			SCC_SRC_DISABLE_STREAMING);
}

static void test_scc_disable(void)
{
	test_ucl_scc_disable();
	test_usr_scc_disable();
}

static void bap_release(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	if (code)
		tester_test_failed();
}

static void state_cc_release(struct bt_bap_stream *stream,
					uint8_t old_state, uint8_t new_state,
					void *user_data)
{
	struct test_data *data = user_data;
	uint8_t id;

	switch (new_state) {
	case BT_BAP_STREAM_STATE_CONFIG:
		id = bt_bap_stream_release(stream, bap_release, data);
		g_assert(id);
		break;
	}
}

static struct test_config cfg_src_cc_release = {
	.cc = LC3_CONFIG_16_2,
	.qos = QOS_UCAST,
	.src = true,
	.state_func = state_cc_release,
};

/* ATT: Write Command (0x52) len 23
 *  Handle: 0x0022
 *    Data: 080103
 * ATT: Handle Value Notification (0x1b) len 7
 *  Handle: 0x0022
 *    Data: 0801030000
 * ATT: Handle Value Notification (0x1b) len 37
 *   Handle: 0x001c
 *     Data: 0300
 */
#define ASE_SRC_RELEASE \
	IOV_DATA(0x52, 0x22, 0x00, 0x08, 0x01, 0x03), \
	IOV_DATA(0x1b, 0x22, 0x00, 0x08, 0x01, 0x03, 0x00, 0x00), \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x1c, 0x00, 0x03, 0x06)

#define SCC_SRC_CC_RELEASE \
	SCC_SRC_16_2, \
	ASE_SRC_RELEASE

static struct test_config cfg_snk_cc_release = {
	.cc = LC3_CONFIG_16_2,
	.qos = QOS_UCAST,
	.snk = true,
	.state_func = state_cc_release,
};

/* ATT: Write Command (0x52) len 23
 *  Handle: 0x0022
 *    Data: 080101
 * ATT: Handle Value Notification (0x1b) len 7
 *  Handle: 0x0022
 *    Data: 0801010000
 * ATT: Handle Value Notification (0x1b) len 37
 *   Handle: 0x0016
 *     Data: 0300
 */
#define ASE_SNK_RELEASE \
	IOV_DATA(0x52, 0x22, 0x00, 0x08, 0x01, 0x01), \
	IOV_DATA(0x1b, 0x22, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00), \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x16, 0x00, 0x01, 0x06)

#define SCC_SNK_CC_RELEASE \
	SCC_SNK_16_2, \
	ASE_SNK_RELEASE

static void state_qos_release(struct bt_bap_stream *stream,
					uint8_t old_state, uint8_t new_state,
					void *user_data)
{
	struct test_data *data = user_data;
	uint8_t id;

	switch (new_state) {
	case BT_BAP_STREAM_STATE_QOS:
		id = bt_bap_stream_release(stream, bap_release, data);
		g_assert(id);
		break;
	}
}

static struct test_config cfg_src_qos_release = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_QOS,
	.state_func = state_qos_release,
};

#define SCC_SRC_QOS_RELEASE \
	SCC_SRC_16_2_1, \
	ASE_SRC_RELEASE

static struct test_config cfg_snk_qos_release = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_QOS,
	.state_func = state_qos_release,
};

#define SCC_SNK_QOS_RELEASE \
	SCC_SNK_16_2_1, \
	ASE_SNK_RELEASE

static void state_enable_release(struct bt_bap_stream *stream,
					uint8_t old_state, uint8_t new_state,
					void *user_data)
{
	struct test_data *data = user_data;
	uint8_t id;

	switch (new_state) {
	case BT_BAP_STREAM_STATE_ENABLING:
		id = bt_bap_stream_release(stream, bap_release, data);
		g_assert(id);
		break;
	}
}

static struct test_config cfg_src_enable_release = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_ENABLING,
	.state_func = state_enable_release,
};

#define SCC_SRC_ENABLE_RELEASE \
	SCC_SRC_ENABLE, \
	ASE_SRC_RELEASE

static struct test_config cfg_snk_enable_release = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_ENABLING,
	.state_func = state_enable_release,
};

#define SCC_SNK_ENABLE_RELEASE \
	SCC_SNK_ENABLE, \
	ASE_SNK_RELEASE

static void state_start_release(struct bt_bap_stream *stream,
					uint8_t old_state, uint8_t new_state,
					void *user_data)
{
	struct test_data *data = user_data;
	uint8_t id;

	switch (new_state) {
	case BT_BAP_STREAM_STATE_STREAMING:
		id = bt_bap_stream_release(stream, bap_release, data);
		g_assert(id);
		break;
	}
}

static struct test_config cfg_src_start_release = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
	.state_func = state_start_release,
};

#define SCC_SRC_START_RELEASE \
	SCC_SRC_ENABLE, \
	SRC_START, \
	ASE_SRC_RELEASE

static void state_disable_release(struct bt_bap_stream *stream,
					uint8_t old_state, uint8_t new_state,
					void *user_data)
{
	struct test_data *data = user_data;
	uint8_t id;

	switch (new_state) {
	case BT_BAP_STREAM_STATE_DISABLING:
		id = bt_bap_stream_release(stream, bap_release, data);
		g_assert(id);
		break;
	}
}

static struct test_config cfg_src_disable_release = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_DISABLING,
	.state_func = state_disable_release,
};

#define SCC_SRC_DISABLE_RELEASE \
	SCC_SRC_DISABLE, \
	ASE_SRC_RELEASE

/* Test Purpose:
 * Verify that a Unicast Client IUT can release an ASE by initiating a Release
 * operation.
 *
 * Pass verdict:
 * The IUT successfully writes to the ASE Control Point characteristic with the
 * opcode set to 0x08 (Release) and the specified parameters.
 */
static void test_ucl_scc_release(void)
{
	define_test("BAP/UCL/SCC/BV-106-C [UCL SNK Release in Codec Configured"
			" state]",
			test_setup, test_client, &cfg_src_cc_release,
			SCC_SRC_CC_RELEASE);
	define_test("BAP/UCL/SCC/BV-107-C [UCL SRC Release in Codec Configured"
			" state]",
			test_setup, test_client, &cfg_snk_cc_release,
			SCC_SNK_CC_RELEASE);
	define_test("BAP/UCL/SCC/BV-108-C [UCL SNK Release in QoS Configured"
			" state]",
			test_setup, test_client, &cfg_src_qos_release,
			SCC_SRC_QOS_RELEASE);
	define_test("BAP/UCL/SCC/BV-109-C [UCL SRC Release in QoS Configured"
			" state]",
			test_setup, test_client, &cfg_snk_qos_release,
			SCC_SNK_QOS_RELEASE);
	define_test("BAP/UCL/SCC/BV-110-C [UCL SNK Release in Enabling state]",
			test_setup, test_client, &cfg_src_enable_release,
			SCC_SRC_ENABLE_RELEASE);
	define_test("BAP/UCL/SCC/BV-111-C [UCL SRC Release in Enabling or"
			" Streaming state]",
			test_setup, test_client, &cfg_snk_enable_release,
			SCC_SNK_ENABLE_RELEASE);
	define_test("BAP/UCL/SCC/BV-112-C [UCL SNK Release in Streaming state]",
			test_setup, test_client, &cfg_src_start_release,
			SCC_SRC_START_RELEASE);
	define_test("BAP/UCL/SCC/BV-113-C [UCL SNK Release in Disabling state]",
			test_setup, test_client, &cfg_src_disable_release,
			SCC_SRC_DISABLE_RELEASE);
}

/* Unicast Server Performs Client-Initiated Release Operation
 *
 * Test Purpose:
 * Verify the behavior of a Unicast Server IUT when a Unicast Client initiates
 * a Release operation.
 *
 * Pass verdict:
 * The IUT sends a notification of the ASE Control Point characteristic value.
 *
 */
static void test_usr_scc_release(void)
{
	define_test("BAP/USR/SCC/BV-143-C [USR SRC Release in Codec Configured"
			" state]",
			test_setup_server, test_server, &cfg_src_cc_release,
			SCC_SRC_CC_RELEASE);
	define_test("BAP/USR/SCC/BV-144-C [USR SNK Release in Codec Configured"
			" state]",
			test_setup_server, test_server, &cfg_snk_cc_release,
			SCC_SNK_CC_RELEASE);
	define_test("BAP/USR/SCC/BV-145-C [USR SRC Release in QoS Configured"
			" state]",
			test_setup_server, test_server, &cfg_src_qos_release,
			SCC_SRC_QOS_RELEASE);
	define_test("BAP/USR/SCC/BV-146-C [USR SNK Release in QoS Configured"
			" state]",
			test_setup_server, test_server, &cfg_snk_qos_release,
			SCC_SNK_QOS_RELEASE);
	define_test("BAP/USR/SCC/BV-147-C [USR SRC Release in Enabling state]",
			test_setup_server, test_server, &cfg_src_enable_release,
			SCC_SRC_ENABLE_RELEASE);
	define_test("BAP/USR/SCC/BV-148-C [USR SNK Release in Enabling or"
			" Streaming state]",
			test_setup_server, test_server, &cfg_snk_enable_release,
			SCC_SNK_ENABLE_RELEASE);
	define_test("BAP/USR/SCC/BV-149-C [USR SRC Release in Streaming state]",
			test_setup_server, test_server, &cfg_src_start_release,
			SCC_SRC_START_RELEASE);
	define_test("BAP/USR/SCC/BV-150-C [USR SRC Release in Disabling state]",
			test_setup_server, test_server,
			&cfg_src_disable_release, SCC_SRC_DISABLE_RELEASE);
}

static void test_scc_release(void)
{
	test_ucl_scc_release();
	test_usr_scc_release();
}

static void bap_metadata(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	if (code)
		tester_test_failed();
}

static void state_enable_metadata(struct bt_bap_stream *stream,
					uint8_t old_state, uint8_t new_state,
					void *user_data)
{
	struct test_data *data = user_data;
	struct iovec iov = {};
	uint8_t id;

	switch (new_state) {
	case BT_BAP_STREAM_STATE_ENABLING:
		id = bt_bap_stream_metadata(stream, &iov, bap_metadata,
						data);
		g_assert(id);
		break;
	}
}

static struct test_config cfg_snk_metadata = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.snk = true,
	.state = BT_BAP_STREAM_STATE_ENABLING,
	.state_func = state_enable_metadata
};

/* ATT: Write Command (0x52) len 23
 *  Handle: 0x0022
 *    Data: 07010100
 * ATT: Handle Value Notification (0x1b) len 7
 *  Handle: 0x0022
 *    Data: 0701010000
 * ATT: Handle Value Notification (0x1b) len 37
 *   Handle: 0x0016
 *     Data: 0103000000
 */
#define ASE_SNK_METADATA \
	IOV_DATA(0x52, 0x22, 0x00, 0x07, 0x01, 0x01, 0x04, 0x03, 0x02, 0x01, \
		0x00), \
	IOV_DATA(0x1b, 0x22, 0x00, 0x07, 0x01, 0x01, 0x00, 0x00), \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x16, 0x00, 0x01, 0x03, 0x00, 0x00, 0x04, 0x03, 0x02, \
		0x01, 0x00)

#define SCC_SNK_METADATA \
	SCC_SNK_ENABLE, \
	ASE_SNK_METADATA

static struct test_config cfg_src_metadata = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_ENABLING,
	.state_func = state_enable_metadata
};

/* ATT: Write Command (0x52) len 23
 *  Handle: 0x0022
 *    Data: 07010300
 * ATT: Handle Value Notification (0x1b) len 7
 *  Handle: 0x0022
 *    Data: 0701030000
 * ATT: Handle Value Notification (0x1b) len 37
 *   Handle: 0x001c
 *     Data: 0303000000
 */
#define ASE_SRC_METADATA(_state) \
	IOV_DATA(0x52, 0x22, 0x00, 0x07, 0x01, 0x03, 0x04, 0x03, 0x02, 0x01, \
		0x00), \
	IOV_DATA(0x1b, 0x22, 0x00, 0x07, 0x01, 0x03, 0x00, 0x00), \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x1c, 0x00, 0x03, _state, 0x00, 0x00, 0x04, 0x03, 0x02, \
		0x01, 0x00)
#define SCC_SRC_METADATA \
	SCC_SRC_ENABLE, \
	ASE_SRC_METADATA(0x03)

static void state_start_metadata(struct bt_bap_stream *stream,
					uint8_t old_state, uint8_t new_state,
					void *user_data)
{
	struct test_data *data = user_data;
	struct iovec iov = {};
	uint8_t id;

	switch (new_state) {
	case BT_BAP_STREAM_STATE_STREAMING:
		id = bt_bap_stream_metadata(stream, &iov, bap_metadata,
						data);
		g_assert(id);
		break;
	}
}

static struct test_config cfg_src_metadata_streaming = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1,
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
	.state_func = state_start_metadata
};

#define SCC_SRC_METADATA_STREAMING \
	SCC_SRC_ENABLE, \
	SRC_START, \
	ASE_SRC_METADATA(0x04)

/* Unicast Client Initiates Update Metadata Operation
 *
 * Test Purpose:
 * Verify that a Unicast Client IUT can update the Metadata of an ASE by
 * initiating an Update Metadata operation.
 *
 * Pass verdict:
 * The IUT successfully writes to the ASE Control Point characteristic with the
 * opcode set to 0x07 (Update Metadata) and the specified parameters.
 */
static void test_ucl_scc_metadata(void)
{
	define_test("BAP/UCL/SCC/BV-115-C [UCL SNK Update Metadata in Enabling "
			"State]",
			test_setup, test_client, &cfg_src_metadata,
			SCC_SRC_METADATA);
	define_test("BAP/UCL/SCC/BV-116-C [UCL SRC Update Metadata in Enabling "
			"or Streaming state]",
			test_setup, test_client, &cfg_snk_metadata,
			SCC_SNK_METADATA);
	define_test("BAP/UCL/SCC/BV-117-C [UCL SNK Update Metadata in Streaming"
			" State]",
			test_setup, test_client, &cfg_src_metadata_streaming,
			SCC_SRC_METADATA_STREAMING);
}

/* Unicast Server Performs Update Metadata Operation
 *
 * Test Purpose:
 * Verify that a Unicast Server IUT can perform an Update Metadata operation
 * initiated by a Unicast Client.
 *
 * Pass verdict:
 * The IUT sends a notification of the ASE Control Point characteristic with
 * Response_Code set to Success (0x00) for the requested ASE_ID and opcode.
 */
static void test_usr_scc_metadata(void)
{
	define_test("BAP/USR/SCC/BV-161-C [USR SRC Update Metadata in Enabling "
			"State]",
			test_setup_server, test_server, &cfg_src_metadata,
			SCC_SRC_METADATA);
	define_test("BAP/USR/SCC/BV-162-C [USR SNK Update Metadata in Enabling "
			"or Streaming state]",
			test_setup_server, test_server, &cfg_snk_metadata,
			SCC_SNK_METADATA);
	define_test("BAP/USR/SCC/BV-163-C [USR SRC Update Metadata in Streaming"
			" State]",
			test_setup_server, test_server,
			&cfg_src_metadata_streaming,
			SCC_SRC_METADATA_STREAMING);
}

static void test_scc_metadata(void)
{
	test_ucl_scc_metadata();
	test_usr_scc_metadata();
}

#define SNK_ENABLE \
	IOV_DATA(0x52, 0x22, 0x00, 0x03, 0x01, 0x01, 0x04, 0x03, 0x02, 0x01, \
			00), \
	IOV_DATA(0x1b, 0x22, 0x00, 0x03, 0x01, 0x01, 0x00, 0x00), \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x16, 0x00, 0x01, 0x03, 0x00, 0x00, 0x04, 0x03, 0x02, \
			0x01, 0x00)

#define SNK_START \
	IOV_NULL, \
	IOV_DATA(0x1b, 0x16, 0x00, 0x01, 0x04, 0x00, 0x00, 0x04, 0x03, 0x02, \
			0x01, 0x00)

static struct test_config str_snk_ac2_8_1_1 = {
	.cc = LC3_CONFIG_8_1_AC(1),
	.qos = LC3_QOS_8_1_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK(_freq, _ac, _dur, _len) \
	SCC_SNK_LC3(0x10, 0x02, 0x01, _freq, 0x02, 0x02, _dur, 0x03, 0x04, \
			_len, _len >> 8, 0x05, 0x03, _ac, 0x00, 0x00, 0x00)

#define STR_SNK_8(_ac, _dur, _len) \
	STR_SNK(LC3_CONFIG_FREQ_8KHZ, _ac, _dur, _len)

#define STR_SNK_8_1(_ac) \
	STR_SNK_8(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_8_1)

#define STR_SNK_QOS(_interval, _frame, _sdu, _rtn, _latency) \
	QOS_SNK(_interval & 0xff, _interval >> 8 & 0xff, \
		_interval >> 16 & 0xff, _frame, 0x02, _sdu & 0xff, \
		_sdu >> 8 & 0xff, _rtn, \
		_latency, _latency >> 8, 0x40, 0x9c, 0x00)

#define STR_SNK_QOS_1(_sdu, _rtn, _latency) \
	STR_SNK_QOS(7500u, LC3_QOS_UNFRAMED, _sdu, _rtn, _latency)

#define STR_SNK_8_1_1(_chans) \
	STR_SNK_8_1((BIT(_chans) - 1)), \
	STR_SNK_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_8_1, LC3_QOS_8_1_1_RTN, \
			LC3_QOS_8_1_1_LATENCY)

#define STR_SNK_AC2_8_1_1 \
	STR_SNK_8_1_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_8_1_1 = {
	.cc = LC3_CONFIG_8_1_AC(2),
	.qos = LC3_QOS_8_1_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_8_1_1 \
	STR_SNK_8_1_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_8_2_1 = {
	.cc = LC3_CONFIG_8_2_AC(1),
	.qos = LC3_QOS_8_2_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_8_2(_ac) \
	STR_SNK_8(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_8_2)

#define STR_SNK_QOS_2(_sdu, _rtn, _latency) \
	STR_SNK_QOS(10000u, LC3_QOS_UNFRAMED, _sdu, _rtn, _latency)

#define STR_SNK_8_2_1(_chans) \
	STR_SNK_8_2((BIT(_chans) - 1)), \
	STR_SNK_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_8_2, LC3_QOS_8_2_1_RTN, \
			LC3_QOS_8_2_1_LATENCY)

#define STR_SNK_AC2_8_2_1 \
	STR_SNK_8_2_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_8_2_1 = {
	.cc = LC3_CONFIG_8_2_AC(2),
	.qos = LC3_QOS_8_2_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_8_2_1 \
	STR_SNK_8_2_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_8_1_2 = {
	.cc = LC3_CONFIG_8_1_AC(1),
	.qos = LC3_QOS_8_1_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_8_1_2(_chans) \
	STR_SNK_8_1((BIT(_chans) - 1)), \
	STR_SNK_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_8_1, LC3_QOS_8_1_2_RTN, \
			LC3_QOS_8_1_2_LATENCY)

#define STR_SNK_AC2_8_1_2 \
	STR_SNK_8_1_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_8_1_2 = {
	.cc = LC3_CONFIG_8_1_AC(2),
	.qos = LC3_QOS_8_1_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_8_1_2 \
	STR_SNK_8_1_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_8_2_2 = {
	.cc = LC3_CONFIG_8_2_AC(1),
	.qos = LC3_QOS_8_2_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_8_2_2(_chans) \
	STR_SNK_8_2((BIT(_chans) - 1)), \
	STR_SNK_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_8_2, LC3_QOS_8_2_2_RTN, \
			LC3_QOS_8_2_2_LATENCY)

#define STR_SNK_AC2_8_2_2 \
	STR_SNK_8_2_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_8_2_2 = {
	.cc = LC3_CONFIG_8_2_AC(2),
	.qos = LC3_QOS_8_2_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_8_2_2 \
	STR_SNK_8_2_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_16_1_1 = {
	.cc = LC3_CONFIG_16_1_AC(1),
	.qos = LC3_QOS_16_1_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_16(_ac, _dur, _len) \
	STR_SNK(LC3_CONFIG_FREQ_16KHZ, _ac, _dur, _len)

#define STR_SNK_16_1(_ac) \
	STR_SNK_16(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_16_1)

#define STR_SNK_16_1_1(_chans) \
	STR_SNK_16_1((BIT(_chans) - 1)), \
	STR_SNK_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_16_1, LC3_QOS_16_1_1_RTN, \
			LC3_QOS_16_1_1_LATENCY)

#define STR_SNK_AC2_16_1_1 \
	STR_SNK_16_1_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_16_1_1 = {
	.cc = LC3_CONFIG_16_1_AC(2),
	.qos = LC3_QOS_16_1_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_16_1_1 \
	STR_SNK_16_1_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_16_2_1 = {
	.cc = LC3_CONFIG_16_2_AC(1),
	.qos = LC3_QOS_16_2_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_16_2(_ac) \
	STR_SNK_16(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_16_2)

#define STR_SNK_16_2_1(_chans) \
	STR_SNK_16_2((BIT(_chans) - 1)), \
	STR_SNK_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_16_2, LC3_QOS_16_2_1_RTN, \
			LC3_QOS_16_2_1_LATENCY)

#define STR_SNK_AC2_16_2_1 \
	STR_SNK_16_2_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_16_2_1 = {
	.cc = LC3_CONFIG_16_2_AC(2),
	.qos = LC3_QOS_16_2_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_16_2_1 \
	STR_SNK_16_2_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_16_1_2 = {
	.cc = LC3_CONFIG_16_1_AC(1),
	.qos = LC3_QOS_16_1_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_16(_ac, _dur, _len) \
	STR_SNK(LC3_CONFIG_FREQ_16KHZ, _ac, _dur, _len)

#define STR_SNK_16_1_2(_chans) \
	STR_SNK_16_1((BIT(_chans) - 1)), \
	STR_SNK_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_16_1, LC3_QOS_16_1_2_RTN, \
			LC3_QOS_16_1_2_LATENCY)

#define STR_SNK_AC2_16_1_2 \
	STR_SNK_16_1_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_16_1_2 = {
	.cc = LC3_CONFIG_16_1_AC(2),
	.qos = LC3_QOS_16_1_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_16_1_2 \
	STR_SNK_16_1_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_16_2_2 = {
	.cc = LC3_CONFIG_16_2_AC(1),
	.qos = LC3_QOS_16_2_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_16_2(_ac) \
	STR_SNK_16(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_16_2)

#define STR_SNK_16_2_2(_chans) \
	STR_SNK_16_2((BIT(_chans) - 1)), \
	STR_SNK_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_16_2, LC3_QOS_16_2_2_RTN, \
			LC3_QOS_16_2_2_LATENCY)

#define STR_SNK_AC2_16_2_2 \
	STR_SNK_16_2_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_16_2_2 = {
	.cc = LC3_CONFIG_16_2_AC(2),
	.qos = LC3_QOS_16_2_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_16_2_2 \
	STR_SNK_16_2_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_24_1_1 = {
	.cc = LC3_CONFIG_24_1_AC(1),
	.qos = LC3_QOS_24_1_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_24(_ac, _dur, _len) \
	STR_SNK(LC3_CONFIG_FREQ_24KHZ, _ac, _dur, _len)

#define STR_SNK_24_1(_ac) \
	STR_SNK_24(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_24_1)

#define STR_SNK_24_1_1(_chans) \
	STR_SNK_24_1((BIT(_chans) - 1)), \
	STR_SNK_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_24_1, LC3_QOS_24_1_1_RTN, \
			LC3_QOS_24_1_1_LATENCY)

#define STR_SNK_AC2_24_1_1 \
	STR_SNK_24_1_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_24_1_1 = {
	.cc = LC3_CONFIG_24_1_AC(2),
	.qos = LC3_QOS_24_1_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_24_1_1 \
	STR_SNK_24_1_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_24_2_1 = {
	.cc = LC3_CONFIG_24_2_AC(1),
	.qos = LC3_QOS_24_2_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_24_2(_ac) \
	STR_SNK_24(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_24_2)

#define STR_SNK_24_2_1(_chans) \
	STR_SNK_24_2((BIT(_chans) - 1)), \
	STR_SNK_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_24_2, LC3_QOS_24_2_1_RTN, \
			LC3_QOS_24_2_1_LATENCY)

#define STR_SNK_AC2_24_2_1 \
	STR_SNK_24_2_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_24_2_1 = {
	.cc = LC3_CONFIG_24_2_AC(2),
	.qos = LC3_QOS_24_2_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_24_2_1 \
	STR_SNK_24_2_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_24_1_2 = {
	.cc = LC3_CONFIG_24_1_AC(1),
	.qos = LC3_QOS_24_1_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_24_1_2(_chans) \
	STR_SNK_24_1((BIT(_chans) - 1)), \
	STR_SNK_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_24_1, LC3_QOS_24_1_2_RTN, \
			LC3_QOS_24_1_2_LATENCY)

#define STR_SNK_AC2_24_1_2 \
	STR_SNK_24_1_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_24_1_2 = {
	.cc = LC3_CONFIG_24_1_AC(2),
	.qos = LC3_QOS_24_1_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_24_1_2 \
	STR_SNK_24_1_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_24_2_2 = {
	.cc = LC3_CONFIG_24_2_AC(1),
	.qos = LC3_QOS_24_2_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_24_2_2(_chans) \
	STR_SNK_24_2((BIT(_chans) - 1)), \
	STR_SNK_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_24_2, LC3_QOS_24_2_2_RTN, \
			LC3_QOS_24_2_2_LATENCY)

#define STR_SNK_AC2_24_2_2 \
	STR_SNK_24_2_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_24_2_2 = {
	.cc = LC3_CONFIG_24_2_AC(2),
	.qos = LC3_QOS_24_2_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_24_2_2 \
	STR_SNK_24_2_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_32_1_1 = {
	.cc = LC3_CONFIG_32_1_AC(1),
	.qos = LC3_QOS_32_1_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_32(_ac, _dur, _len) \
	STR_SNK(LC3_CONFIG_FREQ_32KHZ, _ac, _dur, _len)

#define STR_SNK_32_1(_ac) \
	STR_SNK_32(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_32_1)

#define STR_SNK_32_1_1(_chans) \
	STR_SNK_32_1((BIT(_chans) - 1)), \
	STR_SNK_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_32_1, LC3_QOS_32_1_1_RTN, \
			LC3_QOS_32_1_1_LATENCY)

#define STR_SNK_AC2_32_1_1 \
	STR_SNK_32_1_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_32_1_1 = {
	.cc = LC3_CONFIG_32_1_AC(2),
	.qos = LC3_QOS_32_1_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_32_1_1 \
	STR_SNK_32_1_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_32_2_1 = {
	.cc = LC3_CONFIG_32_2_AC(1),
	.qos = LC3_QOS_32_2_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_32_2(_ac) \
	STR_SNK_32(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_32_2)

#define STR_SNK_32_2_1(_chans) \
	STR_SNK_32_2((BIT(_chans) - 1)), \
	STR_SNK_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_32_2, LC3_QOS_32_2_1_RTN, \
			LC3_QOS_32_2_1_LATENCY)

#define STR_SNK_AC2_32_2_1 \
	STR_SNK_32_2_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_32_2_1 = {
	.cc = LC3_CONFIG_32_2_AC(2),
	.qos = LC3_QOS_32_2_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_32_2_1 \
	STR_SNK_32_2_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_32_1_2 = {
	.cc = LC3_CONFIG_32_1_AC(1),
	.qos = LC3_QOS_32_1_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_32_1_2(_chans) \
	STR_SNK_32_1((BIT(_chans) - 1)), \
	STR_SNK_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_32_1, LC3_QOS_32_1_2_RTN, \
			LC3_QOS_32_1_2_LATENCY)

#define STR_SNK_AC2_32_1_2 \
	STR_SNK_32_1_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_32_1_2 = {
	.cc = LC3_CONFIG_32_1_AC(2),
	.qos = LC3_QOS_32_1_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_32_1_2 \
	STR_SNK_32_1_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_32_2_2 = {
	.cc = LC3_CONFIG_32_2_AC(1),
	.qos = LC3_QOS_32_2_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_32_2_2(_chans) \
	STR_SNK_32_2((BIT(_chans) - 1)), \
	STR_SNK_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_32_2, LC3_QOS_32_2_2_RTN, \
			LC3_QOS_32_2_2_LATENCY)

#define STR_SNK_AC2_32_2_2 \
	STR_SNK_32_2_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_32_2_2 = {
	.cc = LC3_CONFIG_32_2_AC(2),
	.qos = LC3_QOS_32_2_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_32_2_2 \
	STR_SNK_32_2_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_44_1_1 = {
	.cc = LC3_CONFIG_44_1_AC(1),
	.qos = LC3_QOS_44_1_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_44(_ac, _dur, _len) \
	STR_SNK(LC3_CONFIG_FREQ_44KHZ, _ac, _dur, _len)

#define STR_SNK_44_1(_ac) \
	STR_SNK_44(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_44_1)

#define STR_SNK_QOS_44_1(_sdu, _rtn, _latency) \
	STR_SNK_QOS(LC3_QOS_44_1_INTERVAL, LC3_QOS_FRAMED, _sdu, _rtn, \
			_latency)

#define STR_SNK_44_1_1(_chans) \
	STR_SNK_44_1((BIT(_chans) - 1)), \
	STR_SNK_QOS_44_1(_chans * LC3_CONFIG_FRAME_LEN_44_1, \
			LC3_QOS_44_1_1_RTN, LC3_QOS_44_1_1_LATENCY)

#define STR_SNK_AC2_44_1_1 \
	STR_SNK_44_1_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_44_1_1 = {
	.cc = LC3_CONFIG_44_1_AC(2),
	.qos = LC3_QOS_44_1_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_44_1_1 \
	STR_SNK_44_1_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_44_2_1 = {
	.cc = LC3_CONFIG_44_2_AC(1),
	.qos = LC3_QOS_44_2_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_44_2(_ac) \
	STR_SNK_44(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_44_2)

#define STR_SNK_QOS_44_2(_sdu, _rtn, _latency) \
	STR_SNK_QOS(LC3_QOS_44_2_INTERVAL, LC3_QOS_FRAMED, _sdu, _rtn, \
			_latency)

#define STR_SNK_44_2_1(_chans) \
	STR_SNK_44_2((BIT(_chans) - 1)), \
	STR_SNK_QOS_44_2(_chans * LC3_CONFIG_FRAME_LEN_44_2, \
			LC3_QOS_44_2_1_RTN, LC3_QOS_44_2_1_LATENCY)

#define STR_SNK_AC2_44_2_1 \
	STR_SNK_44_2_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_44_2_1 = {
	.cc = LC3_CONFIG_44_2_AC(2),
	.qos = LC3_QOS_44_2_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_44_2_1 \
	STR_SNK_44_2_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_44_1_2 = {
	.cc = LC3_CONFIG_44_1_AC(1),
	.qos = LC3_QOS_44_1_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_44_1_2(_chans) \
	STR_SNK_44_1((BIT(_chans) - 1)), \
	STR_SNK_QOS_44_1(_chans * LC3_CONFIG_FRAME_LEN_44_1, \
			LC3_QOS_44_1_2_RTN, LC3_QOS_44_1_2_LATENCY)

#define STR_SNK_AC2_44_1_2 \
	STR_SNK_44_1_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_44_1_2 = {
	.cc = LC3_CONFIG_44_1_AC(2),
	.qos = LC3_QOS_44_1_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_44_1_2 \
	STR_SNK_44_1_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_44_2_2 = {
	.cc = LC3_CONFIG_44_2_AC(1),
	.qos = LC3_QOS_44_2_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_44_2_2(_chans) \
	STR_SNK_44_2((BIT(_chans) - 1)), \
	STR_SNK_QOS_44_2(_chans * LC3_CONFIG_FRAME_LEN_44_2, \
			LC3_QOS_44_2_2_RTN, LC3_QOS_44_2_2_LATENCY)

#define STR_SNK_AC2_44_2_2 \
	STR_SNK_44_2_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_44_2_2 = {
	.cc = LC3_CONFIG_44_2_AC(2),
	.qos = LC3_QOS_44_2_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_44_2_2 \
	STR_SNK_44_2_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_48_1_1 = {
	.cc = LC3_CONFIG_48_1_AC(1),
	.qos = LC3_QOS_48_1_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_48(_ac, _dur, _len) \
	STR_SNK(LC3_CONFIG_FREQ_48KHZ, _ac, _dur, _len)

#define STR_SNK_48_1(_ac) \
	STR_SNK_48(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_48_1)

#define STR_SNK_48_1_1(_chans) \
	STR_SNK_48_1((BIT(_chans) - 1)), \
	STR_SNK_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_48_1, LC3_QOS_48_1_1_RTN, \
			LC3_QOS_48_1_1_LATENCY)

#define STR_SNK_AC2_48_1_1 \
	STR_SNK_48_1_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_48_1_1 = {
	.cc = LC3_CONFIG_48_1_AC(2),
	.qos = LC3_QOS_48_1_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_48_1_1 \
	STR_SNK_48_1_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_48_2_1 = {
	.cc = LC3_CONFIG_48_2_AC(1),
	.qos = LC3_QOS_48_2_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_48_2(_ac) \
	STR_SNK_48(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_48_2)

#define STR_SNK_48_2_1(_chans) \
	STR_SNK_48_2((BIT(_chans) - 1)), \
	STR_SNK_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_48_2, LC3_QOS_48_2_1_RTN, \
			LC3_QOS_48_2_1_LATENCY)

#define STR_SNK_AC2_48_2_1 \
	STR_SNK_48_2_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_48_2_1 = {
	.cc = LC3_CONFIG_48_2_AC(2),
	.qos = LC3_QOS_48_2_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_48_2_1 \
	STR_SNK_48_2_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_48_3_1 = {
	.cc = LC3_CONFIG_48_3_AC(1),
	.qos = LC3_QOS_48_3_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_48_3(_ac) \
	STR_SNK_48(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_48_3)

#define STR_SNK_48_3_1(_chans) \
	STR_SNK_48_3((BIT(_chans) - 1)), \
	STR_SNK_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_48_3, LC3_QOS_48_3_1_RTN, \
			LC3_QOS_48_3_1_LATENCY)

#define STR_SNK_AC2_48_3_1 \
	STR_SNK_48_3_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_48_3_1 = {
	.cc = LC3_CONFIG_48_3_AC(2),
	.qos = LC3_QOS_48_3_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_48_3_1 \
	STR_SNK_48_3_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_48_4_1 = {
	.cc = LC3_CONFIG_48_4_AC(1),
	.qos = LC3_QOS_48_4_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_48_4(_ac) \
	STR_SNK_48(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_48_4)

#define STR_SNK_48_4_1(_chans) \
	STR_SNK_48_4((BIT(_chans) - 1)), \
	STR_SNK_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_48_4, LC3_QOS_48_4_1_RTN, \
			LC3_QOS_48_4_1_LATENCY)

#define STR_SNK_AC2_48_4_1 \
	STR_SNK_48_4_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_48_4_1 = {
	.cc = LC3_CONFIG_48_4_AC(2),
	.qos = LC3_QOS_48_4_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_48_4_1 \
	STR_SNK_48_4_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_48_5_1 = {
	.cc = LC3_CONFIG_48_5_AC(1),
	.qos = LC3_QOS_48_5_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_48_5(_ac) \
	STR_SNK_48(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_48_5)

#define STR_SNK_48_5_1(_chans) \
	STR_SNK_48_5((BIT(_chans) - 1)), \
	STR_SNK_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_48_5, LC3_QOS_48_5_1_RTN, \
			LC3_QOS_48_5_1_LATENCY)

#define STR_SNK_AC2_48_5_1 \
	STR_SNK_48_5_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_48_5_1 = {
	.cc = LC3_CONFIG_48_5_AC(2),
	.qos = LC3_QOS_48_5_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_48_5_1 \
	STR_SNK_48_5_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_48_6_1 = {
	.cc = LC3_CONFIG_48_6_AC(1),
	.qos = LC3_QOS_48_6_1_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_48_6(_ac) \
	STR_SNK_48(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_48_6)

#define STR_SNK_48_6_1(_chans) \
	STR_SNK_48_6((BIT(_chans) - 1)), \
	STR_SNK_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_48_6, LC3_QOS_48_6_1_RTN, \
			LC3_QOS_48_6_1_LATENCY)

#define STR_SNK_AC2_48_6_1 \
	STR_SNK_48_6_1(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_48_6_1 = {
	.cc = LC3_CONFIG_48_6_AC(2),
	.qos = LC3_QOS_48_6_1_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_48_6_1 \
	STR_SNK_48_6_1(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_48_1_2 = {
	.cc = LC3_CONFIG_48_1_AC(1),
	.qos = LC3_QOS_48_1_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_48_1_2(_chans) \
	STR_SNK_48_1((BIT(_chans) - 1)), \
	STR_SNK_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_48_1, LC3_QOS_48_1_2_RTN, \
			LC3_QOS_48_1_2_LATENCY)

#define STR_SNK_AC2_48_1_2 \
	STR_SNK_48_1_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_48_1_2 = {
	.cc = LC3_CONFIG_48_1_AC(2),
	.qos = LC3_QOS_48_1_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_48_1_2 \
	STR_SNK_48_1_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_48_2_2 = {
	.cc = LC3_CONFIG_48_2_AC(1),
	.qos = LC3_QOS_48_2_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_48_2_2(_chans) \
	STR_SNK_48_2((BIT(_chans) - 1)), \
	STR_SNK_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_48_2, LC3_QOS_48_2_2_RTN, \
			LC3_QOS_48_2_2_LATENCY)

#define STR_SNK_AC2_48_2_2 \
	STR_SNK_48_2_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_48_2_2 = {
	.cc = LC3_CONFIG_48_2_AC(2),
	.qos = LC3_QOS_48_2_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_48_2_2 \
	STR_SNK_48_2_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_48_3_2 = {
	.cc = LC3_CONFIG_48_3_AC(1),
	.qos = LC3_QOS_48_3_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_48_3_2(_chans) \
	STR_SNK_48_3((BIT(_chans) - 1)), \
	STR_SNK_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_48_3, LC3_QOS_48_3_2_RTN, \
			LC3_QOS_48_3_2_LATENCY)

#define STR_SNK_AC2_48_3_2 \
	STR_SNK_48_3_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_48_3_2 = {
	.cc = LC3_CONFIG_48_3_AC(2),
	.qos = LC3_QOS_48_3_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_48_3_2 \
	STR_SNK_48_3_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_48_4_2 = {
	.cc = LC3_CONFIG_48_4_AC(1),
	.qos = LC3_QOS_48_4_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_48_4_2(_chans) \
	STR_SNK_48_4((BIT(_chans) - 1)), \
	STR_SNK_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_48_4, LC3_QOS_48_4_2_RTN, \
			LC3_QOS_48_4_2_LATENCY)

#define STR_SNK_AC2_48_4_2 \
	STR_SNK_48_4_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_48_4_2 = {
	.cc = LC3_CONFIG_48_4_AC(2),
	.qos = LC3_QOS_48_4_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_48_4_2 \
	STR_SNK_48_4_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_48_5_2 = {
	.cc = LC3_CONFIG_48_5_AC(1),
	.qos = LC3_QOS_48_5_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_48_5_2(_chans) \
	STR_SNK_48_5((BIT(_chans) - 1)), \
	STR_SNK_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_48_5, LC3_QOS_48_5_2_RTN, \
			LC3_QOS_48_5_2_LATENCY)

#define STR_SNK_AC2_48_5_2 \
	STR_SNK_48_5_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_48_5_2 = {
	.cc = LC3_CONFIG_48_5_AC(2),
	.qos = LC3_QOS_48_5_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_48_5_2 \
	STR_SNK_48_5_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac2_48_6_2 = {
	.cc = LC3_CONFIG_48_6_AC(1),
	.qos = LC3_QOS_48_6_2_AC(1),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_48_6_2(_chans) \
	STR_SNK_48_6((BIT(_chans) - 1)), \
	STR_SNK_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_48_6, LC3_QOS_48_6_2_RTN, \
			LC3_QOS_48_6_2_LATENCY)

#define STR_SNK_AC2_48_6_2 \
	STR_SNK_48_6_2(1), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_snk_ac10_48_6_2 = {
	.cc = LC3_CONFIG_48_6_AC(2),
	.qos = LC3_QOS_48_6_2_AC(2),
	.snk = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SNK_AC10_48_6_2 \
	STR_SNK_48_6_2(2), \
	SNK_ENABLE, \
	SNK_START

static struct test_config str_src_ac1_8_1_1 = {
	.cc = LC3_CONFIG_8_1_AC(1),
	.qos = LC3_QOS_8_1_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC(_freq, _ac, _dur, _len) \
	SCC_SRC_LC3(0x10, 0x02, 0x01, _freq, 0x02, 0x02, _dur, 0x03, 0x04, \
			_len, _len >> 8, 0x05, 0x03, _ac, 0x00, 0x00, 0x00)

#define STR_SRC_8(_ac, _dur, _len) \
	STR_SRC(LC3_CONFIG_FREQ_8KHZ, _ac, _dur, _len)

#define STR_SRC_8_1(_ac) \
	STR_SRC_8(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_8_1)

#define STR_SRC_QOS(_interval, _frame, _sdu, _rtn, _latency) \
	QOS_SRC(_interval & 0xff, _interval >> 8 & 0xff, \
		_interval >> 16 & 0xff, _frame, 0x02, _sdu & 0xff, \
		_sdu >> 8 & 0xff, _rtn, \
		_latency, _latency >> 8, 0x40, 0x9c, 0x00)

#define STR_SRC_QOS_1(_sdu, _rtn, _latency) \
	STR_SRC_QOS(7500u, LC3_QOS_UNFRAMED, _sdu, _rtn, _latency)

#define STR_SRC_8_1_1(_chans) \
	STR_SRC_8_1((BIT(_chans) - 1)), \
	STR_SRC_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_8_1, LC3_QOS_8_1_1_RTN, \
			LC3_QOS_8_1_1_LATENCY)

#define STR_SRC_AC1_8_1_1 \
	STR_SRC_8_1_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_8_1_1 = {
	.cc = LC3_CONFIG_8_1_AC(2),
	.qos = LC3_QOS_8_1_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_8_1_1 \
	STR_SRC_8_1_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_8_2_1 = {
	.cc = LC3_CONFIG_8_2_AC(1),
	.qos = LC3_QOS_8_2_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_8_2(_ac) \
	STR_SRC_8(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_8_2)

#define STR_SRC_QOS_2(_sdu, _rtn, _latency) \
	STR_SRC_QOS(10000u, LC3_QOS_UNFRAMED, _sdu, _rtn, _latency)

#define STR_SRC_8_2_1(_chans) \
	STR_SRC_8_2((BIT(_chans) - 1)), \
	STR_SRC_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_8_2, LC3_QOS_8_2_1_RTN, \
			LC3_QOS_8_2_1_LATENCY)

#define STR_SRC_AC1_8_2_1 \
	STR_SRC_8_2_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_8_2_1 = {
	.cc = LC3_CONFIG_8_2_AC(2),
	.qos = LC3_QOS_8_2_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_8_2_1 \
	STR_SRC_8_2_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_16_1_1 = {
	.cc = LC3_CONFIG_16_1_AC(1),
	.qos = LC3_QOS_16_1_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_16(_ac, _dur, _len) \
	STR_SRC(LC3_CONFIG_FREQ_16KHZ, _ac, _dur, _len)

#define STR_SRC_16_1(_ac) \
	STR_SRC_16(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_16_1)

#define STR_SRC_16_1_1(_chans) \
	STR_SRC_16_1((BIT(_chans) - 1)), \
	STR_SRC_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_16_1, LC3_QOS_16_1_1_RTN, \
			LC3_QOS_16_1_1_LATENCY)

#define STR_SRC_AC1_16_1_1 \
	STR_SRC_16_1_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_16_1_1 = {
	.cc = LC3_CONFIG_16_1_AC(2),
	.qos = LC3_QOS_16_1_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_16_1_1 \
	STR_SRC_16_1_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_16_2_1 = {
	.cc = LC3_CONFIG_16_2_AC(1),
	.qos = LC3_QOS_16_2_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_16_2(_ac) \
	STR_SRC_16(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_16_2)

#define STR_SRC_16_2_1(_chans) \
	STR_SRC_16_2((BIT(_chans) - 1)), \
	STR_SRC_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_16_2, LC3_QOS_16_2_1_RTN, \
			LC3_QOS_16_2_1_LATENCY)

#define STR_SRC_AC1_16_2_1 \
	STR_SRC_16_2_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_16_2_1 = {
	.cc = LC3_CONFIG_16_2_AC(2),
	.qos = LC3_QOS_16_2_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_16_2_1 \
	STR_SRC_16_2_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_24_1_1 = {
	.cc = LC3_CONFIG_24_1_AC(1),
	.qos = LC3_QOS_24_1_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_24(_ac, _dur, _len) \
	STR_SRC(LC3_CONFIG_FREQ_24KHZ, _ac, _dur, _len)

#define STR_SRC_24_1(_ac) \
	STR_SRC_24(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_24_1)

#define STR_SRC_24_1_1(_chans) \
	STR_SRC_24_1((BIT(_chans) - 1)), \
	STR_SRC_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_24_1, LC3_QOS_24_1_1_RTN, \
			LC3_QOS_24_1_1_LATENCY)

#define STR_SRC_AC1_24_1_1 \
	STR_SRC_24_1_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_24_1_1 = {
	.cc = LC3_CONFIG_24_1_AC(2),
	.qos = LC3_QOS_24_1_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_24_1_1 \
	STR_SRC_24_1_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_24_2_1 = {
	.cc = LC3_CONFIG_24_2_AC(1),
	.qos = LC3_QOS_24_2_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_24_2(_ac) \
	STR_SRC_24(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_24_2)

#define STR_SRC_24_2_1(_chans) \
	STR_SRC_24_2((BIT(_chans) - 1)), \
	STR_SRC_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_24_2, LC3_QOS_24_2_1_RTN, \
			LC3_QOS_24_2_1_LATENCY)

#define STR_SRC_AC1_24_2_1 \
	STR_SRC_24_2_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_24_2_1 = {
	.cc = LC3_CONFIG_24_2_AC(2),
	.qos = LC3_QOS_24_2_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_24_2_1 \
	STR_SRC_24_2_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_32_1_1 = {
	.cc = LC3_CONFIG_32_1_AC(1),
	.qos = LC3_QOS_32_1_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_32(_ac, _dur, _len) \
	STR_SRC(LC3_CONFIG_FREQ_32KHZ, _ac, _dur, _len)

#define STR_SRC_32_1(_ac) \
	STR_SRC_32(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_32_1)

#define STR_SRC_32_1_1(_chans) \
	STR_SRC_32_1((BIT(_chans) - 1)), \
	STR_SRC_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_32_1, LC3_QOS_32_1_1_RTN, \
			LC3_QOS_32_1_1_LATENCY)

#define STR_SRC_AC1_32_1_1 \
	STR_SRC_32_1_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_32_1_1 = {
	.cc = LC3_CONFIG_32_1_AC(2),
	.qos = LC3_QOS_32_1_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_32_1_1 \
	STR_SRC_32_1_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_32_2_1 = {
	.cc = LC3_CONFIG_32_2_AC(1),
	.qos = LC3_QOS_32_2_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_32_2(_ac) \
	STR_SRC_32(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_32_2)

#define STR_SRC_32_2_1(_chans) \
	STR_SRC_32_2((BIT(_chans) - 1)), \
	STR_SRC_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_32_2, LC3_QOS_32_2_1_RTN, \
			LC3_QOS_32_2_1_LATENCY)

#define STR_SRC_AC1_32_2_1 \
	STR_SRC_32_2_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_32_2_1 = {
	.cc = LC3_CONFIG_32_2_AC(2),
	.qos = LC3_QOS_32_2_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_32_2_1 \
	STR_SRC_32_2_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_44_1_1 = {
	.cc = LC3_CONFIG_44_1_AC(1),
	.qos = LC3_QOS_44_1_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_44(_ac, _dur, _len) \
	STR_SRC(LC3_CONFIG_FREQ_44KHZ, _ac, _dur, _len)

#define STR_SRC_44_1(_ac) \
	STR_SRC_44(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_44_1)

#define STR_SRC_QOS_44_1(_sdu, _rtn, _latency) \
	STR_SRC_QOS(LC3_QOS_44_1_INTERVAL, LC3_QOS_FRAMED, _sdu, _rtn, \
			_latency)

#define STR_SRC_44_1_1(_chans) \
	STR_SRC_44_1((BIT(_chans) - 1)), \
	STR_SRC_QOS_44_1(_chans * LC3_CONFIG_FRAME_LEN_44_1, \
			LC3_QOS_44_1_1_RTN, LC3_QOS_44_1_1_LATENCY)

#define STR_SRC_AC1_44_1_1 \
	STR_SRC_44_1_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_44_1_1 = {
	.cc = LC3_CONFIG_44_1_AC(2),
	.qos = LC3_QOS_44_1_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_44_1_1 \
	STR_SRC_44_1_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_44_2_1 = {
	.cc = LC3_CONFIG_44_2_AC(1),
	.qos = LC3_QOS_44_2_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_44_2(_ac) \
	STR_SRC_44(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_44_2)

#define STR_SRC_QOS_44_2(_sdu, _rtn, _latency) \
	STR_SRC_QOS(LC3_QOS_44_2_INTERVAL, LC3_QOS_FRAMED, _sdu, _rtn, \
			_latency)

#define STR_SRC_44_2_1(_chans) \
	STR_SRC_44_2((BIT(_chans) - 1)), \
	STR_SRC_QOS_44_2(_chans * LC3_CONFIG_FRAME_LEN_44_2, \
			LC3_QOS_44_2_1_RTN, LC3_QOS_44_2_1_LATENCY)

#define STR_SRC_AC1_44_2_1 \
	STR_SRC_44_2_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_44_2_1 = {
	.cc = LC3_CONFIG_44_2_AC(2),
	.qos = LC3_QOS_44_2_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_44_2_1 \
	STR_SRC_44_2_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_48_1_1 = {
	.cc = LC3_CONFIG_48_1_AC(1),
	.qos = LC3_QOS_48_1_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_48(_ac, _dur, _len) \
	STR_SRC(LC3_CONFIG_FREQ_48KHZ, _ac, _dur, _len)

#define STR_SRC_48_1(_ac) \
	STR_SRC_48(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_48_1)

#define STR_SRC_48_1_1(_chans) \
	STR_SRC_48_1((BIT(_chans) - 1)), \
	STR_SRC_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_48_1, LC3_QOS_48_1_1_RTN, \
			LC3_QOS_48_1_1_LATENCY)

#define STR_SRC_AC1_48_1_1 \
	STR_SRC_48_1_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_48_1_1 = {
	.cc = LC3_CONFIG_48_1_AC(2),
	.qos = LC3_QOS_48_1_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_48_1_1 \
	STR_SRC_48_1_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_48_2_1 = {
	.cc = LC3_CONFIG_48_2_AC(1),
	.qos = LC3_QOS_48_2_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_48_2(_ac) \
	STR_SRC_48(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_48_2)

#define STR_SRC_48_2_1(_chans) \
	STR_SRC_48_2((BIT(_chans) - 1)), \
	STR_SRC_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_48_2, LC3_QOS_48_2_1_RTN, \
			LC3_QOS_48_2_1_LATENCY)

#define STR_SRC_AC1_48_2_1 \
	STR_SRC_48_2_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_48_2_1 = {
	.cc = LC3_CONFIG_48_2_AC(2),
	.qos = LC3_QOS_48_2_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_48_2_1 \
	STR_SRC_48_2_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_48_3_1 = {
	.cc = LC3_CONFIG_48_3_AC(1),
	.qos = LC3_QOS_48_3_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_48_3(_ac) \
	STR_SRC_48(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_48_3)

#define STR_SRC_48_3_1(_chans) \
	STR_SRC_48_3((BIT(_chans) - 1)), \
	STR_SRC_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_48_3, LC3_QOS_48_3_1_RTN, \
			LC3_QOS_48_3_1_LATENCY)

#define STR_SRC_AC1_48_3_1 \
	STR_SRC_48_3_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_48_3_1 = {
	.cc = LC3_CONFIG_48_3_AC(2),
	.qos = LC3_QOS_48_3_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_48_3_1 \
	STR_SRC_48_3_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_48_4_1 = {
	.cc = LC3_CONFIG_48_4_AC(1),
	.qos = LC3_QOS_48_4_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_48_4(_ac) \
	STR_SRC_48(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_48_4)

#define STR_SRC_48_4_1(_chans) \
	STR_SRC_48_4((BIT(_chans) - 1)), \
	STR_SRC_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_48_4, LC3_QOS_48_4_1_RTN, \
			LC3_QOS_48_4_1_LATENCY)

#define STR_SRC_AC1_48_4_1 \
	STR_SRC_48_4_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_48_4_1 = {
	.cc = LC3_CONFIG_48_4_AC(2),
	.qos = LC3_QOS_48_4_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_48_4_1 \
	STR_SRC_48_4_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_48_5_1 = {
	.cc = LC3_CONFIG_48_5_AC(1),
	.qos = LC3_QOS_48_5_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_48_5(_ac) \
	STR_SRC_48(_ac, LC3_CONFIG_DURATION_7_5, LC3_CONFIG_FRAME_LEN_48_5)

#define STR_SRC_48_5_1(_chans) \
	STR_SRC_48_5((BIT(_chans) - 1)), \
	STR_SRC_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_48_5, LC3_QOS_48_5_1_RTN, \
			LC3_QOS_48_5_1_LATENCY)

#define STR_SRC_AC1_48_5_1 \
	STR_SRC_48_5_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_48_5_1 = {
	.cc = LC3_CONFIG_48_5_AC(2),
	.qos = LC3_QOS_48_5_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_48_5_1 \
	STR_SRC_48_5_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_48_6_1 = {
	.cc = LC3_CONFIG_48_6_AC(1),
	.qos = LC3_QOS_48_6_1_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_48_6(_ac) \
	STR_SRC_48(_ac, LC3_CONFIG_DURATION_10, LC3_CONFIG_FRAME_LEN_48_6)

#define STR_SRC_48_6_1(_chans) \
	STR_SRC_48_6((BIT(_chans) - 1)), \
	STR_SRC_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_48_6, LC3_QOS_48_6_1_RTN, \
			LC3_QOS_48_6_1_LATENCY)

#define STR_SRC_AC1_48_6_1 \
	STR_SRC_48_6_1(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_48_6_1 = {
	.cc = LC3_CONFIG_48_6_AC(2),
	.qos = LC3_QOS_48_6_1_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_48_6_1 \
	STR_SRC_48_6_1(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_8_1_2 = {
	.cc = LC3_CONFIG_8_1_AC(1),
	.qos = LC3_QOS_8_1_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_8_1_2(_chans) \
	STR_SRC_8_1((BIT(_chans) - 1)), \
	STR_SRC_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_8_1, LC3_QOS_8_1_2_RTN, \
			LC3_QOS_8_1_2_LATENCY)

#define STR_SRC_AC1_8_1_2 \
	STR_SRC_8_1_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_8_1_2 = {
	.cc = LC3_CONFIG_8_1_AC(2),
	.qos = LC3_QOS_8_1_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_8_1_2 \
	STR_SRC_8_1_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_8_2_2 = {
	.cc = LC3_CONFIG_8_2_AC(1),
	.qos = LC3_QOS_8_2_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_8_2_2(_chans) \
	STR_SRC_8_2((BIT(_chans) - 1)), \
	STR_SRC_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_8_2, LC3_QOS_8_2_2_RTN, \
			LC3_QOS_8_2_2_LATENCY)

#define STR_SRC_AC1_8_2_2 \
	STR_SRC_8_2_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_8_2_2 = {
	.cc = LC3_CONFIG_8_2_AC(2),
	.qos = LC3_QOS_8_2_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_8_2_2 \
	STR_SRC_8_2_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_16_1_2 = {
	.cc = LC3_CONFIG_16_1_AC(1),
	.qos = LC3_QOS_16_1_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_16_1_2(_chans) \
	STR_SRC_16_1((BIT(_chans) - 1)), \
	STR_SRC_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_16_1, LC3_QOS_16_1_2_RTN, \
			LC3_QOS_16_1_2_LATENCY)

#define STR_SRC_AC1_16_1_2 \
	STR_SRC_16_1_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_16_1_2 = {
	.cc = LC3_CONFIG_16_1_AC(2),
	.qos = LC3_QOS_16_1_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_16_1_2 \
	STR_SRC_16_1_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_16_2_2 = {
	.cc = LC3_CONFIG_16_2_AC(1),
	.qos = LC3_QOS_16_2_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_16_2_2(_chans) \
	STR_SRC_16_2((BIT(_chans) - 1)), \
	STR_SRC_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_16_2, LC3_QOS_16_2_2_RTN, \
			LC3_QOS_16_2_2_LATENCY)

#define STR_SRC_AC1_16_2_2 \
	STR_SRC_16_2_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_16_2_2 = {
	.cc = LC3_CONFIG_16_2_AC(2),
	.qos = LC3_QOS_16_2_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_16_2_2 \
	STR_SRC_16_2_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_24_1_2 = {
	.cc = LC3_CONFIG_24_1_AC(1),
	.qos = LC3_QOS_24_1_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_24_1_2(_chans) \
	STR_SRC_24_1((BIT(_chans) - 1)), \
	STR_SRC_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_24_1, LC3_QOS_24_1_2_RTN, \
			LC3_QOS_24_1_2_LATENCY)

#define STR_SRC_AC1_24_1_2 \
	STR_SRC_24_1_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_24_1_2 = {
	.cc = LC3_CONFIG_24_1_AC(2),
	.qos = LC3_QOS_24_1_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_24_1_2 \
	STR_SRC_24_1_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_24_2_2 = {
	.cc = LC3_CONFIG_24_2_AC(1),
	.qos = LC3_QOS_24_2_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_24_2_2(_chans) \
	STR_SRC_24_2((BIT(_chans) - 1)), \
	STR_SRC_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_24_2, LC3_QOS_24_2_2_RTN, \
			LC3_QOS_24_2_2_LATENCY)

#define STR_SRC_AC1_24_2_2 \
	STR_SRC_24_2_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_24_2_2 = {
	.cc = LC3_CONFIG_24_2_AC(2),
	.qos = LC3_QOS_24_2_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_24_2_2 \
	STR_SRC_24_2_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_32_1_2 = {
	.cc = LC3_CONFIG_32_1_AC(1),
	.qos = LC3_QOS_32_1_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_32_1_2(_chans) \
	STR_SRC_32_1((BIT(_chans) - 1)), \
	STR_SRC_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_32_1, LC3_QOS_32_1_2_RTN, \
			LC3_QOS_32_1_2_LATENCY)

#define STR_SRC_AC1_32_1_2 \
	STR_SRC_32_1_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_32_1_2 = {
	.cc = LC3_CONFIG_32_1_AC(2),
	.qos = LC3_QOS_32_1_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_32_1_2 \
	STR_SRC_32_1_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_32_2_2 = {
	.cc = LC3_CONFIG_32_2_AC(1),
	.qos = LC3_QOS_32_2_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_32_2_2(_chans) \
	STR_SRC_32_2((BIT(_chans) - 1)), \
	STR_SRC_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_32_2, LC3_QOS_32_2_2_RTN, \
			LC3_QOS_32_2_2_LATENCY)

#define STR_SRC_AC1_32_2_2 \
	STR_SRC_32_2_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_32_2_2 = {
	.cc = LC3_CONFIG_32_2_AC(2),
	.qos = LC3_QOS_32_2_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_32_2_2 \
	STR_SRC_32_2_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_44_1_2 = {
	.cc = LC3_CONFIG_44_1_AC(1),
	.qos = LC3_QOS_44_1_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};


#define STR_SRC_44_1_2(_chans) \
	STR_SRC_44_1((BIT(_chans) - 1)), \
	STR_SRC_QOS_44_1(_chans * LC3_CONFIG_FRAME_LEN_44_1, \
			 LC3_QOS_44_1_2_RTN, LC3_QOS_44_1_2_LATENCY)

#define STR_SRC_AC1_44_1_2 \
	STR_SRC_44_1_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_44_1_2 = {
	.cc = LC3_CONFIG_44_1_AC(2),
	.qos = LC3_QOS_44_1_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_44_1_2 \
	STR_SRC_44_1_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_44_2_2 = {
	.cc = LC3_CONFIG_44_2_AC(1),
	.qos = LC3_QOS_44_2_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_44_2_2(_chans) \
	STR_SRC_44_2((BIT(_chans) - 1)), \
	STR_SRC_QOS_44_2(_chans * LC3_CONFIG_FRAME_LEN_44_2, \
			LC3_QOS_44_2_2_RTN, LC3_QOS_44_2_2_LATENCY)

#define STR_SRC_AC1_44_2_2 \
	STR_SRC_44_2_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_44_2_2 = {
	.cc = LC3_CONFIG_44_2_AC(2),
	.qos = LC3_QOS_44_2_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_44_2_2 \
	STR_SRC_44_2_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_48_1_2 = {
	.cc = LC3_CONFIG_48_1_AC(1),
	.qos = LC3_QOS_48_1_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};


#define STR_SRC_48_1_2(_chans) \
	STR_SRC_48_1((BIT(_chans) - 1)), \
	STR_SRC_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_48_1, LC3_QOS_48_1_2_RTN, \
			LC3_QOS_48_1_2_LATENCY)

#define STR_SRC_AC1_48_1_2 \
	STR_SRC_48_1_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_48_1_2 = {
	.cc = LC3_CONFIG_48_1_AC(2),
	.qos = LC3_QOS_48_1_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_48_1_2 \
	STR_SRC_48_1_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_48_2_2 = {
	.cc = LC3_CONFIG_48_2_AC(1),
	.qos = LC3_QOS_48_2_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_48_2_2(_chans) \
	STR_SRC_48_2((BIT(_chans) - 1)), \
	STR_SRC_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_48_2, LC3_QOS_48_2_2_RTN, \
			LC3_QOS_48_2_2_LATENCY)

#define STR_SRC_AC1_48_2_2 \
	STR_SRC_48_2_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_48_2_2 = {
	.cc = LC3_CONFIG_48_2_AC(2),
	.qos = LC3_QOS_48_2_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_48_2_2 \
	STR_SRC_48_2_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_48_3_2 = {
	.cc = LC3_CONFIG_48_3_AC(1),
	.qos = LC3_QOS_48_3_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};


#define STR_SRC_48_3_2(_chans) \
	STR_SRC_48_3((BIT(_chans) - 1)), \
	STR_SRC_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_48_3, LC3_QOS_48_3_2_RTN, \
			LC3_QOS_48_3_2_LATENCY)

#define STR_SRC_AC1_48_3_2 \
	STR_SRC_48_3_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_48_3_2 = {
	.cc = LC3_CONFIG_48_3_AC(2),
	.qos = LC3_QOS_48_3_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_48_3_2 \
	STR_SRC_48_3_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_48_4_2 = {
	.cc = LC3_CONFIG_48_4_AC(1),
	.qos = LC3_QOS_48_4_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_48_4_2(_chans) \
	STR_SRC_48_4((BIT(_chans) - 1)), \
	STR_SRC_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_48_4, LC3_QOS_48_4_2_RTN, \
			LC3_QOS_48_4_2_LATENCY)

#define STR_SRC_AC1_48_4_2 \
	STR_SRC_48_4_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_48_4_2 = {
	.cc = LC3_CONFIG_48_4_AC(2),
	.qos = LC3_QOS_48_4_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_48_4_2 \
	STR_SRC_48_4_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_48_5_2 = {
	.cc = LC3_CONFIG_48_5_AC(1),
	.qos = LC3_QOS_48_5_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};


#define STR_SRC_48_5_2(_chans) \
	STR_SRC_48_5((BIT(_chans) - 1)), \
	STR_SRC_QOS_1(_chans * LC3_CONFIG_FRAME_LEN_48_5, LC3_QOS_48_5_2_RTN, \
			LC3_QOS_48_5_2_LATENCY)

#define STR_SRC_AC1_48_5_2 \
	STR_SRC_48_5_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_48_5_2 = {
	.cc = LC3_CONFIG_48_5_AC(2),
	.qos = LC3_QOS_48_5_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_48_5_2 \
	STR_SRC_48_5_2(2), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac1_48_6_2 = {
	.cc = LC3_CONFIG_48_6_AC(1),
	.qos = LC3_QOS_48_6_2_AC(1),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_48_6_2(_chans) \
	STR_SRC_48_6((BIT(_chans) - 1)), \
	STR_SRC_QOS_2(_chans * LC3_CONFIG_FRAME_LEN_48_6, LC3_QOS_48_6_2_RTN, \
			LC3_QOS_48_6_2_LATENCY)

#define STR_SRC_AC1_48_6_2 \
	STR_SRC_48_6_2(1), \
	SRC_ENABLE, \
	SRC_START

static struct test_config str_src_ac4_48_6_2 = {
	.cc = LC3_CONFIG_48_6_AC(2),
	.qos = LC3_QOS_48_6_2_AC(2),
	.src = true,
	.state = BT_BAP_STREAM_STATE_STREAMING,
};

#define STR_SRC_AC4_48_6_2 \
	STR_SRC_48_6_2(2), \
	SRC_ENABLE, \
	SRC_START

/* Unicast Client Streaming – 1 Unicast Server, 1 Stream, 1 CIS – LC3
 *
 * Test Purpose:
 * Verify that a Unicast Client IUT can stream audio data over one unicast
 * Audio Stream to or from a Unicast Server.
 *
 * Pass verdict:
 * If the IUT is in the Audio Sink role, the IUT receives SDUs with a zero or
 * more length that contains LC3-encoded data formatted using the LC3 Media
 * Packet format (defined in [3] Section 4.2).
 */
static void test_ucl_str_1_1_1_lc3(void)
{
	define_test("BAP/UCL/STR/BV-001-C [UCL, AC 2, LC3 8_1_1]",
			test_setup, test_client, &str_snk_ac2_8_1_1,
			STR_SNK_AC2_8_1_1);
	define_test("BAP/UCL/STR/BV-002-C [UCL, AC 10, LC3 8_1_1]",
			test_setup, test_client, &str_snk_ac10_8_1_1,
			STR_SNK_AC10_8_1_1);
	define_test("BAP/UCL/STR/BV-003-C [UCL, AC 2, LC3 8_2_1]",
			test_setup, test_client, &str_snk_ac2_8_2_1,
			STR_SNK_AC2_8_2_1);
	define_test("BAP/UCL/STR/BV-004-C [UCL, AC 10, LC3 8_2_1]",
			test_setup, test_client, &str_snk_ac10_8_2_1,
			STR_SNK_AC10_8_2_1);
	define_test("BAP/UCL/STR/BV-005-C [UCL, AC 2, LC3 16_1_1]",
			test_setup, test_client, &str_snk_ac2_16_1_1,
			STR_SNK_AC2_16_1_1);
	define_test("BAP/UCL/STR/BV-006-C [UCL, AC 10, LC3 16_1_1]",
			test_setup, test_client, &str_snk_ac10_16_1_1,
			STR_SNK_AC10_16_1_1);
	define_test("BAP/UCL/STR/BV-007-C [UCL, AC 2, LC3 16_2_1]",
			test_setup, test_client, &str_snk_ac2_16_2_1,
			STR_SNK_AC2_16_2_1);
	define_test("BAP/UCL/STR/BV-008-C [UCL, AC 10, LC3 16_2_1]",
			test_setup, test_client, &str_snk_ac10_16_2_1,
			STR_SNK_AC10_16_2_1);
	define_test("BAP/UCL/STR/BV-009-C [UCL, AC 2, LC3 24_1_1]",
			test_setup, test_client, &str_snk_ac2_24_1_1,
			STR_SNK_AC2_24_1_1);
	define_test("BAP/UCL/STR/BV-010-C [UCL, AC 10, LC3 24_1_1]",
			test_setup, test_client, &str_snk_ac10_24_1_1,
			STR_SNK_AC10_24_1_1);
	define_test("BAP/UCL/STR/BV-011-C [UCL, AC 2, LC3 24_2_1]",
			test_setup, test_client, &str_snk_ac2_24_2_1,
			STR_SNK_AC2_24_2_1);
	define_test("BAP/UCL/STR/BV-012-C [UCL, AC 10, LC3 24_2_1]",
			test_setup, test_client, &str_snk_ac10_24_2_1,
			STR_SNK_AC10_24_2_1);
	define_test("BAP/UCL/STR/BV-013-C [UCL, AC 2, LC3 32_1_1]",
			test_setup, test_client, &str_snk_ac2_32_1_1,
			STR_SNK_AC2_32_1_1);
	define_test("BAP/UCL/STR/BV-014-C [UCL, AC 10, LC3 32_1_1]",
			test_setup, test_client, &str_snk_ac10_32_1_1,
			STR_SNK_AC10_32_1_1);
	define_test("BAP/UCL/STR/BV-015-C [UCL, AC 2, LC3 32_2_1]",
			test_setup, test_client, &str_snk_ac2_32_2_1,
			STR_SNK_AC2_32_2_1);
	define_test("BAP/UCL/STR/BV-016-C [UCL, AC 10, LC3 32_2_1]",
			test_setup, test_client, &str_snk_ac10_32_2_1,
			STR_SNK_AC10_32_2_1);
	define_test("BAP/UCL/STR/BV-017-C [UCL, AC 2, LC3 441_1_1]",
			test_setup, test_client, &str_snk_ac2_44_1_1,
			STR_SNK_AC2_44_1_1);
	define_test("BAP/UCL/STR/BV-018-C [UCL, AC 10, LC3 441_1_1]",
			test_setup, test_client, &str_snk_ac10_44_1_1,
			STR_SNK_AC10_44_1_1);
	define_test("BAP/UCL/STR/BV-019-C [UCL, AC 2, LC3 44_2_1]",
			test_setup, test_client, &str_snk_ac2_44_2_1,
			STR_SNK_AC2_44_2_1);
	define_test("BAP/UCL/STR/BV-020-C [UCL, AC 10, LC3 44_2_1]",
			test_setup, test_client, &str_snk_ac10_44_2_1,
			STR_SNK_AC10_44_2_1);
	define_test("BAP/UCL/STR/BV-021-C [UCL, AC 2, LC3 48_1_1]",
			test_setup, test_client, &str_snk_ac2_48_1_1,
			STR_SNK_AC2_48_1_1);
	define_test("BAP/UCL/STR/BV-022-C [UCL, AC 10, LC3 48_1_1]",
			test_setup, test_client, &str_snk_ac10_48_1_1,
			STR_SNK_AC10_48_1_1);
	define_test("BAP/UCL/STR/BV-023-C [UCL, AC 2, LC3 48_2_1]",
			test_setup, test_client, &str_snk_ac2_48_2_1,
			STR_SNK_AC2_48_2_1);
	define_test("BAP/UCL/STR/BV-024-C [UCL, AC 10, LC3 48_2_1]",
			test_setup, test_client, &str_snk_ac10_48_2_1,
			STR_SNK_AC10_48_2_1);
	define_test("BAP/UCL/STR/BV-025-C [UCL, AC 2, LC3 48_3_1]",
			test_setup, test_client, &str_snk_ac2_48_3_1,
			STR_SNK_AC2_48_3_1);
	define_test("BAP/UCL/STR/BV-026-C [UCL, AC 10, LC3 48_3_1]",
			test_setup, test_client, &str_snk_ac10_48_3_1,
			STR_SNK_AC10_48_3_1);
	define_test("BAP/UCL/STR/BV-027-C [UCL, AC 2, LC3 48_4_1]",
			test_setup, test_client, &str_snk_ac2_48_4_1,
			STR_SNK_AC2_48_4_1);
	define_test("BAP/UCL/STR/BV-028-C [UCL, AC 10, LC3 48_4_1]",
			test_setup, test_client, &str_snk_ac10_48_4_1,
			STR_SNK_AC10_48_4_1);
	define_test("BAP/UCL/STR/BV-029-C [UCL, AC 2, LC3 48_5_1]",
			test_setup, test_client, &str_snk_ac2_48_5_1,
			STR_SNK_AC2_48_5_1);
	define_test("BAP/UCL/STR/BV-030-C [UCL, AC 10, LC3 48_5_1]",
			test_setup, test_client, &str_snk_ac10_48_5_1,
			STR_SNK_AC10_48_5_1);
	define_test("BAP/UCL/STR/BV-031-C [UCL, AC 2, LC3 48_6_1]",
			test_setup, test_client, &str_snk_ac2_48_6_1,
			STR_SNK_AC2_48_6_1);
	define_test("BAP/UCL/STR/BV-032-C [UCL, AC 10, LC3 48_6_1]",
			test_setup, test_client, &str_snk_ac10_48_6_1,
			STR_SNK_AC10_48_6_1);
	define_test("BAP/UCL/STR/BV-033-C [UCL, SRC, AC 1, LC3 8_1_1]",
			test_setup, test_client, &str_src_ac1_8_1_1,
			STR_SRC_AC1_8_1_1);
	define_test("BAP/UCL/STR/BV-034-C [UCL, SRC, AC 4, LC3 8_1_1]",
			test_setup, test_client, &str_src_ac4_8_1_1,
			STR_SRC_AC4_8_1_1);
	define_test("BAP/UCL/STR/BV-035-C [UCL, SRC, AC 1, LC3 8_2_1]",
			test_setup, test_client, &str_src_ac1_8_2_1,
			STR_SRC_AC1_8_2_1);
	define_test("BAP/UCL/STR/BV-036-C [UCL, SRC, AC 4, LC3 8_2_1]",
			test_setup, test_client, &str_src_ac4_8_2_1,
			STR_SRC_AC4_8_2_1);
	define_test("BAP/UCL/STR/BV-037-C [UCL, SRC, AC 1, LC3 16_1_1]",
			test_setup, test_client, &str_src_ac1_16_1_1,
			STR_SRC_AC1_16_1_1);
	define_test("BAP/UCL/STR/BV-038-C [UCL, SRC, AC 4, LC3 16_1_1]",
			test_setup, test_client, &str_src_ac4_16_1_1,
			STR_SRC_AC4_16_1_1);
	define_test("BAP/UCL/STR/BV-039-C [UCL, SRC, AC 1, LC3 16_2_1]",
			test_setup, test_client, &str_src_ac1_16_2_1,
			STR_SRC_AC1_16_2_1);
	define_test("BAP/UCL/STR/BV-040-C [UCL, SRC, AC 4, LC3 16_2_1]",
			test_setup, test_client, &str_src_ac4_16_2_1,
			STR_SRC_AC4_16_2_1);
	define_test("BAP/UCL/STR/BV-041-C [UCL, SRC, AC 1, LC3 24_1_1]",
			test_setup, test_client, &str_src_ac1_24_1_1,
			STR_SRC_AC1_24_1_1);
	define_test("BAP/UCL/STR/BV-042-C [UCL, SRC, AC 4, LC3 24_1_1]",
			test_setup, test_client, &str_src_ac4_24_1_1,
			STR_SRC_AC4_24_1_1);
	define_test("BAP/UCL/STR/BV-043-C [UCL, SRC, AC 1, LC3 24_2_1]",
			test_setup, test_client, &str_src_ac1_24_2_1,
			STR_SRC_AC1_24_2_1);
	define_test("BAP/UCL/STR/BV-044-C [UCL, SRC, AC 4, LC3 24_2_1]",
			test_setup, test_client, &str_src_ac4_24_2_1,
			STR_SRC_AC4_24_2_1);
	define_test("BAP/UCL/STR/BV-045-C [UCL, SRC, AC 1, LC3 32_1_1]",
			test_setup, test_client, &str_src_ac1_32_1_1,
			STR_SRC_AC1_32_1_1);
	define_test("BAP/UCL/STR/BV-046-C [UCL, SRC, AC 4, LC3 32_1_1]",
			test_setup, test_client, &str_src_ac4_32_1_1,
			STR_SRC_AC4_32_1_1);
	define_test("BAP/UCL/STR/BV-047-C [UCL, SRC, AC 1, LC3 32_2_1]",
			test_setup, test_client, &str_src_ac1_32_2_1,
			STR_SRC_AC1_32_2_1);
	define_test("BAP/UCL/STR/BV-048-C [UCL, SRC, AC 4, LC3 32_2_1]",
			test_setup, test_client, &str_src_ac4_32_2_1,
			STR_SRC_AC4_32_2_1);
	define_test("BAP/UCL/STR/BV-049-C [UCL, SRC, AC 1, LC3 44_1_1]",
			test_setup, test_client, &str_src_ac1_44_1_1,
			STR_SRC_AC1_44_1_1);
	define_test("BAP/UCL/STR/BV-050-C [UCL, SRC, AC 4, LC3 44_1_1]",
			test_setup, test_client, &str_src_ac4_44_1_1,
			STR_SRC_AC4_44_1_1);
	define_test("BAP/UCL/STR/BV-051-C [UCL, SRC, AC 1, LC3 44_2_1]",
			test_setup, test_client, &str_src_ac1_44_2_1,
			STR_SRC_AC1_44_2_1);
	define_test("BAP/UCL/STR/BV-052-C [UCL, SRC, AC 4, LC3 44_2_1]",
			test_setup, test_client, &str_src_ac4_44_2_1,
			STR_SRC_AC4_44_2_1);
	define_test("BAP/UCL/STR/BV-053-C [UCL, SRC, AC 1, LC3 48_1_1]",
			test_setup, test_client, &str_src_ac1_48_1_1,
			STR_SRC_AC1_48_1_1);
	define_test("BAP/UCL/STR/BV-054-C [UCL, SRC, AC 4, LC3 48_1_1]",
			test_setup, test_client, &str_src_ac4_48_1_1,
			STR_SRC_AC4_48_1_1);
	define_test("BAP/UCL/STR/BV-055-C [UCL, SRC, AC 1, LC3 48_2_1]",
			test_setup, test_client, &str_src_ac1_48_2_1,
			STR_SRC_AC1_48_2_1);
	define_test("BAP/UCL/STR/BV-056-C [UCL, SRC, AC 4, LC3 48_2_1]",
			test_setup, test_client, &str_src_ac4_48_2_1,
			STR_SRC_AC4_48_2_1);
	define_test("BAP/UCL/STR/BV-057-C [UCL, SRC, AC 1, LC3 48_3_1]",
			test_setup, test_client, &str_src_ac1_48_3_1,
			STR_SRC_AC1_48_3_1);
	define_test("BAP/UCL/STR/BV-058-C [UCL, SRC, AC 4, LC3 48_3_1]",
			test_setup, test_client, &str_src_ac4_48_3_1,
			STR_SRC_AC4_48_3_1);
	define_test("BAP/UCL/STR/BV-059-C [UCL, SRC, AC 1, LC3 48_4_1]",
			test_setup, test_client, &str_src_ac1_48_4_1,
			STR_SRC_AC1_48_4_1);
	define_test("BAP/UCL/STR/BV-060-C [UCL, SRC, AC 4, LC3 48_4_1]",
			test_setup, test_client, &str_src_ac4_48_4_1,
			STR_SRC_AC4_48_4_1);
	define_test("BAP/UCL/STR/BV-061-C [UCL, SRC, AC 1, LC3 48_5_1]",
			test_setup, test_client, &str_src_ac1_48_5_1,
			STR_SRC_AC1_48_5_1);
	define_test("BAP/UCL/STR/BV-062-C [UCL, SRC, AC 4, LC3 48_5_1]",
			test_setup, test_client, &str_src_ac4_48_5_1,
			STR_SRC_AC4_48_5_1);
	define_test("BAP/UCL/STR/BV-063-C [UCL, SRC, AC 1, LC3 48_6_1]",
			test_setup, test_client, &str_src_ac1_48_6_1,
			STR_SRC_AC1_48_6_1);
	define_test("BAP/UCL/STR/BV-064-C [UCL, SRC, AC 4, LC3 48_6_1]",
			test_setup, test_client, &str_src_ac4_48_6_1,
			STR_SRC_AC4_48_6_1);
	define_test("BAP/UCL/STR/BV-065-C [UCL, AC 2, LC3 8_1_2]",
			test_setup, test_client, &str_snk_ac2_8_1_2,
			STR_SNK_AC2_8_1_2);
	define_test("BAP/UCL/STR/BV-066-C [UCL, AC 10, LC3 8_1_2]",
			test_setup, test_client, &str_snk_ac10_8_1_2,
			STR_SNK_AC10_8_1_2);
	define_test("BAP/UCL/STR/BV-067-C [UCL, AC 2, LC3 8_2_2]",
			test_setup, test_client, &str_snk_ac2_8_2_2,
			STR_SNK_AC2_8_2_2);
	define_test("BAP/UCL/STR/BV-068-C [UCL, AC 10, LC3 8_2_2]",
			test_setup, test_client, &str_snk_ac10_8_2_2,
			STR_SNK_AC10_8_2_2);
	define_test("BAP/UCL/STR/BV-069-C [UCL, AC 2, LC3 16_1_2]",
			test_setup, test_client, &str_snk_ac2_16_1_2,
			STR_SNK_AC2_16_1_2);
	define_test("BAP/UCL/STR/BV-070-C [UCL, AC 10, LC3 16_1_2]",
			test_setup, test_client, &str_snk_ac10_16_1_2,
			STR_SNK_AC10_16_1_2);
	define_test("BAP/UCL/STR/BV-071-C [UCL, AC 2, LC3 16_2_2]",
			test_setup, test_client, &str_snk_ac2_16_2_2,
			STR_SNK_AC2_16_2_2);
	define_test("BAP/UCL/STR/BV-072-C [UCL, AC 10, LC3 16_2_2]",
			test_setup, test_client, &str_snk_ac10_16_2_2,
			STR_SNK_AC10_16_2_2);
	define_test("BAP/UCL/STR/BV-073-C [UCL, AC 2, LC3 24_1_2]",
			test_setup, test_client, &str_snk_ac2_24_1_2,
			STR_SNK_AC2_24_1_2);
	define_test("BAP/UCL/STR/BV-074-C [UCL, AC 10, LC3 24_1_2]",
			test_setup, test_client, &str_snk_ac10_24_1_2,
			STR_SNK_AC10_24_1_2);
	define_test("BAP/UCL/STR/BV-075-C [UCL, AC 2, LC3 24_2_2]",
			test_setup, test_client, &str_snk_ac2_24_2_2,
			STR_SNK_AC2_24_2_2);
	define_test("BAP/UCL/STR/BV-076-C [UCL, AC 10, LC3 24_2_2]",
			test_setup, test_client, &str_snk_ac10_24_2_2,
			STR_SNK_AC10_24_2_2);
	define_test("BAP/UCL/STR/BV-077-C [UCL, AC 2, LC3 32_1_2]",
			test_setup, test_client, &str_snk_ac2_32_1_2,
			STR_SNK_AC2_32_1_2);
	define_test("BAP/UCL/STR/BV-078-C [UCL, AC 10, LC3 32_1_2]",
			test_setup, test_client, &str_snk_ac10_32_1_2,
			STR_SNK_AC10_32_1_2);
	define_test("BAP/UCL/STR/BV-079-C [UCL, AC 2, LC3 32_2_2]",
			test_setup, test_client, &str_snk_ac2_32_2_2,
			STR_SNK_AC2_32_2_2);
	define_test("BAP/UCL/STR/BV-080-C [UCL, AC 10, LC3 32_2_2]",
			test_setup, test_client, &str_snk_ac10_32_2_2,
			STR_SNK_AC10_32_2_2);
	define_test("BAP/UCL/STR/BV-081-C [UCL, AC 2, LC3 44_1_2]",
			test_setup, test_client, &str_snk_ac2_44_1_2,
			STR_SNK_AC2_44_1_2);
	define_test("BAP/UCL/STR/BV-082-C [UCL, AC 10, LC3 44_1_2]",
			test_setup, test_client, &str_snk_ac10_44_1_2,
			STR_SNK_AC10_44_1_2);
	define_test("BAP/UCL/STR/BV-083-C [UCL, AC 2, LC3 44_2_2]",
			test_setup, test_client, &str_snk_ac2_44_2_2,
			STR_SNK_AC2_44_2_2);
	define_test("BAP/UCL/STR/BV-084-C [UCL, AC 10, LC3 44_2_2]",
			test_setup, test_client, &str_snk_ac10_44_2_2,
			STR_SNK_AC10_44_2_2);
	define_test("BAP/UCL/STR/BV-085-C [UCL, AC 2, LC3 48_1_2]",
			test_setup, test_client, &str_snk_ac2_48_1_2,
			STR_SNK_AC2_48_1_2);
	define_test("BAP/UCL/STR/BV-086-C [UCL, AC 10, LC3 48_1_2]",
			test_setup, test_client, &str_snk_ac10_48_1_2,
			STR_SNK_AC10_48_1_2);
	define_test("BAP/UCL/STR/BV-087-C [UCL, AC 2, LC3 48_2_2]",
			test_setup, test_client, &str_snk_ac2_48_2_2,
			STR_SNK_AC2_48_2_2);
	define_test("BAP/UCL/STR/BV-088-C [UCL, AC 10, LC3 48_2_2]",
			test_setup, test_client, &str_snk_ac10_48_2_2,
			STR_SNK_AC10_48_2_2);
	define_test("BAP/UCL/STR/BV-089-C [UCL, AC 2, LC3 48_3_2]",
			test_setup, test_client, &str_snk_ac2_48_3_2,
			STR_SNK_AC2_48_3_2);
	define_test("BAP/UCL/STR/BV-090-C [UCL, AC 10, LC3 48_3_2]",
			test_setup, test_client, &str_snk_ac10_48_3_2,
			STR_SNK_AC10_48_3_2);
	define_test("BAP/UCL/STR/BV-091-C [UCL, AC 2, LC3 48_4_2]",
			test_setup, test_client, &str_snk_ac2_48_4_2,
			STR_SNK_AC2_48_4_2);
	define_test("BAP/UCL/STR/BV-092-C [UCL, AC 10, LC3 48_4_2]",
			test_setup, test_client, &str_snk_ac10_48_4_2,
			STR_SNK_AC10_48_4_2);
	define_test("BAP/UCL/STR/BV-093-C [UCL, AC 2, LC3 48_5_2]",
			test_setup, test_client, &str_snk_ac2_48_5_2,
			STR_SNK_AC2_48_5_2);
	define_test("BAP/UCL/STR/BV-094-C [UCL, AC 10, LC3 48_5_2]",
			test_setup, test_client, &str_snk_ac10_48_5_2,
			STR_SNK_AC10_48_5_2);
	define_test("BAP/UCL/STR/BV-095-C [UCL, AC 2, LC3 48_6_2]",
			test_setup, test_client, &str_snk_ac2_48_6_2,
			STR_SNK_AC2_48_6_2);
	define_test("BAP/UCL/STR/BV-096-C [UCL, AC 10, LC3 48_6_2]",
			test_setup, test_client, &str_snk_ac10_48_6_2,
			STR_SNK_AC10_48_6_2);
	define_test("BAP/UCL/STR/BV-097-C [UCL, SRC, AC 1, LC3 8_1_2]",
			test_setup, test_client, &str_src_ac1_8_1_2,
			STR_SRC_AC1_8_1_2);
	define_test("BAP/UCL/STR/BV-098-C [UCL, SRC, AC 4, LC3 8_1_2]",
			test_setup, test_client, &str_src_ac4_8_1_2,
			STR_SRC_AC4_8_1_2);
	define_test("BAP/UCL/STR/BV-099-C [UCL, SRC, AC 1, LC3 8_2_2]",
			test_setup, test_client, &str_src_ac1_8_2_2,
			STR_SRC_AC1_8_2_2);
	define_test("BAP/UCL/STR/BV-100-C [UCL, SRC, AC 4, LC3 8_2_2]",
			test_setup, test_client, &str_src_ac4_8_2_2,
			STR_SRC_AC4_8_2_2);
	define_test("BAP/UCL/STR/BV-101-C [UCL, SRC, AC 1, LC3 16_1_2]",
			test_setup, test_client, &str_src_ac1_16_1_2,
			STR_SRC_AC1_16_1_2);
	define_test("BAP/UCL/STR/BV-102-C [UCL, SRC, AC 4, LC3 16_1_2]",
			test_setup, test_client, &str_src_ac4_16_1_2,
			STR_SRC_AC4_16_1_2);
	define_test("BAP/UCL/STR/BV-103-C [UCL, SRC, AC 1, LC3 16_2_2]",
			test_setup, test_client, &str_src_ac1_16_2_2,
			STR_SRC_AC1_16_2_2);
	define_test("BAP/UCL/STR/BV-104-C [UCL, SRC, AC 4, LC3 16_2_2]",
			test_setup, test_client, &str_src_ac4_16_2_2,
			STR_SRC_AC4_16_2_2);
	define_test("BAP/UCL/STR/BV-105-C [UCL, SRC, AC 1, LC3 24_1_2]",
			test_setup, test_client, &str_src_ac1_24_1_2,
			STR_SRC_AC1_24_1_2);
	define_test("BAP/UCL/STR/BV-106-C [UCL, SRC, AC 4, LC3 24_1_2]",
			test_setup, test_client, &str_src_ac4_24_1_2,
			STR_SRC_AC4_24_1_2);
	define_test("BAP/UCL/STR/BV-107-C [UCL, SRC, AC 1, LC3 24_2_2]",
			test_setup, test_client, &str_src_ac1_24_2_2,
			STR_SRC_AC1_24_2_2);
	define_test("BAP/UCL/STR/BV-108-C [UCL, SRC, AC 4, LC3 24_2_2]",
			test_setup, test_client, &str_src_ac4_24_2_2,
			STR_SRC_AC4_24_2_2);
	define_test("BAP/UCL/STR/BV-109-C [UCL, SRC, AC 1, LC3 32_1_2]",
			test_setup, test_client, &str_src_ac1_32_1_2,
			STR_SRC_AC1_32_1_2);
	define_test("BAP/UCL/STR/BV-110-C [UCL, SRC, AC 4, LC3 32_1_2]",
			test_setup, test_client, &str_src_ac4_32_1_2,
			STR_SRC_AC4_32_1_2);
	define_test("BAP/UCL/STR/BV-111-C [UCL, SRC, AC 1, LC3 32_2_2]",
			test_setup, test_client, &str_src_ac1_32_2_2,
			STR_SRC_AC1_32_2_2);
	define_test("BAP/UCL/STR/BV-112-C [UCL, SRC, AC 4, LC3 32_2_2]",
			test_setup, test_client, &str_src_ac4_32_2_2,
			STR_SRC_AC4_32_2_2);
	define_test("BAP/UCL/STR/BV-113-C [UCL, SRC, AC 1, LC3 44_1_2]",
			test_setup, test_client, &str_src_ac1_44_1_2,
			STR_SRC_AC1_44_1_2);
	define_test("BAP/UCL/STR/BV-114-C [UCL, SRC, AC 4, LC3 44_1_2]",
			test_setup, test_client, &str_src_ac4_44_1_2,
			STR_SRC_AC4_44_1_2);
	define_test("BAP/UCL/STR/BV-115-C [UCL, SRC, AC 1, LC3 44_2_2]",
			test_setup, test_client, &str_src_ac1_44_2_2,
			STR_SRC_AC1_44_2_2);
	define_test("BAP/UCL/STR/BV-116-C [UCL, SRC, AC 4, LC3 44_2_2]",
			test_setup, test_client, &str_src_ac4_44_2_2,
			STR_SRC_AC4_44_2_2);
	define_test("BAP/UCL/STR/BV-117-C [UCL, SRC, AC 1, LC3 48_1_2]",
			test_setup, test_client, &str_src_ac1_48_1_2,
			STR_SRC_AC1_48_1_2);
	define_test("BAP/UCL/STR/BV-118-C [UCL, SRC, AC 4, LC3 48_1_2]",
			test_setup, test_client, &str_src_ac4_48_1_2,
			STR_SRC_AC4_48_1_2);
	define_test("BAP/UCL/STR/BV-119-C [UCL, SRC, AC 1, LC3 48_2_2]",
			test_setup, test_client, &str_src_ac1_48_2_2,
			STR_SRC_AC1_48_2_2);
	define_test("BAP/UCL/STR/BV-120-C [UCL, SRC, AC 4, LC3 48_2_2]",
			test_setup, test_client, &str_src_ac4_48_2_2,
			STR_SRC_AC4_48_2_2);
	define_test("BAP/UCL/STR/BV-121-C [UCL, SRC, AC 1, LC3 48_3_2]",
			test_setup, test_client, &str_src_ac1_48_3_2,
			STR_SRC_AC1_48_3_2);
	define_test("BAP/UCL/STR/BV-122-C [UCL, SRC, AC 4, LC3 48_3_2]",
			test_setup, test_client, &str_src_ac4_48_3_2,
			STR_SRC_AC4_48_3_2);
	define_test("BAP/UCL/STR/BV-123-C [UCL, SRC, AC 1, LC3 48_4_2]",
			test_setup, test_client, &str_src_ac1_48_4_2,
			STR_SRC_AC1_48_4_2);
	define_test("BAP/UCL/STR/BV-124-C [UCL, SRC, AC 4, LC3 48_4_2]",
			test_setup, test_client, &str_src_ac4_48_4_2,
			STR_SRC_AC4_48_4_2);
	define_test("BAP/UCL/STR/BV-121-C [UCL, SRC, AC 1, LC3 48_5_2]",
			test_setup, test_client, &str_src_ac1_48_5_2,
			STR_SRC_AC1_48_5_2);
	define_test("BAP/UCL/STR/BV-122-C [UCL, SRC, AC 4, LC3 48_5_2]",
			test_setup, test_client, &str_src_ac4_48_5_2,
			STR_SRC_AC4_48_5_2);
	define_test("BAP/UCL/STR/BV-123-C [UCL AC 2, LC3 48_6_2]",
			test_setup, test_client, &str_src_ac1_48_6_2,
			STR_SRC_AC1_48_6_2);
	define_test("BAP/UCL/STR/BV-124-C [UCL AC 10, LC3 48_6_2]",
			test_setup, test_client, &str_src_ac4_48_6_2,
			STR_SRC_AC4_48_6_2);
}

/* Unicast Server Streaming – 1 Stream, 1 CIS – LC3
 *
 * Test Purpose:
 * Verify that a Unicast Server IUT can stream LC3-encoded audio data over one
 * unicast Audio Stream to/from a Unicast Client.
 *
 * Pass verdict:
 * If the IUT is in the Audio Source role, the IUT sends SDUs with a zero or
 * more length, using the LC3 Media Packet format (defined in [3] Section 4.2).
 * If the IUT is in the Audio Sink role, the IUT receives SDUs with a zero or
 * more length, using the LC3 Media Packet format (defined in [3] Section 4.2).
 */
static void test_usr_str_1_1_1_lc3(void)
{
	define_test("BAP/USR/STR/BV-001-C [USR, AC 2, LC3 8_1_1]",
			test_setup_server, test_server, &str_snk_ac2_8_1_1,
			STR_SNK_AC2_8_1_1);
	define_test("BAP/USR/STR/BV-002-C [USR, AC 10, LC3 8_1_1]",
			test_setup_server, test_server, &str_snk_ac10_8_1_1,
			STR_SNK_AC10_8_1_1);
	define_test("BAP/USR/STR/BV-003-C [USR, AC 2, LC3 8_2_1]",
			test_setup_server, test_server, &str_snk_ac2_8_2_1,
			STR_SNK_AC2_8_2_1);
	define_test("BAP/USR/STR/BV-004-C [USR, AC 10, LC3 8_2_1]",
			test_setup_server, test_server, &str_snk_ac10_8_2_1,
			STR_SNK_AC10_8_2_1);
	define_test("BAP/USR/STR/BV-005-C [USR, AC 2, LC3 16_1_1]",
			test_setup_server, test_server, &str_snk_ac2_16_1_1,
			STR_SNK_AC2_16_1_1);
	define_test("BAP/USR/STR/BV-006-C [USR, AC 10, LC3 16_1_1]",
			test_setup_server, test_server, &str_snk_ac10_16_1_1,
			STR_SNK_AC10_16_1_1);
	define_test("BAP/USR/STR/BV-007-C [USR, AC 2, LC3 16_2_1]",
			test_setup_server, test_server, &str_snk_ac2_16_2_1,
			STR_SNK_AC2_16_2_1);
	define_test("BAP/USR/STR/BV-008-C [USR, AC 10, LC3 16_2_1]",
			test_setup_server, test_server, &str_snk_ac10_16_2_1,
			STR_SNK_AC10_16_2_1);
	define_test("BAP/USR/STR/BV-009-C [USR, AC 2, LC3 24_1_1]",
			test_setup_server, test_server, &str_snk_ac2_24_1_1,
			STR_SNK_AC2_24_1_1);
	define_test("BAP/USR/STR/BV-010-C [USR, AC 10, LC3 24_1_1]",
			test_setup_server, test_server, &str_snk_ac10_24_1_1,
			STR_SNK_AC10_24_1_1);
	define_test("BAP/USR/STR/BV-011-C [USR, AC 2, LC3 24_2_1]",
			test_setup_server, test_server, &str_snk_ac2_24_2_1,
			STR_SNK_AC2_24_2_1);
	define_test("BAP/USR/STR/BV-012-C [USR, AC 10, LC3 24_2_1]",
			test_setup_server, test_server, &str_snk_ac10_24_2_1,
			STR_SNK_AC10_24_2_1);
	define_test("BAP/USR/STR/BV-013-C [USR, AC 2, LC3 32_1_1]",
			test_setup_server, test_server, &str_snk_ac2_32_1_1,
			STR_SNK_AC2_32_1_1);
	define_test("BAP/USR/STR/BV-014-C [USR, AC 10, LC3 32_1_1]",
			test_setup_server, test_server, &str_snk_ac10_32_1_1,
			STR_SNK_AC10_32_1_1);
	define_test("BAP/USR/STR/BV-015-C [USR, AC 2, LC3 32_2_1]",
			test_setup_server, test_server, &str_snk_ac2_32_2_1,
			STR_SNK_AC2_32_2_1);
	define_test("BAP/USR/STR/BV-016-C [USR, AC 10, LC3 32_2_1]",
			test_setup_server, test_server, &str_snk_ac10_32_2_1,
			STR_SNK_AC10_32_2_1);
	define_test("BAP/USR/STR/BV-017-C [USR, AC 1, LC3 441_1_1]",
			test_setup_server, test_server, &str_snk_ac2_44_1_1,
			STR_SNK_AC2_44_1_1);
	define_test("BAP/USR/STR/BV-018-C [USR, AC 4, LC3 441_1_1]",
			test_setup_server, test_server, &str_snk_ac10_44_1_1,
			STR_SNK_AC10_44_1_1);
	define_test("BAP/USR/STR/BV-019-C [USR, AC 1, LC3 44_2_1]",
			test_setup_server, test_server, &str_snk_ac2_44_2_1,
			STR_SNK_AC2_44_2_1);
	define_test("BAP/USR/STR/BV-020-C [USR, AC 4, LC3 44_2_1]",
			test_setup_server, test_server, &str_snk_ac10_44_2_1,
			STR_SNK_AC10_44_2_1);
	define_test("BAP/USR/STR/BV-021-C [USR, AC 1, LC3 48_1_1]",
			test_setup_server, test_server, &str_snk_ac2_48_1_1,
			STR_SNK_AC2_48_1_1);
	define_test("BAP/USR/STR/BV-022-C [USR, AC 4, LC3 48_1_1]",
			test_setup_server, test_server, &str_snk_ac10_48_1_1,
			STR_SNK_AC10_48_1_1);
	define_test("BAP/USR/STR/BV-023-C [USR, AC 1, LC3 48_2_1]",
			test_setup_server, test_server, &str_snk_ac2_48_2_1,
			STR_SNK_AC2_48_2_1);
	define_test("BAP/USR/STR/BV-024-C [USR, AC 4, LC3 48_2_1]",
			test_setup_server, test_server, &str_snk_ac10_48_2_1,
			STR_SNK_AC10_48_2_1);
	define_test("BAP/USR/STR/BV-025-C [USR, AC 1, LC3 48_3_1]",
			test_setup_server, test_server, &str_snk_ac2_48_3_1,
			STR_SNK_AC2_48_3_1);
	define_test("BAP/USR/STR/BV-026-C [USR, AC 4, LC3 48_3_1]",
			test_setup_server, test_server, &str_snk_ac10_48_3_1,
			STR_SNK_AC10_48_3_1);
	define_test("BAP/USR/STR/BV-027-C [USR, AC 1, LC3 48_4_1]",
			test_setup_server, test_server, &str_snk_ac2_48_4_1,
			STR_SNK_AC2_48_4_1);
	define_test("BAP/USR/STR/BV-028-C [USR, AC 4, LC3 48_4_1]",
			test_setup_server, test_server, &str_snk_ac10_48_4_1,
			STR_SNK_AC10_48_4_1);
	define_test("BAP/USR/STR/BV-029-C [USR, AC 1, LC3 48_5_1]",
			test_setup_server, test_server, &str_snk_ac2_48_5_1,
			STR_SNK_AC2_48_5_1);
	define_test("BAP/USR/STR/BV-030-C [USR, AC 4, LC3 48_5_1]",
			test_setup_server, test_server, &str_snk_ac10_48_5_1,
			STR_SNK_AC10_48_5_1);
	define_test("BAP/USR/STR/BV-031-C [USR, AC 1, LC3 48_6_1]",
			test_setup_server, test_server, &str_snk_ac2_48_6_1,
			STR_SNK_AC2_48_6_1);
	define_test("BAP/USR/STR/BV-032-C [USR, AC 4, LC3 48_6_1]",
			test_setup_server, test_server, &str_snk_ac10_48_6_1,
			STR_SNK_AC10_48_6_1);
	define_test("BAP/USR/STR/BV-033-C [USR AC 2, LC3 8_1_1]",
			test_setup_server, test_server, &str_src_ac1_8_1_1,
			STR_SRC_AC1_8_1_1);
	define_test("BAP/USR/STR/BV-034-C [USR AC 10, LC3 8_1_1]",
			test_setup_server, test_server, &str_src_ac4_8_1_1,
			STR_SRC_AC4_8_1_1);
	define_test("BAP/USR/STR/BV-035-C [USR AC 2, LC3 8_2_1]",
			test_setup_server, test_server, &str_src_ac1_8_2_1,
			STR_SRC_AC1_8_2_1);
	define_test("BAP/USR/STR/BV-036-C [USR AC 10, LC3 8_2_1]",
			test_setup_server, test_server, &str_src_ac4_8_2_1,
			STR_SRC_AC4_8_2_1);
	define_test("BAP/USR/STR/BV-037-C [USR AC 2, LC3 16_1_1]",
			test_setup_server, test_server, &str_src_ac1_16_1_1,
			STR_SRC_AC1_16_1_1);
	define_test("BAP/USR/STR/BV-038-C [USR AC 10, LC3 16_1_1]",
			test_setup_server, test_server, &str_src_ac4_16_1_1,
			STR_SRC_AC4_16_1_1);
	define_test("BAP/USR/STR/BV-039-C [USR AC 2, LC3 16_2_1]",
			test_setup_server, test_server, &str_src_ac1_16_2_1,
			STR_SRC_AC1_16_2_1);
	define_test("BAP/USR/STR/BV-040-C [USR AC 10, LC3 16_2_1]",
			test_setup_server, test_server, &str_src_ac4_16_2_1,
			STR_SRC_AC4_16_2_1);
	define_test("BAP/USR/STR/BV-041-C [USR AC 2, LC3 24_1_1]",
			test_setup_server, test_server, &str_src_ac1_24_1_1,
			STR_SRC_AC1_24_1_1);
	define_test("BAP/USR/STR/BV-042-C [USR AC 10, LC3 24_1_1]",
			test_setup_server, test_server, &str_src_ac4_24_1_1,
			STR_SRC_AC4_24_1_1);
	define_test("BAP/USR/STR/BV-043-C [USR AC 2, LC3 24_2_1]",
			test_setup_server, test_server, &str_src_ac1_24_2_1,
			STR_SRC_AC1_24_2_1);
	define_test("BAP/USR/STR/BV-044-C [USR AC 10, LC3 24_2_1]",
			test_setup_server, test_server, &str_src_ac4_24_2_1,
			STR_SRC_AC4_24_2_1);
	define_test("BAP/USR/STR/BV-045-C [USR AC 2, LC3 32_1_1]",
			test_setup_server, test_server, &str_src_ac1_32_1_1,
			STR_SRC_AC1_32_1_1);
	define_test("BAP/USR/STR/BV-046-C [USR AC 10, LC3 32_1_1]",
			test_setup_server, test_server, &str_src_ac4_32_1_1,
			STR_SRC_AC4_32_1_1);
	define_test("BAP/USR/STR/BV-047-C [USR AC 2, LC3 32_2_1]",
			test_setup_server, test_server, &str_src_ac1_32_2_1,
			STR_SRC_AC1_32_2_1);
	define_test("BAP/USR/STR/BV-048-C [USR AC 10, LC3 32_2_1]",
			test_setup_server, test_server, &str_src_ac4_32_2_1,
			STR_SRC_AC4_32_2_1);
	define_test("BAP/USR/STR/BV-049-C [USR AC 2, LC3 44_1_1]",
			test_setup_server, test_server, &str_src_ac1_44_1_1,
			STR_SRC_AC1_44_1_1);
	define_test("BAP/USR/STR/BV-050-C [USR AC 10, LC3 44_1_1]",
			test_setup_server, test_server, &str_src_ac4_44_1_1,
			STR_SRC_AC4_44_1_1);
	define_test("BAP/USR/STR/BV-051-C [USR AC 2, LC3 44_2_1]",
			test_setup_server, test_server, &str_src_ac1_44_2_1,
			STR_SRC_AC1_44_2_1);
	define_test("BAP/USR/STR/BV-052-C [USR AC 10, LC3 44_2_1]",
			test_setup_server, test_server, &str_src_ac4_44_2_1,
			STR_SRC_AC4_44_2_1);
	define_test("BAP/USR/STR/BV-053-C [USR AC 2, LC3 48_1_1]",
			test_setup_server, test_server, &str_src_ac1_48_1_1,
			STR_SRC_AC1_48_1_1);
	define_test("BAP/USR/STR/BV-054-C [USR AC 10, LC3 48_1_1]",
			test_setup_server, test_server, &str_src_ac4_48_1_1,
			STR_SRC_AC4_48_1_1);
	define_test("BAP/USR/STR/BV-055-C [USR AC 2, LC3 48_2_1]",
			test_setup_server, test_server, &str_src_ac1_48_2_1,
			STR_SRC_AC1_48_2_1);
	define_test("BAP/USR/STR/BV-056-C [USR AC 10, LC3 48_2_1]",
			test_setup_server, test_server, &str_src_ac4_48_2_1,
			STR_SRC_AC4_48_2_1);
	define_test("BAP/USR/STR/BV-057-C [USR AC 2, LC3 48_3_1]",
			test_setup_server, test_server, &str_src_ac1_48_3_1,
			STR_SRC_AC1_48_3_1);
	define_test("BAP/USR/STR/BV-058-C [USR AC 10, LC3 48_3_1]",
			test_setup_server, test_server, &str_src_ac4_48_3_1,
			STR_SRC_AC4_48_3_1);
	define_test("BAP/USR/STR/BV-059-C [USR AC 2, LC3 48_4_1]",
			test_setup_server, test_server, &str_src_ac1_48_4_1,
			STR_SRC_AC1_48_4_1);
	define_test("BAP/USR/STR/BV-060-C [USR AC 10, LC3 48_4_1]",
			test_setup_server, test_server, &str_src_ac4_48_4_1,
			STR_SRC_AC4_48_4_1);
	define_test("BAP/USR/STR/BV-061-C [USR AC 2, LC3 48_5_1]",
			test_setup_server, test_server, &str_src_ac1_48_5_1,
			STR_SRC_AC1_48_5_1);
	define_test("BAP/USR/STR/BV-062-C [USR AC 10, LC3 48_5_1]",
			test_setup_server, test_server, &str_src_ac4_48_5_1,
			STR_SRC_AC4_48_5_1);
	define_test("BAP/USR/STR/BV-063-C [USR AC 2, LC3 48_6_1]",
			test_setup_server, test_server, &str_src_ac1_48_6_1,
			STR_SRC_AC1_48_6_1);
	define_test("BAP/USR/STR/BV-064-C [USR AC 10, LC3 48_6_1]",
			test_setup_server, test_server, &str_src_ac4_48_6_1,
			STR_SRC_AC4_48_6_1);
	define_test("BAP/USR/STR/BV-065-C [USR, AC 1, LC3 8_1_2]",
			test_setup_server, test_server, &str_snk_ac2_8_1_2,
			STR_SNK_AC2_8_1_2);
	define_test("BAP/USR/STR/BV-066-C [USR, AC 4, LC3 8_1_2]",
			test_setup_server, test_server, &str_snk_ac10_8_1_2,
			STR_SNK_AC10_8_1_2);
	define_test("BAP/USR/STR/BV-067-C [USR, AC 1, LC3 8_2_2]",
			test_setup_server, test_server, &str_snk_ac2_8_2_2,
			STR_SNK_AC2_8_2_2);
	define_test("BAP/USR/STR/BV-068-C [USR, AC 4, LC3 8_2_2]",
			test_setup_server, test_server, &str_snk_ac10_8_2_2,
			STR_SNK_AC10_8_2_2);
	define_test("BAP/USR/STR/BV-069-C [USR, AC 1, LC3 16_1_2]",
			test_setup_server, test_server, &str_snk_ac2_16_1_2,
			STR_SNK_AC2_16_1_2);
	define_test("BAP/USR/STR/BV-070-C [USR, AC 4, LC3 16_1_2]",
			test_setup_server, test_server, &str_snk_ac10_16_1_2,
			STR_SNK_AC10_16_1_2);
	define_test("BAP/USR/STR/BV-071-C [USR, AC 1, LC3 16_2_2]",
			test_setup_server, test_server, &str_snk_ac2_16_2_2,
			STR_SNK_AC2_16_2_2);
	define_test("BAP/USR/STR/BV-072-C [USR, AC 4, LC3 16_2_2]",
			test_setup_server, test_server, &str_snk_ac10_16_2_2,
			STR_SNK_AC10_16_2_2);
	define_test("BAP/USR/STR/BV-073-C [USR, AC 1, LC3 24_1_2]",
			test_setup_server, test_server, &str_snk_ac2_24_1_2,
			STR_SNK_AC2_24_1_2);
	define_test("BAP/USR/STR/BV-074-C [USR, AC 4, LC3 24_1_2]",
			test_setup_server, test_server, &str_snk_ac10_24_1_2,
			STR_SNK_AC10_24_1_2);
	define_test("BAP/USR/STR/BV-075-C [USR, AC 1, LC3 24_2_2]",
			test_setup_server, test_server, &str_snk_ac2_24_2_2,
			STR_SNK_AC2_24_2_2);
	define_test("BAP/USR/STR/BV-076-C [USR, AC 4, LC3 24_2_2]",
			test_setup_server, test_server, &str_snk_ac10_24_2_2,
			STR_SNK_AC10_24_2_2);
	define_test("BAP/USR/STR/BV-077-C [USR, AC 1, LC3 32_1_2]",
			test_setup_server, test_server, &str_snk_ac2_32_1_2,
			STR_SNK_AC2_32_1_2);
	define_test("BAP/USR/STR/BV-078-C [USR, AC 4, LC3 32_1_2]",
			test_setup_server, test_server, &str_snk_ac10_32_1_2,
			STR_SNK_AC10_32_1_2);
	define_test("BAP/USR/STR/BV-079-C [USR, AC 1, LC3 32_2_2]",
			test_setup_server, test_server, &str_snk_ac2_32_2_2,
			STR_SNK_AC2_32_2_2);
	define_test("BAP/USR/STR/BV-080-C [USR, AC 4, LC3 32_2_2]",
			test_setup_server, test_server, &str_snk_ac10_32_2_2,
			STR_SNK_AC10_32_2_2);
	define_test("BAP/USR/STR/BV-081-C [USR, AC 1, LC3 44_1_2]",
			test_setup_server, test_server, &str_snk_ac2_44_1_2,
			STR_SNK_AC2_44_1_2);
	define_test("BAP/USR/STR/BV-082-C [USR, AC 4, LC3 44_1_2]",
			test_setup_server, test_server, &str_snk_ac10_44_1_2,
			STR_SNK_AC10_44_1_2);
	define_test("BAP/USR/STR/BV-083-C [USR, AC 1, LC3 44_2_2]",
			test_setup_server, test_server, &str_snk_ac2_44_2_2,
			STR_SNK_AC2_44_2_2);
	define_test("BAP/USR/STR/BV-084-C [USR, AC 4, LC3 44_2_2]",
			test_setup_server, test_server, &str_snk_ac10_44_2_2,
			STR_SNK_AC10_44_2_2);
	define_test("BAP/USR/STR/BV-085-C [USR, AC 1, LC3 48_1_2]",
			test_setup_server, test_server, &str_snk_ac2_48_1_2,
			STR_SNK_AC2_48_1_2);
	define_test("BAP/USR/STR/BV-086-C [USR, AC 4, LC3 48_1_2]",
			test_setup_server, test_server, &str_snk_ac10_48_1_2,
			STR_SNK_AC10_48_1_2);
	define_test("BAP/USR/STR/BV-087-C [USR, AC 1, LC3 48_2_2]",
			test_setup_server, test_server, &str_snk_ac2_48_2_2,
			STR_SNK_AC2_48_2_2);
	define_test("BAP/USR/STR/BV-088-C [USR, AC 4, LC3 48_2_2]",
			test_setup_server, test_server, &str_snk_ac10_48_2_2,
			STR_SNK_AC10_48_2_2);
	define_test("BAP/USR/STR/BV-089-C [USR, AC 1, LC3 48_3_2]",
			test_setup_server, test_server, &str_snk_ac2_48_3_2,
			STR_SNK_AC2_48_3_2);
	define_test("BAP/USR/STR/BV-090-C [USR, AC 4, LC3 48_3_2]",
			test_setup_server, test_server, &str_snk_ac10_48_3_2,
			STR_SNK_AC10_48_3_2);
	define_test("BAP/USR/STR/BV-091-C [USR, AC 1, LC3 48_4_2]",
			test_setup_server, test_server, &str_snk_ac2_48_4_2,
			STR_SNK_AC2_48_4_2);
	define_test("BAP/USR/STR/BV-092-C [USR, AC 4, LC3 48_4_2]",
			test_setup_server, test_server, &str_snk_ac10_48_4_2,
			STR_SNK_AC10_48_4_2);
	define_test("BAP/USR/STR/BV-093-C [USR, AC 1, LC3 48_5_2]",
			test_setup_server, test_server, &str_snk_ac2_48_5_2,
			STR_SNK_AC2_48_5_2);
	define_test("BAP/USR/STR/BV-094-C [USR, AC 4, LC3 48_5_2]",
			test_setup_server, test_server, &str_snk_ac10_48_5_2,
			STR_SNK_AC10_48_5_2);
	define_test("BAP/USR/STR/BV-095-C [USR, AC 1, LC3 48_6_2]",
			test_setup_server, test_server, &str_snk_ac2_48_6_2,
			STR_SNK_AC2_48_6_2);
	define_test("BAP/USR/STR/BV-096-C [USR, AC 4, LC3 48_6_2]",
			test_setup_server, test_server, &str_snk_ac10_48_6_2,
			STR_SNK_AC10_48_6_2);
	define_test("BAP/USR/STR/BV-097-C [USR AC 2, LC3 8_1_2]",
			test_setup_server, test_server, &str_src_ac1_8_1_2,
			STR_SRC_AC1_8_1_2);
	define_test("BAP/USR/STR/BV-098-C [USR AC 10, LC3 8_1_2]",
			test_setup_server, test_server, &str_src_ac4_8_1_2,
			STR_SRC_AC4_8_1_2);
	define_test("BAP/USR/STR/BV-099-C [USR AC 2, LC3 8_2_2]",
			test_setup_server, test_server, &str_src_ac1_8_2_2,
			STR_SRC_AC1_8_2_2);
	define_test("BAP/USR/STR/BV-100-C [USR AC 10, LC3 8_2_2]",
			test_setup_server, test_server, &str_src_ac4_8_2_2,
			STR_SRC_AC4_8_2_2);
	define_test("BAP/USR/STR/BV-101-C [USR AC 2, LC3 16_1_2]",
			test_setup_server, test_server, &str_src_ac1_16_1_2,
			STR_SRC_AC1_16_1_2);
	define_test("BAP/USR/STR/BV-102-C [USR AC 10, LC3 16_1_2]",
			test_setup_server, test_server, &str_src_ac4_16_1_2,
			STR_SRC_AC4_16_1_2);
	define_test("BAP/USR/STR/BV-103-C [USR AC 2, LC3 16_2_2]",
			test_setup_server, test_server, &str_src_ac1_16_2_2,
			STR_SRC_AC1_16_2_2);
	define_test("BAP/USR/STR/BV-104-C [USR AC 10, LC3 16_2_2]",
			test_setup_server, test_server, &str_src_ac4_16_2_2,
			STR_SRC_AC4_16_2_2);
	define_test("BAP/USR/STR/BV-105-C [USR AC 2, LC3 24_1_2]",
			test_setup_server, test_server, &str_src_ac1_24_1_2,
			STR_SRC_AC1_24_1_2);
	define_test("BAP/USR/STR/BV-106-C [USR AC 10, LC3 24_1_2]",
			test_setup_server, test_server, &str_src_ac4_24_1_2,
			STR_SRC_AC4_24_1_2);
	define_test("BAP/USR/STR/BV-107-C [USR AC 2, LC3 24_2_2]",
			test_setup_server, test_server, &str_src_ac1_24_2_2,
			STR_SRC_AC1_24_2_2);
	define_test("BAP/USR/STR/BV-108-C [USR AC 10, LC3 24_2_2]",
			test_setup_server, test_server, &str_src_ac4_24_2_2,
			STR_SRC_AC4_24_2_2);
	define_test("BAP/USR/STR/BV-109-C [USR AC 2, LC3 32_1_2]",
			test_setup_server, test_server, &str_src_ac1_32_1_2,
			STR_SRC_AC1_32_1_2);
	define_test("BAP/USR/STR/BV-110-C [USR AC 10, LC3 32_1_2]",
			test_setup_server, test_server, &str_src_ac4_32_1_2,
			STR_SRC_AC4_32_1_2);
	define_test("BAP/USR/STR/BV-111-C [USR AC 2, LC3 32_2_2]",
			test_setup_server, test_server, &str_src_ac1_32_2_2,
			STR_SRC_AC1_32_2_2);
	define_test("BAP/USR/STR/BV-112-C [USR AC 10, LC3 32_2_2]",
			test_setup_server, test_server, &str_src_ac4_32_2_2,
			STR_SRC_AC4_32_2_2);
	define_test("BAP/USR/STR/BV-113-C [USR AC 2, LC3 44_1_2]",
			test_setup_server, test_server, &str_src_ac1_44_1_2,
			STR_SRC_AC1_44_1_2);
	define_test("BAP/USR/STR/BV-114-C [USR AC 10, LC3 44_1_2]",
			test_setup_server, test_server, &str_src_ac4_44_1_2,
			STR_SRC_AC4_44_1_2);
	define_test("BAP/USR/STR/BV-115-C [USR AC 2, LC3 44_2_2]",
			test_setup_server, test_server, &str_src_ac1_44_2_2,
			STR_SRC_AC1_44_2_2);
	define_test("BAP/USR/STR/BV-116-C [USR AC 10, LC3 44_2_2]",
			test_setup_server, test_server, &str_src_ac4_44_2_2,
			STR_SRC_AC4_44_2_2);
	define_test("BAP/USR/STR/BV-117-C [USR AC 2, LC3 48_1_2]",
			test_setup_server, test_server, &str_src_ac1_48_1_2,
			STR_SRC_AC1_48_1_2);
	define_test("BAP/USR/STR/BV-118-C [USR AC 10, LC3 48_1_2]",
			test_setup_server, test_server, &str_src_ac4_48_1_2,
			STR_SRC_AC4_48_1_2);
	define_test("BAP/USR/STR/BV-119-C [USR AC 2, LC3 48_2_2]",
			test_setup_server, test_server, &str_src_ac1_48_2_2,
			STR_SRC_AC1_48_2_2);
	define_test("BAP/USR/STR/BV-120-C [USR AC 10, LC3 48_2_2]",
			test_setup_server, test_server, &str_src_ac4_48_2_2,
			STR_SRC_AC4_48_2_2);
	define_test("BAP/USR/STR/BV-121-C [USR AC 2 LC3 48_3_2]",
			test_setup_server, test_server, &str_src_ac1_48_3_2,
			STR_SRC_AC1_48_3_2);
	define_test("BAP/USR/STR/BV-122-C [USR AC 10, LC3 48_3_2]",
			test_setup_server, test_server, &str_src_ac4_48_3_2,
			STR_SRC_AC4_48_3_2);
	define_test("BAP/USR/STR/BV-123-C [USR AC 2 LC3 48_4_2]",
			test_setup_server, test_server, &str_src_ac1_48_4_2,
			STR_SRC_AC1_48_4_2);
	define_test("BAP/USR/STR/BV-124-C [USR AC 10, LC3 48_4_2]",
			test_setup_server, test_server, &str_src_ac4_48_4_2,
			STR_SRC_AC4_48_4_2);
	define_test("BAP/USR/STR/BV-121-C [USR AC 2 LC3 48_5_2]",
			test_setup_server, test_server, &str_src_ac1_48_5_2,
			STR_SRC_AC1_48_5_2);
	define_test("BAP/USR/STR/BV-122-C [USR AC 10, LC3 48_5_2]",
			test_setup_server, test_server, &str_src_ac4_48_5_2,
			STR_SRC_AC4_48_5_2);
	define_test("BAP/USR/STR/BV-123-C [USR AC 2 LC3 48_6_2]",
			test_setup_server, test_server, &str_src_ac1_48_6_2,
			STR_SRC_AC1_48_6_2);
	define_test("BAP/USR/STR/BV-124-C [USR AC 10, LC3 48_6_2]",
			test_setup_server, test_server, &str_src_ac4_48_6_2,
			STR_SRC_AC4_48_6_2);
}

static void test_str_1_1_1_lc3(void)
{
	test_ucl_str_1_1_1_lc3();
	test_usr_str_1_1_1_lc3();
}

static void test_scc(void)
{
	test_scc_cc_lc3();
	test_scc_cc_vs();
	test_scc_qos_lc3();
	test_scc_qos_vs();
	test_scc_enable();
	test_scc_disable();
	test_scc_release();
	test_scc_metadata();
	test_str_1_1_1_lc3();
}

static struct test_config cfg_bsrc_8_1_1 = {
	.cc = LC3_CONFIG_8_1,
	.qos = LC3_QOS_8_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_8_1),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_8_1_2 = {
	.cc = LC3_CONFIG_8_1,
	.qos = LC3_QOS_8_1_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_8_1),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_8_2_1 = {
	.cc = LC3_CONFIG_8_2,
	.qos = LC3_QOS_8_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_8_2),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_8_2_2 = {
	.cc = LC3_CONFIG_8_2,
	.qos = LC3_QOS_8_2_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_8_2),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_16_1_1 = {
	.cc = LC3_CONFIG_16_1,
	.qos = LC3_QOS_16_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_16_1),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_16_1_2 = {
	.cc = LC3_CONFIG_16_1,
	.qos = LC3_QOS_16_1_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_16_1),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_16_2_1 = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_16_2),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_16_2_2 = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_16_2),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_24_1_1 = {
	.cc = LC3_CONFIG_24_1,
	.qos = LC3_QOS_24_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_24_1),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_24_1_2 = {
	.cc = LC3_CONFIG_24_1,
	.qos = LC3_QOS_24_1_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_24_1),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_24_2_1 = {
	.cc = LC3_CONFIG_24_2,
	.qos = LC3_QOS_24_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_24_2),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_24_2_2 = {
	.cc = LC3_CONFIG_24_2,
	.qos = LC3_QOS_24_2_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_24_2),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_32_1_1 = {
	.cc = LC3_CONFIG_32_1,
	.qos = LC3_QOS_32_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_32_1),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_32_1_2 = {
	.cc = LC3_CONFIG_32_1,
	.qos = LC3_QOS_32_1_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_32_1),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_32_2_1 = {
	.cc = LC3_CONFIG_32_2,
	.qos = LC3_QOS_32_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_32_2),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_32_2_2 = {
	.cc = LC3_CONFIG_32_2,
	.qos = LC3_QOS_32_2_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_32_2),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_44_1_1 = {
	.cc = LC3_CONFIG_44_1,
	.qos = LC3_QOS_44_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_44_1),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_44_1_2 = {
	.cc = LC3_CONFIG_44_1,
	.qos = LC3_QOS_44_1_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_44_1),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_44_2_1 = {
	.cc = LC3_CONFIG_44_2,
	.qos = LC3_QOS_44_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_44_2),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_44_2_2 = {
	.cc = LC3_CONFIG_44_2,
	.qos = LC3_QOS_44_2_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_44_2),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_48_1_1 = {
	.cc = LC3_CONFIG_48_1,
	.qos = LC3_QOS_48_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_1),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_48_1_2 = {
	.cc = LC3_CONFIG_48_1,
	.qos = LC3_QOS_48_1_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_1),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_48_2_1 = {
	.cc = LC3_CONFIG_48_2,
	.qos = LC3_QOS_48_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_2),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_48_2_2 = {
	.cc = LC3_CONFIG_48_2,
	.qos = LC3_QOS_48_2_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_2),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_48_3_1 = {
	.cc = LC3_CONFIG_48_3,
	.qos = LC3_QOS_48_3_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_3),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_48_3_2 = {
	.cc = LC3_CONFIG_48_3,
	.qos = LC3_QOS_48_3_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_3),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_48_4_1 = {
	.cc = LC3_CONFIG_48_4,
	.qos = LC3_QOS_48_4_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_4),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_48_4_2 = {
	.cc = LC3_CONFIG_48_4,
	.qos = LC3_QOS_48_4_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_4),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_48_5_1 = {
	.cc = LC3_CONFIG_48_5,
	.qos = LC3_QOS_48_5_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_5),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_48_5_2 = {
	.cc = LC3_CONFIG_48_5,
	.qos = LC3_QOS_48_5_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_5),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_48_6_1 = {
	.cc = LC3_CONFIG_48_6,
	.qos = LC3_QOS_48_6_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_6),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

static struct test_config cfg_bsrc_48_6_2 = {
	.cc = LC3_CONFIG_48_6,
	.qos = LC3_QOS_48_6_2_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_6),
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

#define VS_CC \
	0x02, 0x01, 0x08, \
	0x02, 0x02, 0x00, \
	0x05, 0x03, 0x01, 0x00, 0x00, 0x00, \
	0x03, 0x04, 0x75, 0x00

#define VS_CFG \
	0x10, \
	VS_CC

#define QOS_BCAST \
{ \
	.bcast.big = 0x00, \
	.bcast.bis = 0x00, \
	.bcast.framing = LC3_QOS_UNFRAMED, \
	.bcast.delay = 40000, \
	.bcast.io_qos.interval = 7500, \
	.bcast.io_qos.latency = 10, \
	.bcast.io_qos.sdu = 40, \
	.bcast.io_qos.phy = BT_BAP_CONFIG_PHY_2M, \
	.bcast.io_qos.rtn = 2, \
}

static struct test_config cfg_bsrc_vs = {
	.cc = UTIL_IOV_INIT(VS_CC),
	.qos = QOS_BCAST,
	.base = UTIL_IOV_INIT(BASE_VS(VS_CFG)),
	.vs = true,
	.src = true,
	.state_func = bsrc_state_cfg,
	.streams = 1,
};

/* Test Purpose:
 * Verify that a Broadcast Source IUT can configure a broadcast
 * Audio Stream with information defined by the values in its BASE
 * structure. The verification is performed one Codec Setting and
 * set of parameters at a time, as enumerated in the test cases in
 * Table 4.73.
 *
 * Pass verdict:
 * In step 2, the AdvData field of AUX_SYNC_IND and optionally
 * AUX_CHAIN_IND PDUs contains the configured BASE information.
 *
 * In step 3, the IUT transmits the PA synchronization information in
 * the SyncInfo field of the Extended Header field of AUX_ADV_IND PDUs.
 * The AUX_ADV_IND PDUs include the Service Data AD Type in the AdvData
 * field with the Service UUID equal to the Broadcast Audio Announcement
 * Service UUID. The additional service data includes Broadcast_ID.
 *
 * Each value included in the Codec_Specific_Configuration is formatted in
 * an LTV structure with the length, type, and value specified in Table 4.74.
 */
static void test_bsrc_scc_config(void)
{
	define_test("BAP/BSRC/SCC/BV-01-C [Config Broadcast, LC3 8_1_1]",
		NULL, test_bcast, &cfg_bsrc_8_1_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-02-C [Config Broadcast, LC3 8_2_1]",
		NULL, test_bcast, &cfg_bsrc_8_2_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-03-C [Config Broadcast, LC3 16_1_1]",
		NULL, test_bcast, &cfg_bsrc_16_1_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-04-C [Config Broadcast, LC3 16_2_1]",
		NULL, test_bcast, &cfg_bsrc_16_2_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-05-C [Config Broadcast, LC3 24_1_1]",
		NULL, test_bcast, &cfg_bsrc_24_1_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-06-C [Config Broadcast, LC3 24_2_1]",
		NULL, test_bcast, &cfg_bsrc_24_2_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-07-C [Config Broadcast, LC3 32_1_1]",
		NULL, test_bcast, &cfg_bsrc_32_1_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-08-C [Config Broadcast, LC3 32_2_1]",
		NULL, test_bcast, &cfg_bsrc_32_2_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-09-C [Config Broadcast, LC3 44.1_1_1]",
		NULL, test_bcast, &cfg_bsrc_44_1_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-10-C [Config Broadcast, LC3 44.1_2_1]",
		NULL, test_bcast, &cfg_bsrc_44_2_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-11-C [Config Broadcast, LC3 48_1_1]",
		NULL, test_bcast, &cfg_bsrc_48_1_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-12-C [Config Broadcast, LC3 48_2_1]",
		NULL, test_bcast, &cfg_bsrc_48_2_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-13-C [Config Broadcast, LC3 48_3_1]",
		NULL, test_bcast, &cfg_bsrc_48_3_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-14-C [Config Broadcast, LC3 48_4_1]",
		NULL, test_bcast, &cfg_bsrc_48_4_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-15-C [Config Broadcast, LC3 48_5_1]",
		NULL, test_bcast, &cfg_bsrc_48_5_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-16-C [Config Broadcast, LC3 48_6_1]",
		NULL, test_bcast, &cfg_bsrc_48_6_1, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-17-C [Config Broadcast, LC3 8_1_2]",
		NULL, test_bcast, &cfg_bsrc_8_1_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-18-C [Config Broadcast, LC3 8_2_2]",
		NULL, test_bcast, &cfg_bsrc_8_2_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-19-C [Config Broadcast, LC3 16_1_2]",
		NULL, test_bcast, &cfg_bsrc_16_1_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-20-C [Config Broadcast, LC3 16_2_2]",
		NULL, test_bcast, &cfg_bsrc_16_2_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-21-C [Config Broadcast, LC3 24_1_2]",
		NULL, test_bcast, &cfg_bsrc_24_1_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-22-C [Config Broadcast, LC3 24_2_2]",
		NULL, test_bcast, &cfg_bsrc_24_2_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-23-C [Config Broadcast, LC3 32_1_2]",
		NULL, test_bcast, &cfg_bsrc_32_1_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-24-C [Config Broadcast, LC3 32_2_2]",
		NULL, test_bcast, &cfg_bsrc_32_2_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-25-C [Config Broadcast, LC3 44.1_1_2]",
		NULL, test_bcast, &cfg_bsrc_44_1_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-26-C [Config Broadcast, LC3 44.1_2_2]",
		NULL, test_bcast, &cfg_bsrc_44_2_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-27-C [Config Broadcast, LC3 48_1_2]",
		NULL, test_bcast, &cfg_bsrc_48_1_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-28-C [Config Broadcast, LC3 48_2_2]",
		NULL, test_bcast, &cfg_bsrc_48_2_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-29-C [Config Broadcast, LC3 48_3_2]",
		NULL, test_bcast, &cfg_bsrc_48_3_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-30-C [Config Broadcast, LC3 48_4_2]",
		NULL, test_bcast, &cfg_bsrc_48_4_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-31-C [Config Broadcast, LC3 48_5_2]",
		NULL, test_bcast, &cfg_bsrc_48_5_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-32-C [Config Broadcast, LC3 48_6_2]",
		NULL, test_bcast, &cfg_bsrc_48_6_2, IOV_NULL);

	define_test("BAP/BSRC/SCC/BV-33-C [Config Broadcast, VS]",
		NULL, test_bcast, &cfg_bsrc_vs, IOV_NULL);
}

static void bsrc_state_estab(struct bt_bap_stream *stream, uint8_t old_state,
				uint8_t new_state, void *user_data)
{
	switch (new_state) {
	case BT_BAP_STREAM_STATE_CONFIG:
		bt_bap_stream_enable(stream, true, NULL, NULL, NULL);
		break;
	case BT_BAP_STREAM_STATE_ENABLING:
		bt_bap_stream_start(stream, NULL, NULL);
		break;
	case BT_BAP_STREAM_STATE_STREAMING:
		tester_test_passed();
		break;
	}
}

static struct test_config cfg_bsrc_8_1_1_estab = {
	.cc = LC3_CONFIG_8_1,
	.qos = LC3_QOS_8_1_1_B,
	.src = true,
	.state_func = bsrc_state_estab,
	.streams = 1,
};

/* Test Purpose:
 * Verify that a Broadcast Source IUT can establish a broadcast
 * Audio Stream.
 *
 * Pass verdict:
 * The IUT sends AUX_SYNC_IND PDUs with an Extended Header
 * containing BIGInfo in the ACAD field. The IUT sends BIS Data
 * PDUs over the broadcast Audio Stream.
 */
static void test_bsrc_scc_estab(void)
{
	define_test("BAP/BSRC/SCC/BV-35-C [Establishes Broadcast]",
		NULL, test_bcast, &cfg_bsrc_8_1_1_estab, IOV_NULL);
}

static void bsrc_state_disable(struct bt_bap_stream *stream, uint8_t old_state,
				uint8_t new_state, void *user_data)
{
	switch (new_state) {
	case BT_BAP_STREAM_STATE_CONFIG:
		if (old_state == BT_BAP_STREAM_STATE_IDLE)
			bt_bap_stream_enable(stream, true, NULL, NULL, NULL);
		else if (old_state == BT_BAP_STREAM_STATE_STREAMING)
			tester_test_passed();
		else
			/* Other transitions to CONFIG state are invalid. */
			tester_test_failed();
		break;
	case BT_BAP_STREAM_STATE_ENABLING:
		bt_bap_stream_start(stream, NULL, NULL);
		break;
	case BT_BAP_STREAM_STATE_STREAMING:
		bt_bap_stream_disable(stream, true, NULL, NULL);
		break;
	}
}

static struct test_config cfg_bsrc_8_1_1_disable = {
	.cc = LC3_CONFIG_8_1,
	.qos = LC3_QOS_8_1_1_B,
	.src = true,
	.state_func = bsrc_state_disable,
	.streams = 1,
};

/* Test Purpose:
 * Verify that a Broadcast Source IUT can disable a broadcast
 * Audio Stream.
 *
 * Pass verdict:
 * The IUT sends a BIG_TERMINATE_IND PDU in step 1.
 */
static void test_bsrc_scc_disable(void)
{
	define_test("BAP/BSRC/SCC/BV-36-C [Disables Broadcast]",
		NULL, test_bcast, &cfg_bsrc_8_1_1_disable, IOV_NULL);
}

static void bsrc_state_release(struct bt_bap_stream *stream, uint8_t old_state,
				uint8_t new_state, void *user_data)
{
	switch (new_state) {
	case BT_BAP_STREAM_STATE_CONFIG:
		if (old_state == BT_BAP_STREAM_STATE_IDLE)
			bt_bap_stream_enable(stream, true, NULL, NULL, NULL);
		else if (old_state == BT_BAP_STREAM_STATE_STREAMING)
			bt_bap_stream_release(stream, NULL, NULL);
		else
			/* Other transitions to CONFIG state are invalid. */
			tester_test_failed();
		break;
	case BT_BAP_STREAM_STATE_ENABLING:
		bt_bap_stream_start(stream, NULL, NULL);
		break;
	case BT_BAP_STREAM_STATE_STREAMING:
		bt_bap_stream_disable(stream, true, NULL, NULL);
		break;
	case BT_BAP_STREAM_STATE_IDLE:
		tester_test_passed();
		break;
	}
}

static struct test_config cfg_bsrc_8_1_1_release = {
	.cc = LC3_CONFIG_8_1,
	.qos = LC3_QOS_8_1_1_B,
	.src = true,
	.state_func = bsrc_state_release,
	.streams = 1,
};

/* Test Purpose:
 * Verify that a Broadcast Source IUT can release a broadcast
 * Audio Stream and transition from Configured state to Idle
 * state.
 *
 * Pass verdict:
 * The IUT stops transmitting periodic advertising.
 */
static void test_bsrc_scc_release(void)
{
	define_test("BAP/BSRC/SCC/BV-37-C [Releases Broadcast]",
		NULL, test_bcast, &cfg_bsrc_8_1_1_release, IOV_NULL);
}

static void test_bsrc_scc(void)
{
	test_bsrc_scc_config();
	test_bsrc_scc_estab();
	test_bsrc_scc_disable();
	test_bsrc_scc_release();
}

static struct test_config cfg_bsnk_8_1 = {
	.cc = LC3_CONFIG_8_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_8_2 = {
	.cc = LC3_CONFIG_8_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_16_1 = {
	.cc = LC3_CONFIG_16_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_16_2 = {
	.cc = LC3_CONFIG_16_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_24_1 = {
	.cc = LC3_CONFIG_24_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_24_2 = {
	.cc = LC3_CONFIG_24_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_32_1 = {
	.cc = LC3_CONFIG_32_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_32_2 = {
	.cc = LC3_CONFIG_32_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_44_1 = {
	.cc = LC3_CONFIG_44_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_44_2 = {
	.cc = LC3_CONFIG_44_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_48_1 = {
	.cc = LC3_CONFIG_48_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_48_2 = {
	.cc = LC3_CONFIG_48_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_48_3 = {
	.cc = LC3_CONFIG_48_3,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_48_4 = {
	.cc = LC3_CONFIG_48_4,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_48_5 = {
	.cc = LC3_CONFIG_48_5,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_48_6 = {
	.cc = LC3_CONFIG_48_6,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static struct test_config cfg_bsnk_vs = {
	.cc = UTIL_IOV_INIT(VS_CC),
	.qos = QOS_BCAST,
	.snk = true,
	.vs = true,
	.state_func = bsnk_state,
	.streams = 1,
};

static void test_bsnk_scc(void)
{
	define_test("BAP/BSNK/SCC/BV-01-C [Sync to PA, LC3 8_1_1]",
		NULL, test_bcast, &cfg_bsnk_8_1, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-02-C [Sync to PA, LC3 8_2_1]",
		NULL, test_bcast, &cfg_bsnk_8_2, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-03-C [Sync to PA, LC3 16_1_1]",
		NULL, test_bcast, &cfg_bsnk_16_1, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-04-C [Sync to PA, LC3 16_2_1]",
		NULL, test_bcast, &cfg_bsnk_16_2, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-05-C [Sync to PA, LC3 24_1_1]",
		NULL, test_bcast, &cfg_bsnk_24_1, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-06-C [Sync to PA, LC3 24_2_1]",
		NULL, test_bcast, &cfg_bsnk_24_2, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-07-C [Sync to PA, LC3 32_1_1]",
		NULL, test_bcast, &cfg_bsnk_32_1, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-08-C [Sync to PA, LC3 32_2_1]",
		NULL, test_bcast, &cfg_bsnk_32_2, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-09-C [Sync to PA, LC3 44.1_1_1]",
		NULL, test_bcast, &cfg_bsnk_44_1, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-10-C [Sync to PA, LC3 44.1_2_1]",
		NULL, test_bcast, &cfg_bsnk_44_2, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-11-C [Sync to PA, LC3 48_1_1]",
		NULL, test_bcast, &cfg_bsnk_48_1, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-12-C [Sync to PA, LC3 48_2_1]",
		NULL, test_bcast, &cfg_bsnk_48_2, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-13-C [Sync to PA, LC3 48_3_1]",
		NULL, test_bcast, &cfg_bsnk_48_3, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-14-C [Sync to PA, LC3 48_4_1]",
		NULL, test_bcast, &cfg_bsnk_48_4, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-15-C [Sync to PA, LC3 48_5_1]",
		NULL, test_bcast, &cfg_bsnk_48_5, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-16-C [Sync to PA, LC3 48_6_1]",
		NULL, test_bcast, &cfg_bsnk_48_6, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-17-C [Sync to PA, LC3 8_1_2]",
		NULL, test_bcast, &cfg_bsnk_8_1, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-18-C [Sync to PA, LC3 8_2_2]",
		NULL, test_bcast, &cfg_bsnk_8_2, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-19-C [Sync to PA, LC3 16_1_2]",
		NULL, test_bcast, &cfg_bsnk_16_1, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-20-C [Sync to PA, LC3 16_2_2]",
		NULL, test_bcast, &cfg_bsnk_16_2, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-21-C [Sync to PA, LC3 24_1_2]",
		NULL, test_bcast, &cfg_bsnk_24_1, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-22-C [Sync to PA, LC3 24_2_2]",
		NULL, test_bcast, &cfg_bsnk_24_2, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-23-C [Sync to PA, LC3 32_1_2]",
		NULL, test_bcast, &cfg_bsnk_32_1, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-24-C [Sync to PA, LC3 32_2_2]",
		NULL, test_bcast, &cfg_bsnk_32_2, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-25-C [Sync to PA, LC3 44.1_1_2]",
		NULL, test_bcast, &cfg_bsnk_44_1, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-26-C [Sync to PA, LC3 44.1_2_2]",
		NULL, test_bcast, &cfg_bsnk_44_2, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-27-C [Sync to PA, LC3 48_1_2]",
		NULL, test_bcast, &cfg_bsnk_48_1, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-28-C [Sync to PA, LC3 48_2_2]",
		NULL, test_bcast, &cfg_bsnk_48_2, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-29-C [Sync to PA, LC3 48_3_2]",
		NULL, test_bcast, &cfg_bsnk_48_3, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-30-C [Sync to PA, LC3 48_4_2]",
		NULL, test_bcast, &cfg_bsnk_48_4, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-31-C [Sync to PA, LC3 48_5_2]",
		NULL, test_bcast, &cfg_bsnk_48_5, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-32-C [Sync to PA, LC3 48_6_2]",
		NULL, test_bcast, &cfg_bsnk_48_6, IOV_NULL);

	define_test("BAP/BSNK/SCC/BV-33-C [Sync to PA, VS]",
		NULL, test_bcast, &cfg_bsnk_vs, IOV_NULL);
}

static void stream_count_streaming(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	uint8_t *num = user_data;

	if (bt_bap_stream_get_state(stream) == BT_BAP_STREAM_STATE_STREAMING)
		(*num)++;
}

static void bsnk_state_str(struct bt_bap_stream *stream, uint8_t old_state,
				uint8_t new_state, void *user_data)
{
	struct test_data *data = user_data;
	struct iovec *cc;
	uint8_t num = 0;

	switch (new_state) {
	case BT_BAP_STREAM_STATE_CONFIG:
		if (old_state == BT_BAP_STREAM_STATE_IDLE) {
			/* Check that stream has been configured as expected */
			cc = bt_bap_stream_get_config(stream);

			g_assert(cc);
			g_assert(cc->iov_len == data->cfg->cc.iov_len);
			g_assert(memcmp(cc->iov_base, data->cfg->cc.iov_base,
					cc->iov_len) == 0);

			/* Enable stream */
			bt_bap_stream_enable(stream, true, NULL, NULL, NULL);
		} else {
			/* Other state transitions are invalid */
			tester_test_failed();
		}

		break;
	case BT_BAP_STREAM_STATE_ENABLING:
		/* Start stream */
		bt_bap_stream_start(stream, NULL, NULL);
		break;
	case BT_BAP_STREAM_STATE_STREAMING:
		queue_foreach(data->streams, stream_count_streaming, &num);

		if (num == data->cfg->streams)
			/* Test is completed after all streams have transitioned
			 * to STREAMING state.
			 */
			tester_test_passed();

		break;
	}
}

static struct test_config cfg_bsnk_str_8_1 = {
	.cc = LC3_CONFIG_8_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_8_2 = {
	.cc = LC3_CONFIG_8_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_16_1 = {
	.cc = LC3_CONFIG_16_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_16_2 = {
	.cc = LC3_CONFIG_16_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_24_1 = {
	.cc = LC3_CONFIG_24_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_24_2 = {
	.cc = LC3_CONFIG_24_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_32_1 = {
	.cc = LC3_CONFIG_32_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_32_2 = {
	.cc = LC3_CONFIG_32_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_44_1 = {
	.cc = LC3_CONFIG_44_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_44_2 = {
	.cc = LC3_CONFIG_44_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_48_1 = {
	.cc = LC3_CONFIG_48_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_48_2 = {
	.cc = LC3_CONFIG_48_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_48_3 = {
	.cc = LC3_CONFIG_48_3,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_48_4 = {
	.cc = LC3_CONFIG_48_4,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_48_5 = {
	.cc = LC3_CONFIG_48_5,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_48_6 = {
	.cc = LC3_CONFIG_48_6,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_vs = {
	.cc = UTIL_IOV_INIT(VS_CC),
	.qos = QOS_BCAST,
	.snk = true,
	.vs = true,
	.state_func = bsnk_state_str,
	.streams = 1,
};

static struct test_config cfg_bsnk_str_8_1_mbis = {
	.cc = LC3_CONFIG_8_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_8_2_mbis = {
	.cc = LC3_CONFIG_8_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_16_1_mbis = {
	.cc = LC3_CONFIG_16_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_16_2_mbis = {
	.cc = LC3_CONFIG_16_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_24_1_mbis = {
	.cc = LC3_CONFIG_24_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_24_2_mbis = {
	.cc = LC3_CONFIG_24_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_32_1_mbis = {
	.cc = LC3_CONFIG_32_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_32_2_mbis = {
	.cc = LC3_CONFIG_32_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_44_1_mbis = {
	.cc = LC3_CONFIG_44_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_44_2_mbis = {
	.cc = LC3_CONFIG_44_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_48_1_mbis = {
	.cc = LC3_CONFIG_48_1,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_48_2_mbis = {
	.cc = LC3_CONFIG_48_2,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_48_3_mbis = {
	.cc = LC3_CONFIG_48_3,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_48_4_mbis = {
	.cc = LC3_CONFIG_48_4,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_48_5_mbis = {
	.cc = LC3_CONFIG_48_5,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_48_6_mbis = {
	.cc = LC3_CONFIG_48_6,
	.qos = QOS_BCAST,
	.snk = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static struct test_config cfg_bsnk_str_vs_mbis = {
	.cc = UTIL_IOV_INIT(VS_CC),
	.qos = QOS_BCAST,
	.snk = true,
	.vs = true,
	.state_func = bsnk_state_str,
	.streams = 2,
};

static void test_bsnk_str(void)
{
	define_test("BAP/BSNK/STR/BV-01-C [BSNK, LC3 8_1]",
		NULL, test_bcast, &cfg_bsnk_str_8_1, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-02-C [BSNK, LC3 8_2]",
		NULL, test_bcast, &cfg_bsnk_str_8_2, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-03-C [BSNK, LC3 16_1]",
		NULL, test_bcast, &cfg_bsnk_str_16_1, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-04-C [BSNK, LC3 16_2]",
		NULL, test_bcast, &cfg_bsnk_str_16_2, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-05-C [BSNK, LC3 24_1]",
		NULL, test_bcast, &cfg_bsnk_str_24_1, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-06-C [BSNK, LC3 24_2]",
		NULL, test_bcast, &cfg_bsnk_str_24_2, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-07-C [BSNK, LC3 32_1]",
		NULL, test_bcast, &cfg_bsnk_str_32_1, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-08-C [BSNK, LC3 32_2]",
		NULL, test_bcast, &cfg_bsnk_str_32_2, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-09-C [BSNK, LC3 44.1_1]",
		NULL, test_bcast, &cfg_bsnk_str_44_1, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-10-C [BSNK, LC3 44.1_2]",
		NULL, test_bcast, &cfg_bsnk_str_44_2, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-11-C [BSNK, LC3 48_1]",
		NULL, test_bcast, &cfg_bsnk_str_48_1, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-12-C [BSNK, LC3 48_2]",
		NULL, test_bcast, &cfg_bsnk_str_48_2, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-13-C [BSNK, LC3 48_3]",
		NULL, test_bcast, &cfg_bsnk_str_48_3, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-14-C [BSNK, LC3 48_4]",
		NULL, test_bcast, &cfg_bsnk_str_48_4, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-15-C [BSNK, LC3 48_5]",
		NULL, test_bcast, &cfg_bsnk_str_48_5, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-16-C [BSNK, LC3 48_6]",
		NULL, test_bcast, &cfg_bsnk_str_48_6, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-17-C [BSNK, VS]",
		NULL, test_bcast, &cfg_bsnk_str_vs, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-18-C [BSNK, Multiple BISes, LC3 8_1]",
		NULL, test_bcast, &cfg_bsnk_str_8_1_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-19-C [BSNK, Multiple BISes, LC3 8_2]",
		NULL, test_bcast, &cfg_bsnk_str_8_2_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-20-C [BSNK, Multiple BISes, LC3 16_1]",
		NULL, test_bcast, &cfg_bsnk_str_16_1_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-21-C [BSNK, Multiple BISes, LC3 16_2]",
		NULL, test_bcast, &cfg_bsnk_str_16_2_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-22-C [BSNK, Multiple BISes, LC3 24_1]",
		NULL, test_bcast, &cfg_bsnk_str_24_1_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-23-C [BSNK, Multiple BISes, LC3 24_2]",
		NULL, test_bcast, &cfg_bsnk_str_24_2_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-24-C [BSNK, Multiple BISes, LC3 32_1]",
		NULL, test_bcast, &cfg_bsnk_str_32_1_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-25-C [BSNK, Multiple BISes, LC3 32_2]",
		NULL, test_bcast, &cfg_bsnk_str_32_2_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-26-C [BSNK, Multiple BISes, LC3 44.1_1]",
		NULL, test_bcast, &cfg_bsnk_str_44_1_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-27-C [BSNK, Multiple BISes, LC3 44.1_2]",
		NULL, test_bcast, &cfg_bsnk_str_44_2_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-28-C [BSNK, Multiple BISes, LC3 48_1]",
		NULL, test_bcast, &cfg_bsnk_str_48_1_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-29-C [BSNK, Multiple BISes, LC3 48_2]",
		NULL, test_bcast, &cfg_bsnk_str_48_2_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-30-C [BSNK, Multiple BISes, LC3 48_3]",
		NULL, test_bcast, &cfg_bsnk_str_48_3_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-31-C [BSNK, Multiple BISes, LC3 48_4]",
		NULL, test_bcast, &cfg_bsnk_str_48_4_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-32-C [BSNK, Multiple BISes, LC3 48_5]",
		NULL, test_bcast, &cfg_bsnk_str_48_5_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-33-C [BSNK, Multiple BISes, LC3 48_6]",
		NULL, test_bcast, &cfg_bsnk_str_48_6_mbis, IOV_NULL);

	define_test("BAP/BSNK/STR/BV-34-C [BSNK, Multiple BISes, VS]",
		NULL, test_bcast, &cfg_bsnk_str_vs_mbis, IOV_NULL);
}

static void stream_count_config(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	uint8_t *streams = user_data;

	if (bt_bap_stream_get_state(stream) == BT_BAP_STREAM_STATE_CONFIG)
		(*streams)++;
}

static void stream_count_enabling(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	uint8_t *streams = user_data;

	if (bt_bap_stream_get_state(stream) == BT_BAP_STREAM_STATE_ENABLING)
		(*streams)++;
}

static void stream_enable(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;

	bt_bap_stream_enable(stream, true, NULL, NULL, NULL);
}

static void stream_start(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;

	bt_bap_stream_start(stream, NULL, NULL);
}

static void bsrc_state_str(struct bt_bap_stream *stream, uint8_t old_state,
				uint8_t new_state, void *user_data)
{
	struct test_data *data = user_data;
	uint8_t streams = 0;

	switch (new_state) {
	case BT_BAP_STREAM_STATE_CONFIG:
		queue_foreach(data->streams, stream_count_config, &streams);

		if (streams == data->cfg->streams)
			/* After all streams have transitioned to CONFIG
			 * state, enable each one.
			 */
			queue_foreach(data->streams, stream_enable, NULL);
		break;
	case BT_BAP_STREAM_STATE_ENABLING:
		queue_foreach(data->streams, stream_count_enabling, &streams);

		if (streams == 1) {
			/* After the first stream has transitioned to ENABLING
			 * state, bt_bap_stream_get_base will generate the
			 * BASE from all previously configured streams.
			 */
			data->base = bt_bap_stream_get_base(stream);

			g_assert(data->base);
			g_assert(data->base->iov_len ==
					data->cfg->base.iov_len);
			g_assert(memcmp(data->base->iov_base,
					data->cfg->base.iov_base,
					data->base->iov_len) == 0);
		}

		if (streams == data->cfg->streams)
			/* After all streams have transitioned to ENABLING
			 * state, start each one.
			 */
			queue_foreach(data->streams, stream_start, NULL);
		break;
	case BT_BAP_STREAM_STATE_STREAMING:
		queue_foreach(data->streams, stream_count_streaming, &streams);

		if (streams == data->cfg->streams)
			/* Test is completed after all streams have transitioned
			 * to STREAMING state.
			 */
			tester_test_passed();
		break;
	}
}

static struct test_config cfg_bsrc_str_8_1 = {
	.cc = LC3_CONFIG_8_1,
	.qos = LC3_QOS_8_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_8_1),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_8_2 = {
	.cc = LC3_CONFIG_8_2,
	.qos = LC3_QOS_8_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_8_2),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_16_1 = {
	.cc = LC3_CONFIG_16_1,
	.qos = LC3_QOS_16_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_16_1),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_16_2 = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_16_2),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_24_1 = {
	.cc = LC3_CONFIG_24_1,
	.qos = LC3_QOS_24_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_24_1),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_24_2 = {
	.cc = LC3_CONFIG_24_2,
	.qos = LC3_QOS_24_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_24_2),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_32_1 = {
	.cc = LC3_CONFIG_32_1,
	.qos = LC3_QOS_32_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_32_1),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_32_2 = {
	.cc = LC3_CONFIG_32_2,
	.qos = LC3_QOS_32_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_32_2),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_44_1 = {
	.cc = LC3_CONFIG_44_1,
	.qos = LC3_QOS_44_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_44_1),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_44_2 = {
	.cc = LC3_CONFIG_44_2,
	.qos = LC3_QOS_44_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_44_2),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_48_1 = {
	.cc = LC3_CONFIG_48_1,
	.qos = LC3_QOS_48_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_1),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_48_2 = {
	.cc = LC3_CONFIG_48_2,
	.qos = LC3_QOS_48_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_2),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_48_3 = {
	.cc = LC3_CONFIG_48_3,
	.qos = LC3_QOS_48_3_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_3),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_48_4 = {
	.cc = LC3_CONFIG_48_4,
	.qos = LC3_QOS_48_4_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_4),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_48_5 = {
	.cc = LC3_CONFIG_48_5,
	.qos = LC3_QOS_48_5_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_5),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_48_6 = {
	.cc = LC3_CONFIG_48_6,
	.qos = LC3_QOS_48_6_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_6),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
};

static struct test_config cfg_bsrc_str_vs = {
	.cc = UTIL_IOV_INIT(VS_CC),
	.qos = QOS_BCAST,
	.base = UTIL_IOV_INIT(BASE_VS(VS_CFG)),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 1,
	.vs = true,
};

/* Test Purpose:
 * Verify that a Broadcast Source IUT can stream one BIS to a
 * Broadcast Sink. The verification is performed for each Config
 * Settings in turn.
 *
 * Pass verdict:
 * If the Codec ID is LC3, the IUT sends encoded LC3 audio data
 * in BIS Data PDUs on the broadcast Audio Stream. The audio data
 * is formatted using the LC3 Media Packet format.
 *
 * If the Codec ID is a vendor-specific Codec ID, the IUT sends BIS
 * Data PDUs on the broadcast Audio Stream. The parameters included
 * in the Codec_Specific_Configuration data are as defined in
 * TSPX_VS_Codec_Specific_Configuration.
 *
 * If the Codec ID is LC3, each parameter included in
 * Codec_Specific_Configuration data is formatted in an LTV structure
 * with the length, type, and value specified in Table 4.79.
 */

static void test_bsrc_str_1b(void)
{
	define_test("BAP/BSRC/STR/BV-01-C [BSRC, LC3 8_1]",
		NULL, test_bcast, &cfg_bsrc_str_8_1, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-02-C [BSRC, LC3 8_2]",
		NULL, test_bcast, &cfg_bsrc_str_8_2, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-03-C [BSRC, LC3 16_1]",
		NULL, test_bcast, &cfg_bsrc_str_16_1, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-04-C [BSRC, LC3 16_2]",
		NULL, test_bcast, &cfg_bsrc_str_16_2, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-05-C [BSRC, LC3 24_1]",
		NULL, test_bcast, &cfg_bsrc_str_24_1, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-06-C [BSRC, LC3 24_2]",
		NULL, test_bcast, &cfg_bsrc_str_24_2, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-07-C [BSRC, LC3 32_1]",
		NULL, test_bcast, &cfg_bsrc_str_32_1, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-08-C [BSRC, LC3 32_2]",
		NULL, test_bcast, &cfg_bsrc_str_32_2, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-09-C [BSRC, LC3 44.1_1]",
		NULL, test_bcast, &cfg_bsrc_str_44_1, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-10-C [BSRC, LC3 44.1_2]",
		NULL, test_bcast, &cfg_bsrc_str_44_2, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-11-C [BSRC, LC3 48_1]",
		NULL, test_bcast, &cfg_bsrc_str_48_1, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-12-C [BSRC, LC3 48_2]",
		NULL, test_bcast, &cfg_bsrc_str_48_2, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-13-C [BSRC, LC3 48_3]",
		NULL, test_bcast, &cfg_bsrc_str_48_3, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-14-C [BSRC, LC3 48_4]",
		NULL, test_bcast, &cfg_bsrc_str_48_4, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-15-C [BSRC, LC3 48_5]",
		NULL, test_bcast, &cfg_bsrc_str_48_5, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-16-C [BSRC, LC3 48_6]",
		NULL, test_bcast, &cfg_bsrc_str_48_6, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-17-C [BSRC, VS]",
		NULL, test_bcast, &cfg_bsrc_str_vs, IOV_NULL);
}

static struct test_config cfg_bsrc_str_8_1_mbis = {
	.cc = LC3_CONFIG_8_1,
	.qos = LC3_QOS_8_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_8_1_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_8_2_mbis = {
	.cc = LC3_CONFIG_8_2,
	.qos = LC3_QOS_8_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_8_2_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_16_1_mbis = {
	.cc = LC3_CONFIG_16_1,
	.qos = LC3_QOS_16_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_16_1_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_16_2_mbis = {
	.cc = LC3_CONFIG_16_2,
	.qos = LC3_QOS_16_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_16_2_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_24_1_mbis = {
	.cc = LC3_CONFIG_24_1,
	.qos = LC3_QOS_24_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_24_1_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_24_2_mbis = {
	.cc = LC3_CONFIG_24_2,
	.qos = LC3_QOS_24_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_24_2_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_32_1_mbis = {
	.cc = LC3_CONFIG_32_1,
	.qos = LC3_QOS_32_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_32_1_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_32_2_mbis = {
	.cc = LC3_CONFIG_32_2,
	.qos = LC3_QOS_32_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_32_2_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_44_1_mbis = {
	.cc = LC3_CONFIG_44_1,
	.qos = LC3_QOS_44_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_44_1_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_44_2_mbis = {
	.cc = LC3_CONFIG_44_2,
	.qos = LC3_QOS_44_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_44_2_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_48_1_mbis = {
	.cc = LC3_CONFIG_48_1,
	.qos = LC3_QOS_48_1_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_1_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_48_2_mbis = {
	.cc = LC3_CONFIG_48_2,
	.qos = LC3_QOS_48_2_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_2_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_48_3_mbis = {
	.cc = LC3_CONFIG_48_3,
	.qos = LC3_QOS_48_3_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_3_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_48_4_mbis = {
	.cc = LC3_CONFIG_48_4,
	.qos = LC3_QOS_48_4_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_4_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_48_5_mbis = {
	.cc = LC3_CONFIG_48_5,
	.qos = LC3_QOS_48_5_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_5_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_48_6_mbis = {
	.cc = LC3_CONFIG_48_6,
	.qos = LC3_QOS_48_6_1_B,
	.base = UTIL_IOV_INIT(BASE_LC3_48_6_MBIS),
	.src = true,
	.state_func = bsrc_state_str,
	.streams = 2,
};

static struct test_config cfg_bsrc_str_vs_mbis = {
	.cc = UTIL_IOV_INIT(VS_CC),
	.qos = QOS_BCAST,
	.base = UTIL_IOV_INIT(BASE_VS_MBIS(VS_CFG)),
	.src = true,
	.state_func = bsrc_state_str,
	.vs = true,
	.streams = 2,
};

/* Test Purpose:
 * Verify that a Broadcast Source IUT can stream multiple BISes to
 * a Broadcast Sink. The verification is performed for each set of
 * parameters in turn, as specified in Table 4.82.
 *
 * Pass verdict:
 * If the Codec ID is LC3, the IUT sends encoded LC3 audio data in
 * BIS Data PDUs on each synchronized BIS.
 *
 * If the Codec ID is a vendor-specific Codec ID, the IUT sends BIS
 * Data PDUs on each synchronized BIS. The parameters included in the
 * Codec_Specific_Configuration data are as defined in
 * TSPX_VS_Codec_Specific_Configuration.
 *
 * If the Codec ID is LC3, each parameter included in
 * Codec_Specific_Configuration data is formatted in an LTV structure
 * with the length, type, and value specified in Table 4.83.
 */
static void test_bsrc_str_2b(void)
{
	define_test("BAP/BSRC/STR/BV-18-C [BSRC, Multiple BISes, LC3 8_1]",
		NULL, test_bcast, &cfg_bsrc_str_8_1_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-19-C [BSRC, Multiple BISes, LC3 8_2]",
		NULL, test_bcast, &cfg_bsrc_str_8_2_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-20-C [BSRC, Multiple BISes, LC3 16_1]",
		NULL, test_bcast, &cfg_bsrc_str_16_1_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-21-C [BSRC, Multiple BISes, LC3 16_2]",
		NULL, test_bcast, &cfg_bsrc_str_16_2_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-22-C [BSRC, Multiple BISes, LC3 24_1]",
		NULL, test_bcast, &cfg_bsrc_str_24_1_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-23-C [BSRC, Multiple BISes, LC3 24_2]",
		NULL, test_bcast, &cfg_bsrc_str_24_2_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-24-C [BSRC, Multiple BISes, LC3 32_1]",
		NULL, test_bcast, &cfg_bsrc_str_32_1_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-25-C [BSRC, Multiple BISes, LC3 32_2]",
		NULL, test_bcast, &cfg_bsrc_str_32_2_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-26-C [BSRC, Multiple BISes, LC3 44.1_1]",
		NULL, test_bcast, &cfg_bsrc_str_44_1_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-27-C [BSRC, Multiple BISes, LC3 44.1_2]",
		NULL, test_bcast, &cfg_bsrc_str_44_2_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-28-C [BSRC, Multiple BISes, LC3 48_1]",
		NULL, test_bcast, &cfg_bsrc_str_48_1_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-29-C [BSRC, Multiple BISes, LC3 48_2]",
		NULL, test_bcast, &cfg_bsrc_str_48_2_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-30-C [BSRC, Multiple BISes, LC3 48_3]",
		NULL, test_bcast, &cfg_bsrc_str_48_3_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-31-C [BSRC, Multiple BISes, LC3 48_4]",
		NULL, test_bcast, &cfg_bsrc_str_48_4_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-32-C [BSRC, Multiple BISes, LC3 48_5]",
		NULL, test_bcast, &cfg_bsrc_str_48_5_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-33-C [BSRC, Multiple BISes, LC3 48_6]",
		NULL, test_bcast, &cfg_bsrc_str_48_6_mbis, IOV_NULL);

	define_test("BAP/BSRC/STR/BV-34-C [BSRC, Multiple BISes, VS]",
		NULL, test_bcast, &cfg_bsrc_str_vs_mbis, IOV_NULL);
}

static void test_bsrc_str(void)
{
	test_bsrc_str_1b();
	test_bsrc_str_2b();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_disc();
	test_scc();
	test_bsrc_scc();
	test_bsnk_scc();
	test_bsnk_str();
	test_bsrc_str();

	return tester_run();
}
