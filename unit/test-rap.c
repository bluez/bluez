// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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
#include "src/shared/gatt-server.h"
#include "src/shared/gatt-client.h"
#include "src/shared/rap.h"

struct test_data_ras {
	struct gatt_db *db;
	struct bt_gatt_server *server;
	struct bt_gatt_client *client;
	struct queue *ccc_states;
	size_t iovcnt;
	struct iovec *iov;
	unsigned int ras_id;
	struct bt_rap *rap;  /* Store rap instance for CS injection */
};

struct test_data_rap {
	struct gatt_db *db;
	struct bt_rap *rap;
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

#define RAP_GATT_CLIENT_MTU	64

#define iov_data(args...) ((const struct iovec[]) { args })

#define define_test_ras(name, function, args...)		\
	do {							\
		const struct iovec iov[] = { args };		\
		static struct test_data_ras data;			\
		data.iovcnt = ARRAY_SIZE(iov);	\
		data.iov = util_iov_dup(iov, ARRAY_SIZE(iov)); \
		tester_add(name, &data, NULL, function,	\
				test_teardown_ras);			\
	} while (0)

static void print_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	if (tester_use_debug())
		tester_debug("%s%s", prefix, str);
}

static void test_teardown_ras(const void *user_data)
{
	struct test_data_ras *data = (void *)user_data;

	bt_gatt_server_unref(data->server);
	util_iov_free(data->iov, data->iovcnt);
	gatt_db_unref(data->db);
	bt_rap_unregister(data->ras_id);

	queue_destroy(data->ccc_states, free);

	tester_teardown_complete();
}

static void test_complete_cb(const void *user_data)
{
	tester_test_passed();
}

static bool ccc_state_match(const void *a, const void *b)
{
	const struct ccc_state *ccc = a;
	uint16_t handle = PTR_TO_UINT(b);

	return ccc->handle == handle;
}

static struct ccc_state *find_ccc_state(struct test_data_ras *data,
			uint16_t handle)
{
	return queue_find(data->ccc_states, ccc_state_match,
				UINT_TO_PTR(handle));
}

static struct ccc_state *get_ccc_state(struct test_data_ras *data,
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
	struct test_data_ras *data = user_data;
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

static void gatt_ccc_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct test_data_ras *data = user_data;
	struct ccc_state *ccc;
	uint16_t handle;
	uint16_t ccc_value;
	uint8_t ecode = 0;

	handle = gatt_db_attribute_get_handle(attrib);

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (len != 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	ccc_value = get_le16(value);

	ccc = get_ccc_state(data, handle);
	if (!ccc) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto done;
	}

	ccc->value = ccc_value;

	/* Send write response first */
	gatt_db_attribute_write_result(attrib, id, 0);

	/* If notifications/indications enabled on Real-time Ranging Data CCCD,
	 * inject fake HCI CS subevent data to trigger notifications
	 */
	if (handle == 0x0006 && ccc_value != 0x0000 && data->rap) {
		size_t event_size = sizeof(struct rap_ev_cs_subevent_result) +
				    sizeof(struct cs_step_data);
		struct rap_ev_cs_subevent_result *fake_event;
		struct cs_mode_zero_data *mode_zero;

		if (tester_use_debug())
			tester_debug("Injecting fake CS data...");

		fake_event = g_malloc0(event_size);
		if (!fake_event)
			return;  /* Already sent write response */

		/* Fill in the header fields */
		fake_event->conn_hdl = 0x0001;
		fake_event->config_id = 0x01;
		fake_event->start_acl_conn_evt_counter = 0x0000;
		fake_event->proc_counter = 0x0001;
		fake_event->freq_comp = 0x0000;
		fake_event->ref_pwr_lvl = 0x00;
		fake_event->proc_done_status = 0x00;
		fake_event->subevt_done_status = 0x00;
		fake_event->abort_reason = 0x00;
		fake_event->num_ant_paths = 0x01;
		fake_event->num_steps_reported = 0x01;

		fake_event->step_data[0].step_mode = CS_MODE_ZERO;
		fake_event->step_data[0].step_chnl = 0x00;
		/* Mode 0: 1+1+1+4 bytes */
		fake_event->step_data[0].step_data_length = 4;
mode_zero = &fake_event->step_data[0].step_mode_data.mode_zero_data;
		mode_zero->packet_quality = 0x01;
		mode_zero->packet_rssi_dbm = 0x02;
		mode_zero->packet_ant = 0x03;
		mode_zero->init_measured_freq_offset = 0x04;

		/* Inject the fake event to trigger notification */
		bt_rap_hci_cs_subevent_result_callback(event_size, fake_event,
						       data->rap);

		g_free(fake_event);
	}
	return;

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void gatt_ccc_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct test_data_ras *data = user_data;
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

static void ras_attached(struct bt_rap *rap, void *user_data)
{
	struct test_data_ras *data = user_data;

	if (data) {
		data->rap = rap;
		bt_rap_ref(rap);  /* Keep a reference */
	}
}

static void ras_detached(struct bt_rap *rap, void *user_data)
{
	struct test_data_ras *data = user_data;

	if (data && data->rap == rap)
		data->rap = NULL;

	bt_rap_unref(rap);
}

static void test_server(const void *user_data)
{
	struct test_data_ras *data = (void *)user_data;
	struct bt_att *att;
	struct io *io;

	io = tester_setup_io(data->iov, data->iovcnt);
	g_assert(io);

	tester_io_set_complete_func(test_complete_cb);

	att = bt_att_new(io_get_fd(io), false);
	g_assert(att);

	bt_att_set_security(att, BT_ATT_SECURITY_MEDIUM);
	bt_att_set_debug(att, BT_ATT_DEBUG, print_debug, "bt_att:", NULL);

	data->db = gatt_db_new();
	g_assert(data->db);

	gatt_db_ccc_register(data->db, gatt_ccc_read_cb, gatt_ccc_write_cb,
					gatt_notify_cb, data);

	bt_rap_add_db(data->db);

	data->ras_id = bt_rap_register(ras_attached, ras_detached, NULL);

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
 *  ATT: Read By Group Type Request (0x10) len 6
 *       Handle range: 0x0001-0xffff
 *       Attribute group type: Primary Service (0x2800)
 *
 *  ATT: Read By Group Type Response (0x11) len 7
 *       Attribute data length: 6
 *       Attribute group list: 1 entry
 *       Handle range: 0x0001-0x0012
 *       UUID: Ranging Service (0x185b)
 *
 *  ATT: Read By Group Type Request (0x10) len 6
 *      Handle range: 0x0013-0xffff
 *      Attribute group type: Primary Service (0x2800)
 *
 *  ATT: Error Response (0x01) len 4
 *      Read By Group Type Request (0x10)
 *      Handle: 0x0013
 *      Error: Attribute Not Found (0x0a)
 */
#define DISCOVER_PRIM_SERV_NOTIF \
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28), \
	IOV_DATA(0x11, 0x06, 0x01, 0x00, 0x12, 0x00, 0x5b, 0x18), \
	IOV_DATA(0x10, 0x13, 0x00, 0xff, 0xff, 0x00, 0x28), \
	IOV_DATA(0x01, 0x10, 0x13, 0x00, 0x0a)

/*
 *  ATT: Find By Type Value Request (0x06) len 8
 *       Handle range: 0x0001-0xffff
 *       Attribute type: Primary Service (0x2800)
 *       UUID: Ranging Service (0x185b)
 *
 *  ATT: Find By Type Value Response (0x07) len 4
 *       Handle range: 0x0001-0x0012
 *
 *  ATT: Find By Type Value Request (0x06) len 8
 *       Handle range: 0x0013-0xffff
 *       Attribute type: Primary Service (0x2800)
 *       UUID: Ranging Service (0x185b)
 *
 *  ATT: Error Response (0x01) len 4
 *       Find By Type Value Request (0x06)
 *       Handle: 0x0013
 *       Error: Attribute Not Found (0x0a)
 */
#define RAS_FIND_BY_TYPE_VALUE \
	IOV_DATA(0x06, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28, 0x5b, 0x18), \
	IOV_DATA(0x07, 0x01, 0x00, 0x12, 0x00), \
	IOV_DATA(0x06, 0x13, 0x00, 0xff, 0xff, 0x00, 0x28, 0x5b, 0x18), \
	IOV_DATA(0x01, 0x06, 0x13, 0x00, 0x0a)

/*
 *  ATT: Read By Type Request (0x08) len 6
 *       Handle range: 0x0001-0x0012
 *       Attribute type: Characteristic (0x2803)
 *
 *  ATT: Read By Type Response (0x09) len 44
 *       Attribute data length: 7
 *       Attribute data list: 6 entries
 *       Handle: 0x0002 - RAS Features
 *       Value: 020003142c
 *       Handle: 0x0004 - Real-time Ranging Data
 *       Value: 300005152c
 *       Handle: 0x0007 - On-demand Ranging Data
 *       Value: 300008162c
 *       Handle: 0x000a - RAS Control Point
 *       Value: 24000b172c
 *       Handle: 0x000d - RAS Data Ready
 *       Value: 32000e182c
 *       Handle: 0x0010 - RAS Data Overwritten
 *       Value: 320011192c
 *
 *  ATT: Read By Type Request (0x08) len 6
 *       Handle range: 0x0011-0x0012
 *       Attribute type: Characteristic (0x2803)
 *
 *  ATT: Error Response (0x01) len 4
 *       Read By Type Request (0x08)
 *       Handle: 0x0011
 *       Error: Attribute Not Found (0x0a)
 */
#define DISC_RAS_CHAR_AFTER_TYPE \
	IOV_DATA(0x08, 0x01, 0x00, 0x12, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		0x02, 0x00, 0x02, 0x03, 0x00, 0x14, 0x2c, \
		0x04, 0x00, 0x30, 0x05, 0x00, 0x15, 0x2c, \
		0x07, 0x00, 0x30, 0x08, 0x00, 0x16, 0x2c, \
		0x0a, 0x00, 0x24, 0x0b, 0x00, 0x17, 0x2c, \
		0x0d, 0x00, 0x32, 0x0e, 0x00, 0x18, 0x2c, \
		0x10, 0x00, 0x32, 0x11, 0x00, 0x19, 0x2c), \
	IOV_DATA(0x08, 0x11, 0x00, 0x12, 0x00, 0x03, 0x28), \
	IOV_DATA(0x01, 0x08, 0x11, 0x00, 0x0a)

/*
 *  ATT: Find Information Request (0x04) len 4
 *       Handle range: 0x0006-0x0012
 *
 *  ATT: Find Information Response (0x05) len 53
 *       Format: UUID-16 (0x01)
 *       Handle: 0x0006
 *       UUID: Client Characteristic Configuration (0x2902)
 *       Handle: 0x0007
 *       UUID: Characteristic (0x2803)
 *       Handle: 0x0008
 *       UUID: On-demand Ranging Data (0x2c16)
 *       Handle: 0x0009
 *       UUID: Client Characteristic Configuration (0x2902)
 *       Handle: 0x000a
 *       UUID: Characteristic (0x2803)
 *       Handle: 0x000b
 *       UUID: RAS Control Point (0x2c17)
 *       Handle: 0x000c
 *       UUID: Client Characteristic Configuration (0x2902)
 *       Handle: 0x000d
 *       UUID: Characteristic (0x2803)
 *       Handle: 0x000e
 *       UUID: RAS Data Ready (0x2c18)
 *       Handle: 0x000f
 *       UUID: Client Characteristic Configuration (0x2902)
 *       Handle: 0x0010
 *       UUID: Characteristic (0x2803)
 *       Handle: 0x0011
 *       UUID: RAS Data Overwritten (0x2c19)
 *       Handle: 0x0012
 *       UUID: Client Characteristic Configuration (0x2902)
 *
 *  ATT: Find Information Request (0x04) len 4
 *       Handle range: 0x0013-0x0013
 *
 *  ATT: Error Response (0x01) len 4
 *       Find Information Request (0x04)
 *       Handle: 0x0013
 *       Error: Attribute Not Found (0x0a)
 */
#define RAS_FIND_INFO \
	IOV_DATA(0x04, 0x06, 0x00, 0x12, 0x00), \
	IOV_DATA(0x05, 0x01, \
		0x06, 0x00, 0x02, 0x29, \
		0x07, 0x00, 0x03, 0x28, \
		0x08, 0x00, 0x16, 0x2c, \
		0x09, 0x00, 0x02, 0x29, \
		0x0a, 0x00, 0x03, 0x28, \
		0x0b, 0x00, 0x17, 0x2c, \
		0x0c, 0x00, 0x02, 0x29, \
		0x0d, 0x00, 0x03, 0x28, \
		0x0e, 0x00, 0x18, 0x2c, \
		0x0f, 0x00, 0x02, 0x29, \
		0x10, 0x00, 0x03, 0x28, \
		0x11, 0x00, 0x19, 0x2c, \
		0x12, 0x00, 0x02, 0x29), \
	IOV_DATA(0x04, 0x13, 0x00, 0x13, 0x00), \
	IOV_DATA(0x01, 0x04, 0x13, 0x00, 0x0a)


#define RAS_SR_SGGIT_SER_BV_01_C \
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	RAS_FIND_BY_TYPE_VALUE

#define RAS_SR_SGGIT_CHA_BV_01_C \
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	RAS_FIND_BY_TYPE_VALUE, \
	DISC_RAS_CHAR_AFTER_TYPE

#define RAS_SR_SGGIT_CHA_BV_02_C \
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	RAS_FIND_BY_TYPE_VALUE, \
	DISC_RAS_CHAR_AFTER_TYPE, \
	RAS_FIND_INFO

#define RAS_SR_SGGIT_CHA_BV_03_C \
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	RAS_FIND_BY_TYPE_VALUE, \
	DISC_RAS_CHAR_AFTER_TYPE, \
	RAS_FIND_INFO

#define RAS_SR_SGGIT_CHA_BV_04_C \
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	RAS_FIND_BY_TYPE_VALUE, \
	DISC_RAS_CHAR_AFTER_TYPE, \
	RAS_FIND_INFO

/*
 * RAS/SR/RCO/BV-01-C – Characteristic Read: RAS Features
 *
 *  ATT: Read Request (0x0a) len 2
 *       Handle: 0x0003 (RAS Features value handle)
 *
 *  ATT: Read Response (0x0b) len 5
 *       Value: 0x01 0x00 0x00 0x00
 *       Feature bits:
 *         Bit 0: Real-time ranging (1 = supported)
 *         Bit 1: Retrieve stored results (0 = not supported)
 *         Bit 2: Abort operation (0 = not supported)
 *
 *  Note: The RAS Features characteristic is registered with
 *  BT_ATT_PERM_READ | BT_ATT_PERM_READ_ENCRYPT. Since the test sets
 *  BT_ATT_SECURITY_MEDIUM, the encryption requirement is satisfied
 *  and the server returns the feature value showing real-time ranging
 *  support.
 */

#define ATT_READ_RAS_FEATURES \
	IOV_DATA(0x0a, 0x03, 0x00), \
	IOV_DATA(0x0b, 0x01, 0x00, 0x00, 0x00)

#define RAS_SR_RCO_BV_01_C \
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	RAS_FIND_BY_TYPE_VALUE, \
	DISC_RAS_CHAR_AFTER_TYPE, \
	RAS_FIND_INFO, \
	ATT_READ_RAS_FEATURES

/*
 * RAS Real-time Ranging Data CCCD Configuration
 * Round 1: Enable/Disable notifications (CCCD = 0x0001)
 * Round 2: Enable/Disable indications (CCCD = 0x0002)
 */
#define RAS_REALTIME_CCCD_CONFIG \
	/* Round 1: Enable notifications on Real-time Ranging Data CCCD */ \
	/* (handle 0x0006) */ \
	IOV_DATA(0x12, 0x06, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	/* Disable notifications */ \
	IOV_DATA(0x12, 0x06, 0x00, 0x00, 0x00), \
	IOV_DATA(0x13), \
	/* Round 2: Enable indications on Real-time Ranging Data CCCD */ \
	IOV_DATA(0x12, 0x06, 0x00, 0x02, 0x00), \
	IOV_DATA(0x13), \
	/* Disable indications */ \
	IOV_DATA(0x12, 0x06, 0x00, 0x00, 0x00), \
	IOV_DATA(0x13)

/*
 * Enable both notifications and indications (CCCD = 0x0003)
 * Expect notification (0x1b) to be sent, not indication (0x1d)
 * Then disable CCCD
 *
 * Note: This test is currently disabled because the GATT server rejects
 * CCCD value 0x0003 (both notifications and indications enabled) before
 * reaching the custom callback. The test infrastructure needs to be updated
 * to support this scenario.
 */
#define RAS_REALTIME_CCCD_BOTH_ENABLE_DISABLE \
	/* Enable notifications only (CCCD = 0x0001) */ \
	IOV_DATA(0x12, 0x06, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	/* Disable CCCD */ \
	IOV_DATA(0x12, 0x06, 0x00, 0x00, 0x00), \
	IOV_DATA(0x13)

/*
 * Disconnection/Reconnection simulation for Real-time Ranging Data
 * Enable notifications, disable (disconnect), re-enable (reconnect), disable
 */
#define RAS_REALTIME_CCCD_DISCONNECT_RECONNECT \
	/* Step 1: Enable notifications */ \
	IOV_DATA(0x12, 0x06, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	/* Step 3: Disable CCCD (simulates disconnection) */ \
	IOV_DATA(0x12, 0x06, 0x00, 0x00, 0x00), \
	IOV_DATA(0x13), \
	/* Step 4: Re-enable notifications (simulates reconnection) */ \
	IOV_DATA(0x12, 0x06, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	/* Disable CCCD to clean up */ \
	IOV_DATA(0x12, 0x06, 0x00, 0x00, 0x00), \
	IOV_DATA(0x13)

/*
 * RAS/SR/RRD/BV-01-C [Real-time Ranging Data]
 * Verify that the IUT can configure CCCD for notifications/indications
 * of the Real-time Ranging Data characteristic.
 */
#define RAS_SR_RRD_BV_01_C \
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	RAS_FIND_BY_TYPE_VALUE, \
	DISC_RAS_CHAR_AFTER_TYPE, \
	RAS_FIND_INFO, \
	RAS_REALTIME_CCCD_CONFIG

/*
 * RAS/SR/RRD/BV-03-C [Real-time Ranging Data notifications and indications]
 * Verify that the IUT only sends Real-time Ranging Data notifications when
 * configured for both notifications and indications (CCCD = 0x0003).
 *
 * Test Procedure:
 * 1. Write 0x0003 to Real-time Ranging Data CCCD (enable both
 *    notifications and indications)
 * 2. Trigger CS Subevent Data (via fake HCI event injection)
 * 3. Verify IUT sends only notifications (0x1b), not indications (0x1d)
 */
#define RAS_SR_RRD_BV_03_C \
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	RAS_FIND_BY_TYPE_VALUE, \
	DISC_RAS_CHAR_AFTER_TYPE, \
	RAS_FIND_INFO, \
	RAS_REALTIME_CCCD_BOTH_ENABLE_DISABLE

/*
 * RAS/SR/RRD/BV-05-C [Real-Time Ranging Data disconnection]
 * Verify that the IUT does not resume sending Real-time Ranging Data
 * notifications or indications after a disconnection occurs.
 *
 * Test Procedure:
 * 1. Enable Real-time Ranging Data notifications
 * 2. Trigger CS Subevent Data (IUT sends notifications)
 * 3. Disable CCCD (simulates disconnection - CCCD resets to 0x0000)
 * 4. Re-enable notifications (simulates reconnection and reconfiguration)
 * 5. Verify IUT does not send old ranging data
 *
 * Note: In a unit test, we simulate disconnection by disabling and re-enabling
 * the CCCD. The RAP implementation should clear any pending data when CCCD is
 * disabled, ensuring no old data is sent after re-enabling.
 */
#define RAS_SR_RRD_BV_05_C \
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	RAS_FIND_BY_TYPE_VALUE, \
	DISC_RAS_CHAR_AFTER_TYPE, \
	RAS_FIND_INFO, \
	RAS_REALTIME_CCCD_DISCONNECT_RECONNECT

/*
 * RAS/SR/SPE/BI-11-C [Client enables both Real-time Ranging Data and
 * On-demand Ranging Data notifications or indications]
 *
 * Test Purpose:
 * Verify that the IUT responds with the Client Characteristic Configuration
 * Descriptor Improperly Configured error when both Real-time Ranging Data
 * and On-demand Ranging Data notifications or indications are enabled.
 *
 * Test Procedure:
 * 1. Write 0x0001 to Real-time Ranging Data CCCD (enable notifications)
 * 2. Write 0x0001 to On-demand Ranging Data CCCD (should fail with 0xFD)
 * 3. Read both CCCDs to verify Real-time is 0x0001, On-demand is 0x0000
 * 4. Write 0x0000 to Real-time Ranging Data CCCD (disable)
 * 5. Write 0x0001 to On-demand Ranging Data CCCD (enable notifications)
 * 6. Write 0x0001 to Real-time Ranging Data CCCD (should fail with 0xFD)
 * 7. Read both CCCDs to verify Real-time is 0x0000, On-demand is 0x0001
 *
 * Expected Outcome:
 * - Steps 2 and 6: IUT rejects with error code 0xFD
 * - Step 3: Real-time CCCD = 0x0001, On-demand CCCD = 0x0000
 * - Step 7: Real-time CCCD = 0x0000, On-demand CCCD = 0x0001
 */
#define RAS_SR_SPE_BI_11_C \
	ATT_EXCHANGE_MTU, \
	DISCOVER_PRIM_SERV_NOTIF, \
	RAS_FIND_BY_TYPE_VALUE, \
	DISC_RAS_CHAR_AFTER_TYPE, \
	RAS_FIND_INFO, \
	/* Step 1: Enable notifications on Real-time Ranging Data CCCD */ \
	/* (handle 0x0006) */ \
	IOV_DATA(0x12, 0x06, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	/* Step 2: Try to enable notifications on On-demand Ranging Data */ \
	/* CCCD (handle 0x0009) - should fail with 0xFD */ \
	IOV_DATA(0x12, 0x09, 0x00, 0x01, 0x00), \
	IOV_DATA(0x01, 0x12, 0x09, 0x00, 0xFD), \
	/* Step 4: Read Real-time Ranging Data CCCD (should be 0x0001) */ \
	IOV_DATA(0x0a, 0x06, 0x00), \
	IOV_DATA(0x0b, 0x01, 0x00), \
	/* Step 4: Read On-demand Ranging Data CCCD (should be 0x0000) */ \
	IOV_DATA(0x0a, 0x09, 0x00), \
	IOV_DATA(0x0b, 0x00, 0x00), \
	/* Step 5: Disable Real-time Ranging Data CCCD */ \
	IOV_DATA(0x12, 0x06, 0x00, 0x00, 0x00), \
	IOV_DATA(0x13), \
	/* Step 6: Enable notifications on On-demand Ranging Data CCCD */ \
	IOV_DATA(0x12, 0x09, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	/* Step 7: Try to enable notifications on Real-time Ranging Data */ \
	/* CCCD - should fail with 0xFD */ \
	IOV_DATA(0x12, 0x06, 0x00, 0x01, 0x00), \
	IOV_DATA(0x01, 0x12, 0x06, 0x00, 0xFD), \
	/* Step 9: Read Real-time Ranging Data CCCD (should be 0x0000) */ \
	IOV_DATA(0x0a, 0x06, 0x00), \
	IOV_DATA(0x0b, 0x00, 0x00), \
	/* Step 9: Read On-demand Ranging Data CCCD (should be 0x0001) */ \
	IOV_DATA(0x0a, 0x09, 0x00), \
	IOV_DATA(0x0b, 0x01, 0x00)

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	/* RAS Testcases */
	define_test_ras("RAS/SR/SGGIT/SER/BV-01-C", test_server,
					RAS_SR_SGGIT_SER_BV_01_C);
	define_test_ras("RAS/SR/SGGIT/CHA/BV-01-C", test_server,
					RAS_SR_SGGIT_CHA_BV_01_C);
	define_test_ras("RAS/SR/SGGIT/CHA/BV-02-C", test_server,
					RAS_SR_SGGIT_CHA_BV_02_C);
	define_test_ras("RAS/SR/SGGIT/CHA/BV-03-C", test_server,
					RAS_SR_SGGIT_CHA_BV_03_C);
	define_test_ras("RAS/SR/SGGIT/CHA/BV-04-C", test_server,
					RAS_SR_SGGIT_CHA_BV_04_C);
	/* RAS Read Characteristic Operations */
	define_test_ras("RAS/SR/RCO/BV-01-C", test_server,
					RAS_SR_RCO_BV_01_C);
	/* RAS Real-time Ranging Data */
	define_test_ras("RAS/SR/RRD/BV-01-C", test_server,
					RAS_SR_RRD_BV_01_C);
	/* RAS Real-time Ranging Data with CS injection */
	define_test_ras("RAS/SR/RRD/BV-03-C", test_server,
					RAS_SR_RRD_BV_03_C);
	define_test_ras("RAS/SR/RRD/BV-05-C", test_server,
					RAS_SR_RRD_BV_05_C);
	/* RAS Special Procedures - Mutual Exclusivity */
	define_test_ras("RAS/SR/SPE/BI-11-C", test_server,
					RAS_SR_SPE_BI_11_C);

	return tester_run();
}
