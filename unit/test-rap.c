/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: LGPL-2.1-or-later
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
#include "src/log.h"
#include "bluetooth/uuid.h"
#include "src/shared/util.h"
#include "src/shared/tester.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/gatt-helpers.h"
#include "src/shared/rap.h"

struct test_data_ras {
	struct gatt_db *db;
	struct bt_gatt_server *server;
	struct bt_gatt_client *client;
	struct queue *ccc_states;
	size_t iovcnt;
	struct iovec *iov;
	unsigned int ras_id;
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
		data.iovcnt = ARRAY_SIZE(iov_data(args));	\
		data.iov = util_iov_dup(iov, ARRAY_SIZE(iov_data(args))); \
		tester_add(name, &data, NULL, function,	\
				test_teardown_ras);			\
	} while (0)

/* Unit-test local stubs for BlueZ daemon logging functions.
 * These satisfy linker dependencies from src/log.h (used by rap.c)
 * without pulling daemon objects. Messages go through GLib logging.
 */
static const char *btd_log_domain = "unit/test-rap";

void btd_error(uint16_t index, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	g_logv(btd_log_domain, G_LOG_LEVEL_WARNING, format, ap);
	va_end(ap);
}

void btd_debug(uint16_t index, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	g_logv(btd_log_domain, G_LOG_LEVEL_DEBUG, format, ap);
	va_end(ap);
}

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

static void test_teardown_rap(const void *user_data)
{
	struct test_data_rap *data = (void *)user_data;

	bt_rap_unref(data->rap);
	bt_gatt_client_unref(data->client);
	util_iov_free(data->iov, data->iovcnt);
	gatt_db_unref(data->db);

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
}

static void ras_detached(struct bt_rap *rap, void *user_data)
{
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

	bt_att_set_debug(att, BT_ATT_DEBUG, print_debug, "bt_att:", NULL);

	data->db = gatt_db_new();
	g_assert(data->db);

	gatt_db_ccc_register(data->db, gatt_ccc_read_cb, NULL,
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

	return tester_run();
}
