// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

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
#include "src/shared/uhid.h"
#include "src/shared/hog.h"

/*
 * HOGP Report Host tests, see HOGP.TS. The HID Device (Lower Tester) is
 * emulated with the PDUs below, and the uHID device with a socket pair.
 *
 * The HID Service of the HID Device is laid out as follows, the SCI
 * variant adding the HID SCI Mode and HID SCI Information characteristics
 * and the multiple instances variant having a second HID Service at
 * 0x0021 with the same layout as the SCI variant:
 *
 * 0x0001 HID Service
 * 0x0003   Protocol Mode (Read, Write Without Response)
 * 0x0005   Report Map (Read)
 * 0x0006     External Report Reference: Battery Level
 * 0x0008   HID Information (Read)
 * 0x000a   HID Control Point (Write Without Response)
 * 0x000c   Report (Read, Notify): Input Report 1
 * 0x000d     Client Characteristic Configuration
 * 0x000e     Report Reference
 * 0x0010   Report (Read, Write, Write Without Response): Output Report 1
 * 0x0011     Report Reference
 * 0x0013   Report (Read, Write): Feature Report 1
 * 0x0014     Report Reference
 * 0x0016   Boot Keyboard Input Report (Read, Notify)
 * 0x0017     Client Characteristic Configuration
 * 0x0019   Boot Mouse Input Report (Read, Notify)
 * 0x001a     Client Characteristic Configuration
 * 0x001c   HID SCI Mode (Read, Notify) - SCI variant
 * 0x001d     Client Characteristic Configuration
 * 0x001f   HID SCI Information (Read) - SCI variant
 *
 * followed by a Battery Service with the Battery Level characteristic.
 *
 * The Client Characteristic Configuration descriptors following a
 * characteristic with no other descriptor are not discovered with Find
 * Information, as bt_gatt_client assumes them in that case.
 */

#define HOG_GATT_CLIENT_MTU	64

#define REPORT_MAP_LEN		73

enum action {
	ACT_NONE,
	ACT_NOTIFY,
	ACT_GET_INPUT,
	ACT_GET_OUTPUT,
	ACT_GET_FEATURE,
	ACT_SET_INPUT,
	ACT_SET_OUTPUT,
	ACT_SET_FEATURE,
	ACT_OUTPUT,
	ACT_SUSPEND,
	ACT_RESUME,
	ACT_DETACH,
	ACT_REATTACH,
	ACT_SCI,
};

struct test_config {
	enum action action;
	/* Number of uHID devices created, once the Report Map is read */
	unsigned int creates;
	/* HID SCI modes to enable, the second once the first is notified */
	uint8_t mode[2];
	/* Number of HID SCI Mode notifications per mode */
	unsigned int notifications;
	/* uHID event expected after the action */
	uint32_t uhid_type;
	const uint8_t *uhid_data;
	size_t uhid_len;
};

struct test_data {
	const struct iovec *setup;
	size_t setup_cnt;
	struct iovec *iov;
	size_t iovcnt;
	const struct test_config *cfg;
	struct bt_gatt_client *client;
	struct bt_hog *hog;
	int uhid_fd;
	struct io *uhid_io;
	unsigned int created;
	unsigned int notified;
	unsigned int mode_idx;
	bool io_done;
	bool uhid_done;
	bool sci_done;
};

#define define_test(name, _setup, _cfg, args...)			\
	do {								\
		const struct iovec iov[] = { args };			\
		static struct test_data data;				\
		data.setup = _setup;					\
		data.setup_cnt = ARRAY_SIZE(_setup);			\
		data.cfg = _cfg;					\
		data.iovcnt = ARRAY_SIZE(iov);				\
		data.iov = util_iov_dup(iov, ARRAY_SIZE(iov));		\
		tester_add_full(name, &data, NULL, test_setup,		\
				test_hog, test_teardown, NULL, 2,	\
				&data, test_free);			\
	} while (0)

static void test_free(void *user_data)
{
	struct test_data *data = user_data;

	util_iov_free(data->iov, data->iovcnt);
}

static void print_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	if (tester_use_debug())
		tester_debug("%s%s", prefix, str);
}

static void test_done(struct test_data *data)
{
	if (data->io_done && data->uhid_done && data->sci_done)
		tester_test_passed();
}

static void test_complete_cb(const void *user_data)
{
	struct test_data *data = (void *) user_data;

	data->io_done = true;
	test_done(data);
}

static void uhid_send(struct test_data *data, uint32_t type, uint8_t rtype)
{
	struct uhid_event ev;
	ssize_t len;

	memset(&ev, 0, sizeof(ev));
	ev.type = type;

	switch (type) {
	case UHID_START:
		ev.u.start.dev_flags = UHID_DEV_NUMBERED_FEATURE_REPORTS |
					UHID_DEV_NUMBERED_OUTPUT_REPORTS |
					UHID_DEV_NUMBERED_INPUT_REPORTS;
		break;
	case UHID_GET_REPORT:
		ev.u.get_report.id = 1;
		ev.u.get_report.rnum = 1;
		ev.u.get_report.rtype = rtype;
		break;
	case UHID_SET_REPORT:
		ev.u.set_report.id = 2;
		ev.u.set_report.rnum = 1;
		ev.u.set_report.rtype = rtype;
		ev.u.set_report.size = 2;
		ev.u.set_report.data[0] = 0x01;
		ev.u.set_report.data[1] = 0x42;
		break;
	case UHID_OUTPUT:
		ev.u.output.rtype = rtype;
		ev.u.output.size = 2;
		ev.u.output.data[0] = 0x01;
		ev.u.output.data[1] = 0x07;
		break;
	}

	len = write(io_get_fd(data->uhid_io), &ev, sizeof(ev));
	g_assert_cmpint(len, ==, sizeof(ev));
}

static void do_action(struct test_data *data)
{
	const struct test_config *cfg = data->cfg;

	switch (cfg->action) {
	case ACT_NONE:
		break;
	case ACT_NOTIFY:
		/* Have the HID Device send the notifications */
		tester_io_send();
		break;
	case ACT_GET_INPUT:
		uhid_send(data, UHID_GET_REPORT, UHID_INPUT_REPORT);
		break;
	case ACT_GET_OUTPUT:
		uhid_send(data, UHID_GET_REPORT, UHID_OUTPUT_REPORT);
		break;
	case ACT_GET_FEATURE:
		uhid_send(data, UHID_GET_REPORT, UHID_FEATURE_REPORT);
		break;
	case ACT_SET_INPUT:
		uhid_send(data, UHID_SET_REPORT, UHID_INPUT_REPORT);
		break;
	case ACT_SET_OUTPUT:
		uhid_send(data, UHID_SET_REPORT, UHID_OUTPUT_REPORT);
		break;
	case ACT_SET_FEATURE:
		uhid_send(data, UHID_SET_REPORT, UHID_FEATURE_REPORT);
		break;
	case ACT_OUTPUT:
		uhid_send(data, UHID_OUTPUT, UHID_OUTPUT_REPORT);
		break;
	case ACT_SUSPEND:
		g_assert_cmpint(bt_hog_set_control_point(data->hog, true), ==,
									0);
		break;
	case ACT_RESUME:
		g_assert_cmpint(bt_hog_set_control_point(data->hog, false), ==,
									0);
		break;
	case ACT_DETACH:
		bt_hog_detach(data->hog, true);
		break;
	case ACT_REATTACH:
		/* Reconnect, the uHID device being destroyed meanwhile */
		bt_hog_detach(data->hog, true);
		g_assert(bt_hog_attach(data->hog, data->client));
		break;
	case ACT_SCI:
		g_assert_cmpint(bt_hog_set_sci_mode(data->hog, cfg->mode[0]),
								==, 0);
		break;
	}
}

static void uhid_check(struct test_data *data, const struct uhid_event *ev)
{
	const struct test_config *cfg = data->cfg;
	const uint8_t *buf = NULL;
	size_t len = 0;

	if (ev->type != cfg->uhid_type)
		return;

	switch (ev->type) {
	case UHID_INPUT2:
		buf = ev->u.input2.data;
		len = ev->u.input2.size;
		break;
	case UHID_GET_REPORT_REPLY:
		g_assert_cmpint(ev->u.get_report_reply.id, ==, 1);
		g_assert_cmpint(ev->u.get_report_reply.err, ==, 0);
		buf = ev->u.get_report_reply.data;
		len = ev->u.get_report_reply.size;
		break;
	case UHID_SET_REPORT_REPLY:
		g_assert_cmpint(ev->u.set_report_reply.id, ==, 2);
		g_assert_cmpint(ev->u.set_report_reply.err, ==, 0);
		break;
	}

	if (cfg->uhid_data) {
		g_assert_cmpint(len, ==, cfg->uhid_len);
		g_assert(!memcmp(buf, cfg->uhid_data, len));
	}

	data->uhid_done = true;
	test_done(data);
}

static bool uhid_read(struct io *io, void *user_data)
{
	struct test_data *data = user_data;
	struct uhid_event ev;
	ssize_t len;

	len = read(io_get_fd(io), &ev, sizeof(ev));
	if (len < 0)
		return errno == EAGAIN;

	g_assert_cmpint(len, ==, sizeof(ev));

	if (ev.type == UHID_CREATE2) {
		g_assert_cmpstr((char *) ev.u.create2.name, ==, "bluez-hog");
		g_assert_cmpint(ev.u.create2.vendor, ==, 0x0002);
		g_assert_cmpint(ev.u.create2.product, ==, 0x0001);
		g_assert_cmpint(ev.u.create2.version, ==, 0x0001);
		g_assert_cmpint(ev.u.create2.bus, ==, BUS_BLUETOOTH);
		g_assert_cmpint(ev.u.create2.rd_size, ==, REPORT_MAP_LEN);

		uhid_send(data, UHID_START, 0);

		/* Once all instances are created, perform the action of the
		 * test.
		 */
		if (++data->created == data->cfg->creates)
			do_action(data);

		return true;
	}

	uhid_check(data, &ev);

	return true;
}

static void sci_mode_cb(uint8_t mode, void *user_data)
{
	struct test_data *data = user_data;
	const struct test_config *cfg = data->cfg;

	g_assert_cmpint(mode, ==, cfg->mode[data->mode_idx]);

	/* Wait for the notification of every HID SCI Mode characteristic */
	if (++data->notified < cfg->notifications)
		return;

	data->notified = 0;

	/* Change to another mode, see HOGP.TS 4.6.1 step 6 */
	if (!data->mode_idx && cfg->mode[1]) {
		data->mode_idx++;
		g_assert_cmpint(bt_hog_set_sci_mode(data->hog, cfg->mode[1]),
								==, 0);
		return;
	}

	data->sci_done = true;
	test_done(data);
}

static void test_hog(const void *user_data)
{
	struct test_data *data = (void *) user_data;
	struct io *io;
	int fds[2];

	io = tester_setup_io(data->iov, data->iovcnt);
	g_assert(io);

	tester_io_set_complete_func(test_complete_cb);

	data->uhid_done = !data->cfg->uhid_type;
	data->sci_done = !data->cfg->notifications;

	g_assert(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
						SOCK_CLOEXEC, 0, fds));

	data->uhid_io = io_new(fds[1]);
	g_assert(data->uhid_io);
	io_set_close_on_destroy(data->uhid_io, true);
	io_set_read_handler(data->uhid_io, uhid_read, data, NULL);

	/* Not closed by bt_hog, see test_teardown */
	data->uhid_fd = fds[0];

	data->hog = bt_hog_new(fds[0], "bluez-hog", 0x0002, 0x0001, 0x0001,
								0, NULL);
	g_assert(data->hog);

	bt_hog_set_debug(data->hog, print_debug, "bt_hog: ", NULL);
	bt_hog_set_sci_mode_callback(data->hog, sci_mode_cb, data);

	g_assert(bt_hog_attach(data->hog, data->client));
}

static void client_ready_cb(bool success, uint8_t att_ecode, void *user_data)
{
	if (!success) {
		tester_setup_failed();
		return;
	}

	tester_setup_complete();
}

static void test_setup(const void *user_data)
{
	struct test_data *data = (void *) user_data;
	struct bt_att *att;
	struct gatt_db *db;
	struct io *io;

	io = tester_setup_io(data->setup, data->setup_cnt);
	g_assert(io);

	att = bt_att_new(io_get_fd(io), false);
	g_assert(att);

	bt_att_set_debug(att, BT_ATT_DEBUG, print_debug, "bt_att: ", NULL);

	db = gatt_db_new();
	g_assert(db);

	data->client = bt_gatt_client_new(db, att, HOG_GATT_CLIENT_MTU, 0);
	g_assert(data->client);

	bt_gatt_client_set_debug(data->client, print_debug,
						"bt_gatt_client: ", NULL);

	bt_gatt_client_ready_register(data->client, client_ready_cb, data,
									NULL);

	bt_att_unref(att);
	gatt_db_unref(db);
}

static void test_teardown(const void *user_data)
{
	struct test_data *data = (void *) user_data;

	bt_hog_unref(data->hog);
	data->hog = NULL;
	close(data->uhid_fd);
	io_destroy(data->uhid_io);
	data->uhid_io = NULL;
	bt_gatt_client_unref(data->client);
	data->client = NULL;

	data->created = 0;
	data->notified = 0;
	data->mode_idx = 0;
	data->io_done = false;

	tester_teardown_complete();
}

/* ATT: Read Request (0x0a) / Read Response (0x0b) */
#define READ(hnd, value...) \
	IOV_DATA(0x0a, hnd, 0x00), \
	IOV_DATA(0x0b, ##value)

/* ATT: Write Request (0x12) / Write Response (0x13) */
#define WRITE(hnd, value...) \
	IOV_DATA(0x12, hnd, 0x00, value), \
	IOV_DATA(0x13)

/* ATT: Write Command (0x52), which has no response */
#define WRITE_CMD(hnd, value...) \
	IOV_DATA(0x52, hnd, 0x00, value), \
	IOV_NULL

/* ATT: Handle Value Notification (0x1b), following another PDU sent */
#define NOTIFY(hnd, value...) \
	IOV_NULL, \
	IOV_DATA(0x1b, hnd, 0x00, value)

#define REPORT_MAP \
	0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x01, 0x05, 0x07, \
	0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, \
	0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, \
	0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, \
	0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, 0x95, 0x06, \
	0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, \
	0x29, 0x65, 0x81, 0x00, 0x09, 0x01, 0x95, 0x01, 0x75, 0x08, \
	0xb1, 0x02, 0xc0

#define REPORT_MAP_1 \
	0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x01, 0x05, 0x07, \
	0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, \
	0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, \
	0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, \
	0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, 0x95, 0x06, \
	0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, \
	0x29, 0x65, 0x81

#define REPORT_MAP_2 \
	0x00, 0x09, 0x01, 0x95, 0x01, 0x75, 0x08, 0xb1, 0x02, 0xc0

#define INPUT_REPORT	0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00

/* Protocol Mode: Report Protocol Mode */
#define READ_PROTO_MODE		READ(0x03, 0x01)
/* External Report Reference: Battery Level, which is not a Report */
#define READ_EXT_REPORT_REF	READ(0x06, 0x19, 0x2a)
/* HID Information: bcdHID 1.11, NormallyConnectable */
#define READ_INFO		READ(0x08, 0x11, 0x01, 0x00, 0x02)
/* HID Information: bcdHID 1.11, NormallyConnectable, SCI and SCI Low
 * Power mode supported.
 */
#define READ_INFO_SCI		READ(0x08, 0x11, 0x01, 0x00, 0x0e)
#define READ_INPUT		READ(0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, \
					0x00, 0x00, 0x00)
#define READ_INPUT_REF		READ(0x0e, 0x01, 0x01)
#define READ_OUTPUT		READ(0x10, 0x00)
#define READ_OUTPUT_REF		READ(0x11, 0x01, 0x02)
#define READ_FEATURE		READ(0x13, 0x00)
#define READ_FEATURE_REF	READ(0x14, 0x01, 0x03)
#define READ_INPUT_CCC		READ(0x0d, 0x00, 0x00)
#define ENABLE_INPUT_CCC	WRITE(0x0d, 0x01, 0x00)
#define DISABLE_INPUT_CCC	WRITE(0x0d, 0x00, 0x00)
#define READ_SCI_MODE		READ(0x1c, 0x00)
#define READ_SCI_INFO		READ(0x1f, 0x08, 0x01, 0x08, 0x00, 0x50, \
					0x00, 0x08, 0x00)
#define ENABLE_SCI_MODE_CCC	WRITE(0x1d, 0x01, 0x00)
#define DISABLE_SCI_MODE_CCC	WRITE(0x1d, 0x00, 0x00)

/* The Report Map is longer than the MTU so it is read with Read Blob */
#define READ_REPORT_MAP \
	IOV_DATA(0x0a, 0x05, 0x00), \
	IOV_DATA(0x0b, REPORT_MAP_1), \
	IOV_DATA(0x0c, 0x05, 0x00, 0x3f, 0x00), \
	IOV_DATA(0x0d, REPORT_MAP_2)

/* The Report Map is read last, once every report is known */
#define ATTACH \
	READ_PROTO_MODE, \
	READ_EXT_REPORT_REF, \
	READ_INFO, \
	READ_INPUT, \
	READ_INPUT_REF, \
	READ_OUTPUT, \
	READ_OUTPUT_REF, \
	READ_FEATURE, \
	READ_FEATURE_REF, \
	READ_INPUT_CCC, \
	ENABLE_INPUT_CCC, \
	READ_REPORT_MAP

/* HID SCI Mode notifications are enabled once SCI support is known */
#define SCI_ATTACH \
	READ_PROTO_MODE, \
	READ_EXT_REPORT_REF, \
	READ_INFO_SCI, \
	READ_INPUT, \
	READ_INPUT_REF, \
	READ_OUTPUT, \
	READ_OUTPUT_REF, \
	READ_FEATURE, \
	READ_FEATURE_REF, \
	READ_SCI_MODE, \
	READ_SCI_INFO, \
	ENABLE_SCI_MODE_CCC, \
	READ_INPUT_CCC, \
	ENABLE_INPUT_CCC, \
	READ_REPORT_MAP

/* Protocol Mode in Boot Protocol Mode, set to Report Protocol Mode */
#define BOOT_ATTACH \
	READ(0x03, 0x00), \
	WRITE_CMD(0x03, 0x01), \
	READ_EXT_REPORT_REF, \
	READ_INFO, \
	READ_INPUT, \
	READ_INPUT_REF, \
	READ_OUTPUT, \
	READ_OUTPUT_REF, \
	READ_FEATURE, \
	READ_FEATURE_REF, \
	READ_INPUT_CCC, \
	ENABLE_INPUT_CCC, \
	READ_REPORT_MAP

/* Enable a HID SCI mode, with no response other than the notification
 * of the HID SCI Mode characteristics once the connection rate has been
 * changed.
 */
#define MULTI_SCI_MODE(mode) \
	WRITE_CMD(0x0a, mode), \
	NOTIFY(0x1c, mode), \
	NOTIFY(0x3c, mode)

/* Discovery by bt_gatt_client */
#define DISC_MTU \
	IOV_DATA(0x02, 0x40, 0x00), \
	IOV_DATA(0x03, 0x40, 0x00)

#define DISC_SR_FEATURES \
	IOV_DATA(0x08, 0x01, 0x00, 0xff, 0xff, 0x3a, 0x2b), \
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a)

#define DISC_SECONDARY \
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x01, 0x28), \
	IOV_DATA(0x01, 0x10, 0x01, 0x00, 0x0a)

#define DISC_HID_CHRC_1 \
	IOV_DATA(0x09, 0x07, 0x02, 0x00, 0x06, 0x03, 0x00, 0x4e, 0x2a, \
			0x04, 0x00, 0x02, 0x05, 0x00, 0x4b, 0x2a, 0x07, \
			0x00, 0x02, 0x08, 0x00, 0x4a, 0x2a, 0x09, 0x00, \
			0x04, 0x0a, 0x00, 0x4c, 0x2a, 0x0b, 0x00, 0x12, \
			0x0c, 0x00, 0x4d, 0x2a, 0x0f, 0x00, 0x0e, 0x10, \
			0x00, 0x4d, 0x2a, 0x12, 0x00, 0x0a, 0x13, 0x00, \
			0x4d, 0x2a, 0x15, 0x00, 0x12, 0x16, 0x00, 0x22, \
			0x2a)

#define DISC_HID_DESC \
	IOV_DATA(0x04, 0x06, 0x00, 0x06, 0x00), \
	IOV_DATA(0x05, 0x01, 0x06, 0x00, 0x07, 0x29), \
	IOV_DATA(0x04, 0x0d, 0x00, 0x0e, 0x00), \
	IOV_DATA(0x05, 0x01, 0x0d, 0x00, 0x02, 0x29, 0x0e, 0x00, 0x08, \
			0x29), \
	IOV_DATA(0x04, 0x11, 0x00, 0x11, 0x00), \
	IOV_DATA(0x05, 0x01, 0x11, 0x00, 0x08, 0x29), \
	IOV_DATA(0x04, 0x14, 0x00, 0x14, 0x00), \
	IOV_DATA(0x05, 0x01, 0x14, 0x00, 0x08, 0x29)

static const struct iovec setup_basic[] = {
	DISC_MTU,
	DISC_SR_FEATURES,
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	IOV_DATA(0x11, 0x06, 0x01, 0x00, 0x1a, 0x00, 0x12, 0x18, 0x1b,
			0x00, 0x1e, 0x00, 0x0f, 0x18),
	IOV_DATA(0x10, 0x1f, 0x00, 0xff, 0xff, 0x00, 0x28),
	IOV_DATA(0x01, 0x10, 0x1f, 0x00, 0x0a),
	DISC_SECONDARY,
	IOV_DATA(0x08, 0x01, 0x00, 0x1e, 0x00, 0x02, 0x28),
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a),
	IOV_DATA(0x08, 0x01, 0x00, 0x1e, 0x00, 0x03, 0x28),
	DISC_HID_CHRC_1,
	IOV_DATA(0x08, 0x16, 0x00, 0x1e, 0x00, 0x03, 0x28),
	IOV_DATA(0x09, 0x07, 0x18, 0x00, 0x12, 0x19, 0x00, 0x33, 0x2a,
			0x1c, 0x00, 0x12, 0x1d, 0x00, 0x19, 0x2a),
	IOV_DATA(0x08, 0x1d, 0x00, 0x1e, 0x00, 0x03, 0x28),
	IOV_DATA(0x01, 0x08, 0x1d, 0x00, 0x0a),
	DISC_HID_DESC,
};

static const struct iovec setup_sci[] = {
	DISC_MTU,
	DISC_SR_FEATURES,
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	IOV_DATA(0x11, 0x06, 0x01, 0x00, 0x20, 0x00, 0x12, 0x18, 0x21,
			0x00, 0x24, 0x00, 0x0f, 0x18),
	IOV_DATA(0x10, 0x25, 0x00, 0xff, 0xff, 0x00, 0x28),
	IOV_DATA(0x01, 0x10, 0x25, 0x00, 0x0a),
	DISC_SECONDARY,
	IOV_DATA(0x08, 0x01, 0x00, 0x24, 0x00, 0x02, 0x28),
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a),
	IOV_DATA(0x08, 0x01, 0x00, 0x24, 0x00, 0x03, 0x28),
	DISC_HID_CHRC_1,
	IOV_DATA(0x08, 0x16, 0x00, 0x24, 0x00, 0x03, 0x28),
	IOV_DATA(0x09, 0x07, 0x18, 0x00, 0x12, 0x19, 0x00, 0x33, 0x2a,
			0x1b, 0x00, 0x12, 0x1c, 0x00, 0x39, 0x2c, 0x1e,
			0x00, 0x02, 0x1f, 0x00, 0x3a, 0x2c, 0x22, 0x00,
			0x12, 0x23, 0x00, 0x19, 0x2a),
	IOV_DATA(0x08, 0x23, 0x00, 0x24, 0x00, 0x03, 0x28),
	IOV_DATA(0x01, 0x08, 0x23, 0x00, 0x0a),
	DISC_HID_DESC,
	IOV_DATA(0x04, 0x20, 0x00, 0x20, 0x00),
	IOV_DATA(0x01, 0x04, 0x20, 0x00, 0x0a),
};

/* Two instances of the HID Service, with SCI support */
static const struct iovec setup_multi[] = {
	IOV_DATA(0x02, 0x40, 0x00),
	IOV_DATA(0x03, 0x40, 0x00),
	IOV_DATA(0x08, 0x01, 0x00, 0xff, 0xff, 0x3a, 0x2b),
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a),
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	IOV_DATA(0x11, 0x06, 0x01, 0x00, 0x20, 0x00, 0x12, 0x18, 0x21,
			0x00, 0x40, 0x00, 0x12, 0x18, 0x41, 0x00, 0x44,
			0x00, 0x0f, 0x18),
	IOV_DATA(0x10, 0x45, 0x00, 0xff, 0xff, 0x00, 0x28),
	IOV_DATA(0x01, 0x10, 0x45, 0x00, 0x0a),
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x01, 0x28),
	IOV_DATA(0x01, 0x10, 0x01, 0x00, 0x0a),
	IOV_DATA(0x08, 0x01, 0x00, 0x44, 0x00, 0x02, 0x28),
	IOV_DATA(0x01, 0x08, 0x01, 0x00, 0x0a),
	IOV_DATA(0x08, 0x01, 0x00, 0x44, 0x00, 0x03, 0x28),
	IOV_DATA(0x09, 0x07, 0x02, 0x00, 0x06, 0x03, 0x00, 0x4e, 0x2a,
			0x04, 0x00, 0x02, 0x05, 0x00, 0x4b, 0x2a, 0x07,
			0x00, 0x02, 0x08, 0x00, 0x4a, 0x2a, 0x09, 0x00,
			0x04, 0x0a, 0x00, 0x4c, 0x2a, 0x0b, 0x00, 0x12,
			0x0c, 0x00, 0x4d, 0x2a, 0x0f, 0x00, 0x0e, 0x10,
			0x00, 0x4d, 0x2a, 0x12, 0x00, 0x0a, 0x13, 0x00,
			0x4d, 0x2a, 0x15, 0x00, 0x12, 0x16, 0x00, 0x22,
			0x2a),
	IOV_DATA(0x08, 0x16, 0x00, 0x44, 0x00, 0x03, 0x28),
	IOV_DATA(0x09, 0x07, 0x18, 0x00, 0x12, 0x19, 0x00, 0x33, 0x2a,
			0x1b, 0x00, 0x12, 0x1c, 0x00, 0x39, 0x2c, 0x1e,
			0x00, 0x02, 0x1f, 0x00, 0x3a, 0x2c, 0x22, 0x00,
			0x06, 0x23, 0x00, 0x4e, 0x2a, 0x24, 0x00, 0x02,
			0x25, 0x00, 0x4b, 0x2a, 0x27, 0x00, 0x02, 0x28,
			0x00, 0x4a, 0x2a, 0x29, 0x00, 0x04, 0x2a, 0x00,
			0x4c, 0x2a, 0x2b, 0x00, 0x12, 0x2c, 0x00, 0x4d,
			0x2a),
	IOV_DATA(0x08, 0x2c, 0x00, 0x44, 0x00, 0x03, 0x28),
	IOV_DATA(0x09, 0x07, 0x2f, 0x00, 0x0e, 0x30, 0x00, 0x4d, 0x2a,
			0x32, 0x00, 0x0a, 0x33, 0x00, 0x4d, 0x2a, 0x35,
			0x00, 0x12, 0x36, 0x00, 0x22, 0x2a, 0x38, 0x00,
			0x12, 0x39, 0x00, 0x33, 0x2a, 0x3b, 0x00, 0x12,
			0x3c, 0x00, 0x39, 0x2c, 0x3e, 0x00, 0x02, 0x3f,
			0x00, 0x3a, 0x2c, 0x42, 0x00, 0x12, 0x43, 0x00,
			0x19, 0x2a),
	IOV_DATA(0x08, 0x43, 0x00, 0x44, 0x00, 0x03, 0x28),
	IOV_DATA(0x01, 0x08, 0x43, 0x00, 0x0a),
	IOV_DATA(0x04, 0x06, 0x00, 0x06, 0x00),
	IOV_DATA(0x05, 0x01, 0x06, 0x00, 0x07, 0x29),
	IOV_DATA(0x04, 0x0d, 0x00, 0x0e, 0x00),
	IOV_DATA(0x05, 0x01, 0x0d, 0x00, 0x02, 0x29, 0x0e, 0x00, 0x08,
			0x29),
	IOV_DATA(0x04, 0x11, 0x00, 0x11, 0x00),
	IOV_DATA(0x05, 0x01, 0x11, 0x00, 0x08, 0x29),
	IOV_DATA(0x04, 0x14, 0x00, 0x14, 0x00),
	IOV_DATA(0x05, 0x01, 0x14, 0x00, 0x08, 0x29),
	IOV_DATA(0x04, 0x20, 0x00, 0x20, 0x00),
	IOV_DATA(0x01, 0x04, 0x20, 0x00, 0x0a),
	IOV_DATA(0x04, 0x26, 0x00, 0x26, 0x00),
	IOV_DATA(0x05, 0x01, 0x26, 0x00, 0x07, 0x29),
	IOV_DATA(0x04, 0x2d, 0x00, 0x2e, 0x00),
	IOV_DATA(0x05, 0x01, 0x2d, 0x00, 0x02, 0x29, 0x2e, 0x00, 0x08,
			0x29),
	IOV_DATA(0x04, 0x31, 0x00, 0x31, 0x00),
	IOV_DATA(0x05, 0x01, 0x31, 0x00, 0x08, 0x29),
	IOV_DATA(0x04, 0x34, 0x00, 0x34, 0x00),
	IOV_DATA(0x05, 0x01, 0x34, 0x00, 0x08, 0x29),
	IOV_DATA(0x04, 0x40, 0x00, 0x40, 0x00),
	IOV_DATA(0x01, 0x04, 0x40, 0x00, 0x0a),
};

#define MULTI_ATTACH \
	IOV_DATA(0x0a, 0x23, 0x00), \
	IOV_DATA(0x0b, 0x01), \
	IOV_DATA(0x0a, 0x26, 0x00), \
	IOV_DATA(0x0b, 0x19, 0x2a), \
	IOV_DATA(0x0a, 0x28, 0x00), \
	IOV_DATA(0x0b, 0x11, 0x01, 0x00, 0x0e), \
	IOV_DATA(0x0a, 0x2c, 0x00), \
	IOV_DATA(0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00), \
	IOV_DATA(0x0a, 0x2e, 0x00), \
	IOV_DATA(0x0b, 0x01, 0x01), \
	IOV_DATA(0x0a, 0x30, 0x00), \
	IOV_DATA(0x0b, 0x00), \
	IOV_DATA(0x0a, 0x31, 0x00), \
	IOV_DATA(0x0b, 0x01, 0x02), \
	IOV_DATA(0x0a, 0x33, 0x00), \
	IOV_DATA(0x0b, 0x00), \
	IOV_DATA(0x0a, 0x34, 0x00), \
	IOV_DATA(0x0b, 0x01, 0x03), \
	IOV_DATA(0x0a, 0x03, 0x00), \
	IOV_DATA(0x0b, 0x01), \
	IOV_DATA(0x0a, 0x06, 0x00), \
	IOV_DATA(0x0b, 0x19, 0x2a), \
	IOV_DATA(0x0a, 0x08, 0x00), \
	IOV_DATA(0x0b, 0x11, 0x01, 0x00, 0x0e), \
	IOV_DATA(0x0a, 0x0c, 0x00), \
	IOV_DATA(0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00), \
	IOV_DATA(0x0a, 0x0e, 0x00), \
	IOV_DATA(0x0b, 0x01, 0x01), \
	IOV_DATA(0x0a, 0x10, 0x00), \
	IOV_DATA(0x0b, 0x00), \
	IOV_DATA(0x0a, 0x11, 0x00), \
	IOV_DATA(0x0b, 0x01, 0x02), \
	IOV_DATA(0x0a, 0x13, 0x00), \
	IOV_DATA(0x0b, 0x00), \
	IOV_DATA(0x0a, 0x14, 0x00), \
	IOV_DATA(0x0b, 0x01, 0x03), \
	IOV_DATA(0x0a, 0x3c, 0x00), \
	IOV_DATA(0x0b, 0x00), \
	IOV_DATA(0x0a, 0x3f, 0x00), \
	IOV_DATA(0x0b, 0x08, 0x01, 0x08, 0x00, 0x50, 0x00, 0x08, 0x00), \
	IOV_DATA(0x12, 0x3d, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	IOV_DATA(0x0a, 0x2d, 0x00), \
	IOV_DATA(0x0b, 0x00, 0x00), \
	IOV_DATA(0x0a, 0x1c, 0x00), \
	IOV_DATA(0x0b, 0x00), \
	IOV_DATA(0x0a, 0x1f, 0x00), \
	IOV_DATA(0x0b, 0x08, 0x01, 0x08, 0x00, 0x50, 0x00, 0x08, 0x00), \
	IOV_DATA(0x12, 0x1d, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	IOV_DATA(0x0a, 0x0d, 0x00), \
	IOV_DATA(0x0b, 0x00, 0x00), \
	IOV_DATA(0x12, 0x2d, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	IOV_DATA(0x0a, 0x25, 0x00), \
	IOV_DATA(0x0b, 0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x01, \
			0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, \
			0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, \
			0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05, \
			0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, \
			0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, \
			0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, \
			0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81), \
	IOV_DATA(0x0c, 0x25, 0x00, 0x3f, 0x00), \
	IOV_DATA(0x0d, 0x00, 0x09, 0x01, 0x95, 0x01, 0x75, 0x08, 0xb1, \
			0x02, 0xc0), \
	IOV_DATA(0x12, 0x0d, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	IOV_DATA(0x0a, 0x05, 0x00), \
	IOV_DATA(0x0b, 0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x01, \
			0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, \
			0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, \
			0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05, \
			0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, \
			0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, \
			0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, \
			0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81), \
	IOV_DATA(0x0c, 0x05, 0x00, 0x3f, 0x00), \
	IOV_DATA(0x0d, 0x00, 0x09, 0x01, 0x95, 0x01, 0x75, 0x08, 0xb1, \
			0x02, 0xc0)

static const uint8_t input_report[] = { 0x01, INPUT_REPORT };
static const uint8_t input_value[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00 };
static const uint8_t output_report[] = { 0x01, 0x00 };
static const uint8_t feature_report[] = { 0x01, 0x00 };

static const struct test_config cfg_none = {
	.action = ACT_NONE,
};

static const struct test_config cfg_attach = {
	.action = ACT_NONE,
	.creates = 1,
};

static const struct test_config cfg_multi_attach = {
	.action = ACT_NONE,
	.creates = 2,
};

static const struct test_config cfg_notify = {
	.action = ACT_NOTIFY,
	.creates = 1,
	.uhid_type = UHID_INPUT2,
	.uhid_data = input_report,
	.uhid_len = sizeof(input_report),
};

static const struct test_config cfg_get_input = {
	.action = ACT_GET_INPUT,
	.creates = 1,
	.uhid_type = UHID_GET_REPORT_REPLY,
	.uhid_data = input_value,
	.uhid_len = sizeof(input_value),
};

static const struct test_config cfg_get_output = {
	.action = ACT_GET_OUTPUT,
	.creates = 1,
	.uhid_type = UHID_GET_REPORT_REPLY,
	.uhid_data = output_report,
	.uhid_len = sizeof(output_report),
};

static const struct test_config cfg_get_feature = {
	.action = ACT_GET_FEATURE,
	.creates = 1,
	.uhid_type = UHID_GET_REPORT_REPLY,
	.uhid_data = feature_report,
	.uhid_len = sizeof(feature_report),
};

static const struct test_config cfg_set_input = {
	.action = ACT_SET_INPUT,
	.creates = 1,
	.uhid_type = UHID_SET_REPORT_REPLY,
};

static const struct test_config cfg_set_output = {
	.action = ACT_SET_OUTPUT,
	.creates = 1,
	.uhid_type = UHID_SET_REPORT_REPLY,
};

static const struct test_config cfg_set_feature = {
	.action = ACT_SET_FEATURE,
	.creates = 1,
	.uhid_type = UHID_SET_REPORT_REPLY,
};

static const struct test_config cfg_output = {
	.action = ACT_OUTPUT,
	.creates = 1,
};

static const struct test_config cfg_suspend = {
	.action = ACT_SUSPEND,
	.creates = 1,
};

static const struct test_config cfg_resume = {
	.action = ACT_RESUME,
	.creates = 1,
};

static const struct test_config cfg_detach = {
	.action = ACT_DETACH,
	.creates = 1,
};

static const struct test_config cfg_reattach = {
	.action = ACT_REATTACH,
	.creates = 1,
	.uhid_type = UHID_INPUT2,
	.uhid_data = input_report,
	.uhid_len = sizeof(input_report),
};

#define define_cfg_sci(_name, _mode, _mode2, _notifications) \
static const struct test_config _name = { \
	.action = ACT_SCI, \
	.creates = 2, \
	.mode = { _mode, _mode2 }, \
	.notifications = _notifications, \
}

/* HOGP.TS 4.6.1: change from the tested mode to Full Range if Default,
 * otherwise to Default.
 */
define_cfg_sci(cfg_sci_default, BT_HOG_SCI_MODE_DEFAULT,
				BT_HOG_SCI_MODE_FULL_RANGE, 2);
define_cfg_sci(cfg_sci_fast, BT_HOG_SCI_MODE_FAST,
				BT_HOG_SCI_MODE_DEFAULT, 2);
define_cfg_sci(cfg_sci_low_power, BT_HOG_SCI_MODE_LOW_POWER,
				BT_HOG_SCI_MODE_DEFAULT, 2);
define_cfg_sci(cfg_sci_full_range, BT_HOG_SCI_MODE_FULL_RANGE,
				BT_HOG_SCI_MODE_DEFAULT, 2);

static const struct test_config cfg_sci_attach = {
	.action = ACT_NONE,
	.creates = 1,
};

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	/* Discovery */
	define_test("HOGP/RH/HGDC/BV-03-C [Discover Report Characteristics]",
			setup_multi, &cfg_multi_attach,
			MULTI_ATTACH);
	define_test("HOGP/RH/HGDC/BV-04-C [Discover Report Characteristic "
			"Client Characteristic Configuration Descriptors]",
			setup_basic, &cfg_none,
			READ_PROTO_MODE, READ_EXT_REPORT_REF, READ_INFO,
			READ_INPUT, READ_INPUT_REF, READ_OUTPUT,
			READ_OUTPUT_REF, READ_FEATURE, READ_FEATURE_REF,
			READ_INPUT_CCC);
	define_test("HOGP/RH/HGDC/BV-05-C [Discover Report Characteristic "
			"Report Reference Characteristic Descriptors]",
			setup_basic, &cfg_none,
			READ_PROTO_MODE, READ_EXT_REPORT_REF, READ_INFO,
			READ_INPUT, READ_INPUT_REF, READ_OUTPUT,
			READ_OUTPUT_REF, READ_FEATURE, READ_FEATURE_REF);

	/* Read */
	define_test("HOGP/RH/HGRF/BV-02-C [Read External Report Reference "
			"Characteristic Descriptors for Report Map]",
			setup_basic, &cfg_none,
			READ_PROTO_MODE, READ_EXT_REPORT_REF);
	define_test("HOGP/RH/HGRF/BV-03-C [Read Report Characteristics - "
			"Input Report]",
			setup_basic, &cfg_get_input,
			ATTACH, READ_INPUT);
	define_test("HOGP/RH/HGRF/BV-04-C [Read Report Reference "
			"Characteristic Descriptors for Report Characteristics "
			"- Input Report]",
			setup_basic, &cfg_none,
			READ_PROTO_MODE, READ_EXT_REPORT_REF, READ_INFO,
			READ_INPUT, READ_INPUT_REF);
	define_test("HOGP/RH/HGRF/BV-05-C [Read Client Characteristic "
			"Configuration Descriptors for Report Characteristics "
			"- Input Report]",
			setup_basic, &cfg_none,
			READ_PROTO_MODE, READ_EXT_REPORT_REF, READ_INFO,
			READ_INPUT, READ_INPUT_REF, READ_OUTPUT,
			READ_OUTPUT_REF, READ_FEATURE, READ_FEATURE_REF,
			READ_INPUT_CCC);
	define_test("HOGP/RH/HGRF/BV-19-C [Read Report Characteristics - "
			"Output Report]",
			setup_basic, &cfg_get_output,
			ATTACH, READ_OUTPUT);
	define_test("HOGP/RH/HGRF/BV-06-C [Read Report Reference "
			"Characteristic Descriptors for Report Characteristics "
			"- Output Report]",
			setup_basic, &cfg_none,
			READ_PROTO_MODE, READ_EXT_REPORT_REF, READ_INFO,
			READ_INPUT, READ_INPUT_REF, READ_OUTPUT,
			READ_OUTPUT_REF);
	define_test("HOGP/RH/HGRF/BV-07-C [Read Report Characteristics - "
			"Feature Report]",
			setup_basic, &cfg_get_feature,
			ATTACH, READ_FEATURE);
	define_test("HOGP/RH/HGRF/BV-08-C [Read Report Reference "
			"Characteristic Descriptors for Report Characteristics "
			"- Feature Report]",
			setup_basic, &cfg_none,
			READ_PROTO_MODE, READ_EXT_REPORT_REF, READ_INFO,
			READ_INPUT, READ_INPUT_REF, READ_OUTPUT,
			READ_OUTPUT_REF, READ_FEATURE, READ_FEATURE_REF);
	define_test("HOGP/RH/HGRF/BV-18-C [Read Protocol Mode Characteristics "
			"(Get Boot Protocol Mode Command) - RH]",
			setup_basic, &cfg_none,
			READ_PROTO_MODE);

	/* Write */
	define_test("HOGP/RH/HGWF/BV-01-C [Write Report Characteristics - "
			"Input Report]",
			setup_basic, &cfg_set_input,
			ATTACH, WRITE(0x0c, 0x42));
	define_test("HOGP/RH/HGWF/BV-02-C [Write Report Characteristics - "
			"Output Report]",
			setup_basic, &cfg_output,
			ATTACH, WRITE(0x10, 0x07));
	define_test("HOGP/RH/HGWF/BV-02-C [Write Report Characteristics - "
			"Output Report] - Set Report",
			setup_basic, &cfg_set_output,
			ATTACH, WRITE(0x10, 0x42));
	define_test("HOGP/RH/HGWF/BV-04-C [Write Report Characteristics - "
			"Feature Report]",
			setup_basic, &cfg_set_feature,
			ATTACH, WRITE(0x13, 0x42));
	define_test("HOGP/RH/HGWF/BV-05-C [Write HID Control Point "
			"Characteristics - Suspend]",
			setup_basic, &cfg_suspend,
			ATTACH, IOV_DATA(0x52, 0x0a, 0x00, 0x00));
	define_test("HOGP/RH/HGWF/BV-06-C [Write HID Control Point "
			"Characteristics - Exit Suspend]",
			setup_basic, &cfg_resume,
			ATTACH, IOV_DATA(0x52, 0x0a, 0x00, 0x01));
	define_test("HOGP/RH/HGWF/BV-07-C [Write Protocol Mode "
			"Characteristics - Set Protocol Command (Protocol Mode "
			"= Report Protocol Mode)]",
			setup_basic, &cfg_attach,
			BOOT_ATTACH);

	/* HID SCI, see HOGP.TS 4.6.1 */
	define_test("HOGP/RH/HGWF/BV-08-C [Write HID Control Point "
			"Characteristic, Enable SCI Default mode]",
			setup_multi, &cfg_sci_default,
			MULTI_ATTACH,
			MULTI_SCI_MODE(BT_HOG_SCI_MODE_DEFAULT),
			MULTI_SCI_MODE(BT_HOG_SCI_MODE_FULL_RANGE));
	define_test("HOGP/RH/HGWF/BV-09-C [Write HID Control Point "
			"Characteristic, Enable SCI Fast mode]",
			setup_multi, &cfg_sci_fast,
			MULTI_ATTACH,
			MULTI_SCI_MODE(BT_HOG_SCI_MODE_FAST),
			MULTI_SCI_MODE(BT_HOG_SCI_MODE_DEFAULT));
	define_test("HOGP/RH/HGWF/BV-10-C [Write HID Control Point "
			"Characteristic, Enable SCI Low Power mode]",
			setup_multi, &cfg_sci_low_power,
			MULTI_ATTACH,
			MULTI_SCI_MODE(BT_HOG_SCI_MODE_LOW_POWER),
			MULTI_SCI_MODE(BT_HOG_SCI_MODE_DEFAULT));
	define_test("HOGP/RH/HGWF/BV-11-C [Write HID Control Point "
			"Characteristic, Enable SCI Full Range mode]",
			setup_multi, &cfg_sci_full_range,
			MULTI_ATTACH,
			MULTI_SCI_MODE(BT_HOG_SCI_MODE_FULL_RANGE),
			MULTI_SCI_MODE(BT_HOG_SCI_MODE_DEFAULT));

	/* Configuration */
	define_test("HOGP/RH/HGCF/BV-01-C [Report Characteristic - Input "
			"Reports - enable notifications (write with 0x0001)]",
			setup_basic, &cfg_none,
			READ_PROTO_MODE, READ_EXT_REPORT_REF, READ_INFO,
			READ_INPUT, READ_INPUT_REF, READ_OUTPUT,
			READ_OUTPUT_REF, READ_FEATURE, READ_FEATURE_REF,
			READ_INPUT_CCC, ENABLE_INPUT_CCC);
	define_test("HOGP/RH/HGCF/BV-02-C [Report Characteristic - Input "
			"Reports - disable notifications (write with 0x0000)]",
			setup_basic, &cfg_detach,
			ATTACH, DISABLE_INPUT_CCC);

	/* Notifications */
	define_test("HOGP/RH/HGNF/BV-01-C [Report Characteristic "
			"Configuration, receive notifications]",
			setup_basic, &cfg_notify,
			ATTACH, IOV_DATA(0x1b, 0x0c, 0x00, INPUT_REPORT));
	/* Reconnection: the reports are known and the Report Map cached, so
	 * the uHID device is created right away and only the notifications
	 * need to be enabled again.
	 */
	define_test("HOGP/RH/HGNF/BV-01-C [Report Characteristic "
			"Configuration, receive notifications] - Reconnect",
			setup_basic, &cfg_reattach,
			ATTACH, DISABLE_INPUT_CCC,
			READ_PROTO_MODE, READ_EXT_REPORT_REF, READ_INFO,
			ENABLE_INPUT_CCC,
			NOTIFY(0x0c, INPUT_REPORT));
	define_test("HOGP/RH/HGNF/BI-01-C [Boot Keyboard Input Report "
			"Characteristic Configuration, ignore notifications, "
			"Report Host]",
			setup_basic, &cfg_notify,
			ATTACH,
			IOV_DATA(0x1b, 0x16, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
					0x00, 0x00, 0x00),
			NOTIFY(0x0c, INPUT_REPORT));
	define_test("HOGP/RH/HGNF/BI-02-C [Boot Mouse Input Report "
			"Characteristic Configuration, ignore notifications, "
			"Report Host]",
			setup_basic, &cfg_notify,
			ATTACH,
			IOV_DATA(0x1b, 0x19, 0x00, 0x01, 0x02, 0x03),
			NOTIFY(0x0c, INPUT_REPORT));

	/* Characteristic GGIT, the discovery being done by bt_gatt_client */
	define_test("HOGP/RH/CGGIT/CHA/BV-01-C [Characteristic GGIT - Report "
			"Map - RH]",
			setup_basic, &cfg_attach,
			ATTACH);
	define_test("HOGP/RH/CGGIT/CHA/BV-02-C [Characteristic GGIT - HID "
			"Information - RH]",
			setup_basic, &cfg_none,
			READ_PROTO_MODE, READ_EXT_REPORT_REF, READ_INFO);
	define_test("HOGP/RH/CGGIT/CHA/BV-03-C [Characteristic GGIT - HID "
			"Control Point]",
			setup_basic, &cfg_resume,
			ATTACH, IOV_DATA(0x52, 0x0a, 0x00, 0x01));
	define_test("HOGP/RH/CGGIT/CHA/BV-04-C [Characteristic GGIT - "
			"Protocol Mode - RH]",
			setup_basic, &cfg_none,
			READ_PROTO_MODE);
	define_test("HOGP/RH/CGGIT/DES/BV-01-C [Descriptor GGIT - External "
			"Report Reference for Report Map]",
			setup_basic, &cfg_none,
			READ_PROTO_MODE, READ_EXT_REPORT_REF);
	define_test("HOGP/RH/CGGIT/CHA/BV-09-C [Characteristic GGIT - HID SCI "
			"Information]",
			setup_sci, &cfg_sci_attach,
			SCI_ATTACH);
	define_test("HOGP/RH/CGGIT/CHA/BV-10-C [Characteristic GGIT - HID SCI "
			"Mode]",
			setup_sci, &cfg_none,
			READ_PROTO_MODE, READ_EXT_REPORT_REF, READ_INFO_SCI,
			READ_INPUT, READ_INPUT_REF, READ_OUTPUT,
			READ_OUTPUT_REF, READ_FEATURE, READ_FEATURE_REF,
			READ_SCI_MODE, READ_SCI_INFO, ENABLE_SCI_MODE_CCC);

	return tester_run();
}
