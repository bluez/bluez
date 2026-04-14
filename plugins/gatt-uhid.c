// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Generic GATT-to-UHID bridge
 *  Bridges a BLE GATT service to the kernel HID subsystem via /dev/uhid.
 *
 *  Report format (both directions):
 *    byte 0:    HID report ID (0x01)
 *    byte 1-2:  GATT handle, little-endian
 *    byte 3+:   payload
 *
 *  Input:  bridge prepends [report_id][handle_lo][handle_hi] to the raw
 *          GATT notification payload.
 *  Output: bridge reads [report_id][handle_lo][handle_hi] from the HID
 *          output report and writes the remaining payload to that GATT
 *          handle via write-without-response.
 *
 *  The HID report descriptor uses a vendor-defined usage page with a
 *  single input and output report, each sized for the 2-byte handle
 *  prefix plus the maximum payload.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/uhid.h>

#include <glib.h>

#include "src/log.h"
#include "src/shared/att.h"
#include "src/shared/gatt-client.h"
#include "src/shared/util.h"

#include "plugins/gatt-uhid.h"

#define GATT_UHID_REPORT_ID	0x01

/* Handle prefix overhead added to every report */
#define GATT_UHID_HANDLE_SIZE	2

/*
 * The struct representing a GATT_UHID-Bridge.
 */
struct gatt_uhid {
	struct bt_gatt_client *client;

	int fd; /* /dev/uhid file descriptor */
	guint watch_id; /* GLib I/O watch for UHID_OUTPUT */

	unsigned int *notify_ids; /* registered GATT notify IDs */
	unsigned int notify_count;

	unsigned int cccd_pending; /* CCCDs not yet confirmed */
};


/*
 * A prototypical HID report descriptor.
 *
 * One input and one output report, each sized for the 2-byte handle
 * prefix plus the maximum payload.  The two Report Count fields
 * (marked 0x00, 0x00) are patched at runtime.
 */
static const uint8_t hid_desc_template[] = {
	0x06, 0x00, 0xff, /* Usage Page; Vendor Defined; no hid-generic */
	0x09, 0x01, /* Usage; we are a vendor */
	0xa1, 0x01, /* Collection; <hid_descriptor> */

	/* Input report */
	0x85, GATT_UHID_REPORT_ID,
	0x09, 0x01,		/* Usage */
	0x15, 0x00,		/* Logical Minimum (0) */
	0x26, 0xff, 0x00,	/* Logical Maximum (255) */
	0x75, 0x08,		/* Report Size (8) */
	0x96, 0x00, 0x00,	/* Put max input size here! */
	0x81, 0x02,		/* Input (Data, Variable, Absolute) */

	/* Output report */
	0x85, GATT_UHID_REPORT_ID,
	0x09, 0x02,		/* Usage */
	0x75, 0x08,		/* Report Size (8) */
	0x96, 0x00, 0x00,	/* Put max output size here! */
	0x91, 0x02,		/* Output (Data, Variable, Absolute) */

	0xc0,			/* End Collection; </hid_descriptor> */
};

/* Offsets used to put device max sizes into hid_desc_template */
#define HID_DESC_MAX_INPUT_OFFSET 19
#define HID_DESC_MAX_OUTPUT_OFFSET 30

static size_t build_hid_descriptor(uint8_t *buf, uint16_t input_size,
							uint16_t output_size)
{
	uint16_t in_total = GATT_UHID_HANDLE_SIZE + input_size;
	uint16_t out_total = GATT_UHID_HANDLE_SIZE + output_size;

	memcpy(buf, hid_desc_template, sizeof(hid_desc_template));

	/* little endian! */
	buf[HID_DESC_MAX_INPUT_OFFSET] = in_total & 0xff;
	buf[HID_DESC_MAX_INPUT_OFFSET + 1] = (in_total >> 8) & 0xff;

	buf[HID_DESC_MAX_OUTPUT_OFFSET] = out_total & 0xff;
	buf[HID_DESC_MAX_OUTPUT_OFFSET + 1] = (out_total >> 8) & 0xff;

	return sizeof(hid_desc_template);
}

/* Create device using params from device specific plugin */
static int uhid_create(const struct gatt_uhid_params *params)
{
	struct uhid_event ev = {};
	uint8_t hid_desc[128];
	size_t hid_desc_len;
	int fd;

	fd = open("/dev/uhid", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		error("gatt-uhid: open /dev/uhid: %s", strerror(errno));
		return -1;
	}

	hid_desc_len = build_hid_descriptor(hid_desc,
					params->input_size,
					params->output_size);

	ev.type = UHID_CREATE2;
	ev.u.create2.bus = BUS_BLUETOOTH;
	ev.u.create2.vendor = params->vendor;
	ev.u.create2.product = params->product;
	ev.u.create2.version = params->version;
	ev.u.create2.country = 0;
	ev.u.create2.rd_size = hid_desc_len;
	strncpy((char *) ev.u.create2.name, params->name, 127);
	memcpy(ev.u.create2.rd_data, hid_desc, hid_desc_len);

	if (write(fd, &ev, sizeof(ev)) < 0) {
		error("gatt-uhid: UHID_CREATE2: %s", strerror(errno));
		close(fd);
		return -1;
	}

	DBG("gatt-uhid: uhid device created (%s)", params->name);
	return fd;
}

/*
 * From HID to BLE device
 *
 * UHID_OUTPUT data from the kernel HID driver:
 *   byte 0-1:  GATT handle, little-endian
 *   byte 2+:   payload to write
 */
static gboolean uhid_output_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct gatt_uhid *bridge = user_data;
	struct uhid_event ev;
	uint16_t handle;
	ssize_t n;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		DBG("gatt-uhid: output_cb error/hup/nval cond=0x%x",
								(int) cond);
		bridge->watch_id = 0;
		return FALSE;
	}

	n = read(bridge->fd, &ev, sizeof(ev)); /* fetch the event */
	if (n < 0 || (size_t) n < sizeof(ev)) {
		DBG("gatt-uhid: output_cb read returned %zd", n);
		return TRUE;
	}

	DBG("gatt-uhid: output_cb event type=%u size=%u",
					ev.type, ev.u.output.size);

	if (ev.type != UHID_OUTPUT) {
		DBG("gatt-uhid: output_cb ignoring event type %u", ev.type);
		return TRUE;
	}

	if (!bridge->client) {
		DBG("gatt-uhid: output_cb no client");
		return TRUE;
	}

	/* Need at least the 2-byte handle prefix */
	if (ev.u.output.size < GATT_UHID_HANDLE_SIZE) {
		DBG("gatt-uhid: output_cb too short: %u", ev.u.output.size);
		return TRUE;
	}

	handle = ev.u.output.data[0] | ((uint16_t) ev.u.output.data[1] << 8);

	if (!handle) {
		DBG("gatt-uhid: output_cb handle is zero");
		return TRUE;
	}

	bt_gatt_client_write_without_response(bridge->client,
				handle, false,
				ev.u.output.data + GATT_UHID_HANDLE_SIZE,
				ev.u.output.size - GATT_UHID_HANDLE_SIZE);
	return TRUE;
}


/*
 * From BLE device to HID
 *
 * Input report format to kernel HID driver:
 *   byte 0:    report ID (0x01)
 *   byte 1-2:  GATT handle, little-endian
 *   byte 3+:   raw notification payload
 */
static void notify_cb(uint16_t value_handle, const uint8_t *value,
			uint16_t length, void *user_data)
{
	struct gatt_uhid *bridge = user_data;
	struct uhid_event ev = {};

	if (length == 0 || bridge->fd < 0)
		return;

	/* Don't forward until all CCCDs are confirmed, so we don't have
	 * to deal with **some** available handles. */
	if (bridge->cccd_pending)
		return;

	ev.type = UHID_INPUT2;
	ev.u.input2.size = 1 + GATT_UHID_HANDLE_SIZE + length;
	ev.u.input2.data[0] = GATT_UHID_REPORT_ID;
	ev.u.input2.data[1] = value_handle & 0xff;
	ev.u.input2.data[2] = (value_handle >> 8) & 0xff;
	memcpy(&ev.u.input2.data[3], value, length);

	if (write(bridge->fd, &ev, sizeof(ev)) < 0)
		error("gatt-uhid: uhid write: %s", strerror(errno));
}

/* We can react to every single subscription on_registered */
static void notify_registered_cb(uint16_t att_ecode, void *user_data)
{
	struct gatt_uhid *bridge = user_data;

	if (att_ecode) {
		error("gatt-uhid: notify registration failed: 0x%04x",
								att_ecode);
	}

	if (bridge->cccd_pending > 0)
		bridge->cccd_pending--;

	if (bridge->cccd_pending == 0)
		DBG("gatt-uhid: all %u CCCDs confirmed, forwarding input",
						bridge->notify_count);
}

/*
 * Public API
 */

struct gatt_uhid *gatt_uhid_new(struct bt_gatt_client *client,
				const struct gatt_uhid_params *params)
{
	struct gatt_uhid *bridge;
	GIOChannel *io;
	unsigned int c;

	if (!client || !params || !params->notify_count)
		return NULL;

	/* Create bridge */
	bridge = g_new0(struct gatt_uhid, 1);
	bridge->client = client;
	bridge->notify_count = params->notify_count;
	bridge->notify_ids = g_new0(unsigned int, params->notify_count);

	bridge->fd = uhid_create(params); /* Create hid device */
	if (bridge->fd < 0) {
		g_free(bridge->notify_ids);
		g_free(bridge);
		return NULL;
	}

	/* Watch for UHID_OUTPUT events (commands from kernel HID driver) */
	io = g_io_channel_unix_new(bridge->fd);
	g_io_channel_set_encoding(io, NULL, NULL);
	g_io_channel_set_buffered(io, FALSE);
	bridge->watch_id = g_io_add_watch(io, G_IO_IN | G_IO_ERR | G_IO_HUP,
							uhid_output_cb, bridge);
	g_io_channel_unref(io);

	/* Subscribe to all GATT notification handles. */
	bridge->cccd_pending = params->notify_count;
	for (c = 0; c < params->notify_count; c++) {
		bridge->notify_ids[c] = bt_gatt_client_register_notify(
					client,
					params->notify_handles[c],
					notify_registered_cb,
					notify_cb,
					bridge, NULL);
		if (!bridge->notify_ids[c])
			error("gatt-uhid: failed to register notify "
				"for handle 0x%04x", params->notify_handles[c]);
	}

	return bridge;
}

void gatt_uhid_free(struct gatt_uhid *bridge)
{
	struct uhid_event ev = {};
	unsigned int c;

	if (!bridge)
		return;

	for (c = 0; c < bridge->notify_count; c++) {
		if (bridge->notify_ids[c] && bridge->client)
			bt_gatt_client_unregister_notify(bridge->client,
						bridge->notify_ids[c]);
	}

	if (bridge->watch_id)
		g_source_remove(bridge->watch_id);

	if (bridge->fd >= 0) {
		ev.type = UHID_DESTROY;
		if (write(bridge->fd, &ev, sizeof(ev)) < 0)
			error("gatt-uhid: UHID_DESTROY: %s", strerror(errno));
		close(bridge->fd);
	}

	g_free(bridge->notify_ids);
	g_free(bridge);
}
