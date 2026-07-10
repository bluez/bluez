/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Gamepad Quirk Support
 *
 *  DualShock 4 (CUH-ZCT2x) / TG170W gamepad quirk.
 *
 *  This controller identifies as a DualShock 4 compatible device and
 *  works perfectly via USB. Over Bluetooth it exposes an incomplete
 *  or malformed HID SDP record, causing BlueZ to fail with -ENOENT.
 *
 *  Windows and Android handle this gracefully; Linux/BlueZ does not.
 *  This quirk injects the correct BT HID report descriptor so the
 *  kernel's hid-playstation driver can create an input device.
 *
 *  Matching criteria (multi-factor, no single-field matching):
 *    - Bluetooth device name + SDP provider
 *    - Vendor/Product ID from device info
 *
 *  BT report descriptor constructed from kernel hid-playstation.c:
 *    DS4_INPUT_REPORT_BT = 0x11, size = 78 bytes
 *    DS4_OUTPUT_REPORT_BT = 0x11, size = 78 bytes
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/hidp.h"
#include "bluetooth/sdp.h"
#include "bluetooth/sdp_lib.h"

#include "src/log.h"

#include "../quirk.h"

/*
 * DualShock 4 Bluetooth HID Report Descriptor.
 *
 * The USB descriptor (report ID 0x01, 64 bytes) does NOT work over
 * Bluetooth. The DS4 sends 78-byte packets with report ID 0x11 on BT.
 * The kernel's hid-playstation driver expects exactly this format.
 *
 * This descriptor tells the HID core to accept report ID 0x11 packets
 * and route them to the driver's parse_report callback. The driver
 * creates input devices programmatically -- it doesn't need field-level
 * mappings in the descriptor.
 *
 * Report layout (from hid-playstation.c):
 *   0x11 Input:  78 bytes total (1 ID + 77 data)
 *   0x11 Output: 78 bytes total (1 ID + 77 data, rumble/LED)
 *   0x05 Feature: 41 bytes (gyro/accel calibration)
 *   0x12 Feature: 16 bytes (pairing info / MAC address)
 *   0xa3 Feature: 49 bytes (firmware info)
 */
static const uint8_t tg170w_hid_report_descriptor[] = {
	/* Usage Page (Generic Desktop), Usage (Gamepad), Collection (Application) */
	0x05, 0x01, 0x09, 0x05, 0xa1, 0x01,

	/*
	 * Report ID 0x11 -- BT Enhanced Input Report
	 * 78 bytes total = 1 byte ID + 77 bytes payload
	 * Contains: sticks, buttons, gyro, accel, timestamp, touchpad, CRC
	 */
	0x85, 0x11,        /* Report ID (0x11) */
	0x06, 0x00, 0xff,  /* Usage Page (Vendor Defined 0xFF00) */
	0x09, 0x20,        /* Usage (0x20) */
	0x15, 0x00,        /* Logical Minimum (0) */
	0x26, 0xff, 0x00,  /* Logical Maximum (255) */
	0x75, 0x08,        /* Report Size (8) */
	0x95, 0x4d,        /* Report Count (77) */
	0x81, 0x02,        /* Input (Data, Var, Abs) */

	/*
	 * Report ID 0x11 -- BT Output Report
	 * 78 bytes total = 1 byte ID + 77 bytes payload
	 * Used for: rumble motors, lightbar RGB, player LEDs
	 */
	0x85, 0x11,        /* Report ID (0x11) */
	0x09, 0x21,        /* Usage (0x21) */
	0x95, 0x4d,        /* Report Count (77) */
	0x91, 0x02,        /* Output (Data, Var, Abs) */

	/*
	 * Report ID 0x05 -- Calibration Feature Report (41 bytes)
	 * Gyroscope and accelerometer calibration data
	 */
	0x85, 0x05,        /* Report ID (0x05) */
	0x09, 0x22,        /* Usage (0x22) */
	0x95, 0x29,        /* Report Count (41) */
	0xb1, 0x02,        /* Feature (Data, Var, Abs) */

	/*
	 * Report ID 0x12 -- Pairing Info Feature Report (16 bytes)
	 * Contains MAC address for device identification
	 */
	0x85, 0x12,        /* Report ID (0x12) */
	0x09, 0x23,        /* Usage (0x23) */
	0x95, 0x10,        /* Report Count (16) */
	0xb1, 0x02,        /* Feature (Data, Var, Abs) */

	/*
	 * Report ID 0xa3 -- Firmware Info Feature Report (49 bytes)
	 * Hardware/firmware version information
	 */
	0x85, 0xa3,        /* Report ID (0xa3) */
	0x09, 0x24,        /* Usage (0x24) */
	0x95, 0x31,        /* Report Count (49) */
	0xb1, 0x02,        /* Feature (Data, Var, Abs) */

	/* End Collection */
	0xc0
};

/* Sony DualShock 4 v2 (CUH-ZCT2x) */
#define TG170W_VID  0x054c  /* Sony */
#define TG170W_PID  0x09cc  /* DualShock 4 v2 */

/* Opaque structs - we don't pull in heavy headers */
struct input_device;
struct btd_device;
struct btd_service;

/* Declarations from src/device.h and src/service.h */
extern struct btd_service *input_device_get_service(
					struct input_device *idev);
extern struct btd_device *btd_service_get_device(
					const struct btd_service *service);
extern uint16_t btd_device_get_vendor(struct btd_device *device);
extern uint16_t btd_device_get_product(struct btd_device *device);
extern const sdp_record_t *btd_device_get_record(
					struct btd_device *device,
					const char *uuid);
extern bool device_name_known(struct btd_device *device);
extern void device_get_name(struct btd_device *device,
					char *name, size_t len);

static bool tg170w_match(struct input_device *idev)
{
	struct btd_service *service;
	struct btd_device *device;
	char name[248];
	uint16_t vendor, product;
	const sdp_record_t *rec;
	sdp_data_t *pdlist;

	if (!idev)
		return false;

	service = input_device_get_service(idev);
	if (!service)
		return false;

	device = btd_service_get_device(service);
	if (!device)
		return false;

	/* Check vendor/product ID from device info */
	vendor = btd_device_get_vendor(device);
	product = btd_device_get_product(device);

	/* Match by VID/PID (Sony DS4 v2) */
	if (vendor == TG170W_VID && product == TG170W_PID) {
		DBG("TG170W quirk: matched by VID/PID %04x:%04x",
							vendor, product);
		return true;
	}

	/* Match by name + SDP provider */
	if (!device_name_known(device))
		return false;

	device_get_name(device, name, sizeof(name));

	if (strcmp(name, "Wireless Controller"))
		return false;

	/* Additional check: look for Sony in SDP provider */
	rec = btd_device_get_record(device,
			"00001124-0000-1000-8000-00805f9b34fb");
	if (!rec)
		return false;

	pdlist = sdp_data_get(rec, SDP_ATTR_PROVNAME_PRIMARY);
	if (!pdlist || !pdlist->val.str)
		return false;

	if (!strstr(pdlist->val.str, "Sony"))
		return false;

	DBG("TG170W quirk: matched by name + provider");
	return true;
}

static int tg170w_apply(struct input_device *idev,
			struct hidp_connadd_req *req)
{
	/*
	 * HID parser version 1.11 per Bluetooth HID spec.
	 * The playstation kernel driver doesn't inspect this value,
	 * but it should be valid for proper HID core behavior.
	 */
	req->parser = 0x0111;
	req->country = 0;
	req->subclass = 0;

	/* Inject the Bluetooth HID report descriptor */
	req->rd_size = sizeof(tg170w_hid_report_descriptor);
	req->rd_data = malloc(req->rd_size);
	if (!req->rd_data)
		return -ENOMEM;

	memcpy(req->rd_data, tg170w_hid_report_descriptor, req->rd_size);

	DBG("TG170W: injected %u byte BT HID descriptor", req->rd_size);

	return 0;
}

struct gamepad_quirk tg170w_quirk = {
	.name = "TG170W",
	.match = tg170w_match,
	.apply = tg170w_apply,
};
