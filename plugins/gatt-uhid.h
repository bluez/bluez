/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Generic GATT-to-UHID bridge
 *  Bridges a BLE GATT service to the kernel HID subsystem via /dev/uhid.
 *
 *  GATT notifications are forwarded as HID input reports; ble->bluez->uhid
 *  HID output reports are forwarded back as GATT writes; hid->bluez->ble
 *
 *  The bridge is device-agnostic — all protocol knowledge lives in the
 *  kernel HID driver that claims the uhid device by vendor/product ID.
 *
 *  This lets the kernel driver identify which characteristic produced
 *  each input report, and target specific handles for output writes.
 */

#include <stdint.h>
#include <stdbool.h>

struct gatt_uhid;
struct bt_gatt_client;

/*
 * Device specific plugins provide a gatt_uhid_params to
 * configure the bridge.
 *
 * All GATT handles are value handles (not CCCD handles).
 */
struct gatt_uhid_params {
	const char *name; /* Shown device name */
	uint16_t vendor;  /* Vendor ID like USB VID. Use this to match */
	uint16_t product; /* Product ID like USB PID. Use this to match */
	uint16_t version;

	uint16_t *notify_handles;  /* array of notification value handles */
	unsigned int notify_count; /* number of entries in notify_handles */

	/* Max payload sizes (excluding report ID and 2-byte handle prefix).*/
	uint16_t input_size;  /* size of a notification from BLE */
	uint16_t output_size; /* size of an output from HID */
};

/*
 * Create a GATT-UHID bridge.  Opens /dev/uhid, creates the device,
 * and subscribes to the specified GATT notification handles.
 * Returns NULL on failure.
 */
struct gatt_uhid *gatt_uhid_new(struct bt_gatt_client *client,
				const struct gatt_uhid_params *params);

/*
 * Destroy the bridge — unsubscribes GATT notifications, sends
 * UHID_DESTROY, and frees resources.
 */
void gatt_uhid_free(struct gatt_uhid *bridge);
