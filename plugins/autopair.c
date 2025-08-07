// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012 Google Inc.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/sdp.h"

#include "src/plugin.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/log.h"
#include "src/storage.h"
#include "src/shared/util.h"

/*
 * Nintendo Wii Remote devices require the bdaddr of the host as pin input for
 * authentication. This plugin registers a pin-callback and forces this pin
 * to be used for authentication.
 *
 * There are two ways to place the wiimote into discoverable mode.
 *  - Pressing the red-sync button on the back of the wiimote. This module
 *    supports pairing via this method. Auto-reconnect should be possible after
 *    the device was paired once.
 *  - Pressing the 1+2 buttons on the front of the wiimote. This module does
 *    not support this method since this method never enables auto-reconnect.
 *    Hence, pairing is not needed. Use it without pairing if you want.
 * After connecting the wiimote you should immediately connect to the input
 * service of the wiimote. If you don't, the wiimote will close the connection.
 * The wiimote waits about 5 seconds until it turns off again.
 * Auto-reconnect is only enabled when pairing with the wiimote via the red
 * sync-button and then connecting to the input service. If you do not connect
 * to the input service, then auto-reconnect is not enabled.
 * If enabled, the wiimote connects to the host automatically when any button
 * is pressed.
 */

static uint16_t wii_ids[][2] = {
	{ 0x057e, 0x0306 },		/* 1st gen */
	{ 0x054c, 0x0306 },		/* LEGO wiimote */
	{ 0x057e, 0x0330 },		/* 2nd gen */
};

static const char *wii_names[] = {
	"Nintendo RVL-CNT-01",		/* 1st gen */
	"Nintendo RVL-CNT-01-TR",	/* 2nd gen */
	"Nintendo RVL-CNT-01-UC",	/* Wii U Pro Controller */
	"Nintendo RVL-WBC-01",		/* Balance Board */
};

static ssize_t wii_pincb(struct btd_adapter *adapter, struct btd_device *device,
						char *pinbuf, bool *display,
						unsigned int attempt)
{
	uint16_t vendor, product;
	char addr[18], name[25];
	unsigned int i;

	/* Only try the pin code once per device. If it's not correct then it's
	 * an unknown device.
	 */
	if (attempt > 1)
		return 0;

	ba2str(device_get_address(device), addr);

	vendor = btd_device_get_vendor(device);
	product = btd_device_get_product(device);

	device_get_name(device, name, sizeof(name));

	for (i = 0; i < G_N_ELEMENTS(wii_ids); ++i) {
		if (vendor == wii_ids[i][0] && product == wii_ids[i][1])
			goto found;
	}

	for (i = 0; i < G_N_ELEMENTS(wii_names); ++i) {
		if (g_str_equal(name, wii_names[i]))
			goto found;
	}

	return 0;

found:
	DBG("Forcing fixed pin on detected wiimote %s", addr);
	memcpy(pinbuf, btd_adapter_get_address(adapter), 6);
	return 6;
}

/*
 * Plugin to handle automatic pairing of devices with reduced user
 * interaction, including implementing the recommendation of the HID spec
 * for keyboard devices.
 *
 * The plugin works by intercepting the PIN request for devices; if the
 * device is a keyboard a random six-digit numeric PIN is generated and
 * returned, flagged for displaying using DisplayPinCode.
 *
 */

static ssize_t autopair_pincb(struct btd_adapter *adapter,
						struct btd_device *device,
						char *pinbuf, bool *display,
						unsigned int attempt)
{
	char addr[18];
	char pinstr[7];
	char name[25];
	uint32_t class;
	uint32_t val;
	ssize_t ret;

	/* Try with the wii_pincb first */
	ret = wii_pincb(adapter, device, pinbuf, display, attempt);
	if (ret > 0)
		return ret;

	ba2str(device_get_address(device), addr);

	class = btd_device_get_class(device);

	device_get_name(device, name, sizeof(name));

	DBG("device '%s' (%s) class: 0x%x vid/pid: 0x%X/0x%X",
		name, addr, class,
		btd_device_get_vendor (device),
		btd_device_get_product (device));

	/* The iCade shouldn't use random PINs like normal keyboards */
	if (strstr(name, "iCade") != NULL)
		return 0;

	/* This is a class-based pincode guesser. Ignore devices with an
	 * unknown class.
	 */
	if (class == 0)
		return 0;

	switch ((class & 0x1f00) >> 8) {
	case 0x04:		/* Audio/Video */
		switch ((class & 0xfc) >> 2) {
		case 0x01:		/* Wearable Headset Device */
		case 0x02:		/* Hands-free Device */
		case 0x06:		/* Headphones */
		case 0x07:		/* Portable Audio */
		case 0x0a:		/* HiFi Audio Device */
			{
				const char *pincodes[] = {
					"0000",
					"1234",
					"1111"
				};
				const char *pincode;

				if (attempt > G_N_ELEMENTS(pincodes))
					return 0;
				pincode = pincodes[attempt - 1];
				memcpy(pinbuf, pincode, strlen(pincode));
				return strlen(pincode);
			}
		}
		break;

	case 0x05:		/* Peripheral */
		switch ((class & 0xc0) >> 6) {
		case 0x00:
			switch ((class & 0x1e) >> 2) {
			case 0x01:	/* Joystick */
			case 0x02:	/* Gamepad */
			case 0x03:	/* Remote Control */
				if (attempt > 1)
					return 0;
				memcpy(pinbuf, "0000", 4);
				return 4;
			}

			break;
		case 0x01:		/* Keyboard */
		case 0x03:		/* Combo keyboard/pointing device */
			/* For keyboards rejecting the first random code
			 * in less than 500ms, try a fixed code. */
			if (attempt > 1 &&
				device_bonding_last_duration(device) < 500) {
				/* Don't try more than one dumb code */
				if (attempt > 2)
					return 0;
				/* Try "0000" as the code for the second
				 * attempt. */
				memcpy(pinbuf, "0000", 4);
				return 4;
			}

			/* Never try more than 3 random pincodes. */
			if (attempt >= 4)
				return 0;

			if (util_getrandom(&val, sizeof(val), 0) < 0) {
				error("Failed to get a random pincode");
				return 0;
			}
			snprintf(pinstr, sizeof(pinstr), "%06u",
						val % 1000000);
			*display = true;
			memcpy(pinbuf, pinstr, 6);
			return 6;

		case 0x02: /* Pointing device */
			if (attempt > 1)
				return 0;
			memcpy(pinbuf, "0000", 4);
			return 4;
		}

		break;
	case 0x06:		/* Imaging */
		if (class & 0x80) {	/* Printer */
			if (attempt > 1)
				return 0;
			memcpy(pinbuf, "0000", 4);
			return 4;
		}
		break;
	}

	return 0;
}


static int autopair_probe(struct btd_adapter *adapter)
{
	btd_adapter_register_pin_cb(adapter, autopair_pincb);

	return 0;
}

static void autopair_remove(struct btd_adapter *adapter)
{
	btd_adapter_unregister_pin_cb(adapter, autopair_pincb);
}

static struct btd_adapter_driver autopair_driver = {
	.name = "autopair",
	.probe = autopair_probe,
	.remove = autopair_remove,
};

static int autopair_init(void)
{
	/* Initialize the random seed from /dev/urandom */
	unsigned int seed;
	int fd, err;
	ssize_t n;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		err = -errno;
		error("Failed to open /dev/urandom: %s (%d)", strerror(-err),
									-err);
		return err;
	}

	n = read(fd, &seed, sizeof(seed));
	if (n < (ssize_t) sizeof(seed)) {
		err = (n == -1) ? -errno : -EIO;
		error("Failed to read %zu bytes from /dev/urandom: %s (%d)",
					sizeof(seed), strerror(-err), -err);
		close(fd);
		return err;
	}

	close(fd);

	srand(seed);

	return btd_register_adapter_driver(&autopair_driver);
}

static void autopair_exit(void)
{
	btd_unregister_adapter_driver(&autopair_driver);
}

BLUETOOTH_PLUGIN_DEFINE(autopair, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
						autopair_init, autopair_exit)
