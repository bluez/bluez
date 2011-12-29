/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  David Herrmann <dh.herrmann@googlemail.com>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <bluetooth/bluetooth.h>

#include "plugin.h"
#include "adapter.h"
#include "device.h"
#include "log.h"
#include "storage.h"

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

static ssize_t wii_pincb(struct btd_adapter *adapter, struct btd_device *device,
								char *pinbuf)
{
	uint16_t vendor, product;
	bdaddr_t sba, dba;
	char addr[18];

	adapter_get_address(adapter, &sba);
	device_get_address(device, &dba, NULL);
	ba2str(&dba, addr);

	vendor = btd_device_get_vendor(device);
	if (vendor != 0x057e)
		return 0;

	product = btd_device_get_product(device);
	if (product == 0x0306) {
		DBG("Forcing fixed pin on detected wiimote %s", addr);
		memcpy(pinbuf, &sba, 6);
		return 6;
	}

	return 0;
}

static int wii_probe(struct btd_adapter *adapter)
{
	btd_adapter_register_pin_cb(adapter, wii_pincb);

	return 0;
}

static void wii_remove(struct btd_adapter *adapter)
{
	btd_adapter_unregister_pin_cb(adapter, wii_pincb);
}

static struct btd_adapter_driver wii_driver = {
	.name	= "wiimote",
	.probe	= wii_probe,
	.remove	= wii_remove,
};

static int wii_init(void)
{
	return btd_register_adapter_driver(&wii_driver);
}

static void wii_exit(void)
{
	btd_unregister_adapter_driver(&wii_driver);
}

BLUETOOTH_PLUGIN_DEFINE(wiimote, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_LOW, wii_init, wii_exit)
