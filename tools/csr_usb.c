/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <usb.h>

#include "csr.h"

#ifdef NEED_USB_GET_BUSSES
static inline struct usb_bus *usb_get_busses(void)
{
	return usb_busses;
}
#endif

#ifdef NEED_USB_INTERRUPT_READ
static inline int usb_interrupt_read(usb_dev_handle *dev, int ep, char *bytes, int size, int timeout)
{
	return usb_bulk_read(dev, ep, bytes, size, timeout);
}
#endif

#ifndef USB_DIR_OUT
#define USB_DIR_OUT	0x00
#endif

static uint16_t seqnum = 0x0000;

static struct usb_dev_handle *udev = NULL;

int csr_open_usb(char *device)
{
	struct usb_bus *bus;
	struct usb_device *dev;

	usb_init();

	usb_find_busses();
	usb_find_devices();

	for (bus = usb_get_busses(); bus; bus = bus->next) {
		for (dev = bus->devices; dev; dev = dev->next) {
			if (dev->descriptor.bDeviceClass == USB_CLASS_HUB)
				continue;

			if (dev->descriptor.idVendor != 0x0a12 ||
					dev->descriptor.idProduct != 0x0001)
				continue;

			goto found;
		}
	}

	fprintf(stderr, "Device not available\n");

	return -1;

found:
	udev = usb_open(dev);
	if (!udev) {
		fprintf(stderr, "Can't open device: %s (%d)\n",
						strerror(errno), errno);
		return -1;
	}

	if (usb_claim_interface(udev, 0) < 0) {
		fprintf(stderr, "Can't claim interface: %s (%d)\n",
						strerror(errno), errno);
		usb_close(udev);
		return -1;
	}

	return 0;
}

static int do_command(uint16_t command, uint16_t seqnum, uint16_t varid, uint8_t *value, uint16_t length)
{
	unsigned char cp[254], rp[254];
	uint8_t cmd[10];
	uint16_t size;
	int len, offset = 0;

	size = (length < 8) ? 9 : ((length + 1) / 2) + 5;

	cmd[0] = command & 0xff;
	cmd[1] = command >> 8;
	cmd[2] = size & 0xff;
	cmd[3] = size >> 8;
	cmd[4] = seqnum & 0xff;
	cmd[5] = seqnum >> 8;
	cmd[6] = varid & 0xff;
	cmd[7] = varid >> 8;
	cmd[8] = 0x00;
	cmd[9] = 0x00;

	memset(cp, 0, sizeof(cp));
	cp[0] = 0x00;
	cp[1] = 0xfc;
	cp[2] = (size * 2) + 1;
	cp[3] = 0xc2;
	memcpy(cp + 4, cmd, sizeof(cmd));
	memcpy(cp + 14, value, length);

	usb_interrupt_read(udev, 0x81, (void *) rp, sizeof(rp), 2);

	if (usb_control_msg(udev, USB_TYPE_CLASS | USB_DIR_OUT | USB_RECIP_DEVICE,
				0, 0, 0, (void *) cp, (size * 2) + 4, 1000) < 0)
		return -1;

	switch (varid) {
	case CSR_VARID_COLD_RESET:
	case CSR_VARID_WARM_RESET:
	case CSR_VARID_COLD_HALT:
	case CSR_VARID_WARM_HALT:
		return 0;
	}

	do {
		len = usb_interrupt_read(udev, 0x81,
			(void *) (rp + offset), sizeof(rp) - offset, 10);
		offset += len;
	} while (len > 0);

	if (rp[0] != 0xff || rp[2] != 0xc2) {
		errno = EIO;
		return -1;
	}

	if ((rp[11] + (rp[12] << 8)) != 0) {
		errno = ENXIO;
		return -1;
	}

	memcpy(value, rp + 13, length);

	return 0;
}

int csr_read_usb(uint16_t varid, uint8_t *value, uint16_t length)
{
	return do_command(0x0000, seqnum++, varid, value, length);
}

int csr_write_usb(uint16_t varid, uint8_t *value, uint16_t length)
{
	return do_command(0x0002, seqnum++, varid, value, length);
}

void csr_close_usb(void)
{
	usb_release_interface(udev, 0);
	usb_close(udev);
}
