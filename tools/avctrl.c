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
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include <usb.h>

#ifdef NEED_USB_GET_BUSSES
static inline struct usb_bus *usb_get_busses(void)
{
	return usb_busses;
}
#endif

#ifndef USB_DIR_OUT
#define USB_DIR_OUT	0x00
#endif

#ifndef USB_DIR_IN
#define USB_DIR_IN	0x80
#endif

#define HID_REQ_GET_REPORT	0x01
#define HID_REQ_GET_IDLE	0x02
#define HID_REQ_GET_PROTOCOL	0x03
#define HID_REQ_SET_REPORT	0x09
#define HID_REQ_SET_IDLE	0x0a
#define HID_REQ_SET_PROTOCOL	0x0b

struct device_info;

struct device_id {
	uint16_t vendor;
	uint16_t product;
	int (*func)(struct device_info *dev, int argc, char *argv[]);
};

struct device_info {
	struct usb_device *dev;
	struct device_id *id;
};

#define GET_STATE		0x01
#define GET_REMOTE_BDADDR	0x02
#define DISCOVER		0x03
#define SWITCH_TO_DFU		0x04
#define READ_CODEC		0x05

static int dongle_csr(struct device_info *devinfo, int argc, char *argv[])
{
	char buf[8];
	struct usb_dev_handle *udev;
	int err, intf = 2;

	memset(buf, 0, sizeof(buf));

	if (!strncasecmp(argv[0], "discover", 4))
		buf[0] = DISCOVER;
	else if (!strncasecmp(argv[0], "switch", 3))
		buf[0] = SWITCH_TO_DFU;
	else if (!strncasecmp(argv[0], "dfu", 3))
		buf[0] = SWITCH_TO_DFU;
	else
		return -EINVAL;

	udev = usb_open(devinfo->dev);
	if (!udev)
		return -errno;

	if (usb_claim_interface(udev, intf) < 0) {
		err = -errno;
		usb_close(udev);
		return err;
	}

	err = usb_control_msg(udev, USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
				HID_REQ_SET_REPORT, 0x03 << 8, intf, buf, sizeof(buf), 10000);

	if (err == 0) {
		err = -1;
		errno = EALREADY;
	} else {
		if (errno == ETIMEDOUT)
			err = 0;
	}

	usb_release_interface(udev, intf);
	usb_close(udev);

	return err;
}

static struct device_id device_list[] = {
	{ 0x0a12, 0x1004, dongle_csr },
	{ -1 }
};

static struct device_id *match_device(uint16_t vendor, uint16_t product)
{
	int i;

	for (i = 0; device_list[i].func; i++) {
		if (vendor == device_list[i].vendor &&
				product == device_list[i].product)
			return &device_list[i];
	}

	return NULL;
}

static int find_devices(struct device_info *devinfo, size_t size)
{
	struct usb_bus *bus;
	struct usb_device *dev;
	struct device_id *id;
	int count = 0;

	usb_find_busses();
	usb_find_devices();

	for (bus = usb_get_busses(); bus; bus = bus->next)
		for (dev = bus->devices; dev; dev = dev->next) {
			id = match_device(dev->descriptor.idVendor,
						dev->descriptor.idProduct);
			if (!id)
				continue;

			if (count < size) {
				devinfo[count].dev = dev;
				devinfo[count].id = id;
				count++;
			}
		}

	return count;
}

static void usage(void)
{
	printf("avctrl - Bluetooth Audio/Video control utility\n\n");

	printf("Usage:\n"
		"\tavctrl [options] <command>\n"
		"\n");

	printf("Options:\n"
		"\t-h, --help           Display help\n"
		"\t-q, --quiet          Don't display any messages\n"
		"\n");

	printf("Commands:\n"
		"\tdiscover         Simulate pressing the discover button\n"
		"\tswitch           Switch the dongle to DFU mode\n"
		"\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "quiet",	0, 0, 'q' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct device_info dev[16];
	int i, opt, num, quiet = 0;

	while ((opt = getopt_long(argc, argv, "+qh", main_options, NULL)) != -1) {
		switch (opt) {
		case 'q':
			quiet = 1;
			break;
		case 'h':
			usage();
			exit(0);
		default:
			exit(0);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		usage();
		exit(1);
	}

	usb_init();

	num = find_devices(dev, sizeof(dev) / sizeof(dev[0]));
	if (num <= 0) {
		if (!quiet)
			fprintf(stderr, "No Audio/Video devices found\n");
		exit(1);
	}

	for (i = 0; i < num; i++) {
		struct device_id *id = dev[i].id;
		int err;

		if (!quiet)
			printf("Selecting device %04x:%04x ",
						id->vendor, id->product);
		fflush(stdout);

		err = id->func(&dev[i], argc, argv);
		if (err < 0) {
			if (!quiet)
				printf("failed (%s)\n", strerror(-err));
		} else {
			if (!quiet)
				printf("was successful\n");
		}
	}

	return 0;
}
