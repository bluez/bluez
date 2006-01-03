/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <sys/ioctl.h>

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

static char devpath[PATH_MAX + 1] = "/dev";

struct hiddev_devinfo {
	unsigned int bustype;
	unsigned int busnum;
	unsigned int devnum;
	unsigned int ifnum;
	short vendor;
	short product;
	short version;
	unsigned num_applications;
};

struct hiddev_report_info {
	unsigned report_type;
	unsigned report_id;
	unsigned num_fields;
};

typedef __signed__ int __s32;

struct hiddev_usage_ref {
	unsigned report_type;
	unsigned report_id;
	unsigned field_index;
	unsigned usage_index;
	unsigned usage_code;
	__s32 value;
};

#define HIDIOCGDEVINFO		_IOR('H', 0x03, struct hiddev_devinfo)
#define HIDIOCINITREPORT	_IO('H', 0x05)
#define HIDIOCSREPORT		_IOW('H', 0x08, struct hiddev_report_info)
#define HIDIOCSUSAGE		_IOW('H', 0x0C, struct hiddev_usage_ref)

#define HID_REPORT_TYPE_OUTPUT	2

#define HCI 0
#define HID 1

struct device_info;

struct device_id {
	int mode;
	uint16_t vendor;
	uint16_t product;
	int (*func)(struct device_info *dev);
};

struct device_info {
	struct usb_device *dev;
	struct device_id *id;
};

static int switch_hidproxy(struct device_info *devinfo)
{
	struct usb_dev_handle *udev;
	int err;

	udev = usb_open(devinfo->dev);
	if (!udev)
		return -errno;

	err = usb_control_msg(udev, USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE,
				0, devinfo->id->mode, 0, NULL, 0, 10000);

	if (err == 0) {
		err = -1;
		errno = EALREADY;
	} else {
		if (errno == ETIMEDOUT)
			err = 0;
	}

	usb_close(udev);

	return err;
}

static int send_report(int fd, const char *buf, size_t size)
{
	struct hiddev_report_info rinfo;
	struct hiddev_usage_ref uref;
	int i, err;

	for (i = 0; i < size; i++) {
		memset(&uref, 0, sizeof(uref));
		uref.report_type = HID_REPORT_TYPE_OUTPUT;
		uref.report_id   = 0x10;
		uref.field_index = 0;
		uref.usage_index = i;
		uref.usage_code  = 0xff000001;
		uref.value       = buf[i];
		err = ioctl(fd, HIDIOCSUSAGE, &uref);
		if (err < 0)
			return err;
	}

	memset(&rinfo, 0, sizeof(rinfo));
	rinfo.report_type = HID_REPORT_TYPE_OUTPUT;
	rinfo.report_id   = 0x10;
	rinfo.num_fields  = 1;
	err = ioctl(fd, HIDIOCSREPORT, &rinfo);

	return err;
}

static int switch_logitech(struct device_info *devinfo)
{
	char devname[PATH_MAX + 1];
	int i, fd, err = -1;

	for (i = 0; i < 16; i++) {
		struct hiddev_devinfo dinfo;
		char rep1[] = { 0xff, 0x80, 0x80, 0x01, 0x00, 0x00 };
		char rep2[] = { 0xff, 0x80, 0x00, 0x00, 0x30, 0x00 };
		char rep3[] = { 0xff, 0x81, 0x80, 0x00, 0x00, 0x00 };

		sprintf(devname, "%s/hiddev%d", devpath, i);
		fd = open(devname, O_RDWR);
		if (fd < 0) {
			sprintf(devname, "%s/usb/hiddev%d", devpath, i);
			fd = open(devname, O_RDWR);
			if (fd < 0) {
				sprintf(devname, "%s/usb/hid/hiddev%d", devpath, i);
				fd = open(devname, O_RDWR);
				if (fd < 0)
					continue;
			}
		}

		memset(&dinfo, 0, sizeof(dinfo));
		err = ioctl(fd, HIDIOCGDEVINFO, &dinfo);
		if (err < 0 || dinfo.busnum != atoi(devinfo->dev->bus->dirname) ||
				dinfo.devnum != atoi(devinfo->dev->filename)) {
			close(fd);
			continue;
		}

		err = ioctl(fd, HIDIOCINITREPORT, 0);
		if (err < 0) {
			close(fd);
			break;
		}

		err = send_report(fd, rep1, sizeof(rep1));
		if (err < 0) {
			close(fd);
			break;
		}

		err = send_report(fd, rep2, sizeof(rep2));
		if (err < 0) {
			close(fd);
			break;
		}

		err = send_report(fd, rep3, sizeof(rep3));
		close(fd);
		break;
	}

	return err;
}

static struct device_id device_list[] = {
	{ HCI, 0x0a12, 0x1000, switch_hidproxy },
	{ HID, 0x0a12, 0x0001, switch_hidproxy },
	{ HCI, 0x0458, 0x1000, switch_hidproxy },
	{ HID, 0x0458, 0x003f, switch_hidproxy },
	{ HCI, 0x05ac, 0x1000, switch_hidproxy },
	{ HID, 0x05ac, 0x8203, switch_hidproxy },
	{ HCI, 0x046d, 0xc703, switch_logitech },
	{ HCI, 0x046d, 0xc704, switch_logitech },
	{ HCI, 0x046d, 0xc705, switch_logitech },
	{ HCI, 0x046d, 0x0b02, switch_logitech },	/* Logitech diNovo Media Desktop Laser */
	{ -1 }
};

static struct device_id *match_device(int mode, uint16_t vendor, uint16_t product)
{
	int i;

	for (i = 0; device_list[i].mode >= 0; i++) {
		if (mode != device_list[i].mode)
			continue;
		if (vendor == device_list[i].vendor &&
				product == device_list[i].product)
			return &device_list[i];
	}

	return NULL;
}

static int find_devices(int mode, struct device_info *devinfo, size_t size)
{
	struct usb_bus *bus;
	struct usb_device *dev;
	struct device_id *id;
	int count = 0;

	usb_find_busses();
	usb_find_devices();

	for (bus = usb_get_busses(); bus; bus = bus->next)
		for (dev = bus->devices; dev; dev = dev->next) {
			id = match_device(mode, dev->descriptor.idVendor,
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
	printf("hid2hci - Bluetooth HID to HCI mode switching utility\n\n");

	printf("Usage:\n"
		"\thid2hci [options]\n"
		"\n");

	printf("Options:\n"
		"\t-h, --help           Display help\n"
		"\t-q, --quiet          Don't display any messages\n"
		"\t-0, --tohci          Switch to HCI mode (default)\n"
		"\t-1, --tohid          Switch to HID mode\n"
		"\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "quiet",	0, 0, 'q' },
	{ "tohci",	0, 0, '0' },
	{ "tohid",	0, 0, '1' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct device_info dev[16];
	int i, opt, num, quiet = 0, mode = HCI;

	while ((opt = getopt_long(argc, argv, "+01qh", main_options, NULL)) != -1) {
		switch (opt) {
		case '0':
			mode = HCI;
			break;
		case '1':
			mode = HID;
			break;
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

	usb_init();

	num = find_devices(mode, dev, sizeof(dev) / sizeof(dev[0]));
	if (num <= 0) {
		if (!quiet)
			fprintf(stderr, "No devices in %s mode found\n",
							mode ? "HID" : "HCI");
		exit(1);
	}

	for (i = 0; i < num; i++) {
		struct device_id *id = dev[i].id;

		if (!quiet)
			printf("Switching device %04x:%04x to %s mode ",
				id->vendor, id->product, mode ? "HID" : "HCI");
		fflush(stdout);

		if (id->func(&dev[i]) < 0) {
			if (!quiet)
				printf("failed (%s)\n", strerror(errno));
		} else {
			if (!quiet)
				printf("was successful\n");
		}
	}

	return 0;
}
