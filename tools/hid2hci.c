/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2004  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <string.h>
#include <getopt.h>
#include <sys/ioctl.h>

static char usbpath[PATH_MAX + 1] = "/proc/bus/usb";

struct usb_device_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t bcdUSB;
	uint8_t  bDeviceClass;
	uint8_t  bDeviceSubClass;
	uint8_t  bDeviceProtocol;
	uint8_t  bMaxPacketSize0;
	uint16_t idVendor;
	uint16_t idProduct;
	uint16_t bcdDevice;
	uint8_t  iManufacturer;
	uint8_t  iProduct;
	uint8_t  iSerialNumber;
	uint8_t  bNumConfigurations;
} __attribute__ ((packed));

struct usb_ctrltransfer {
	uint8_t  bRequestType;
	uint8_t  bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;

	uint32_t timeout;	/* in milliseconds */
	void *data;		/* pointer to data */
};

#define IOCTL_USB_CONTROL	_IOWR('U', 0, struct usb_ctrltransfer)

#define USB_RECIP_DEVICE	0x00
#define USB_TYPE_VENDOR		0x40
#define USB_DIR_OUT		0x00

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
	uint16_t busnum;
	uint16_t devnum;
	struct device_id *id;
};

static int switch_hidproxy(struct device_info *dev)
{
	struct usb_ctrltransfer ctrl;
	char devname[PATH_MAX + 1];
	int fd, err;

	snprintf(devname, PATH_MAX, "%s/%03d/%03d",
					usbpath, dev->busnum, dev->devnum);

	fd = open(devname, O_RDWR);
	if (fd < 0)
		return fd;

	ctrl.bRequestType = USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE;
	ctrl.bRequest     = 0;
	ctrl.wValue       = dev->id->mode;
	ctrl.wIndex       = 0;
	ctrl.wLength      = 0;

	ctrl.data    = NULL;
	ctrl.timeout = 10000;

	err = ioctl(fd, IOCTL_USB_CONTROL, &ctrl);

	if (err == 0) {
		err = -1;
		errno = EALREADY;
	} else {
		if (errno == ETIMEDOUT)
			err = 0;
	}

	close(fd);

	return err;
}

static int send_report(int fd, const unsigned char *buf, size_t size)
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

static int switch_logitech(struct device_info *dev)
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
		if (err < 0 || dinfo.busnum != dev->busnum ||
				dinfo.devnum != dev->devnum) {
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
	{ HCI, 0x05ac, 0x1000, switch_hidproxy },
	{ HID, 0x05ac, 0x8203, switch_hidproxy },
	{ HCI, 0x046d, 0xc703, switch_logitech },
	{ HCI, 0x046d, 0xc704, switch_logitech },
	{ HCI, 0x046d, 0xc705, switch_logitech },
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

static int find_devices(int mode, struct device_info *dev, size_t size)
{
	DIR *busdir, *devdir;
	struct dirent *entry;
	struct usb_device_descriptor desc;
	struct device_id *id;
	int fd, len, busnum, devnum, count = 0;
	char buspath[PATH_MAX + 1];
	char devname[PATH_MAX + 1];

	if (!(busdir = opendir(usbpath)))
		return -1;

	while ((entry = readdir(busdir))) {
		if (entry->d_name[0] == '.')
			continue;

		if (!strchr("0123456789",
				entry->d_name[strlen(entry->d_name) - 1]))
			continue;

		busnum = atoi(entry->d_name);
		snprintf(buspath, PATH_MAX, "%s/%s", usbpath, entry->d_name);
		if (!(devdir = opendir(buspath)))
			continue;

		while ((entry = readdir(devdir))) {
			if (entry->d_name[0] == '.')
				continue;

			if (!strchr("0123456789",
					entry->d_name[strlen(entry->d_name) - 1]))
				continue;

			devnum = atoi(entry->d_name);
			snprintf(devname, PATH_MAX, "%s/%s",
							buspath, entry->d_name);

			if ((fd = open(devname, O_RDONLY)) < 0)
				continue;

			len = read(fd, &desc, sizeof(desc));
			if (len < 0 || len != sizeof(desc))
				continue;

			id = match_device(mode, desc.idVendor, desc.idProduct);
			if (!id)
				continue;

			if (count < size) {
				dev[count].busnum  = busnum;
				dev[count].devnum  = devnum;
				dev[count].id = id;
				count++;
			}
		}

		closedir(devdir);
	}

	closedir(busdir);

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
		"\t-0, --tohci          Switch to HCI mode (default)\n"
		"\t-1, --tohid          Switch to HID mode\n"
		"\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "tohci",	0, 0, '0' },
	{ "tohid",	0, 0, '1' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct device_info dev[16];
	int i, opt, num, mode = HCI;

	while ((opt = getopt_long(argc, argv, "+01h", main_options, NULL)) != -1) {
		switch (opt) {
		case '0':
			mode = HCI;
			break;
		case '1':
			mode = HID;
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

	num = find_devices(mode, dev, sizeof(dev) / sizeof(dev[0]));
	if (num <= 0) {
		fprintf(stderr, "No devices in %s mode found\n",
						mode ? "HID" : "HCI");
		exit(1);
	}

	for (i = 0; i < num; i++) {
		struct device_id *id = dev[i].id;

		printf("Switching device %04x:%04x to %s mode ",
			id->vendor, id->product, mode ? "HID" : "HCI");
		fflush(stdout);

		if (id->func(&dev[i]) < 0)
			printf("failed (%s)\n", strerror(errno));
		else
			printf("was successful\n");
	}

	return 0;
}
