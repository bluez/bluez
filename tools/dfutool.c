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
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <malloc.h>
#include <string.h>
#include <libgen.h>
#include <endian.h>
#include <byteswap.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <usb.h>

#include "dfu.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le16(d)  (d)
#define cpu_to_le32(d)  (d)
#define le16_to_cpu(d)  (d)
#define le32_to_cpu(d)  (d)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_le16(d)  bswap_16(d)
#define cpu_to_le32(d)  bswap_32(d)
#define le16_to_cpu(d)  bswap_16(d)
#define le32_to_cpu(d)  bswap_32(d)
#else
#error "Unknown byte order"
#endif

#ifdef NEED_USB_GET_BUSSES
static inline struct usb_bus *usb_get_busses(void)
{
	return usb_busses;
}
#endif

#ifndef USB_CLASS_WIRELESS
#define USB_CLASS_WIRELESS	0xe0
#endif

#ifndef USB_CLASS_APPLICATION
#define USB_CLASS_APPLICATION	0xfe
#endif

static int get_interface_number(struct usb_device *dev)
{
	int c, i, a;

	for (c = 0; c < dev->descriptor.bNumConfigurations; c++) {
		struct usb_config_descriptor *config = &dev->config[c];

		for (i = 0; i < config->bNumInterfaces; i++) {
			struct usb_interface *interface = &config->interface[i];

			for (a = 0; a < interface->num_altsetting; a++) {
				struct usb_interface_descriptor *desc = &interface->altsetting[a];

				if (desc->bInterfaceClass != USB_CLASS_APPLICATION)
					continue;
				if (desc->bInterfaceSubClass != 0x01)
					continue;
				if (desc->bInterfaceProtocol != 0x00)
					continue;

				return desc->bInterfaceNumber;
			}
		}
	}

	return -1;
}

static void print_device(struct usb_device *dev)
{
	printf("Bus %s Device %s: ID %04x:%04x Interface %d%s\n",
		dev->bus->dirname, dev->filename,
		dev->descriptor.idVendor, dev->descriptor.idProduct,
		get_interface_number(dev),
		dev->descriptor.bDeviceClass == USB_CLASS_APPLICATION ? " (DFU mode)" : "");
}

static struct usb_dev_handle *open_device(char *device, struct dfu_suffix *suffix)
{
	struct usb_bus *bus;
	struct usb_device *dev, *dfu_dev[10];
	struct usb_dev_handle *udev;
	struct dfu_status status;
	char str[8];
	int i, intf, sel, num = 0, try = 5, bus_id = -1, dev_id = -1;

	printf("Scanning USB busses ... ");
	fflush(stdout);

	usb_find_busses();
	usb_find_devices();

	for (bus = usb_get_busses(); bus; bus = bus->next) {
		if (bus_id > 0) {
			snprintf(str, sizeof(str) - 1, "%03i", bus_id);
			if (strcmp(str, bus->dirname))
				continue;
		}

		for (dev = bus->devices; dev; dev = dev->next) {
			if (bus_id > 0 && dev_id > 0) {
				snprintf(str, sizeof(str) - 1, "%03i", dev_id);
				if (strcmp(str, dev->filename))
					continue;
			}

			if (dev->descriptor.bDeviceClass == USB_CLASS_HUB)
				continue;

			if (num > 9 || get_interface_number(dev) < 0)
				continue;

			dfu_dev[num++] = dev;
		}
	}

	if (num < 1) {
		printf("\rCan't find any DFU devices\n");
		return NULL;
	}

	printf("\rAvailable devices with DFU support:\n\n");
	for (i = 0; i < num; i++) {
		printf("\t%2d) ", i + 1);
		print_device(dfu_dev[i]);
	}
	printf("\n");

	do {
		printf("\rSelect device (abort with 0): ");
		fflush(stdout);
		memset(str, 0, sizeof(str));
		fgets(str, sizeof(str) - 1, stdin);
		sel = atoi(str);
	} while (!isdigit(str[0]) || sel < 0 || sel > num );

	if (sel < 1)
		return NULL;

	sel--;
	intf = get_interface_number(dfu_dev[sel]);
	printf("\n");

	udev = usb_open(dfu_dev[sel]);
	if (!udev) {
		printf("Can't open device: %s (%d)\n", strerror(errno), errno);
		return NULL;
	}

	if (usb_claim_interface(udev, intf) < 0) {
		printf("Can't claim interface: %s (%d)\n", strerror(errno), errno);
		usb_close(udev);
		return NULL;
	}

	if (dfu_get_status(udev, intf, &status) < 0) {
		printf("Can't get status: %s (%d)\n", strerror(errno), errno);
		goto error;
	}

	if (status.bState == DFU_STATE_ERROR) {
		if (dfu_clear_status(udev, intf) < 0) {
			printf("Can't clear status: %s (%d)\n", strerror(errno), errno);
			goto error;
		}
		if (dfu_abort(udev, intf) < 0) {
			printf("Can't abort previous action: %s (%d)\n", strerror(errno), errno);
			goto error;
		}
		if (dfu_get_status(udev, intf, &status) < 0) {
			printf("Can't get status: %s (%d)\n", strerror(errno), errno);
			goto error;
		}
	}

	if (status.bState == DFU_STATE_DFU_IDLE) {
		if (suffix) {
			suffix->idVendor  = cpu_to_le16(0x0000);
			suffix->idProduct = cpu_to_le16(0x0000);
			suffix->bcdDevice = cpu_to_le16(0x0000);
		}
		return udev;
	}

	if (status.bState != DFU_STATE_APP_IDLE) {
		printf("Device is not idle, can't detach it (state %d)\n", status.bState);
		goto error;
	}

	printf("Switching device into DFU mode ... ");
	fflush(stdout);

	if (suffix) {
		suffix->idVendor  = cpu_to_le16(dfu_dev[sel]->descriptor.idVendor);
		suffix->idProduct = cpu_to_le16(dfu_dev[sel]->descriptor.idProduct);
		suffix->bcdDevice = cpu_to_le16(dfu_dev[sel]->descriptor.bcdDevice);
	}

	if (dfu_detach(udev, intf) < 0) {
		printf("\rCan't detach device: %s (%d)\n", strerror(errno), errno);
		goto error;
	}

	if (dfu_get_status(udev, intf, &status) < 0) {
		printf("\rCan't get status: %s (%d)\n", strerror(errno), errno);
		goto error;
	}

	if (status.bState != DFU_STATE_APP_DETACH) {
		printf("\rDevice is not in detach mode, try again\n");
		goto error;
	}

	usb_release_interface(udev, intf);
	usb_reset(udev);
	usb_close(udev);

	bus = dfu_dev[sel]->bus;
	num = 0;

	while (num != 1 && try-- > 0) {
		sleep(1);
		usb_find_devices();

		for (dev = bus->devices; dev; dev = dev->next) {
			if (dev->descriptor.bDeviceClass != USB_CLASS_APPLICATION)
				continue;

			if (suffix && dev->descriptor.idVendor != le16_to_cpu(suffix->idVendor))
				continue;

			if (num > 9 || get_interface_number(dev) != 0)
				continue;

			dfu_dev[num++] = dev;
		}
	}

	if (num != 1) {
		printf("\rCan't identify device with DFU mode\n");
		goto error;
	}

	printf("\r");

	intf = 0;

	udev = usb_open(dfu_dev[0]);
	if (!udev) {
		printf("Can't open device: %s (%d)\n", strerror(errno), errno);
		return NULL;
	}

	if (usb_claim_interface(udev, intf) < 0) {
		printf("Can't claim interface: %s (%d)\n", strerror(errno), errno);
		usb_close(udev);
		return NULL;
	}

	if (dfu_get_status(udev, intf, &status) < 0) {
		printf("Can't get status: %s (%d)\n", strerror(errno), errno);
		goto error;
	}

	if (status.bState != DFU_STATE_DFU_IDLE) {
		printf("Device is not in DFU mode, can't use it\n");
		goto error;
	}

	return udev;

error:
	usb_release_interface(udev, intf);
	usb_close(udev);
	return NULL;
}

static void usage(void);

static void cmd_verify(char *device, int argc, char **argv)
{
	struct stat st;
	struct dfu_suffix *suffix;
	uint32_t crc;
	uint16_t bcd;
	char str[16];
	unsigned char *buf;
	unsigned long size;
	char *filename;
	int i, fd, len;

	if (argc < 2) {
		usage();
		exit(1);
	}

	filename = argv[1];

	if (stat(filename, &st) < 0) {
		perror("Can't access firmware");
		exit(1);
	}

	size = st.st_size;

	if (!(buf = malloc(size))) {
		perror("Unable to allocate file buffer"); 
		exit(1);
	}

	if ((fd = open(filename, O_RDONLY)) < 0) {
		perror("Can't open firmware");
		free(buf);
		exit(1);
	}

	if (read(fd, buf, size) < size) {
		perror("Can't load firmware");
		free(buf);
		close(fd);
		exit(1);
	}

	printf("Filename\t%s\n", basename(filename));
	printf("Filesize\t%ld\n", size);

	crc = crc32_init();
	for (i = 0; i < size - 4; i++)
		crc = crc32_byte(crc, buf[i]);
	printf("Checksum\t%08x\n", crc);

	printf("\n");
	len = buf[size - 5];
	printf("DFU suffix\t");
	for (i = 0; i < len; i++) {
		printf("%02x ", buf[size - len + i]);
	}
	printf("\n\n");

	suffix = (struct dfu_suffix *) (buf + size - DFU_SUFFIX_SIZE);

	printf("idVendor\t%04x\n", le16_to_cpu(suffix->idVendor));
	printf("idProduct\t%04x\n", le16_to_cpu(suffix->idProduct));
	printf("bcdDevice\t%x\n", le16_to_cpu(suffix->bcdDevice));

	printf("\n");

	bcd = le16_to_cpu(suffix->bcdDFU);

	printf("bcdDFU\t\t%x.%x\n", bcd >> 8, bcd & 0xff);
	printf("ucDfuSignature\t%c%c%c\n", suffix->ucDfuSignature[2],
		suffix->ucDfuSignature[1], suffix->ucDfuSignature[0]);
	printf("bLength\t\t%d\n", suffix->bLength);
	printf("dwCRC\t\t%08x\n", le32_to_cpu(suffix->dwCRC));
	printf("\n");

	memset(str, 0, sizeof(str));
	memcpy(str, buf, 8);

	if (!strcmp(str, "CSR-dfu1") || !strcmp(str, "CSR-dfu2")) {
		crc = crc32_init();
		for (i = 0; i < size - DFU_SUFFIX_SIZE; i++)
			crc = crc32_byte(crc, buf[i]);

		printf("Firmware type\t%s\n", str);
		printf("Firmware check\t%s checksum\n", crc == 0 ? "valid" : "corrupt");
		printf("\n");
	}

	free(buf);

	close(fd);
}

static void cmd_modify(char *device, int argc, char **argv)
{
}

static void cmd_upgrade(char *device, int argc, char **argv)
{
	struct usb_dev_handle *udev;
	struct dfu_status status;
	struct dfu_suffix suffix;
	struct stat st;
	char *buf;
	unsigned long filesize, count, timeout = 0;
	char *filename;
	uint32_t crc, dwCRC;
	int fd, i, block, len, size, sent = 0, try = 10;

	if (argc < 2) {
		usage();
		exit(1);
	}

	filename = argv[1];

	if (stat(filename, &st) < 0) {
		perror("Can't access firmware");
		exit(1);
	}

	filesize = st.st_size;

	if (!(buf = malloc(filesize))) {
		perror("Unable to allocate file buffer"); 
		exit(1);
	}

	if ((fd = open(filename, O_RDONLY)) < 0) {
		perror("Can't open firmware");
		free(buf);
		exit(1);
	}

	if (read(fd, buf, filesize) < filesize) {
		perror("Can't load firmware");
		free(buf);
		close(fd);
		exit(1);
	}

	memcpy(&suffix, buf + filesize - DFU_SUFFIX_SIZE, sizeof(suffix));
	dwCRC = le32_to_cpu(suffix.dwCRC);

	printf("Filename\t%s\n", basename(filename));
	printf("Filesize\t%ld\n", filesize);

	crc = crc32_init();
	for (i = 0; i < filesize - 4; i++)
		crc = crc32_byte(crc, buf[i]);

	printf("Checksum\t%08x (%s)\n", crc,
			crc == dwCRC ? "valid" : "corrupt");

	if (crc != dwCRC) {
		free(buf);
		close(fd);
		exit(1);
	}

	printf("\n");

	udev = open_device(device, &suffix);
	if (!udev)
		exit(1);

	printf("\r" "          " "          " "          " "          " "          ");
	printf("\rFirmware download ... ");
	fflush(stdout);

	count = filesize - DFU_SUFFIX_SIZE;
	block = 0;

	while (count) {
		size = (count > 1023) ? 1023 : count;

		if (dfu_get_status(udev, 0, &status) < 0) {
			if (try-- > 0) {
				sleep(1);
				continue;
			}
			printf("\rCan't get status: %s (%d)\n", strerror(errno), errno);
			goto done;
		}

		if (status.bStatus != DFU_OK) {
			if (try-- > 0) {
				dfu_clear_status(udev, 0);
				sleep(1);
				continue;
			}
			printf("\rFirmware download ... aborting (status %d state %d)\n",
						status.bStatus, status.bState);
			goto done;
		}

		if (status.bState != DFU_STATE_DFU_IDLE &&
				status.bState != DFU_STATE_DFU_DNLOAD_IDLE) {
			sleep(1);
			continue;
		}

		timeout = (status.bwPollTimeout[2] << 16) |
				(status.bwPollTimeout[1] << 8) |
					status.bwPollTimeout[0];

		usleep(timeout * 1000);

		len = dfu_download(udev, 0, block, buf + sent, size);
		if (len < 0) {
			if (try-- > 0) {
				sleep(1);
				continue;
			}
			printf("\rCan't upload next block: %s (%d)\n", strerror(errno), errno);
			goto done;
		}

		printf("\rFirmware download ... %d bytes ", block * 1023 + len);
		fflush(stdout);

		sent  += len;
		count -= len;
		block++;
	}

	printf("\r" "          " "          " "          " "          " "          ");
	printf("\rFinishing firmware download ... ");
	fflush(stdout);

	sleep(1);

	if (dfu_get_status(udev, 0, &status) < 0) {
		printf("\rCan't get status: %s (%d)\n", strerror(errno), errno);
		goto done;
	}

	timeout = (status.bwPollTimeout[2] << 16) |
			(status.bwPollTimeout[1] << 8) |
				status.bwPollTimeout[0];

	usleep(timeout * 1000);

	if (count == 0) {
		len = dfu_download(udev, 0, block, NULL, 0);
		if (len < 0) {
			printf("\rCan't send final block: %s (%d)\n", strerror(errno), errno);
			goto done;
		}
	}

	printf("\r" "          " "          " "          " "          " "          ");
	printf("\rWaiting for device ... ");
	fflush(stdout);

	sleep(10);

	printf("\n");

done:
	free(buf);
	close(fd);

	usb_release_interface(udev, 0);
	usb_reset(udev);
	usb_close(udev);
}

static void cmd_archive(char *device, int argc, char **argv)
{
	struct usb_dev_handle *udev;
	struct dfu_status status;
	struct dfu_suffix suffix;
	char buf[2048];
	unsigned long timeout = 0;
	char *filename;
	uint32_t crc;
	int fd, i, n, len, try = 8;

	if (argc < 2) {
		usage();
		exit(1);
	}

	filename = argv[1];

	udev = open_device(device, &suffix);
	if (!udev)
		exit(1);

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		printf("Can't open firmware file: %s (%d)\n", strerror(errno), errno);
		goto done;
	}

	printf("\r" "          " "          " "          " "          " "          ");
	printf("\rFirmware upload ... ");
	fflush(stdout);

	crc = crc32_init();
	n = 0;
	while (1) {
		if (dfu_get_status(udev, 0, &status) < 0) {
			if (try-- > 0) {
				sleep(1);
				continue;
			}
			printf("\rCan't get status: %s (%d)\n", strerror(errno), errno);
			goto done;
		}

		if (status.bStatus != DFU_OK) {
			if (try-- > 0) {
				dfu_clear_status(udev, 0);
				sleep(1);
				continue;
			}
			printf("\rFirmware upload ... aborting (status %d state %d)\n",
						status.bStatus, status.bState);
			goto done;
		}

		if (status.bState != DFU_STATE_DFU_IDLE &&
				status.bState != DFU_STATE_UPLOAD_IDLE) {
			sleep(1);
			continue;
		}

		timeout = (status.bwPollTimeout[2] << 16) |
				(status.bwPollTimeout[1] << 8) |
					status.bwPollTimeout[0];

		usleep(timeout * 1000);

		len = dfu_upload(udev, 0, n, buf, 1023);
		if (len < 0) {
			if (try-- > 0) {
				sleep(1);
				continue;
			}
			printf("\rCan't upload next block: %s (%d)\n", strerror(errno), errno);
			goto done;
		}

		printf("\rFirmware upload ... %d bytes ", n * 1023 + len);
		fflush(stdout);

		for (i = 0; i < len; i++)
			crc = crc32_byte(crc, buf[i]);

		if (len > 0)
			write(fd, buf, len);

		n++;
		if (len != 1023)
			break;
	}
	printf("\n");

	suffix.bcdDFU = cpu_to_le16(0x0100);
	suffix.ucDfuSignature[0] = 'U';
	suffix.ucDfuSignature[1] = 'F';
	suffix.ucDfuSignature[2] = 'D';
	suffix.bLength = DFU_SUFFIX_SIZE;

	memcpy(buf, &suffix, DFU_SUFFIX_SIZE);
	for (i = 0; i < DFU_SUFFIX_SIZE - 4; i++)
		crc = crc32_byte(crc, buf[i]);

	suffix.dwCRC = cpu_to_le32(crc);

	write(fd, &suffix, DFU_SUFFIX_SIZE);

done:
	close(fd);

	usb_release_interface(udev, 0);
	usb_reset(udev);
	usb_close(udev);
}

struct {
	char *cmd;
	char *alt;
	void (*func)(char *device, int argc, char **argv);
	char *opt;
	char *doc;
} command[] = {
	{ "verify",  "check",    cmd_verify,  "<dfu-file>", "Check firmware file"         },
	{ "modify",  "change",   cmd_modify,  "<dfu-file>", "Change firmware attributes"  },
	{ "upgrade", "download", cmd_upgrade, "<dfu-file>", "Download a new firmware"     },
	{ "archive", "upload",   cmd_archive, "<dfu-file>", "Upload the current firmware" },
	{ NULL, NULL, NULL, 0, 0 }
};

static void usage(void)
{
	int i;

	printf("dfutool - Device Firmware Upgrade utility ver %s\n\n", VERSION);

	printf("Usage:\n"
		"\tdfutool [options] <command>\n"
		"\n");

	printf("Options:\n"
		"\t-d, --device <device>   USB device\n"
		"\t-h, --help              Display help\n"
		"\n");

	printf("Commands:\n");
	for (i = 0; command[i].cmd; i++)
		printf("\t%-8s %-10s\t%s\n", command[i].cmd,
		command[i].opt ? command[i].opt : " ",
		command[i].doc);
	printf("\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "device",	1, 0, 'd' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	char *device = NULL;
	int i, opt;

	while ((opt = getopt_long(argc, argv, "+d:h", main_options, NULL)) != -1) {
		switch(opt) {
		case 'd':
			device = strdup(optarg);
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

	for (i = 0; command[i].cmd; i++) {
		if (strcmp(command[i].cmd, argv[0]) && strcmp(command[i].alt, argv[0]))
			continue;
		command[i].func(device, argc, argv);
		exit(0);
	}

	usage();
	exit(1);
}
