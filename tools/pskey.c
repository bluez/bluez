/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "csr.h"

#define CSR_TYPE_NULL	0
#define CSR_TYPE_ARRAY	1
#define CSR_TYPE_UINT8	2
#define CSR_TYPE_UINT16	3

static int write_pskey(int dd, uint16_t pskey, int type, int argc, char *argv[])
{
	uint16_t value;
	int err;

	if (type != CSR_TYPE_UINT8 && type != CSR_TYPE_UINT16) {
		errno = EFAULT;
		return -1;
	}

	if (argc != 1) {
		errno = E2BIG;
		return -1;
	}

	if (!strncasecmp(argv[0], "0x", 2))
		value = strtol(argv[0] + 2, NULL, 16);
	else
		value = atoi(argv[0]);

	err = csr_write_pskey_uint16(dd, 0x4711, pskey, value);

	return err;
}

static int read_pskey(int dd, uint16_t pskey, int type)
{
	uint8_t array[64];
	uint16_t value = 0;
	int i, err, size = sizeof(array);

	memset(array, 0, sizeof(array));

	if (type != CSR_TYPE_ARRAY &&
			type != CSR_TYPE_UINT8 &&
			type != CSR_TYPE_UINT16) {
		errno = EFAULT;
		return -1;
	}

	if (type != CSR_TYPE_ARRAY) {
		err = csr_read_pskey_uint16(dd, 0x4711, pskey, &value);
		if (err < 0)
			return err;

		printf("%s: 0x%04x (%d)\n", csr_pskeytostr(pskey), value, value);
	} else {
		if (pskey == CSR_PSKEY_LOCAL_SUPPORTED_FEATURES)
			size = 8;

		err = csr_read_pskey_complex(dd, 0x4711, pskey, array, size);
		if (err < 0)
			return err;

		printf("%s:", csr_pskeytostr(pskey));
		for (i = 0; i < size; i++)
			printf(" 0x%02x", array[i]);
		printf("\n");
	}

	return err;
}

static struct {
	uint16_t pskey;
	int type;
	char *str;
} storage[] = {
	{ CSR_PSKEY_ENC_KEY_LMIN,             CSR_TYPE_UINT16, "keymin"   },
	{ CSR_PSKEY_ENC_KEY_LMAX,             CSR_TYPE_UINT16, "keymax"   },
	{ CSR_PSKEY_LOCAL_SUPPORTED_FEATURES, CSR_TYPE_ARRAY,  "features" },
	{ CSR_PSKEY_HCI_LMP_LOCAL_VERSION,    CSR_TYPE_UINT16, "version"  },
	{ CSR_PSKEY_LMP_REMOTE_VERSION,       CSR_TYPE_UINT8,  "remver"   },
	{ CSR_PSKEY_HOSTIO_MAP_SCO_PCM,       CSR_TYPE_UINT16, "mapsco"   },
	{ CSR_PSKEY_UART_BAUDRATE,            CSR_TYPE_UINT16, "baudrate" },
	{ CSR_PSKEY_HOST_INTERFACE,           CSR_TYPE_UINT16, "hostintf" },
	{ CSR_PSKEY_USB_VENDOR_ID,            CSR_TYPE_UINT16, "usbvid"   },
	{ CSR_PSKEY_USB_PRODUCT_ID,           CSR_TYPE_UINT16, "usbpid"   },
	{ CSR_PSKEY_USB_DFU_PRODUCT_ID,       CSR_TYPE_UINT16, "dfupid"   },
	{ CSR_PSKEY_INITIAL_BOOTMODE,         CSR_TYPE_UINT16, "bootmode" },
	{ 0x0000, CSR_TYPE_NULL, NULL },
};

static void usage(void)
{
	int i, pos = 0;

	printf("pskey - Utility for changing CSR persistent storage\n\n");
	printf("Usage:\n"
		"\tpskey [-i <dev>] <key> [value]\n\n");

	printf("Keys:\n\t");
	for (i = 0; storage[i].pskey; i++) {
		printf("%s ", storage[i].str);
		pos += strlen(storage[i].str) + 1;
		if (pos > 60) {
			printf("\n\t");
			pos = 0;
		}
	}
	printf("\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "device",	1, 0, 'i' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct hci_dev_info di;
	struct hci_version ver;
	int i, err, dd, opt, dev = 0;

	while ((opt=getopt_long(argc, argv, "+i:h", main_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			dev = hci_devid(optarg);
			if (dev < 0) {
				perror("Invalid device");
				exit(1);
			}
			break;

		case 'h':
		default:
			usage();
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

	dd = hci_open_dev(dev);
	if (dd < 0) {
		fprintf(stderr, "Can't open device hci%d: %s (%d)\n",
						dev, strerror(errno), errno);
		exit(1);
	}

	if (hci_devinfo(dev, &di) < 0) {
		fprintf(stderr, "Can't get device info for hci%d: %s (%d)\n",
						dev, strerror(errno), errno);
		hci_close_dev(dd);
		exit(1);
	}

	if (hci_read_local_version(dd, &ver, 1000) < 0) {
		fprintf(stderr, "Can't read version info for hci%d: %s (%d)\n",
						dev, strerror(errno), errno);
		hci_close_dev(dd);
		exit(1);
	}

	if (ver.manufacturer != 10) {
		fprintf(stderr, "Unsupported manufacturer\n");
		hci_close_dev(dd);
		exit(1);
	}

	for (i = 0; storage[i].pskey; i++) {
		if (strcasecmp(storage[i].str, argv[0]))
			continue;

		if (argc > 1)
			err = write_pskey(dd, storage[i].pskey,
					storage[i].type, argc - 1, argv + 1);
		else
			err = read_pskey(dd, storage[i].pskey, storage[i].type);

		hci_close_dev(dd);

		if (err < 0) {
			fprintf(stderr, "Can't %s persistent storage: %s (%d)\n",
				argc > 1 ? "write" : "read", strerror(errno), errno);
			exit(1);
		}

		exit(0);
	}

	fprintf(stderr, "Unsupported persistent storage\n");

	hci_close_dev(dd);

	exit(1);
}
