/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
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
#define CSR_TYPE_UINT32	4

enum {
	NONE = 0,
	LIST,
	READ,
};

static int transient = 0;

static int cmd_list(int dd, int argc, char *argv[])
{
	uint8_t array[8];
	uint16_t length, seqnum = 0x0000, pskey = 0x0000;
	int err;

	while (1) {
		memset(array, 0, sizeof(array));
		array[0] = pskey & 0xff;
		array[1] = pskey >> 8;

		err = csr_read_varid_complex(dd, seqnum++,
				CSR_VARID_PS_NEXT, array, sizeof(array));
		if (err < 0)
			break;

		pskey = array[4] + (array[5] << 8);
		if (pskey == 0x0000)
			break;

		memset(array, 0, sizeof(array));
		array[0] = pskey & 0xff;
		array[1] = pskey >> 8;

		err = csr_read_varid_complex(dd, seqnum++,
				CSR_VARID_PS_SIZE, array, sizeof(array));
		if (err < 0)
			continue;

		length = array[2] + (array[3] << 8);

		printf("0x%04x - %s (%d bytes)\n", pskey,
					csr_pskeytostr(pskey), length * 2);
	}

	return 0;
}

static int cmd_read(int dd, int argc, char *argv[])
{
	uint8_t array[256];
	uint16_t length, seqnum = 0x0000, pskey = 0x0000;
	char *str, val[7];
	int i, err;

	while (1) {
		memset(array, 0, sizeof(array));
		array[0] = pskey & 0xff;
		array[1] = pskey >> 8;

		err = csr_read_varid_complex(dd, seqnum++,
				CSR_VARID_PS_NEXT, array, 8);
		if (err < 0)
			break;

		pskey = array[4] + (array[5] << 8);
		if (pskey == 0x0000)
			break;

		memset(array, 0, sizeof(array));
		array[0] = pskey & 0xff;
		array[1] = pskey >> 8;

		err = csr_read_varid_complex(dd, seqnum++,
				CSR_VARID_PS_SIZE, array, 8);
		if (err < 0)
			continue;

		length = array[2] + (array[3] << 8);
		if (length > sizeof(array) / 2)
			continue;

		err = csr_read_pskey_complex(dd, seqnum++, pskey,
						0x0000, array, length * 2);
		if (err < 0)
			continue;

		str = csr_pskeytoval(pskey);
		if (!strcasecmp(str, "UNKNOWN")) {
			sprintf(val, "0x%04x", pskey);
			str = NULL;
		}

		printf("// %s%s\n&%04x =", str ? "PSKEY_" : "", 
						str ? str : val, pskey);
		for (i = 0; i < length; i++)
			printf(" %02x%02x", array[i * 2 + 1], array[i * 2]);
		printf("\n");
	}

	return 0;
}

static int pskey_size(uint16_t pskey)
{
	switch (pskey) {
	case CSR_PSKEY_BDADDR:
		return 8;
	case CSR_PSKEY_LOCAL_SUPPORTED_FEATURES:
		return 8;
	case CSR_PSKEY_LOCAL_SUPPORTED_COMMANDS:
		return 18;
	default:
		return 64;
	}
}

static int write_pskey(int dd, uint16_t pskey, int type, int argc, char *argv[])
{
	uint8_t array[64];
	uint16_t value;
	uint32_t val32;
	int i, err, size = sizeof(array);

	memset(array, 0, sizeof(array));

	switch (type) {
	case CSR_TYPE_ARRAY:
		size = pskey_size(pskey);

		if (argc != size) {
			errno = EINVAL;
			return -1;
		}

		for (i = 0; i < size; i++)
			if (!strncasecmp(argv[0], "0x", 2))
				array[i] = strtol(argv[i] + 2, NULL, 16);
			else
				array[i] = atoi(argv[i]);

		err = csr_write_pskey_complex(dd, 0x4711, pskey,
					transient ? 0x0008 : 0x0000, array, size);
		break;

	case CSR_TYPE_UINT8:
	case CSR_TYPE_UINT16:
		if (argc != 1) {
			errno = E2BIG;
			return -1;
		}

		if (!strncasecmp(argv[0], "0x", 2))
			value = strtol(argv[0] + 2, NULL, 16);
		else
			value = atoi(argv[0]);

		err = csr_write_pskey_uint16(dd, 0x4711, pskey,
					transient ? 0x0008 : 0x0000, value);
		break;

	case CSR_TYPE_UINT32:
		if (argc != 1) {
			errno = E2BIG;
			return -1;
		}

		if (!strncasecmp(argv[0], "0x", 2))
			val32 = strtol(argv[0] + 2, NULL, 16);
		else
			val32 = atoi(argv[0]);

		err = csr_write_pskey_uint32(dd, 0x4711, pskey,
					transient ? 0x0008 : 0x0000, val32);
		break;

	default:
		errno = EFAULT;
		err = -1;
		break;
	}

	return err;
}

static int read_pskey(int dd, uint16_t pskey, int type)
{
	uint8_t array[64];
	uint16_t value = 0;
	uint32_t val32 = 0;
	int i, err, size = sizeof(array);

	memset(array, 0, sizeof(array));

	switch (type) {
	case CSR_TYPE_ARRAY:
		size = pskey_size(pskey);

		err = csr_read_pskey_complex(dd, 0x4711, pskey, 0x0000, array, size);
		if (err < 0)
			return err;

		printf("%s:", csr_pskeytostr(pskey));
		for (i = 0; i < size; i++)
			printf(" 0x%02x", array[i]);
		printf("\n");
		break;

	case CSR_TYPE_UINT8:
	case CSR_TYPE_UINT16:
		err = csr_read_pskey_uint16(dd, 0x4711, pskey, 0x0000, &value);
		if (err < 0)
			return err;

		printf("%s: 0x%04x (%d)\n", csr_pskeytostr(pskey), value, value);
		break;

	case CSR_TYPE_UINT32:
		err = csr_read_pskey_uint32(dd, 0x4711, pskey, 0x0000, &val32);
		if (err < 0)
			return err;

		printf("%s: 0x%08x (%d)\n", csr_pskeytostr(pskey), val32, val32);
		break;

	default:
		errno = EFAULT;
		err = -1;
		break;
	}

	return err;
}

static struct {
	uint16_t pskey;
	int type;
	char *str;
} storage[] = {
	{ CSR_PSKEY_BDADDR,                   CSR_TYPE_ARRAY,  "bdaddr"   },
	{ CSR_PSKEY_COUNTRYCODE,              CSR_TYPE_UINT16, "country"  },
	{ CSR_PSKEY_CLASSOFDEVICE,            CSR_TYPE_UINT32, "devclass" },
	{ CSR_PSKEY_ENC_KEY_LMIN,             CSR_TYPE_UINT16, "keymin"   },
	{ CSR_PSKEY_ENC_KEY_LMAX,             CSR_TYPE_UINT16, "keymax"   },
	{ CSR_PSKEY_LOCAL_SUPPORTED_FEATURES, CSR_TYPE_ARRAY,  "features" },
	{ CSR_PSKEY_LOCAL_SUPPORTED_COMMANDS, CSR_TYPE_ARRAY,  "commands" },
	{ CSR_PSKEY_HCI_LMP_LOCAL_VERSION,    CSR_TYPE_UINT16, "version"  },
	{ CSR_PSKEY_LMP_REMOTE_VERSION,       CSR_TYPE_UINT8,  "remver"   },
	{ CSR_PSKEY_HOSTIO_USE_HCI_EXTN,      CSR_TYPE_UINT16, "hciextn"  },
	{ CSR_PSKEY_HOSTIO_MAP_SCO_PCM,       CSR_TYPE_UINT16, "mapsco"   },
	{ CSR_PSKEY_UART_BAUDRATE,            CSR_TYPE_UINT16, "baudrate" },
	{ CSR_PSKEY_HOST_INTERFACE,           CSR_TYPE_UINT16, "hostintf" },
	{ CSR_PSKEY_ANA_FREQ,                 CSR_TYPE_UINT16, "anafreq"  },
	{ CSR_PSKEY_ANA_FTRIM,                CSR_TYPE_UINT16, "anaftrim" },
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
		"\tpskey [-i <dev>] [-r] [-t] <key> [value]\n"
		"\tpskey [-i <dev>] --list\n"
		"\tpskey [-i <dev>] --read\n\n");

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
	{ "device",	1, 0, 'i' },
	{ "reset",	0, 0, 'r' },
	{ "transient",	0, 0, 't' },
	{ "list",	0, 0, 'L' },
	{ "read",	0, 0, 'R' },
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct hci_dev_info di;
	struct hci_version ver;
	int i, err, dd, opt, dev = 0, reset = 0, mode = NONE;

	while ((opt=getopt_long(argc, argv, "+i:rtLRh", main_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			dev = hci_devid(optarg);
			if (dev < 0) {
				perror("Invalid device");
				exit(1);
			}
			break;

		case 'r':
			reset = 1;
			break;

		case 't':
			transient = 1;
			break;

		case 'L':
			mode = LIST;
			break;

		case 'R':
			mode = READ;
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

	if (mode == NONE && argc < 1) {
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

	if (mode > 0) {
		switch (mode) {
		case LIST:
			err = cmd_list(dd, argc, argv);
			break;

		case READ:
			err = cmd_read(dd, argc, argv);
			break;

		default:
			usage();
			err = -1;
			break;
		}

		hci_close_dev(dd);
		exit(err < 0 ? 1 : 0);
	}

	for (i = 0; storage[i].pskey; i++) {
		if (strcasecmp(storage[i].str, argv[0]))
			continue;

		if (argc > 1) {
			err = write_pskey(dd, storage[i].pskey,
					storage[i].type, argc - 1, argv + 1);

			if (!err && reset)
				csr_write_varid_valueless(dd, 0x0000,
							CSR_VARID_WARM_RESET);
		} else
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
