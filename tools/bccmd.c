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

#define CSR_TRANSPORT_UNKNOWN	0
#define CSR_TRANSPORT_HCI	1
#define CSR_TRANSPORT_USB	2
#define CSR_TRANSPORT_BCSP	3
#define CSR_TRANSPORT_H4	4
#define CSR_TRANSPORT_3WIRE	5

#define CSR_STORES_PSI		(0x0001)
#define CSR_STORES_PSF		(0x0002)
#define CSR_STORES_PSROM	(0x0004)
#define CSR_STORES_PSRAM	(0x0008)
#define CSR_STORES_DEFAULT	(CSR_STORES_PSI | CSR_STORES_PSF)

#define CSR_TYPE_NULL		0
#define CSR_TYPE_COMPLEX	1
#define CSR_TYPE_UINT8		2
#define CSR_TYPE_UINT16		3
#define CSR_TYPE_UINT32		4

#define CSR_TYPE_ARRAY		CSR_TYPE_COMPLEX
#define CSR_TYPE_BDADDR		CSR_TYPE_COMPLEX

static uint16_t seqnum = 0x0000;

static struct {
	uint16_t pskey;
	int type;
	int size;
	char *str;
} storage[] = {
	{ CSR_PSKEY_BDADDR,                   CSR_TYPE_BDADDR,  8,  "bdaddr"   },
	{ CSR_PSKEY_COUNTRYCODE,              CSR_TYPE_UINT16,  0,  "country"  },
	{ CSR_PSKEY_CLASSOFDEVICE,            CSR_TYPE_UINT32,  0,  "devclass" },
	{ CSR_PSKEY_ENC_KEY_LMIN,             CSR_TYPE_UINT16,  0,  "keymin"   },
	{ CSR_PSKEY_ENC_KEY_LMAX,             CSR_TYPE_UINT16,  0,  "keymax"   },
	{ CSR_PSKEY_LOCAL_SUPPORTED_FEATURES, CSR_TYPE_ARRAY,   8,  "features" },
	{ CSR_PSKEY_LOCAL_SUPPORTED_COMMANDS, CSR_TYPE_ARRAY,   18, "commands" },
	{ CSR_PSKEY_HCI_LMP_LOCAL_VERSION,    CSR_TYPE_UINT16,  0,  "version"  },
	{ CSR_PSKEY_LMP_REMOTE_VERSION,       CSR_TYPE_UINT8,   0,  "remver"   },
	{ CSR_PSKEY_HOSTIO_USE_HCI_EXTN,      CSR_TYPE_UINT16,  0,  "hciextn"  },
	{ CSR_PSKEY_HOSTIO_MAP_SCO_PCM,       CSR_TYPE_UINT16,  0,  "mapsco"   },
	{ CSR_PSKEY_UART_BAUDRATE,            CSR_TYPE_UINT16,  0,  "baudrate" },
	{ CSR_PSKEY_HOST_INTERFACE,           CSR_TYPE_UINT16,  0,  "hostintf" },
	{ CSR_PSKEY_ANA_FREQ,                 CSR_TYPE_UINT16,  0,  "anafreq"  },
	{ CSR_PSKEY_ANA_FTRIM,                CSR_TYPE_UINT16,  0,  "anaftrim" },
	{ CSR_PSKEY_USB_VENDOR_ID,            CSR_TYPE_UINT16,  0,  "usbvid"   },
	{ CSR_PSKEY_USB_PRODUCT_ID,           CSR_TYPE_UINT16,  0,  "usbpid"   },
	{ CSR_PSKEY_USB_DFU_PRODUCT_ID,       CSR_TYPE_UINT16,  0,  "dfupid"   },
	{ CSR_PSKEY_INITIAL_BOOTMODE,         CSR_TYPE_UINT16,  0,  "bootmode" },
	{ 0x0000 },
};

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

static char *storestostr(uint16_t stores)
{
	switch (stores) {
	case 0x0000:
		return "Default";
	case 0x0001:
		return "psi";
	case 0x0002:
		return "psf";
	case 0x0004:
		return "psrom";
	case 0x0008:
		return "psram";
	default:
		return "Unknown";
	}
}

static char *memorytostr(uint16_t type)
{
	switch (type) {
	case 0x0000:
		return "Flash memory";
	case 0x0001:
		return "EEPROM";
	case 0x0002:
		return "RAM (transient)";
	case 0x0003:
		return "ROM (or \"read-only\" flash memory)";
	default:
		return "Unknown";
	}
}

#define OPT_RANGE(range) \
		if (argc < (range)) { errno = EINVAL; return -1; } \
		if (argc > (range)) { errno = E2BIG; return -1; }

static struct option help_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static int opt_help(int argc, char *argv[], int *help)
{
	int opt;

	while ((opt=getopt_long(argc, argv, "+h", help_options, NULL)) != EOF) {
		switch (opt) {
		case 'h':
			if (help)
				*help = 1;
			break;
		}
	}

	return optind;
}

#define OPT_HELP(range, help) \
		opt_help(argc, argv, (help)); \
		argc -= optind; argv += optind; optind = 0; \
		OPT_RANGE((range))

static int cmd_builddef(int dd, int argc, char *argv[])
{
	uint8_t buf[8];
	uint16_t def = 0x0000, nextdef = 0x0000;
	int err = 0;

	OPT_HELP(0, NULL);

	printf("Build definitions:\n");

	while (1) {
		memset(buf, 0, sizeof(buf));
		buf[0] = def & 0xff;
		buf[1] = def >> 8;

		err = csr_read_varid_complex(dd, seqnum++,
				CSR_VARID_GET_NEXT_BUILDDEF, buf, sizeof(buf));
		if (err < 0) {
			errno = -err;
			break;
		}

		nextdef = buf[2] | (buf[3] << 8);

		if (nextdef == 0x0000)
			break;

		def = nextdef;

		printf("0x%04x - %s\n", def, csr_builddeftostr(def));
	}

	return err;
}

static int cmd_keylen(int dd, int argc, char *argv[])
{
	uint8_t buf[8];
	uint16_t handle, keylen;
	int err;

	OPT_HELP(1, NULL);

	handle = atoi(argv[0]);

	memset(buf, 0, sizeof(buf));
	buf[0] = handle & 0xff;
	buf[1] = handle >> 8;

	err = csr_read_varid_complex(dd, seqnum++,
				CSR_VARID_CRYPT_KEY_LENGTH, buf, sizeof(buf));
	if (err < 0) {
		errno = -err;
		return -1;
	}

	handle = buf[0] | (buf[1] << 8);
	keylen = buf[2] | (buf[3] << 8);

	printf("Crypt key length: %d bit\n", keylen * 8);

	return 0;
}

static int cmd_clock(int dd, int argc, char *argv[])
{
	uint32_t clock = 0;
	int err;

	OPT_HELP(0, NULL);

	err = csr_read_varid_uint32(dd, seqnum++, CSR_VARID_BT_CLOCK, &clock);
	if (err < 0) {
		errno = -err;
		return -1;
	}

	printf("Bluetooth clock: 0x%04x (%d)\n", clock, clock);

	return 0;
}

static int cmd_rand(int dd, int argc, char *argv[])
{
	uint16_t rand = 0;
	int err;

	OPT_HELP(0, NULL);

	err = csr_read_varid_uint16(dd, seqnum++, CSR_VARID_RAND, &rand);
	if (err < 0) {
		errno = -err;
		return -1;
	}

	printf("Random number: 0x%02x (%d)\n", rand, rand);

	return 0;
}

static int cmd_panicarg(int dd, int argc, char *argv[])
{
	uint16_t error = 0;
	int err;

	OPT_HELP(0, NULL);

	err = csr_read_varid_uint16(dd, seqnum++, CSR_VARID_PANIC_ARG, &error);
	if (err < 0) {
		errno = -err;
		return -1;
	}

	printf("Panic code: 0x%02x (%s)\n", error,
					error < 0x100 ? "valid" : "invalid");

	return 0;
}

static int cmd_faultarg(int dd, int argc, char *argv[])
{
	uint16_t error = 0;
	int err;

	OPT_HELP(0, NULL);

	err = csr_read_varid_uint16(dd, seqnum++, CSR_VARID_FAULT_ARG, &error);
	if (err < 0) {
		errno = -err;
		return -1;
	}

	printf("Fault code: 0x%02x (%s)\n", error,
					error < 0x100 ? "valid" : "invalid");

	return 0;
}

static int cmd_coldreset(int dd, int argc, char *argv[])
{
	return csr_write_varid_valueless(dd, seqnum++, CSR_VARID_COLD_RESET);
}

static int cmd_warmreset(int dd, int argc, char *argv[])
{
	return csr_write_varid_valueless(dd, seqnum++, CSR_VARID_WARM_RESET);
}

static int cmd_disabletx(int dd, int argc, char *argv[])
{
	return csr_write_varid_valueless(dd, seqnum++, CSR_VARID_DISABLE_TX);
}

static int cmd_enabletx(int dd, int argc, char *argv[])
{
	return csr_write_varid_valueless(dd, seqnum++, CSR_VARID_ENABLE_TX);
}

static int cmd_memtypes(int dd, int argc, char *argv[])
{
	uint8_t array[8];
	uint16_t type, stores[4] = { 0x0001, 0x0002, 0x0004, 0x0008 };
	int i, err;

	OPT_HELP(0, NULL);

	for (i = 0; i < 4; i++) {
		memset(array, 0, sizeof(array));
		array[0] = stores[i] & 0xff;
		array[1] = stores[i] >> 8;

		err = csr_read_varid_complex(dd, seqnum++,
				CSR_VARID_PS_MEMORY_TYPE, array, sizeof(array));
		if (err < 0)
			continue;

		type = array[2] + (array[3] << 8);

		printf("%s (0x%04x) = %s (%d)\n", storestostr(stores[i]),
					stores[i], memorytostr(type), type);
	}

	return 0;
}

static struct option pskey_options[] = {
	{ "stores",	1, 0, 's' },
	{ "reset",	0, 0, 'r' },
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static int opt_pskey(int argc, char *argv[], uint16_t *stores, int *reset, int *help)
{
	int opt;

	while ((opt=getopt_long(argc, argv, "+s:rh", pskey_options, NULL)) != EOF) {
		switch (opt) {
		case 's':
			if (!stores)
				break;
			if (!strcasecmp(optarg, "default"))
				*stores = 0x0000;
			else if (!strcasecmp(optarg, "implementation"))
				*stores = 0x0001;
			else if (!strcasecmp(optarg, "factory"))
				*stores = 0x0002;
			else if (!strcasecmp(optarg, "rom"))
				*stores = 0x0004;
			else if (!strcasecmp(optarg, "ram"))
				*stores = 0x0008;
			else if (!strcasecmp(optarg, "psi"))
				*stores = 0x0001;
			else if (!strcasecmp(optarg, "psf"))
				*stores = 0x0002;
			else if (!strcasecmp(optarg, "psrom"))
				*stores = 0x0004;
			else if (!strcasecmp(optarg, "psram"))
				*stores = 0x0008;
			else if (!strncasecmp(optarg, "0x", 2))
				*stores = strtol(optarg, NULL, 16);
			else
				*stores = atoi(optarg);
			break;

		case 'r':
			if (reset)
				*reset = 1;
			break;

		case 'h':
			if (help)
				*help = 1;
			break;
		}
	}

	return optind;
}

#define OPT_PSKEY(range, stores, reset, help) \
		opt_pskey(argc, argv, (stores), (reset), (help)); \
		argc -= optind; argv += optind; optind = 0; \
		OPT_RANGE((range))

static int cmd_psget(int dd, int argc, char *argv[])
{
	uint8_t array[64];
	uint16_t pskey, length, value, stores = CSR_STORES_DEFAULT;
	uint32_t val32;
	int i, err, size, reset = 0, type = CSR_TYPE_NULL;

	memset(array, 0, sizeof(array));

	OPT_PSKEY(1, &stores, &reset, NULL);

	if (strncasecmp(argv[0], "0x", 2)) {
		pskey = atoi(argv[0]);
		type = CSR_TYPE_COMPLEX;
		size = sizeof(array);

		for (i = 0; storage[i].pskey; i++) {
			if (strcasecmp(storage[i].str, argv[0]))
				continue;

			pskey = storage[i].pskey;
			type = storage[i].type;
			size = storage[i].type;
			break;
		}
	} else {
		pskey = strtol(argv[0] + 2, NULL, 16);
		type = CSR_TYPE_COMPLEX;
		size = sizeof(array);
	}

	switch (type) {
	case CSR_TYPE_COMPLEX:
		memset(array, 0, sizeof(array));
		array[0] = pskey & 0xff;
		array[1] = pskey >> 8;
		array[2] = stores & 0xff;
		array[3] = stores >> 8;

		err = csr_read_varid_complex(dd, seqnum++,
						CSR_VARID_PS_SIZE, array, 8);
		if (err < 0)
			return err;

		length = array[2] + (array[3] << 8);
		if (length > sizeof(array) / 2)
			return -EIO;

		err = csr_read_pskey_complex(dd, seqnum++, pskey, stores,
							array, length * 2);
		if (err < 0)
			return err;

		printf("%s:", csr_pskeytostr(pskey));
		for (i = 0; i < length; i++)
			printf(" 0x%02x%02x", array[i * 2], array[(i * 2) + 1]);
		printf("\n");
		break;

	case CSR_TYPE_UINT8:
	case CSR_TYPE_UINT16:
		err = csr_read_pskey_uint16(dd, seqnum++, pskey, stores, &value);
		if (err < 0)
			return err;

		printf("%s: 0x%04x (%d)\n", csr_pskeytostr(pskey), value, value);
		break;

	case CSR_TYPE_UINT32:
		err = csr_read_pskey_uint32(dd, seqnum++, pskey, stores, &val32);
		if (err < 0)
			return err;

		printf("%s: 0x%08x (%d)\n", csr_pskeytostr(pskey), val32, val32);
		break;

	default:
		errno = EFAULT;
		err = -1;
		break;
	}

	if (!err && reset)
		csr_write_varid_valueless(dd, seqnum++, CSR_VARID_WARM_RESET);

	return err;
}

static int cmd_psset(int dd, int argc, char *argv[])
{
	uint8_t array[64];
	uint16_t pskey, value, stores = CSR_STORES_PSRAM;
	uint32_t val32;
	int i, err, size, reset = 0, type = CSR_TYPE_NULL;

	memset(array, 0, sizeof(array));

	OPT_PSKEY(2, &stores, &reset, NULL);

	if (strncasecmp(argv[0], "0x", 2)) {
		pskey = atoi(argv[0]);
		type = CSR_TYPE_COMPLEX;
		size = sizeof(array);

		for (i = 0; storage[i].pskey; i++) {
			if (strcasecmp(storage[i].str, argv[0]))
				continue;

			pskey = storage[i].pskey;
			type = storage[i].type;
			size = storage[i].type;
			break;
		}
	} else {
		pskey = strtol(argv[0] + 2, NULL, 16);
		type = CSR_TYPE_COMPLEX;
		size = sizeof(array);
	}

	argc--;
	argv++;

	switch (type) {
	case CSR_TYPE_COMPLEX:
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

		err = csr_write_pskey_complex(dd, seqnum++, pskey,
							stores, array, size);
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

		err = csr_write_pskey_uint16(dd, seqnum++, pskey, stores, value);
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

		err = csr_write_pskey_uint32(dd, seqnum++, pskey, stores, val32);
		break;

	default:
		errno = EFAULT;
		err = -1;
		break;
	}

	if (!err && reset)
		csr_write_varid_valueless(dd, seqnum++, CSR_VARID_WARM_RESET);

	return err;
}

static int cmd_psclr(int dd, int argc, char *argv[])
{
	uint8_t array[8];
	uint16_t pskey, stores = CSR_STORES_PSRAM;
	int i, err, reset = 0;

	OPT_PSKEY(1, &stores, &reset, NULL);

	if (strncasecmp(argv[0], "0x", 2)) {
		pskey = atoi(argv[0]);

		for (i = 0; storage[i].pskey; i++) {
			if (strcasecmp(storage[i].str, argv[0]))
				continue;

			pskey = storage[i].pskey;
			break;
		}
	} else
		pskey = strtol(argv[0] + 2, NULL, 16);

	memset(array, 0, sizeof(array));
	array[0] = pskey & 0xff;
	array[1] = pskey >> 8;
	array[2] = stores & 0xff;
	array[3] = stores >> 8;

	err = csr_write_varid_complex(dd, seqnum++,
				CSR_VARID_PS_CLR_STORES, array, sizeof(array));

	if (!err && reset)
		csr_write_varid_valueless(dd, seqnum++, CSR_VARID_WARM_RESET);

	return err;
}

static int cmd_pslist(int dd, int argc, char *argv[])
{
	uint8_t array[8];
	uint16_t pskey = 0x0000, length, stores = CSR_STORES_DEFAULT;
	int err, reset = 0;

	OPT_PSKEY(0, &stores, &reset, NULL);

	while (1) {
		memset(array, 0, sizeof(array));
		array[0] = pskey & 0xff;
		array[1] = pskey >> 8;
		array[2] = stores & 0xff;
		array[3] = stores >> 8;

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
		array[2] = stores & 0xff;
		array[3] = stores >> 8;

		err = csr_read_varid_complex(dd, seqnum++,
				CSR_VARID_PS_SIZE, array, sizeof(array));
		if (err < 0)
			continue;

		length = array[2] + (array[3] << 8);

		printf("0x%04x - %s (%d bytes)\n", pskey,
					csr_pskeytostr(pskey), length * 2);
	}

	if (reset)
		csr_write_varid_valueless(dd, seqnum++, CSR_VARID_WARM_RESET);

	return 0;
}

static int cmd_psread(int dd, int argc, char *argv[])
{
	uint8_t array[256];
	uint16_t pskey = 0x0000, length, stores = CSR_STORES_DEFAULT;
	char *str, val[7];
	int i, err, reset = 0;

	OPT_PSKEY(0, &stores, &reset, NULL);

	while (1) {
		memset(array, 0, sizeof(array));
		array[0] = pskey & 0xff;
		array[1] = pskey >> 8;
		array[2] = stores & 0xff;
		array[3] = stores >> 8;

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
		array[2] = stores & 0xff;
		array[3] = stores >> 8;

		err = csr_read_varid_complex(dd, seqnum++,
						CSR_VARID_PS_SIZE, array, 8);
		if (err < 0)
			continue;

		length = array[2] + (array[3] << 8);
		if (length > sizeof(array) / 2)
			continue;

		err = csr_read_pskey_complex(dd, seqnum++, pskey,
						stores, array, length * 2);
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

	if (reset)
		csr_write_varid_valueless(dd, seqnum++, CSR_VARID_WARM_RESET);

	return 0;
}

static int cmd_psload(int dd, int argc, char *argv[])
{
	uint8_t array[256];
	uint16_t pskey, size, stores = CSR_STORES_PSRAM;
	char *str, val[7];
	int err, reset = 0;

	OPT_PSKEY(1, &stores, &reset, NULL);

	psr_read(argv[0]);

	while (psr_get(&pskey, array, &size) == 0) {
		str = csr_pskeytoval(pskey);
		if (!strcasecmp(str, "UNKNOWN")) {
			sprintf(val, "0x%04x", pskey);
			str = NULL;
		}

		printf("Loading %s%s ... ", str ? "PSKEY_" : "",
							str ? str : val);
		fflush(stdout);

		err = csr_write_pskey_complex(dd, seqnum++, pskey,
							stores, array, size);

		printf("%s\n", err < 0 ? "failed" : "done");
	}

	if (reset)
		csr_write_varid_valueless(dd, seqnum++, CSR_VARID_WARM_RESET);

	return 0;
}

static int cmd_pscheck(int dd, int argc, char *argv[])
{
	uint8_t array[256];
	uint16_t pskey, size;
	int i;

	OPT_HELP(1, NULL);

	psr_read(argv[0]);

	while (psr_get(&pskey, array, &size) == 0) {
		printf("0x%04x =", pskey);
		for (i = 0; i < size; i++)
			printf(" 0x%02x", array[i]);
		printf("\n");
	}

	return 0;
}

static struct {
	char *str;
	int (*func)(int dd, int argc, char *argv[]);
	char *arg;
	char *doc;
} commands[] = {
	{ "builddef",  cmd_builddef,  "",              "Get build definitions"          },
	{ "keylen",    cmd_keylen,    "<handle>",      "Get current crypt key length"   },
	{ "clock",     cmd_clock,     "",              "Get local Bluetooth clock"      },
	{ "rand",      cmd_rand,      "",              "Get random number"              },
	{ "panicarg",  cmd_panicarg,  "",              "Get panic code argument"        },
	{ "faultarg",  cmd_faultarg,  "",              "Get fault code argument"        },
	{ "coldreset", cmd_coldreset, "",              "Perform cold reset"             },
	{ "warmreset", cmd_warmreset, "",              "Perform warm reset"             },
	{ "disabletx", cmd_disabletx, "",              "Disable TX on the device"       },
	{ "enabletx",  cmd_enabletx,  "",              "Enable TX on the device"        },
	{ "memtypes",  cmd_memtypes,  NULL,            "Get memory types"               },
	{ "psget",     cmd_psget,     "<key>",         "Get value for PS key"           },
	{ "psset",     cmd_psset,     "<key> <value>", "Set value for PS key"           },
	{ "psclr",     cmd_psclr,     "<key>",         "Clear value for PS key"         },
	{ "pslist",    cmd_pslist,    NULL,            "List all PS keys"               },
	{ "psread",    cmd_psread,    NULL,            "Read all PS keys"               },
	{ "psload",    cmd_psload,    "<file>",        "Load all PS keys from PSR file" },
	{ "pscheck",   cmd_pscheck,   "<file>",        "Check PSR file"                 },
	{ NULL }
};

static void usage(void)
{
	int i, pos = 0;

	printf("bccmd - Utility for the CSR BCCMD interface\n\n");
	printf("Usage:\n"
		"\tbccmd [options] <command>\n\n");

	printf("Options:\n"
		"\t-t <transport>     Select the transport\n"
		"\t-d <device>        Select the device\n"
		"\t-h, --help         Display help\n"
		"\n");

	printf("Commands:\n");
	for (i = 0; commands[i].str; i++)
		printf("\t%-10s %-14s\t%s\n", commands[i].str,
		commands[i].arg ? commands[i].arg : " ",
		commands[i].doc);
	printf("\n");

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
	{ "transport",	1, 0, 't' },
	{ "device",	1, 0, 'd' },
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct hci_dev_info di;
	struct hci_version ver;
	char *device = NULL;
	int i, err, opt, dd, dev, transport = CSR_TRANSPORT_HCI;

	while ((opt=getopt_long(argc, argv, "+t:d:i:h", main_options, NULL)) != EOF) {
		switch (opt) {
		case 't':
			if (!strcasecmp(optarg, "hci"))
				transport = CSR_TRANSPORT_HCI;
			else if (!strcasecmp(optarg, "usb"))
				transport = CSR_TRANSPORT_USB;
			else if (!strcasecmp(optarg, "bcsp"))
				transport = CSR_TRANSPORT_BCSP;
			else if (!strcasecmp(optarg, "h4"))
				transport = CSR_TRANSPORT_H4;
			else if (!strcasecmp(optarg, "h5"))
				transport = CSR_TRANSPORT_3WIRE;
			else if (!strcasecmp(optarg, "3wire"))
				transport = CSR_TRANSPORT_3WIRE;
			else if (!strcasecmp(optarg, "twutl"))
				transport = CSR_TRANSPORT_3WIRE;
			else
				transport = CSR_TRANSPORT_UNKNOWN;
			break;

		case 'd':
		case 'i':
			device = strdup(optarg);
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

	if (transport != CSR_TRANSPORT_HCI) {
		fprintf(stderr, "Unsupported transport\n");
		exit(1);
	}

	if (device) {
		dev = hci_devid(device);
		if (dev < 0) {
			fprintf(stderr, "Device not available\n");
			exit(1);
		}
		free(device);
	} else
		dev = 0;

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

	for (i = 0; commands[i].str; i++) {
		if (strcasecmp(commands[i].str, argv[0]))
			continue;

		err = commands[i].func(dd, argc, argv);

		hci_close_dev(dd);

		if (err < 0) {
			fprintf(stderr, "Can't execute command: %s (%d)\n",
							strerror(errno), errno);
			exit(1);
		}

		exit(0);
	}

	fprintf(stderr, "Unsupported command\n");

	hci_close_dev(dd);

	exit(1);
}
