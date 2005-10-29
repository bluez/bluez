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

static int cmd_builddef(int dd, int argc, char *argv[])
{
	uint8_t buf[8];
	uint16_t seqnum = 0x4711, def = 0x0000, nextdef = 0x0000;
	int err = 0;

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

	if (argc < 1) {
		errno = EINVAL;
		return -1;
	}

	if (argc > 1) {
		errno = E2BIG;
		return -1;
	}

	handle = atoi(argv[0]);

	memset(buf, 0, sizeof(buf));
	buf[0] = handle & 0xff;
	buf[1] = handle >> 8;

	err = csr_read_varid_complex(dd, 0x4711,
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

	err = csr_read_varid_uint32(dd, 0x4711, CSR_VARID_BT_CLOCK, &clock);
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

	err = csr_read_varid_uint16(dd, 5, CSR_VARID_RAND, &rand);
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

	err = csr_read_varid_uint16(dd, 5, CSR_VARID_PANIC_ARG, &error);
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

	err = csr_read_varid_uint16(dd, 5, CSR_VARID_FAULT_ARG, &error);
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
	return csr_write_varid_valueless(dd, 0, CSR_VARID_COLD_RESET);
}

static int cmd_warmreset(int dd, int argc, char *argv[])
{
	return csr_write_varid_valueless(dd, 0, CSR_VARID_WARM_RESET);
}

static int cmd_disabletx(int dd, int argc, char *argv[])
{
	return csr_write_varid_valueless(dd, 0, CSR_VARID_DISABLE_TX);
}

static int cmd_enabletx(int dd, int argc, char *argv[])
{
	return csr_write_varid_valueless(dd, 0, CSR_VARID_ENABLE_TX);
}

static struct {
	char *str;
	int (*func)(int dd, int argc, char **argv);
	char *arg;
	char *doc;
} commands[] = {
	{ "builddef",  cmd_builddef,  "",         "Get build definitions"        },
	{ "keylen",    cmd_keylen,    "<handle>", "Get current crypt key length" },
	{ "clock",     cmd_clock,     "",         "Get local Bluetooth clock"    },
	{ "rand",      cmd_rand,      "",         "Get random number"            },
	{ "panicarg",  cmd_panicarg,  "",         "Get panic code argument"      },
	{ "faultarg",  cmd_faultarg,  "",         "Get fault code argument"      },
	{ "coldreset", cmd_coldreset, "",         "Perform cold reset"           },
	{ "warmreset", cmd_warmreset, "",         "Perform warm reset"           },
	{ "disabletx", cmd_disabletx, "",         "Disable TX on the device"     },
	{ "enabletx",  cmd_enabletx,  "",         "Enable TX on the device"      },
	{ NULL },
};

static void usage(void)
{
	int i;

	printf("bccmd - Utility for the CSR BCCMD interface\n\n");
	printf("Usage:\n"
		"\tbccmd [-i <dev>] <command>\n\n");

	printf("Commands:\n");
		for (i = 0; commands[i].str; i++)
			printf("\t%-10s%-8s\t%s\n", commands[i].str,
				commands[i].arg, commands[i].doc);
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

	for (i = 0; commands[i].str; i++) {
		if (strcasecmp(commands[i].str, argv[0]))
			continue;

		err = commands[i].func(dd, argc - 1, argv + 1);

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
