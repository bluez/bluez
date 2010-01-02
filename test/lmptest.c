/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2005-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#if 0
#define OCF_ERICSSON_SEND_LMP		0x0021
typedef struct {
	uint16_t handle;
	uint8_t  length;
	uint8_t  data[17];
} __attribute__ ((packed)) ericsson_send_lmp_cp;
#define ERICSSON_SEND_LMP_CP_SIZE 20

static int ericsson_send_lmp(int dd, uint16_t handle, uint8_t length, uint8_t *data)
{
	struct hci_request rq;
	ericsson_send_lmp_cp cp;

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(handle);
	cp.length = length;
	memcpy(cp.data, data, length);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_VENDOR_CMD;
	rq.ocf    = OCF_ERICSSON_SEND_LMP;
	rq.cparam = &cp;
	rq.clen   = ERICSSON_SEND_LMP_CP_SIZE;
	rq.rparam = NULL;
	rq.rlen   = 0;

	if (hci_send_req(dd, &rq, 1000) < 0)
		return -1;

	return 0;
}
#endif

#define OCF_ERICSSON_WRITE_EVENTS	0x0043
typedef struct {
	uint8_t mask;
	uint8_t opcode;
	uint8_t opcode_ext;
} __attribute__ ((packed)) ericsson_write_events_cp;
#define ERICSSON_WRITE_EVENTS_CP_SIZE 3

static int ericsson_write_events(int dd, uint8_t mask)
{
	struct hci_request rq;
	ericsson_write_events_cp cp;

	memset(&cp, 0, sizeof(cp));
	cp.mask = mask;
	cp.opcode = 0x00;
	cp.opcode_ext = 0x00;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_VENDOR_CMD;
	rq.ocf    = OCF_ERICSSON_WRITE_EVENTS;
	rq.cparam = &cp;
	rq.clen   = ERICSSON_WRITE_EVENTS_CP_SIZE;
	rq.rparam = NULL;
	rq.rlen   = 0;

	if (hci_send_req(dd, &rq, 1000) < 0)
		return -1;

	return 0;
}

static void usage(void)
{
	printf("lmptest - Utility for testing special LMP functions\n\n");
	printf("Usage:\n"
		"\tlmptest [-i <dev>]\n");
}

static struct option main_options[] = {
	{ "device",	1, 0, 'i' },
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct hci_version ver;
	int dd, opt, dev = 0;

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

	dd = hci_open_dev(dev);
	if (dd < 0) {
		fprintf(stderr, "Can't open device hci%d: %s (%d)\n",
						dev, strerror(errno), errno);
		exit(1);
	}

	if (hci_read_local_version(dd, &ver, 1000) < 0) {
		fprintf(stderr, "Can't read version for hci%d: %s (%d)\n",
						dev, strerror(errno), errno);
		hci_close_dev(dd);
		exit(1);
	}

	if (ver.manufacturer != 37 && ver.manufacturer != 48) {
		fprintf(stderr, "Can't find supported device hci%d: %s (%d)\n",
						dev, strerror(ENOSYS), ENOSYS);
		hci_close_dev(dd);
		exit(1);
	}

	if (ericsson_write_events(dd, 0x03) < 0) {
		fprintf(stderr, "Can't activate events for hci%d: %s (%d)\n",
						dev, strerror(errno), errno);
		hci_close_dev(dd);
		exit(1);
	}

	hci_close_dev(dd);

	return 0;
}
