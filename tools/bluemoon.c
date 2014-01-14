/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "monitor/mainloop.h"
#include "monitor/bt.h"
#include "src/shared/util.h"
#include "src/shared/hci.h"

#define CMD_BLUEMOON_READ_VERSION	0xfc05
struct rsp_bluemoon_read_version {
	uint8_t  status;
	uint8_t  hw_platform;
	uint8_t  hw_variant;
	uint8_t  hw_revision;
	uint8_t  fw_variant;
	uint8_t  fw_revision;
	uint8_t  fw_build_nn;
	uint8_t  fw_build_cw;
	uint8_t  fw_build_yy;
	uint8_t  fw_patch;
} __attribute__ ((packed));

static struct bt_hci *hci_dev;

static void bluemoon_read_version_complete(const void *data, uint8_t size,
							void *user_data)
{
	const struct rsp_bluemoon_read_version *rsp = data;
	const char *str;

	if (rsp->status) {
		fprintf(stderr, "Failed to read version (0x%02x)\n",
							rsp->status);
		mainloop_quit();
		return;
	}

	printf("Controller Version Information\n");
	printf("\tHardware Platform:\t%u\n", rsp->hw_platform);

	switch (rsp->hw_variant) {
	case 0x07:
		str = "iBT 2.0";
		break;
	default:
		str = "Reserved";
		break;
	}

	printf("\tHardware Variant:\t%s (0x%02x)\n", str, rsp->hw_variant);
	printf("\tHardware Revision:\t%u.%u\n", rsp->hw_revision >> 4,
						rsp->hw_revision & 0x0f);

	switch (rsp->fw_variant) {
	case 0x01:
		str = "BT IP 4.0";
		break;
	case 0x06:
		str = "iBT Bootloader";
		break;
	default:
		str = "Reserved";
		break;
	}

	printf("\tFirmware Variant:\t%s (0x%02x)\n", str, rsp->fw_variant);
	printf("\tFirmware Revision:\t%u.%u\n", rsp->fw_revision >> 4,
						rsp->fw_revision & 0x0f);
	printf("\tFirmware Build Number:\t%u-%u.%u\n", rsp->fw_build_nn,
				rsp->fw_build_cw, 2000 + rsp->fw_build_yy);
	printf("\tFirmware Patch Number:\t%u\n", rsp->fw_patch);

	mainloop_quit();
}

static void read_local_version_complete(const void *data, uint8_t size,
							void *user_data)
{
	const struct bt_hci_rsp_read_local_version *rsp = data;
	uint16_t manufacturer;

	if (rsp->status) {
		fprintf(stderr, "Failed to read local version (0x%02x)\n",
								rsp->status);
		mainloop_quit();
		return;
	}

	manufacturer = le16_to_cpu(rsp->manufacturer);

	if (manufacturer != 2) {
		fprintf(stderr, "Unsupported manufacturer (%u)\n",
							manufacturer);
		mainloop_quit();
		return;
	}

	bt_hci_send(hci_dev, CMD_BLUEMOON_READ_VERSION,  NULL, 0,
				bluemoon_read_version_complete, NULL, NULL);
}

static void signal_callback(int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		mainloop_quit();
		break;
	}
}

static void usage(void)
{
	printf("bluemoon - Bluemoon configuration utility\n"
		"Usage:\n");
	printf("\tbluemoon [options]\n");
	printf("Options:\n"
		"\t-i, --index <num>      Use specified controller\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "index",   required_argument, NULL, 'i' },
	{ "version", no_argument,       NULL, 'v' },
	{ "help",    no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	uint16_t index = 0;
	const char *str;
	sigset_t mask;
	int exit_status;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "i:vh", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'i':
			if (strlen(optarg) > 3 && !strncmp(optarg, "hci", 3))
				str = optarg + 3;
			else
				str = optarg;
			if (!isdigit(*str)) {
				usage();
				return EXIT_FAILURE;
			}
			index = atoi(str);
			break;
		case 'v':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return EXIT_FAILURE;
	}

	mainloop_init();

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	mainloop_set_signal(&mask, signal_callback, NULL, NULL);

	printf("Bluemoon configuration utility ver %s\n", VERSION);

	hci_dev = bt_hci_new_user_channel(index);
	if (!hci_dev) {
		fprintf(stderr, "Failed to open HCI user channel\n");
		return EXIT_FAILURE;
	}

	bt_hci_send(hci_dev, BT_HCI_CMD_READ_LOCAL_VERSION, NULL, 0,
				read_local_version_complete, NULL, NULL);

	exit_status = mainloop_run();

	bt_hci_unref(hci_dev);

	return exit_status;
}
