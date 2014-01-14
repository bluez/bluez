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

#define CMD_READ_VERSION	0xfc05
struct rsp_read_version {
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

#define CMD_MANUFACTURER_MODE	0xfc11
struct cmd_manufacturer_mode {
	uint8_t  mode_switch;
	uint8_t  reset;
} __attribute__ ((packed));

#define CMD_WRITE_BD_DATA	0xfc2f
struct cmd_write_bd_data {
	uint8_t  bdaddr[6];
	uint8_t  reserved1[6];
	uint8_t  features[8];
	uint8_t  le_features;
	uint8_t  reserved2[32];
	uint8_t  lmp_version;
	uint8_t  reserved3[26];
} __attribute__ ((packed));

#define CMD_READ_BD_DATA	0xfc30
struct rsp_read_bd_data {
	uint8_t  status;
	uint8_t  bdaddr[6];
	uint8_t  reserved1[6];
	uint8_t  features[8];
	uint8_t  le_features;
	uint8_t  reserved2[32];
	uint8_t  lmp_version;
	uint8_t  reserved3[26];
} __attribute__ ((packed));

#define CMD_WRITE_BD_ADDRESS	0xfc31
struct cmd_write_bd_address {
	uint8_t  bdaddr[6];
} __attribute__ ((packed));

#define CMD_ACT_DEACT_TRACES	0xfc43
struct cmd_act_deact_traces {
	uint8_t  tx_trace;
	uint8_t  tx_arq;
	uint8_t  rx_trace;
} __attribute__ ((packed));

static struct bt_hci *hci_dev;
static uint16_t hci_index = 0;

static bool set_bdaddr = false;
static const char *set_bdaddr_value = NULL;

static bool reset_on_exit = false;
static bool use_manufacturer_mode = false;
static bool get_bddata = false;
static bool set_traces = false;

static void reset_complete(const void *data, uint8_t size, void *user_data)
{
	uint8_t status = *((uint8_t *) data);

	if (status) {
		fprintf(stderr, "Failed to reset (0x%02x)\n", status);
		mainloop_quit();
		return;
	}

	mainloop_quit();
}

static void leave_manufacturer_mode_complete(const void *data, uint8_t size,
							void *user_data)
{
	uint8_t status = *((uint8_t *) data);

	if (status) {
		fprintf(stderr, "Failed to leave manufacturer mode (0x%02x)\n",
									status);
		mainloop_quit();
		return;
	}

	if (reset_on_exit) {
		bt_hci_send(hci_dev, BT_HCI_CMD_RESET, NULL, 0,
						reset_complete, NULL, NULL);
		return;
	}

	mainloop_quit();
}

static void shutdown_device(void)
{
	bt_hci_flush(hci_dev);

	if (use_manufacturer_mode) {
		struct cmd_manufacturer_mode cmd;

		cmd.mode_switch = 0x00;
		cmd.reset = 0x00;

		bt_hci_send(hci_dev, CMD_MANUFACTURER_MODE, &cmd, sizeof(cmd),
				leave_manufacturer_mode_complete, NULL, NULL);
		return;
	}

	if (reset_on_exit) {
		bt_hci_send(hci_dev, BT_HCI_CMD_RESET, NULL, 0,
						reset_complete, NULL, NULL);
		return;
	}

	mainloop_quit();
}

static void write_bd_address_complete(const void *data, uint8_t size,
							void *user_data)
{
	uint8_t status = *((uint8_t *) data);

	if (status) {
		fprintf(stderr, "Failed to write address (0x%02x)\n", status);
		mainloop_quit();
		return;
	}

	shutdown_device();
}

static void read_bd_addr_complete(const void *data, uint8_t size,
							void *user_data)
{
	const struct bt_hci_rsp_read_bd_addr *rsp = data;
	struct cmd_write_bd_address cmd;

	if (rsp->status) {
		fprintf(stderr, "Failed to read address (0x%02x)\n",
							rsp->status);
		mainloop_quit();
		shutdown_device();
		return;
	}

	if (set_bdaddr_value) {
		fprintf(stderr, "Setting address is not supported\n");
		mainloop_quit();
		return;
	}

	printf("Controller Address\n");
	printf("\tOld BD_ADDR: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",
					rsp->bdaddr[5], rsp->bdaddr[4],
					rsp->bdaddr[3], rsp->bdaddr[2],
					rsp->bdaddr[1], rsp->bdaddr[0]);

	memcpy(cmd.bdaddr, rsp->bdaddr, 6);
	cmd.bdaddr[0] = (hci_index & 0xff);

	printf("\tNew BD_ADDR: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",
					cmd.bdaddr[5], cmd.bdaddr[4],
					cmd.bdaddr[3], cmd.bdaddr[2],
					cmd.bdaddr[1], cmd.bdaddr[0]);

	bt_hci_send(hci_dev, CMD_WRITE_BD_ADDRESS, &cmd, sizeof(cmd),
					write_bd_address_complete, NULL, NULL);
}

static void act_deact_traces_complete(const void *data, uint8_t size,
							void *user_data)
{
	uint8_t status = *((uint8_t *) data);

	if (status) {
		fprintf(stderr, "Failed to activate traces (0x%02x)\n", status);
		shutdown_device();
		return;
	}

	shutdown_device();
}

static void act_deact_traces(void)
{
	struct cmd_act_deact_traces cmd;

	cmd.tx_trace = 0x03;
	cmd.tx_arq = 0x03;
	cmd.rx_trace = 0x03;

	bt_hci_send(hci_dev, CMD_ACT_DEACT_TRACES, &cmd, sizeof(cmd),
					act_deact_traces_complete, NULL, NULL);
}

static void write_bd_data_complete(const void *data, uint8_t size,
							void *user_data)
{
	uint8_t status = *((uint8_t *) data);

	if (status) {
		fprintf(stderr, "Failed to write data (0x%02x)\n", status);
		shutdown_device();
		return;
	}

	if (set_traces) {
		act_deact_traces();
		return;
	}

	shutdown_device();
}

static void read_bd_data_complete(const void *data, uint8_t size,
							void *user_data)
{
	const struct rsp_read_bd_data *rsp = data;

	if (rsp->status) {
		fprintf(stderr, "Failed to read data (0x%02x)\n", rsp->status);
		shutdown_device();
		return;
	}

	printf("Controller Data\n");
	printf("\tBD_ADDR: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",
					rsp->bdaddr[5], rsp->bdaddr[4],
					rsp->bdaddr[3], rsp->bdaddr[2],
					rsp->bdaddr[1], rsp->bdaddr[0]);

	printf("\tLMP Version: %u\n", rsp->lmp_version);
	printf("\tLMP Features: 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x"
					" 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x\n",
					rsp->features[0], rsp->features[1],
					rsp->features[2], rsp->features[3],
					rsp->features[4], rsp->features[5],
					rsp->features[6], rsp->features[7]);
	printf("\tLE Features: 0x%2.2x\n", rsp->le_features);

	if (set_bdaddr) {
		struct cmd_write_bd_data cmd;

		memcpy(cmd.bdaddr, rsp->bdaddr, 6);
		cmd.bdaddr[0] = (hci_index & 0xff);
		cmd.lmp_version = 0x07;
		memcpy(cmd.features, rsp->features, 8);
		cmd.le_features = rsp->le_features;
		cmd.le_features |= 0x1e;
		memcpy(cmd.reserved1, rsp->reserved1, sizeof(cmd.reserved1));
		memcpy(cmd.reserved2, rsp->reserved2, sizeof(cmd.reserved2));
		memcpy(cmd.reserved3, rsp->reserved3, sizeof(cmd.reserved3));

		bt_hci_send(hci_dev, CMD_WRITE_BD_DATA, &cmd, sizeof(cmd),
					write_bd_data_complete, NULL, NULL);
		return;
	}

	shutdown_device();
}

static void enter_manufacturer_mode_complete(const void *data, uint8_t size,
							void *user_data)
{
	uint8_t status = *((uint8_t *) data);

	if (status) {
		fprintf(stderr, "Failed to enter manufacturer mode (0x%02x)\n",
									status);
		mainloop_quit();
		return;
	}

	if (get_bddata || set_bdaddr) {
		bt_hci_send(hci_dev, CMD_READ_BD_DATA, NULL, 0,
					read_bd_data_complete, NULL, NULL);
		return;
	}

	if (set_traces) {
		act_deact_traces();
		return;
	}

	shutdown_device();
}

static void read_version_complete(const void *data, uint8_t size,
							void *user_data)
{
	const struct rsp_read_version *rsp = data;
	const char *str;

	if (rsp->status) {
		fprintf(stderr, "Failed to read version (0x%02x)\n",
							rsp->status);
		mainloop_quit();
		return;
	}

	if (use_manufacturer_mode) {
		struct cmd_manufacturer_mode cmd;

		cmd.mode_switch = 0x01;
		cmd.reset = 0x00;

		bt_hci_send(hci_dev, CMD_MANUFACTURER_MODE, &cmd, sizeof(cmd),
				enter_manufacturer_mode_complete, NULL, NULL);
		return;
	}

	if (set_bdaddr) {
		bt_hci_send(hci_dev, BT_HCI_CMD_READ_BD_ADDR, NULL, 0,
					read_bd_addr_complete, NULL, NULL);
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

	bt_hci_send(hci_dev, CMD_READ_VERSION, NULL, 0,
					read_version_complete, NULL, NULL);
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
		"\t-B, --bdaddr [addr]    Set Bluetooth address\n"
		"\t-R, --reset            Reset controller\n"
		"\t-i, --index <num>      Use specified controller\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "bdaddr",  optional_argument, NULL, 'A' },
	{ "bddata",  no_argument,       NULL, 'D' },
	{ "traces",  no_argument,       NULL, 'T' },
	{ "reset",   no_argument,       NULL, 'R' },
	{ "index",   required_argument, NULL, 'i' },
	{ "version", no_argument,       NULL, 'v' },
	{ "help",    no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	const char *str;
	sigset_t mask;
	int exit_status;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "A::DTRi:vh", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'A':
			if (optarg)
				set_bdaddr_value = optarg;
			set_bdaddr = true;
			break;
		case 'D':
			use_manufacturer_mode = true;
			get_bddata = true;
			break;
		case 'T':
			use_manufacturer_mode = true;
			set_traces = true;
			break;
		case 'R':
			reset_on_exit = true;
			break;
		case 'i':
			if (strlen(optarg) > 3 && !strncmp(optarg, "hci", 3))
				str = optarg + 3;
			else
				str = optarg;
			if (!isdigit(*str)) {
				usage();
				return EXIT_FAILURE;
			}
			hci_index = atoi(str);
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

	hci_dev = bt_hci_new_user_channel(hci_index);
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
