/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <unistd.h>
#include <stdlib.h>
#include <alloca.h>
#include <getopt.h>
#include <stdbool.h>
#include <poll.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#include "monitor/bt.h"

#define le16_to_cpu(val) (val)
#define le32_to_cpu(val) (val)
#define cpu_to_le16(val) (val)
#define cpu_to_le32(val) (val)

struct bt_h4_pkt {
	uint8_t type;
	union {
		struct {
			uint16_t opcode;
			uint8_t plen;
			union {
				uint8_t data;
			};
		} cmd;
		struct {
			uint8_t event;
			uint8_t plen;
			union {
				uint8_t data;
				struct bt_hci_evt_cmd_complete cmd_complete;
				struct bt_hci_evt_cmd_status cmd_status;
			};
		} evt;
	};
} __attribute__ ((packed));

static bool hci_request(int fd, uint16_t opcode,
			const void *cmd_data, uint8_t cmd_len,
			void *rsp_data, uint8_t rsp_size, uint8_t *rsp_len)
{
	struct bt_h4_pkt *cmd = alloca(4 + cmd_len);
	struct bt_h4_pkt *rsp = alloca(2048);
	ssize_t len;

	cmd->type = BT_H4_CMD_PKT;
	cmd->cmd.opcode = cpu_to_le16(opcode);
	cmd->cmd.plen = cpu_to_le16(cmd_len);
	if (cmd_len > 0)
		memcpy(&cmd->cmd.data, cmd_data, cmd_len);

	if (write(fd, cmd, 4 + cmd_len) < 0) {
		perror("Failed to write command");
		return false;
	}

	len = read(fd, rsp, 2048);
	if (len < 0) {
		perror("Failed to read event");
		return false;
	}

	if (rsp->type != BT_H4_EVT_PKT) {
		fprintf(stderr, "Unexpected packet type %d\n", rsp->type);
		return false;
	}

	if (rsp->evt.event == BT_HCI_EVT_CMD_COMPLETE) {
		if (opcode != le16_to_cpu(rsp->evt.cmd_complete.opcode))
			return false;

		if (rsp_data)
			memcpy(rsp_data, (&rsp->evt.data) + 3, rsp->evt.plen - 3);

		if (rsp_len)
			*rsp_len = rsp->evt.plen - 3;

		return true;
	} else if (rsp->evt.event == BT_HCI_EVT_CMD_STATUS) {
		if (opcode == le16_to_cpu(rsp->evt.cmd_status.opcode))
			return false;

		if (rsp->evt.cmd_status.status != BT_HCI_ERR_SUCCESS)
			return false;

		if (rsp_len)
			*rsp_len = 0;

		return true;
	}

	return false;
}

static int cmd_local(int fd, int argc, char *argv[])
{
	struct bt_hci_rsp_read_local_features lf;
	struct bt_hci_rsp_read_local_version lv;
	struct bt_hci_rsp_read_local_commands lc;
	struct bt_hci_cmd_read_local_ext_features lef_cmd;
	struct bt_hci_rsp_read_local_ext_features lef;
	uint8_t len;

	if (!hci_request(fd, BT_HCI_CMD_RESET, NULL, 0, NULL, 0, &len))
		return EXIT_FAILURE;

	if (!hci_request(fd, BT_HCI_CMD_READ_LOCAL_FEATURES, NULL, 0,
						&lf, sizeof(lf), &len))
		return EXIT_FAILURE;

	if (lf.status != BT_HCI_ERR_SUCCESS)
		return EXIT_FAILURE;

	printf("Features: 0x%02x 0x%02x 0x%02x 0x%02x "
					"0x%02x 0x%02x 0x%02x 0x%02x\n",
					lf.features[0], lf.features[1],
					lf.features[2], lf.features[3],
					lf.features[4], lf.features[5],
					lf.features[6], lf.features[7]);

	if (!hci_request(fd, BT_HCI_CMD_READ_LOCAL_VERSION, NULL, 0,
						&lv, sizeof(lv), &len))
		return EXIT_FAILURE;

	if (lv.status != BT_HCI_ERR_SUCCESS)
		return EXIT_FAILURE;

	printf("Version: %d\n", lv.hci_ver);
	printf("Manufacturer: %d\n", le16_to_cpu(lv.manufacturer));

	if (!hci_request(fd, BT_HCI_CMD_READ_LOCAL_COMMANDS, NULL, 0,
						&lc, sizeof(lc), &len))
		return EXIT_FAILURE;

	if (lc.status != BT_HCI_ERR_SUCCESS)
		return EXIT_FAILURE;

	if (!(lf.features[7] & 0x80))
		return EXIT_SUCCESS;

	lef_cmd.page = 0x01;

	if (!hci_request(fd, BT_HCI_CMD_READ_LOCAL_EXT_FEATURES,
						&lef_cmd, sizeof(lef_cmd),
						&lef, sizeof(lef), &len))
		return EXIT_FAILURE;

	if (lef.status != BT_HCI_ERR_SUCCESS)
		return EXIT_FAILURE;

	printf("Host features: 0x%02x 0x%02x 0x%02x 0x%02x "
					"0x%02x 0x%02x 0x%02x 0x%02x\n",
					lef.features[0], lef.features[1],
					lef.features[2], lef.features[3],
					lef.features[4], lef.features[5],
					lef.features[6], lef.features[7]);

	if (lef.max_page < 0x02)
		return EXIT_SUCCESS;

	lef_cmd.page = 0x02;

	if (!hci_request(fd, BT_HCI_CMD_READ_LOCAL_EXT_FEATURES,
						&lef_cmd, sizeof(lef_cmd),
						&lef, sizeof(lef), &len))
		return EXIT_FAILURE;

	if (lef.status != BT_HCI_ERR_SUCCESS)
		return EXIT_FAILURE;

	printf("Extended features: 0x%02x 0x%02x 0x%02x 0x%02x "
					"0x%02x 0x%02x 0x%02x 0x%02x\n",
					lef.features[0], lef.features[1],
					lef.features[2], lef.features[3],
					lef.features[4], lef.features[5],
					lef.features[6], lef.features[7]);

	return EXIT_SUCCESS;
}

typedef int (*cmd_func_t)(int fd, int argc, char *argv[]);

static const struct {
	const char *name;
	cmd_func_t func;
	const char *help;
} cmd_table[] = {
	{ "local", cmd_local, "Print local controller details" },
	{ }
};

static void usage(void)
{
	int i;

	printf("btinfo - Bluetooth device testing tool\n"
		"Usage:\n");
	printf("\tbtinfo [options] <command>\n");
	printf("options:\n"
		"\t-i, --device <hcidev>    Use local HCI device\n"
		"\t-h, --help               Show help options\n");
	printf("commands:\n");
	for (i = 0; cmd_table[i].name; i++)
		printf("\t%-25s%s\n", cmd_table[i].name, cmd_table[i].help);
}

static const struct option main_options[] = {
	{ "device",  required_argument, NULL, 'i' },
	{ "version", no_argument,       NULL, 'v' },
	{ "help",    no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	const char *device = NULL;
	cmd_func_t func = NULL;
	struct sockaddr_hci addr;
	int result, fd, i;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "i:vh",
						main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'i':
			device = optarg;
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

	if (argc - optind < 1) {
		fprintf(stderr, "Missing command argument\n");
		return EXIT_FAILURE;
	}

	for (i = 0; cmd_table[i].name; i++) {
		if (!strcmp(cmd_table[i].name, argv[optind])) {
			func = cmd_table[i].func;
			break;
		}
	}

	if (!func) {
		fprintf(stderr, "Unsupported command specified\n");
		return EXIT_FAILURE;
	}

	fd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
	if (fd < 0) {
		perror("Failed to open channel");
		return EXIT_FAILURE;
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_channel = HCI_CHANNEL_USER;

	if (device)
		addr.hci_dev = atoi(device);
	else
		addr.hci_dev = 0;

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to bind channel");
		close(fd);
		return EXIT_FAILURE;
	}

	result = func(fd, argc - optind - 1, argv + optind + 1);

	close(fd);

	return result;
}
