/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <getopt.h>
#include <stdbool.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/mgmt.h>

#ifndef NELEM
#define NELEM(x) (sizeof(x) / sizeof((x)[0]))
#endif

static const char *mgmt_op[] = {
	"<0x0000>",
	"Read Version",
	"Read Features",
	"Read Index List",
	"Read Controller Info",
	"Set Powered",
	"Set Discoverable",
	"Set Connectable",
	"Set Pairable",
	"Add UUID",
	"Remove UUID",
	"Set Dev Class",
	"Set Service Cache",
	"Load Link Keys",
	"Remove Keys",
	"Disconnect",
	"Get Connections",
	"PIN Code Reply",
	"PIN Code Neg Reply",
	"Set IO Capability",
	"Pair Device",
	"User Confirm Reply",
	"User Confirm Neg Reply",
	"Set Local Name",
	"Read Local OOB Data",
	"Add Remote OOB Data",
	"Remove Remove OOB Data",
	"Start Discoery",
	"Block Device",
	"Unblock Device",
	"Set Fast Connectable",
};

static const char *mgmt_ev[] = {
	"<0x0000>",
	"Command Complete",
	"Command Status",
	"Controller Error",
	"Index Added",
	"Index Removed",
	"Powered",
	"Discoverable",
	"Connectable",
	"Pairable",
	"New Link Key",
	"Device Connected",
	"Device Disconnected",
	"Connect Failed",
	"PIN Code Request",
	"User Confirm Request",
	"Authentication Failed",
	"Local Name Changed",
	"Device Found",
	"Remote Name",
	"Discovering",
	"Device Blocked",
	"Device Unblocked",
};

static bool monitor = false;

typedef void (*cmd_cb)(int mgmt_sk, uint16_t op, uint16_t id, uint8_t status,
				void *rsp, uint16_t len, void *user_data);

static struct pending_cmd {
	uint16_t op;
	uint16_t id;
	cmd_cb cb;
	void *user_data;
	struct pending_cmd *next;
} *pending = NULL;

static const char *mgmt_opstr(uint16_t op)
{
	if (op >= NELEM(mgmt_op))
		return "<unknown opcode>";
	return mgmt_op[op];
}

static const char *mgmt_evstr(uint16_t ev)
{
	if (ev >= NELEM(mgmt_ev))
		return "<unknown event>";
	return mgmt_ev[ev];
}

static int mgmt_send_cmd(int mgmt_sk, uint16_t op, uint16_t id, void *data,
				size_t len, cmd_cb func, void *user_data)
{
	char buf[1024];
	struct pending_cmd *cmd;
	struct mgmt_hdr *hdr = (void *) buf;

	if (len + MGMT_HDR_SIZE > sizeof(buf))
		return -EINVAL;

	cmd = calloc(1, sizeof(struct pending_cmd));
	if (cmd == NULL)
		return -errno;

	cmd->op = op;
	cmd->id = id;
	cmd->cb = func;
	cmd->user_data = user_data;

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(op);
	hdr->index = htobs(id);
	hdr->len = htobs(len);
	memcpy(buf + MGMT_HDR_SIZE, data, len);

	if (write(mgmt_sk, buf, MGMT_HDR_SIZE + len) < 0) {
		fprintf(stderr, "Unable to write to socket: %s\n",
							strerror(errno));
		free(cmd);
		return -1;
	}

	cmd->next = pending;
	pending = cmd;

	return 0;
}

static int mgmt_open(void)
{
	struct sockaddr_hci addr;
	int sk;

	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0) {
		fprintf(stderr, "socket: %s\n", strerror(errno));
		return sk;
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	addr.hci_channel = HCI_CHANNEL_CONTROL;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "bind: %s\n", strerror(errno));
		close(sk);
		return -1;
	}

	return sk;
}

static void mgmt_check_pending(int mgmt_sk, uint16_t op, uint16_t index,
				uint16_t status, void *data, uint16_t len)
{
	struct pending_cmd *c, *prev;

	for (c = pending, prev = NULL; c != NULL; prev = c, c = c->next) {
		if (c->op != op)
			continue;
		if (c->id != index)
			continue;

		if (c == pending)
			pending = c->next;
		else
			prev->next = c->next;

		c->cb(mgmt_sk, op, index, status, data, len, c->user_data);

		free(c);
	}
}

static int mgmt_cmd_complete(int mgmt_sk, uint16_t index,
				struct mgmt_ev_cmd_complete *ev, uint16_t len)
{
	uint16_t op;

	if (len < sizeof(*ev)) {
		fprintf(stderr, "Too short (%u bytes) cmd complete event\n",
									len);
		return -EINVAL;
	}

	op = bt_get_le16(&ev->opcode);

	len -= sizeof(*ev);

	if (monitor)
		printf("%s complete, opcode 0x%04x len %u\n", mgmt_opstr(op),
								op, len);

	mgmt_check_pending(mgmt_sk, op, index, 0, ev->data, len);

	return 0;
}

static int mgmt_cmd_status(int mgmt_sk, uint16_t index,
				struct mgmt_ev_cmd_status *ev, uint16_t len)
{
	uint16_t opcode;

	if (len < sizeof(*ev)) {
		fprintf(stderr, "Too short (%u bytes) cmd status event\n",
									len);
		return -EINVAL;
	}

	opcode = bt_get_le16(&ev->opcode);

	if (monitor)
		printf("cmd status, opcode 0x%04x status 0x%02x\n",
							opcode, ev->status);

	if (ev->status != 0)
		mgmt_check_pending(mgmt_sk, opcode, index, ev->status,
								NULL, 0);

	return 0;
}

static int mgmt_controller_error(uint16_t index,
					struct mgmt_ev_controller_error *ev,
					uint16_t len)
{
	if (len < sizeof(*ev)) {
		fprintf(stderr,
			"Too short (%u bytes) controller error event\n", len);
		return -EINVAL;
	}

	printf("hci%u error 0x%02x\n", index, ev->error_code);

	return 0;
}

static int mgmt_index_added(int mgmt_sk, uint16_t index)
{
	printf("hci%u added\n", index);
	return 0;
}

static int mgmt_index_removed(int mgmt_sk, uint16_t index)
{
	printf("hci%u removed\n", index);
	return 0;
}

static int mgmt_powered(int mgmt_sk, uint16_t index, struct mgmt_mode *ev,
								uint16_t len)
{
	if (len < sizeof(*ev)) {
		fprintf(stderr, "Too short (%u bytes) mgmt powered event\n",
									len);
		return -EINVAL;
	}

	printf("hci%u powered %s\n", index, ev->val ? "on" : "off");

	return 0;
}

static int mgmt_discoverable(int mgmt_sk, uint16_t index, struct mgmt_mode *ev,
								uint16_t len)
{
	if (len < sizeof(*ev)) {
		fprintf(stderr,
			"Too short (%u bytes) mgmt discoverable event\n", len);
		return -EINVAL;
	}

	printf("hci%u discoverable %s\n", index, ev->val ? "on" : "off");

	return 0;
}

static int mgmt_connectable(int mgmt_sk, uint16_t index, struct mgmt_mode *ev,
								uint16_t len)
{
	if (len < sizeof(*ev)) {
		fprintf(stderr,
			"Too short (%u bytes) mgmt connectable event\n", len);
		return -EINVAL;
	}

	printf("hci%u connectable %s\n", index, ev->val ? "on" : "off");

	return 0;
}

static int mgmt_pairable(int mgmt_sk, uint16_t index, struct mgmt_mode *ev,
								uint16_t len)
{
	if (len < sizeof(*ev)) {
		fprintf(stderr, "Too short (%u bytes) mgmt pairable event\n",
									len);
		return -EINVAL;
	}

	printf("hci%u pairable %s\n", index, ev->val ? "on" : "off");

	return 0;
}

static int mgmt_handle_event(int mgmt_sk, uint16_t ev, uint16_t index,
						void *data, uint16_t len)
{
	if (monitor)
		printf("event: %s\n", mgmt_evstr(ev));

	switch (ev) {
	case MGMT_EV_CMD_COMPLETE:
		return mgmt_cmd_complete(mgmt_sk, index, data, len);
	case MGMT_EV_CMD_STATUS:
		return mgmt_cmd_status(mgmt_sk, index, data, len);
	case MGMT_EV_CONTROLLER_ERROR:
		return mgmt_controller_error(index, data, len);
	case MGMT_EV_INDEX_ADDED:
		return mgmt_index_added(mgmt_sk, index);
	case MGMT_EV_INDEX_REMOVED:
		return mgmt_index_removed(mgmt_sk, index);
	case MGMT_EV_POWERED:
		return mgmt_powered(mgmt_sk, index, data, len);
	case MGMT_EV_DISCOVERABLE:
		return mgmt_discoverable(mgmt_sk, index, data, len);
	case MGMT_EV_CONNECTABLE:
		return mgmt_connectable(mgmt_sk, index, data, len);
	case MGMT_EV_PAIRABLE:
		return mgmt_pairable(mgmt_sk, index, data, len);
	default:
		if (monitor)
			printf("Unhandled event 0x%04x (%s)\n", ev, mgmt_evstr(ev));
		return 0;
	}
}

static int mgmt_process_data(int mgmt_sk)
{
	char buf[1024];
	struct mgmt_hdr *hdr = (void *) buf;
	uint16_t len, ev, index;
	ssize_t ret;

	ret = read(mgmt_sk, buf, sizeof(buf));
	if (ret < 0) {
		fprintf(stderr, "read: %s\n", strerror(errno));
		return len;
	}

	if (ret < MGMT_HDR_SIZE) {
		fprintf(stderr, "Too small mgmt packet (%zd bytes)\n", ret);
		return 0;
	}

	ev = bt_get_le16(&hdr->opcode);
	index = bt_get_le16(&hdr->index);
	len = bt_get_le16(&hdr->len);

	if (monitor)
		printf("event 0x%04x len 0x%04x index 0x%04x\n", ev, len, index);

	if (ret != MGMT_HDR_SIZE + len) {
		fprintf(stderr, "Packet length mismatch. ret %zd len %u",
								ret, len);
		return 0;
	}

	mgmt_handle_event(mgmt_sk, ev, index, buf + MGMT_HDR_SIZE, len);

	return 0;
}

static void cmd_monitor(int mgmt_sk, int argc, char **argv)
{
	printf("Monitoring mgmt events...\n");
	monitor = true;
}

static void info_rsp(int mgmt_sk, uint16_t op, uint16_t id, uint8_t status,
				void *rsp, uint16_t len, void *user_data)
{
	struct mgmt_rp_read_info *rp = rsp;
	char addr[18];

	if (status != 0) {
		fprintf(stderr, "Reading hci%u info failed with status %u\n",
								id, status);
		exit(EXIT_FAILURE);
	}

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Too small info reply (%u bytes)\n", len);
		exit(EXIT_FAILURE);
	}

	ba2str(&rp->bdaddr, addr);
	printf("hci%u:\ttype %u addr %s\n", id, rp->type, addr);
	printf("\tclass 0x%02x%02x%02x\n",
		rp->dev_class[2], rp->dev_class[1], rp->dev_class[0]);
	printf("\tmanufacturer %d HCI ver %d:%d\n",
					bt_get_le16(&rp->manufacturer),
					rp->hci_ver, bt_get_le16(&rp->hci_rev));
	printf("\tpowered %u discoverable %u pairable %u sec_mode %u\n",
				rp->powered, rp->discoverable,
				rp->pairable, rp->sec_mode);
	printf("\tname %s\n\n", (char *) rp->name);

	if (pending == NULL)
		exit(EXIT_SUCCESS);
}

static void index_rsp(int mgmt_sk, uint16_t op, uint16_t id, uint8_t status,
				void *rsp, uint16_t len, void *user_data)
{
	struct mgmt_rp_read_index_list *rp = rsp;
	uint16_t count;
	unsigned int i;

	if (status != 0) {
		fprintf(stderr, "Reading index list failed with status %u\n",
								status);
		exit(EXIT_FAILURE);
	}

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Too small index list reply (%u bytes)\n",
									len);
		exit(EXIT_FAILURE);
	}

	count = bt_get_le16(&rp->num_controllers);

	if (len < sizeof(*rp) + count * sizeof(uint16_t)) {
		fprintf(stderr,
			"Index count (%u) doesn't match reply length (%u)\n",
								count, len);
		exit(EXIT_FAILURE);
	}

	if (monitor)
		printf("Index list with %u item%s\n",
						count, count > 1 ? "s" : "");

	if (count == 0)
		exit(EXIT_SUCCESS);

	if (monitor && count > 0)
		printf("\t");

	for (i = 0; i < count; i++) {
		uint16_t index;

		index = bt_get_le16(&rp->index[i]);

		if (monitor)
			printf("hci%u ", index);

		if (mgmt_send_cmd(mgmt_sk, MGMT_OP_READ_INFO, index, NULL,
					0, info_rsp, NULL) < 0) {
			fprintf(stderr, "Unable to send read_info cmd\n");
			exit(EXIT_FAILURE);
		}
	}

	if (monitor && count > 0)
		printf("\n");
}

static void cmd_info(int mgmt_sk, int argc, char **argv)
{
	if (argc < 2) {
		if (mgmt_send_cmd(mgmt_sk, MGMT_OP_READ_INDEX_LIST,
					MGMT_INDEX_NONE, NULL, 0,
					index_rsp, NULL) < 0) {
			fprintf(stderr, "Unable to send index_list cmd\n");
			exit(EXIT_FAILURE);
		}

		return;
	}

	if (mgmt_send_cmd(mgmt_sk, MGMT_OP_READ_INFO, atoi(argv[1]), NULL,
						0, info_rsp, NULL) < 0) {
		fprintf(stderr, "Unable to send read_info cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void power_rsp(int mgmt_sk, uint16_t op, uint16_t id, uint8_t status,
				void *rsp, uint16_t len, void *user_data)
{
	struct mgmt_mode *rp = rsp;

	if (status != 0) {
		fprintf(stderr, "Changing powered state for hci%u "
				"failed with status %u\n", id, status);
		exit(EXIT_FAILURE);
	}

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Too small set_powered response (%u bytes)\n",
									len);
		exit(EXIT_FAILURE);
	}

	printf("hci%u powered %s\n", id, rp->val ? "on" : "off");

	exit(EXIT_SUCCESS);
}


static void cmd_power(int mgmt_sk, int argc, char **argv)
{
	uint8_t power;

	if (argc < 2) {
		printf("Specify \"on\" or \"off\"\n");
		exit(EXIT_FAILURE);
	}

	if (strcasecmp(argv[1], "on") == 0)
		power = 1;
	else if (strcasecmp(argv[1], "off") == 0)
		power = 0;
	else
		power = atoi(argv[1]);

	if (mgmt_send_cmd(mgmt_sk, MGMT_OP_SET_POWERED, 0, &power,
					sizeof(power), power_rsp, NULL) < 0) {
		fprintf(stderr, "Unable to send set_powered cmd\n");
		exit(EXIT_FAILURE);
	}
}

static struct {
	char *cmd;
	void (*func)(int mgmt_sk, int argc, char **argv);
	char *doc;
} command[] = {
	{ "monitor",	cmd_monitor,	"Monitor events"		},
	{ "info",	cmd_info,	"Show controller info"		},
	{ "power",	cmd_power,	"Toggle powered state"		},
	{ NULL, NULL, 0 }
};

static void usage(void)
{
	int i;

	printf("btmgmt ver %s\n", VERSION);
	printf("Usage:\n"
		"\tbtmgmt [options] <command> [command parameters]\n");

	printf("Options:\n"
		"\t--verbose\tEnable extra logging\n"
		"\t--help\tDisplay help\n");

	printf("Commands:\n");
	for (i = 0; command[i].cmd; i++)
		printf("\t%-4s\t%s\n", command[i].cmd, command[i].doc);

	printf("\n"
		"For more information on the usage of each command use:\n"
		"\tbtmgmt <command> --help\n" );
}

static struct option main_options[] = {
	{ "verbose",	0, 0, 'v' },
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	int opt, i, mgmt_sk;
	struct pollfd pollfd;

	while ((opt=getopt_long(argc, argv, "+hv", main_options, NULL)) != -1) {
		switch (opt) {
		case 'v':
			monitor = true;
			break;
		case 'h':
		default:
			usage();
			return 0;
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		usage();
		return 0;
	}

	mgmt_sk = mgmt_open();
	if (mgmt_sk < 0) {
		fprintf(stderr, "Unable to open mgmt socket\n");
		return -1;
	}

	for (i = 0; command[i].cmd; i++) {
		if (strcmp(command[i].cmd, argv[0]) != 0)
			continue;

		command[i].func(mgmt_sk, argc, argv);
		break;
	}

	pollfd.fd = mgmt_sk;
	pollfd.events = POLLIN;
	pollfd.revents = 0;

	while (poll(&pollfd, 1, -1) >= 0) {
		if (pollfd.revents & (POLLHUP | POLLERR | POLLNVAL))
			break;

		if (pollfd.revents & POLLIN)
			mgmt_process_data(mgmt_sk);

		pollfd.revents = 0;
	}

	close(mgmt_sk);

	return 0;
}
