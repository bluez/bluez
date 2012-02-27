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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/mgmt.h>

#include "mainloop.h"
#include "packet.h"
#include "control.h"

struct control_data {
	uint16_t channel;
	int fd;
};

static void free_data(void *user_data)
{
	struct control_data *data = user_data;

	close(data->fd);

	free(data);
}

static void mgmt_index_added(uint16_t len, const void *buf)
{
	printf("@ Index Added\n");

	packet_hexdump(buf, len);
}

static void mgmt_index_removed(uint16_t len, const void *buf)
{
	printf("@ Index Removed\n");

	packet_hexdump(buf, len);
}

static void mgmt_controller_error(uint16_t len, const void *buf)
{
	const struct mgmt_ev_controller_error *ev = buf;

	if (len < sizeof(*ev)) {
		printf("* Malformed Controller Error control\n");
		return;
	}

	printf("@ Controller Error: 0x%2.2x\n", ev->error_code);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

#ifndef NELEM
#define NELEM(x) (sizeof(x) / sizeof((x)[0]))
#endif

static const char *settings_str[] = {
	"powered", "connectable", "fast-connectable", "discoverable",
	"pairable", "link-security", "ssp", "br/edr", "hs", "le"
};

static void mgmt_new_settings(uint16_t len, const void *buf)
{
	uint32_t settings;
	unsigned int i;

	if (len < 4) {
		printf("* Malformed New Settings control\n");
		return;
	}

	settings = bt_get_le32(buf);

	printf("@ New Settings: 0x%4.4x\n", settings);

	printf("%-12c", ' ');
	for (i = 0; i < NELEM(settings_str); i++) {
		if (settings & (1 << i))
			printf("%s ", settings_str[i]);
	}
	printf("\n");

	buf += 4;
	len -= 4;

	packet_hexdump(buf, len);
}

static void mgmt_class_of_dev_changed(uint16_t len, const void *buf)
{
	const struct mgmt_ev_class_of_dev_changed *ev = buf;

	if (len < sizeof(*ev)) {
		printf("* Malformed Class of Device Changed control\n");
		return;
	}

	printf("@ Class of Device Changed: 0x%2.2x%2.2x%2.2x\n",
						ev->class_of_dev[2],
						ev->class_of_dev[1],
						ev->class_of_dev[0]);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_local_name_changed(uint16_t len, const void *buf)
{
	const struct mgmt_ev_local_name_changed *ev = buf;

	if (len < sizeof(*ev)) {
		printf("* Malformed Local Name Changed control\n");
		return;
	}

	printf("@ Local Name Changed: %s (%s)\n", ev->name, ev->short_name);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_new_link_key(uint16_t len, const void *buf)
{
	const struct mgmt_ev_new_link_key *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed New Link Key control\n");
		return;
	}

	ba2str(&ev->key.addr.bdaddr, str);

	printf("@ New Link Key: %s (%d)\n", str, ev->key.addr.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_new_long_term_key(uint16_t len, const void *buf)
{
	const struct mgmt_ev_new_long_term_key *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed New Long Term Key control\n");
		return;
	}

	ba2str(&ev->key.addr.bdaddr, str);

	printf("@ New Long Term Key: %s (%d)\n", str, ev->key.addr.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_device_connected(uint16_t len, const void *buf)
{
	const struct mgmt_ev_device_connected *ev = buf;
	uint32_t flags;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Device Connected control\n");
		return;
	}

	flags = btohs(ev->flags);
	ba2str(&ev->addr.bdaddr, str);

	printf("@ Device Connected: %s (%d) flags 0x%4.4x\n",
						str, ev->addr.type, flags);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_device_disconnected(uint16_t len, const void *buf)
{
	const struct mgmt_ev_device_disconnected *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Device Disconnected control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ Device Disconnected: %s (%d)\n", str, ev->addr.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_connect_failed(uint16_t len, const void *buf)
{
	const struct mgmt_ev_connect_failed *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Connect Failed control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ Connect Failed: %s (%d) status 0x%2.2x\n",
					str, ev->addr.type, ev->status);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_pin_code_request(uint16_t len, const void *buf)
{
	const struct mgmt_ev_pin_code_request *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed PIN Code Request control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ PIN Code Request: %s (%d) secure 0x%2.2x\n",
					str, ev->addr.type, ev->secure);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_user_confirm_request(uint16_t len, const void *buf)
{
	const struct mgmt_ev_user_confirm_request *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed User Confirmation Request control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ User Confirmation Request: %s (%d) hint %d value %d\n",
			str, ev->addr.type, ev->confirm_hint, ev->value);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_user_passkey_request(uint16_t len, const void *buf)
{
	const struct mgmt_ev_user_passkey_request *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed User Passkey Request control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ PIN User Passkey Request: %s (%d)\n", str, ev->addr.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_auth_failed(uint16_t len, const void *buf)
{
	const struct mgmt_ev_auth_failed *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Authentication Failed control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ Authentication Failed: %s (%d) status 0x%2.2x\n",
					str, ev->addr.type, ev->status);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_device_found(uint16_t len, const void *buf)
{
	const struct mgmt_ev_device_found *ev = buf;
	uint32_t flags;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Device Found control\n");
		return;
	}

	flags = btohs(ev->flags);
	ba2str(&ev->addr.bdaddr, str);

	printf("@ Device Found: %s (%d) rssi %d flags 0x%4.4x\n",
					str, ev->addr.type, ev->rssi, flags);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_discovering(uint16_t len, const void *buf)
{
	const struct mgmt_ev_discovering *ev = buf;

	if (len < sizeof(*ev)) {
		printf("* Malformed Discovering control\n");
		return;
	}

	printf("@ Discovering: 0x%2.2x (%d)\n", ev->discovering, ev->type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_device_blocked(uint16_t len, const void *buf)
{
	const struct mgmt_ev_device_blocked *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Device Blocked control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ Device Blocked: %s (%d)\n", str, ev->addr.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_device_unblocked(uint16_t len, const void *buf)
{
	const struct mgmt_ev_device_unblocked *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Device Unblocked control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ Device Unblocked: %s (%d)\n", str, ev->addr.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

static void mgmt_device_unpaired(uint16_t len, const void *buf)
{
	const struct mgmt_ev_device_unpaired *ev = buf;
	char str[18];

	if (len < sizeof(*ev)) {
		printf("* Malformed Device Unpaired control\n");
		return;
	}

	ba2str(&ev->addr.bdaddr, str);

	printf("@ Device Unpaired: %s (%d)\n", str, ev->addr.type);

	buf += sizeof(*ev);
	len -= sizeof(*ev);

	packet_hexdump(buf, len);
}

void control_message(uint16_t opcode, const void *data, uint16_t size)
{
	switch (opcode) {
	case MGMT_EV_INDEX_ADDED:
		mgmt_index_added(size, data);
		break;
	case MGMT_EV_INDEX_REMOVED:
		mgmt_index_removed(size, data);
		break;
	case MGMT_EV_CONTROLLER_ERROR:
		mgmt_controller_error(size, data);
		break;
	case MGMT_EV_NEW_SETTINGS:
		mgmt_new_settings(size, data);
		break;
	case MGMT_EV_CLASS_OF_DEV_CHANGED:
		mgmt_class_of_dev_changed(size, data);
		break;
	case MGMT_EV_LOCAL_NAME_CHANGED:
		mgmt_local_name_changed(size, data);
		break;
	case MGMT_EV_NEW_LINK_KEY:
		mgmt_new_link_key(size, data);
		break;
	case MGMT_EV_NEW_LONG_TERM_KEY:
		mgmt_new_long_term_key(size, data);
		break;
	case MGMT_EV_DEVICE_CONNECTED:
		mgmt_device_connected(size, data);
		break;
	case MGMT_EV_DEVICE_DISCONNECTED:
		mgmt_device_disconnected(size, data);
		break;
	case MGMT_EV_CONNECT_FAILED:
		mgmt_connect_failed(size, data);
		break;
	case MGMT_EV_PIN_CODE_REQUEST:
		mgmt_pin_code_request(size, data);
		break;
	case MGMT_EV_USER_CONFIRM_REQUEST:
		mgmt_user_confirm_request(size, data);
		break;
	case MGMT_EV_USER_PASSKEY_REQUEST:
		mgmt_user_passkey_request(size, data);
		break;
	case MGMT_EV_AUTH_FAILED:
		mgmt_auth_failed(size, data);
		break;
	case MGMT_EV_DEVICE_FOUND:
		mgmt_device_found(size, data);
		break;
	case MGMT_EV_DISCOVERING:
		mgmt_discovering(size, data);
		break;
	case MGMT_EV_DEVICE_BLOCKED:
		mgmt_device_blocked(size, data);
		break;
	case MGMT_EV_DEVICE_UNBLOCKED:
		mgmt_device_unblocked(size, data);
		break;
	case MGMT_EV_DEVICE_UNPAIRED:
		mgmt_device_unpaired(size, data);
		break;
	default:
		printf("* Unknown control (code %d len %d)\n", opcode, size);
		packet_hexdump(data, size);
		break;
	}
}

static void data_callback(int fd, uint32_t events, void *user_data)
{
	struct control_data *data = user_data;
	unsigned char buf[HCI_MAX_FRAME_SIZE];
	unsigned char control[32];
	struct mgmt_hdr hdr;
	struct msghdr msg;
	struct iovec iov[2];

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_remove_fd(fd);
		return;
	}

	iov[0].iov_base = &hdr;
	iov[0].iov_len = MGMT_HDR_SIZE;
	iov[1].iov_base = buf;
	iov[1].iov_len = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	while (1) {
		struct cmsghdr *cmsg;
		struct timeval *tv = NULL;
		uint16_t opcode, index, pktlen;
		ssize_t len;

		len = recvmsg(fd, &msg, MSG_DONTWAIT);
		if (len < 0)
			break;

		if (len < MGMT_HDR_SIZE)
			break;

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
					cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_SOCKET)
				continue;

			if (cmsg->cmsg_type == SCM_TIMESTAMP)
				tv = (struct timeval *) CMSG_DATA(cmsg);
		}

		opcode = btohs(hdr.opcode);
		index  = btohs(hdr.index);
		pktlen = btohs(hdr.len);

		switch (data->channel) {
		case HCI_CHANNEL_CONTROL:
			packet_control(tv, index, opcode, buf, pktlen);
			break;
		case HCI_CHANNEL_MONITOR:
			packet_monitor(tv, index, opcode, buf, pktlen);
			break;
		}
	}
}

static int open_socket(uint16_t channel)
{
	struct sockaddr_hci addr;
	int fd, opt = 1;

	fd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (fd < 0) {
		perror("Failed to open channel");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	addr.hci_channel = channel;

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (errno == EINVAL) {
			/* Fallback to hcidump support */
			close(fd);
			return -1;
		}
		perror("Failed to bind channel");
		close(fd);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt)) < 0) {
		perror("Failed to enable timestamps");
		close(fd);
		return -1;
	}

	return fd;
}

static int open_channel(uint16_t channel)
{
	struct control_data *data;

	data = malloc(sizeof(*data));
	if (!data)
		return -1;

	memset(data, 0, sizeof(*data));
	data->channel = channel;

	data->fd = open_socket(channel);
	if (data->fd < 0) {
		free(data);
		return -1;
	}

	mainloop_add_fd(data->fd, EPOLLIN, data_callback, data, free_data);

	return 0;
}

int control_tracing(void)
{
	if (open_channel(HCI_CHANNEL_MONITOR) < 0)
		return -1;

	open_channel(HCI_CHANNEL_CONTROL);

	return 0;
}
