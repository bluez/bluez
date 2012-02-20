/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <sys/epoll.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#ifndef HCI_CHANNEL_MONITOR
#define HCI_CHANNEL_MONITOR  2
#endif

struct monitor_hdr {
	uint16_t opcode;
	uint16_t index;
	uint16_t len;
} __attribute__((packed));

#define MONITOR_HDR_SIZE 6

#define MONITOR_NEW_INDEX	0
#define MONITOR_DEL_INDEX	1
#define MONITOR_COMMAND_PKT	2
#define MONITOR_EVENT_PKT	3
#define MONITOR_ACL_TX_PKT	4
#define MONITOR_ACL_RX_PKT	5
#define MONITOR_SCO_TX_PKT	6
#define MONITOR_SCO_RX_PKT	7

struct monitor_new_index {
	uint8_t  type;
	uint8_t  bus;
	bdaddr_t bdaddr;
	char     name[8];
} __attribute__((packed));

#define MONITOR_NEW_INDEX_SIZE 16

#define MONITOR_DEL_INDEX_SIZE 0

static unsigned long filter_mask = 0;

#define FILTER_SHOW_INDEX	(1 << 0)
#define FILTER_SHOW_DATE	(1 << 1)
#define FILTER_SHOW_TIME	(1 << 2)
#define FILTER_SHOW_ACL_DATA	(1 << 3)
#define FILTER_SHOW_SCO_DATA	(1 << 4)

#define MAX_INDEX 16

static struct monitor_new_index index_list[MAX_INDEX];

static const char *devtype2str(uint8_t type)
{
	switch (type) {
	case 0:
		return "BR/EDR";
	case 1:
		return "AMP";
	}

	return "UNKNOWN";
}

static const char *devbus2str(uint8_t bus)
{
	switch (bus) {
	case 0:
		return "VIRTUAL";
	case 1:
		return "USB";
	case 2:
		return "PCCARD";
	case 3:
		return "UART";
	}

	return "UNKNOWN";
}

static const char *opcode2str(uint16_t opcode)
{
	return "Unknown";
}

static const char *event2str(uint8_t event)
{
	return "Unknown";
}

static void hexdump(const unsigned char *buf, uint16_t len)
{
	static const char hexdigits[] = "0123456789abcdef";
	char str[68];
	uint16_t i;

	if (!len)
		return;

	for (i = 0; i < len; i++) {
		str[((i % 16) * 3) + 0] = hexdigits[buf[i] >> 4];
		str[((i % 16) * 3) + 1] = hexdigits[buf[i] & 0xf];
		str[((i % 16) * 3) + 2] = ' ';
		str[(i % 16) + 49] = isprint(buf[i]) ? buf[i] : '.';

		if ((i + 1) % 16 == 0) {
			str[47] = ' ';
			str[48] = ' ';
			str[65] = '\0';
			printf("%-12c%s\n", ' ', str);
			str[0] = ' ';
		}
	}

	if (i % 16 > 0) {
		uint16_t j;
		for (j = (i % 16); j < 16; j++) {
			str[(j * 3) + 0] = ' ';
			str[(j * 3) + 1] = ' ';
			str[(j * 3) + 2] = ' ';
			str[j + 49] = ' ';
		}
		str[47] = ' ';
		str[48] = ' ';
		str[65] = '\0';
		printf("%-12c%s\n", ' ', str);
	}
}

static void process_new_index(uint16_t index, uint16_t len, void *buf)
{
	struct monitor_new_index *ni = buf;
	char str[18];

	if (len != MONITOR_NEW_INDEX_SIZE) {
		printf("* Malformed New Index packet\n");
		return;
	}

	ba2str(&ni->bdaddr, str);

	printf("= New Index: %s (%s,%s,%s)\n", str,
					devtype2str(ni->type),
					devbus2str(ni->bus), ni->name);

	if (index < MAX_INDEX)
		memcpy(&index_list[index], ni, MONITOR_NEW_INDEX_SIZE);
}

static void process_del_index(uint16_t index, uint16_t len)
{
	char str[18];

	if (len != MONITOR_DEL_INDEX_SIZE) {
		printf("* Malformed Delete Index packet\n");
		return;
	}

	if (index < MAX_INDEX)
		ba2str(&index_list[index].bdaddr, str);
	else
		ba2str(BDADDR_ANY, str);

	printf("= Delete Index: %s\n", str);
}

static void process_command_pkt(uint16_t len, void *buf)
{
	hci_command_hdr *hdr = buf;
	uint16_t opcode = btohs(hdr->opcode);
	uint16_t ogf = cmd_opcode_ogf(opcode);
	uint16_t ocf = cmd_opcode_ocf(opcode);

	if (len < HCI_COMMAND_HDR_SIZE) {
		printf("* Malformed HCI Command packet\n");
		return;
	}

	printf("< HCI Command: %s (0x%2.2x|0x%4.4x) plen %d\n",
				opcode2str(opcode), ogf, ocf, hdr->plen);

	buf += HCI_COMMAND_HDR_SIZE;
	len -= HCI_COMMAND_HDR_SIZE;

	hexdump(buf, len);
}

static void process_event_pkt(uint16_t len, void *buf)
{
	hci_event_hdr *hdr = buf;

	if (len < HCI_EVENT_HDR_SIZE) {
		printf("* Malformed HCI Event packet\n");
		return;
	}

	printf("> HCI Event: %s (0x%2.2x) plen %d\n",
				event2str(hdr->evt), hdr->evt, hdr->plen);

	buf += HCI_EVENT_HDR_SIZE;
	len -= HCI_EVENT_HDR_SIZE;

	hexdump(buf, len);
}

static void process_acldata_pkt(bool in, uint16_t len, void *buf)
{
	hci_acl_hdr *hdr = buf;
	uint16_t handle = btohs(hdr->handle);
	uint16_t dlen = btohs(hdr->dlen);
	uint8_t flags = acl_flags(handle);

	if (len < HCI_ACL_HDR_SIZE) {
		printf("* Malformed ACL Data %s packet\n", in ? "RX" : "TX");
		return;
	}

	printf("%c ACL Data: handle %d flags 0x%2.2x dlen %d\n",
			in ? '>' : '<', acl_handle(handle), flags, dlen);

	buf += HCI_ACL_HDR_SIZE;
	len -= HCI_ACL_HDR_SIZE;

	if (filter_mask & FILTER_SHOW_ACL_DATA)
		hexdump(buf, len);
}

static void process_scodata_pkt(bool in, uint16_t len, void *buf)
{
	hci_sco_hdr *hdr = buf;
	uint16_t handle = btohs(hdr->handle);
	uint8_t flags = acl_flags(handle);

	if (len < HCI_SCO_HDR_SIZE) {
		printf("* Malformed SCO Data %s packet\n", in ? "RX" : "TX");
		return;
	}

	printf("%c SCO Data: handle %d flags 0x%2.2x dlen %d\n",
			in ? '>' : '<',	acl_handle(handle), flags, hdr->dlen);

	buf += HCI_SCO_HDR_SIZE;
	len -= HCI_SCO_HDR_SIZE;

	if (filter_mask & FILTER_SHOW_SCO_DATA)
		hexdump(buf, len);
}

static void process_monitor(int fd)
{
	unsigned char buf[4096];
	unsigned char control[32];
	struct monitor_hdr hdr;
	struct msghdr msg;
	struct iovec iov[2];
	struct cmsghdr *cmsg;
	struct timeval *tv = NULL;
	uint16_t opcode, index, pktlen;
	ssize_t len;

	iov[0].iov_base = &hdr;
	iov[0].iov_len = MONITOR_HDR_SIZE;
	iov[1].iov_base = buf;
	iov[1].iov_len = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	len = recvmsg(fd, &msg, MSG_DONTWAIT);
	if (len < 0)
		return;

	if (len < MONITOR_HDR_SIZE)
		return;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
					cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET)
			continue;

		if (cmsg->cmsg_type == SCM_TIMESTAMP)
			tv = (void *) CMSG_DATA(cmsg);
	}

	opcode = btohs(hdr.opcode);
	index  = btohs(hdr.index);
	pktlen = btohs(hdr.len);

	if (filter_mask & FILTER_SHOW_INDEX)
		printf("[hci%d] ", index);

	if (tv) {
		time_t t = tv->tv_sec;
		struct tm tm;

		localtime_r(&t, &tm);

		if (filter_mask & FILTER_SHOW_DATE)
			printf("%04d-%02d-%02d ",
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);

		if (filter_mask & FILTER_SHOW_TIME)
			printf("%02d:%02d:%02d.%06lu ",
				tm.tm_hour, tm.tm_min, tm.tm_sec, tv->tv_usec);
	}

	switch (opcode) {
	case MONITOR_NEW_INDEX:
		process_new_index(index, pktlen, buf);
		break;
	case MONITOR_DEL_INDEX:
		process_del_index(index, pktlen);
		break;
	case MONITOR_COMMAND_PKT:
		process_command_pkt(pktlen, buf);
		break;
	case MONITOR_EVENT_PKT:
		process_event_pkt(pktlen, buf);
		break;
	case MONITOR_ACL_TX_PKT:
		process_acldata_pkt(false, pktlen, buf);
		break;
	case MONITOR_ACL_RX_PKT:
		process_acldata_pkt(true, pktlen, buf);
		break;
	case MONITOR_SCO_TX_PKT:
		process_scodata_pkt(false, pktlen, buf);
		break;
	case MONITOR_SCO_RX_PKT:
		process_scodata_pkt(true, pktlen, buf);
		break;
	default:
		printf("* Unknown packet (code %d len %d)\n", opcode, pktlen);
		hexdump(buf, pktlen);
		break;
	}
}

static int open_monitor(void)
{
	struct sockaddr_hci addr;
	int fd, opt = 1;

	fd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (fd < 0) {
		perror("Failed to open monitor channel");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	addr.hci_channel = HCI_CHANNEL_MONITOR;

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to bind monitor channel");
		close(fd);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt)) < 0) {
		perror("Failed to enable monitor timestamps");
		close(fd);
		return -1;
	}

	return fd;
}

#define MAX_EPOLL_EVENTS 10

int main(int argc, char *argv[])
{
	int exitcode = EXIT_FAILURE;
	struct epoll_event mon_event;
	int mon_fd, epoll_fd;

	filter_mask |= FILTER_SHOW_INDEX;
	filter_mask |= FILTER_SHOW_TIME;
	filter_mask |= FILTER_SHOW_ACL_DATA;

	mon_fd = open_monitor();
	if (mon_fd < 0)
		return exitcode;

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) {
		perror("Failed to create epoll descriptor");
		goto close_monitor;
	}

	memset(&mon_event, 0, sizeof(mon_event));
	mon_event.events = EPOLLIN;
	mon_event.data.fd = mon_fd;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, mon_fd, &mon_event) < 0) {
		perror("Failed to setup monitor event watch");
                goto close_epoll;
        }

	for (;;) {
		struct epoll_event events[MAX_EPOLL_EVENTS];
		int n, nfds;

		nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, -1);
		if (nfds < 0)
			continue;

		for (n = 0; n < nfds; n++) {
			if (events[n].data.fd == mon_fd)
				process_monitor(mon_fd);
		}
	}

	exitcode = EXIT_SUCCESS;

close_epoll:
	close(epoll_fd);

close_monitor:
	close(mon_fd);

	return exitcode;
}
