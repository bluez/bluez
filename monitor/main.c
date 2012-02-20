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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
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

static void process_monitor(int fd)
{
	unsigned char buf[4096];
	unsigned char control[32];
	struct monitor_hdr hdr;
	struct msghdr msg;
	struct iovec iov[2];
	struct cmsghdr *cmsg;
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

		if (cmsg->cmsg_type == SCM_TIMESTAMP) {
			struct timeval *tv = (void *) CMSG_DATA(cmsg);

			printf("[%jd.%03jd] ", tv->tv_sec, tv->tv_usec);
		}
	}

	printf("{opcode=%d,index=%d,len=%d}\n",
				hdr.opcode, hdr.index, hdr.len);
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
