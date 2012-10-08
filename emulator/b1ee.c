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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <arpa/inet.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#include "mainloop.h"

#define DEFAULT_SERVER	"b1ee.com"
#define DEFAULT_PORT	"45550"		/* 0xb1ee */

static int server_fd;
static int vhci_fd;

static uint8_t *server_pkt_data;
static uint8_t server_pkt_type;
static uint16_t server_pkt_expect;
static uint16_t server_pkt_len;
static uint16_t server_pkt_offset;

static void server_read_callback(int fd, uint32_t events, void *user_data)
{
	static uint8_t buf[4096];
	uint8_t *ptr = buf;
	ssize_t len;
	uint16_t count;

	if (events & (EPOLLERR | EPOLLHUP))
		return;

again:
	len = recv(server_fd, buf + server_pkt_offset,
			sizeof(buf) - server_pkt_offset, MSG_DONTWAIT);
	if (len < 0) {
		if (errno == EAGAIN)
			goto again;
		return;
	}

	count = server_pkt_offset + len;

	while (count > 0) {
		hci_event_hdr *evt_hdr;

		if (!server_pkt_data) {
			server_pkt_type = ptr[0];

			switch (server_pkt_type) {
			case HCI_EVENT_PKT:
				if (count < HCI_EVENT_HDR_SIZE + 1) {
					server_pkt_offset += len;
					return;
				}
				evt_hdr = (hci_event_hdr *) (ptr + 1);
				server_pkt_expect = HCI_EVENT_HDR_SIZE +
							evt_hdr->plen + 1;
				server_pkt_data = malloc(server_pkt_expect);
				server_pkt_len = 0;
				break;
			default:
				fprintf(stderr, "Unknown packet from server\n");
				return;
			}

			server_pkt_offset = 0;
		}

		if (count >= server_pkt_expect) {
			ssize_t written;

			memcpy(server_pkt_data + server_pkt_len,
						ptr, server_pkt_expect);
			ptr += server_pkt_expect;
			count -= server_pkt_expect;

			written = write(vhci_fd, server_pkt_data,
					server_pkt_len + server_pkt_expect);
			if (written != server_pkt_len + server_pkt_expect)
				fprintf(stderr, "Write to /dev/vhci failed\n");

			free(server_pkt_data);
			server_pkt_data = NULL;
		} else {
			memcpy(server_pkt_data + server_pkt_len, ptr, count);
			server_pkt_len += count;
			server_pkt_expect -= count;
			count = 0;
		}
	}
}

static void vhci_read_callback(int fd, uint32_t events, void *user_data)
{
	unsigned char buf[4096];
	ssize_t len, written;

	if (events & (EPOLLERR | EPOLLHUP))
		return;

	len = read(vhci_fd, buf, sizeof(buf));
	if (len < 0)
		return;

	written = write(server_fd, buf, len);
	if (written != len)
		fprintf(stderr, "Write to server failed\n");
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

int main(int argc, char *argv[])
{
	sigset_t mask;
	struct addrinfo hints;
	struct addrinfo *info, *res;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	err = getaddrinfo(DEFAULT_SERVER, DEFAULT_PORT, &hints, &res);
	if (err) {
		perror(gai_strerror(err));
		exit(1);
	}

	for (info = res; info; info = info->ai_next) {
		char str[INET6_ADDRSTRLEN];

		inet_ntop(info->ai_family, info->ai_addr->sa_data,
							str, sizeof(str));

		server_fd = socket(info->ai_family, info->ai_socktype,
						info->ai_protocol);
		if (server_fd < 0)
			continue;

		printf("Trying to connect to %s on port %s\n",
						str, DEFAULT_PORT);

		if (connect(server_fd, res->ai_addr, res->ai_addrlen) < 0) {
			perror("Failed to connect");
			continue;
		}

		printf("Successfully connected to %s\n", str);
		break;
	}

	freeaddrinfo(res);

	if (res == NULL)
		exit(1);

	vhci_fd = open("/dev/vhci", O_RDWR | O_NONBLOCK);
	if (vhci_fd < 0) {
		perror("Failed to /dev/vhci");
		close(server_fd);
		exit(1);
	}

	mainloop_init();

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	mainloop_set_signal(&mask, signal_callback, NULL, NULL);

	mainloop_add_fd(server_fd, EPOLLIN, server_read_callback, NULL, NULL);
	mainloop_add_fd(vhci_fd, EPOLLIN, vhci_read_callback, NULL, NULL);

	return mainloop_run();
}
