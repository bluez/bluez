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
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netdb.h>
#include <arpa/inet.h>

#include "monitor/mainloop.h"
#include "monitor/bt.h"

#define le16_to_cpu(val) (val)
#define cpu_to_le16(val) (val)

#define BTPROTO_HCI	1
struct sockaddr_hci {
	sa_family_t	hci_family;
	unsigned short	hci_dev;
	unsigned short  hci_channel;
};
#define HCI_CHANNEL_USER	1

static uint16_t hci_index = 0;

static int channel_fd = -1;
static int server_fd = -1;
static int client_fd = -1;
static uint8_t client_buffer[4096];
static uint8_t client_length = 0;

static int open_channel(uint16_t index)
{
	struct sockaddr_hci addr;
	int fd;

	fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
	if (fd < 0) {
		perror("Failed to open Bluetooth socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = index;
	addr.hci_channel = HCI_CHANNEL_USER;

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(fd);
		perror("Failed to bind Bluetooth socket");
		return -1;
	}

	return fd;
}

static void channel_callback(int fd, uint32_t events, void *user_data)
{
	unsigned char buf[4096];
	ssize_t len, written;

	if (events & (EPOLLERR | EPOLLHUP)) {
		printf("Device disconnected\n");
		mainloop_remove_fd(channel_fd);
		close(channel_fd);
		channel_fd = -1;
		mainloop_remove_fd(client_fd);
		close(client_fd);
		client_fd = -1;
		return;
	}

	len = read(channel_fd, buf, sizeof(buf));
	if (len < 1) {
		fprintf(stderr, "Failed to read channel packet\n");
		return;
	}

	written = write(client_fd, buf, len);
	if (written < 1) {
		fprintf(stderr, "Failed to write to unix socket\n");
		return;
	}
}

static void client_callback(int fd, uint32_t events, void *user_data)
{
	ssize_t len, written;
	uint16_t pktlen;

	if (events & (EPOLLERR | EPOLLHUP)) {
		printf("Client disconnected\n");
		mainloop_remove_fd(channel_fd);
		close(channel_fd);
		channel_fd = -1;
		mainloop_remove_fd(client_fd);
		close(client_fd);
		client_fd = -1;
		return;
	}

	len = read(client_fd, client_buffer + client_length,
					sizeof(client_buffer) - client_length);
	if (len < 1) {
		fprintf(stderr, "Failed to read client packet\n");
		return;
	}

	client_length += len;

	switch (client_buffer[0]) {
	case BT_H4_CMD_PKT:
		{
			struct bt_hci_cmd_hdr *hdr;

			if (client_length < 1 + sizeof(*hdr))
				return;

			hdr = (void *) (client_buffer + 1);
			pktlen = 1 + sizeof(*hdr) + hdr->plen;
		}
		break;
	case BT_H4_ACL_PKT:
		{
			struct bt_hci_acl_hdr *hdr;

			if (client_length < 1 + sizeof(*hdr))
				return;

			hdr = (void *) (client_buffer + 1);
			pktlen = 1 + sizeof(*hdr) + cpu_to_le16(hdr->dlen);
		}
		break;
	case BT_H4_SCO_PKT:
		{
			struct bt_hci_sco_hdr *hdr;

			if (client_length < 1 + sizeof(*hdr))
				return;

			hdr = (void *) (client_buffer + 1);
			pktlen = 1 + sizeof(*hdr) + hdr->dlen;
		}
		break;
	default:
		fprintf(stderr, "Received wrong packet type\n");
		return;
	}

	if (client_length < pktlen)
		return;

	written = write(channel_fd, client_buffer, pktlen);
	if (written < 0) {
		fprintf(stderr, "Failed to write channel packet\n");
		return;
	}

	if (client_length > pktlen) {
		memmove(client_buffer, client_buffer + pktlen,
						client_length - pktlen);
		client_length -= pktlen;
	}
}

static void server_callback(int fd, uint32_t events, void *user_data)
{
	struct sockaddr_un addr;
	socklen_t len;
	int nfd;

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_quit();
		return;
	}

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);

	if (getsockname(fd, (struct sockaddr *) &addr, &len) < 0) {
		perror("Failed to get socket name");
		return;
	}

	nfd = accept(fd, (struct sockaddr *) &addr, &len);
	if (nfd < 0) {
		perror("Failed to accept client socket");
		return;
	}

	if (client_fd >= 0) {
		fprintf(stderr, "Active client already present\n");
		close(nfd);
		return;
	}

	channel_fd = open_channel(hci_index);
	if (channel_fd < 0) {
		close(nfd);
		return;
	}

	printf("New client connected\n");

	if (mainloop_add_fd(channel_fd, EPOLLIN, channel_callback,
							NULL, NULL) < 0) {
		close(nfd);
		close(channel_fd);
		channel_fd = -1;
		return;
	}

	if (mainloop_add_fd(nfd, EPOLLIN, client_callback, NULL, NULL) < 0) {
		close(nfd);
		close(channel_fd);
		channel_fd = -1;
		return;
	}

	client_fd = nfd;
}

static int open_unix(const char *path)
{
	struct sockaddr_un addr;
	int fd;

	unlink(path);

	fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("Failed to open Unix server socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to bind Unix server socket");
		close(fd);
		return -1;
	}

	if (listen(fd, 1) < 0) {
		perror("Failed to listen Unix server socket");
		close(fd);
		return -1;
	}

	if (chmod(path, 0666) < 0)
		perror("Failed to change mode");

	return fd;
}

static int open_tcp(unsigned int port)
{
	struct sockaddr_in addr;
	int fd, opt = 1;

	fd = socket(PF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("Failed to open TCP server socket");
		return -1;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to bind TCP server socket");
		close(fd);
		return -1;
	}

	if (listen(fd, 1) < 0) {
		perror("Failed to listen TCP server socket");
		close(fd);
		return -1;
	}

	return fd;
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
	printf("btproxy - Bluetooth controller proxy\n"
		"Usage:\n");
	printf("\tbtproxy [options]\n");
	printf("options:\n"
		"\t-u, --unix [unixpath]    Use unix server\n"
		"\t-p, --port [port]        Use TCP server\n"
		"\t-i, --index <num>        Use specified controller\n"
		"\t-h, --help               Show help options\n");
}

static const struct option main_options[] = {
	{ "unix",    optional_argument, NULL, 'u' },
	{ "port",    optional_argument, NULL, 'p' },
	{ "index",   required_argument, NULL, 'i' },
	{ "version", no_argument,       NULL, 'v' },
	{ "help",    no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	const char *unixpath = NULL;
	unsigned short tcpport = 0;
	const char *str;
	sigset_t mask;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "u::p::i:vh",
						main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'u':
			if (optarg)
				unixpath = optarg;
			else
				unixpath = "/tmp/bt-server-bredr";
			break;
		case 'p':
			if (optarg)
				tcpport = atoi(optarg);
			else
				tcpport = 0xb1ee;
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

	if (unixpath)
		server_fd = open_unix(unixpath);
	else if (tcpport > 0)
		server_fd = open_tcp(tcpport);
	else {
		fprintf(stderr, "Missing emulator device\n");
		return EXIT_FAILURE;
	}

	if (server_fd < 0)
		return EXIT_FAILURE;

	mainloop_add_fd(server_fd, EPOLLIN, server_callback, NULL, NULL);

	return mainloop_run();
}
