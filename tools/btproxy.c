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
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netdb.h>
#include <arpa/inet.h>

#include "src/shared/util.h"
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
static bool use_smd = false;
static bool client_active = false;

static void hexdump_print(const char *str, void *user_data)
{
	printf("%s\n", str);
}

struct stream {
	char dir;
	int src_fd;
	uint8_t src_type;
	int dst_fd;
	uint8_t dst_type;
	uint8_t buf[4096];
	uint16_t len;
};

static void stream_free(void *data)
{
	struct stream *stream = data;

	printf("Closing stream %c\n", stream->dir);

	client_active = false;

	close(stream->src_fd);

	free(stream);
}

static void stream_callback(int fd, uint32_t events, void *user_data)
{
	struct stream *stream = user_data;
	uint8_t *wbuf;
	ssize_t wlen, len;
	uint16_t pktlen;

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_remove_fd(stream->src_fd);
		return;
	}

	len = read(stream->src_fd, stream->buf + stream->len,
					sizeof(stream->buf) - stream->len);
	if (len < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return;
		fprintf(stderr, "Failed to read stream packet\n");
		mainloop_remove_fd(stream->src_fd);
		return;
	}

	util_hexdump(stream->dir, stream->buf + stream->len, len,
						hexdump_print, NULL);

	stream->len += len;

process_packet:
	if (stream->len < 1)
		return;

	switch (stream->buf[0]) {
	case BT_H4_CMD_PKT:
		{
			struct bt_hci_cmd_hdr *hdr;

			if (stream->len < 1 + sizeof(*hdr))
				return;

			hdr = (void *) (stream->buf + 1);
			pktlen = 1 + sizeof(*hdr) + hdr->plen;
		}
		break;
	case BT_H4_ACL_PKT:
		{
			struct bt_hci_acl_hdr *hdr;

			if (stream->len < 1 + sizeof(*hdr))
				return;

			hdr = (void *) (stream->buf + 1);
			pktlen = 1 + sizeof(*hdr) + cpu_to_le16(hdr->dlen);
		}
		break;
	case BT_H4_SCO_PKT:
		{
			struct bt_hci_sco_hdr *hdr;

			if (stream->len < 1 + sizeof(*hdr))
				return;

			hdr = (void *) (stream->buf + 1);
			pktlen = 1 + sizeof(*hdr) + hdr->dlen;
		}
		break;
	case BT_H4_EVT_PKT:
		{
			struct bt_hci_evt_hdr *hdr;

			if (stream->len < 1 + sizeof(*hdr))
				return;

			hdr = (void *) (stream->buf + 1);
			pktlen = 1 + sizeof(*hdr) + hdr->plen;
		}
		break;
	case 0xff:
		if (stream->src_type > 0) {
			mainloop_remove_fd(stream->src_fd);
			return;
		}
		/* Notification packet from /dev/vhci - ignore */
		stream->len = 0;
		return;
	default:
		fprintf(stderr, "Received unknown packet type 0x%02x\n",
							stream->buf[0]);
		mainloop_remove_fd(stream->src_fd);
		return;
	}

	if (stream->len < pktlen)
		return;

	if (stream->dst_type > 0) {
		if (stream->buf[0] != stream->dst_type)
			goto next_packet;
		wbuf = stream->buf + 1;
		wlen = pktlen - 1;
	} else {
		wbuf = stream->buf;
		wlen = pktlen;
	}

	printf("* wlen = %zd\n", wlen);
	util_hexdump('*', wbuf, wlen, hexdump_print, NULL);

	while (wlen > 0) {
		ssize_t written;

		written = write(stream->dst_fd, wbuf, wlen);
		if (written < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			fprintf(stderr, "Failed to write stream packet\n");
			mainloop_remove_fd(stream->src_fd);
			return;
		}

		wbuf += written;
		wlen -= written;
	}

next_packet:
	if (stream->len > pktlen) {
		if (stream->src_type > 0) {
			memmove(stream->buf + 1, stream->buf + pktlen,
						stream->len - pktlen);
			stream->len -= pktlen;

			stream->buf[0] = stream->src_type;
			stream->len++;
		} else {
			memmove(stream->buf, stream->buf + pktlen,
						stream->len - pktlen);
			stream->len -= pktlen;
		}

		goto process_packet;
	} else {
		if (stream->src_type > 0) {
			stream->buf[0] = stream->src_type;
			stream->len = 1;
		} else
			stream->len = 0;
	}
}

static struct stream *stream_create(char dir, int src_fd, uint8_t src_type,
						int dst_fd, uint8_t dst_type)
{
	struct stream *stream;

	stream = new0(struct stream, 1);
	if (!stream)
		return NULL;

	stream->dir = dir;

	stream->src_fd = src_fd;
	stream->src_type = src_type;

	stream->dst_fd = dst_fd;
	stream->dst_type = dst_type;

	if (stream->src_type > 0) {
		stream->buf[0] = stream->src_type;
		stream->len = 1;
	}

	mainloop_add_fd(stream->src_fd, EPOLLIN, stream_callback,
						stream, stream_free);

	return stream;
}

static bool setup_streams(int src_fd, uint8_t src_type_rx,
					uint8_t src_type_tx, int dst_fd)
{
	struct stream *stream;

	stream = stream_create('>', src_fd, src_type_rx, dst_fd, 0x00);
	if (!stream) {
		fprintf(stderr, "Failed to create source stream\n");
		close(src_fd);
		close(dst_fd);
		return false;
	}

	stream = stream_create('<', dst_fd, 0x00, src_fd, src_type_tx);
	if (!stream) {
		fprintf(stderr, "Failed to create destination stream\n");
		close(src_fd);
		close(dst_fd);
		return false;
	}

	return true;
}

static int open_smd(void)
{
	struct termios ti;
	int fd;

	printf("Opening /dev/smd3 device\n");

	fd = open("/dev/smd3", O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (fd < 0) {
		perror("Failed to open /dev/smd3 device");
		return -1;
	}

	/* Sleep 0.5 sec to give smd port time to fully initialize */
	usleep(500000);

	if (tcflush(fd, TCIOFLUSH) < 0) {
		perror("Failed to flush /dev/smd3 device");
		close(fd);
		return -1;
	}

	if (tcgetattr(fd, &ti) < 0) {
		perror("Failed to get /dev/smd3 attributes");
		close(fd);
		return -1;
	}

	/* Switch to raw mode */
	cfmakeraw(&ti);

	ti.c_cflag |= CRTSCTS | CLOCAL;

	if (tcsetattr(fd, TCSANOW, &ti) < 0) {
		perror("Failed to set /dev/smd3 attributes");
		close(fd);
		return -1;
	}

	return fd;
}

static int open_channel(uint16_t index)
{
	struct sockaddr_hci addr;
	int fd;

	printf("Opening user channel for hci%u\n", hci_index);

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

static void server_callback(int fd, uint32_t events, void *user_data)
{
	union {
		struct sockaddr_un sun;
		struct sockaddr_in sin;
	} addr;
	socklen_t len;
	int src_fd, dst_fd;
	uint8_t src_type_rx, src_type_tx;

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

	dst_fd = accept(fd, (struct sockaddr *) &addr, &len);
	if (dst_fd < 0) {
		perror("Failed to accept client socket");
		return;
	}

	if (client_active) {
		fprintf(stderr, "Active client already present\n");
		close(dst_fd);
		return;
	}

	if (use_smd) {
		src_fd = open_smd();
		src_type_rx = BT_H4_EVT_PKT;
		src_type_tx = BT_H4_CMD_PKT;
	} else {
		src_fd = open_channel(hci_index);
		src_type_rx = 0x00;
		src_type_tx = 0x00;
	}

	if (src_fd < 0) {
		close(dst_fd);
		return;
	}

	printf("New client connected\n");

	if (!setup_streams(src_fd, src_type_rx, src_type_tx,  dst_fd)) {
		close(dst_fd);
		close(src_fd);
		return;
	}

	client_active = true;
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

static int open_tcp(const char *address, unsigned int port)
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
	addr.sin_addr.s_addr = inet_addr(address);
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

static int connect_tcp(const char *address, unsigned int port)
{
	struct sockaddr_in addr;
	int fd;

	fd = socket(PF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("Failed to open TCP client socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(address);
	addr.sin_port = htons(port);

	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to connect TCP client socket");
		close(fd);
		return -1;
	}

	return fd;
}

static int open_vhci(uint8_t type)
{
	uint8_t create_req[2] = { 0xff, type };
	ssize_t written;
	int fd;

	fd = open("/dev/vhci", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("Failed to open /dev/vhci device");
		return -1;
	}

	written = write(fd, create_req, sizeof(create_req));
	if (written < 0) {
		perror("Failed to set device type");
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
		"\t-c, --connect <address>     Connect to server\n"
		"\t-l, --listen [address]      Use TCP server\n"
		"\t-u, --unix [path]           Use Unix server\n"
		"\t-p, --port <port>           Use specified TCP port\n"
		"\t-i, --index <num>           Use specified controller\n"
		"\t-s, --smd                   Use SMD channel devices\n"
		"\t-h, --help                  Show help options\n");
}

static const struct option main_options[] = {
	{ "connect", required_argument, NULL, 'c' },
	{ "listen",  optional_argument, NULL, 'l' },
	{ "unix",    optional_argument, NULL, 'u' },
	{ "port",    required_argument, NULL, 'p' },
	{ "index",   required_argument, NULL, 'i' },
	{ "smd",     no_argument,       NULL, 's' },
	{ "version", no_argument,       NULL, 'v' },
	{ "help",    no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	const char *connect_address = NULL;
	const char *server_address = NULL;
	const char *unix_path = NULL;
	unsigned short tcp_port = 0xb1ee;
	const char *str;
	sigset_t mask;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "c:l::u::p:i:svh",
						main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'c':
			connect_address = optarg;
			break;
		case 'l':
			if (optarg)
				server_address = optarg;
			else
				server_address = "0.0.0.0";
			break;
		case 'u':
			if (optarg)
				unix_path = optarg;
			else
				unix_path = "/tmp/bt-server-bredr";
			break;
		case 'p':
			tcp_port = atoi(optarg);
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
		case 's':
			use_smd = true;
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

	if (connect_address) {
		int src_fd, dst_fd;

		printf("Connecting to %s:%u\n", connect_address, tcp_port);

		src_fd = connect_tcp(connect_address, tcp_port);
		if (src_fd < 0)
			return EXIT_FAILURE;

		printf("Opening virtual device\n");

		dst_fd = open_vhci(0x00);
		if (dst_fd < 0) {
			close(src_fd);
			return EXIT_FAILURE;
		}

		if (!setup_streams(src_fd, 0x00, 0x00, dst_fd))
			return EXIT_FAILURE;
	} else {
		int server_fd;

		if (unix_path) {
			printf("Listening on %s\n", unix_path);

			server_fd = open_unix(unix_path);
		} else if (server_address) {
			printf("Listening on %s:%u\n", server_address,
								tcp_port);

			server_fd = open_tcp(server_address, tcp_port);
		} else {
			fprintf(stderr, "Missing emulator device\n");
			return EXIT_FAILURE;
		}

		if (server_fd < 0)
			return EXIT_FAILURE;

		mainloop_add_fd(server_fd, EPOLLIN, server_callback,
							NULL, NULL);
	}

	return mainloop_run();
}
