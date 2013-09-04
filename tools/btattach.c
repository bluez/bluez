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
#include <getopt.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/poll.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "hciattach.h"

static int open_serial(const char *path)
{
	struct termios ti;
	int fd, ldisc = N_HCI;

	fd = open(path, O_RDWR | O_NOCTTY);
	if (fd < 0) {
		perror("Failed to open serial port");
		return -1;
	}

	if (tcflush(fd, TCIOFLUSH) < 0) {
		perror("Failed to flush serial port");
		close(fd);
		return -1;
	}

	/* Switch TTY to raw mode */
	memset(&ti, 0, sizeof(ti));
	cfmakeraw(&ti);

	ti.c_cflag |= (B115200 | CLOCAL | CREAD);

	if (tcsetattr(fd, TCSANOW, &ti) < 0) {
		perror("Failed to set serial port settings");
		close(fd);
		return -1;
	}

	if (ioctl(fd, TIOCSETD, &ldisc) < 0) {
		perror("Failed set serial line discipline");
		close(fd);
		return -1;
	}

	return fd;
}

static int attach_proto(const char *path, unsigned int proto,
						unsigned int flags)
{
	int fd;

	fd = open_serial(path);
	if (fd < 0)
		return -1;

	if (ioctl(fd, HCIUARTSETFLAGS, flags) < 0) {
		perror("Failed to set flags");
		close(fd);
		return -1;
	}

	if (ioctl(fd, HCIUARTSETPROTO, proto) < 0) {
		perror("Failed to set protocol");
		close(fd);
		return -1;
	}

	return fd;
}

static void usage(void)
{
	printf("btattach - Bluetooth serial utility\n"
		"Usage:\n");
	printf("\tbtattach [options]\n");
	printf("options:\n"
		"\t-B, --bredr <device>   Attach BR/EDR controller\n"
		"\t-A, --amp <device>     Attach AMP controller\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "bredr",   required_argument, NULL, 'B' },
	{ "amp",     required_argument, NULL, 'A' },
	{ "version", no_argument,       NULL, 'v' },
	{ "help",    no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	const char *bredr_path = NULL, *amp_path = NULL;
	struct pollfd p[5];
	int i, count = 0;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "B:A:vh",
						main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'B':
			bredr_path = optarg;
			break;
		case 'A':
			amp_path = optarg;
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

	if (bredr_path) {
		unsigned long flags;
		int fd;

		printf("Attaching BR/EDR controller to %s\n", bredr_path);

		flags = (1 << HCI_UART_RESET_ON_INIT);

		fd = attach_proto(bredr_path, HCI_UART_H4, flags);
		if (fd >= 0)
			p[count++].fd = fd;
	}

	if (amp_path) {
		unsigned long flags;
		int fd;

		printf("Attaching AMP controller to %s\n", amp_path);

		flags = (1 << HCI_UART_RESET_ON_INIT) |
			(1 << HCI_UART_CREATE_AMP);

		fd = attach_proto(amp_path, HCI_UART_H4, flags);
		if (fd >= 0)
			p[count++].fd = fd;
	}

	if (count < 1) {
		fprintf(stderr, "No controller attached\n");
		return EXIT_FAILURE;
	}

	for (i = 0; i < count; i++) {
		p[i].events = POLLERR | POLLHUP;
		p[i].revents = 0;
	}

	while (1) {
		if (poll(p, count, -1) < 0)
			break;
        }

	for (i = 0; i < count; i++)
		close(p[i].fd);

	return EXIT_SUCCESS;
}
