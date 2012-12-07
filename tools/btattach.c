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

int main(int argc, char *argv[])
{
	struct pollfd p[5];
	unsigned long flags = 0;
	int fd, i, count = 0;

	flags |= (1 << HCI_UART_RESET_ON_INIT);

	fd = attach_proto("/dev/ttyS0", HCI_UART_H4, flags);
	if (fd >= 0)
		p[count++].fd = fd;

	flags |= (1 << HCI_UART_CREATE_AMP);

	fd = attach_proto("/dev/ttyS1", HCI_UART_H4, flags);
	if (fd >= 0)
		p[count++].fd = fd;

	for (i = 0; i < count; i++)
		p[i].events = POLLERR | POLLHUP;

	while (1) {
		poll(p, count, -1);
        }

	for (i = 0; i < count; i++)
		close(p[i].fd);

	return EXIT_SUCCESS;
}
