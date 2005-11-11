/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
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
#include <string.h>
#include <stdint.h>
#include <termios.h>

#include "csr.h"

static uint16_t seqnum = 0x0000;

static int fd = -1;

int csr_open_bcsp(char *device)
{
	struct termios ti;

	if (!device)
		device = "/dev/ttyS0";

	fd = open(device, O_RDWR | O_NOCTTY);
	if (fd < 0) {
		fprintf(stderr, "Can't open serial port: %s (%d)\n",
						strerror(errno), errno);
		return -1;
	}

	tcflush(fd, TCIOFLUSH);

	if (tcgetattr(fd, &ti) < 0) {
		fprintf(stderr, "Can't get port settings: %s (%d)\n",
						strerror(errno), errno);
		close(fd);
		return -1;
	}

	cfmakeraw(&ti);

	ti.c_cflag |=  CLOCAL;
	ti.c_cflag &= ~CRTSCTS;
	ti.c_cflag |=  PARENB;
	ti.c_cflag &= ~PARODD;
	ti.c_cflag &= ~CSIZE;
	ti.c_cflag |=  CS8;
	ti.c_cflag &= ~CSTOPB;

	ti.c_cc[VMIN] = 1;
	ti.c_cc[VTIME] = 0;

	cfsetospeed(&ti, B38400);

	if (tcsetattr(fd, TCSANOW, &ti) < 0) {
		fprintf(stderr, "Can't change port settings: %s (%d)\n",
						strerror(errno), errno);
		close(fd);
		return -1;
	}

	tcflush(fd, TCIOFLUSH);

	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
		fprintf(stderr, "Can't set non blocking mode: %s (%d)\n",
						strerror(errno), errno);
		close(fd);
		return -1;
	}

	return 0;
}

static int do_command(uint16_t command, uint16_t seqnum, uint16_t varid, uint8_t *value, uint16_t length)
{
	errno = EIO;

	return -1;
}

int csr_read_bcsp(uint16_t varid, uint8_t *value, uint16_t length)
{
	return do_command(0x0000, seqnum++, varid, value, length);
}

int csr_write_bcsp(uint16_t varid, uint8_t *value, uint16_t length)
{
	return do_command(0x0002, seqnum++, varid, value, length);
}

void csr_close_bcsp(void)
{
	close(fd);
}
