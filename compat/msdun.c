/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdint.h>
#include <stdlib.h>
#include <syslog.h>
#include <setjmp.h>
#include <string.h>

#include "lib.h"
#include "dund.h"

#define MS_PPP      2
#define MS_SUCCESS  1
#define MS_FAILED  -1
#define MS_TIMEOUT -2

static sigjmp_buf jmp;
static int        retry;
static int        timeout;

static void sig_alarm(int sig)
{
	siglongjmp(jmp, MS_TIMEOUT);
}

static int w4_str(int fd, char *str)
{
	char buf[40];
	unsigned len = 0;
	int r;

	while (1) {
		r = read(fd, buf + len, sizeof(buf) - len - 1);
		if (r < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			break;
		}
		if (!r)
			break;

		len += r;

		if (len < strlen(str))
			continue;
		buf[len] = 0;

		if (strstr(buf, str))
			return MS_SUCCESS;

		/* Detect PPP */
		if (strchr(buf, '~'))
			return MS_PPP;
	}
	return MS_FAILED;
}

static int ms_server(int fd)
{
	switch (w4_str(fd, "CLIENT")) {
	case MS_SUCCESS:
		write_n(fd, "CLIENTSERVER", 12);
	case MS_PPP:
		return MS_SUCCESS;
	default:
		return MS_FAILED;
	}
}

static int ms_client(int fd)
{
	write_n(fd, "CLIENT", 6);
	return w4_str(fd, "CLIENTSERVER");
}

int ms_dun(int fd, int server, int timeo)
{
	sig_t osig;

	retry    = 4;
	timeout  = timeo;

	if (!server)
		timeout /= retry;

	osig = signal(SIGALRM, sig_alarm);

	while (1) {
		int r = sigsetjmp(jmp, 1);
		if (r) {
			if (r == MS_TIMEOUT && !server && --retry)
				continue;

			alarm(0);
			signal(SIGALRM, osig);

			switch (r) {
			case MS_SUCCESS:
			case MS_PPP:
				errno = 0;
				return 0;

			case MS_FAILED:
				errno = EPROTO;
				break;

			case MS_TIMEOUT:
				errno = ETIMEDOUT;
				break;
			}
			return -1;
		}

		alarm(timeout);

		if (server)
			r = ms_server(fd);
		else
			r = ms_client(fd);

		siglongjmp(jmp, r);
	}
}
