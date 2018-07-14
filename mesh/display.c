/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <ell/ell.h>

#include "display.h"

static unsigned int cached_num_columns;

unsigned int num_columns(void)
{
	struct winsize ws;

	if (cached_num_columns > 0)
		return cached_num_columns;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0 || ws.ws_col == 0)
		cached_num_columns = 80;
	else
		cached_num_columns = ws.ws_col;

	return cached_num_columns;
}

void print_packet(const char *label, const void *data, uint16_t size)
{
	struct timeval pkt_time;

	gettimeofday(&pkt_time, NULL);

	if (size > 0) {
		char *str;

		str = l_util_hexstring(data, size);
		l_debug("%05d.%03d %s: %s",
				(uint32_t) pkt_time.tv_sec % 100000,
				(uint32_t) pkt_time.tv_usec/1000, label, str);
		l_free(str);
	} else
		l_debug("%05d.%03d %s: empty",
				(uint32_t) pkt_time.tv_sec % 100000,
				(uint32_t) pkt_time.tv_usec/1000, label);
}
