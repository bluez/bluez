/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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

#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/uio.h>

#include <glib.h>

void info(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vfprintf(stdout, format, ap);
	fprintf(stdout, "\n");

	va_end(ap);
}

void warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vfprintf(stderr, format, ap);
	fprintf(stderr, "\n");

	va_end(ap);
}

void error(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vfprintf(stderr, format, ap);
	fprintf(stderr, "\n");

	va_end(ap);
}

void btd_debug(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vfprintf(stdout, format, ap);
	fprintf(stdout, "\n");

	va_end(ap);
}
