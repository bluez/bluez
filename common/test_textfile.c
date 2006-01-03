/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
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

#include "textfile.h"

int main(int argc, char *argv[])
{
	char filename[] = "/tmp/textfile";
	char key[18], value[512], *str;
	int i, j, fd;

	fd = creat(filename, 0644);
	close(fd);

	for (i = 1; i < 101; i++) {
		sprintf(key, "00:00:00:00:00:%02X", i);

		memset(value, 0, sizeof(value));
		for (j = 0; j < i; j++)
			value[j] = 'x';

		printf("%s %s\n", key, value);

		if (textfile_put(filename, key, value) < 0) {
			fprintf(stderr, "%s (%d)\n", strerror(errno), errno);
			break;
		}

		str = textfile_get(filename, key);
		if (!str)
			fprintf(stderr, "No value for %s\n", key);
		else
			free(str);
	}

	return 0;
}
