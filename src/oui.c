/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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
#include <sys/stat.h>
#include <sys/mman.h>

#include "oui.h"

/* http://standards.ieee.org/regauth/oui/oui.txt */

#define OUIFILE "/var/lib/misc/oui.txt"

char *ouitocomp(const char *oui)
{
	struct stat st;
	char *str, *map, *off, *end;
	int fd;

	fd = open("oui.txt", O_RDONLY);
	if (fd < 0) {
		fd = open(OUIFILE, O_RDONLY);
		if (fd < 0) {
			fd = open("/usr/share/misc/oui.txt", O_RDONLY);
			if (fd < 0)
				return NULL;
		}
	}

	if (fstat(fd, &st) < 0) {
		close(fd);
		return NULL;
	}

	str = malloc(128);
	if (!str) {
		close(fd);
		return NULL;
	}

	memset(str, 0, 128);

	map = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (!map || map == MAP_FAILED) {
		free(str);
		close(fd);
		return NULL;
	}

	off = strstr(map, oui);
	if (off) {
		off += 18;
		end = strpbrk(off, "\r\n");
		strncpy(str, off, end - off);
	} else {
		free(str);
		str = NULL;
	}

	munmap(map, st.st_size);

	close(fd);

	return str;
}

int oui2comp(const char *oui, char *comp, size_t size)
{
	char *tmp;

	tmp = ouitocomp(oui);
	if (!tmp)
		return -1;

	snprintf(comp, size, "%s", tmp);

	free(tmp);

	return 0;
}
