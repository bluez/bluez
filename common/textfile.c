/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mman.h>

char *textfile_get(const char *pathname, const char *key)
{
	struct stat st;
	char *map, *off, *end, *str = NULL;
	off_t size; size_t len;
	int fd;

	fd = open(pathname, O_RDONLY);
	if (fd < 0)
		return NULL;

	if (flock(fd, LOCK_SH) < 0)
		goto close;

	if (fstat(fd, &st) < 0)
		goto unlock;

	size = st.st_size;

	map = mmap(0, size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
		goto close;

	off = strstr(map, key);
	if (!off)
		goto unmap;

	if (off > map) {
		while (*(off - 1) != '\r' && *(off - 1) != '\n') {
			off = strstr(map, key);
			if (!off)
				goto unmap;
		}
	}

	end = strpbrk(off, "\r\n");
	if (!end)
		goto unmap;

	len = strlen(key);
	str = malloc(end - off - len);
	memset(str, 0, end - off - len);
	if (!str)
		goto unmap;

	strncpy(str, off + len + 1, end - off - len - 1);

unmap:
	munmap(map, size);

unlock:
	flock(fd, LOCK_UN);

close:
	close(fd);

	return str;
}
