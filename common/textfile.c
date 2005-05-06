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

static int write_key_value(const int fd, const char *key, const char *value)
{
	char *str;
	int size, err = 0;

	size = strlen(key) + strlen(value) + 2;

	str = malloc(size);
	if (!str)
		return ENOMEM;

	sprintf(str, "%s %s\n", key, value);

	if (write(fd, str, size) < 0)
		err = errno;

	free(str);

	return err;
}

int textfile_put(const char *pathname, const char *key, const char *value)
{
	struct stat st;
	char *map, *off, *end, *str;
	off_t size, pos; size_t base, len;
	int fd, err = 0;

	fd = open(pathname, O_RDWR);
	if (fd < 0)
		return -errno;

	if (flock(fd, LOCK_EX) < 0) {
		err = errno;
		goto close;
	}

	if (fstat(fd, &st) < 0) {
		err = errno;
		goto unlock;
	}

	size = st.st_size;

	if (!size) {
		pos = lseek(fd, size, SEEK_SET);
		err = write_key_value(fd, key, value);
		goto unlock;
	}

	map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		err = errno;
		goto unlock;
	}

	off = strstr(map, key);
	if (!off) {
		munmap(map, size);
		pos = lseek(fd, size, SEEK_SET);
		err = write_key_value(fd, key, value);
		goto unlock;
	}

	if (off > map) {
		while (*(off - 1) != '\r' && *(off - 1) != '\n') {
			off = strstr(off, key);
			if (!off) {
				munmap(map, size);
				pos = lseek(fd, size, SEEK_SET);
				err = write_key_value(fd, key, value);
				goto unlock;
			}
		}
	}

	base = off - map;

	end = strpbrk(off, "\r\n");
	if (!end) {
		err = EILSEQ;
		goto unmap;
	}

	len = strspn(end, "\r\n");
	end += len;

	len = size - (end - map);

	str = malloc(len);
	if (!str) {
		err = errno;
		goto unmap;
	}

	memcpy(str, end, len);
	munmap(map, size);

	ftruncate(fd, base);
	pos = lseek(fd, base, SEEK_SET);

	write_key_value(fd, key, value);
	write(fd, str, len);

	free(str);

	goto unlock;

unmap:
	munmap(map, size);

unlock:
	flock(fd, LOCK_UN);

close:
	close(fd);
	errno = err;

	return -err;
}

char *textfile_get(const char *pathname, const char *key)
{
	struct stat st;
	char *map, *off, *end, *str = NULL;
	off_t size; size_t len;
	int fd, err = 0;

	fd = open(pathname, O_RDONLY);
	if (fd < 0)
		return NULL;

	if (flock(fd, LOCK_SH) < 0) {
		err = errno;
		goto close;
	}

	if (fstat(fd, &st) < 0) {
		err = errno;
		goto unlock;
	}

	size = st.st_size;

	map = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		err = errno;
		goto unlock;
	}

	off = strstr(map, key);
	if (!off) {
		err = EILSEQ;
		goto unmap;
	}

	if (off > map) {
		while (*(off - 1) != '\r' && *(off - 1) != '\n') {
			off = strstr(off, key);
			if (!off) {
				err = EILSEQ;
				goto unmap;
			}
		}
	}

	end = strpbrk(off, "\r\n");
	if (!end) {
		err = EILSEQ;
		goto unmap;
	}

	len = strlen(key);
	str = malloc(end - off - len);
	if (!str) {
		err = EILSEQ;
		goto unmap;
	}

	memset(str, 0, end - off - len);
	strncpy(str, off + len + 1, end - off - len - 1);

unmap:
	munmap(map, size);

unlock:
	flock(fd, LOCK_UN);

close:
	close(fd);
	errno = err;

	return str;
}
