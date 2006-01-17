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
#include <malloc.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>

int create_dirs(char *filename, mode_t mode)
{
	struct stat st;
	char dir[PATH_MAX + 1], *prev, *next;
	int err;

	err = stat(filename, &st);
	if (!err && S_ISREG(st.st_mode))
		return 0;

	memset(dir, 0, PATH_MAX + 1);
	strcat(dir, "/");

	prev = strchr(filename, '/');

	while (prev) {
		next = strchr(prev + 1, '/');
		if (!next)
			break;

		if (next - prev == 1) {
			prev = next;
			continue;
		}

		strncat(dir, prev + 1, next - prev);
		mkdir(dir, mode);

		prev = next;
	}

	return 0;
}

int create_file(char *filename, mode_t mode)
{
	int fd;

	umask(S_IWGRP | S_IWOTH);
	create_dirs(filename, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

	fd = open(filename, O_RDWR | O_CREAT, mode);
	if (fd < 0)
		return fd;

	close(fd);

	return 0;
}

static inline int write_key_value(int fd, char *key, char *value)
{
	char *str;
	size_t size;
	int err = 0;

	size = strlen(key) + strlen(value) + 2;

	str = malloc(size + 1);
	if (!str)
		return ENOMEM;

	sprintf(str, "%s %s\n", key, value);

	if (write(fd, str, size) < 0)
		err = errno;

	free(str);

	return err;
}

static inline char *find_key(char *map, char *key, size_t len)
{
	char *off = strstr(map, key);

	while (off && ((off > map && *(off - 1) != '\r' &&
				*(off - 1) != '\n') || *(off + len) != ' '))
		off = strstr(off + len, key);

	return off;
}

int textfile_put(char *pathname, char *key, char *value)
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

	map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_LOCKED, fd, 0);
	if (!map || map == MAP_FAILED) {
		err = errno;
		goto unlock;
	}

	off = find_key(map, key, strlen(key));
	if (!off) {
		munmap(map, size);
		pos = lseek(fd, size, SEEK_SET);
		err = write_key_value(fd, key, value);
		goto unlock;
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
	if (!len) {
		munmap(map, size);
		ftruncate(fd, base);
		pos = lseek(fd, base, SEEK_SET);
		err = write_key_value(fd, key, value);
		goto unlock;
	}

	if (len < 0 || len > size) {
		err = EILSEQ;
		goto unmap;
	}

	str = malloc(len);
	if (!str) {
		err = errno;
		goto unmap;
	}

	memcpy(str, end, len);

	munmap(map, size);
	ftruncate(fd, base);
	pos = lseek(fd, base, SEEK_SET);
	err = write_key_value(fd, key, value);

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

char *textfile_get(char *pathname, char *key)
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
	if (!map || map == MAP_FAILED) {
		err = errno;
		goto unlock;
	}

	len = strlen(key);
	off = find_key(map, key, len);
	if (!off) {
		err = EILSEQ;
		goto unmap;
	}

	end = strpbrk(off, "\r\n");
	if (!end) {
		err = EILSEQ;
		goto unmap;
	}

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
