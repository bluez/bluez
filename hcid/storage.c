/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2005  Marcel Holtmann <marcel@holtmann.org>
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
#include <syslog.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>

#include "hcid.h"

#define DEVPATH "/var/lib/bluetooth/"

struct list {
	bdaddr_t bdaddr;
	unsigned char *data;
	size_t size;
	struct list *next;
};

static struct list *list_add(struct list *list, const bdaddr_t *bdaddr,
				const unsigned char *data, const size_t size)
{
	struct list *temp = list, *last = list;

	if (!bacmp(bdaddr, BDADDR_ANY))
		return list;

	while (temp) {
		if (!bacmp(&temp->bdaddr, bdaddr)) {
			if (temp->data)
				free(temp->data);

			temp->data = malloc(size);
			if (temp->data) {
				memcpy(temp->data, data, size);
				temp->size = size;
			} else
				temp->size = 0;

			return list;
		}
		temp = temp->next;
	}

	temp = malloc(sizeof(*temp));
	if (!temp)
		return list;

	memset(temp, 0, sizeof(*temp));

	bacpy(&temp->bdaddr, bdaddr);
	temp->data = malloc(size);
	if (temp->data) {
		memcpy(temp->data, data, size);
		temp->size = size;
	} else
		temp->size = 0;

	temp->next = NULL;

	if (!list)
		return temp;

	while (last->next)
		last = last->next;

	last->next = temp;

	return list;
}

static struct list *list_free(struct list *list)
{
	struct list *temp = list;

	if (!list)
		return NULL;

	while (list->next) {
		temp = list;
		list = list->next;
		if (temp->data)
			free(temp->data);
		free(temp);
	}

	return NULL;
}

#define list_foreach(list, entry) \
	for (entry = list; entry; entry = entry->next)

static int create_dirs(const char *filename, mode_t mode)
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

int write_device_name(const bdaddr_t *local, const bdaddr_t *peer, const char *name)
{
	struct list *temp, *list = NULL;
	char filename[PATH_MAX + 1], addr[18], str[249], *buf, *ptr;
	bdaddr_t bdaddr;
	struct stat st;
	int fd, pos, err = 0;

	ba2str(local, addr);
	snprintf(filename, PATH_MAX, "%s/%s/names", DEVPATH, addr);

	umask(S_IWGRP | S_IWOTH);
	create_dirs(filename, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

	fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0)
		return -errno;

	if (flock(fd, LOCK_EX) < 0) {
		err = -errno;
		goto close;
	}

	if (fstat(fd, &st) < 0) {
		err = -errno;
		goto unlock;
	}

	buf = malloc(st.st_size + 200);
	if (!buf) {
		err = -ENOMEM;
		goto unlock;
	}

	if (st.st_size > 0) {
		read(fd, buf, st.st_size);

		ptr = buf;

		while (sscanf(ptr, "%17s %[^\n]\n%n", addr, str, &pos) != EOF) {
			str2ba(addr, &bdaddr);
			list = list_add(list, &bdaddr, str, strlen(str) + 1);
			ptr += pos;
		};

		lseek(fd, 0, SEEK_SET);
		ftruncate(fd, 0);
	}

	list = list_add(list, peer, name, strlen(name) + 1);
	if (!list) {
		err = -EIO;
		goto unlock;
	}

	list_foreach(list, temp) {
		ba2str(&temp->bdaddr, addr);
		snprintf(buf, 200, "%s %s\n", addr, temp->data);
		write(fd, buf, strlen(buf));
	}

unlock:
	flock(fd, LOCK_UN);

close:
	close(fd);
	list_free(list);
	return err;
}

int write_link_key(const bdaddr_t *local, const bdaddr_t *peer, const unsigned char *key, const int type)
{
	struct list *temp, *list = NULL;
	char filename[PATH_MAX + 1], addr[18], str[35], *buf, *ptr;
	bdaddr_t bdaddr;
	struct stat st;
	int i, fd, pos, err = 0;

	ba2str(local, addr);
	snprintf(filename, PATH_MAX, "%s/%s/linkkeys", DEVPATH, addr);

	umask(S_IWGRP | S_IWOTH);
	create_dirs(filename, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

	fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0)
		return -errno;

	if (flock(fd, LOCK_EX) < 0) {
		err = -errno;
		goto close;
	}

	if (fstat(fd, &st) < 0) {
		err = -errno;
		goto unlock;
	}

	buf = malloc(st.st_size + 200);
	if (!buf) {
		err = -ENOMEM;
		goto unlock;
	}

	if (st.st_size > 0) {
		read(fd, buf, st.st_size);

		ptr = buf;

		while (sscanf(ptr, "%17s %[^\n]\n%n", addr, str, &pos) != EOF) {
			str2ba(addr, &bdaddr);
			list = list_add(list, &bdaddr, str, strlen(str) + 1);
			ptr += pos;
		};

		lseek(fd, 0, SEEK_SET);
		ftruncate(fd, 0);
	}

	memset(str, 0, sizeof(str));
	for (i = 0; i < 16; i++)
		sprintf(str + (i * 2), "%2.2X", key[i]);
	sprintf(str + 32, " %d", type);

	list = list_add(list, peer, str, strlen(str) + 1);
	if (!list) {
		err = -EIO;
		goto unlock;
	}

	list_foreach(list, temp) {
		ba2str(&temp->bdaddr, addr);
		snprintf(buf, 200, "%s %s\n", addr, temp->data);
		write(fd, buf, strlen(buf));
	}

unlock:
	flock(fd, LOCK_UN);

close:
	close(fd);
	list_free(list);
	return err;
}

int read_link_key(const bdaddr_t *local, const bdaddr_t *peer, unsigned char *key)
{
	return -ENOENT;
}
