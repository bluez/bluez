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
#include <string.h>

#include <fuse.h>

static int btfs_getattr(const char *path, struct stat *stbuf)
{
	int err = 0;

	memset(stbuf, 0, sizeof(struct stat));

	if (!strcmp(path, "/")) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (!strcmp(path, "/test")) {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen("/test");
	} else
		err = -ENOENT;

	return err;
}

static int btfs_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
	if (strcmp(path, "/"))
		return -ENOENT;

	filler(h, ".", 0);
	filler(h, "..", 0);
	filler(h, "test", 0);

	return 0;
}

static int btfs_open(const char *path, int flags)
{
	if (strcmp(path, "/test"))
		return -ENOENT;

	if ((flags & 3) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int btfs_read(const char *path, char *buf, size_t size, off_t offset)
{
	if (strcmp(path, "/test"))
		return -ENOENT;

	memcpy(buf, "Test" + offset, size);

	return size;
}

static struct fuse_operations btfs_ops = {
	.getattr	= btfs_getattr,
	.getdir		= btfs_getdir,
	.open		= btfs_open,
	.read		= btfs_read,
};

int main(int argc, char *argv[])
{
	return fuse_main(argc, argv, &btfs_ops);
}
