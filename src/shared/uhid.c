/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
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
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "src/shared/io.h"
#include "src/shared/util.h"
#include "src/shared/uhid.h"

#define UHID_DEVICE_FILE "/dev/uhid"

struct bt_uhid {
	int ref_count;
	struct io *io;
};

static void uhid_free(struct bt_uhid *uhid)
{
	if (uhid->io)
		io_destroy(uhid->io);

	free(uhid);
}

static bool uhid_read_handler(struct io *io, void *user_data)
{
	int fd;
	ssize_t len;
	struct uhid_event ev;

	fd = io_get_fd(io);
	if (fd < 0)
		return false;

	memset(&ev, 0, sizeof(ev));

	len = read(fd, &ev, sizeof(ev));
	if (len < 0)
		return false;

	if ((size_t) len < sizeof(ev.type))
		return false;

	return true;
}

struct bt_uhid *bt_uhid_new_default(void)
{
	struct bt_uhid *uhid;
	int fd;

	fd = open(UHID_DEVICE_FILE, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	uhid = bt_uhid_new(fd);
	if (!uhid) {
		close(fd);
		return NULL;
	}

	io_set_close_on_destroy(uhid->io, true);

	return uhid;
}

struct bt_uhid *bt_uhid_new(int fd)
{
	struct bt_uhid *uhid;

	uhid = new0(struct bt_uhid, 1);
	if (!uhid)
		return NULL;

	uhid->io = io_new(fd);
	if (!uhid->io)
		goto failed;

	if (!io_set_read_handler(uhid->io, uhid_read_handler, uhid, NULL))
		goto failed;

	return bt_uhid_ref(uhid);

failed:
	uhid_free(uhid);
	return NULL;
}

struct bt_uhid *bt_uhid_ref(struct bt_uhid *uhid)
{
	if (!uhid)
		return NULL;

	__sync_fetch_and_add(&uhid->ref_count, 1);

	return uhid;
}

void bt_uhid_unref(struct bt_uhid *uhid)
{
	if (!uhid)
		return;

	if (__sync_sub_and_fetch(&uhid->ref_count, 1))
		return;

	uhid_free(uhid);
}

bool bt_uhid_set_close_on_unref(struct bt_uhid *uhid, bool do_close)
{
	if (!uhid || !uhid->io)
		return false;

	io_set_close_on_destroy(uhid->io, do_close);

	return true;
}

unsigned int bt_uhid_register(struct bt_uhid *uhid, uint32_t type,
				bt_uhid_notify_func_t func, void *user_data)
{
	return 0;
}

bool bt_uhid_unregister(struct bt_uhid *uhid, unsigned int id)
{
	return false;
}

int bt_uhid_send(struct bt_uhid *uhid, const struct uhid_event *ev)
{
	int fd;
	ssize_t len;

	if (!uhid->io)
		return -ENOTCONN;

	fd = io_get_fd(uhid->io);

	len = write(fd, ev, sizeof(*ev));
	if (len < 0)
		return -errno;

	/* uHID kernel driver does not handle partial writes */
	return len != sizeof(*ev) ? -EIO : 0;
}
