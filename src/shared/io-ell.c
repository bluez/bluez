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
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

#include <ell/ell.h>

#include "src/shared/io.h"

struct io {
	struct l_io *l_io;
};

struct io *io_new(int fd)
{
	struct io *io;
	struct l_io *l_io;

	if (fd < 0)
		return NULL;

	io = l_new(struct io, 1);
	if (!io)
		return NULL;

	l_io = l_io_new(fd);
	if (!l_io) {
		l_free(io);
		return NULL;
	}

	io->l_io = l_io;

	return io;
}

void io_destroy(struct io *io)
{
	if (!io)
		return;

	if (io->l_io)
		l_io_destroy(io->l_io);

	l_free(io);
}

int io_get_fd(struct io *io)
{
	if (!io || !io->l_io)
		return -ENOTCONN;

	return l_io_get_fd(io->l_io);
}

bool io_set_close_on_destroy(struct io *io, bool do_close)
{
	if (!io || !io->l_io)
		return false;

	return l_io_set_close_on_destroy(io->l_io, do_close);
}

bool io_set_read_handler(struct io *io, io_callback_func_t callback,
				void *user_data, io_destroy_func_t destroy)
{
	if (!io || !io->l_io)
		return false;

	return l_io_set_read_handler(io->l_io, (l_io_read_cb_t) callback,
							user_data, destroy);
}

bool io_set_write_handler(struct io *io, io_callback_func_t callback,
				void *user_data, io_destroy_func_t destroy)
{
	if (!io || !io->l_io)
		return false;

	return l_io_set_write_handler(io->l_io, (l_io_write_cb_t) callback,
							user_data, destroy);
}

bool io_set_disconnect_handler(struct io *io, io_callback_func_t callback,
				void *user_data, io_destroy_func_t destroy)
{
	if (!io || !io->l_io)
		return false;

	return l_io_set_disconnect_handler(io->l_io, (void *) callback,
							user_data, destroy);
}

ssize_t io_send(struct io *io, const struct iovec *iov, int iovcnt)
{
	ssize_t ret;
	int fd;

	if (!io || !io->l_io)
		return -ENOTCONN;

	fd = l_io_get_fd(io->l_io);
	if (fd < 0)
		return -ENOTCONN;

	do {
		ret = writev(fd, iov, iovcnt);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		return -errno;

	return ret;
}

bool io_shutdown(struct io *io)
{
	int fd;

	if (!io || !io->l_io)
		return false;

	fd = l_io_get_fd(io->l_io);
	if (fd < 0)
		return false;

	return shutdown(fd, SHUT_RDWR) == 0;
}
