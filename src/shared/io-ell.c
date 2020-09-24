// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
 *
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
	io_callback_func_t read_cb;
	io_destroy_func_t read_destroy;
	void *read_data;
	io_callback_func_t write_cb;
	io_destroy_func_t write_destroy;
	void *write_data;
};

static bool read_callback(struct l_io *l_io, void *user_data)
{
	struct io *io = user_data;
	bool result = false;

	if (!io)
		return false;

	if (io->read_cb)
		result = io->read_cb(io, io->read_data);

	if (io->read_destroy)
		io->read_destroy(io->read_data);

	return result;
}

static bool write_callback(struct l_io *l_io, void *user_data)
{
	struct io *io = user_data;
	bool result = false;

	if (!io)
		return false;

	if (io->write_cb)
		result = io->write_cb(io, io->write_data);

	if (io->write_destroy)
		io->write_destroy(io->write_data);

	return result;
}

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

	io->read_cb = callback;
	io->read_data = user_data;
	io->read_destroy = destroy;

	return l_io_set_read_handler(io->l_io, read_callback, io, NULL);
}

bool io_set_write_handler(struct io *io, io_callback_func_t callback,
				void *user_data, io_destroy_func_t destroy)
{
	if (!io || !io->l_io)
		return false;

	io->write_cb = callback;
	io->write_data = user_data;
	io->write_destroy = destroy;

	return l_io_set_write_handler(io->l_io, write_callback, io, NULL);
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
