// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <glib.h>

#include "src/shared/io.h"
#include "src/shared/util.h"
#include "src/shared/tester.h"

static void test_basic(const void *data)
{
	tester_test_passed();
}

static bool test_io_recv(struct io *io, void *user_data)
{
	const struct iovec *iov = user_data;
	unsigned char buf[512];
	int fd;
	ssize_t len;

	fd = io_get_fd(io);

	len = read(fd, buf, sizeof(buf));

	g_assert(len > 0);
	g_assert_cmpint(len, ==, iov->iov_len);
	g_assert(memcmp(buf, iov->iov_base, len) == 0);

	tester_test_passed();

	return false;
}

static const struct iovec iov[] = {
	IOV_DATA(0x01),
	IOV_DATA(0x01, 0x02),
};

static void test_setup_io(const void *data)
{
	struct io *io;
	ssize_t len;

	io = tester_setup_io(iov, ARRAY_SIZE(iov));
	g_assert(io);

	io_set_read_handler(io, test_io_recv, (void *)&iov[1], NULL);

	len = io_send(io, (void *)&iov[0], 1);
	g_assert_cmpint(len, ==, iov[0].iov_len);
}

static void test_io_send(const void *data)
{
	struct io *io;

	io = tester_setup_io(iov, ARRAY_SIZE(iov));
	g_assert(io);

	io_set_read_handler(io, test_io_recv, (void *)&iov[0], NULL);

	tester_io_send();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	tester_add("/tester/basic", NULL, NULL, test_basic, NULL);
	tester_add("/tester/setup_io", NULL, NULL, test_setup_io, NULL);
	tester_add("/tester/io_send", NULL, NULL, test_io_send, NULL);

	return tester_run();
}

