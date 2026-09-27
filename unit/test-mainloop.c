// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026 Pauli Virtanen
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "src/shared/mainloop.h"


#define test_failed_msg(msg) \
	fail_and_abort(msg, __FILE__, __LINE__, __func__)

#define test_failed() \
	test_failed_msg("")

#define check(condition) \
	({ if (!(condition)) test_failed_msg(#condition " not true"); })


struct test_data {
	int fds[4];
	unsigned int old_calls;
	unsigned int new_calls;
	unsigned int destroys;
	unsigned int timeout_calls;
};


static void fail_and_abort(const char *msg, const char *file, int line,
							const char *func)
{
	fprintf(stderr, "test failed\n");
	fprintf(stderr, "    %s in %s:%d (%s)\n", msg, file, line, func);
	abort();
}

static void teardown(struct test_data *data)
{
	int i;

	for (i = 0; i < 4; ++i)
		if (data->fds[i] > 0)
			close(data->fds[i]);
}

static void destroy(void *user_data)
{
	struct test_data *data = user_data;

	data->destroys++;
}

static void fd_callback(int fd, uint32_t events, void *user_data)
{
	struct test_data *data = user_data;
	char buf;

	check(events & EPOLLIN);
	check(read(fd, &buf, 1) == 1);
	check(buf == 'a');
	data->old_calls++;
	mainloop_exit_failure();
}

static void test_modify_fd(struct test_data *data)
{
	check(pipe(data->fds) == 0);

	mainloop_init();

	check(mainloop_add_fd(data->fds[0], EPOLLOUT, fd_callback,
						data, destroy) == 0);
	check(mainloop_modify_fd(data->fds[0], EPOLLIN) == 0);
	check(write(data->fds[1], "a", 1) == 1);
	check(mainloop_run() == EXIT_FAILURE);
	check(data->old_calls == 1);
	check(data->destroys == 1);
}

static void new_callback(int fd, uint32_t events, void *user_data)
{
	struct test_data *data = user_data;

	data->new_calls++;
}

static void old_callback(int fd, uint32_t events, void *user_data)
{
	struct test_data *data = user_data;
	int other_fd = fd == data->fds[0] ? data->fds[2] : data->fds[0];

	data->old_calls++;
	check(mainloop_remove_fd(other_fd) == 0);
	check(data->destroys == 1);
	check(mainloop_add_fd(other_fd, EPOLLIN, new_callback, data,
								destroy) == 0);
	mainloop_exit_success();
}

static void test_readd_other_callback(struct test_data *data)
{
	check(pipe(&data->fds[0]) == 0);
	check(pipe(&data->fds[2]) == 0);

	mainloop_init();

	check(mainloop_add_fd(data->fds[0], EPOLLIN, old_callback,
							data, destroy) == 0);
	check(mainloop_add_fd(data->fds[2], EPOLLIN, old_callback,
							data, destroy) == 0);
	check(write(data->fds[1], "a", 1) == 1);
	check(write(data->fds[3], "b", 1) == 1);

	check(mainloop_run() == 0);

	check(data->old_calls == 1);
	check(data->new_calls == 0);
	check(data->destroys == 3);
}

static void timeout_callback(int id, void *user_data)
{
	struct test_data *data = user_data;

	data->timeout_calls++;
	if (data->timeout_calls == 1) {
		check(mainloop_modify_timeout(id, 1) == 0);
		return;
	}

	check(mainloop_remove_timeout(id) == 0);
	mainloop_quit();
}

static void test_timeout(struct test_data *data)
{
	int id;

	mainloop_init();

	id = mainloop_add_timeout(0, timeout_callback, data, destroy);
	check(id > 0);
	check(mainloop_modify_timeout(id, 1) == 0);
	check(mainloop_run() == EXIT_SUCCESS);
	check(data->timeout_calls == 2);
	check(data->destroys == 1);
}

#define define_test(name, function)				\
	do {							\
		static struct test_data data = {};		\
		fprintf(stderr, "%s - ", name);			\
		function(&data);				\
		fprintf(stderr, "test passed\n");		\
		teardown(&data);				\
	} while (0)

int main(int argc, char *argv[])
{
	define_test("Test Modify File Descriptor", test_modify_fd);
	define_test("Test Re-Add Other Callback", test_readd_other_callback);
	define_test("Test Timeout", test_timeout);
	return 0;
}
