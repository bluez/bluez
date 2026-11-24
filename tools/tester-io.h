/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Intel Corporation
 *
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <poll.h>
#include <sys/epoll.h>

/* Watches on file descriptors for the testers, in the way of GLib's
 * GIOChannel watches, on top of the mainloop: several watches per file
 * descriptor, each holding a reference to it, and the file descriptor
 * closed with the last reference if requested. Like GLib, watches are
 * called after the other ready descriptors were handled.
 */

#define TESTER_IO_IN	EPOLLIN
#define TESTER_IO_OUT	EPOLLOUT
#define TESTER_IO_ERR	EPOLLERR
#define TESTER_IO_HUP	EPOLLHUP
/* Reported once the descriptor was closed with tester_io_close() */
#define TESTER_IO_NVAL	POLLNVAL

struct tester_io;

typedef bool (*tester_io_func_t)(struct tester_io *io, uint32_t cond,
							void *user_data);

struct tester_io *tester_io_new(int fd);
struct tester_io *tester_io_ref(struct tester_io *io);
void tester_io_unref(struct tester_io *io);
int tester_io_get_fd(struct tester_io *io);
void tester_io_set_close_on_unref(struct tester_io *io, bool close_on_unref);

/* Closes the descriptor, which the watches see as TESTER_IO_NVAL */
void tester_io_close(struct tester_io *io);

/* The watch is called while one of cond is set, until it returns false */
unsigned int tester_io_add_watch(struct tester_io *io, uint32_t cond,
				tester_io_func_t func, void *user_data);

/* Removes a watch, or a timeout added with timeout_add() */
void tester_remove_source(unsigned int id);

/* The id of the watch being called, 0 outside of a watch */
unsigned int tester_current_source(void);
