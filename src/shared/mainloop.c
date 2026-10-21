// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "mainloop.h"
#include "mainloop-notify.h"

#define MAX_EPOLL_EVENTS 10

static int epoll_fd;
static int epoll_terminate;
static int exit_status = EXIT_SUCCESS;
static uint64_t next_id;

struct mainloop_data {
	int fd;
	uint64_t id;
	uint32_t events;
	mainloop_event_func callback;
	mainloop_destroy_func destroy;
	void *user_data;
};

#define MAX_MAINLOOP_ENTRIES 128

static struct mainloop_data *mainloop_list[MAX_MAINLOOP_ENTRIES];

struct timeout_data {
	int fd;
	mainloop_timeout_func callback;
	mainloop_destroy_func destroy;
	void *user_data;
};

void mainloop_init(void)
{
	unsigned int i;

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);

	for (i = 0; i < MAX_MAINLOOP_ENTRIES; i++)
		mainloop_list[i] = NULL;

	epoll_terminate = 0;
}

void mainloop_quit(void)
{
	epoll_terminate = 1;

	mainloop_sd_notify("STOPPING=1");
}

void mainloop_exit_success(void)
{
	exit_status = EXIT_SUCCESS;
	epoll_terminate = 1;
}

void mainloop_exit_failure(void)
{
	exit_status = EXIT_FAILURE;
	epoll_terminate = 1;
}

static bool idle_pending(void);
static void run_idles(bool deferred);
static void remove_all_idles(void);

int mainloop_run(void)
{
	unsigned int i;

	while (!epoll_terminate) {
		struct epoll_event events[MAX_EPOLL_EVENTS];
		int n, nfds;

		nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS,
						idle_pending() ? 0 : -1);
		if (nfds < 0)
			continue;

		if (!nfds) {
			run_idles(true);
			run_idles(false);
			continue;
		}

		for (n = 0; n < nfds; n++) {
			uint64_t id = events[n].data.u64;
			int fd = id % MAX_MAINLOOP_ENTRIES;
			struct mainloop_data *data = mainloop_list[fd];

			/* Another callback may have removed it */
			if (!data || data->id != id)
				continue;

			data->callback(data->fd, events[n].events,
							data->user_data);
		}

		run_idles(true);
	}

	for (i = 0; i < MAX_MAINLOOP_ENTRIES; i++) {
		struct mainloop_data *data = mainloop_list[i];

		mainloop_list[i] = NULL;

		if (data) {
			epoll_ctl(epoll_fd, EPOLL_CTL_DEL, data->fd, NULL);

			if (data->destroy)
				data->destroy(data->user_data);

			free(data);
		}
	}

	remove_all_idles();

	close(epoll_fd);
	epoll_fd = 0;

	mainloop_notify_exit();

	return exit_status;
}

int mainloop_add_fd(int fd, uint32_t events, mainloop_event_func callback,
				void *user_data, mainloop_destroy_func destroy)
{
	struct mainloop_data *data;
	struct epoll_event ev;
	int err;

	if (fd < 0 || fd > MAX_MAINLOOP_ENTRIES - 1 || !callback)
		return -EINVAL;

	data = malloc(sizeof(*data));
	if (!data)
		return -ENOMEM;

	memset(data, 0, sizeof(*data));
	data->fd = fd;
	data->id = ++next_id * MAX_MAINLOOP_ENTRIES + fd;
	data->events = events;
	data->callback = callback;
	data->destroy = destroy;
	data->user_data = user_data;

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.u64 = data->id;

	err = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, data->fd, &ev);
	if (err < 0) {
		free(data);
		return err;
	}

	mainloop_list[fd] = data;

	return 0;
}

int mainloop_modify_fd(int fd, uint32_t events)
{
	struct mainloop_data *data;
	struct epoll_event ev;
	int err;

	if (fd < 0 || fd > MAX_MAINLOOP_ENTRIES - 1)
		return -EINVAL;

	data = mainloop_list[fd];
	if (!data)
		return -ENXIO;

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.u64 = data->id;

	err = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, data->fd, &ev);
	if (err < 0)
		return err;

	data->events = events;

	return 0;
}

int mainloop_remove_fd(int fd)
{
	struct mainloop_data *data;
	int err;

	if (fd < 0 || fd > MAX_MAINLOOP_ENTRIES - 1)
		return -EINVAL;

	data = mainloop_list[fd];
	if (!data)
		return -ENXIO;

	mainloop_list[fd] = NULL;

	err = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, data->fd, NULL);

	if (data->destroy)
		data->destroy(data->user_data);

	free(data);

	return err;
}

static void timeout_destroy(void *user_data)
{
	struct timeout_data *data = user_data;

	close(data->fd);
	data->fd = -1;

	if (data->destroy)
		data->destroy(data->user_data);

	free(data);
}

static void timeout_callback(int fd, uint32_t events, void *user_data)
{
	struct timeout_data *data = user_data;
	uint64_t expired;
	ssize_t result;

	if (events & (EPOLLERR | EPOLLHUP))
		return;

	result = read(data->fd, &expired, sizeof(expired));
	if (result != sizeof(expired))
		return;

	if (data->callback)
		data->callback(data->fd, data->user_data);
}

static inline int timeout_set(int fd, unsigned int msec)
{
	struct itimerspec itimer;
	unsigned int sec = msec / 1000;

	memset(&itimer, 0, sizeof(itimer));
	itimer.it_interval.tv_sec = 0;
	itimer.it_interval.tv_nsec = 0;
	itimer.it_value.tv_sec = sec;
	itimer.it_value.tv_nsec = (msec - (sec * 1000)) * 1000 * 1000;

	return timerfd_settime(fd, 0, &itimer, NULL);
}

int mainloop_add_timeout(unsigned int msec, mainloop_timeout_func callback,
				void *user_data, mainloop_destroy_func destroy)
{
	struct timeout_data *data;

	if (!callback)
		return -EINVAL;

	data = malloc(sizeof(*data));
	if (!data)
		return -ENOMEM;

	memset(data, 0, sizeof(*data));
	data->callback = callback;
	data->destroy = destroy;
	data->user_data = user_data;

	data->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (data->fd < 0) {
		free(data);
		return -EIO;
	}

	if (msec > 0) {
		if (timeout_set(data->fd, msec) < 0) {
			close(data->fd);
			free(data);
			return -EIO;
		}
	}

	if (mainloop_add_fd(data->fd, EPOLLIN | EPOLLONESHOT,
				timeout_callback, data, timeout_destroy) < 0) {
		close(data->fd);
		free(data);
		return -EIO;
	}

	return data->fd;
}

/* Idle callbacks run when no file descriptor is ready, after everything
 * pending was handled, as with GLib. Their ids are above the file
 * descriptors, so the timeout functions tell them apart.
 */
#define IDLE_ID_BASE 0x10000

struct idle_data {
	int id;
	bool deferred;
	bool armed;
	bool removed;
	mainloop_timeout_func callback;
	mainloop_destroy_func destroy;
	void *user_data;
	struct idle_data *next;
};

static struct idle_data *idle_list;
static int idle_next_id = IDLE_ID_BASE;

static struct idle_data *find_idle(int id)
{
	struct idle_data *idle;

	for (idle = idle_list; idle; idle = idle->next) {
		if (idle->id == id && !idle->removed)
			return idle;
	}

	return NULL;
}

static bool idle_pending(void)
{
	struct idle_data *idle;

	for (idle = idle_list; idle; idle = idle->next) {
		if (idle->armed && !idle->removed)
			return true;
	}

	return false;
}

static void free_removed_idles(void)
{
	struct idle_data **prev = &idle_list;

	while (*prev) {
		struct idle_data *idle = *prev;

		if (!idle->removed) {
			prev = &idle->next;
			continue;
		}

		*prev = idle->next;

		if (idle->destroy)
			idle->destroy(idle->user_data);

		free(idle);
	}
}

static void remove_all_idles(void)
{
	struct idle_data *idle;

	for (idle = idle_list; idle; idle = idle->next)
		idle->removed = true;

	free_removed_idles();
}

/* Run the idle or deferred callbacks armed before this pass, once each */
static void run_idles(bool deferred)
{
	struct idle_data *idle;
	int last = idle_next_id;

	for (idle = idle_list; idle; idle = idle->next) {
		if (idle->removed || !idle->armed || idle->id >= last ||
						idle->deferred != deferred)
			continue;

		idle->armed = false;
		idle->callback(idle->id, idle->user_data);
	}

	free_removed_idles();
}

static int add_idle(bool deferred, mainloop_timeout_func callback,
			void *user_data, mainloop_destroy_func destroy)
{
	struct idle_data *idle, **last;

	if (!callback)
		return -EINVAL;

	idle = malloc(sizeof(*idle));
	if (!idle)
		return -ENOMEM;

	memset(idle, 0, sizeof(*idle));
	idle->id = idle_next_id++;
	idle->deferred = deferred;
	idle->armed = true;
	idle->callback = callback;
	idle->destroy = destroy;
	idle->user_data = user_data;

	for (last = &idle_list; *last; last = &(*last)->next)
		;
	*last = idle;

	return idle->id;
}

/* Run callback once the mainloop is idle, again after
 * mainloop_modify_timeout() with 0; removed with mainloop_remove_timeout().
 */
int mainloop_add_idle(mainloop_timeout_func callback, void *user_data,
				mainloop_destroy_func destroy)
{
	return add_idle(false, callback, user_data, destroy);
}

/* Run callback after the events ready now were handled, before the idle
 * callbacks, like a source of default priority added last with GLib.
 */
int mainloop_add_deferred(mainloop_timeout_func callback, void *user_data,
				mainloop_destroy_func destroy)
{
	return add_idle(true, callback, user_data, destroy);
}

int mainloop_modify_timeout(int id, unsigned int msec)
{
	if (id >= IDLE_ID_BASE) {
		struct idle_data *idle = find_idle(id);

		if (!idle)
			return -ENOENT;

		idle->armed = true;
		return 0;
	}

	if (msec > 0) {
		if (timeout_set(id, msec) < 0)
			return -EIO;
	}

	if (mainloop_modify_fd(id, EPOLLIN | EPOLLONESHOT) < 0)
		return -EIO;

	return 0;
}

int mainloop_remove_timeout(int id)
{
	if (id >= IDLE_ID_BASE) {
		struct idle_data *idle = find_idle(id);

		if (!idle)
			return -ENOENT;

		/* Freed after the current pass, which may be running it */
		idle->removed = true;
		return 0;
	}

	return mainloop_remove_fd(id);
}
