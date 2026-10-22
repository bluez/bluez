// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Intel Corporation
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>

#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/mainloop.h"
#include "src/shared/timeout.h"
#include "tools/tester-io.h"

/* Watch ids have the high bit set, so tester_remove_source() can tell them
 * from timeout ids.
 */
#define WATCH_ID_BIT	0x80000000u

struct tester_io {
	int ref_count;
	int fd;
	bool close_on_unref;
	bool registered;
	bool dispatching;
	bool scheduled;
	unsigned int backoff_id;
	uint32_t pending;
	struct queue *watches;
};

struct watch {
	unsigned int id;
	struct tester_io *io;
	uint32_t cond;
	tester_io_func_t func;
	void *user_data;
	bool removed;
};

/* The tester_io with watches, in the order of their first watch */
static struct queue *ios;
static int dispatch_id;
static unsigned int next_id;
static unsigned int current_id;

struct tester_io *tester_io_new(int fd)
{
	struct tester_io *io;

	io = new0(struct tester_io, 1);
	io->ref_count = 1;
	io->fd = fd;
	io->watches = queue_new();

	return io;
}

struct tester_io *tester_io_ref(struct tester_io *io)
{
	if (io)
		io->ref_count++;

	return io;
}

void tester_io_unref(struct tester_io *io)
{
	if (!io || --io->ref_count > 0)
		return;

	queue_destroy(io->watches, free);

	if (io->close_on_unref && io->fd >= 0)
		close(io->fd);

	free(io);
}

int tester_io_get_fd(struct tester_io *io)
{
	return io ? io->fd : -1;
}

void tester_io_set_close_on_unref(struct tester_io *io, bool close_on_unref)
{
	if (io)
		io->close_on_unref = close_on_unref;
}

static void collect_cond(void *data, void *user_data)
{
	struct watch *watch = data;
	uint32_t *events = user_data;

	if (!watch->removed)
		*events |= watch->cond;
}

static void io_event(int fd, uint32_t events, void *user_data);

static bool match_registered_fd(const void *data, const void *match_data)
{
	const struct tester_io *io = data;

	return io->registered && io->fd == PTR_TO_INT(match_data);
}

static void unregister(struct tester_io *io)
{
	if (!io->registered)
		return;

	io->registered = false;
	mainloop_remove_fd(io->fd);
}

/* Poll for what the watches want, except while their callbacks are
 * pending, and stop polling without any.
 */
static void update_events(struct tester_io *io)
{
	uint32_t events = 0;

	queue_foreach(io->watches, collect_cond, &events);
	events &= ~TESTER_IO_NVAL;

	if (queue_isempty(io->watches) || io->scheduled || io->backoff_id ||
								io->fd < 0) {
		unregister(io);
		return;
	}

	if (!io->registered) {
		if (mainloop_add_fd(io->fd, events, io_event, io, NULL) < 0) {
			struct tester_io *stale;

			/* The descriptor of another io was closed directly,
			 * and the same number was given to this one.
			 */
			stale = queue_find(ios, match_registered_fd,
							INT_TO_PTR(io->fd));
			if (!stale || stale == io)
				return;

			unregister(stale);

			if (mainloop_add_fd(io->fd, events, io_event, io,
								NULL) < 0)
				return;
		}

		io->registered = true;
		return;
	}

	mainloop_modify_fd(io->fd, events);
}

static bool match_removed(const void *data, const void *match_data)
{
	const struct watch *watch = data;

	return watch->removed;
}

/* Drops the removed watches and their references to io. The caller holds
 * a reference of its own, so io is freed by the caller's unref at most.
 */
static void cleanup(struct tester_io *io)
{
	struct watch *watch;

	while ((watch = queue_remove_if(io->watches, match_removed, NULL))) {
		free(watch);
		io->ref_count--;
	}

	if (queue_isempty(io->watches)) {
		io->scheduled = false;
		io->pending = 0;
		timeout_remove(io->backoff_id);
		io->backoff_id = 0;
		queue_remove(ios, io);
	}

	update_events(io);
}

static bool backoff_done(void *user_data)
{
	struct tester_io *io = user_data;

	io->backoff_id = 0;
	update_events(io);

	return false;
}

static void remove_watch(void *data, void *user_data)
{
	struct watch *watch = data;

	watch->removed = true;
}

static void dispatch(struct tester_io *io)
{
	const struct queue_entry *entry;
	unsigned int last = next_id;
	uint32_t events = io->pending;
	uint32_t wanted = 0;

	io->scheduled = false;
	io->pending = 0;

	tester_io_ref(io);
	io->dispatching = true;

	queue_foreach(io->watches, collect_cond, &wanted);

	/* Watches added by a callback wait for the next event */
	for (entry = queue_get_entries(io->watches); entry;
							entry = entry->next) {
		struct watch *watch = entry->data;

		if (watch->removed || (watch->id & ~WATCH_ID_BIT) > last ||
						!(events & watch->cond))
			continue;

		current_id = watch->id;

		if (!watch->func(io, events & watch->cond, watch->user_data))
			watch->removed = true;

		current_id = 0;
	}

	/* A hang up nobody watches for would be reported over and over,
	 * waking up the mainloop for good: drop the watches instead, as with
	 * a closed descriptor. An error may be transient, e.g. a connection
	 * attempt timing out, so keep watching after one, as GLib does.
	 */
	if (events & (TESTER_IO_HUP | TESTER_IO_NVAL) & ~wanted)
		queue_foreach(io->watches, remove_watch, NULL);
	else if (events & TESTER_IO_ERR & ~wanted && !io->backoff_id)
		/* Polling would report the error right away again, so look
		 * again a bit later, which lets simulated time advance too.
		 */
		io->backoff_id = timeout_add(1, backoff_done, io, NULL);

	if (io->fd < 0)
		queue_foreach(io->watches, remove_watch, NULL);

	io->dispatching = false;
	cleanup(io);
	tester_io_unref(io);
}

static bool match_scheduled(const void *data, const void *match_data)
{
	const struct tester_io *io = data;

	return io->scheduled;
}

static void dispatch_all(int id, void *user_data)
{
	struct tester_io *io;

	mainloop_remove_timeout(id);
	dispatch_id = 0;

	while ((io = queue_find(ios, match_scheduled, NULL)))
		dispatch(io);
}

/* Like GLib, which dispatches the ready sources in the order they were
 * added, call the watches after the other descriptors ready at the same
 * time, e.g. those of the emulated controllers, were handled, in the order
 * of the first watch of each descriptor, and before idle callbacks: stop
 * polling and dispatch once the ready descriptors were handled.
 */
static void schedule_dispatch(struct tester_io *io, uint32_t events)
{
	io->pending |= events;

	if (io->scheduled)
		return;

	io->scheduled = true;
	unregister(io);

	if (!dispatch_id)
		dispatch_id = mainloop_add_deferred(dispatch_all, NULL, NULL);
}

static void io_event(int fd, uint32_t events, void *user_data)
{
	struct tester_io *io = user_data;

	schedule_dispatch(io, events);
}

unsigned int tester_io_add_watch(struct tester_io *io, uint32_t cond,
				tester_io_func_t func, void *user_data)
{
	struct watch *watch;

	if (!io || !func)
		return 0;

	if (!ios)
		ios = queue_new();

	watch = new0(struct watch, 1);
	watch->id = ++next_id | WATCH_ID_BIT;
	watch->io = tester_io_ref(io);
	watch->cond = cond;
	watch->func = func;
	watch->user_data = user_data;

	if (queue_isempty(io->watches))
		queue_push_tail(ios, io);

	queue_push_tail(io->watches, watch);
	update_events(io);

	return watch->id;
}

void tester_io_close(struct tester_io *io)
{
	if (!io || io->fd < 0)
		return;

	unregister(io);
	close(io->fd);
	io->fd = -1;

	if (!queue_isempty(io->watches))
		schedule_dispatch(io, TESTER_IO_NVAL);
}

static bool match_watch_id(const void *data, const void *match_data)
{
	const struct watch *watch = data;

	return watch->id == PTR_TO_UINT(match_data) && !watch->removed;
}

static bool match_io_watch(const void *data, const void *match_data)
{
	const struct tester_io *io = data;

	return queue_find(io->watches, match_watch_id, match_data);
}

unsigned int tester_current_source(void)
{
	return current_id;
}

void tester_remove_source(unsigned int id)
{
	struct tester_io *io;
	struct watch *watch;

	if (!id)
		return;

	if (!(id & WATCH_ID_BIT)) {
		timeout_remove(id);
		return;
	}

	io = queue_find(ios, match_io_watch, UINT_TO_PTR(id));
	if (!io)
		return;

	watch = queue_find(io->watches, match_watch_id, UINT_TO_PTR(id));
	watch->removed = true;

	/* Cleaned up once the callbacks are done */
	if (io->dispatching)
		return;

	tester_io_ref(io);
	cleanup(io);
	tester_io_unref(io);
}
