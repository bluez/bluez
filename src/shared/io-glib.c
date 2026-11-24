// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <sys/socket.h>

#include <glib.h>

#include "src/shared/io.h"

#define	IO_ERR_WATCH_RATELIMIT		(500 * G_TIME_SPAN_MILLISECOND)

struct io_watch {
	struct io *io;
	guint id;
	io_callback_func_t callback;
	io_destroy_func_t destroy;
	void *user_data;
};

struct io {
	int ref_count;
	GIOChannel *channel;
	bool err_watch;
	struct io_watch *read_watch;
	struct io_watch *write_watch;
	struct io_watch *disconnect_watch;
};

struct io_err_watch {
	GSource			source;
	GIOChannel		*io;
	GIOCondition		events;
	gpointer		tag;
};

static guint io_glib_add_err_watch_full(GIOChannel *io, gint priority,
					GIOCondition events,
					GIOFunc func, gpointer user_data,
					GDestroyNotify notify);

static struct io *io_ref(struct io *io)
{
	if (!io)
		return NULL;

	__sync_fetch_and_add(&io->ref_count, 1);

	return io;
}

static void io_unref(struct io *io)
{
	if (!io)
		return;

	if (__sync_sub_and_fetch(&io->ref_count, 1))
		return;

	g_free(io);
}

struct io *io_new(int fd)
{
	struct io *io;

	if (fd < 0)
		return NULL;

	io = g_try_new0(struct io, 1);
	if (!io)
		return NULL;

	io->channel = g_io_channel_unix_new(fd);

	g_io_channel_set_encoding(io->channel, NULL, NULL);
	g_io_channel_set_buffered(io->channel, FALSE);

	g_io_channel_set_close_on_unref(io->channel, FALSE);

	return io_ref(io);
}

static void watch_destroy(void *user_data)
{
	struct io_watch *watch = user_data;
	struct io *io = watch->io;

	if (watch == io->read_watch)
		io->read_watch = NULL;
	else if (watch == io->write_watch)
		io->write_watch = NULL;
	else if (watch == io->disconnect_watch)
		io->disconnect_watch = NULL;

	if (watch->destroy)
		watch->destroy(watch->user_data);

	io_unref(watch->io);
	g_free(watch);
}

void io_destroy(struct io *io)
{
	if (!io)
		return;

	if (io->read_watch) {
		g_source_remove(io->read_watch->id);
		io->read_watch = NULL;
	}

	if (io->write_watch) {
		g_source_remove(io->write_watch->id);
		io->write_watch = NULL;
	}

	if (io->disconnect_watch) {
		g_source_remove(io->disconnect_watch->id);
		io->disconnect_watch = NULL;
	}

	g_io_channel_unref(io->channel);
	io->channel = NULL;

	io_unref(io);
}

int io_get_fd(struct io *io)
{
	if (!io)
		return -ENOTCONN;

	return g_io_channel_unix_get_fd(io->channel);
}

bool io_set_close_on_destroy(struct io *io, bool do_close)
{
	if (!io)
		return false;

	if (do_close)
		g_io_channel_set_close_on_unref(io->channel, TRUE);
	else
		g_io_channel_set_close_on_unref(io->channel, FALSE);

	return true;
}

static gboolean watch_callback(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct io_watch *watch = user_data;
	bool result, destroy;

	destroy = watch == watch->io->disconnect_watch;

	if (!destroy && (cond & (G_IO_ERR | G_IO_NVAL)))
		return FALSE;

	if (watch->callback)
		result = watch->callback(watch->io, watch->user_data);
	else
		result = false;

	return result ? TRUE : FALSE;
}

static struct io_watch *watch_new(struct io *io, GIOCondition cond,
				io_callback_func_t callback, void *user_data,
				io_destroy_func_t destroy)
{
	struct io_watch *watch;
	int prio;

	watch = g_try_new0(struct io_watch, 1);
	if (!watch)
		return NULL;

	watch->io = io_ref(io);
	watch->callback = callback;
	watch->destroy = destroy;
	watch->user_data = user_data;

	prio = cond == G_IO_HUP ? G_PRIORITY_DEFAULT_IDLE : G_PRIORITY_DEFAULT;

	if (!io->err_watch)
		watch->id = g_io_add_watch_full(io->channel, prio,
						cond | G_IO_ERR | G_IO_NVAL,
						watch_callback, watch,
						watch_destroy);
	else
		watch->id = io_glib_add_err_watch_full(io->channel, prio,
						cond | G_IO_ERR | G_IO_NVAL,
						watch_callback, watch,
						watch_destroy);

	if (watch->id == 0) {
		watch_destroy(watch);
		return NULL;
	}

	return watch;
}

static bool io_set_handler(struct io *io, GIOCondition cond,
				io_callback_func_t callback, void *user_data,
				io_destroy_func_t destroy)
{
	struct io_watch **watch;

	if (!io)
		return false;

	switch (cond) {
	case G_IO_IN:
		watch = &io->read_watch;
		break;
	case G_IO_OUT:
		watch = &io->write_watch;
		break;
	case G_IO_HUP:
		watch = &io->disconnect_watch;
		break;
	case G_IO_PRI:
	case G_IO_ERR:
	case G_IO_NVAL:
	default:
		return false;
	}

	if (*watch) {
		g_source_remove((*watch)->id);
		*watch = NULL;
	}

	if (!callback)
		return true;

	*watch = watch_new(io, cond, callback, user_data, destroy);
	if (!*watch)
		return false;

	return true;
}

bool io_set_read_handler(struct io *io, io_callback_func_t callback,
				void *user_data, io_destroy_func_t destroy)
{
	return io_set_handler(io, G_IO_IN, callback, user_data, destroy);
}

bool io_set_write_handler(struct io *io, io_callback_func_t callback,
				void *user_data, io_destroy_func_t destroy)
{
	return io_set_handler(io, G_IO_OUT, callback, user_data, destroy);
}

bool io_set_disconnect_handler(struct io *io, io_callback_func_t callback,
				void *user_data, io_destroy_func_t destroy)
{
	return io_set_handler(io, G_IO_HUP, callback, user_data, destroy);
}

bool io_set_ignore_errqueue(struct io *io, bool do_ignore)
{
	if (!io)
		return false;

	io->err_watch = do_ignore;
	return true;
}

ssize_t io_send(struct io *io, const struct iovec *iov, int iovcnt)
{
	int fd;
	ssize_t ret;

	if (!io || !io->channel)
		return -ENOTCONN;

	fd = io_get_fd(io);

	do {
		ret = writev(fd, iov, iovcnt);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		return -errno;

	return ret;
}

bool io_shutdown(struct io *io)
{
	if (!io || !io->channel)
		return false;

	return g_io_channel_shutdown(io->channel, TRUE, NULL)
							== G_IO_STATUS_NORMAL;
}

/*
 * GSource implementation that tolerates non-empty MSG_ERRQUEUE, without
 * attempting to flush it. This is intended for use with TX timestamping in
 * cases where someone else is reading the timestamps and we are only interested
 * in POLLHUP or socket errors.
 */

static gint64 io_err_watch_wakeup;

static gboolean io_err_watch_dispatch(GSource *source,
				GSourceFunc callback, gpointer user_data)
{
	struct io_err_watch *watch = (void *)source;
	const GIOFunc func = (void *)callback;
	const gint64 timeout = IO_ERR_WATCH_RATELIMIT;
	GIOCondition cond;
	int fd;

	if (!func)
		return FALSE;

	fd = g_io_channel_unix_get_fd(watch->io);

	/*
	 * If woken up by POLLERR only, and SO_ERROR is not set, ignore this
	 * event. Also disable polling for some time so that we don't consume
	 * too much CPU on events we are not interested in, or busy loop if
	 * nobody is flushing the errqueue.
	 */

	if (watch->tag)
		cond = g_source_query_unix_fd(&watch->source, watch->tag);
	else
		cond = 0;

	if (cond == G_IO_ERR) {
		int err, ret;
		socklen_t len = sizeof(err);

		ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
		if (ret == 0 && err == 0) {
			g_source_remove_unix_fd(&watch->source, watch->tag);
			watch->tag = NULL;

			/* io_err watches all wake up at the same time */
			if (!io_err_watch_wakeup)
				io_err_watch_wakeup = g_get_monotonic_time()
								+ timeout;

			g_source_set_ready_time(&watch->source,
							io_err_watch_wakeup);
			return TRUE;
		}
	}

	if (g_source_get_ready_time(&watch->source) != -1) {
		g_assert(!watch->tag);
		io_err_watch_wakeup = 0;
		watch->tag = g_source_add_unix_fd(&watch->source, fd,
							watch->events);
		g_source_set_ready_time(&watch->source, -1);
	}

	cond &= watch->events;

	if (cond)
		return func(watch->io, cond, user_data);
	else
		return TRUE;
}

static void io_err_watch_finalize(GSource *source)
{
	struct io_err_watch *watch = (void *)source;

	if (watch->tag)
		g_source_remove_unix_fd(&watch->source, watch->tag);

	g_io_channel_unref(watch->io);
}

static guint io_glib_add_err_watch_full(GIOChannel *io, gint priority,
					GIOCondition events,
					GIOFunc func, gpointer user_data,
					GDestroyNotify notify)
{
	static GSourceFuncs source_funcs = {
		.dispatch = io_err_watch_dispatch,
		.finalize = io_err_watch_finalize,
	};
	GSourceFunc callback = (void *)func;
	struct io_err_watch *watch;
	gint fd;
	guint id;

	g_return_val_if_fail(!(events & (G_IO_IN | G_IO_OUT)), 0);
	g_return_val_if_fail(events, 0);
	g_return_val_if_fail(func, 0);

	fd = g_io_channel_unix_get_fd(io);

	watch = (void *)g_source_new(&source_funcs,
					sizeof(struct io_err_watch));

	watch->io = g_io_channel_ref(io);
	watch->events = events;
	watch->tag = g_source_add_unix_fd(&watch->source, fd, events);

	g_source_set_name((void *)watch, "io_glib_err_watch");
	g_source_set_callback(&watch->source, callback, user_data, notify);

	if (priority != G_PRIORITY_DEFAULT)
		g_source_set_priority(&watch->source, priority);

	id = g_source_attach(&watch->source, NULL);
	g_source_unref(&watch->source);

	return id;
}

struct err_watch_cb_data {
	io_glib_err_func_t func;
	void *data;
};

static gboolean err_watch_callback(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct err_watch_cb_data *data = user_data;

	data->func(cond, data->data);
	return FALSE;
}

unsigned int io_glib_add_err_watch(void *giochannel,
						io_glib_err_func_t func,
						void *user_data)
{
	struct err_watch_cb_data *data;

	data = g_try_new0(struct err_watch_cb_data, 1);
	if (!data)
		return 0;

	data->func = func;
	data->data = user_data;
	return io_glib_add_err_watch_full(giochannel, G_PRIORITY_DEFAULT,
					G_IO_ERR | G_IO_HUP | G_IO_NVAL,
					err_watch_callback, data, g_free);
}
