#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <limits.h>
#include <sys/time.h>
#include <time.h>

#include "glib-ectomy.h"
#include "list.h"

GIOError g_io_channel_read(GIOChannel *channel, gchar *buf, gsize count, gsize *bytes_read)
{
	int fd = channel->fd;
	gssize result;

	/* At least according to the Debian manpage for read */
	if (count > SSIZE_MAX)
		count = SSIZE_MAX;

retry:
	result = read (fd, buf, count);

	if (result < 0) {
		*bytes_read = 0;

		switch (errno) {
#ifdef EINTR
		case EINTR:
			goto retry;
#endif
#ifdef EAGAIN
		case EAGAIN:
			return G_IO_STATUS_AGAIN;
#endif
		default:
			return G_IO_STATUS_ERROR;
		}
	}

	*bytes_read = result;

	return (result > 0) ? G_IO_STATUS_NORMAL : G_IO_STATUS_EOF;
}

void g_io_channel_close(GIOChannel *channel)
{
	if (!channel)
		return;

	close(channel->fd);

	memset(channel, 0, sizeof(channel));
	free(channel);
}

GIOChannel *g_io_channel_unix_new(int fd)
{
	GIOChannel *channel;

	channel = malloc(sizeof(GIOChannel));
	if (!channel)
		return NULL;

	channel->fd = fd;

	return channel;
}

gint g_io_channel_unix_get_fd(GIOChannel *channel)
{
	return channel->fd;
}

struct watch {
	guint id;
	GIOChannel *channel;
	gint priority;
	GIOCondition condition;
	short *revents;
	GIOFunc func;
	gpointer user_data;
	GDestroyNotify destroy;

	struct watch *prev;
	struct watch *next;
};

static struct watch watch_head = { .id = 0, .prev = 0, .next = 0, .revents = 0 };

static GMainContext *default_context = NULL;

static void watch_remove(struct watch *w)
{
	struct watch *p, *n;

	if (!w)
		return;

	p = w->prev;
	n = w->next;

	if (p)
		p->next = n;

	if (n)
		n->prev = p;

	free(w);
}

void g_io_remove_watch(guint id)
{
	struct watch *w, *n;

	for (w = watch_head.next; w; w = n) {
		n = w->next;
		if (w->id != id)
			continue;

		watch_remove(w);
		return;
	}
}

guint g_io_add_watch_full(GIOChannel *channel, gint priority,
				GIOCondition condition, GIOFunc func,
				gpointer user_data, GDestroyNotify notify)
{
	struct watch *watch = malloc(sizeof(struct watch));

	watch->id = ++watch_head.id;
	watch->channel = channel;
	watch->priority = priority;
	watch->condition = condition;
	watch->func = func;
	watch->user_data = user_data;
	watch->destroy = notify;

	watch->prev = &watch_head;
	watch->next = watch_head.next;
	if (watch_head.next)
		watch_head.next->prev = watch;

	watch_head.next = watch;

	return watch->id;
}

guint g_io_add_watch(GIOChannel *channel, GIOCondition condition,
					GIOFunc func, gpointer user_data)
{
	return g_io_add_watch_full(channel, 0, condition,
						func, user_data, NULL);
}

static void timeout_free(void *data, void *user_data)
{
	struct timeout *t = data;

	if (t)
		free (t);
}

static GMainContext *g_main_context_default()
{
	if (default_context)
		return default_context;

	default_context = malloc(sizeof(GMainContext));
	if (!default_context)
		return NULL;

	memset(default_context, 0, sizeof(GMainContext));

	default_context->timeout = -1;

	return default_context;
}

GMainLoop *g_main_loop_new(GMainContext *context, gboolean is_running)
{
	GMainLoop *ml;

	ml = malloc(sizeof(GMainLoop));
	if (!ml)
		return NULL;

	memset(ml, 0, sizeof(GMainLoop));

	if (!context)
		ml->context = g_main_context_default();
	else
		ml->context = context;

	ml->bail = 0;

	return ml;
}

static void timeout_handlers_prepare(GMainContext *context)
{
	struct slist *l = context->ltimeout;
	struct timeout *t;
	struct timeval tv;
	glong msec, timeout = LONG_MAX;

	gettimeofday(&tv, NULL);

	while (l) {
		t = l->data;
		l = l->next;

		/* calculate the remainning time */
		msec = (t->expiration.tv_sec - tv.tv_sec) * 1000 +
				(t->expiration.tv_usec - tv.tv_usec) / 1000;
		if (msec < 0)
			msec = 0;

		timeout = MIN_TIMEOUT(timeout, msec);
	}

	/* set to min value found or NO timeout */
	context->timeout = (timeout != LONG_MAX ? timeout: -1);
}

static int timeout_cmp(const void *t1, const void *t2)
{
	return t1-t2;
}

static void timeout_handlers_check(GMainContext *context)
{
	struct slist *l = context->ltimeout;
	struct timeout *t;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	while (l) {
		t = l->data;
		l = l->next;

		if ((tv.tv_sec < t->expiration.tv_sec) ||
			(tv.tv_sec == t->expiration.tv_sec &&
			 tv.tv_usec < t->expiration.tv_usec))
			continue;

		if (t->function(t->data)) {
			struct slist *match;
			/* if false/expired: remove it from the list
			 * Before remove check again in order to cover the situation
			 * when the handler is removed/freed by the callback function
			 */
			match = slist_find(context->ltimeout, t, timeout_cmp);
			if (match) {
				t = match->data;
				context->ltimeout = slist_remove(context->ltimeout, t);
				free(t);
			}
		} else {
			glong secs, msecs;
			/* update the next expiration time */
			secs = t->interval / 1000;
			msecs = t->interval - secs * 1000;

			t->expiration.tv_sec = tv.tv_sec + secs;
			t->expiration.tv_usec = tv.tv_usec + msecs * 1000;
			if (t->expiration.tv_usec >= 1000000) {
				t->expiration.tv_usec -= 1000000;
				t->expiration.tv_sec++;
			}
		}
	}
}

void g_main_loop_run(GMainLoop *loop)
{
	int open_max = sysconf(_SC_OPEN_MAX);
	struct pollfd *ufds;

	ufds = malloc(open_max * sizeof(struct pollfd));
	if (!ufds)
		return;

	while (!loop->bail) {
		int nfds, rc;
		struct watch *n, *w;

		nfds = 0;
		for (w = watch_head.next; w != NULL; w = w->next) {
			ufds[nfds].fd = w->channel->fd;
			ufds[nfds].events = w->condition;
			ufds[nfds].revents = 0;
			w->revents = &ufds[nfds].revents;
			nfds++;
		}

		/* calculate the next timeout */
		timeout_handlers_prepare(loop->context);

		rc = poll(ufds, nfds, loop->context->timeout);
		if (rc < 0)
			continue;

		w = watch_head.next;
		while (w) {
			if (!*w->revents || w->func(w->channel, *w->revents, w->user_data)) {
				w = w->next;
				continue;
			}

			n = w->next;

			if (w->destroy)
				w->destroy(w->user_data);
			watch_remove(w);

			w = n;
		}

		/* check expired timers */
		timeout_handlers_check(loop->context);
	}

	free(ufds);
}

void g_main_loop_quit(GMainLoop *loop)
{
	struct watch *w;

	loop->bail = 1;

	for (w = watch_head.next; w; w = w->next) {
		if (w->destroy)
			w->destroy(w->user_data);
		watch_head.next = w->next;
		free(w);
	}
}

void g_main_loop_unref(GMainLoop *loop)
{
	if (!loop->context)
		return;

	slist_foreach(loop->context->ltimeout, timeout_free, NULL);
	slist_free(loop->context->ltimeout);
	free(loop->context);
}

guint g_timeout_add(guint interval, GSourceFunc function, gpointer data)
{
	struct timeval tv;
	guint secs;
	guint msecs;
	struct timeout *t;

	if (!default_context || !function)
		return 0;

	t = malloc(sizeof(*t));

	if (!t)
		return 0;

	t->interval = interval;
	t->function = function;
	t->data = data;

	gettimeofday(&tv, NULL);

	secs = interval /1000;
	msecs = interval - secs * 1000;

	t->expiration.tv_sec = tv.tv_sec + secs;
	t->expiration.tv_usec = tv.tv_usec + msecs * 1000;

	if (t->expiration.tv_usec >= 1000000) {
		t->expiration.tv_usec -= 1000000;
		t->expiration.tv_sec++;
	}

	/* attach the timeout the default context */
	t->id = ++default_context->next_id;
	default_context->ltimeout = slist_append(default_context->ltimeout, t);

	return t->id;
}

gint g_timeout_remove(const guint id)
{
	struct slist *l;
	struct timeout *t;

	if (!default_context)
		return -1;

	l = default_context->ltimeout;

	while (l) {
		t = l->data;
		l = l->next;

		if (t->id != id)
			continue;

		default_context->ltimeout = slist_remove(default_context->ltimeout, t);
		free(t);

		return 0;
	}

	return -1;
}
