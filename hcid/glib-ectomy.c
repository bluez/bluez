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

#include "glib-ectomy.h"

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
	GIOCondition condition;
	GIOFunc func;
	gpointer user_data;

	struct watch *next;
};

static struct watch watch_head = { .id = 0, .next = 0 };

void g_io_remove_watch(guint id)
{
	struct watch *w, *p;

	for (p = &watch_head, w = watch_head.next; w; w = w->next)
		if (w->id == id) {
			p->next = w->next;
			free (w);
			return;
		}
}

guint g_io_add_watch(GIOChannel *channel, GIOCondition condition, GIOFunc func, gpointer user_data)
{
	struct watch *watch = malloc(sizeof(struct watch));

	watch->id = ++watch_head.id;
	watch->channel = channel;
	watch->condition = condition;
	watch->func = func;
	watch->user_data = user_data;

	watch->next = watch_head.next;
	watch_head.next = watch;

	return watch->id;
}

GMainLoop *g_main_loop_new(GMainContext *context, gboolean is_running)
{
	GMainLoop *ml;

	ml = malloc(sizeof(GMainLoop));
	if (!ml)
		return NULL;

	ml->bail = 0;

	return ml;
}

void g_main_loop_run(GMainLoop *loop)
{
	int open_max = sysconf(_SC_OPEN_MAX);
	struct pollfd *ufds;

	ufds = malloc(open_max * sizeof(struct pollfd));
	if (!ufds)
		return;

	while (!loop->bail) {
		int nfds, rc, i;
		struct watch *p, *w;

		nfds = 0;
		for (w = watch_head.next; w != NULL; w = w->next) {
			ufds[nfds].fd = w->channel->fd;
			ufds[nfds].events = w->condition;
			ufds[nfds].revents = 0;
			nfds++;
		}

		rc = poll(ufds, nfds, -1);
		if (rc < 0)
			continue;

		p = &watch_head;
		w = watch_head.next;
		i = 0;

		while (w) {
			if (ufds[i].revents) {
				gboolean keep = w->func(w->channel, ufds[i].revents, w->user_data);
				if (!keep) {
					p->next = w->next;
					memset(w, 0, sizeof(*w));
					w = p->next;
					i++;
					continue;
				}
			}

			p = w;
			w = w->next;
			i++;
		}
	}

	free(ufds);
}

void g_main_loop_quit(GMainLoop *loop)
{
	loop->bail = 1;
}
