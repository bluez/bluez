#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <ctype.h>
#include <dlfcn.h>
#include <dirent.h>
#include <signal.h>

#include <gmain.h>

struct timeout {
	guint id;
	guint interval;
	struct timeval expiration;
	gpointer data;
	GSourceFunc function;
};

struct _GIOChannel {
	int fd;
	int ref_count;
	gboolean closed;
	gboolean close_on_unref;
};

struct child_watch {
	guint id;
	GPid pid;
	GChildWatchFunc function;
	gpointer user_data;
};

struct _GMainContext {
	guint next_id;
	glong next_timeout;

	GSList *timeouts;
	GSList *proc_timeouts;
	gboolean timeout_lock;

	GSList *io_watches;
	GSList *proc_io_watches;
	gboolean io_lock;

	GSList *child_watches;
	GSList *proc_child_watches;
	gboolean child_lock;
};

struct _GMainLoop {
	gboolean is_running;
	GMainContext *context;
};

struct _GDir
{
	DIR *dirp;
};

GIOError g_io_channel_read(GIOChannel *channel, gchar *buf, gsize count,
				gsize *bytes_read)
{
	int fd = channel->fd;
	gssize result;

	if (channel->closed)
		return G_IO_STATUS_ERROR;

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

GIOError g_io_channel_write(GIOChannel *channel, const gchar *buf, gsize count,
				gsize *bytes_written)
{
	int fd = channel->fd;
	gssize result;

	if (channel->closed)
		return G_IO_STATUS_ERROR;

	/* At least according to the Debian manpage for read */
	if (count > SSIZE_MAX)
		count = SSIZE_MAX;

retry:
	result = write(fd, buf, count);

	if (result < 0) {
		*bytes_written = 0;

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

	*bytes_written = result;

	return (result > 0) ? G_IO_STATUS_NORMAL : G_IO_STATUS_EOF;
}

void g_io_channel_close(GIOChannel *channel)
{
	if (!channel || channel->closed)
		return;

	close(channel->fd);

	channel->closed = TRUE;
}

void g_io_channel_unref(GIOChannel *channel)
{
	if (!channel)
		return;

	if (--channel->ref_count > 0)
		return;

	if (channel->close_on_unref && channel->fd >= 0)
		g_io_channel_close(channel);

	g_free(channel);
}

GIOChannel *g_io_channel_ref(GIOChannel *channel)
{
	channel->ref_count++;
	return channel;
}

GIOChannel *g_io_channel_unix_new(int fd)
{
	GIOChannel *channel;

	channel = g_new0(GIOChannel, 1);

	channel->fd = fd;
	channel->ref_count = 1;

	return channel;
}

void g_io_channel_set_close_on_unref(GIOChannel *channel, gboolean do_close)
{
	channel->close_on_unref = do_close;
}

gint g_io_channel_unix_get_fd(GIOChannel *channel)
{
	if (channel->closed)
		return -1;

	return channel->fd;
}

static int set_flags(int fd, long flags)
{
	long arg;

	arg = fcntl(fd, F_GETFL);
	if (arg < 0)
		return -errno;

	/* Return if already set */
	if ((arg & flags) == flags)
		return 0;

	arg |= flags;
	if (fcntl(fd, F_SETFL, arg) < 0)
		return -errno;

	return 0;
}

GIOStatus g_io_channel_set_flags(GIOChannel *channel, GIOFlags flags,
				GError **error)
{
	int err, fd;
	long fd_flags = 0;

	if (!channel || channel->closed)
		return G_IO_STATUS_ERROR;

	fd = g_io_channel_unix_get_fd(channel);

	if (flags & G_IO_FLAG_APPEND)
		fd_flags |= O_APPEND;
	if (flags & G_IO_FLAG_NONBLOCK)
		fd_flags |= O_NONBLOCK;

	err = set_flags(fd, fd_flags);
	if (err < 0) {
		if (error)
			g_set_error(error, 0, 0, "Unable to set flags: %s",
					strerror(-err));
		return G_IO_STATUS_ERROR;
	}

	return G_IO_STATUS_NORMAL;
}

struct io_watch {
	guint id;
	GIOChannel *channel;
	gint priority;
	GIOCondition condition;
	short *revents;
	GIOFunc func;
	gpointer user_data;
	GDestroyNotify destroy;
};

static GMainContext *default_context = NULL;

static void watch_free(struct io_watch *watch)
{
	if (watch->destroy)
		watch->destroy(watch->user_data);
	g_io_channel_unref(watch->channel);
	g_free(watch);
}

static GMainContext *g_main_context_default()
{
	if (default_context)
		return default_context;

	default_context = g_new0(GMainContext, 1);

	default_context->next_timeout = -1;
	default_context->next_id = 1;

	return default_context;
}

static gboolean g_io_remove_watch(GMainContext *context, guint id)
{
	GSList *l;
	struct io_watch *w;

	for (l = context->io_watches; l != NULL; l = l->next) {
		w = l->data;

		if (w->id != id)
			continue;

		context->io_watches = g_slist_remove(context->io_watches, w);
		watch_free(w);

		return TRUE;
	}

	for (l = context->proc_io_watches; l != NULL; l = l->next) {
		w = l->data;

		if (w->id != id)
			continue;

		context->proc_io_watches = g_slist_remove(context->proc_io_watches, w);
		watch_free(w);

		return TRUE;
	}

	return FALSE;
}

static gboolean g_timeout_remove(GMainContext *context, const guint id)
{
	GSList *l;
	struct timeout *t;

	l = context->timeouts;

	while (l) {
		t = l->data;
		l = l->next;

		if (t->id != id)
			continue;

		context->timeouts = g_slist_remove(context->timeouts, t);
		g_free(t);

		return TRUE;
	}

	l = context->proc_timeouts;

	while (l) {
		t = l->data;
		l = l->next;

		if (t->id != id)
			continue;

		context->proc_timeouts = g_slist_remove(context->proc_timeouts, t);
		g_free(t);

		return TRUE;
	}

	return FALSE;
}

int watch_prio_cmp(struct io_watch *w1, struct io_watch *w2)
{
	return w1->priority - w2->priority;
}

#define watch_list_add(l, w) g_slist_insert_sorted((l), (w), (GCompareFunc) watch_prio_cmp)

guint g_io_add_watch_full(GIOChannel *channel, gint priority,
				GIOCondition condition, GIOFunc func,
				gpointer user_data, GDestroyNotify notify)
{
	struct io_watch *watch;
	GMainContext *context = g_main_context_default();

	watch = g_new(struct io_watch, 1);

	watch->id = context->next_id++;
	watch->channel = g_io_channel_ref(channel);
	watch->priority = priority;
	watch->condition = condition;
	watch->func = func;
	watch->user_data = user_data;
	watch->destroy = notify;

	if (context->io_lock)
		context->proc_io_watches = watch_list_add(context->proc_io_watches, watch);
	else
		context->io_watches = watch_list_add(context->io_watches, watch);

	return watch->id;
}

guint g_io_add_watch(GIOChannel *channel, GIOCondition condition,
					GIOFunc func, gpointer user_data)
{
	return g_io_add_watch_full(channel, 0, condition,
						func, user_data, NULL);
}

GMainLoop *g_main_loop_new(GMainContext *context, gboolean is_running)
{
	GMainLoop *ml;

	if (!context)
		context = g_main_context_default();

	ml = g_new0(GMainLoop, 1);

	ml->context = context;
	ml->is_running = is_running;

	return ml;
}

static void timeout_handlers_prepare(GMainContext *context)
{
	GSList *l;
	struct timeval tv;
	glong msec, timeout = LONG_MAX;

	gettimeofday(&tv, NULL);

	for (l = context->timeouts; l != NULL; l = l->next) {
		struct timeout *t = l->data;

		/* calculate the remainning time */
		msec = (t->expiration.tv_sec - tv.tv_sec) * 1000 +
				(t->expiration.tv_usec - tv.tv_usec) / 1000;
		if (msec < 0)
			msec = 0;

		timeout = MIN_TIMEOUT(timeout, msec);
	}

	/* set to min value found or NO timeout */
	context->next_timeout = (timeout != LONG_MAX ? timeout : -1);
}

static int ptr_cmp(const void *t1, const void *t2)
{
	return t1 - t2;
}

static void timeout_handlers_check(GMainContext *context)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	context->timeout_lock = TRUE;

	while (context->timeouts) {
		struct timeout *t = context->timeouts->data;
		glong secs, msecs;
		gboolean ret;

		if (timercmp(&tv, &t->expiration, <)) {
			context->timeouts = g_slist_remove(context->timeouts, t);
			context->proc_timeouts = g_slist_append(context->proc_timeouts, t);
			continue;
		}

		ret = t->function(t->data);

		/* Check if the handler was removed/freed by the callback
		 * function */
		if (!g_slist_find_custom(context->timeouts, t, ptr_cmp))
			continue;

		context->timeouts = g_slist_remove(context->timeouts, t);

		if (!ret) {
			g_free(t);
			continue;
		}

		/* update the next expiration time */
		secs = t->interval / 1000;
		msecs = t->interval - secs * 1000;

		t->expiration.tv_sec = tv.tv_sec + secs;
		t->expiration.tv_usec = tv.tv_usec + msecs * 1000;
		if (t->expiration.tv_usec >= 1000000) {
			t->expiration.tv_usec -= 1000000;
			t->expiration.tv_sec++;
		}

		context->proc_timeouts = g_slist_append(context->proc_timeouts, t);
	}

	context->timeouts = context->proc_timeouts;
	context->proc_timeouts = NULL;
	context->timeout_lock = FALSE;
}

void g_main_loop_run(GMainLoop *loop)
{
	int open_max = sysconf(_SC_OPEN_MAX);
	struct pollfd *ufds;
	GMainContext *context = loop->context;

	ufds = g_new(struct pollfd, open_max);

	loop->is_running = TRUE;

	while (loop->is_running) {
		int nfds;
		GSList *l;
		struct io_watch *w;

		for (nfds = 0, l = context->io_watches; l != NULL; l = l->next, nfds++) {
			w = l->data;
			ufds[nfds].fd = w->channel->fd;
			ufds[nfds].events = w->condition;
			ufds[nfds].revents = 0;
			w->revents = &ufds[nfds].revents;
		}

		/* calculate the next timeout */
		timeout_handlers_prepare(context);

		if (poll(ufds, nfds, context->next_timeout) < 0)
			continue;

		context->io_lock = TRUE;

		while (context->io_watches) {
			gboolean ret;

			w = context->io_watches->data;

			if (!*w->revents) {
				context->io_watches = g_slist_remove(context->io_watches, w);
				context->proc_io_watches = watch_list_add(context->proc_io_watches, w);
				continue;
			}

			ret = w->func(w->channel, *w->revents, w->user_data);

			/* Check if the watch was removed/freed by the callback
			 * function */
			if (!g_slist_find_custom(context->io_watches, w, ptr_cmp))
				continue;

			context->io_watches = g_slist_remove(context->io_watches, w);

			if (!ret) {
				watch_free(w);
				continue;
			}

			context->proc_io_watches = watch_list_add(context->proc_io_watches, w);
		}

		context->io_watches = context->proc_io_watches;
		context->proc_io_watches = NULL;
		context->io_lock = FALSE;

		/* check expired timers */
		timeout_handlers_check(loop->context);
	}

	g_free(ufds);
}

void g_main_loop_quit(GMainLoop *loop)
{
	loop->is_running = FALSE;
}

void g_main_loop_unref(GMainLoop *loop)
{
	if (!loop->context)
		return;

	g_slist_foreach(loop->context->io_watches, (GFunc)watch_free, NULL);
	g_slist_free(loop->context->io_watches);

	g_slist_foreach(loop->context->timeouts, (GFunc)g_free, NULL);
	g_slist_free(loop->context->timeouts);

	g_free(loop->context);
	loop->context = NULL;
}

guint g_timeout_add(guint interval, GSourceFunc function, gpointer data)
{
	GMainContext *context = g_main_context_default();
	struct timeval tv;
	guint secs;
	guint msecs;
	struct timeout *t;

	t = g_new0(struct timeout, 1);

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
	t->id = context->next_id++;

	if (context->timeout_lock)
		context->proc_timeouts = g_slist_prepend(context->proc_timeouts, t);
	else
		context->timeouts = g_slist_prepend(context->timeouts, t);

	return t->id;
}

guint g_timeout_add_seconds(guint interval, GSourceFunc function, gpointer data)
{
	return g_timeout_add(interval, function, data);
}

guint g_idle_add(GSourceFunc function, gpointer data)
{
	return g_timeout_add(1, function, data);
}

/* GError */

GError* g_error_new_literal(GQuark domain, gint code, const gchar *message)
{
	GError *err;

	err = g_new(GError, 1);

	err->domain = domain;
	err->code = code;
	err->message = g_strdup(message);

	return err;
}

void g_set_error(GError **err, GQuark domain, gint code,
			const gchar *format, ...)
{
	gchar msg[1024];
	va_list ap;

	if (!err)
		return;

	va_start(ap, format);

	vsnprintf(msg, sizeof(msg) - 1, format, ap);

	va_end(ap);

	*err = g_error_new_literal(domain, code, msg);
}

void g_error_free(GError *err)
{
	g_free(err->message);
	g_free(err);
}

/* Spawning related functions */

static int child_watch_pipe[2] = { -1, -1 };

static void sigchld_handler(int signal)
{
	int ret;
	ret = write(child_watch_pipe[1], "B", 1);
}

static gboolean child_watch_remove(GMainContext *context, guint id)
{
	GSList *l;
	struct child_watch *w;

	for (l = context->child_watches; l != NULL; l = l->next) {
		w = l->data;

		if (w->id != id)
			continue;

		context->child_watches =
			g_slist_remove(context->child_watches, w);
		g_free(w);

		return TRUE;
	}

	for (l = context->proc_child_watches; l != NULL; l = l->next) {
		w = l->data;

		if (w->id != id)
			continue;

		context->proc_child_watches =
			g_slist_remove(context->proc_child_watches, w);
		g_free(w);

		return TRUE;
	}


	return FALSE;
}

static gboolean child_watch(GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	int ret;
	char b[20];
	GMainContext *context = g_main_context_default();

	ret = read(child_watch_pipe[0], b, 20);

	context->child_lock = TRUE;

	while (context->child_watches) {
		gint status;
		struct child_watch *w = context->child_watches->data;

		if (waitpid(w->pid, &status, WNOHANG) <= 0) {
			context->child_watches =
				g_slist_remove(context->child_watches, w);
			context->proc_child_watches =
				watch_list_add(context->proc_child_watches, w);
			continue;
		}

		w->function(w->pid, status, w->user_data);

		/* Check if the callback already removed us */
		if (!g_slist_find(context->child_watches, w))
			continue;

		context->child_watches = g_slist_remove(context->child_watches, w);
		g_free(w);
	}

	context->child_watches = context->proc_child_watches;
	context->proc_child_watches = NULL;
	context->child_lock = FALSE;

	return TRUE;
}

static void init_child_pipe(void)
{
	struct sigaction action;
	GIOChannel *io;

	if (pipe(child_watch_pipe) < 0) {
		fprintf(stderr, "Unable to initialize child watch pipe: %s (%d)\n",
				strerror(errno), errno);
		abort();
	}

	fcntl(child_watch_pipe[1], F_SETFL,
			O_NONBLOCK | fcntl(child_watch_pipe[1], F_GETFL));

	action.sa_handler = sigchld_handler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_NOCLDSTOP;
	sigaction(SIGCHLD, &action, NULL);

	io = g_io_channel_unix_new(child_watch_pipe[0]);
	g_io_add_watch(io, G_IO_IN, child_watch, NULL);
	g_io_channel_unref(io);
}

static void exec_child(const gchar *working_directory,
			gchar **argv, gchar **envp,
			GSpawnFlags flags,
			GSpawnChildSetupFunc child_setup,
			gpointer user_data)
{
	int null;

	if (working_directory && chdir(working_directory) < 0)
		_exit(EXIT_FAILURE);

	if (!(flags & G_SPAWN_LEAVE_DESCRIPTORS_OPEN)) {
		int open_max, fd, ret;

		ret = 0;
		open_max = sysconf(_SC_OPEN_MAX);
		for (fd = 3; fd < open_max && ret == 0; fd++)
			ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
	}

	null = open("/dev/null", O_RDWR);
	if (!(flags & G_SPAWN_CHILD_INHERITS_STDIN))
		dup2(null, STDIN_FILENO);
	if (flags & G_SPAWN_STDOUT_TO_DEV_NULL)
		dup2(null, STDOUT_FILENO);
	if (flags & G_SPAWN_STDERR_TO_DEV_NULL)
		dup2(null, STDERR_FILENO);
	if (null > 2)
		close(null);

	if (child_setup)
		child_setup(user_data);

	if (envp)
		execve(argv[0], argv, envp);
	else
		execv(argv[0], argv);

	/* exec failed if we get here */
	_exit(EXIT_FAILURE);
}

gboolean g_spawn_async(const gchar *working_directory,
			gchar **argv, gchar **envp,
			GSpawnFlags flags,
			GSpawnChildSetupFunc child_setup,
			gpointer user_data,
			GPid *child_pid,
			GError **error)
{
	GPid pid;

	if (access(argv[0], X_OK) < 0) {
		g_set_error(error, 0, 0, "%s is not executable", argv[0]);
		return FALSE;
	}

	if (child_watch_pipe[0] < 0)
		init_child_pipe();

	/* Flush output streams so child doesn't get them */
	fflush(NULL);

	switch (pid = fork()) {
	case -1:
		g_set_error(error, 0, 0, "fork failed: %s", strerror(errno));
		return FALSE;
	case 0:
		exec_child(working_directory, argv, envp, flags,
				child_setup, user_data);
		break;
	default:
		if (child_pid)
			*child_pid = pid;
		return TRUE;
	}

	/* Never reached */
	return FALSE;
}

void g_spawn_close_pid(GPid pid)
{
	return;
}

guint g_child_watch_add(GPid pid, GChildWatchFunc func, gpointer user_data)
{
	struct child_watch *w;
	GMainContext *context = g_main_context_default();

	if (child_watch_pipe[0] < 0)
		init_child_pipe();

	w = g_new(struct child_watch, 1);

	w->id = context->next_id++;
	w->pid = pid;
	w->function = func;
	w->user_data = user_data;

	if (context->child_lock)
		context->proc_child_watches =
			watch_list_add(context->proc_child_watches, w);
	else
		context->child_watches =
			watch_list_add(context->child_watches, w);

	return w->id;
}

gboolean g_source_remove(guint tag)
{
	GMainContext *context = g_main_context_default();

	if (g_io_remove_watch(context, tag))
		return TRUE;

	if (g_timeout_remove(context, tag))
		return TRUE;

	if (child_watch_remove(context, tag))
		return TRUE;

	return FALSE;
}

/* UTF-8 Validation: approximate copy/paste from glib2. */

#define UNICODE_VALID(c)			\
	((c) < 0x110000 &&			\
	(((c) & 0xFFFFF800) != 0xD800) &&	\
	((c) < 0xFDD0 || (c) > 0xFDEF) &&	\
	((c) & 0xFFFE) != 0xFFFE)

#define CONTINUATION_CHAR(c, val)				\
	do {							\
		if (((c) & 0xc0) != 0x80) /* 10xxxxxx */	\
			goto failed;				\
		(val) <<= 6;					\
		(val) |= (c) & 0x3f;				\
	} while (0)

#define INCREMENT_AND_CHECK_MAX(p, i, max_len)					\
	do {									\
		(i)++;								\
		if ((p)[(i)] == '\0' || ((max_len) >= 0 && (i) >= (max_len)))	\
			goto failed;						\
	} while (0)


gboolean g_utf8_validate(const gchar *str, gssize max_len, const gchar **end)
{
	unsigned long val, min, i;
	const unsigned char *p, *last;

	min = val = 0;

	for (p = (unsigned char *) str, i = 0; p[i]; i++) {
		if (max_len >= 0 && i >= max_len)
			break;

		if (p[i] < 128)
			continue;

		last = &p[i];

		if ((p[i] & 0xe0) == 0xc0) { /* 110xxxxx */
			if ((p[i] & 0x1e) == 0)
				goto failed;
			INCREMENT_AND_CHECK_MAX(p, i, max_len);
			if ((p[i] & 0xc0) != 0x80)
				goto failed; /* 10xxxxxx */
		} else {
			if ((p[i] & 0xf0) == 0xe0) {
				/* 1110xxxx */
				min = (1 << 11);
				val = p[i] & 0x0f;
				goto two_remaining;
			} else if ((p[i] & 0xf8) == 0xf0) {
				/* 11110xxx */
				min = (1 << 16);
				val = p[i] & 0x07;
			} else
				goto failed;

			INCREMENT_AND_CHECK_MAX(p, i, max_len);
			CONTINUATION_CHAR(p[i], val);
two_remaining:
			INCREMENT_AND_CHECK_MAX(p, i, max_len);
			CONTINUATION_CHAR(p[i], val);

			INCREMENT_AND_CHECK_MAX(p, i, max_len);
			CONTINUATION_CHAR(p[i], val);

			if (val < min || !UNICODE_VALID(val))
				goto failed;
		}
	}

	if (end)
		*end = (const gchar *) &p[i];

	return TRUE;

failed:
	if (end)
		*end = (const gchar *) last;

	return FALSE;
}

/* GSList functions */

GSList *g_slist_append(GSList *list, void *data)
{
	GSList *entry, *tail;

	entry = g_new(GSList, 1);

	entry->data = data;
	entry->next = NULL;

	if (!list)
		return entry;

	/* Find the end of the list */
	for (tail = list; tail->next; tail = tail->next);

	tail->next = entry;

	return list;
}

GSList *g_slist_prepend(GSList *list, void *data)
{
	GSList *entry;

	entry = g_new(GSList, 1);

	entry->data = data;
	entry->next = list;

	return entry;
}

GSList *g_slist_insert_sorted(GSList *list, void *data, GCompareFunc cmp_func)
{
	GSList *tmp, *prev, *entry;
	int cmp;

	entry = g_new(GSList, 1);

	entry->data = data;
	entry->next = NULL;

	if (!list)
		return entry;

	prev = NULL;
	tmp = list;

	cmp = cmp_func(data, tmp->data);

	while (tmp->next && cmp > 0) {
		prev = tmp;
		tmp = tmp->next;

		cmp = cmp_func(data, tmp->data);
	}

	if (!tmp->next && cmp > 0) {
		tmp->next = entry;
		return list;
	}

	if (prev) {
		prev->next = entry;
		entry->next = tmp;
		return list;
	} else {
		entry->next = list;
		return entry;
	}
}

GSList *g_slist_remove(GSList *list, void *data)
{
	GSList *l, *next, *prev = NULL, *match = NULL;

	if (!list)
		return NULL;

	for (l = list; l != NULL; l = l->next) {
		if (l->data == data) {
			match = l;
			break;
		}
		prev = l;
	}

	if (!match)
		return list;

	next = match->next;

	g_free(match);

	/* If the head was removed, return the next element */
	if (!prev)
		return next;

	prev->next = next;

	return list;
}

GSList *g_slist_find(GSList *list, gconstpointer data)
{
	GSList *l;

	for (l = list; l != NULL; l = l->next) {
		if (l->data == data)
			return l;
	}

	return NULL;
}

GSList *g_slist_find_custom(GSList *list, const void *data,
			GCompareFunc cmp_func)
{
	GSList *l;

	for (l = list; l != NULL; l = l->next) {
		if (!cmp_func(l->data, data))
			return l;
	}

	return NULL;
}

static GSList *g_slist_sort_merge(GSList *l1, GSList *l2,
					GCompareFunc cmp_func)
{
	GSList list, *l;
	int cmp;

	l = &list;

	while (l1 && l2) {
		cmp = cmp_func(l1->data, l2->data);

		if (cmp <= 0) {
			l = l->next = l1;
			l1 = l1->next;
		} else {
			l = l->next = l2;
			l2 = l2->next;
		}
	}

	l->next = l1 ? l1 : l2;

	return list.next;
}

GSList *g_slist_sort(GSList *list, GCompareFunc cmp_func)
{
	GSList *l1, *l2;

	if (!list || !list->next)
		return list;

	l1 = list;
	l2 = list->next;

	while ((l2 = l2->next) != NULL) {
		if ((l2 = l2->next) == NULL)
			break;
		l1 = l1->next;
	}

	l2 = l1->next;
	l1->next = NULL;

	return g_slist_sort_merge(g_slist_sort(list, cmp_func),
				g_slist_sort(l2, cmp_func), cmp_func);
}

int g_slist_length(GSList *list)
{
	int len;

	for (len = 0; list != NULL; list = list->next)
		len++;

	return len;
}

void g_slist_foreach(GSList *list, GFunc func, void *user_data)
{
	while (list) {
		GSList *next = list->next;
		func(list->data, user_data);
		list = next;
	}
}

void g_slist_free(GSList *list)
{
	GSList *l, *next;

	for (l = list; l != NULL; l = next) {
		next = l->next;
		g_free(l);
	}
}

GSList *g_slist_nth(GSList *list, guint n)
{
	while (n-- > 0 && list)
		list = list->next;

	return list;
}

gpointer g_slist_nth_data(GSList *list, guint n)
{
	while (n-- > 0 && list)
		list = list->next;

	return list ? list->data : NULL;
}

gint g_slist_position(GSList *list, GSList *link)
{
	gint i;

	for (i = 0; list; list = list->next, i++) {
		if (list == link)
			return i;
	}

	return -1;
}

GSList* g_slist_last(GSList *list)
{
	if (list)
		while (list->next)
			list = list->next;

	return list;
}

static inline GSList* _g_slist_remove_link(GSList *list, GSList *link)
{
	GSList *tmp;
	GSList *prev;

	prev = NULL;
	tmp = list;

	while (tmp) {
		if (tmp == link) {
			if (prev)
				prev->next = tmp->next;
			if (list == tmp)
				list = list->next;

			tmp->next = NULL;
			break;
		}

		prev = tmp;
		tmp = tmp->next;
	}

	return list;
}

GSList* g_slist_delete_link(GSList *list, GSList *link)
{
	list = _g_slist_remove_link(list, link);
	g_free(link);

	return list;
}

/* Memory allocation functions */

gpointer g_malloc(gulong n_bytes)
{
	gpointer mem;

	if (!n_bytes)
		return NULL;

	mem = malloc((size_t) n_bytes);
	if (!mem) {
		fprintf(stderr, "g_malloc: failed to allocate %lu bytes",
				n_bytes);
		abort();
	}

	return mem;
}

gpointer g_malloc0(gulong n_bytes)
{
	gpointer mem;

	if (!n_bytes)
		return NULL;

	mem = g_malloc(n_bytes);

	memset(mem, 0, (size_t) n_bytes);

	return mem;
}

gpointer g_try_malloc(gulong n_bytes)
{
	if (!n_bytes)
		return NULL;

	return malloc((size_t) n_bytes);
}

gpointer g_try_malloc0(gulong n_bytes)
{
	gpointer mem;

	mem = g_try_malloc(n_bytes);
	if (mem)
		memset(mem, 0, (size_t) n_bytes);

	return mem;
}

gpointer g_realloc(gpointer mem, gulong n_bytes)
{
	mem = realloc(mem, n_bytes);
	if (!mem) {
		fprintf(stderr, "g_realloc: failed to allocate %lu bytes",
				n_bytes);
		abort();
	}

	return mem;
}

void g_free(gpointer mem)
{
	if (mem)
		free(mem);
}

gchar *g_strdup(const gchar *str)
{
	gchar *s;

	if (!str)
		return NULL;

	s = strdup(str);
	if (!s) {
		fprintf(stderr, "strdup: failed to allocate new string");
		abort();
	}

	return s;
}

gchar *g_strdup_printf(const gchar *format, ...)
{
	va_list args;
	gchar buffer[1024];
	gint length;

	va_start(args, format);
	length = vsnprintf(buffer, sizeof(buffer) - 1, format, args);
	va_end(args);

	return g_strdup(buffer);
}

gchar *g_strdelimit(gchar *string, const gchar *delimiters, gchar new_delim)
{
	register gchar *c;

	if (!string)
		return NULL;

	for (c = string; *c; c++)
		if (strchr(delimiters, *c))
			*c = new_delim;

	return string;
}

gchar *g_strconcat(const gchar *string1, ...)
{
	gsize l;
	va_list args;
	gchar *s, *concat;

	if (!string1)
		return NULL;

	l = 1 + strlen(string1);
	va_start(args, string1);
	s = va_arg(args, gchar *);
	while (s) {
		l += strlen(s);
		s = va_arg(args, gchar *);
	}
	va_end (args);

	concat = g_new(gchar, l);
	concat[0] = '\0';

	va_start(args, string1);
	s = va_arg(args, gchar*);
	while (s) {
		strcat(concat, s);
		s = va_arg(args, gchar *);
	}
	va_end (args);

	return concat;
}

gsize g_strlcat(gchar *dest, const gchar *src, gsize dest_size)
{
	gchar *d = dest;
	const gchar *s = src;
	gsize bytes_left = dest_size;
	gsize dlength;  /* Logically, MIN(strlen(d), dest_size) */

	if (!d || !s)
		return 0;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (*d != 0 && bytes_left-- != 0)
		d++;
	dlength = d - dest;
	bytes_left = dest_size - dlength;

	if (bytes_left == 0)
		return dlength + strlen(s);

	while (*s != 0) {
		if (bytes_left != 1) {
			*d++ = *s;
			bytes_left--;
		}
		s++;
	}
	*d = 0;

	return dlength + (s - src);  /* count does not include NULL */
}

gchar **g_strsplit(const gchar *string, const gchar *delimiter, gint max_tokens)
{
	GSList *string_list = NULL, *slist;
	gchar **str_array, *s;
	guint n = 0;
	const gchar *remainder;

	if (string == NULL || delimiter == NULL || delimiter[0] == '\0')
		return NULL;

	if (max_tokens < 1)
		max_tokens = INT_MAX;

	remainder = string;
	s = strstr(remainder, delimiter);
	if (s) {
		gsize delimiter_len = strlen(delimiter);

		while (--max_tokens && s) {
			gsize len;
			gchar *tmp;

			len = s - remainder;
			tmp = g_new(char, len);
			memcpy(tmp, remainder, len);
			string_list = g_slist_prepend(string_list, tmp);
			n++;
			remainder = s + delimiter_len;
			s = strstr(remainder, delimiter);
		}
	}
	if (*string) {
		n++;
		string_list = g_slist_prepend(string_list, g_strdup(remainder));
	}

	str_array = g_new(gchar *, n + 1);

	str_array[n--] = NULL;
	for (slist = string_list; slist; slist = slist->next)
		str_array[n--] = slist->data;

	g_slist_free(string_list);

	return str_array;
}

gchar *g_ascii_strup(const gchar *str, gssize len)
{
	int i;
	gchar *s;

	s = g_strdup(str);
	if (!s)
		return NULL;

	if (len < 0)
		len = strlen(s);

	for (i = 0; i < len; i++)
		s[i] = toupper(s[i]);

	return s;
}

gboolean g_str_equal(gconstpointer v1, gconstpointer v2)
{
	const gchar *string1 = v1;
	const gchar *string2 = v2;

	return strcmp(string1, string2) == 0;
}

gboolean g_str_has_prefix(const gchar *str, const gchar *prefix)
{
	int str_len;
	int prefix_len;

	if (str == NULL || prefix == NULL)
		return FALSE;

	str_len = strlen (str);
	prefix_len = strlen (prefix);

	if (str_len < prefix_len)
		return FALSE;

	return strncmp(str, prefix, prefix_len) == 0;
}

gboolean g_str_has_suffix(const gchar *str, const gchar *suffix)
{
	int str_len;
	int suffix_len;

	if (!str || !suffix)
		return FALSE;

	str_len = strlen(str);
	suffix_len = strlen(suffix);

	if (str_len < suffix_len)
		return FALSE;

	return strcmp(str + str_len - suffix_len, suffix) == 0;
}

void g_strfreev(gchar **str_array)
{
	int i;

	if (str_array == NULL)
		return;

	for(i = 0; str_array[i] != NULL; i++)
		g_free(str_array[i]);

	g_free(str_array);
}

/* GKeyFile */

struct _GKeyFile {
	gchar *filename;
};

GKeyFile *g_key_file_new(void)
{
	return g_new0(GKeyFile, 1);
}

void g_key_file_free(GKeyFile *key_file)
{
	g_free(key_file->filename);
	g_free(key_file);
}

gboolean g_key_file_load_from_file(GKeyFile *key_file,
				const gchar *file,
				GKeyFileFlags flags,
				GError **error)
{
	key_file->filename = g_strdup(file);
	return TRUE;
}

static char *next_line(const char *ptr)
{
	char *nl;

	nl = strchr(ptr, '\n');
	if (!nl)
		return NULL;

	if (nl[1] == '\0')
		return NULL;

	return nl + 1;
}

gchar *g_key_file_get_string(GKeyFile *key_file,
				const gchar *group_name,
				const gchar *key,
				GError **error)
{
	struct stat st;
	char *map, *line, *group = NULL, *value = NULL;
	off_t size;
	size_t key_len, group_len;
	int fd, err = 0;

	fd = open(key_file->filename, O_RDONLY);
	if (fd < 0) {
		g_set_error(error, 0, 0, "%s: %s", key_file->filename,
				strerror(errno));
		return NULL;
	}

	if (flock(fd, LOCK_SH) < 0) {
		err = errno;
		goto close;
	}

	if (fstat(fd, &st) < 0) {
		err = errno;
		goto unlock;
	}

	size = st.st_size;

	map = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (!map || map == MAP_FAILED) {
		err = errno;
		goto unlock;
	}

	group_len = strlen(group_name);
	key_len = strlen(key);

	for (line = map; line != NULL; line = next_line(line)) {
		int i;
		size_t to_copy, value_len;
		char tmp[1024], *nl;

		if (*line == '#')
			continue;

		if (!group) {
			if (line[0] != '[' || strncmp(line + 1, group_name, group_len))
				continue;
			if (line[group_len + 1] == ']')
				group = line + 1;
			continue;
		}

		if (strncmp(line, key, key_len))
			continue;

		for (i = key_len; line[i] != '\n'; i++) {
			if (line[i] == '=')
				break;
			if (!isspace(line[i]))
				break;
		}

		if (line[i] != '=')
			continue;

		nl = strchr(line, '\n');
		if (!nl)
			continue;

		value_len = nl - (line + i + 1);
		to_copy = value_len > (sizeof(tmp) - 1) ? sizeof(tmp) - 1 : value_len;
		memset(tmp, 0, sizeof(tmp));
		strncpy(tmp, line + i + 1, to_copy);

		value = g_strdup(tmp);
		break;
	}

	munmap(map, size);

unlock:
	flock(fd, LOCK_UN);

close:
	close(fd);

	if (err)
		g_set_error(error, 0, 0, "%s: %s", key_file->filename,
				strerror(err));
	else if (!group)
		g_set_error(error, 0, 0, "%s: group %s not found",
				key_file->filename, group_name);
	else if (!value)
		g_set_error(error, 0, 0, "%s: key %s not found",
				key_file->filename, key);

	return value;
}

gboolean g_key_file_get_boolean(GKeyFile *key_file,
				const gchar *group_name,
				const gchar *key,
				GError **error)
{
	gboolean ret;
	gchar *str;

	str = g_key_file_get_string(key_file, group_name, key, error);
	if (!str)
		return FALSE;

	if (strcmp(str, "true") == 0 || strcmp(str, "1") == 0)
		ret = TRUE;
	else
		ret = FALSE;

	g_free(str);

	return ret;
}

gint g_key_file_get_integer(GKeyFile *key_file,
				const gchar *group_name,
				const gchar *key,
				GError **error)
{
	int ret;
	gchar *str;

	str = g_key_file_get_string(key_file, group_name, key, error);
	if (!str)
		return 0;

	ret = atoi(str);

	g_free(str);

	return ret;
}

gchar **g_key_file_get_string_list(GKeyFile *key_file, const gchar *group_name,
					const gchar *key, gsize *length,
					GError **error)
{
	gchar *str, *item, **list;
	int items = 0;

	str = g_key_file_get_string(key_file, group_name, key, error);
	if (!str)
		return NULL;

	items = 0;
	list = g_new0(char *, 1);

	item = strtok(str, ",");
	while (item) {
		items++;

		list = g_renew(char *, list, items + 1);

		list[items - 1] = g_strdup(item);
		list[items] = NULL;

		item = strtok(NULL, ",");
	}

	g_free(str);

	return list;
}

/* GString */

#define MY_MAXSIZE ((gsize)-1)

static gsize nearest_power(gsize base, gsize num)
{
	gsize n = base;

	if (num > MY_MAXSIZE / 2)
		return MY_MAXSIZE;

	while (n < num)
		n <<= 1;

	return n;
}

static void g_string_maybe_expand(GString *string, gsize len)
{
	if (string->len + len < string->allocated_len)
		return;

	string->allocated_len = nearest_power(1, string->len + len + 1);
	string->str = g_realloc(string->str, string->allocated_len);
}

static GString *g_string_sized_new(gsize dfl_size)
{
	GString *string;

	string = g_new0(GString, 1);

	g_string_maybe_expand(string, dfl_size);
	string->str[0] = '\0';

	return string;
}

static GString *g_string_append_len(GString *string, const gchar *val, gssize len)
{
	g_string_maybe_expand(string, len);

	if (len == 1)
		string->str[string->len] = *val;
	else
		memcpy(string->str + string->len, val, len);

	string->len += len;
	string->str[string->len] = '\0';

	return string;
}

GString *g_string_new(const gchar *init)
{
	GString *string;
	gint len;

	if (init == NULL || *init == '\0')
		return g_string_sized_new(2);

	len = strlen(init);
	string = g_string_sized_new(len + 2);

	g_string_append_len(string, init, len);

	return string;
}

void g_string_append_printf(GString *string, const gchar *format, ...)
{
	gchar buffer[1024];
	gint length;
	va_list args;

	va_start(args, format);
	length = vsnprintf(buffer, sizeof(buffer) - 1, format, args);
	va_end(args);

	g_string_append_len(string, buffer, length);
}

gchar *g_string_free(GString *string, gboolean free_segment)
{
	gchar *segment;

	if (free_segment) {
		g_free(string->str);
		segment = NULL;
	} else
		segment = string->str;

	g_free(string);

	return segment;
}

/* GMarkup */

struct _GMarkupParseContext {
	char dummy;
};

GMarkupParseContext *g_markup_parse_context_new(const GMarkupParser *parser,
					GMarkupParseFlags flags,
					gpointer user_data,
					GDestroyNotify user_data_dnotify)
{
	return g_new0(GMarkupParseContext, 1);
}

gboolean g_markup_parse_context_parse(GMarkupParseContext *context,
					const gchar *text, gssize text_len,
					GError **error)
{
	g_set_error(error, 0, 0, "Not implemented");
	return FALSE;
}

void g_markup_parse_context_free(GMarkupParseContext *context)
{
	g_free(context);
}

static gchar *g_build_pathname_va(const gchar *first_element,
						va_list args, gpointer *data)
{
	gchar result[PATH_MAX], *element;

	strncpy(result, first_element, PATH_MAX);
	element = va_arg(args, gchar *);

	while (element) {
		g_strlcat(result, "/", PATH_MAX);
		g_strlcat(result, element, PATH_MAX);
		element = va_arg(args, gchar *);
	}

	va_end(args);

	return g_strdup(result);
}

gchar *g_build_filename(const gchar *first_element, ...)
{
	gchar *str;
	va_list args;

	va_start(args, first_element);
	str = g_build_pathname_va(first_element, args, NULL);
	va_end(args);

	return str;
}

/* GDir */

GDir *g_dir_open(const gchar *path, guint flags, GError **error)
{
	GDir *dir;

	if (path == NULL)
		return NULL;

	dir = g_new(GDir, 1);

	dir->dirp = opendir(path);

	if (dir->dirp)
		return dir;

	/* error case */
	g_set_error(error, 0, 0, "Error opening directory '%s': %s",
						path, strerror(errno));

	g_free(dir);

	return NULL;
}

const gchar *g_dir_read_name(GDir *dir)
{
	struct dirent *entry;

	if (dir == NULL)
		return NULL;

	entry = readdir(dir->dirp);

	while (entry && (strcmp(entry->d_name, ".") == 0 ||
					strcmp(entry->d_name, "..") == 0))
		entry = readdir(dir->dirp);

	return entry ? entry->d_name : NULL;
}

void g_dir_close(GDir *dir)
{
	if (dir == NULL)
		return;

	closedir(dir->dirp);
	g_free(dir);
}
