#ifndef __GLIB_ECTOMY_H
#define __GLIB_ECTOMY_H

#ifdef HAVE_GLIB
#include <glib.h>
#define g_timeout_remove g_source_remove
#define g_io_remove_watch g_source_remove
#else

#include <stdlib.h>
#include <sys/poll.h>

typedef char	gchar;
typedef short	gshort;
typedef long	glong;
typedef int	gint;
typedef gint	gboolean;

typedef unsigned char	guchar;
typedef unsigned short	gushort;
typedef unsigned long	gulong;
typedef unsigned int	guint;

typedef float	gfloat;
typedef double	gdouble;

typedef void *		gpointer;
typedef const void *	gconstpointer;

typedef size_t	gsize;
typedef ssize_t	gssize;

#ifndef SSIZE_MAX
#define SSIZE_MAX	INT_MAX
#endif

#define MIN_TIMEOUT(a, b)  (((a) < (b)) ? (a) : (b))

typedef struct _GIOChannel GIOChannel;

typedef gboolean (*GSourceFunc) (gpointer data);

typedef struct _GMainContext GMainContext;

typedef struct _GMainLoop GMainLoop;

typedef enum {
	G_IO_ERROR_NONE,
	G_IO_ERROR_AGAIN,
	G_IO_ERROR_INVAL,
	G_IO_ERROR_UNKNOWN
} GIOError;

typedef enum {
	G_IO_STATUS_ERROR	= -1,
	G_IO_STATUS_NORMAL	= 0,
	G_IO_STATUS_EOF		= 1,
	G_IO_STATUS_AGAIN	= 2
} GIOStatus;

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef TRUE
#define TRUE (!FALSE)
#endif

typedef enum {
	G_IO_IN		= POLLIN,
	G_IO_OUT	= POLLOUT,
	G_IO_PRI	= POLLPRI,
	G_IO_ERR	= POLLERR,
	G_IO_HUP	= POLLHUP,
	G_IO_NVAL	= POLLNVAL
} GIOCondition;

#define G_PRIORITY_HIGH		-100
#define G_PRIORITY_DEFAULT	0
#define G_PRIORITY_HIGH_IDLE	100
#define G_PRIORITY_DEFAULT_IDLE	200
#define G_PRIORITY_LOW		300

typedef void (*GDestroyNotify) (gpointer data);
typedef gboolean (*GIOFunc) (GIOChannel *source, GIOCondition condition, gpointer data);

GIOError g_io_channel_read(GIOChannel *channel, gchar *buf, gsize count, gsize *bytes_read);
void g_io_channel_close(GIOChannel *channel);

GIOChannel *g_io_channel_unix_new(int fd);
void g_io_channel_unref(GIOChannel *channel);
void g_io_channel_set_close_on_unref(GIOChannel *channel, gboolean do_close);
gint g_io_channel_unix_get_fd(GIOChannel *channel);
guint g_io_add_watch(GIOChannel *channel, GIOCondition condition,
					GIOFunc func, gpointer user_data);
guint g_io_add_watch_full(GIOChannel *channel, gint priority,
				GIOCondition condition, GIOFunc func,
				gpointer user_data, GDestroyNotify notify);
void g_io_remove_watch(guint id);

GMainLoop *g_main_loop_new(GMainContext *context, gboolean is_running);
void g_main_loop_run(GMainLoop *loop);
void g_main_loop_quit(GMainLoop *loop);
void g_main_loop_unref(GMainLoop *loop);
guint g_timeout_add(guint interval, GSourceFunc function, gpointer data);
gint g_timeout_remove(const guint id);

gboolean g_utf8_validate(const gchar *str, gssize max_len, const gchar **end);

#define g_main_new(is_running)	g_main_loop_new(NULL, is_running);
#define g_main_run(loop)	g_main_loop_run(loop)
#define g_main_quit(loop)	g_main_loop_quit(loop)
#define g_main_unref(loop)	g_main_loop_unref(loop)

/* Begin GSList declarations */

typedef struct _GSList {
	void *data;
	struct _GSList *next;
} GSList;

typedef int (*GCompareFunc)(const void *a, const void *b);
typedef void (*GFunc)(void *data, void *user_data);

GSList *g_slist_append(GSList *list, void *data);

GSList *g_slist_prepend(GSList *list, void *data);

GSList *g_slist_insert_sorted(GSList *list, void *data, GCompareFunc cmp_func);

GSList *g_slist_remove(GSList *list, void *data);

GSList *g_slist_find_custom(GSList *list, const void *data,
			GCompareFunc cmp_func);

GSList *g_slist_sort(GSList *list, GCompareFunc cmp_func);

int g_slist_length(GSList *list);

void g_slist_foreach(GSList *list, GFunc func, void *user_data);
void g_slist_free(GSList *list);

/* End GSList declarations */

#endif

#endif /* __GLIB_ECTOMY_H */
