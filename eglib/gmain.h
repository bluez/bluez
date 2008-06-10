#ifndef __GMAIN_H
#define __GMAIN_H

#include <stdlib.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

typedef char	gchar;
typedef short	gshort;
typedef long	glong;
typedef int	gint;
typedef gint	gboolean;

typedef unsigned char	guchar;
typedef unsigned short	gushort;
typedef unsigned long	gulong;
typedef unsigned int	guint;

typedef uint8_t  guint8;
typedef uint16_t guint16;
typedef uint32_t guint32;

typedef float	gfloat;
typedef double	gdouble;

typedef void *		gpointer;
typedef const void *	gconstpointer;

typedef size_t	gsize;
typedef ssize_t	gssize;

#define GPOINTER_TO_INT(p)	((gint)  (glong) (p))
#define GPOINTER_TO_UINT(p)	((guint) (gulong) (p))

#define GINT_TO_POINTER(i)	((gpointer) (glong) (i))
#define GUINT_TO_POINTER(u)	((gpointer) (gulong) (u))

#ifndef SSIZE_MAX
#define SSIZE_MAX	INT_MAX
#endif

#define g_ntohs(val) ntohs(val)
#define g_ntohl(val) ntohl(val)
#define g_htons(val) htons(val)
#define g_htonl(val) htonl(val)

typedef pid_t GPid;

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

typedef enum {
	G_IO_FLAG_APPEND	= 1 << 0,
	G_IO_FLAG_NONBLOCK	= 1 << 1,
	G_IO_FLAG_IS_READABLE	= 1 << 2,
	G_IO_FLAG_IS_WRITEABLE	= 1 << 3,
	G_IO_FLAG_IS_SEEKABLE	= 1 << 4,
	G_IO_FLAG_MASK		= (1 << 5) - 1,
	G_IO_FLAG_GET_MASK	= G_IO_FLAG_MASK,
	G_IO_FLAG_SET_MASK	= G_IO_FLAG_APPEND | G_IO_FLAG_NONBLOCK
} GIOFlags;

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef TRUE
#define TRUE (!FALSE)
#endif

#undef MAX
#define MAX(a, b)  (((a) > (b)) ? (a) : (b))

#undef MIN
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

#undef ABS
#define ABS(a) (((a) < 0) ? -(a) : (a))

#undef CLAMP
#define CLAMP(x, low, high) (((x) > (high)) ? (high) : (((x) < (low)) ? (low) : (x)))

/* GError */

typedef guint32 GQuark;

typedef struct {
	GQuark       domain;
	gint         code;
	gchar       *message;
} GError;

void g_set_error(GError **err, GQuark domain, gint code,
			const gchar *format, ...);
GError* g_error_new_literal(GQuark domain, gint code, const gchar *message);
void g_error_free(GError *err);

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
typedef gboolean (*GIOFunc) (GIOChannel *source, GIOCondition condition,
								gpointer data);

GIOError g_io_channel_read(GIOChannel *channel, gchar *buf, gsize count,
							gsize *bytes_read);
GIOError g_io_channel_write(GIOChannel *channel, const gchar *buf, gsize count,
							gsize *bytes_written);

void g_io_channel_close(GIOChannel *channel);

GIOChannel *g_io_channel_unix_new(int fd);
GIOChannel *g_io_channel_ref(GIOChannel *channel);
void g_io_channel_unref(GIOChannel *channel);
void g_io_channel_set_close_on_unref(GIOChannel *channel, gboolean do_close);
gint g_io_channel_unix_get_fd(GIOChannel *channel);
GIOStatus g_io_channel_set_flags(GIOChannel *channel, GIOFlags flags,
				GError **error);
guint g_io_add_watch(GIOChannel *channel, GIOCondition condition,
					GIOFunc func, gpointer user_data);
guint g_io_add_watch_full(GIOChannel *channel, gint priority,
				GIOCondition condition, GIOFunc func,
				gpointer user_data, GDestroyNotify notify);

GMainLoop *g_main_loop_new(GMainContext *context, gboolean is_running);
void g_main_loop_run(GMainLoop *loop);
void g_main_loop_quit(GMainLoop *loop);
void g_main_loop_unref(GMainLoop *loop);
guint g_timeout_add(guint interval, GSourceFunc function, gpointer data);
guint g_timeout_add_seconds(guint interval, GSourceFunc function, gpointer data);
guint g_idle_add(GSourceFunc function, gpointer data);
gboolean g_source_remove(guint tag);

/* Spawning related functions */

typedef enum {
	G_SPAWN_LEAVE_DESCRIPTORS_OPEN = 1 << 0,
	G_SPAWN_DO_NOT_REAP_CHILD      = 1 << 1,
	/* look for argv[0] in the path i.e. use execvp() */
	G_SPAWN_SEARCH_PATH            = 1 << 2,
	/* Dump output to /dev/null */
	G_SPAWN_STDOUT_TO_DEV_NULL     = 1 << 3,
	G_SPAWN_STDERR_TO_DEV_NULL     = 1 << 4,
	G_SPAWN_CHILD_INHERITS_STDIN   = 1 << 5,
	G_SPAWN_FILE_AND_ARGV_ZERO     = 1 << 6
} GSpawnFlags;

typedef void (*GSpawnChildSetupFunc) (gpointer user_data);

gboolean g_spawn_async(const gchar *working_directory,
			gchar **argv, gchar **envp,
			GSpawnFlags flags,
			GSpawnChildSetupFunc child_setup,
			gpointer user_data,
			GPid *child_pid,
			GError **error);

void g_spawn_close_pid(GPid pid);

typedef void (*GChildWatchFunc) (GPid pid, gint status, gpointer data);

guint g_child_watch_add(GPid pid, GChildWatchFunc func, gpointer user_data);

gboolean g_utf8_validate(const gchar *str, gssize max_len, const gchar **end);

#define g_main_new(is_running)	g_main_loop_new(NULL, is_running);
#define g_main_run(loop)	g_main_loop_run(loop)
#define g_main_quit(loop)	g_main_loop_quit(loop)
#define g_main_unref(loop)	g_main_loop_unref(loop)

/* GSList declarations */

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

GSList *g_slist_find(GSList *list, gconstpointer data);

GSList *g_slist_find_custom(GSList *list, const void *data,
							GCompareFunc cmp_func);

GSList *g_slist_sort(GSList *list, GCompareFunc cmp_func);

int g_slist_length(GSList *list);

void g_slist_foreach(GSList *list, GFunc func, void *user_data);
void g_slist_free(GSList *list);
GSList *g_slist_delete_link(GSList *list, GSList *link);

GSList *g_slist_nth(GSList *list, guint n);
gpointer g_slist_nth_data(GSList *list, guint n);
int g_slist_position(GSList *list, GSList *link);
GSList* g_slist_last(GSList *list);

#define g_slist_next(l) ((l)->next)

/* Memory allocation related */

gpointer g_malloc(gulong n_bytes);
gpointer g_malloc0(gulong n_bytes);
gpointer g_try_malloc(gulong n_bytes);
gpointer g_try_malloc0(gulong n_bytes);
gpointer g_realloc(gpointer mem, gulong n_bytes);

void g_free(gpointer mem);

gchar *g_strdup(const gchar *str);
gchar* g_strdup_printf(const gchar *format, ...);
gchar* g_strdelimit(gchar *string, const gchar *delimiters, gchar new_delim);
gchar *g_strconcat(const gchar *string1, ...);
gsize g_strlcat(gchar *dest, const gchar *src, gsize dest_size);
gchar **g_strsplit(const gchar *string, const gchar *delimiter, gint max_tokens);
gchar *g_ascii_strup(const gchar *str, gssize len);
gboolean g_str_equal(gconstpointer v1, gconstpointer v2);
gboolean g_str_has_prefix(const gchar *str, const gchar *prefix);
gboolean g_str_has_suffix(const gchar *str, const gchar *suffix);
void g_strfreev(gchar **str_array);

#define g_new(struct_type, n_structs) \
	((struct_type *) g_malloc (((gsize) sizeof (struct_type)) * ((gsize) (n_structs))))
#define g_new0(struct_type, n_structs) \
	((struct_type *) g_malloc0 (((gsize) sizeof (struct_type)) * ((gsize) (n_structs))))
#define g_try_new(struct_type, n_structs) \
	((struct_type *) g_try_malloc (((gsize) sizeof (struct_type)) * ((gsize) (n_structs))))
#define g_try_new0(struct_type, n_structs) \
	((struct_type *) g_try_malloc0 (((gsize) sizeof (struct_type)) * ((gsize) (n_structs))))
#define g_renew(struct_type, mem, n_structs) \
	((struct_type *) g_realloc ((mem), ((gsize) sizeof (struct_type)) * ((gsize) (n_structs))))

/* GKeyFile */

typedef enum {
	G_KEY_FILE_NONE              = 0,
	G_KEY_FILE_KEEP_COMMENTS     = 1 << 0,
	G_KEY_FILE_KEEP_TRANSLATIONS = 1 << 1
} GKeyFileFlags;

typedef struct _GKeyFile GKeyFile;

GKeyFile *g_key_file_new(void);

void g_key_file_free(GKeyFile *key_file);

gboolean g_key_file_load_from_file(GKeyFile *key_file,
				const gchar *file,
				GKeyFileFlags flags,
				GError **error);

gchar *g_key_file_get_string(GKeyFile *key_file,
				const gchar *group_name,
				const gchar *key,
				GError **error);

gboolean g_key_file_get_boolean(GKeyFile *key_file,
				const gchar *group_name,
				const gchar *key,
				GError **error);

gint g_key_file_get_integer(GKeyFile *key_file,
				const gchar *group_name,
				const gchar *key,
				GError **error);

gchar **g_key_file_get_string_list(GKeyFile *key_file,
					const gchar *group_name,
					const gchar *key, gsize *length,
					GError **error);
/* GString */

typedef struct {
	gchar *str;
	gsize len;
	gsize allocated_len;
} GString;

GString *g_string_new(const gchar *init);

void g_string_append_printf(GString *string, const gchar *format, ...);

gchar *g_string_free(GString *string, gboolean free_segment);

/* GMarkup */

typedef enum {
	G_MARKUP_DO_NOT_USE_THIS_UNSUPPORTED_FLAG	= 1 << 0,
	G_MARKUP_TREAT_CDATA_AS_TEXT			= 1 << 1
} GMarkupParseFlags;

typedef struct _GMarkupParseContext GMarkupParseContext;
typedef struct _GMarkupParser GMarkupParser;

struct _GMarkupParser {
	/* Called for open tags <foo bar="baz"> */
	void (*start_element) (GMarkupParseContext *context,
			const gchar *element_name,
			const gchar **attribute_names,
			const gchar **attribute_values,
			gpointer user_data,
			GError **error);

	/* Called for close tags </foo> */
	void (*end_element) (GMarkupParseContext *context,
			const gchar         *element_name,
			gpointer             user_data,
			GError             **error);

	/* Called for character data */
	/* text is not nul-terminated */
	void (*text) (GMarkupParseContext *context,
			const gchar *text,
			gsize text_len,
			gpointer user_data,
			GError **error);

	/* Called for strings that should be re-saved verbatim in this same
	 * position, but are not otherwise interpretable.  At the moment
	 * this includes comments and processing instructions.
	 */
	/* text is not nul-terminated. */
	void (*passthrough) (GMarkupParseContext *context,
			const gchar *passthrough_text,
			gsize text_len,
			gpointer user_data,
			GError **error);

	/* Called on error, including one set by other
	 * methods in the vtable. The GError should not be freed.
	 */
	void (*error) (GMarkupParseContext *context,
			GError *error,
			gpointer user_data);
};

GMarkupParseContext *g_markup_parse_context_new(const GMarkupParser *parser,
					GMarkupParseFlags flags,
					gpointer user_data,
					GDestroyNotify user_data_dnotify);

gboolean g_markup_parse_context_parse(GMarkupParseContext *context,
					const gchar *text, gssize text_len,
					GError **error);

void g_markup_parse_context_free(GMarkupParseContext *context);

/* GDir */

typedef struct _GDir GDir;

GDir *g_dir_open(const gchar *path, guint flags, GError **error);
const gchar *g_dir_read_name(GDir *dir);
void g_dir_close(GDir *dir);

/* Various */

gchar *g_build_filename(const gchar *first_element, ...);

#endif /* __GMAIN_H */
