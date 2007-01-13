
if EXPAT
sdp_sources = sdp-expat.c
else
sdp_sources = sdp-dummy.c
endif

if INOTIFY
notify_sources = notify-inotify.c
else
notify_sources = notify-dummy.c
endif

if GLIB
glib_sources =
glib_cflags  = @GLIB_CFLAGS@
else
glib_sources = glib-ectomy.c
glib_cflags  =
endif

noinst_LIBRARIES = libhelper.a

libhelper_a_SOURCES = oui.h oui.c dbus.h dbus.c \
	textfile.h textfile.c logging.h logging.c \
	sdp-xml.h sdp-xml.c $(sdp_sources) \
	notify.h $(notify_sources) \
	glib-ectomy.h $(glib_sources)

noinst_PROGRAMS = test_textfile

test_textfile_LDADD = libhelper.a

AM_CFLAGS = @DBUS_CFLAGS@ $(glib_cflags)

EXTRA_DIST = ppoll.h sdp-dummy.c sdp-expat.c \
	notify-dummy.c notify-inotify.c glib-ectomy.c

MAINTAINERCLEANFILES = Makefile.in
