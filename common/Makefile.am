
if INOTIFY
notify_sources = notify-inotify.c
else
notify_sources = notify-dummy.c
endif

noinst_LIBRARIES = libhelper.a

libhelper_a_SOURCES = oui.h oui.c dbus.h dbus.c \
	textfile.h textfile.c logging.h logging.c \
	dbus-helper.h dbus-helper.c error.h error.c \
	glib-helper.h glib-helper.c notify.h $(notify_sources) \
	sdp-xml.h sdp-xml.c sdp-glib.c

noinst_PROGRAMS = test_textfile

test_textfile_LDADD = libhelper.a

AM_CFLAGS = @DBUS_CFLAGS@ @GLIB_CFLAGS@

EXTRA_DIST = ppoll.h uinput.h notify-dummy.c notify-inotify.c

MAINTAINERCLEANFILES = Makefile.in
