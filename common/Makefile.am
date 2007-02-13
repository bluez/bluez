
if GLIB
sdp_sources = sdp-glib.c
else
if EXPAT
sdp_sources = sdp-expat.c
else
sdp_sources = sdp-dummy.c
endif
endif

if INOTIFY
notify_sources = notify-inotify.c
else
notify_sources = notify-dummy.c
endif

noinst_LIBRARIES = libhelper.a

libhelper_a_SOURCES = oui.h oui.c dbus.h dbus.c \
	textfile.h textfile.c logging.h logging.c \
	dbus-helper.h dbus-helper.c \
	sdp-xml.h sdp-xml.c $(sdp_sources) \
	notify.h $(notify_sources)

noinst_PROGRAMS = test_textfile

test_textfile_LDADD = libhelper.a

AM_CFLAGS = @DBUS_CFLAGS@ @GLIB_CFLAGS@

EXTRA_DIST = ppoll.h uinput.h \
		notify-dummy.c notify-inotify.c \
		sdp-dummy.c sdp-expat.c sdp-glib.c

MAINTAINERCLEANFILES = Makefile.in
