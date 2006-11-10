
noinst_LIBRARIES = libhelper.a

libhelper_a_SOURCES = oui.h oui.c list.h list.c \
	textfile.h textfile.c helper.h helper.c \
	glib-ectomy.h glib-ectomy.c logging.h logging.c \
	dbus.h dbus.c sdp-xml.h sdp-xml.c

noinst_PROGRAMS = test_textfile

test_textfile_LDADD = libhelper.a

AM_CFLAGS = @DBUS_CFLAGS@

EXTRA_DIST = ppoll.h

MAINTAINERCLEANFILES = Makefile.in
