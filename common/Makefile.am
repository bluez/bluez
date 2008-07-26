
noinst_LIBRARIES = libhelper.a

libhelper_a_SOURCES = oui.h oui.c textfile.h textfile.c \
	logging.h logging.c error.h error.c \
	glib-helper.h glib-helper.c sdp-xml.h sdp-xml.c sdp-glib.c

noinst_PROGRAMS = test_textfile

test_textfile_LDADD = libhelper.a

AM_CFLAGS = @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@

EXTRA_DIST = ppoll.h uinput.h

MAINTAINERCLEANFILES = Makefile.in
