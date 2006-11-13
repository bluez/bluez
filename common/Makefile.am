
if EXPAT
sdp_sources = sdp-expat.c
else
sdp_sources = sdp-dummy.c
endif

noinst_LIBRARIES = libhelper.a

libhelper_a_SOURCES = oui.h oui.c list.h list.c \
	textfile.h textfile.c helper.h helper.c \
	glib-ectomy.h glib-ectomy.c logging.h logging.c \
	dbus.h dbus.c sdp-xml.h sdp-xml.c $(sdp_sources)

noinst_PROGRAMS = test_textfile

test_textfile_LDADD = libhelper.a

AM_CFLAGS = @DBUS_CFLAGS@

EXTRA_DIST = ppoll.h sdp-dummy.c sdp-expat.c

MAINTAINERCLEANFILES = Makefile.in
