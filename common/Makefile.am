
noinst_LIBRARIES = libhelper.a

libhelper_a_SOURCES = oui.h oui.c list.h list.c \
	textfile.h textfile.c helper.h helper.c \
	glib-ectomy.h glib-ectomy.c logging.h logging.c

noinst_PROGRAMS = test_textfile

test_textfile_LDADD = libhelper.a

EXTRA_DIST = ppoll.h

MAINTAINERCLEANFILES = Makefile.in
