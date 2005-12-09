
bin_PROGRAMS = hidd

hidd_SOURCES = main.c hidd.h sdp.c uinput.h fakehid.c
hidd_LDADD = @BLUEZ_LIBS@ -lm $(top_builddir)/common/libtextfile.a

AM_CFLAGS = @BLUEZ_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

man_MANS = hidd.1

EXTRA_DIST = $(man_MANS)

MAINTAINERCLEANFILES = Makefile.in
