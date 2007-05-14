
if HIDD
bin_PROGRAMS = hidd

hidd_SOURCES = main.c hidd.h sdp.c fakehid.c

hidd_LDADD = @BLUEZ_LIBS@ -lm $(top_builddir)/common/libhelper.a
endif

AM_CFLAGS = @BLUEZ_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

if HIDD
if MANPAGES
man_MANS = hidd.1
endif
endif

EXTRA_DIST = hidd.1 fakehid.txt

MAINTAINERCLEANFILES = Makefile.in
