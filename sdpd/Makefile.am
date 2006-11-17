
sbin_PROGRAMS = sdpd

sdpd_SOURCES = main.c request.c service.c cstate.c servicedb.c sdpd.h

sdpd_LDADD = @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

AM_CFLAGS = @BLUEZ_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

man_MANS = sdpd.8

EXTRA_DIST = $(man_MANS)

MAINTAINERCLEANFILES = Makefile.in
