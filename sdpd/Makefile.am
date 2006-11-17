
noinst_LIBRARIES = libsdpserver.a

libsdpserver_a_SOURCES = sdpd.h cstate.c request.c service.c servicedb.c

sbin_PROGRAMS = sdpd

sdpd_SOURCES = main.c

sdpd_LDADD = @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a libsdpserver.a

AM_CFLAGS = @BLUEZ_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

man_MANS = sdpd.8

EXTRA_DIST = $(man_MANS)

MAINTAINERCLEANFILES = Makefile.in
