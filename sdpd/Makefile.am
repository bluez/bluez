
noinst_LIBRARIES = libsdpserver.a

libsdpserver_a_SOURCES = \
		sdpd.h server.c cstate.c request.c service.c servicedb.c

AM_CFLAGS = @BLUEZ_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

MAINTAINERCLEANFILES = Makefile.in
