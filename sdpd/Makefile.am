
noinst_LIBRARIES = libsdpserver.a

libsdpserver_a_SOURCES = sdpd.h server.c cstate.c request.c service.c servicedb.c

if SDPD
sbin_PROGRAMS = sdpd

sdpd_SOURCES = main.c

sdpd_LDADD = libsdpserver.a \
	$(top_builddir)/common/libhelper.a \
	@GLIB_LIBS@ @BLUEZ_LIBS@
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

man_MANS = sdpd.8

EXTRA_DIST = $(man_MANS)

MAINTAINERCLEANFILES = Makefile.in
