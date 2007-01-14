
if OBEX
noinst_PROGRAMS = transferd

transferd_SOURCES = main.c

LDADD = $(top_builddir)/common/libhelper.a \
	@DBUS_LIBS@ @OPENOBEX_LIBS@ @BLUEZ_LIBS@
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @OPENOBEX_CFLAGS@ @DBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

MAINTAINERCLEANFILES = Makefile.in
