
noinst_PROGRAMS = bluetoothd

bluetoothd_SOURCES = main.c

bluetoothd_LDADD = @GLIB_LIBS@ @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

AM_CFLAGS = @BLUEZ_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

MAINTAINERCLEANFILES = Makefile.in
