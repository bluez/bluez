
if DBUS
noinst_PROGRAMS = bluetoothd

bluetoothd_SOURCES = main.c

bluetoothd_LDADD = @DBUS_LIBS@ @BLUEZ_LIBS@ $(top_builddir)/common/libtextfile.a
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

MAINTAINERCLEANFILES = Makefile.in
