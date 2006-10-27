
noinst_PROGRAMS = bt.audiod

bt_audiod_SOURCES = main.c

bt_audiod_LDADD = @DBUS_LIBS@ @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

MAINTAINERCLEANFILES = Makefile.in
