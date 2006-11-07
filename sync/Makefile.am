
noinst_PROGRAMS = bt.syncd

bt_syncd_SOURCES = main.c

bt_syncd_LDADD = @DBUS_LIBS@ @OPENSYNC_LIBS@ @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

AM_CFLAGS = @BLUEZ_CFLAGS@ @OPENSYNC_CFLAGS@ @DBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

MAINTAINERCLEANFILES = Makefile.in
