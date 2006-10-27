
noinst_PROGRAMS = bt.networkd

bt_networkd_SOURCES = main.c

bt_networkd_LDADD = @DBUS_LIBS@ @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

MAINTAINERCLEANFILES = Makefile.in
