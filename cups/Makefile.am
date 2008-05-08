
if CUPS
cupsdir = $(libdir)/cups/backend

cups_PROGRAMS = bluetooth

bluetooth_SOURCES = main.c cups.h sdp.c spp.c hcrp.c

bluetooth_LDADD = $(top_builddir)/common/libhelper.a \
		@GDBUS_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@ 
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

MAINTAINERCLEANFILES = Makefile.in
