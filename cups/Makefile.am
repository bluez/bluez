
if CUPS
cupsdir = $(libdir)/cups/backend

cups_PROGRAMS = bluetooth

bluetooth_SOURCES = main.c sdp.c spp.c hcrp.c

bluetooth_LDADD = $(top_builddir)/common/libhelper.a \
			@DBUS_LIBS@ @GLIB_LIBS@ @BLUEZ_LIBS@ 

if EXPAT
bluetooth_LDADD += -lexpat
endif
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

MAINTAINERCLEANFILES = Makefile.in
