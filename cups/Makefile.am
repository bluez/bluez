
if CUPS
cupsdir = $(libdir)/cups/backend

cups_PROGRAMS = bluetooth
else
noinst_PROGRAMS = bluetooth
endif

bluetooth_SOURCES = main.c sdp.c spp.c hcrp.c
bluetooth_LDADD = @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@

MAINTAINERCLEANFILES = Makefile.in
