
if CUPS
cupsdir = $(libdir)/cups/backend

cups_PROGRAMS = bluetooth

bluetooth_SOURCES = main.c sdp.c spp.c hcrp.c
bluetooth_LDADD = @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@
endif

MAINTAINERCLEANFILES = Makefile.in
