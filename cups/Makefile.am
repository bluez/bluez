#
#  $Id$
#

noinst_PROGRAMS = bluetooth

bluetooth_SOURCES = main.c sdp.c spp.c hcrp.c

LIBS = @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@

if CUPS
install-data-local: bluetooth
	$(INSTALL) -D -m 755 $(srcdir)/bluetooth $(DESTDIR)@CUPS_BACKEND_DIR@/bluetooth
endif
