#
#  $Id$
#

noinst_PROGRAMS = bluetooth

bluetooth_SOURCES = main.c sdp.c spp.c hcrp.c

LDFLAGS = @BLUEZ_LIBS@

INCLUDES = @BLUEZ_INCLUDES@

if CUPS
install-data-local: bluetooth
	$(INSTALL) -D -m 755 $(srcdir)/bluetooth $(DESTDIR)@CUPS_BACKEND_DIR@/bluetooth
endif
