#  
#  $Id$
#

hdrdir = $(prefix)/include/bluetooth

EXTRA_DIST = bluetooth.h  hci.h  hci_lib.h  hci_uart.h  hci_vhci.h  l2cap.h  sco.h

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(hdrdir)
	$(INSTALL) -m 644 $(srcdir)/*.h $(DESTDIR)$(hdrdir)
