#  
#  $Id$
#

includedir = @includedir@/bluetooth

include_HEADERS = bluetooth.h hci.h hci_lib.h hci_uart.h hci_vhci.h l2cap.h sco.h rfcomm.h

bluetooth:
	ln -s . bluetooth

all-local: bluetooth
clean-local:
	rm -f bluetooth
