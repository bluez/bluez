
if UDEVRULES
rulesdir = @UDEV_DATADIR@

rules_DATA = 97-bluetooth.rules

if HID2HCI
rules_DATA += 97-bluetooth-hid2hci.rules
endif

if PCMCIA
rules_DATA += 97-bluetooth-serial.rules
endif
endif

if PCMCIA
udevdir = $(libexecdir)/udev

udev_SCRIPTS = bluetooth_serial
endif

CLEANFILES = $(rules_DATA)

EXTRA_DIST = bluetooth-hid2hci.rules bluetooth-serial.rules bluetooth_serial

MAINTAINERCLEANFILES = Makefile.in

97-bluetooth.rules: bluetooth.rules
	cp $< $@

97-bluetooth-hid2hci.rules: bluetooth-hid2hci.rules
	cp $< $@

97-bluetooth-serial.rules: bluetooth-serial.rules
	cp $< $@
