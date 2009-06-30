
if UDEVRULES
rulesdir = $(sysconfdir)/udev

rules_DATA = bluetooth.rules

if HID2HCI
rules_DATA += bluetooth-hid2hci.rules
endif

if PCMCIA
rules_DATA += bluetooth-serial.rules
endif
endif

if PCMCIA
udevdir = $(libexecdir)/udev

udev_SCRIPTS = bluetooth_serial
endif

EXTRA_DIST = bluetooth.init bluetooth.default bluetooth.rules \
	bluetooth-hid2hci.rules bluetooth-serial.rules bluetooth_serial

MAINTAINERCLEANFILES = Makefile.in
