
if CONFIGFILES
rulesdir = $(sysconfdir)/udev

rules_DATA =

if HID2HCI
rules_DATA += bluetooth-hid2hci.rules
endif

if PCMCIARULES
rules_DATA += bluetooth-serial.rules
endif
endif

if PCMCIARULES
udevdir = $(libexecdir)/udev

udev_SCRIPTS = bluetooth_serial
endif

EXTRA_DIST = bluetooth.init bluetooth.default bluetooth-hid2hci.rules \
				bluetooth-serial.rules bluetooth_serial

MAINTAINERCLEANFILES = Makefile.in

if INITSCRIPTS
install-data-local:
	$(INSTALL) -D -m 755 $(srcdir)/bluetooth.init $(DESTDIR)$(sysconfdir)/init.d/bluetooth
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/default
	[ -f $(DESTDIR)$(sysconfdir)/default/bluetooth ] || \
		$(INSTALL_DATA) $(srcdir)/bluetooth.default $(DESTDIR)$(sysconfdir)/default/bluetooth

uninstall-local:
	@rm -f $(DESTDIR)$(sysconfdir)/init.d/bluetooth
	@rm -f $(DESTDIR)$(sysconfdir)/default/bluetooth
endif
