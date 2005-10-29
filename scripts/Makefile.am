
if BLUEPIN
bin_SCRIPTS = bluepin
endif

EXTRA_DIST = bluepin bluetooth.init bluetooth.default create_dev

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
