# 
#  $Id$
#

bin_SCRIPTS = bluepin

EXTRA_DIST = bluepin bluetooth.init bluetooth.default create_dev

install-data-local:
	$(INSTALL) -D -m 755 $(srcdir)/bluetooth.init $(DESTDIR)$(sysconfdir)/init.d/bluetooth
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/default
	[ -f $(DESTDIR)$(sysconfdir)/default/bluetooth ] || \
		$(INSTALL_DATA) $(srcdir)/bluetooth.default $(DESTDIR)$(sysconfdir)/default/bluetooth
