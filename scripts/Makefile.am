# 
#  $Id$
#

bin_SCRIPTS = bluepin

EXTRA_DIST = bluepin bluetooth.init bluetooth.default create_dev

install-data-local:
	$(INSTALL) -D -m 755 $(srcdir)/bluetooth.init $(DESTDIR)$(sysconfdir)/init.d/bluetooth
	$(INSTALL) -D -m 644 $(srcdir)/bluetooth.default $(DESTDIR)$(sysconfdir)/default/bluetooth
