# 
#  $Id$
#

bin_SCRIPTS = bluepin

EXTRA_DIST = bluepin bluetooth.rc.rh bluetooth.rc.deb create_dev

install-data-local:
	[ ! -f /etc/redhat-release -o ! -f /etc/mandrake-release ] || \
		$(INSTALL) -D -m 755 $(srcdir)/bluetooth.rc.rh $(DESTDIR)$(sysconfdir)/rc.d/init.d/bluetooth
	[ ! -f /etc/debian_version ] || \
		$(INSTALL) -D -m 755 $(srcdir)/bluetooth.rc.deb $(DESTDIR)$(sysconfdir)/init.d/bluetooth
