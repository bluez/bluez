# 
#  $Id$
#

bin_SCRIPTS = bluepin

EXTRA_DIST  = bluepin bluetooth.rc.rh bluetooth.rc.deb create_dev

install-data-local: @DISTRO@

unknown:
	-echo Unknown distribution 

redhat:
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL) -m 755 $(srcdir)/bluetooth.rc.rh $(DESTDIR)$(sysconfdir)/rc.d/init.d/bluetooth

debian:
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/init.d
	$(INSTALL) -m 755 $(srcdir)/bluetooth.rc.deb $(DESTDIR)$(sysconfdir)/init.d/bluetooth
