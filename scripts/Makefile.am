# 
#  $Id$
#

bin_SCRIPTS = bluepin

install-data-local: @DISTRO@

unknown:
	-echo Unknown distribution 

redhat:
	$(mkinstalldirs) $(DESTDIR)/etc/rc.d/init.d
	$(INSTALL) -m 755 $(srcdir)/bluetooth.rc.rh $(DESTDIR)/etc/rc.d/init.d/bluetooth

debian:
	$(mkinstalldirs) $(DESTDIR)/etc/init.d
	$(INSTALL) -m 755 $(srcdir)/bluetooth.rc.deb $(DESTDIR)/etc/init.d/bluetooth
