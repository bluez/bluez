# 
#  $Id$
#

pcmciadir = /etc/pcmcia

install-data-local: @PCMCIA@

pcmcia:
	$(mkinstalldirs) $(DESTDIR)$(pcmciadir)
	$(INSTALL) -m 755 $(srcdir)/bluetooth $(DESTDIR)$(pcmciadir)
	$(INSTALL) -m 644 $(srcdir)/bluetooth.conf $(DESTDIR)$(pcmciadir)
