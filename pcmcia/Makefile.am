# 
#  $Id$
#

pcmciadir = $(sysconfdir)/pcmcia

EXTRA_DIST = bluetooth bluetooth.conf

MAINTAINERCLEANFILES = Makefile.in

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pcmciadir)
	[ -f $(DESTDIR)$(pcmciadir)/bluetooth ] || \
		$(INSTALL_DATA) $(srcdir)/bluetooth $(DESTDIR)$(pcmciadir)
	[ -f $(DESTDIR)$(pcmciadir)/bluetooth.conf ] || \
		$(INSTALL_DATA) $(srcdir)/bluetooth.conf $(DESTDIR)$(pcmciadir)
