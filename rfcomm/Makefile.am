#  
#  $Id$
#

confdir = $(sysconfdir)/bluetooth

bin_PROGRAMS = rfcomm

rfcomm_SOURCES = main.c parser.h parser.y lexer.l kword.h kword.c
rfcomm_CONFIG  = rfcomm.conf

man_MANS = rfcomm.1

YFLAGS = -d

CLEANFILES = lexer.c parser.c parser.h

EXTRA_DIST = $(man_MANS) $(rfcomm_CONFIG)

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(confdir)
	[ -f $(DESTDIR)$(confdir)/$(rfcomm_CONFIG) ] || \
		$(INSTALL_DATA) $(srcdir)/$(rfcomm_CONFIG) $(DESTDIR)$(confdir)/$(rfcomm_CONFIG)
