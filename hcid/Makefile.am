#
#  $Id$
#

sbin_PROGRAMS = hcid

hcid_SOURCES = main.c security.c hcid.h lib.c lib.h parser.h parser.y lexer.l kword.h kword.c glib-ectomy.h glib-ectomy.c
hcid_CONFIG  = hcid.conf

YFLAGS   = -d

CLEANFILES = lexer.c parser.c parser.h

EXTRA_DIST = $(hcid_CONFIG)

#
# Install configuration files
# 
confdir   = $(prefix)/etc/bluetooth
conf_FILE = $(confdir)/$(hcid_CONFIG)
pin_FILE  = $(confdir)/pin

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(confdir)
	[ -f $(DESTDIR)$(conf_FILE) ] || \
		$(INSTALL_DATA) $(srcdir)/$(hcid_CONFIG) $(DESTDIR)$(conf_FILE)
	[ -f $(DESTDIR)$(pin_FILE) ]  || \
		echo "BlueZ" > $(DESTDIR)$(pin_FILE); \
		chmod 600 $(DESTDIR)$(pin_FILE)
