#
#  $Id$
#

mandir = $(prefix)/share/man

sbin_PROGRAMS = hcid

if ENABLE_DBUS
dbus_hcid_sources = dbus.c
else
dbus_hcid_sources =
endif

hcid_SOURCES = main.c security.c hcid.h lib.c lib.h parser.h parser.y lexer.l kword.h kword.c glib-ectomy.h glib-ectomy.c $(dbus_hcid_sources)
hcid_CONFIG  = hcid.conf

man_MANS = hcid.8 hcid.conf.5

YFLAGS   = -d

CLEANFILES = lexer.c parser.c parser.h

EXTRA_DIST = $(hcid_CONFIG) $(man_MANS) dbus.c

#
# Install configuration files
# 
confdir   = $(sysconfdir)/bluetooth
conf_FILE = $(confdir)/$(hcid_CONFIG)
pin_FILE  = $(confdir)/pin

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(confdir)
	[ -f $(DESTDIR)$(conf_FILE) ] || \
		$(INSTALL_DATA) $(srcdir)/$(hcid_CONFIG) $(DESTDIR)$(conf_FILE)
	[ -f $(DESTDIR)$(pin_FILE) ]  || \
		echo "BlueZ" > $(DESTDIR)$(pin_FILE); \
		chmod 600 $(DESTDIR)$(pin_FILE)
