#
#  $Id$
#

sbin_PROGRAMS = hcid

if DBUS
dbus_hcid_sources = dbus.c
dbus_hcid_libs    = @DBUS_LIBS@
dbus_hcid_cflags  = -DENABLE_DBUS -DDBUS_API_SUBJECT_TO_CHANGE
else
dbus_hcid_sources =
dbus_hcid_libs    =
dbus_hcid_cflags  =
endif

hcid_SOURCES = main.c security.c hcid.h lib.c lib.h parser.h parser.y lexer.l kword.h kword.c glib-ectomy.h glib-ectomy.c $(dbus_hcid_sources)
hcid_CONFIG  = hcid.conf

LIBS = $(dbus_hcid_libs) @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ $(dbus_hcid_cflags)

man_MANS = hcid.8 hcid.conf.5

AM_YFLAGS = -d

CLEANFILES = lexer.c parser.c parser.h

EXTRA_DIST = $(hcid_CONFIG) $(man_MANS) dbus.c

MAINTAINERCLEANFILES = Makefile.in

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

uninstall-local:
	@rm -f $(DESTDIR)$(conf_FILE)
	@rm -f $(DESTDIR)$(pin_FILE)
