
confdir = $(sysconfdir)/bluetooth

conf_DATA = hcid.conf

statedir = $(localstatedir)/lib/bluetooth

state_DATA =

if DBUS
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = bluez-hcid.conf
endif

sbin_PROGRAMS = hcid

noinst_SCRIPTS = dbus-test

if DBUS
dbus_hcid_sources = dbus.h dbus.c
dbus_hcid_libs    = @DBUS_LIBS@
dbus_hcid_cflags  = -DENABLE_DBUS -DDBUS_API_SUBJECT_TO_CHANGE
else
dbus_hcid_sources =
dbus_hcid_libs    =
dbus_hcid_cflags  =
endif

hcid_SOURCES = main.c security.c storage.c hcid.h lib.c lib.h \
		parser.h parser.y lexer.l kword.h kword.c $(dbus_hcid_sources)

hcid_LDADD = $(dbus_hcid_libs) @BLUEZ_LIBS@ \
		$(top_builddir)/common/libglib-ectomy.a \
		$(top_builddir)/common/libtextfile.a

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ $(dbus_hcid_cflags)

INCLUDES = -I$(top_srcdir)/common

man_MANS = hcid.8 hcid.conf.5

AM_YFLAGS = -d

CLEANFILES = lexer.c parser.c parser.h

EXTRA_DIST = $(man_MANS) $(conf_DATA) dbus.h dbus.c dbus-test bluez-hcid.conf

MAINTAINERCLEANFILES = Makefile.in

pinfile = $(confdir)/pin

install-data-local:
	[ -f $(DESTDIR)$(pinfile) ] || \
		echo "BlueZ" > $(DESTDIR)$(pinfile); \
		chmod 600 $(DESTDIR)$(pinfile)

uninstall-local:
	@rm -f $(DESTDIR)$(pinfile)
