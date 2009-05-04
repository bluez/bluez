
plugindir = $(libdir)/bluetooth/plugins

plugin_LTLIBRARIES =

builtin_modules =
builtin_sources =
builtin_cflags =

if SERVICEPLUGIN
builtin_modules += service
builtin_sources += service.c
endif

builtin_modules += hciops
builtin_sources += hciops.c

if NETLINK
plugin_LTLIBRARIES += netlink.la
netlink_la_LIBADD = @NETLINK_LIBS@
endif

builtin_modules += hal
builtin_sources += hal.c

builtin_modules += storage
builtin_sources += storage.c

noinst_LTLIBRARIES = libbuiltin.la echo.la

libbuiltin_la_SOURCES = $(builtin_sources)
libbuiltin_la_LDFLAGS =
libbuiltin_la_CFLAGS = $(AM_CFLAGS) \
			$(builtin_cflags) -DBLUETOOTH_PLUGIN_BUILTIN

BUILT_SOURCES = builtin.h

nodist_libbuiltin_la_SOURCES = $(BUILT_SOURCES)

AM_LDFLAGS = -module -avoid-version -no-undefined

AM_CFLAGS = -fvisibility=hidden @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ \
			@GLIB_CFLAGS@ @GDBUS_CFLAGS@ @NETLINK_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/src

CLEANFILES = $(BUILT_SOURCES)

MAINTAINERCLEANFILES = Makefile.in

builtin.h:
	echo "" > $@
	list='$(builtin_modules)'; for i in $$list; \
	  do echo "extern struct bluetooth_plugin_desc __bluetooth_builtin_$$i;" >> $@; done
	echo "" >> $@
	echo "static struct bluetooth_plugin_desc *__bluetooth_builtin[] = {" >> $@
	list='$(builtin_modules)'; for i in $$list; \
	  do echo "&__bluetooth_builtin_$$i," >> $@; done
	echo "NULL };" >> $@

all-local:
	@$(LN_S) -f $(top_srcdir)/input/.libs/input.so
	@$(LN_S) -f $(top_srcdir)/audio/.libs/audio.so
	@$(LN_S) -f $(top_srcdir)/serial/.libs/serial.so
	@$(LN_S) -f $(top_srcdir)/network/.libs/network.so

clean-local:
	@rm -f network.so
	@rm -f serial.so
	@rm -f audio.so
	@rm -f input.so
