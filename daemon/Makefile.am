
if GLIB
noinst_PROGRAMS = bluetoothd bt.echod

bluetoothd_SOURCES = main.c

bluetoothd_LDADD = @GLIB_LIBS@ @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

bt_echod_SOURCES = echo.c

bt_echod_LDADD = @GLIB_LIBS@ @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

BUILT_SOURCES = service-agent-glue.h

CLEANFILES = $(BUILT_SOURCES)
endif

EXTRA_DIST = service-agent.xml

MAINTAINERCLEANFILES = Makefile.in

service-agent-glue.h: service-agent.xml
	$(DBUS_BINDING_TOOL) --prefix=service_agent --mode=glib-server --output=$@ $(srcdir)/$<
