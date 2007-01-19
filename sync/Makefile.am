
if SYNC
noinst_PROGRAMS = bluetoothd-service-sync

bluetoothd_service_sync_SOURCES = main.c

LDADD = $(top_builddir)/common/libhelper.a \
	@OPENSYNC_LIBS@ @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @OPENSYNC_CFLAGS@

INCLUDES = -I$(top_srcdir)/common
endif

MAINTAINERCLEANFILES = Makefile.in
