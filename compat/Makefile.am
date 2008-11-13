
bin_PROGRAMS =
man_MANS =

if HIDD
bin_PROGRAMS += hidd

hidd_SOURCES = hidd.c hidd.h sdp.h sdp.c fakehid.c

hidd_LDADD = $(top_builddir)/common/libhelper.a @BLUEZ_LIBS@ -lm

if MANPAGES
man_MANS += hidd.1
endif
endif

if PAND
bin_PROGRAMS += pand

pand_SOURCES = pand.c pand.h bnep.c sdp.h sdp.c

pand_LDADD = $(top_builddir)/common/libhelper.a @BLUEZ_LIBS@

if MANPAGES
man_MANS += pand.1
endif
endif

if DUND
bin_PROGRAMS += dund

dund_SOURCES = dund.c dund.h lib.h sdp.h sdp.c dun.c msdun.c

dund_LDADD = $(top_builddir)/common/libhelper.a @BLUEZ_LIBS@

if MANPAGES
man_MANS += dund.1
endif
endif

AM_CFLAGS = @BLUEZ_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = fakehid.txt hidd.1 pand.1 dund.1

MAINTAINERCLEANFILES = Makefile.in
