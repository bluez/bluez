
if DUND
bin_PROGRAMS = dund

dund_SOURCES = main.c dun.c dund.h sdp.c lib.h msdun.c

dund_LDADD = @BLUEZ_LIBS@
endif

AM_CFLAGS = @BLUEZ_CFLAGS@

if DUND
if MANPAGES
man_MANS = dund.1
endif
endif

EXTRA_DIST = dund.1

MAINTAINERCLEANFILES = Makefile.in
