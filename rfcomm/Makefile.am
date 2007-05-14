
if CONFIGFILES
confdir = $(sysconfdir)/bluetooth

conf_DATA = rfcomm.conf
endif

bin_PROGRAMS = rfcomm

rfcomm_SOURCES = main.c parser.h parser.y lexer.l kword.h kword.c
rfcomm_LDADD = @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

BUILT_SOURCES = parser.h

if MANPAGES
man_MANS = rfcomm.1
endif

AM_YFLAGS = -d

CLEANFILES = lexer.c parser.c parser.h

EXTRA_DIST = rfcomm.1 rfcomm.conf

MAINTAINERCLEANFILES = Makefile.in
