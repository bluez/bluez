#
#  $Id$
#

sbin_PROGRAMS = sdpd

sdpd_SOURCES = main.c request.c service.c cstate.c servicedb.c sdpd.h

LIBS = @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@

man_MANS = sdpd.8

EXTRA_DIST = $(man_MANS)
