
noinst_LTLIBRARIES = libsbc.la

libsbc_la_SOURCES = sbc.h sbc.c sbc_math.h sbc_tables.h

noinst_PROGRAMS = sbcinfo sbcdec sbcenc

sbcdec_LDADD = libsbc.la

sbcenc_LDADD = libsbc.la

MAINTAINERCLEANFILES = Makefile.in
