
DOC_MODULE = bluez

DOC_MAIN_SGML_FILE = $(DOC_MODULE)-docs.xml

DOC_SOURCE_DIR = ../src

SCAN_OPTIONS = --rebuild-sections

MKDB_OPTIONS = --sgml-mode --output-format=xml --tmpl-dir=. \
					--source-suffixes=c,h

MKTMPL_OPTIONS = --output-dir=.

HFILE_GLOB = $(top_srcdir)/src/*.h
CFILE_GLOB = $(top_srcdir)/src/*.c

IGNORE_HFILES =

MAINTAINERCLEANFILES = Makefile.in \
	$(DOC_MODULE).types $(DOC_MODULE)-*.txt *.sgml

if ENABLE_GTK_DOC
include $(top_srcdir)/doc/gtk-doc.make
else
EXTRA_DIST = $(DOC_MAIN_SGML_FILE) $(content_files)
endif

EXTRA_DIST += manager-api.txt adapter-api.txt device-api.txt \
		service-api.txt agent-api.txt serial-api.txt \
		network-api.txt input-api.txt audio-api.txt control-api.txt
