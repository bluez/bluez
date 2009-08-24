
AM_MAKEFLAGS = --no-print-directory

lib_LTLIBRARIES =

noinst_LTLIBRARIES =

bin_PROGRAMS =

sbin_PROGRAMS =

noinst_PROGRAMS =

dist_man_MANS =

dist_noinst_MANS =

CLEANFILES =

EXTRA_DIST =

includedir = @includedir@/bluetooth

include_HEADERS =

confdir = $(sysconfdir)/bluetooth

conf_DATA =

plugindir = $(libdir)/bluetooth/plugins

plugin_LTLIBRARIES =


lib_headers = lib/bluetooth.h lib/hci.h lib/hci_lib.h \
			lib/sco.h lib/l2cap.h lib/sdp.h lib/sdp_lib.h \
				lib/rfcomm.h lib/bnep.h lib/cmtp.h lib/hidp.h
local_headers = $(foreach file,$(lib_headers), lib/bluetooth/$(notdir $(file)))

include_HEADERS += $(lib_headers)

lib_LTLIBRARIES += lib/libbluetooth.la

lib_libbluetooth_la_SOURCES = $(lib_headers) \
					lib/bluetooth.c lib/hci.c lib/sdp.c
lib_libbluetooth_la_LDFLAGS = -version-info 6:0:3
lib_libbluetooth_la_DEPENDENCIES = $(local_headers)

CLEANFILES += $(local_headers)


if SBC
noinst_LTLIBRARIES += sbc/libsbc.la

sbc_libsbc_la_SOURCES = sbc/sbc.h sbc/sbc.c sbc/sbc_math.h sbc/sbc_tables.h \
			sbc/sbc_primitives.h sbc/sbc_primitives.c \
			sbc/sbc_primitives_mmx.h sbc/sbc_primitives_mmx.c \
			sbc/sbc_primitives_neon.h sbc/sbc_primitives_neon.c

sbc_libsbc_la_CFLAGS = -finline-functions -fgcse-after-reload \
					-funswitch-loops -funroll-loops

noinst_PROGRAMS += sbc/sbcinfo sbc/sbcdec sbc/sbcenc

sbc_sbcdec_SOURCES = sbc/sbcdec.c sbc/formats.h
sbc_sbcdec_LDADD = sbc/libsbc.la

sbc_sbcenc_SOURCES = sbc/sbcenc.c sbc/formats.h
sbc_sbcenc_LDADD = sbc/libsbc.la

if SNDFILE
noinst_PROGRAMS += sbc/sbctester

sbc_sbctester_LDADD = @SNDFILE_LIBS@
sbc_sbctest_CFLAGS = @SNDFILE_CFLAGS@
endif
endif


if NETLINK
plugin_LTLIBRARIES += plugins/netlink.la

plugins_netlink_la_LIBADD = @NETLINK_LIBS@
plugins_netlink_la_LDFLAGS = -module -avoid-version -no-undefined
plugins_netlink_la_CFLAGS = -fvisibility=hidden @DBUS_CFLAGS@ \
					@GLIB_CFLAGS@ @NETLINK_CFLAGS@
endif

gdbus_sources = gdbus/gdbus.h gdbus/mainloop.c gdbus/object.c gdbus/watch.c

builtin_modules =
builtin_sources =
builtin_nodist =

if ECHOPLUGIN
builtin_modules += echo
builtin_sources += plugins/echo.c
endif

if AUDIOPLUGIN
builtin_modules += audio
builtin_sources += audio/main.c \
			audio/manager.h audio/manager.c \
			audio/gateway.h audio/gateway.c \
			audio/headset.h audio/headset.c \
			audio/control.h audio/control.c \
			audio/device.h audio/device.c \
			audio/source.h audio/source.c \
			audio/sink.h audio/sink.c \
			audio/a2dp.h audio/a2dp.c \
			audio/avdtp.h audio/avdtp.c \
			audio/ipc.h audio/ipc.c \
			audio/unix.h audio/unix.c \
			audio/telephony.h
builtin_nodist += audio/telephony.c
endif

if INPUTPLUGIN
builtin_modules += input
builtin_sources += input/main.c \
			input/manager.h input/manager.c \
			input/server.h input/server.c \
			input/device.h input/device.c \
			input/fakehid.c input/fakehid.h
endif

if SERIALPLUGIN
builtin_modules += serial
builtin_sources += serial/main.c \
			serial/manager.h serial/manager.c \
			serial/proxy.h serial/proxy.c \
			serial/port.h serial/port.c
endif

if NETWORKPLUGIN
builtin_modules += network
builtin_sources += network/main.c \
			network/manager.h network/manager.c \
			network/common.h network/common.c \
			network/server.h network/server.c \
			network/bridge.h network/bridge.c \
			network/connection.h network/connection.c
endif

if SERVICEPLUGIN
builtin_modules += service
builtin_sources += plugins/service.c
endif

builtin_modules += hciops
builtin_sources += plugins/hciops.c

builtin_modules += hal
builtin_sources += plugins/hal.c

builtin_modules += storage
builtin_sources += plugins/storage.c

sbin_PROGRAMS += src/bluetoothd

src_bluetoothd_SOURCES = $(gdbus_sources) $(builtin_sources) \
			common/uinput.h common/ppoll.h \
			common/glib-helper.h common/glib-helper.c \
			common/btio.h common/btio.c \
			common/oui.h common/oui.c \
			common/textfile.h common/textfile.c \
			common/sdp-xml.h common/sdp-xml.c \
			src/main.c src/logging.h src/logging.c \
			src/security.c src/rfkill.c src/hcid.h src/sdpd.h \
			src/sdpd-server.c src/sdpd-request.c \
			src/sdpd-service.c src/sdpd-database.c \
			src/plugin.h src/plugin.c \
			src/storage.h src/storage.c \
			src/agent.h src/agent.c \
			src/error.h src/error.c \
			src/manager.h src/manager.c \
			src/adapter.h src/adapter.c \
			src/device.h src/device.c \
			src/dbus-common.c src/dbus-common.h \
			src/dbus-hci.h src/dbus-hci.c
src_bluetoothd_LDADD = lib/libbluetooth.la @GLIB_LIBS@ @DBUS_LIBS@ -ldl
src_bluetoothd_LDFLAGS = -Wl,--export-dynamic

builtin_files = src/builtin.h $(builtin_nodist)

nodist_src_bluetoothd_SOURCES = $(builtin_files)

CLEANFILES += $(builtin_files)

man_MANS = src/bluetoothd.8

if CONFIGFILES
conf_DATA += src/main.conf
endif

EXTRA_DIST += src/genbuiltin src/main.conf network/network.conf \
			input/input.conf serial/serial.conf \
			audio/audio.conf audio/telephony-dummy.c \
			audio/telephony-maemo.c audio/telephony-ofono.c


include Makefile.audio
include Makefile.tools

if UDEVRULES
rulesdir = @UDEV_DATADIR@

udev_files = scripts/bluetooth.rules

if HID2HCI
udev_files += scripts/bluetooth-hid2hci.rules
endif

if PCMCIA
udev_files += scripts/bluetooth-serial.rules
endif

rules_DATA = $(foreach file,$(udev_files), scripts/97-$(notdir $(file)))
endif

CLEANFILES += $(rules_DATA)

EXTRA_DIST += scripts/bluetooth.rules \
		scripts/bluetooth-hid2hci.rules scripts/bluetooth-serial.rules

if PCMCIA
udevdir = $(libexecdir)/udev

dist_udev_SCRIPTS = scripts/bluetooth_serial
endif

EXTRA_DIST += doc/manager-api.txt \
		doc/adapter-api.txt doc/device-api.txt \
		doc/service-api.txt doc/agent-api.txt \
		doc/serial-api.txt doc/network-api.txt \
		doc/input-api.txt doc/audio-api.txt doc/control-api.txt

AM_YFLAGS = -d

AM_CFLAGS = @DBUS_CFLAGS@ @GLIB_CFLAGS@ \
		-DBLUETOOTH_PLUGIN_BUILTIN -DPLUGINDIR=\""$(plugindir)"\"

INCLUDES = -I$(builddir)/lib \
			-I$(builddir)/src -I$(srcdir)/src -I$(srcdir)/common \
			-I$(srcdir)/audio -I$(srcdir)/sbc -I$(srcdir)/gdbus


pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = bluez.pc

DISTCHECK_CONFIGURE_FLAGS = --disable-udevrules

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs ylwrap

src/plugin.$(OBJEXT): src/builtin.h

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

audio/telephony.c: audio/@TELEPHONY_DRIVER@
	$(AM_V_GEN)$(LN_S) $(abs_top_srcdir)/$< $@

scripts/%.rules:
	$(AM_V_GEN)cp $(subst 97-,,$@) $@

$(lib_libbluetooth_la_OBJECTS): $(local_headers)

lib/bluetooth/%.h: lib/%.h
	$(AM_V_at)if [ ! -e lib/bluetooth ] ; then mkdir lib/bluetooth ; fi
	$(AM_V_GEN)$(LN_S) $(abs_top_srcdir)/$< $@

clean-local: lib/bluetooth
	@rm -r $<
