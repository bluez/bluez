
AM_MAKEFLAGS = --no-print-directory

lib_LTLIBRARIES =

noinst_LIBRARIES =

noinst_LTLIBRARIES =

bin_PROGRAMS =

libexec_PROGRAMS =

noinst_PROGRAMS =

dist_man_MANS =

dist_noinst_MANS =

CLEANFILES =

EXTRA_DIST =

includedir = @includedir@/bluetooth

include_HEADERS =

AM_CFLAGS = $(WARNING_CFLAGS) $(MISC_CFLAGS)
AM_LDFLAGS = $(MISC_LDFLAGS)

if DATAFILES
dbusdir = $(sysconfdir)/dbus-1/system.d
dbusservicedir = $(datadir)/dbus-1/system-services

dbus_DATA = src/bluetooth.conf
dbusservice_DATA = src/org.bluez.service

confdir = $(sysconfdir)/bluetooth

conf_DATA =

statedir = $(localstatedir)/lib/bluetooth

state_DATA =

if SYSTEMD
systemdunitdir = @SYSTEMD_UNITDIR@

systemdunit_DATA = src/bluetooth.service
endif
endif

EXTRA_DIST += src/bluetooth.service.in

plugindir = $(libdir)/bluetooth/plugins

if MAINTAINER_MODE
build_plugindir = $(abs_top_srcdir)/plugins/.libs
else
build_plugindir = $(plugindir)
endif


plugin_LTLIBRARIES =


lib_headers = lib/bluetooth.h lib/hci.h lib/hci_lib.h lib/mgmt.h \
		lib/sco.h lib/l2cap.h lib/sdp.h lib/sdp_lib.h lib/uuid.h \
		lib/rfcomm.h lib/bnep.h lib/cmtp.h lib/hidp.h lib/a2mp.h \
		lib/amp.h
local_headers = $(foreach file,$(lib_headers), lib/bluetooth/$(notdir $(file)))

BUILT_SOURCES = $(local_headers) src/builtin.h

include_HEADERS += $(lib_headers)

lib_LTLIBRARIES += lib/libbluetooth.la

lib_libbluetooth_la_SOURCES = $(lib_headers) \
				lib/bluetooth.c lib/hci.c lib/sdp.c lib/uuid.c
lib_libbluetooth_la_LDFLAGS = $(AM_LDFLAGS) -version-info 16:0:13
lib_libbluetooth_la_DEPENDENCIES = $(local_headers)

noinst_LTLIBRARIES += lib/libbluetooth-private.la

lib_libbluetooth_private_la_SOURCES = $(lib_libbluetooth_la_SOURCES)

attrib_sources = attrib/att.h attrib/att-database.h attrib/att.c \
		attrib/gatt.h attrib/gatt.c \
		attrib/gattrib.h attrib/gattrib.c attrib/client.h \
		attrib/client.c attrib/gatt-service.h attrib/gatt-service.c

gdbus_sources = gdbus/gdbus.h gdbus/mainloop.c gdbus/watch.c \
					gdbus/object.c gdbus/polkit.c

btio_sources = btio/btio.h btio/btio.c

gobex_sources = gobex/gobex.h gobex/gobex.c \
			gobex/gobex-defs.h gobex/gobex-defs.c \
			gobex/gobex-packet.c gobex/gobex-packet.h \
			gobex/gobex-header.c gobex/gobex-header.h \
			gobex/gobex-transfer.c gobex/gobex-debug.h \
			gobex/gobex-apparam.c gobex/gobex-apparam.h

builtin_modules =
builtin_sources =
builtin_nodist =

include Makefile.plugins
include Makefile.profiles

if SAPPLUGIN
builtin_modules += sap
builtin_sources += profiles/sap/main.c profiles/sap/manager.h \
			profiles/sap/manager.c profiles/sap/server.h \
			profiles/sap/server.c profiles/sap/sap.h

builtin_nodist += profiles/sap/sap.c

noinst_LIBRARIES += profiles/sap/libsap.a

profiles_sap_libsap_a_SOURCES = profiles/sap/sap.h profiles/sap/sap-dummy.c \
				profiles/sap/sap-u8500.c
endif

if MAINTAINER_MODE
plugin_LTLIBRARIES += plugins/external-dummy.la
plugins_external_dummy_la_SOURCES = plugins/external-dummy.c
plugins_external_dummy_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version \
				    -no-undefined
plugins_external_dummy_la_CFLAGS = $(AM_CFLAGS) -fvisibility=hidden
endif

libexec_PROGRAMS += src/bluetoothd

src_bluetoothd_SOURCES = $(gdbus_sources) $(builtin_sources) \
			$(attrib_sources) $(btio_sources) \
			src/bluetooth.ver \
			src/main.c src/log.h src/log.c \
			src/systemd.h src/systemd.c \
			src/rfkill.c src/hcid.h src/sdpd.h \
			src/sdpd-server.c src/sdpd-request.c \
			src/sdpd-service.c src/sdpd-database.c \
			src/attrib-server.h src/attrib-server.c \
			src/sdp-xml.h src/sdp-xml.c \
			src/sdp-client.h src/sdp-client.c \
			src/textfile.h src/textfile.c \
			src/glib-helper.h src/glib-helper.c \
			src/uinput.h \
			src/plugin.h src/plugin.c \
			src/storage.h src/storage.c \
			src/agent.h src/agent.c \
			src/error.h src/error.c \
			src/manager.h src/manager.c \
			src/adapter.h src/adapter.c \
			src/profile.h src/profile.c \
			src/device.h src/device.c src/attio.h \
			src/dbus-common.c src/dbus-common.h \
			src/eir.h src/eir.c src/mgmt.c src/mgmt.h
src_bluetoothd_LDADD = lib/libbluetooth-private.la @GLIB_LIBS@ @DBUS_LIBS@ \
								-ldl -lrt
src_bluetoothd_LDFLAGS = $(AM_LDFLAGS) -Wl,--export-dynamic \
				-Wl,--version-script=$(srcdir)/src/bluetooth.ver

src_bluetoothd_DEPENDENCIES = lib/libbluetooth-private.la \
						src/bluetooth.service

src_bluetoothd_CFLAGS = $(AM_CFLAGS) -DBLUETOOTH_PLUGIN_BUILTIN \
					-DPLUGINDIR=\""$(build_plugindir)"\"
src_bluetoothd_SHORTNAME = bluetoothd

builtin_files = src/builtin.h $(builtin_nodist)

nodist_src_bluetoothd_SOURCES = $(builtin_files)

CLEANFILES += $(builtin_files) src/bluetooth.service

man_MANS = src/bluetoothd.8

if DATAFILES
conf_DATA += src/main.conf
endif

EXTRA_DIST += src/genbuiltin src/bluetooth.conf src/org.bluez.service \
			src/main.conf profiles/network/network.conf \
			profiles/input/input.conf profiles/proximity/proximity.conf \
			profiles/audio/audio.conf \
			profiles/sap/sap-dummy.c profiles/sap/sap-u8500.c

include Makefile.tools
include Makefile.obexd

if DATAFILES
rulesdir = @UDEV_DIR@/rules.d

udev_files =

if HID2HCI
udev_files += scripts/bluetooth-hid2hci.rules
endif

rules_DATA = $(foreach file,$(udev_files), scripts/97-$(notdir $(file)))
endif

CLEANFILES += $(rules_DATA)

EXTRA_DIST += scripts/bluetooth-hid2hci.rules

EXTRA_DIST += doc/adapter-api.txt doc/device-api.txt doc/profile-api.txt \
		doc/service-api.txt doc/agent-api.txt doc/attribute-api.txt \
		doc/network-api.txt doc/control-api.txt doc/health-api.txt \
		doc/sap-api.txt doc/media-api.txt doc/assigned-numbers.txt \
		doc/supported-features.txt doc/alert-api.txt doc/mgmt-api.txt \
		doc/oob-api.txt doc/proximity-api.txt doc/heartrate-api.txt \
		doc/thermometer-api.txt doc/audio-telephony-design.txt \
		doc/cyclingspeed-api.txt

AM_CFLAGS += @DBUS_CFLAGS@ @GLIB_CFLAGS@

AM_CPPFLAGS = -I$(builddir)/lib -I$(builddir)/src -I$(srcdir)/src \
			-I$(srcdir)/gdbus -I$(srcdir)/btio


unit_tests = unit/test-eir unit/test-uuid unit/test-textfile

unit_test_eir_SOURCES = unit/test-eir.c src/eir.c src/glib-helper.c
unit_test_eir_LDADD = lib/libbluetooth-private.la @GLIB_LIBS@

unit_test_uuid_SOURCES = unit/test-uuid.c
unit_test_uuid_LDADD = lib/libbluetooth-private.la @GLIB_LIBS@

unit_test_textfile_SOURCES = unit/test-textfile.c src/textfile.h src/textfile.c
unit_test_textfile_LDADD = @GLIB_LIBS@

unit_tests += unit/test-gobex-header unit/test-gobex-packet unit/test-gobex \
			unit/test-gobex-transfer unit/test-gobex-apparam

unit_test_gobex_SOURCES = $(gobex_sources) unit/util.c unit/util.h \
						unit/test-gobex.c
unit_test_gobex_LDADD = @GLIB_LIBS@

unit_test_gobex_packet_SOURCES = $(gobex_sources) unit/util.c unit/util.h \
						unit/test-gobex-packet.c
unit_test_gobex_packet_LDADD = @GLIB_LIBS@

unit_test_gobex_header_SOURCES = $(gobex_sources) unit/util.c unit/util.h \
						unit/test-gobex-header.c
unit_test_gobex_header_LDADD = @GLIB_LIBS@

unit_test_gobex_transfer_SOURCES = $(gobex_sources) unit/util.c unit/util.h \
						unit/test-gobex-transfer.c
unit_test_gobex_transfer_LDADD = @GLIB_LIBS@

unit_test_gobex_apparam_SOURCES = $(gobex_sources) unit/util.c unit/util.h \
						unit/test-gobex-apparam.c
unit_test_gobex_apparam_LDADD = @GLIB_LIBS@

noinst_PROGRAMS += $(unit_tests)

TESTS = $(unit_tests)

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = bluez.pc

DISTCHECK_CONFIGURE_FLAGS = --disable-datafiles

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs

SED_PROCESS = $(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
		$(SED) -e 's,@libexecdir\@,$(libexecdir),g' \
		< $< > $@

%.service: %.service.in Makefile
	$(SED_PROCESS)

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

profiles/sap/sap.c: profiles/sap/@SAP_DRIVER@
	$(AM_V_GEN)$(LN_S) -f $(abs_top_srcdir)/$< $@

scripts/%.rules:
	$(AM_V_GEN)cp $(subst 97-,,$@) $@

$(lib_libbluetooth_la_OBJECTS): $(local_headers)

lib/bluetooth/%.h: lib/%.h
	$(AM_V_at)$(MKDIR_P) lib/bluetooth
	$(AM_V_GEN)$(LN_S) -f $(abs_top_builddir)/$< $@

clean-local:
	$(RM) -r lib/bluetooth
