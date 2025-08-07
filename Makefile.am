# SPDX-License-Identifier: GPL-2.0
AM_MAKEFLAGS = --no-print-directory
AM_CPPFLAGS =

lib_LTLIBRARIES =

noinst_LIBRARIES =

noinst_LTLIBRARIES =

bin_PROGRAMS =

noinst_PROGRAMS =

CLEANFILES =

EXTRA_DIST =

pkglibexecdir = @PKGLIBEXECDIR@

pkglibexec_PROGRAMS =

pkgincludedir = $(includedir)/bluetooth

pkginclude_HEADERS =

AM_CFLAGS = $(MISC_CFLAGS) $(WARNING_CFLAGS) $(UDEV_CFLAGS) $(LIBEBOOK_CFLAGS) \
				$(LIBEDATASERVER_CFLAGS) $(ell_cflags)
AM_LDFLAGS = $(MISC_LDFLAGS)

confdir = $(sysconfdir)/bluetooth
statedir = $(localstatedir)/lib/bluetooth

bluetoothd-fix-permissions:
	install -dm755 $(DESTDIR)$(confdir)
	install -dm700 $(DESTDIR)$(statedir)

if DATAFILES
dbusdir = $(DBUS_CONFDIR)/dbus-1/system.d
dbus_DATA = src/bluetooth.conf

if OBEX
dbus_DATA += obexd/src/obex.conf
endif

conf_DATA = src/main.conf
conf_DATA += profiles/input/input.conf
conf_DATA += profiles/network/network.conf
state_DATA =
endif

if SYSTEMD
systemdsystemunitdir = $(SYSTEMD_SYSTEMUNITDIR)
systemdsystemunit_DATA = src/bluetooth.service

systemduserunitdir = $(SYSTEMD_USERUNITDIR)
systemduserunit_DATA =

dbussystembusdir = $(DBUS_SYSTEMBUSDIR)
dbussystembus_DATA = src/org.bluez.service
endif

EXTRA_DIST += src/org.bluez.service

plugindir = $(libdir)/bluetooth/plugins

build_plugindir = $(plugindir)

if MANPAGES
man_MANS =
endif
manual_pages =

plugin_LTLIBRARIES =

lib_sources = lib/bluetooth/bluetooth.c lib/bluetooth/hci.c lib/bluetooth/sdp.c
lib_headers = lib/bluetooth/bluetooth.h lib/bluetooth/hci.h lib/bluetooth/hci_lib.h \
		lib/bluetooth/sco.h lib/bluetooth/l2cap.h lib/bluetooth/sdp.h lib/bluetooth/sdp_lib.h \
		lib/bluetooth/rfcomm.h lib/bluetooth/bnep.h lib/bluetooth/cmtp.h lib/bluetooth/hidp.h

extra_headers = lib/bluetooth/mgmt.h lib/bluetooth/uuid.h lib/bluetooth/iso.h
extra_sources = lib/bluetooth/uuid.c

BUILT_SOURCES = $(ell_built_sources) src/builtin.h

if LIBRARY
pkginclude_HEADERS += $(lib_headers)

lib_LTLIBRARIES += lib/libbluetooth.la

lib_libbluetooth_la_SOURCES = $(lib_headers) $(lib_sources)
lib_libbluetooth_la_LDFLAGS = $(AM_LDFLAGS) -version-info 22:15:19
endif

noinst_LTLIBRARIES += lib/libbluetooth-internal.la

lib_libbluetooth_internal_la_SOURCES = $(lib_headers) $(lib_sources) \
					$(extra_headers) $(extra_sources)

noinst_LTLIBRARIES += gdbus/libgdbus-internal.la

gdbus_libgdbus_internal_la_SOURCES = gdbus/gdbus.h \
				gdbus/mainloop.c gdbus/watch.c \
				gdbus/object.c gdbus/client.c gdbus/polkit.c

if EXTERNAL_ELL
ell_cflags = @ELL_CFLAGS@
ell_ldadd = @ELL_LIBS@
ell_built_sources = ell/shared
else
ell_cflags =
ell_ldadd = ell/libell-internal.la
ell_built_sources = ell/shared ell/internal ell/ell.h

noinst_LTLIBRARIES += ell/libell-internal.la

ell_headers = ell/util.h \
			ell/log.h \
			ell/queue.h \
			ell/hashmap.h \
			ell/random.h \
			ell/signal.h \
			ell/time.h \
			ell/time-private.h \
			ell/timeout.h \
			ell/cipher.h \
			ell/checksum.h \
			ell/io.h \
			ell/idle.h \
			ell/main.h \
			ell/settings.h \
			ell/strv.h \
			ell/string.h \
			ell/utf8.h \
			ell/dbus.h \
			ell/dbus-service.h \
			ell/dbus-client.h \
			ell/key.h \
			ell/cert.h \
			ell/pem.h \
			ell/base64.h \
			ell/asn1-private.h \
			ell/cert-private.h \
			ell/pem-private.h \
			ell/uuid.h \
			ell/useful.h \
			ell/main-private.h \
			ell/tester.h \
			ell/tls.h \
			ell/tls-private.h \
			ell/ecc.h \
			ell/ecc-private.h \
			ell/cleanup.h \
			ell/ecdh.h

ell_sources = ell/private.h ell/missing.h \
			ell/util.c \
			ell/log.c \
			ell/queue.c \
			ell/hashmap.c \
			ell/random.c \
			ell/signal.c \
			ell/time.c \
			ell/timeout.c \
			ell/io.c \
			ell/idle.c \
			ell/main.c \
			ell/settings.c \
			ell/strv.c \
			ell/string.c \
			ell/cipher.c \
			ell/checksum.c \
			ell/pem.c \
			ell/cert.c \
			ell/cert-crypto.c \
			ell/key.c \
			ell/base64.c \
			ell/utf8.c \
			ell/dbus-private.h \
			ell/dbus.c \
			ell/dbus-message.c \
			ell/dbus-util.c \
			ell/dbus-service.c \
			ell/dbus-client.c \
			ell/dbus-name-cache.c \
			ell/dbus-filter.c \
			ell/gvariant-private.h \
			ell/gvariant-util.c \
			ell/siphash-private.h \
			ell/siphash.c \
			ell/uuid.c \
			ell/tester.c \
			ell/tls.c \
			ell/tls-extensions.c \
			ell/tls-suites.c \
			ell/tls-record.c \
			ell/ecc.c \
			ell/ecc-external.c \
			ell/ecdh.c

ell_shared = ell/useful.h

ell_libell_internal_la_SOURCES = $(ell_headers) $(ell_sources) $(ell_shared)
endif

CLEANFILES += $(ell_built_sources)

noinst_LTLIBRARIES += src/libshared-glib.la src/libshared-mainloop.la

if LIBSHARED_ELL
noinst_LTLIBRARIES += src/libshared-ell.la
endif

shared_sources = src/shared/io.h src/shared/timeout.h \
			src/shared/queue.h src/shared/queue.c \
			src/shared/util.h src/shared/util.c \
			src/shared/mgmt.h src/shared/mgmt.c \
			src/shared/crypto.h src/shared/crypto.c \
			src/shared/ecc.h src/shared/ecc.c \
			src/shared/ringbuf.h src/shared/ringbuf.c \
			src/shared/tester.h\
			src/shared/hci.h src/shared/hci.c \
			src/shared/hci-crypto.h src/shared/hci-crypto.c \
			src/shared/hfp.h src/shared/hfp.c \
			src/shared/uhid.h src/shared/uhid.c \
			src/shared/pcap.h src/shared/pcap.c \
			src/shared/btsnoop.h src/shared/btsnoop.c \
			src/shared/ad.h src/shared/ad.c \
			src/shared/att-types.h \
			src/shared/att.h src/shared/att.c \
			src/shared/gatt-helpers.h src/shared/gatt-helpers.c \
			src/shared/gatt-client.h src/shared/gatt-client.c \
			src/shared/gatt-server.h src/shared/gatt-server.c \
			src/shared/gatt-db.h src/shared/gatt-db.c \
			src/shared/gap.h src/shared/gap.c \
			src/shared/log.h src/shared/log.c \
			src/shared/bap.h src/shared/bap.c src/shared/ascs.h \
			src/shared/bap-debug.h src/shared/bap-debug.c \
			src/shared/mcs.h src/shared/mcp.h src/shared/mcp.c \
			src/shared/vcp.c src/shared/vcp.h \
			src/shared/micp.c src/shared/micp.h \
			src/shared/csip.c src/shared/csip.h \
			src/shared/bass.h src/shared/bass.c \
			src/shared/ccp.h src/shared/ccp.c \
			src/shared/lc3.h src/shared/tty.h \
			src/shared/bap-defs.h \
			src/shared/asha.h src/shared/asha.c

if READLINE
shared_sources += src/shared/shell.c src/shared/shell.h
endif

src_libshared_glib_la_SOURCES = $(shared_sources) \
				src/shared/io-glib.c \
				src/shared/timeout-glib.c \
				src/shared/mainloop-glib.c \
				src/shared/mainloop-notify.h \
				src/shared/mainloop-notify.c \
				src/shared/tester.c
src_libshared_glib_la_LDFLAGS = $(AM_LDFLAGS)
src_libshared_glib_la_CFLAGS = $(AM_CFLAGS)

src_libshared_mainloop_la_SOURCES = $(shared_sources) \
				src/shared/io-mainloop.c \
				src/shared/timeout-mainloop.c \
				src/shared/mainloop.h src/shared/mainloop.c \
				src/shared/mainloop-notify.h \
				src/shared/mainloop-notify.c
src_libshared_mainloop_la_LDFLAGS = $(AM_LDFLAGS)
src_libshared_mainloop_la_CFLAGS = $(AM_CFLAGS)

if LIBSHARED_ELL
src_libshared_ell_la_SOURCES = $(shared_sources) \
				src/shared/io-ell.c \
				src/shared/timeout-ell.c \
				src/shared/mainloop.h \
				src/shared/mainloop-ell.c
src_libshared_ell_la_LDFLAGS = $(AM_LDFLAGS)
src_libshared_ell_la_CFLAGS = $(AM_CFLAGS)
endif

attrib_sources = attrib/att.h attrib/att-database.h attrib/att.c \
		attrib/gatt.h attrib/gatt.c \
		attrib/gattrib.h attrib/gattrib.c

btio_sources = btio/btio.h btio/btio.c

gobex_sources = gobex/gobex.h gobex/gobex.c \
			gobex/gobex-defs.h gobex/gobex-defs.c \
			gobex/gobex-packet.c gobex/gobex-packet.h \
			gobex/gobex-header.c gobex/gobex-header.h \
			gobex/gobex-transfer.c gobex/gobex-debug.h \
			gobex/gobex-apparam.c gobex/gobex-apparam.h

builtin_modules =
builtin_sources =
builtin_cppflags =
builtin_ldadd =

include Makefile.plugins

pkglibexec_PROGRAMS += src/bluetoothd

src_bluetoothd_SOURCES = $(builtin_sources) \
			$(attrib_sources) $(btio_sources) \
			src/main.c src/log.h src/log.c \
			src/backtrace.h src/backtrace.c \
			src/rfkill.c src/btd.h src/sdpd.h \
			src/sdpd-server.c src/sdpd-request.c \
			src/sdpd-service.c src/sdpd-database.c \
			src/gatt-database.h src/gatt-database.c \
			src/sdp-xml.h src/sdp-xml.c \
			src/sdp-client.h src/sdp-client.c \
			src/textfile.h src/textfile.c \
			src/uuid-helper.h src/uuid-helper.c \
			src/plugin.h src/plugin.c \
			src/storage.h src/storage.c \
			src/advertising.h src/advertising.c \
			src/agent.h src/agent.c \
			src/error.h src/error.c \
			src/adapter.h src/adapter.c \
			src/profile.h src/profile.c \
			src/service.h src/service.c \
			src/gatt-client.h src/gatt-client.c \
			src/device.h src/device.c \
			src/dbus-common.c src/dbus-common.h \
			src/eir.h src/eir.c \
			src/adv_monitor.h src/adv_monitor.c \
			src/battery.h src/battery.c \
			src/settings.h src/settings.c \
			src/set.h src/set.c \
			src/bearer.h src/bearer.c
src_bluetoothd_LDADD = lib/libbluetooth-internal.la \
			gdbus/libgdbus-internal.la \
			src/libshared-glib.la \
			$(BACKTRACE_LIBS) $(GLIB_LIBS) $(DBUS_LIBS) -ldl -lrt \
			$(builtin_ldadd)

if EXTERNAL_PLUGINS
src_bluetoothd_SOURCES += src/bluetooth.ver
src_bluetoothd_LDFLAGS = $(AM_LDFLAGS) -Wl,--export-dynamic \
				-Wl,--version-script=$(srcdir)/src/bluetooth.ver
endif

src_bluetoothd_CPPFLAGS = $(AM_CPPFLAGS) -DBLUETOOTH_PLUGIN_BUILTIN \
					-DPLUGINDIR=\""$(build_plugindir)"\" \
					$(BACKTRACE_CFLAGS) $(builtin_cppflags)
src_bluetoothd_SHORTNAME = bluetoothd

builtin_files = src/builtin.h

nodist_src_bluetoothd_SOURCES = $(builtin_files)

CLEANFILES += $(builtin_files)

if MANPAGES
man_MANS += src/bluetoothd.8
man_MANS += doc/hci.7 doc/mgmt.7 doc/l2cap.7 doc/rfcomm.7 doc/sco.7 doc/iso.7
man_MANS += doc/org.bluez.Adapter.5 doc/org.bluez.Device.5 \
		doc/org.bluez.Bearer.LE.5 doc/org.bluez.Bearer.BREDR.5 \
		doc/org.bluez.DeviceSet.5 doc/org.bluez.AgentManager.5 \
		doc/org.bluez.Agent.5 doc/org.bluez.ProfileManager.5 \
		doc/org.bluez.Profile.5 doc/org.bluez.NetworkServer.5 \
		doc/org.bluez.Network.5 doc/org.bluez.Input.5 \
		doc/org.bluez.BatteryProviderManager.5 \
		doc/org.bluez.BatteryProvider.5 doc/org.bluez.Battery.5 \
		doc/org.bluez.AdminPolicySet.5 \
		doc/org.bluez.AdminPolicyStatus.5
man_MANS += doc/org.bluez.Media.5 doc/org.bluez.MediaControl.5 \
		doc/org.bluez.MediaPlayer.5 doc/org.bluez.MediaFolder.5 \
		doc/org.bluez.MediaItem.5 doc/org.bluez.MediaEndpoint.5 \
		doc/org.bluez.MediaTransport.5 doc/org.bluez.MediaAssistant.5
man_MANS += doc/org.bluez.GattManager.5 doc/org.bluez.GattProfile.5 \
		doc/org.bluez.GattService.5 \
		doc/org.bluez.GattCharacteristic.5 \
		doc/org.bluez.GattDescriptor.5 \
		doc/org.bluez.LEAdvertisingManager.5 \
		doc/org.bluez.LEAdvertisement.5 \
		doc/org.bluez.AdvertisementMonitorManager.5 \
		doc/org.bluez.AdvertisementMonitor.5
man_MANS += doc/org.bluez.obex.Client.5 doc/org.bluez.obex.Session.5 \
		doc/org.bluez.obex.Transfer.5 \
		doc/org.bluez.obex.ObjectPush.5 \
		doc/org.bluez.obex.FileTransfer.5 \
		doc/org.bluez.obex.Synchronization.5 \
		doc/org.bluez.obex.PhonebookAccess.5 \
		doc/org.bluez.obex.MessageAccess.5 \
		doc/org.bluez.obex.Message.5 \
		doc/org.bluez.obex.AgentManager.5 doc/org.bluez.obex.Agent.5 \
		doc/org.bluez.obex.Image.5
endif
manual_pages += src/bluetoothd.8
manual_pages += doc/hci.7 doc/mgmt.7 doc/l2cap.7 doc/rfcomm.7 doc/sco.7 \
		doc/iso.7
manual_pages += doc/org.bluez.Adapter.5 doc/org.bluez.Device.5 \
		doc/org.bluez.Bearer.LE.5 doc/org.bluez.Bearer.BREDR.5 \
		doc/org.bluez.DeviceSet.5 doc/org.bluez.AgentManager.5 \
		doc/org.bluez.Agent.5 doc/org.bluez.ProfileManager.5 \
		doc/org.bluez.Profile.5 doc/org.bluez.NetworkServer.5 \
		doc/org.bluez.Network.5 doc/org.bluez.Input.5\
		doc/org.bluez.BatteryProviderManager.5 \
		doc/org.bluez.BatteryProvider.5 doc/org.bluez.Battery.5 \
		doc/org.bluez.AdminPolicySet.5 \
		doc/org.bluez.AdminPolicyStatus.5
manual_pages += doc/org.bluez.Media.5 doc/org.bluez.MediaControl.5 \
		doc/org.bluez.MediaPlayer.5 doc/org.bluez.MediaFolder.5 \
		doc/org.bluez.MediaItem.5 doc/org.bluez.MediaEndpoint.5 \
		doc/org.bluez.MediaTransport.5 doc/org.bluez.MediaAssistant.5
manual_pages += doc/org.bluez.GattManager.5 doc/org.bluez.GattProfile.5 \
		doc/org.bluez.GattService.5 \
		doc/org.bluez.GattCharacteristic.5 \
		doc/org.bluez.GattDescriptor.5 \
		doc/org.bluez.LEAdvertisingManager.5 \
		doc/org.bluez.LEAdvertisement.5 \
		doc/org.bluez.AdvertisementMonitorManager.5 \
		doc/org.bluez.AdvertisementMonitor.5
manual_pages += doc/org.bluez.obex.Client.5 doc/org.bluez.obex.Session.5 \
		doc/org.bluez.obex.Transfer.5 \
		doc/org.bluez.obex.ObjectPush.5 \
		doc/org.bluez.obex.FileTransfer.5 \
		doc/org.bluez.obex.Synchronization.5 \
		doc/org.bluez.obex.PhonebookAccess.5 \
		doc/org.bluez.obex.MessageAccess.5 \
		doc/org.bluez.obex.Message.5 \
		doc/org.bluez.obex.AgentManager.5 doc/org.bluez.obex.Agent.5 \
		doc/org.bluez.obex.Image.5

EXTRA_DIST += src/genbuiltin src/bluetooth.conf \
			src/main.conf profiles/network/network.conf \
			profiles/input/input.conf obexd/src/obex.conf

test_scripts =
unit_tests =

include Makefile.tools
include Makefile.obexd
include Makefile.mesh

if SYSTEMD
install-data-hook: obexd-add-service-symlink
else
install-data-hook: bluetoothd-fix-permissions obexd-add-service-symlink
endif

uninstall-hook: obexd-remove-service-symlink

if HID2HCI
rulesdir = $(UDEV_DIR)/rules.d

rules_DATA = tools/97-hid2hci.rules

CLEANFILES += $(rules_DATA)
endif

EXTRA_DIST += tools/hid2hci.rules

if TEST
testdir = $(pkglibdir)/test
test_SCRIPTS = $(test_scripts)
endif

EXTRA_DIST += $(test_scripts)

EXTRA_DIST += doc/assigned-numbers.txt doc/supported-features.txt \
				doc/test-coverage.txt \
				doc/test-runner.rst \
				doc/settings-storage.txt

EXTRA_DIST += doc/health-api.txt \
		doc/sap-api.txt

EXTRA_DIST += doc/hci.rst doc/mgmt.rst doc/l2cap.rst doc/rfcomm.rst \
	      doc/sco.rst doc/iso.rst

EXTRA_DIST += doc/org.bluez.Adapter.rst doc/org.bluez.Device.rst \
		doc/org.bluez.Bearer.LE.rst doc/org.bluez.Bearer.BREDR.rst \
		doc/org.bluez.DeviceSet.rst doc/org.bluez.AgentManager.rst \
		doc/org.bluez.Agent.rst doc/org.bluez.ProfileManager.rst \
		doc/org.bluez.Profile.rst doc/org.bluez.NetworkServer.rst \
		doc/org.bluez.Network.rst doc/org.bluez.Input.rst \
		doc/org.bluez.BatteryProviderManager.rst \
		doc/org.bluez.BatteryProvider.rst doc/org.bluez.Battery.rst \
		doc/org.bluez.AdminPolicySet.rst \
		doc/org.bluez.AdminPolicyStatus.rst

EXTRA_DIST += doc/org.bluez.Media.rst doc/org.bluez.MediaControl.rst \
		doc/org.bluez.MediaPlayer.rst doc/org.bluez.MediaFolder.rst \
		doc/org.bluez.MediaItem.rst doc/org.bluez.MediaEndpoint.rst \
		doc/org.bluez.MediaTransport.rst doc/org.bluez.MediaAssistant.rst

EXTRA_DIST += doc/org.bluez.GattManager.rst doc/org.bluez.GattProfile.rst\
		doc/org.bluez.GattService.rst \
		doc/org.bluez.GattCharacteristic.rst \
		doc/org.bluez.GattDescriptor.rst \
		doc/org.bluez.LEAdvertisingManager.rst \
		doc/org.bluez.LEAdvertisement.rst \
		doc/org.bluez.AdvertisementMonitorManager.rst \
		doc/org.bluez.AdvertisementMonitor.rst

EXTRA_DIST += doc/org.bluez.obex.Client.rst doc/org.bluez.obex.Session.rst \
		doc/org.bluez.obex.Transfer.rst \
		doc/org.bluez.obex.ObjectPush.rst \
		doc/org.bluez.obex.FileTransfer.rst \
		doc/org.bluez.obex.Synchronization.rst \
		doc/org.bluez.obex.PhonebookAccess.rst \
		doc/org.bluez.obex.MessageAccess.rst \
		doc/org.bluez.obex.Message.rst \
		doc/org.bluez.obex.AgentManager.rst doc/org.bluez.obex.Agent.rst \
		doc/org.bluez.obex.Image.rst

EXTRA_DIST += doc/pics-opp.txt doc/pixit-opp.txt \
		doc/pts-opp.txt

EXTRA_DIST += doc/btsnoop.txt

EXTRA_DIST += tools/magic.btsnoop

AM_CPPFLAGS += $(DBUS_CFLAGS) $(GLIB_CFLAGS) -I$(srcdir)/lib

unit_tests += unit/test-tester

unit_test_tester_SOURCES = unit/test-tester.c
unit_test_tester_LDADD = src/libshared-glib.la lib/libbluetooth-internal.la \
								$(GLIB_LIBS)

unit_tests += unit/test-eir

unit_test_eir_SOURCES = unit/test-eir.c src/eir.c src/uuid-helper.c
unit_test_eir_LDADD = src/libshared-glib.la lib/libbluetooth-internal.la \
								$(GLIB_LIBS)

unit_tests += unit/test-uuid

unit_test_uuid_SOURCES = unit/test-uuid.c
unit_test_uuid_LDADD = src/libshared-glib.la lib/libbluetooth-internal.la \
								$(GLIB_LIBS)

unit_tests += unit/test-textfile

unit_test_textfile_SOURCES = unit/test-textfile.c src/textfile.h src/textfile.c
unit_test_textfile_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_tests += unit/test-crc

unit_test_crc_SOURCES = unit/test-crc.c monitor/crc.h monitor/crc.c
unit_test_crc_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_tests += unit/test-crypto

unit_test_crypto_SOURCES = unit/test-crypto.c
unit_test_crypto_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_tests += unit/test-ecc

unit_test_ecc_SOURCES = unit/test-ecc.c
unit_test_ecc_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_tests += unit/test-ringbuf unit/test-queue

unit_test_ringbuf_SOURCES = unit/test-ringbuf.c
unit_test_ringbuf_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_test_queue_SOURCES = unit/test-queue.c
unit_test_queue_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_tests += unit/test-mgmt

unit_test_mgmt_SOURCES = unit/test-mgmt.c
unit_test_mgmt_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_tests += unit/test-uhid

unit_test_uhid_SOURCES = unit/test-uhid.c
unit_test_uhid_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_tests += unit/test-sdp

unit_test_sdp_SOURCES = unit/test-sdp.c \
				src/sdpd.h src/sdpd-database.c \
				src/log.h src/log.c \
				src/sdpd-service.c src/sdpd-request.c
unit_test_sdp_LDADD = lib/libbluetooth-internal.la \
				src/libshared-glib.la $(GLIB_LIBS)

unit_tests += unit/test-avdtp

unit_test_avdtp_SOURCES = unit/test-avdtp.c \
				src/log.h src/log.c \
				unit/avdtp.c unit/avdtp.h
unit_test_avdtp_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_tests += unit/test-avctp

unit_test_avctp_SOURCES = unit/test-avctp.c \
				src/log.h src/log.c \
				unit/avctp.c unit/avctp.h
unit_test_avctp_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_tests += unit/test-avrcp

unit_test_avrcp_SOURCES = unit/test-avrcp.c \
				src/log.h src/log.c \
				unit/avctp.c unit/avctp.h \
				unit/avrcp-lib.c unit/avrcp-lib.h
unit_test_avrcp_LDADD = lib/libbluetooth-internal.la \
				src/libshared-glib.la $(GLIB_LIBS)

unit_tests += unit/test-hfp

unit_test_hfp_SOURCES = unit/test-hfp.c
unit_test_hfp_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_tests += unit/test-gdbus-client

unit_test_gdbus_client_SOURCES = unit/test-gdbus-client.c
unit_test_gdbus_client_LDADD = gdbus/libgdbus-internal.la \
				src/libshared-glib.la $(GLIB_LIBS) $(DBUS_LIBS)

if OBEX
unit_tests += unit/test-gobex-header unit/test-gobex-packet unit/test-gobex \
			unit/test-gobex-transfer unit/test-gobex-apparam

unit_test_gobex_SOURCES = $(gobex_sources) unit/util.c unit/util.h \
						unit/test-gobex.c
unit_test_gobex_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_test_gobex_packet_SOURCES = $(gobex_sources) unit/util.c unit/util.h \
						unit/test-gobex-packet.c
unit_test_gobex_packet_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_test_gobex_header_SOURCES = $(gobex_sources) unit/util.c unit/util.h \
						unit/test-gobex-header.c
unit_test_gobex_header_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_test_gobex_transfer_SOURCES = $(gobex_sources) unit/util.c unit/util.h \
						unit/test-gobex-transfer.c
unit_test_gobex_transfer_LDADD = src/libshared-glib.la $(GLIB_LIBS)

unit_test_gobex_apparam_SOURCES = $(gobex_sources) unit/util.c unit/util.h \
						unit/test-gobex-apparam.c
unit_test_gobex_apparam_LDADD = src/libshared-glib.la $(GLIB_LIBS)
endif

unit_tests += unit/test-lib

unit_test_lib_SOURCES = unit/test-lib.c
unit_test_lib_LDADD = src/libshared-glib.la \
				lib/libbluetooth-internal.la $(GLIB_LIBS)

unit_tests += unit/test-gatt

unit_test_gatt_SOURCES = unit/test-gatt.c
unit_test_gatt_LDADD = src/libshared-glib.la \
				lib/libbluetooth-internal.la $(GLIB_LIBS)

unit_tests += unit/test-hog

unit_test_hog_SOURCES = unit/test-hog.c \
			$(btio_sources) \
			profiles/input/hog-lib.h profiles/input/hog-lib.c \
			profiles/scanparam/scpp.h profiles/scanparam/scpp.c \
			profiles/battery/bas.h profiles/battery/bas.c \
			profiles/deviceinfo/dis.h profiles/deviceinfo/dis.c \
			src/log.h src/log.c \
			attrib/att.h attrib/att.c \
			attrib/gatt.h attrib/gatt.c \
			attrib/gattrib.h attrib/gattrib.c
unit_test_hog_LDADD = src/libshared-glib.la \
				lib/libbluetooth-internal.la $(GLIB_LIBS)

unit_tests += unit/test-gattrib

unit_test_gattrib_SOURCES = unit/test-gattrib.c attrib/gattrib.c \
					$(btio_sources) src/log.h src/log.c
unit_test_gattrib_LDADD = src/libshared-glib.la \
				lib/libbluetooth-internal.la \
				$(GLIB_LIBS) $(DBUS_LIBS) -ldl -lrt

unit_tests += unit/test-bap

unit_test_bap_SOURCES = unit/test-bap.c
unit_test_bap_LDADD = src/libshared-glib.la \
				lib/libbluetooth-internal.la $(GLIB_LIBS)

unit_tests += unit/test-micp

unit_test_micp_SOURCES = unit/test-micp.c
unit_test_micp_LDADD = src/libshared-glib.la \
				lib/libbluetooth-internal.la $(GLIB_LIBS)

unit_tests += unit/test-bass

unit_test_bass_SOURCES = unit/test-bass.c $(btio_sources)
unit_test_bass_LDADD = src/libshared-glib.la \
				lib/libbluetooth-internal.la $(GLIB_LIBS)

unit_tests += unit/test-vcp

unit_test_vcp_SOURCES = unit/test-vcp.c $(btio_sources)
unit_test_vcp_LDADD = src/libshared-glib.la \
				lib/libbluetooth-internal.la $(GLIB_LIBS)

if MIDI
unit_tests += unit/test-midi
unit_test_midi_CPPFLAGS = $(AM_CPPFLAGS) $(ALSA_CFLAGS) -DMIDI_TEST
unit_test_midi_SOURCES = unit/test-midi.c \
			profiles/midi/libmidi.h \
			profiles/midi/libmidi.c
unit_test_midi_LDADD = src/libshared-glib.la \
			$(GLIB_LIBS) $(ALSA_LIBS)
endif

if MESH
unit_tests += unit/test-mesh-crypto
unit_test_mesh_crypto_CPPFLAGS = $(ell_cflags)
unit_test_mesh_crypto_SOURCES = unit/test-mesh-crypto.c \
				mesh/crypto.h ell/internal ell/ell.h
unit_test_mesh_crypto_LDADD = $(ell_ldadd)
endif

if MAINTAINER_MODE
noinst_PROGRAMS += $(unit_tests)
endif

TESTS = $(unit_tests)
AM_TESTS_ENVIRONMENT = MALLOC_CHECK_=3 MALLOC_PERTURB_=69

if DBUS_RUN_SESSION
AM_TESTS_ENVIRONMENT += dbus-run-session --
endif

if VALGRIND
LOG_COMPILER = valgrind --error-exitcode=1 --num-callers=30
LOG_FLAGS = --trace-children=yes --leak-check=full --show-reachable=no \
		--suppressions=$(srcdir)/tools/valgrind.supp --quiet
endif

pkgconfigdir = $(libdir)/pkgconfig

if LIBRARY
pkgconfig_DATA = lib/bluez.pc
endif

EXTRA_DIST += $(manual_pages) $(patsubst %.1,%.rst, \
				$(patsubst %.8,%.rst,$(manual_pages)))

DISTCHECK_CONFIGURE_FLAGS = --disable-datafiles --enable-library \
						--enable-health \
						--enable-midi \
						--enable-manpages \
						--enable-mesh \
						--enable-btpclient \
						--disable-systemd \
						--disable-udev

DISTCLEANFILES = $(pkgconfig_DATA) $(unit_tests) $(manual_pages)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs test-driver

if RUN_RST2MAN
RST2MAN_PROCESS = $(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
			$(RST2MAN) --strict --no-raw \
			--no-generator --no-datestamp $< $@
else
RST2MAN_PROCESS = $(AM_V_GEN)test -f $@ || \
		{ echo "Generated manual page $@ does not exist"; false; }
endif

%.1: %.rst Makefile
	$(RST2MAN_PROCESS)

%.5: %.rst Makefile
	$(RST2MAN_PROCESS)

%.7: %.rst Makefile
	$(RST2MAN_PROCESS)

%.8: %.rst Makefile
	$(RST2MAN_PROCESS)

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

tools/%.rules:
	$(AM_V_at)$(MKDIR_P) tools
	$(AM_V_GEN)cp $(srcdir)/$(subst 97-,,$@) $@

ell/shared: Makefile
	$(AM_V_at)$(MKDIR_P) ell
	$(AM_V_GEN)for f in $(ell_shared) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t ell -f $(abs_srcdir)/../ell/$$f ; \
		fi \
	done > $@

ell/internal: Makefile
	$(AM_V_at)$(MKDIR_P) ell
	$(AM_V_GEN)for f in $(ell_headers) $(ell_sources) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t ell -f $(abs_srcdir)/../ell/$$f ; \
		fi \
	done > $@

ell/ell.h: Makefile
	$(AM_V_at)echo -n > $@
	$(AM_V_GEN)for f in $(ell_headers) ; do \
		echo "#include <$$f>" >> $@ ; \
	done

maintainer-clean-local:
	-rm -rf ell

clean-coverage:
if COVERAGE
	@lcov --directory $(top_builddir) --zerocounters
	$(RM) -r coverage $(top_builddir)/coverage.info

coverage: check
	@lcov --compat-libtool --directory $(top_builddir) --capture \
				--output-file $(top_builddir)/coverage.info
	$(AM_V_at)$(MKDIR_P) coverage
	@genhtml -o coverage/ $(top_builddir)/coverage.info
endif

clean-local: clean-coverage
	-find $(top_builddir) -name "*.gcno" -delete
	-find $(top_builddir) -name "*.gcda" -delete
