if ANDROID
android_plugindir = $(abs_top_srcdir)/android/.libs

noinst_PROGRAMS += android/system-emulator

android_system_emulator_SOURCES = android/system-emulator.c \
					monitor/mainloop.h monitor/mainloop.c

noinst_PROGRAMS += android/bluetoothd-snoop

android_bluetoothd_snoop_SOURCES = android/bluetoothd-snoop.c \
				monitor/mainloop.h monitor/mainloop.c \
				src/shared/btsnoop.h src/shared/btsnoop.c

noinst_PROGRAMS += android/bluetoothd

android_bluetoothd_SOURCES = android/main.c \
				src/log.c \
				android/hal-msg.h \
				android/audio-msg.h \
				android/sco-msg.h \
				android/utils.h \
				src/sdpd-database.c src/sdpd-server.c \
				src/sdpd-service.c src/sdpd-request.c \
				src/uuid-helper.h src/uuid-helper.c \
				src/eir.h src/eir.c \
				src/shared/io.h src/shared/io-glib.c \
				src/shared/queue.h src/shared/queue.c \
				src/shared/util.h src/shared/util.c \
				src/shared/mgmt.h src/shared/mgmt.c \
				src/shared/ringbuf.h src/shared/ringbuf.c \
				src/shared/hfp.h src/shared/hfp.c \
				src/shared/gatt-db.h src/shared/gatt-db.c \
				android/bluetooth.h android/bluetooth.c \
				android/hidhost.h android/hidhost.c \
				android/ipc-common.h \
				android/ipc.h android/ipc.c \
				android/avdtp.h android/avdtp.c \
				android/a2dp.h android/a2dp.c \
				android/avctp.h android/avctp.c \
				android/avrcp.h android/avrcp.c \
				android/avrcp-lib.h android/avrcp-lib.c \
				android/socket.h android/socket.c \
				android/pan.h android/pan.c \
				android/handsfree.h android/handsfree.c \
				android/gatt.h android/gatt.c \
				android/health.h android/health.c \
				android/mcap-lib.h android/mcap-lib.c \
				attrib/att.c attrib/att.h \
				attrib/gatt.c attrib/gatt.h \
				attrib/gattrib.c attrib/gattrib.h \
				btio/btio.h btio/btio.c \
				src/sdp-client.h src/sdp-client.c \
				profiles/network/bnep.h profiles/network/bnep.c

android_bluetoothd_LDADD = lib/libbluetooth-internal.la @GLIB_LIBS@

plugin_LTLIBRARIES += android/bluetooth.default.la

android_bluetooth_default_la_SOURCES = android/hal.h android/hal-bluetooth.c \
					android/hal-socket.c \
					android/hal-hidhost.c \
					android/hal-health.c \
					android/hal-pan.c \
					android/hal-a2dp.c \
					android/hal-avrcp.c \
					android/hal-handsfree.c \
					android/hal-gatt.c \
					android/hardware/bluetooth.h \
					android/hardware/bt_av.h \
					android/hardware/bt_gatt.h \
					android/hardware/bt_gatt_client.h \
					android/hardware/bt_gatt_server.h \
					android/hardware/bt_gatt_types.h \
					android/hardware/bt_hf.h \
					android/hardware/bt_hh.h \
					android/hardware/bt_hl.h \
					android/hardware/bt_pan.h \
					android/hardware/bt_rc.h \
					android/hardware/bt_sock.h \
					android/hardware/hardware.h \
					android/cutils/properties.h \
					android/ipc-common.h \
					android/hal-log.h \
					android/hal-ipc.h android/hal-ipc.c \
					android/hal-utils.h android/hal-utils.c

android_bluetooth_default_la_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/android
android_bluetooth_default_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version \
					-no-undefined

noinst_PROGRAMS += android/haltest

android_haltest_SOURCES = android/client/haltest.c \
				android/client/pollhandler.h \
				android/client/pollhandler.c \
				android/client/terminal.h \
				android/client/terminal.c \
				android/client/history.h \
				android/client/history.c \
				android/client/tabcompletion.c \
				android/client/if-main.h \
				android/client/if-av.c \
				android/client/if-rc.c \
				android/client/if-bt.c \
				android/client/if-gatt.c \
				android/client/if-hf.c \
				android/client/if-hh.c \
				android/client/if-pan.c \
				android/client/if-hl.c \
				android/client/if-sock.c \
				android/client/if-audio.c \
				android/client/if-sco.c \
				android/hardware/hardware.c \
				android/hal-utils.h android/hal-utils.c

android_haltest_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/android \
				-DPLUGINDIR=\""$(android_plugindir)"\"

android_haltest_LDFLAGS = -pthread -ldl -lm

noinst_PROGRAMS += android/android-tester

android_android_tester_SOURCES = emulator/btdev.h emulator/btdev.c \
				emulator/bthost.h emulator/bthost.c \
				emulator/smp.c \
				src/shared/crypto.h src/shared/crypto.c \
				src/shared/io.h src/shared/io-glib.c \
				src/shared/queue.h src/shared/queue.c \
				src/shared/util.h src/shared/util.c \
				src/shared/mgmt.h src/shared/mgmt.c \
				src/shared/hciemu.h src/shared/hciemu.c \
				src/shared/tester.h src/shared/tester.c \
				src/shared/timeout.h src/shared/timeout-glib.c \
				monitor/rfcomm.h \
				android/hardware/hardware.c \
				android/android-tester.c

android_android_tester_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/android \
				-DPLUGINDIR=\""$(android_plugindir)"\"

android_android_tester_LDADD = lib/libbluetooth-internal.la @GLIB_LIBS@

android_android_tester_LDFLAGS = -pthread -ldl

noinst_PROGRAMS += android/ipc-tester

android_ipc_tester_SOURCES = emulator/btdev.h emulator/btdev.c \
				emulator/bthost.h emulator/bthost.c \
				emulator/smp.c \
				src/shared/crypto.h src/shared/crypto.c \
				src/shared/io.h src/shared/io-glib.c \
				src/shared/queue.h src/shared/queue.c \
				src/shared/util.h src/shared/util.c \
				src/shared/mgmt.h src/shared/mgmt.c \
				src/shared/hciemu.h src/shared/hciemu.c \
				src/shared/tester.h src/shared/tester.c \
				src/shared/timeout.h src/shared/timeout-glib.c \
				android/hal-utils.h android/hal-utils.c \
				android/ipc-common.h android/ipc-tester.c

android_ipc_tester_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/android

android_ipc_tester_LDADD = lib/libbluetooth-internal.la @GLIB_LIBS@

android_audio_a2dp_default_la_SOURCES = android/audio-msg.h \
					android/hal-msg.h \
					android/hal-audio.c \
					android/hardware/audio.h \
					android/hardware/audio_effect.h \
					android/hardware/hardware.h \
					android/system/audio.h

android_audio_sco_default_la_SOURCES = android/hal-log.h \
					android/sco-msg.h \
					android/hal-sco.c \
					android/hardware/audio.h \
					android/hardware/audio_effect.h \
					android/hardware/hardware.h \
					android/audio_utils/resampler.c \
					android/audio_utils/resampler.h \
					android/system/audio.h

android_audio_sco_default_la_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/android

android_audio_sco_default_la_LIBADD = @SPEEXDSP_LIBS@

android_audio_sco_default_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version \
					-no-undefined -lrt

plugin_LTLIBRARIES += android/audio.sco.default.la

unit_tests += android/test-ipc

android_test_ipc_SOURCES = android/test-ipc.c \
				src/shared/util.h src/shared/util.c \
				src/log.h src/log.c \
				android/ipc-common.h \
				android/ipc.c android/ipc.h
android_test_ipc_LDADD = @GLIB_LIBS@

plugin_LTLIBRARIES += android/audio.a2dp.default.la

android_audio_a2dp_default_la_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/android

android_audio_a2dp_default_la_LIBADD = @SBC_LIBS@

android_audio_a2dp_default_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version \
					-no-undefined -pthread -lrt

endif

EXTRA_DIST += android/Android.mk android/README \
				android/init.bluetooth.rc \
				android/hal-ipc-api.txt \
				android/audio-ipc-api.txt \
				android/pics-rfcomm.txt \
				android/pics-spp.txt \
				android/pics-sdp.txt \
				android/pics-l2cap.txt \
				android/pics-gap.txt \
				android/pics-did.txt \
				android/pics-hid.txt \
				android/pics-pan.txt \
				android/pics-opp.txt \
				android/pics-map.txt \
				android/pics-pbap.txt \
				android/pics-a2dp.txt \
				android/pics-avctp.txt \
				android/pics-avrcp.txt \
				android/pics-hsp.txt \
				android/pics-hfp.txt \
				android/pics-gatt.txt \
				android/pics-mcap.txt \
				android/pics-hdp.txt \
				android/pics-iopt.txt \
				android/pics-sm.txt \
				android/pics-mps.txt \
				android/pixit-l2cap.txt \
				android/pixit-gap.txt \
				android/pixit-did.txt \
				android/pixit-hid.txt \
				android/pixit-pan.txt \
				android/pixit-opp.txt \
				android/pixit-map.txt \
				android/pixit-pbap.txt \
				android/pixit-a2dp.txt \
				android/pixit-avctp.txt \
				android/pixit-avrcp.txt \
				android/pixit-hsp.txt \
				android/pixit-hfp.txt \
				android/pixit-gatt.txt \
				android/pixit-mcap.txt \
				android/pixit-hdp.txt \
				android/pixit-iopt.txt \
				android/pixit-sm.txt \
				android/pixit-mps.txt \
				android/bite-rfcomm.txt \
				android/bite-spp.txt \
				android/pts-l2cap.txt \
				android/pts-gap.txt \
				android/pts-did.txt \
				android/pts-hid.txt \
				android/pts-pan.txt \
				android/pts-opp.txt \
				android/pts-map.txt \
				android/pts-a2dp.txt \
				android/pts-avrcp.txt \
				android/pts-avctp.txt \
				android/pts-pbap.txt \
				android/pts-hfp.txt \
				android/pts-gatt.txt \
				android/pts-hsp.txt \
				android/pts-iopt.txt \
				android/pts-hdp.txt \
				android/pts-mcap.txt \
				android/pts-mps.txt \
				android/pts-sm.txt
