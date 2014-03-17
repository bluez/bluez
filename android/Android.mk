LOCAL_PATH := external/bluetooth

# Retrieve BlueZ version from configure.ac file
BLUEZ_VERSION := `grep "^AC_INIT" $(LOCAL_PATH)/bluez/configure.ac | sed -e "s/.*,.\(.*\))/\1/"`

# Specify pathmap for glib and sbc
pathmap_INCL += glib:external/bluetooth/glib \
		sbc:external/bluetooth/sbc \

# Specify common compiler flags
BLUEZ_COMMON_CFLAGS := -DVERSION=\"$(BLUEZ_VERSION)\" \
			-DANDROID_STORAGEDIR=\"/data/misc/bluetooth\" \

# Enable warnings enabled in autotools build
BLUEZ_COMMON_CFLAGS += -Wall -Wextra \
			-Wdeclaration-after-statement \
			-Wmissing-declarations \
			-Wredundant-decls \
			-Wcast-align \

# Disable warnings enabled by Android but not enabled in autotools build
BLUEZ_COMMON_CFLAGS += -Wno-pointer-arith \
			-Wno-missing-field-initializers \
			-Wno-unused-parameter \

#
# Android BlueZ daemon (bluetoothd)
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	bluez/android/main.c \
	bluez/android/bluetooth.c \
	bluez/android/hidhost.c \
	bluez/android/socket.c \
	bluez/android/ipc.c \
	bluez/android/avdtp.c \
	bluez/android/a2dp.c \
	bluez/android/avctp.c \
	bluez/android/avrcp.c \
	bluez/android/avrcp-lib.c \
	bluez/android/pan.c \
	bluez/android/handsfree.c \
	bluez/android/gatt.c \
	bluez/android/health.c \
	bluez/src/log.c \
	bluez/src/shared/mgmt.c \
	bluez/src/shared/util.c \
	bluez/src/shared/queue.c \
	bluez/src/shared/ringbuf.c \
	bluez/src/shared/hfp.c \
	bluez/src/shared/io-glib.c \
	bluez/src/sdpd-database.c \
	bluez/src/sdpd-service.c \
	bluez/src/sdpd-request.c \
	bluez/src/sdpd-server.c \
	bluez/src/uuid-helper.c \
	bluez/src/eir.c \
	bluez/lib/sdp.c \
	bluez/lib/bluetooth.c \
	bluez/lib/hci.c \
	bluez/lib/uuid.c \
	bluez/btio/btio.c \
	bluez/src/sdp-client.c \
	bluez/profiles/network/bnep.c \
	bluez/attrib/gattrib.c \
	bluez/attrib/gatt.c \
	bluez/attrib/att.c

LOCAL_C_INCLUDES := \
	$(call include-path-for, glib) \
	$(call include-path-for, glib)/glib \

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/bluez \
	$(LOCAL_PATH)/bluez/lib \

LOCAL_CFLAGS := $(BLUEZ_COMMON_CFLAGS)

LOCAL_SHARED_LIBRARIES := \
	libglib \

lib_headers := \
	bluetooth.h \
	hci.h \
	hci_lib.h \
	l2cap.h \
	sdp_lib.h \
	sdp.h \
	rfcomm.h \
	sco.h \
	bnep.h \

$(shell mkdir -p $(LOCAL_PATH)/bluez/lib/bluetooth)

$(foreach file,$(lib_headers), $(shell ln -sf ../$(file) $(LOCAL_PATH)/bluez/lib/bluetooth/$(file)))

LOCAL_MODULE_TAGS := optional

# for userdebug/eng this module is bluetoothd-main since bluetoothd is used as
# wrapper to launch bluetooth with Valgrind
ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_MODULE := bluetoothd-main
LOCAL_STRIP_MODULE := false
else
LOCAL_MODULE := bluetoothd
endif

include $(BUILD_EXECUTABLE)

#
# bluetooth.default.so HAL
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	bluez/android/hal-ipc.c \
	bluez/android/hal-bluetooth.c \
	bluez/android/hal-socket.c \
	bluez/android/hal-hidhost.c \
	bluez/android/hal-pan.c \
	bluez/android/hal-a2dp.c \
	bluez/android/hal-avrcp.c \
	bluez/android/hal-handsfree.c \
	bluez/android/hal-gatt.c \
	bluez/android/hal-utils.c \
	bluez/android/hal-health.c \

LOCAL_C_INCLUDES += \
	$(call include-path-for, system-core) \
	$(call include-path-for, libhardware) \

LOCAL_SHARED_LIBRARIES := \
	libcutils \

LOCAL_CFLAGS := $(BLUEZ_COMMON_CFLAGS)

LOCAL_MODULE := bluetooth.default
LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)/hw
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
LOCAL_REQUIRED_MODULES := bluetoothd bluetoothd-snoop init.bluetooth.rc

include $(BUILD_SHARED_LIBRARY)

#
# haltest
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	bluez/android/client/haltest.c \
	bluez/android/client/pollhandler.c \
	bluez/android/client/terminal.c \
	bluez/android/client/history.c \
	bluez/android/client/tabcompletion.c \
	bluez/android/client/if-audio.c \
	bluez/android/client/if-av.c \
	bluez/android/client/if-rc.c \
	bluez/android/client/if-bt.c \
	bluez/android/client/if-hf.c \
	bluez/android/client/if-hh.c \
	bluez/android/client/if-pan.c \
	bluez/android/client/if-sock.c \
	bluez/android/client/if-gatt.c \
	bluez/android/hal-utils.c \

LOCAL_C_INCLUDES += \
	$(call include-path-for, system-core) \
	$(call include-path-for, libhardware) \

LOCAL_CFLAGS := $(BLUEZ_COMMON_CFLAGS)

LOCAL_SHARED_LIBRARIES := libhardware

LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE := haltest

include $(BUILD_EXECUTABLE)

#
# btmon
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	bluez/monitor/main.c \
	bluez/monitor/mainloop.c \
	bluez/monitor/display.c \
	bluez/monitor/hcidump.c \
	bluez/monitor/control.c \
	bluez/monitor/packet.c \
	bluez/monitor/l2cap.c \
	bluez/monitor/uuid.c \
	bluez/monitor/sdp.c \
	bluez/monitor/vendor.c \
	bluez/monitor/lmp.c \
	bluez/monitor/crc.c \
	bluez/monitor/ll.c \
	bluez/monitor/hwdb.c \
	bluez/monitor/keys.c \
	bluez/monitor/ellisys.c \
	bluez/monitor/analyze.c \
	bluez/src/shared/util.c \
	bluez/src/shared/queue.c \
	bluez/src/shared/crypto.c \
	bluez/src/shared/btsnoop.c \
	bluez/lib/hci.c \
	bluez/lib/bluetooth.c \

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/bluez \
	$(LOCAL_PATH)/bluez/lib \

LOCAL_CFLAGS := $(BLUEZ_COMMON_CFLAGS)

LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE := btmon

include $(BUILD_EXECUTABLE)

#
# btproxy
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	bluez/tools/btproxy.c \
	bluez/monitor/mainloop.c \
	bluez/src/shared/util.c \

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/bluez \

LOCAL_CFLAGS := $(BLUEZ_COMMON_CFLAGS)

LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE := btproxy

include $(BUILD_EXECUTABLE)

#
# A2DP audio
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := bluez/android/hal-audio.c

LOCAL_C_INCLUDES = \
	$(call include-path-for, system-core) \
	$(call include-path-for, libhardware) \
	$(call include-path-for, sbc) \

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libsbc \

LOCAL_CFLAGS := $(BLUEZ_COMMON_CFLAGS)

LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)/hw
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := audio.a2dp.default

include $(BUILD_SHARED_LIBRARY)

#
# l2cap-test
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	bluez/tools/l2test.c \
	bluez/lib/bluetooth.c \
	bluez/lib/hci.c \

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/bluez \
	$(LOCAL_PATH)/bluez/lib \

LOCAL_CFLAGS := $(BLUEZ_COMMON_CFLAGS)

LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE := l2test

include $(BUILD_EXECUTABLE)

#
# bluetoothd-snoop
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	bluez/android/bluetoothd-snoop.c \
	bluez/monitor/mainloop.c \
	bluez/src/shared/btsnoop.c \

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/bluez \
	$(LOCAL_PATH)/bluez/lib \

LOCAL_CFLAGS := $(BLUEZ_COMMON_CFLAGS)

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := bluetoothd-snoop

include $(BUILD_EXECUTABLE)

#
# init.bluetooth.rc
#

include $(CLEAR_VARS)

LOCAL_MODULE := init.bluetooth.rc
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := bluez/android/$(LOCAL_MODULE)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

include $(BUILD_PREBUILT)

#
# btmgmt
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	bluez/tools/btmgmt.c \
	bluez/lib/bluetooth.c \
	bluez/lib/sdp.c \
	bluez/monitor/mainloop.c \
	bluez/src/shared/io-mainloop.c \
	bluez/src/shared/mgmt.c \
	bluez/src/shared/queue.c \
	bluez/src/shared/util.c \
	bluez/src/uuid-helper.c \

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/bluez \
	$(LOCAL_PATH)/bluez/lib \

LOCAL_CFLAGS := $(BLUEZ_COMMON_CFLAGS)

LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE := btmgmt

include $(BUILD_EXECUTABLE)

#
# l2ping
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	bluez/tools/l2ping.c \
	bluez/lib/bluetooth.c \
	bluez/lib/hci.c \

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/bluez/lib \

LOCAL_CFLAGS := $(BLUEZ_COMMON_CFLAGS)

LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE := l2ping

include $(BUILD_EXECUTABLE)

#
# avtest
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	bluez/tools/avtest.c \
	bluez/lib/bluetooth.c \
	bluez/lib/hci.c \

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/bluez/lib \

LOCAL_CFLAGS := $(BLUEZ_COMMON_CFLAGS)

LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE := avtest

include $(BUILD_EXECUTABLE)

#
# libsbc
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	sbc/sbc/sbc.c \
	sbc/sbc/sbc_primitives.c \
	sbc/sbc/sbc_primitives_mmx.c \
	sbc/sbc/sbc_primitives_neon.c \
	sbc/sbc/sbc_primitives_armv6.c \
	sbc/sbc/sbc_primitives_iwmmxt.c \

LOCAL_C_INCLUDES:= \
	$(LOCAL_PATH)/sbc \

LOCAL_CFLAGS:= \
	-Os \
	-Wno-sign-compare \
	-Wno-missing-field-initializers \
	-Wno-unused-parameter \
	-Wno-type-limits \
	-Wno-empty-body \

LOCAL_MODULE := libsbc

include $(BUILD_SHARED_LIBRARY)

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))

#
# bluetoothd (debug)
# this is just a wrapper used in userdebug/eng to launch bluetoothd-main
# with/without Valgrind
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	bluez/android/bluetoothd-wrapper.c

LOCAL_CFLAGS := $(BLUEZ_COMMON_CFLAGS)

LOCAL_SHARED_LIBRARIES := \
	libcutils \

LOCAL_MODULE_PATH := $(TARGET_OUT_EXECUTABLES)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := bluetoothd

LOCAL_REQUIRED_MODULES := \
	bluetoothd-main \
	valgrind \
	memcheck-$(TARGET_ARCH)-linux \
	vgpreload_core-$(TARGET_ARCH)-linux \
	vgpreload_memcheck-$(TARGET_ARCH)-linux \
	default.supp

include $(BUILD_EXECUTABLE)

endif
