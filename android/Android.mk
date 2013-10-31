LOCAL_PATH := $(call my-dir)

# Retrieve BlueZ version from configure.ac file
BLUEZ_VERSION := $(shell grep ^AC_INIT $(LOCAL_PATH)/../configure.ac | cpp -P -D'AC_INIT(_,v)=v')

# Specify pathmap for glib
pathmap_INCL += glib:external/bluetooth/glib

# Specify common compiler flags
BLUEZ_COMMON_CFLAGS := -DVERSION=\"$(BLUEZ_VERSION)\" \
	-DPLATFORM_SDK_VERSION=$(PLATFORM_SDK_VERSION)

# Disable warnings enabled by Android but not enabled in autotools build
BLUEZ_COMMON_CFLAGS += -Wno-pointer-arith

#
# Android BlueZ daemon (bluetoothd)
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	main.c \
	adapter.c \
	hid.c \
	socket.c \
	ipc.c ipc.h \
	../src/log.c \
	../src/shared/mgmt.c \
	../src/shared/util.c \
	../src/sdpd-database.c \
	../src/sdpd-service.c \
	../src/sdpd-request.c \
	../src/sdpd-server.c \
	../lib/sdp.c \
	../lib/bluetooth.c \
	../lib/hci.c \
	../btio/btio.c

LOCAL_C_INCLUDES := \
	$(call include-path-for, glib) \
	$(call include-path-for, glib)/glib \

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/../ \
	$(LOCAL_PATH)/../src \
	$(LOCAL_PATH)/../lib \

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

$(shell mkdir -p $(LOCAL_PATH)/../lib/bluetooth)

$(foreach file,$(lib_headers), $(shell ln -sf ../$(file) $(LOCAL_PATH)/../lib/bluetooth/$(file)))

LOCAL_MODULE := bluetoothd

include $(BUILD_EXECUTABLE)

#
# bluetooth.default.so HAL
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	hal-ipc.c \
	hal-bluetooth.c \
	hal-sock.c \
	hal-hidhost.c \
	hal-pan.c \
	hal-av.c \
	client/textconv.c \

LOCAL_C_INCLUDES += \
	$(call include-path-for, system-core) \
	$(call include-path-for, libhardware) \

LOCAL_SHARED_LIBRARIES := \
	libcutils \

LOCAL_CFLAGS := $(BLUEZ_COMMON_CFLAGS) \

LOCAL_MODULE := bluetooth.default
LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)/hw
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
LOCAL_REQUIRED_MODULES := haltest bluetoothd

include $(BUILD_SHARED_LIBRARY)

#
# haltest
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	client/haltest.c \
	client/pollhandler.c \
	client/terminal.c \
	client/history.c \
	client/textconv.c \
	client/tabcompletion.c \
	client/if-av.c \
	client/if-bt.c \
	client/if-hf.c \
	client/if-hh.c \
	client/if-pan.c \
	client/if-sock.c \

LOCAL_C_INCLUDES += \
	$(call include-path-for, system-core) \
	$(call include-path-for, libhardware) \

LOCAL_CFLAGS := $(BLUEZ_COMMON_CFLAGS)

LOCAL_SHARED_LIBRARIES := libhardware

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := haltest

include $(BUILD_EXECUTABLE)
