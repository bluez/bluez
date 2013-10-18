LOCAL_PATH := $(call my-dir)

# Retrieve BlueZ version from configure.ac file
BLUEZ_VERSION := $(shell grep ^AC_INIT $(LOCAL_PATH)/../configure.ac | cpp -P -D'AC_INIT(_,v)=v')

# Specify pathmap for glib
pathmap_INCL += glib:external/bluetooth/glib

#
# Android BlueZ daemon (bluetoothd)
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	main.c \
	log.c \
	adapter.c \
	../src/shared/mgmt.c \
	../src/shared/util.c \
	../src/sdpd-database.c \
	../src/sdpd-service.c \
	../src/sdpd-request.c \
	../src/sdpd-server.c \
	../lib/sdp.c \
	../lib/bluetooth.c \
	../lib/hci.c \

LOCAL_C_INCLUDES := \
	$(call include-path-for, glib) \
	$(call include-path-for, glib)/glib \

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/../ \
	$(LOCAL_PATH)/../src \
	$(LOCAL_PATH)/../lib \

LOCAL_CFLAGS := -DVERSION=\"$(BLUEZ_VERSION)\"

LOCAL_SHARED_LIBRARIES := \
	libglib \

LOCAL_MODULE := bluetoothd

include $(BUILD_EXECUTABLE)

#
# bluetooth.default.so HAL
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	hal-bluetooth.c \
	hal-sock.c \
	hal-hidhost.c \
	hal-pan.c \

LOCAL_SHARED_LIBRARIES := \
	libcutils \

LOCAL_MODULE := bluetooth.default
LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)/hw
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := SHARED_LIBRARIES

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
	client/if-bt.c \

LOCAL_SHARED_LIBRARIES := libhardware

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := haltest

include $(BUILD_EXECUTABLE)
