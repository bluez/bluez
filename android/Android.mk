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

LOCAL_C_INCLUDES := \
	$(call include-path-for, glib) \
	$(call include-path-for, glib)/glib \
	$(LOCAL_PATH)/../src \

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
	hal_bluetooth.c \
	hal_bt_sock.c \

LOCAL_SHARED_LIBRARIES := \
	libcutils \

LOCAL_MODULE := bluetooth.default
LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)/hw
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := SHARED_LIBRARIES

include $(BUILD_SHARED_LIBRARY)
