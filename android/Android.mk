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
