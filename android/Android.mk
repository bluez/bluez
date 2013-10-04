LOCAL_PATH := $(call my-dir)

# Retrieve BlueZ version from configure.ac file
BLUEZ_VERSION := $(shell grep ^AC_INIT $(LOCAL_PATH)/../configure.ac | cpp -P -D'AC_INIT(_,v)=v')
