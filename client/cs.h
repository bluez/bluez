// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include "gdbus/gdbus.h"

void cs_add_submenu(void);
void cs_remove_submenu(void);

void cs_proxy_added(GDBusProxy *proxy);
void cs_proxy_removed(GDBusProxy *proxy);
void cs_device_disconnected(const char *dev_path);
void cs_measurement_started(GDBusProxy *proxy);
void cs_measurement_stopped(GDBusProxy *proxy);
void cs_set_device_list(GList **devices);
