// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022 Intel Corporation. All rights reserved.
 *
 *
 */

void print_property(GDBusProxy *proxy, const char *name);
void print_property_with_label(GDBusProxy *proxy, const char *name,
					const char *label);
void print_iter(const char *label, const char *name, DBusMessageIter *iter);
