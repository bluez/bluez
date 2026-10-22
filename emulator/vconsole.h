/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Intel Corporation
 *
 *
 */

#include <stdbool.h>

struct vcon;

/* Serve a virtio console with named ports on the vhost-user socket path.
 * Each port is relayed to a Unix socket "<path>-<name>" for a peer outside
 * the guest. spec is "<path>:<name>[=sync]:<name>[=sync]...", a sync port
 * carries requests from the peer: time is held while the peer has none
 * outstanding on any sync port.
 */
struct vcon *vcon_open(const char *spec);
void vcon_close(struct vcon *vcon);

typedef void (*vcon_debug_func_t)(const char *str, void *user_data);
bool vcon_set_debug(struct vcon *vcon, vcon_debug_func_t callback,
							void *user_data);
