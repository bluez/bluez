/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#include <stdint.h>

struct vhci;

typedef void (*vhci_debug_func_t)(const char *str, void *user_data);
typedef void (*vhci_destroy_func_t)(void *user_data);
bool vhci_set_debug(struct vhci *vhci, vhci_debug_func_t callback,
			void *user_data, vhci_destroy_func_t destroy);

struct vhci *vhci_open(uint8_t type);
void vhci_close(struct vhci *vhci);

struct btdev *vhci_get_btdev(struct vhci *vhci);

int vhci_set_force_suspend(struct vhci *vhci, bool enable);
int vhci_set_force_wakeup(struct vhci *vhci, bool enable);
int vhci_set_msft_opcode(struct vhci *vhci, uint16_t opcode);
int vhci_set_aosp_capable(struct vhci *vhci, bool enable);
int vhci_set_emu_opcode(struct vhci *vhci, uint16_t opcode);
