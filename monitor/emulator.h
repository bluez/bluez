/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#define EMU_SUBCMD_TEST_EVENT 0x00

struct emu_cmd_test_event {
	uint8_t subcmd;
	uint8_t evt;
	uint8_t data[];
} __attribute__((packed));
