// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2011  Texas Instruments, Inc.
 *
 *
 */

struct bt_uinput;

struct bt_uinput_key_map {
	const char *name;
	unsigned int code;
	uint16_t uinput;
};

typedef void (*bt_uinput_debug_func_t)(const char *str, void *user_data);

struct bt_uinput *bt_uinput_new(const char *name, const char *suffix,
					const bdaddr_t *addr,
					const struct input_id *dev_id,
					const struct bt_uinput_key_map *key_map,
					bt_uinput_debug_func_t debug,
					void *user_data);
void bt_uinput_destroy(struct bt_uinput *uinput);

void bt_uinput_send_key(struct bt_uinput *uinput, uint16_t key, bool pressed);
