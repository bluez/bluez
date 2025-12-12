/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  Pauli Virtanen
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
				const struct input_id *dev_id);

void bt_uinput_set_debug(struct bt_uinput *uinput,
					bt_uinput_debug_func_t debug_func,
					void *user_data);

int bt_uinput_create(struct bt_uinput *uinput,
				const struct bt_uinput_key_map *key_map);

void bt_uinput_destroy(struct bt_uinput *uinput);

void bt_uinput_send_key(struct bt_uinput *uinput, uint16_t key, bool pressed);
