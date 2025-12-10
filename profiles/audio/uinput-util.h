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

struct uinput_key_map {
	const char *name;
	unsigned int code;
	uint16_t uinput;
};

int uinput_create(struct btd_adapter *adapter, struct btd_device *device,
					const char *name, const char *suffix,
					const struct uinput_key_map *key_map);

void uinput_send_key(int fd, uint16_t key, int pressed);
