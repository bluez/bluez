/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Gamepad Quirk Support
 *
 *  Minimal HID fallback for third-party gamepads with broken SDP records.
 *  Only activates for specifically matched devices.
 */

#ifndef __INPUT_QUIRK_H
#define __INPUT_QUIRK_H

#include <stdbool.h>

struct input_device;
struct hidp_connadd_req;

struct gamepad_quirk {
	const char *name;
	bool (*match)(struct input_device *idev);
	int (*apply)(struct input_device *idev,
			struct hidp_connadd_req *req);
};

bool gamepad_quirk_match(struct input_device *idev);

int gamepad_quirk_apply(struct input_device *idev,
			struct hidp_connadd_req *req);

#endif
