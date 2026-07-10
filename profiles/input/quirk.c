/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Gamepad Quirk Support
 *
 *  Dispatcher for gamepad HID quirks. When BlueZ fails to parse an SDP
 *  record for a known gamepad, this layer injects a fallback HID report
 *  descriptor so the kernel HID driver can create an input device.
 *
 *  This does NOT weaken HID parsing globally — quirks only activate for
 *  specifically matched controllers.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/hidp.h"

#include "src/log.h"

#include "quirk.h"

/* Individual quirk declarations */
extern struct gamepad_quirk tg170w_quirk;

static struct gamepad_quirk *quirks[] = {
	&tg170w_quirk,
	NULL
};

bool gamepad_quirk_match(struct input_device *idev)
{
	int i;

	for (i = 0; quirks[i]; i++) {
		if (quirks[i]->match(idev))
			return true;
	}

	return false;
}

int gamepad_quirk_apply(struct input_device *idev,
			struct hidp_connadd_req *req)
{
	int i;

	for (i = 0; quirks[i]; i++) {
		if (!quirks[i]->match(idev))
			continue;

		DBG("Applying HID quirk: %s", quirks[i]->name);

		return quirks[i]->apply(idev, req);
	}

	return -1;
}
