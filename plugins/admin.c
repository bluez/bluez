// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2021 Google LLC
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "src/log.h"
#include "src/plugin.h"

static int admin_init(void)
{
	DBG("");

	return 0;
}

static void admin_exit(void)
{
	DBG("");
}

BLUETOOTH_PLUGIN_DEFINE(admin, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			admin_init, admin_exit)
