/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012 Tieto Poland
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <glib.h>
#include <errno.h>

#include "plugin.h"
#include "manager.h"
#include "hcid.h"
#include "log.h"

static int heartrate_init(void)
{
	if (!main_opts.gatt_enabled) {
		DBG("GATT is disabled");
		return -ENOTSUP;
	}

	return heartrate_manager_init();
}

static void heartrate_exit(void)
{
	heartrate_manager_exit();
}

BLUETOOTH_PLUGIN_DEFINE(heartrate, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
					heartrate_init, heartrate_exit)
