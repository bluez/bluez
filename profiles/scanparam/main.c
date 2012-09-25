/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Nordic Semiconductor Inc.
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia - INdT
 *
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

#include <errno.h>
#include <stdint.h>
#include <glib.h>

#include "log.h"
#include "plugin.h"
#include "hcid.h"

static int scan_param_init(void)
{
	if (!main_opts.gatt_enabled) {
		DBG("Scan Parameters: GATT is disabled");
		return -ENOTSUP;
	}

	return 0;
}

static void scan_param_exit(void)
{
}

BLUETOOTH_PLUGIN_DEFINE(scanparam, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			scan_param_init, scan_param_exit)
