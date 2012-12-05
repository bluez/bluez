/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011 GSyC/LibreSoft, Universidad Rey Juan Carlos.
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

#include <stdint.h>
#include <glib.h>
#include <errno.h>

#include "plugin.h"
#include "manager.h"
#include "hcid.h"
#include "log.h"

static int thermometer_init(void)
{
	return thermometer_manager_init();
}

static void thermometer_exit(void)
{
	thermometer_manager_exit();
}

BLUETOOTH_PLUGIN_DEFINE(thermometer, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
					thermometer_init, thermometer_exit)
