/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdlib.h>
#include <errno.h>

#include <bluetooth/bluetooth.h>

#include "plugin.h"
#include "adapter.h"
#include "log.h"

#define DMI_CHASSIS_FILE "/sys/class/dmi/id/chassis_type"
#define DMI_CHASSIS_FILE_FALLBACK "/sys/devices/virtual/dmi/id/chassis_type"

/* Map the chassis type from chassis_type to a sensible type used in hal
 *
 * See also 3.3.4.1 of the "System Management BIOS Reference Specification,
 * Version 2.6.1" (Preliminary Standard) document, available from
 * http://www.dmtf.org/standards/smbios.
 *
 * TODO: figure out WTF the mapping should be; "Lunch Box"? Give me a break :-)
 *
 * Copied from hal/hald/linux/osspec.c
 */
static const char *chassis_map[] = {
	"Other",                 "unknown", /* 0x01 */
	"Unknown",               "unknown",
	"Desktop",               "desktop",
	"Low Profile Desktop",   "desktop",
	"Pizza Box",             "server",
	"Mini Tower",            "desktop",
	"Tower",                 "desktop",
	"Portable",              "laptop",
	"Laptop",                "laptop",
	"Notebook",              "laptop",
	"Hand Held",             "handheld",
	"Docking Station",       "laptop",
	"All In One",            "unknown",
	"Sub Notebook",          "laptop",
	"Space-saving",          "desktop",
	"Lunch Box",             "unknown",
	"Main Server Chassis",   "server",
	"Expansion Chassis",     "unknown",
	"Sub Chassis",           "unknown",
	"Bus Expansion Chassis", "unknown",
	"Peripheral Chassis",    "unknown",
	"RAID Chassis",          "unknown",
	"Rack Mount Chassis",    "unknown",
	"Sealed-case PC",        "unknown",
	"Multi-system",          "unknown",
	"CompactPCI",            "unknown",
	"AdvancedTCA",           "unknown",
	"Blade",                 "server",
	"Blade Enclosure",       "unknown", /* 0x1D */
	NULL
};

static int formfactor_probe(struct btd_adapter *adapter)
{
	int chassis_type;
	uint8_t minor = 0;
	const char *formfactor;
	char *contents;

	if (g_file_get_contents(DMI_CHASSIS_FILE,
				&contents, NULL, NULL) == FALSE) {
		if (g_file_get_contents(DMI_CHASSIS_FILE_FALLBACK,
					&contents, NULL, NULL) == FALSE) {
			error("Could not get the contents of DMI chassis type");
			return 0;
		}
	}

	chassis_type = atoi(contents);
	g_free (contents);

	if (chassis_type > 0x1D || chassis_type <= 0) {
		error ("Chassis type is not a known chassis type");
		return 0;
	}

	formfactor = chassis_map[chassis_type * 2 - 1];
	if (formfactor != NULL) {
		if (g_str_equal(formfactor, "laptop") == TRUE)
			minor |= (1 << 2) | (1 << 3);
		else if (g_str_equal(formfactor, "desktop") == TRUE)
			minor |= 1 << 2;
		else if (g_str_equal(formfactor, "server") == TRUE)
			minor |= 1 << 3;
		else if (g_str_equal(formfactor, "handheld") == TRUE)
			minor += 1 << 4;
	}

	/* Computer major class */
	DBG("Setting 0x%06x for major/minor device class", (1 << 8) | minor);

	btd_adapter_set_class(adapter, 0x01, minor);

	return 0;
}

static void formfactor_remove(struct btd_adapter *adapter)
{
}

static struct btd_adapter_driver formfactor_driver = {
	.name	= "formfactor",
	.probe	= formfactor_probe,
	.remove	= formfactor_remove,
};

static int formfactor_init(void)
{
	return btd_register_adapter_driver(&formfactor_driver);
}

static void formfactor_exit(void)
{
	btd_unregister_adapter_driver(&formfactor_driver);
}

BLUETOOTH_PLUGIN_DEFINE(formfactor, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_LOW, formfactor_init, formfactor_exit)
