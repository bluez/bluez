/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>
#include <stdlib.h>

#include <hal/libhal.h>

#include "plugin.h"
#include "adapter.h"
#include "logging.h"

#if 0
static uint32_t get_form_factor(LibHalContext *ctx)
{
	char *formfactor;
	uint8_t minor = 0;

	formfactor = libhal_device_get_property_string(ctx,
				"/org/freedesktop/Hal/devices/computer",
						"system.formfactor", NULL);

	if (formfactor == NULL)
		return (1 << 8);

	if (g_str_equal(formfactor, "laptop") == TRUE)
		minor |= (1 << 2) | (1 << 3);
	else if (g_str_equal(formfactor, "desktop") == TRUE)
		minor |= 1 << 2;
	else if (g_str_equal(formfactor, "server") == TRUE)
		minor |= 1 << 3;
	else if (g_str_equal(formfactor, "handheld") == TRUE)
		minor += 1 << 4;

	free(formfactor);

	/* Computer major class */
	return (1 << 8) | minor;
}
#endif

static int hal_probe(struct btd_adapter *adapter)
{
#if 0
	DBusConnection *conn;
	LibHalContext *ctx;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL)
		return -ENOMEM;

	ctx = libhal_ctx_new();
	if (libhal_ctx_set_dbus_connection(ctx, conn) == FALSE) {
		libhal_ctx_free(ctx);
		dbus_connection_unref(conn);
		return -EIO;
	}

	if (libhal_ctx_init(ctx, NULL) == FALSE) {
		error("Unable to init HAL context");
		libhal_ctx_free(ctx);
		dbus_connection_unref(conn);
		return -EIO;
	}

	debug("Setting 0x%06x device class", get_form_factor(ctx));

	libhal_ctx_free(ctx);
	dbus_connection_unref(conn);
#endif

	return -ENODEV;
}

static struct btd_adapter_driver hal_driver = {
	.name	= "hal",
	.probe	= hal_probe,
};

static int hal_init(void)
{
	return btd_register_adapter_driver(&hal_driver);
}

static void hal_exit(void)
{
	btd_unregister_adapter_driver(&hal_driver);
}

BLUETOOTH_PLUGIN_DEFINE("hal", hal_init, hal_exit)
