/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#include <readline/readline.h>
#include <readline/history.h>
#include <glib.h>
#include <gdbus.h>

#include "monitor/uuid.h"
#include "display.h"
#include "gatt.h"

/* String display constants */
#define COLORED_NEW	COLOR_GREEN "NEW" COLOR_OFF
#define COLORED_CHG	COLOR_YELLOW "CHG" COLOR_OFF
#define COLORED_DEL	COLOR_RED "DEL" COLOR_OFF

static GList *services;

static void print_service(GDBusProxy *proxy, const char *description)
{
	DBusMessageIter iter;
	const char *uuid, *text;
	dbus_bool_t primary;

	if (g_dbus_proxy_get_property(proxy, "UUID", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &uuid);

	if (g_dbus_proxy_get_property(proxy, "Primary", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &primary);

	text = uuidstr_to_str(uuid);
	if (!text)
		text = uuid;

	rl_printf("%s%s%sService %s %s %s\n",
				description ? "[" : "",
				description ? : "",
				description ? "] " : "",
				g_dbus_proxy_get_path(proxy),
				text, primary ? "(Primary)" : "(Secondary)");
}

void gatt_add_service(GDBusProxy *proxy)
{
	services = g_list_append(services, proxy);

	print_service(proxy, COLORED_NEW);
}

void gatt_remove_service(GDBusProxy *proxy)
{
	services = g_list_remove(services, proxy);

	print_service(proxy, COLORED_DEL);
}
