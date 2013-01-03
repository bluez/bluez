/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
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
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include <gdbus/gdbus.h>

#include "glib-helper.h"
#include "hcid.h"
#include "dbus-common.h"
#include "log.h"
#include "adapter.h"
#include "device.h"
#include "error.h"
#include "manager.h"

static int default_adapter_id = -1;
static GSList *adapters = NULL;

static void manager_set_default_adapter(int id)
{
	default_adapter_id = id;
}

struct btd_adapter *manager_get_default_adapter(void)
{
	return manager_find_adapter_by_id(default_adapter_id);
}

static void manager_remove_adapter(struct btd_adapter *adapter)
{
	uint16_t dev_id = adapter_get_dev_id(adapter);

	adapters = g_slist_remove(adapters, adapter);

	if (default_adapter_id == dev_id || default_adapter_id < 0) {
		int new_default = hci_get_route(NULL);

		manager_set_default_adapter(new_default);
	}

	adapter_remove(adapter);
	btd_adapter_unref(adapter);
}

void manager_cleanup(const char *path)
{
	while (adapters) {
		struct btd_adapter *adapter = adapters->data;

		adapter_remove(adapter);
		adapters = g_slist_remove(adapters, adapter);
		btd_adapter_unref(adapter);
	}
}

static gint adapter_id_cmp(gconstpointer a, gconstpointer b)
{
	struct btd_adapter *adapter = (struct btd_adapter *) a;
	uint16_t id = GPOINTER_TO_UINT(b);
	uint16_t dev_id = adapter_get_dev_id(adapter);

	return dev_id == id ? 0 : -1;
}

static gint adapter_cmp(gconstpointer a, gconstpointer b)
{
	struct btd_adapter *adapter = (struct btd_adapter *) a;
	const bdaddr_t *bdaddr = b;

	return bacmp(adapter_get_address(adapter), bdaddr);
}

struct btd_adapter *manager_find_adapter(const bdaddr_t *sba)
{
	GSList *match;

	match = g_slist_find_custom(adapters, sba, adapter_cmp);
	if (!match)
		return NULL;

	return match->data;
}

struct btd_adapter *manager_find_adapter_by_id(int id)
{
	GSList *match;

	match = g_slist_find_custom(adapters, GINT_TO_POINTER(id),
							adapter_id_cmp);
	if (!match)
		return NULL;

	return match->data;
}

void manager_foreach_adapter(adapter_cb func, gpointer user_data)
{
	g_slist_foreach(adapters, (GFunc) func, user_data);
}

GSList *manager_get_adapters(void)
{
	return adapters;
}

struct btd_adapter *btd_manager_register_adapter(int id, gboolean powered,
							bool connectable,
							bool discoverable)
{
	struct btd_adapter *adapter;
	const char *path;

	adapter = manager_find_adapter_by_id(id);
	if (adapter) {
		error("Unable to register adapter: hci%d already exist", id);
		return NULL;
	}

	adapter = adapter_create(id);
	if (!adapter)
		return NULL;

	adapters = g_slist_append(adapters, adapter);

	if (!adapter_init(adapter, powered, connectable, discoverable)) {
		adapters = g_slist_remove(adapters, adapter);
		btd_adapter_unref(adapter);
		return NULL;
	}

	path = adapter_get_path(adapter);

	if (default_adapter_id < 0)
		manager_set_default_adapter(id);

	if (main_opts.did_source)
		btd_adapter_set_did(adapter, main_opts.did_vendor,
						main_opts.did_product,
						main_opts.did_version,
						main_opts.did_source);

	DBG("Adapter %s registered", path);

	return btd_adapter_ref(adapter);
}

int btd_manager_unregister_adapter(int id)
{
	struct btd_adapter *adapter;
	const gchar *path;

	adapter = manager_find_adapter_by_id(id);
	if (!adapter)
		return -1;

	path = adapter_get_path(adapter);

	DBG("Unregister path: %s", path);

	manager_remove_adapter(adapter);

	return 0;
}
