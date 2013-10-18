/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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

#include <errno.h>

#include "lib/bluetooth.h"
#include "src/shared/mgmt.h"
#include "lib/mgmt.h"
#include "log.h"
#include "adapter.h"

struct bt_adapter {
	uint16_t index;
	struct mgmt *mgmt;

	bt_adapter_ready ready;

	bdaddr_t bdaddr;
	uint32_t dev_class;

	char *name;

	uint32_t supported_settings;
	uint32_t current_settings;
};

static struct bt_adapter *default_adapter;

static void load_link_keys_complete(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct bt_adapter *adapter = user_data;
	int err;

	if (status) {
		error("Failed to load link keys for index %u: %s (0x%02x)",
			adapter->index, mgmt_errstr(status), status);
		err = -EIO;
		goto failed;
	}

	DBG("status %u", status);

	default_adapter = adapter;
	adapter->ready(adapter, 0);
	return;

failed:
	adapter->ready(NULL, err);
}

static void load_link_keys(struct bt_adapter *adapter, GSList *keys)
{
	struct mgmt_cp_load_link_keys *cp;
	size_t key_len = g_slist_length(keys);
	struct mgmt_link_key_info *key;
	size_t len;

	DBG("");

	len = sizeof(*cp) + key_len * sizeof(*key);
	cp = g_malloc0(len);

	cp->debug_keys = 0;
	cp->key_count = htobs(key_len);

	mgmt_send(adapter->mgmt, MGMT_OP_LOAD_LINK_KEYS, 0, len,
				cp, load_link_keys_complete, adapter, NULL);

	g_free(cp);
}

static void read_info_complete(uint8_t status, uint16_t length, const void *param,
							void *user_data)
{
	struct bt_adapter *adapter = user_data;
	const struct mgmt_rp_read_info *rp = param;
	int err;

	DBG("");

	if (status) {
		error("Failed to read info for index %u: %s (0x%02x)",
			adapter->index, mgmt_errstr(status), status);
		err = -EIO;
		goto failed;
	}

	if (length < sizeof(*rp)) {
		error("Too small read info complete response");
		err = -EIO;
		goto failed;
	}

	if (!bacmp(&rp->bdaddr, BDADDR_ANY)) {
		error("No Bluetooth address");
		err = -ENODEV;
		goto failed;
	}

	/* Store adapter information */
	bacpy(&adapter->bdaddr, &rp->bdaddr);
	adapter->dev_class = rp->dev_class[0] | (rp->dev_class[1] << 8) |
						(rp->dev_class[2] << 16);
	adapter->name = g_strdup((const char *) rp->name);

	adapter->supported_settings = btohs(rp->supported_settings);
	adapter->current_settings = btohs(rp->current_settings);

	/* TODO: Register all event notification handlers */

	load_link_keys(adapter, NULL);

	return;

failed:
	adapter->ready(NULL, err);
}

bool bt_adapter_init(uint16_t index, struct mgmt *mgmt_if,
						bt_adapter_ready ready)
{
	struct bt_adapter *adapter;

	adapter = g_new0(struct bt_adapter, 1);

	adapter->mgmt = mgmt_ref(mgmt_if);
	adapter->index = index;
	adapter->ready = ready;

	if (mgmt_send(mgmt_if, MGMT_OP_READ_INFO, index, 0, NULL,
				read_info_complete, adapter, NULL) > 0) {
		mgmt_unref(mgmt_if);
		return false;
	}

	return adapter;
}
