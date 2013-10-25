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

#include <glib.h>

#include "lib/bluetooth.h"
#include "src/shared/mgmt.h"
#include "lib/mgmt.h"
#include "log.h"
#include "hal-msg.h"
#include "ipc.h"
#include "adapter.h"

static GIOChannel *notification_io = NULL;

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

static struct bt_adapter *adapter;

static void mgmt_local_name_changed_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_cp_set_local_name *rp = param;

	if (length < sizeof(*rp)) {
		error("Wrong size of local name changed parameters");
		return;
	}

	if (!g_strcmp0(adapter->name, (const char *) rp->name))
		return;

	DBG("name: %s", rp->name);

	g_free(adapter->name);
	adapter->name = g_strdup((const char *) rp->name);

	/* TODO Update services if needed */
}

static void settings_changed_powered(void)
{
	struct hal_ev_adapter_state_changed ev;

	ev.state = (adapter->current_settings & MGMT_SETTING_POWERED) ?
						HAL_POWER_ON : HAL_POWER_OFF;

	DBG("%u", ev.state);

	ipc_send(notification_io, HAL_SERVICE_ID_BLUETOOTH,
			HAL_EV_ADAPTER_STATE_CHANGED, sizeof(ev), &ev, -1);
}

static void settings_changed_connectable(void)
{
	/* TODO */
}

static void settings_changed_discoverable(void)
{
	/* TODO */
}

static void settings_changed(uint32_t settings)
{
	uint32_t changed_mask;

	changed_mask = adapter->current_settings ^ settings;

	adapter->current_settings = settings;

	DBG("0x%08x", changed_mask);

	if (changed_mask & MGMT_SETTING_POWERED)
		settings_changed_powered();

	if (changed_mask & MGMT_SETTING_CONNECTABLE) {
		DBG("Connectable");

		settings_changed_connectable();
	}

	if (changed_mask & MGMT_SETTING_DISCOVERABLE) {
		DBG("Discoverable");

		settings_changed_discoverable();
	}
}

static void new_settings_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	uint32_t settings;

	if (length < sizeof(settings)) {
		error("Wrong size of new settings parameters");
		return;
	}

	settings = bt_get_le32(param);

	DBG("settings: 0x%8.8x -> 0x%8.8x", adapter->current_settings,
								settings);

	if (settings == adapter->current_settings)
		return;

	settings_changed(settings);
}

static void mgmt_dev_class_changed_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_cod *rp = param;
	uint32_t dev_class;

	if (length < sizeof(*rp)) {
		error("Wrong size of class of device changed parameters");
		return;
	}

	dev_class = rp->val[0] | (rp->val[1] << 8) | (rp->val[2] << 16);

	if (dev_class == adapter->dev_class)
		return;

	DBG("Class: 0x%06x", dev_class);

	adapter->dev_class = dev_class;

	/* TODO: Inform prop change: Class */

	/* TODO: Gatt attrib set*/
}

static void register_mgmt_handlers(void)
{
	mgmt_register(adapter->mgmt, MGMT_EV_NEW_SETTINGS, adapter->index,
					new_settings_callback, NULL, NULL);

	mgmt_register(adapter->mgmt, MGMT_EV_CLASS_OF_DEV_CHANGED,
				adapter->index, mgmt_dev_class_changed_event,
				NULL, NULL);

	mgmt_register(adapter->mgmt, MGMT_EV_LOCAL_NAME_CHANGED,
				adapter->index, mgmt_local_name_changed_event,
				NULL, NULL);
}

static void load_link_keys_complete(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int err;

	if (status) {
		error("Failed to load link keys for index %u: %s (0x%02x)",
			adapter->index, mgmt_errstr(status), status);
		err = -EIO;
		goto failed;
	}

	DBG("status %u", status);

	adapter->ready(0);
	return;

failed:
	adapter->ready(err);
}

static void load_link_keys(GSList *keys)
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

	mgmt_send(adapter->mgmt, MGMT_OP_LOAD_LINK_KEYS, adapter->index, len,
				cp, load_link_keys_complete, NULL, NULL);

	g_free(cp);
}

static void read_info_complete(uint8_t status, uint16_t length, const void *param,
							void *user_data)
{
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
	register_mgmt_handlers();

	load_link_keys(NULL);

	return;

failed:
	adapter->ready(err);
}

void bt_adapter_init(uint16_t index, struct mgmt *mgmt, bt_adapter_ready cb)
{
	adapter = g_new0(struct bt_adapter, 1);

	adapter->mgmt = mgmt_ref(mgmt);
	adapter->index = index;
	adapter->ready = cb;

	if (mgmt_send(mgmt, MGMT_OP_READ_INFO, index, 0, NULL,
					read_info_complete, NULL, NULL) > 0)
		return;

	mgmt_unref(adapter->mgmt);
	adapter->ready(-EIO);
}

static void set_mode_complete(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		error("Failed to set mode: %s (0x%02x)",
						mgmt_errstr(status), status);
		return;
	}

	/*
	 * The parameters are identical and also the task that is
	 * required in both cases. So it is safe to just call the
	 * event handling functions here.
	 */
	new_settings_callback(adapter->index, length, param, NULL);
}

static bool set_mode(uint16_t opcode, uint8_t mode)
{
	struct mgmt_mode cp;

	memset(&cp, 0, sizeof(cp));
	cp.val = mode;

	DBG("opcode=0x%x mode=0x%x", opcode, mode);

	if (mgmt_send(adapter->mgmt, opcode, adapter->index, sizeof(cp), &cp,
					set_mode_complete, NULL, NULL) > 0)
		return true;

	error("Failed to set mode");

	return false;
}

static void send_adapter_name(void)
{
	struct hal_ev_adapter_props_changed *ev;
	int len;

	len = sizeof(*ev) + sizeof(struct hal_property) + sizeof(bdaddr_t);

	ev = g_malloc(len);

	ev->num_props = 1;
	ev->status = HAL_STATUS_SUCCESS;

	ev->props[0].type = HAL_PROP_ADAPTER_ADDR;
	ev->props[0].len = sizeof(bdaddr_t);
	baswap((bdaddr_t *) ev->props[0].val, &adapter->bdaddr);

	ipc_send(notification_io, HAL_SERVICE_ID_BLUETOOTH,
				HAL_EV_ADAPTER_PROPS_CHANGED, len, ev, -1);

	g_free(ev);
}

static bool get_property(void *buf, uint16_t len)
{
	struct hal_cmd_get_adapter_prop *cmd = buf;

	switch (cmd->type) {
	case HAL_PROP_ADAPTER_ADDR:
		send_adapter_name();
		return true;
	case HAL_PROP_ADAPTER_NAME:
	case HAL_PROP_ADAPTER_UUIDS:
	case HAL_PROP_ADAPTER_CLASS:
	case HAL_PROP_ADAPTER_TYPE:
	case HAL_PROP_ADAPTER_SERVICE_REC:
	case HAL_PROP_ADAPTER_SCAN_MODE:
	case HAL_PROP_ADAPTER_BONDED_DEVICES:
	case HAL_PROP_ADAPTER_DISC_TIMEOUT:
	default:
		return false;
	}
}

void bt_adapter_handle_cmd(GIOChannel *io, uint8_t opcode, void *buf,
								uint16_t len)
{
	uint8_t status = HAL_STATUS_FAILED;

	switch (opcode) {
	case HAL_OP_ENABLE:
		if (adapter->current_settings & MGMT_SETTING_POWERED) {
			status = HAL_STATUS_DONE;
			break;
		}

		if (set_mode(MGMT_OP_SET_POWERED, 0x01)) {
			ipc_send(io, HAL_SERVICE_ID_BLUETOOTH, opcode, 0, NULL,
									-1);
			return;
		}
		break;
	case HAL_OP_DISABLE:
		if (!(adapter->current_settings & MGMT_SETTING_POWERED)) {
			status = HAL_STATUS_DONE;
			break;
		}

		if (set_mode(MGMT_OP_SET_POWERED, 0x00)) {
			ipc_send(io, HAL_SERVICE_ID_BLUETOOTH, opcode, 0, NULL,
									-1);
			return;
		}
		break;
	case HAL_OP_GET_ADAPTER_PROP:
		if (get_property(buf, len)) {
			ipc_send(io, HAL_SERVICE_ID_BLUETOOTH, opcode, 0, NULL,
									-1);
			return;
		}
		break;
	default:
		DBG("Unhandled command, opcode 0x%x", opcode);
		break;
	}

	ipc_send_rsp(io, HAL_SERVICE_ID_BLUETOOTH, status);
}

const bdaddr_t *bt_adapter_get_address(void)
{
	return &adapter->bdaddr;
}

bool bt_adapter_register(GIOChannel *io)
{
	DBG("");

	notification_io = g_io_channel_ref(io);

	return true;
}

void bt_adapter_unregister(void)
{
	DBG("");

	g_io_channel_unref(notification_io);
	notification_io = NULL;
}
