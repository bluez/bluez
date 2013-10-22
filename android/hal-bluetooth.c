/*
 * Copyright (C) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "hal-log.h"
#include "hal.h"
#include "hal-msg.h"
#include "hal-ipc.h"

static const bt_callbacks_t *bt_hal_cbacks = NULL;

static void handle_adapter_state_changed(void *buf)
{
	struct hal_msg_ev_bt_adapter_state_changed *ev = buf;

	if (bt_hal_cbacks->adapter_state_changed_cb)
		bt_hal_cbacks->adapter_state_changed_cb(ev->state);
}

/* will be called from notification thread context */
void bt_notify_adapter(uint16_t opcode, void *buf, uint16_t len)
{
	if (!bt_hal_cbacks)
		return;

	switch (opcode) {
	case HAL_MSG_EV_BT_ADAPTER_STATE_CHANGED:
		handle_adapter_state_changed(buf);
		break;
	default:
		DBG("Unhandled callback opcode=0x%x", opcode);
		break;
	}
}

static bool interface_ready(void)
{
	return bt_hal_cbacks != NULL;
}

static int init(bt_callbacks_t *callbacks)
{
	struct hal_msg_cmd_register_module cmd;

	DBG("");

	if (interface_ready())
		return BT_STATUS_SUCCESS;

	if (!hal_ipc_init())
		return BT_STATUS_FAIL;

	bt_hal_cbacks = callbacks;

	cmd.service_id = HAL_SERVICE_ID_BLUETOOTH;

	if (hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_MSG_OP_REGISTER_MODULE,
				sizeof(cmd), &cmd, 0, NULL, NULL) < 0) {
		error("Failed to register 'bluetooth' service");
		goto fail;
	}

	cmd.service_id = HAL_SERVICE_ID_SOCK;

	if (hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_MSG_OP_REGISTER_MODULE,
				sizeof(cmd), &cmd, 0, NULL, NULL) < 0) {
		error("Failed to register 'socket' service");
		goto fail;
	}

	return BT_STATUS_SUCCESS;

fail:

	hal_ipc_cleanup();
	bt_hal_cbacks = NULL;
	return BT_STATUS_FAIL;

}

static int enable(void)
{
	int ret;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	ret = hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_MSG_OP_BT_ENABLE, 0, NULL,
								0, NULL, NULL);
	if (ret < 0)
		return -ret;

	return BT_STATUS_SUCCESS;
}

static int disable(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static void cleanup(void)
{
	DBG("");

	if (!interface_ready())
		return;

	hal_ipc_cleanup();

	bt_hal_cbacks = NULL;
}

static int get_adapter_properties(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int get_adapter_property(bt_property_type_t type)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int set_adapter_property(const bt_property_t *property)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (property == NULL)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static int get_remote_device_properties(bt_bdaddr_t *remote_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int get_remote_device_property(bt_bdaddr_t *remote_addr,
						bt_property_type_t type)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int set_remote_device_property(bt_bdaddr_t *remote_addr,
						const bt_property_t *property)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int get_remote_service_record(bt_bdaddr_t *remote_addr, bt_uuid_t *uuid)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int get_remote_services(bt_bdaddr_t *remote_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int start_discovery(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int cancel_discovery(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int create_bond(const bt_bdaddr_t *bd_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static int cancel_bond(const bt_bdaddr_t *bd_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int remove_bond(const bt_bdaddr_t *bd_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int pin_reply(const bt_bdaddr_t *bd_addr, uint8_t accept,
				uint8_t pin_len, bt_pin_code_t *pin_code)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int ssp_reply(const bt_bdaddr_t *bd_addr, bt_ssp_variant_t variant,
					uint8_t accept, uint32_t passkey)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static const void *get_profile_interface(const char *profile_id)
{
	DBG("%s: %s", __func__, profile_id);

	if (!interface_ready())
		return NULL;

	if (!strcmp(profile_id, BT_PROFILE_SOCKETS_ID))
		return bt_get_sock_interface();

	if (!strcmp(profile_id, BT_PROFILE_HIDHOST_ID))
		return bt_get_hidhost_interface();

	if (!strcmp(profile_id, BT_PROFILE_PAN_ID))
		return bt_get_pan_interface();

	return NULL;
}

static int dut_mode_configure(uint8_t enable)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int dut_mode_send(uint16_t opcode, uint8_t *buf, uint8_t len)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static const bt_interface_t bluetooth_if = {
	.size = sizeof(bt_interface_t),
	.init = init,
	.enable = enable,
	.disable = disable,
	.cleanup = cleanup,
	.get_adapter_properties = get_adapter_properties,
	.get_adapter_property = get_adapter_property,
	.set_adapter_property = set_adapter_property,
	.get_remote_device_properties = get_remote_device_properties,
	.get_remote_device_property = get_remote_device_property,
	.set_remote_device_property = set_remote_device_property,
	.get_remote_service_record = get_remote_service_record,
	.get_remote_services = get_remote_services,
	.start_discovery = start_discovery,
	.cancel_discovery = cancel_discovery,
	.create_bond = create_bond,
	.remove_bond = remove_bond,
	.cancel_bond = cancel_bond,
	.pin_reply = pin_reply,
	.ssp_reply = ssp_reply,
	.get_profile_interface = get_profile_interface,
	.dut_mode_configure = dut_mode_configure,
	.dut_mode_send = dut_mode_send
};

static const bt_interface_t *get_bluetooth_interface(void)
{
	DBG("");

	return &bluetooth_if;
}

static int close_bluetooth(struct hw_device_t *device)
{
	DBG("");

	cleanup();

	return 0;
}

static int open_bluetooth(const struct hw_module_t *module, char const *name,
					struct hw_device_t **device)
{
	bluetooth_device_t *dev = malloc(sizeof(bluetooth_device_t));

	DBG("");

	memset(dev, 0, sizeof(bluetooth_device_t));
	dev->common.tag = HARDWARE_DEVICE_TAG;
	dev->common.version = 0;
	dev->common.module = (struct hw_module_t *) module;
	dev->common.close = close_bluetooth;
	dev->get_bluetooth_interface = get_bluetooth_interface;

	*device = (struct hw_device_t *) dev;

	return 0;
}

static struct hw_module_methods_t bluetooth_module_methods = {
	.open = open_bluetooth,
};

struct hw_module_t HAL_MODULE_INFO_SYM = {
	.tag = HARDWARE_MODULE_TAG,
	.version_major = 1,
	.version_minor = 0,
	.id = BT_HARDWARE_MODULE_ID,
	.name = "BlueZ Bluetooth stack",
	.author = "Intel Corporation",
	.methods = &bluetooth_module_methods
};
