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

#include "client/textconv.h"

static const bt_callbacks_t *bt_hal_cbacks = NULL;

static void handle_adapter_state_changed(void *buf)
{
	struct hal_ev_adapter_state_changed *ev = buf;

	if (bt_hal_cbacks->adapter_state_changed_cb)
		bt_hal_cbacks->adapter_state_changed_cb(ev->state);
}

static void handle_adapter_props_changed(void *buf, uint16_t len)
{
	struct hal_ev_adapter_props_changed *ev = buf;
	bt_property_t props[ev->num_props];
	struct hal_property *hal_prop;
	void *p;
	int i;

	if (!bt_hal_cbacks->adapter_properties_cb)
		return;

	hal_prop = ev->props;
	p = ev->props;

	for (i = 0; i < ev->num_props; i++) {
		if (p + sizeof(*hal_prop) + hal_prop->len > buf + len) {
			error("invalid adapter properties event, aborting");
			exit(EXIT_FAILURE);
		}

		props[i].type = hal_prop->type;
		props[i].len = hal_prop->len;
		props[i].val = hal_prop->val;

		p += sizeof(*hal_prop) + hal_prop->len;
		hal_prop = p;
	}

	bt_hal_cbacks->adapter_properties_cb(ev->status, ev->num_props, props);
}

static void handle_bond_state_change(void *buf)
{
	struct hal_ev_bond_state_changed *ev = buf;
	bt_bdaddr_t *addr = (bt_bdaddr_t *) ev->bdaddr;

	if (bt_hal_cbacks->bond_state_changed_cb)
		bt_hal_cbacks->bond_state_changed_cb(ev->status, addr,
								ev->state);
}

static void handle_pin_request(void *buf)
{
	struct hal_ev_pin_request *ev = buf;
	/* Those are declared as packed, so it's safe to assign pointers */
	bt_bdaddr_t *addr = (bt_bdaddr_t *) ev->bdaddr;
	bt_bdname_t *name = (bt_bdname_t *) ev->name;

	if (bt_hal_cbacks->pin_request_cb)
		bt_hal_cbacks->pin_request_cb(addr, name, ev->class_of_dev);
}

void bt_thread_associate(void)
{
	if (bt_hal_cbacks->thread_evt_cb)
		bt_hal_cbacks->thread_evt_cb(ASSOCIATE_JVM);
}

void bt_thread_disassociate(void)
{
	if (bt_hal_cbacks->thread_evt_cb)
		bt_hal_cbacks->thread_evt_cb(DISASSOCIATE_JVM);
}

static bool interface_ready(void)
{
	return bt_hal_cbacks != NULL;
}

/* will be called from notification thread context */
void bt_notify_adapter(uint16_t opcode, void *buf, uint16_t len)
{
	if (!interface_ready())
		return;

	switch (opcode) {
	case HAL_EV_ADAPTER_STATE_CHANGED:
		handle_adapter_state_changed(buf);
		break;
	case HAL_EV_ADAPTER_PROPS_CHANGED:
		handle_adapter_props_changed(buf, len);
		break;
	case HAL_EV_BOND_STATE_CHANGED:
		handle_bond_state_change(buf);
		break;
	case HAL_EV_PIN_REQUEST:
		handle_pin_request(buf);
		break;
	default:
		DBG("Unhandled callback opcode=0x%x", opcode);
		break;
	}
}

static int init(bt_callbacks_t *callbacks)
{
	struct hal_cmd_register_module cmd;
	int status;

	DBG("");

	if (interface_ready())
		return BT_STATUS_SUCCESS;

	bt_hal_cbacks = callbacks;

	if (!hal_ipc_init()) {
		bt_hal_cbacks = NULL;
		return BT_STATUS_FAIL;
	}

	cmd.service_id = HAL_SERVICE_ID_BLUETOOTH;

	status = hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_REGISTER_MODULE,
					sizeof(cmd), &cmd, NULL, NULL, NULL);
	if (status != BT_STATUS_SUCCESS) {
		error("Failed to register 'bluetooth' service");
		goto fail;
	}

	cmd.service_id = HAL_SERVICE_ID_SOCK;

	status = hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_REGISTER_MODULE,
					sizeof(cmd), &cmd, NULL, NULL, NULL);
	if (status != BT_STATUS_SUCCESS) {
		error("Failed to register 'socket' service");
		goto fail;
	}

	return status;

fail:
	hal_ipc_cleanup();
	bt_hal_cbacks = NULL;
	return status;
}

static int enable(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return hal_ipc_cmd(HAL_SERVICE_ID_BLUETOOTH, HAL_OP_ENABLE, 0, NULL, 0,
								NULL, NULL);
}

static int disable(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return hal_ipc_cmd(HAL_SERVICE_ID_BLUETOOTH, HAL_OP_DISABLE, 0, NULL, 0,
								NULL, NULL);
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

	return hal_ipc_cmd(HAL_SERVICE_ID_BLUETOOTH, HAL_OP_GET_ADAPTER_PROPS,
						0, NULL, 0, NULL, NULL);
}

static int get_adapter_property(bt_property_type_t type)
{
	struct hal_cmd_get_adapter_prop cmd;

	DBG("prop: %s", bt_property_type_t2str(type));

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	switch (type) {
	case BT_PROPERTY_BDNAME:
	case BT_PROPERTY_BDADDR:
	case BT_PROPERTY_UUIDS:
	case BT_PROPERTY_CLASS_OF_DEVICE:
	case BT_PROPERTY_TYPE_OF_DEVICE:
	case BT_PROPERTY_SERVICE_RECORD:
	case BT_PROPERTY_ADAPTER_SCAN_MODE:
	case BT_PROPERTY_ADAPTER_BONDED_DEVICES:
	case BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT:
		break;
	default:
		return BT_STATUS_PARM_INVALID;
	}

	/* type match IPC type */
	cmd.type = type;

	return hal_ipc_cmd(HAL_SERVICE_ID_BLUETOOTH, HAL_OP_GET_ADAPTER_PROP,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static int set_adapter_property(const bt_property_t *property)
{
	char buf[sizeof(struct hal_cmd_set_adapter_prop) + property->len];
	struct hal_cmd_set_adapter_prop *cmd = (void *) buf;

	DBG("prop: %s", bt_property_type_t2str(property->type));

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	switch (property->type) {
	case BT_PROPERTY_BDNAME:
	case BT_PROPERTY_ADAPTER_SCAN_MODE:
	case BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT:
		break;
	default:
		return BT_STATUS_PARM_INVALID;
	}

	/* type match IPC type */
	cmd->type = property->type;
	cmd->len = property->len;
	memcpy(cmd->val, property->val, property->len);

	return hal_ipc_cmd(HAL_SERVICE_ID_BLUETOOTH, HAL_OP_SET_ADAPTER_PROP,
					sizeof(buf), cmd, 0, NULL, NULL);
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
	struct hal_cmd_create_bond cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_BLUETOOTH, HAL_OP_CREATE_BOND,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static int cancel_bond(const bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_cancel_bond cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_BLUETOOTH, HAL_OP_CANCEL_BOND,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static int remove_bond(const bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_remove_bond cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_BLUETOOTH, HAL_OP_REMOVE_BOND,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static int pin_reply(const bt_bdaddr_t *bd_addr, uint8_t accept,
				uint8_t pin_len, bt_pin_code_t *pin_code)
{
	struct hal_cmd_pin_reply cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));
	cmd.accept = accept;
	cmd.pin_len = pin_len;
	memcpy(cmd.pin_code, pin_code, sizeof(cmd.pin_code));

	return hal_ipc_cmd(HAL_SERVICE_ID_BLUETOOTH, HAL_OP_PIN_REPLY,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static int ssp_reply(const bt_bdaddr_t *bd_addr, bt_ssp_variant_t variant,
					uint8_t accept, uint32_t passkey)
{
	struct hal_cmd_ssp_reply cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));
	/* type match IPC type */
	cmd.ssp_variant = variant;
	cmd.accept = accept;
	cmd.passkey = passkey;

	return hal_ipc_cmd(HAL_SERVICE_ID_BLUETOOTH, HAL_OP_SSP_REPLY,
					sizeof(cmd), &cmd, 0, NULL, NULL);
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

	if (!strcmp(profile_id, BT_PROFILE_ADVANCED_AUDIO_ID))
		return bt_get_av_interface();

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
