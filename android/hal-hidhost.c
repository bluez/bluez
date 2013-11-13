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

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "hal-log.h"
#include "hal.h"
#include "hal-msg.h"
#include "hal-ipc.h"

static const bthh_callbacks_t *cbacks;

static bool interface_ready(void)
{
	return cbacks != NULL;
}

static void handle_conn_state(void *buf)
{
	struct hal_ev_hidhost_conn_state *ev = buf;

	if (cbacks->connection_state_cb)
		cbacks->connection_state_cb((bt_bdaddr_t *) ev->bdaddr,
								ev->state);
}

static void handle_info(void *buf)
{
	struct hal_ev_hidhost_info *ev = buf;
	bthh_hid_info_t info;

	info.attr_mask = ev->attr;
	info.sub_class = ev->subclass;
	info.app_id = ev->app_id;
	info.vendor_id = ev->vendor;
	info.product_id = ev->product;
	info.version = ev->version;
	info.ctry_code = ev->country;
	info.dl_len = ev->descr_len;
	memcpy(info.dsc_list, ev->descr, info.dl_len);

	if (cbacks->hid_info_cb)
		cbacks->hid_info_cb((bt_bdaddr_t *) ev->bdaddr, info);
}

static void handle_proto_mode(void *buf)
{
	struct hal_ev_hidhost_proto_mode *ev = buf;

	if (cbacks->protocol_mode_cb)
		cbacks->protocol_mode_cb((bt_bdaddr_t *) ev->bdaddr,
							ev->status, ev->mode);
}

static void handle_get_report(void *buf)
{
	struct hal_ev_hidhost_get_report *ev = buf;

	if (cbacks->get_report_cb)
		cbacks->get_report_cb((bt_bdaddr_t *) ev->bdaddr, ev->status,
							ev->data, ev->len);
}

static void handle_virtual_unplug(void *buf)
{
	struct hal_ev_hidhost_virtual_unplug *ev = buf;

	if (cbacks->virtual_unplug_cb)
		cbacks->virtual_unplug_cb((bt_bdaddr_t *) ev->bdaddr,
								ev->status);
}

/* will be called from notification thread context */
void bt_notify_hidhost(uint8_t opcode, void *buf, uint16_t len)
{
	if (!interface_ready())
		return;

	switch (opcode) {
	case HAL_EV_HIDHOST_CONN_STATE:
		handle_conn_state(buf);
		break;
	case HAL_EV_HIDHOST_INFO:
		handle_info(buf);
		break;
	case HAL_EV_HIDHOST_PROTO_MODE:
		handle_proto_mode(buf);
		break;
	case HAL_EV_HIDHOST_GET_REPORT:
		handle_get_report(buf);
		break;
	case HAL_EV_HIDHOST_VIRTUAL_UNPLUG:
		handle_virtual_unplug(buf);
		break;
	default:
		DBG("Unhandled callback opcode=0x%x", opcode);
		break;
	}
}

static bt_status_t hidhost_connect(bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_hidhost_connect cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST, HAL_OP_HIDHOST_CONNECT,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t disconnect(bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_hidhost_disconnect cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST, HAL_OP_HIDHOST_DISCONNECT,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t virtual_unplug(bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_hidhost_virtual_unplug cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST,
					HAL_OP_HIDHOST_VIRTUAL_UNPLUG,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t set_info(bt_bdaddr_t *bd_addr, bthh_hid_info_t hid_info)
{
	struct hal_cmd_hidhost_set_info cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));
	cmd.attr = hid_info.attr_mask;
	cmd.subclass = hid_info.sub_class;
	cmd.app_id = hid_info.app_id;
	cmd.vendor = hid_info.vendor_id;
	cmd.product = hid_info.product_id;
	cmd.country = hid_info.ctry_code;
	cmd.descr_len = hid_info.dl_len;
	memcpy(cmd.descr, hid_info.dsc_list, cmd.descr_len);

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST, HAL_OP_HIDHOST_SET_INFO,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t get_protocol(bt_bdaddr_t *bd_addr,
					bthh_protocol_mode_t protocol_mode)
{
	struct hal_cmd_hidhost_get_protocol cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	switch (protocol_mode) {
	case BTHH_REPORT_MODE:
		cmd.mode = HAL_HIDHOST_REPORT_PROTOCOL;
		break;
	case BTHH_BOOT_MODE:
		cmd.mode = HAL_HIDHOST_BOOT_PROTOCOL;
		break;
	default:
		return BT_STATUS_PARM_INVALID;
	}

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST,
				HAL_OP_HIDHOST_GET_PROTOCOL,
				sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t set_protocol(bt_bdaddr_t *bd_addr,
					bthh_protocol_mode_t protocol_mode)
{
	struct hal_cmd_hidhost_set_protocol cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	switch (protocol_mode) {
	case BTHH_REPORT_MODE:
		cmd.mode = HAL_HIDHOST_REPORT_PROTOCOL;
		break;
	case BTHH_BOOT_MODE:
		cmd.mode = HAL_HIDHOST_BOOT_PROTOCOL;
		break;
	default:
		return BT_STATUS_PARM_INVALID;
	}

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST,
				HAL_OP_HIDHOST_SET_PROTOCOL,
				sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t get_report(bt_bdaddr_t *bd_addr,
						bthh_report_type_t report_type,
						uint8_t report_id,
						int buffer_size)
{
	struct hal_cmd_hidhost_get_report cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));
	cmd.id = report_id;
	cmd.buf_size = buffer_size;

	switch (report_type) {
	case BTHH_INPUT_REPORT:
		cmd.type = HAL_HIDHOST_INPUT_REPORT;
		break;
	case BTHH_OUTPUT_REPORT:
		cmd.type = HAL_HIDHOST_OUTPUT_REPORT;
		break;
	case BTHH_FEATURE_REPORT:
		cmd.type = HAL_HIDHOST_FEATURE_REPORT;
		break;
	default:
		return BT_STATUS_PARM_INVALID;
	}

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST, HAL_OP_HIDHOST_GET_REPORT,
			sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t set_report(bt_bdaddr_t *bd_addr,
						bthh_report_type_t report_type,
						char *report)
{
	uint8_t buf[BLUEZ_HAL_MTU];
	struct hal_cmd_hidhost_set_report *cmd = (void *) buf;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr || !report)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd->bdaddr, bd_addr, sizeof(cmd->bdaddr));
	cmd->len = strlen(report);
	memcpy(cmd->data, report, cmd->len);

	switch (report_type) {
	case BTHH_INPUT_REPORT:
		cmd->type = HAL_HIDHOST_INPUT_REPORT;
		break;
	case BTHH_OUTPUT_REPORT:
		cmd->type = HAL_HIDHOST_OUTPUT_REPORT;
		break;
	case BTHH_FEATURE_REPORT:
		cmd->type = HAL_HIDHOST_FEATURE_REPORT;
		break;
	default:
		return BT_STATUS_PARM_INVALID;
	}

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST, HAL_OP_HIDHOST_SET_REPORT,
				sizeof(*cmd) + cmd->len, buf, 0, NULL, NULL);
}

static bt_status_t send_data(bt_bdaddr_t *bd_addr, char *data)
{
	uint8_t buf[BLUEZ_HAL_MTU];
	struct hal_cmd_hidhost_send_data *cmd = (void *) buf;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr || !data)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd->bdaddr, bd_addr, sizeof(cmd->bdaddr));
	cmd->len = strlen(data);
	memcpy(cmd->data, data, cmd->len);

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST, HAL_OP_HIDHOST_SEND_DATA,
				sizeof(*cmd) + cmd->len, buf, 0, NULL, NULL);
}

static bt_status_t init(bthh_callbacks_t *callbacks)
{
	struct hal_cmd_register_module cmd;

	DBG("");

	/* store reference to user callbacks */
	cbacks = callbacks;

	cmd.service_id = HAL_SERVICE_ID_HIDHOST;

	return hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_REGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static void cleanup(void)
{
	struct hal_cmd_unregister_module cmd;

	DBG("");

	if (!interface_ready())
		return;

	cbacks = NULL;

	cmd.service_id = HAL_SERVICE_ID_HIDHOST;

	hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_UNREGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bthh_interface_t hidhost_if = {
	.size = sizeof(hidhost_if),
	.init = init,
	.connect = hidhost_connect,
	.disconnect = disconnect,
	.virtual_unplug = virtual_unplug,
	.set_info = set_info,
	.get_protocol = get_protocol,
	.set_protocol = set_protocol,
	.get_report = get_report,
	.set_report = set_report,
	.send_data = send_data,
	.cleanup = cleanup
};

bthh_interface_t *bt_get_hidhost_interface(void)
{
	return &hidhost_if;
}
