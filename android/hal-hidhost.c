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

#include "hal-log.h"
#include "hal.h"
#include "hal-msg.h"
#include "hal-ipc.h"

static const bthh_callbacks_t *bt_hh_cbacks;

static bool interface_ready(void)
{
	return bt_hh_cbacks != NULL;
}

static void handle_conn_state(void *buf)
{
	struct hal_ev_hid_conn_state *ev = buf;

	if (bt_hh_cbacks->connection_state_cb)
		bt_hh_cbacks->connection_state_cb((bt_bdaddr_t *) ev->bdaddr,
								ev->state);
}

/* will be called from notification thread context */
void bt_notify_hh(uint16_t opcode, void *buf, uint16_t len)
{
	if (!interface_ready())
		return;

	switch (opcode) {
	case HAL_EV_HID_CONN_STATE:
		handle_conn_state(buf);
		break;
	default:
		DBG("Unhandled callback opcode=0x%x", opcode);
		break;
	}
}

static bt_status_t hh_connect(bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_hid_connect cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST, HAL_OP_HID_CONNECT,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t hh_disconnect(bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_hid_disconnect cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST, HAL_OP_HID_DISCONNECT,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t hh_virtual_unplug(bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_hid_vp cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST, HAL_OP_HID_VP,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t hh_set_info(bt_bdaddr_t *bd_addr, bthh_hid_info_t hid_info)
{
	struct hal_cmd_hid_set_info cmd;

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

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST, HAL_OP_HID_SET_INFO,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t hh_get_protocol(bt_bdaddr_t *bd_addr,
					bthh_protocol_mode_t protocolMode)
{
	struct hal_cmd_hid_get_protocol cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	switch (protocolMode) {
	case BTHH_REPORT_MODE:
		cmd.mode = HAL_HID_REPORT_PROTOCOL;
		break;
	case BTHH_BOOT_MODE:
		cmd.mode = HAL_HID_BOOT_PROTOCOL;
		break;
	case BTHH_UNSUPPORTED_MODE:
		cmd.mode = HAL_HID_UNSUPPORTED_PROTOCOL;
		break;
	}

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST,
				HAL_OP_HID_GET_PROTOCOL,
				sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t hh_set_protocol(bt_bdaddr_t *bd_addr,
					bthh_protocol_mode_t protocolMode)
{
	struct hal_cmd_hid_set_protocol cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	switch (protocolMode) {
	case BTHH_REPORT_MODE:
		cmd.mode = HAL_HID_REPORT_PROTOCOL;
		break;
	case BTHH_BOOT_MODE:
		cmd.mode = HAL_HID_BOOT_PROTOCOL;
		break;
	case BTHH_UNSUPPORTED_MODE:
		cmd.mode = HAL_HID_UNSUPPORTED_PROTOCOL;
		break;
	}

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST,
				HAL_OP_HID_SET_PROTOCOL,
				sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t hh_get_report(bt_bdaddr_t *bd_addr,
						bthh_report_type_t reportType,
						uint8_t reportId,
						int bufferSize)
{
	struct hal_cmd_hid_get_report cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));
	cmd.id = reportId;

	switch (reportType) {
	case BTHH_INPUT_REPORT:
		cmd.type = HAL_HID_INPUT_REPORT;
		break;
	case BTHH_OUTPUT_REPORT:
		cmd.type = HAL_HID_OUTPUT_REPORT;
		break;
	case BTHH_FEATURE_REPORT:
		cmd.type = HAL_HID_FEATURE_REPORT;
		break;
	}

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST, HAL_OP_HID_GET_REPORT,
			sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t hh_set_report(bt_bdaddr_t *bd_addr,
						bthh_report_type_t reportType,
						char *report)
{
	struct hal_cmd_hid_set_report cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr || !report)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	switch (reportType) {
	case BTHH_INPUT_REPORT:
		cmd.type = HAL_HID_INPUT_REPORT;
		break;
	case BTHH_OUTPUT_REPORT:
		cmd.type = HAL_HID_OUTPUT_REPORT;
		break;
	case BTHH_FEATURE_REPORT:
		cmd.type = HAL_HID_FEATURE_REPORT;
		break;
	}

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST, HAL_OP_HID_SET_REPORT,
				sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t hh_send_data(bt_bdaddr_t *bd_addr, char *data)
{
	struct hal_cmd_hid_send_data cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr || !data)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_HIDHOST, HAL_OP_HID_SEND_DATA,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t hh_init(bthh_callbacks_t *callbacks)
{
	struct hal_cmd_register_module cmd;

	DBG("");

	/* store reference to user callbacks */
	bt_hh_cbacks = callbacks;

	cmd.service_id = HAL_SERVICE_ID_HIDHOST;

	return hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_REGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static void hh_cleanup(void)
{
	struct hal_cmd_unregister_module cmd;

	DBG("");

	if (!interface_ready())
		return;

	bt_hh_cbacks = NULL;

	cmd.service_id = HAL_SERVICE_ID_HIDHOST;

	hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_UNREGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bthh_interface_t hh_if = {
	.size = sizeof(hh_if),
	.init = hh_init,
	.connect = hh_connect,
	.disconnect = hh_disconnect,
	.virtual_unplug = hh_virtual_unplug,
	.set_info = hh_set_info,
	.get_protocol = hh_get_protocol,
	.set_protocol = hh_set_protocol,
	.get_report = hh_get_report,
	.set_report = hh_set_report,
	.send_data = hh_send_data,
	.cleanup = hh_cleanup
};

bthh_interface_t *bt_get_hidhost_interface(void)
{
	return &hh_if;
}
