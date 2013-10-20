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

#include <hardware/bluetooth.h>
#include <hardware/bt_hh.h>

#include "hal-log.h"
#include "hal.h"

bthh_callbacks_t *bt_hh_cbacks;

static bool interface_ready(void)
{
	return bt_hh_cbacks != NULL;
}

static bt_status_t bt_hidhost_connect(bt_bdaddr_t *bd_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t bt_hidhost_disconnect(bt_bdaddr_t *bd_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t bt_hidhost_virtual_unplug(bt_bdaddr_t *bd_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t bt_hidhost_set_info(bt_bdaddr_t *bd_addr,
						bthh_hid_info_t hid_info)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t bt_hidhost_get_protocol(bt_bdaddr_t *bd_addr,
					bthh_protocol_mode_t protocolMode)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t bt_hidhost_set_protocol(bt_bdaddr_t *bd_addr,
					bthh_protocol_mode_t protocolMode)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t bt_hidhost_get_report(bt_bdaddr_t *bd_addr,
						bthh_report_type_t reportType,
						uint8_t reportId,
						int bufferSize)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t bt_hidhost_set_report(bt_bdaddr_t *bd_addr,
						bthh_report_type_t reportType,
						char *report)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr || !report)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t bt_hidhost_send_data(bt_bdaddr_t *bd_addr, char *data)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr || !data)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t bt_hidhost_init(bthh_callbacks_t *callbacks)
{
	DBG("");

	/* store reference to user callbacks */
	bt_hh_cbacks = callbacks;

	/* TODO: start HID Host thread */

	/* TODO: enable service */

	return BT_STATUS_SUCCESS;
}

static void bt_hidhost_cleanup(void)
{
	DBG("");

	if (!interface_ready())
		return;

	/* TODO: disable service */

	/* TODO: stop HID Host thread */

	bt_hh_cbacks = NULL;
}

static bthh_interface_t bt_hidhost_if = {
	.size = sizeof(bt_hidhost_if),
	.init = bt_hidhost_init,
	.connect = bt_hidhost_connect,
	.disconnect = bt_hidhost_disconnect,
	.virtual_unplug = bt_hidhost_virtual_unplug,
	.set_info = bt_hidhost_set_info,
	.get_protocol = bt_hidhost_get_protocol,
	.set_protocol = bt_hidhost_set_protocol,
	.get_report = bt_hidhost_get_report,
	.set_report = bt_hidhost_set_report,
	.send_data = bt_hidhost_send_data,
	.cleanup = bt_hidhost_cleanup
};

bthh_interface_t *bt_get_hidhost_interface(void)
{
	return &bt_hidhost_if;
}
