/*
 * Copyright (C) 2014 Intel Corporation
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

static const btrc_callbacks_t *cbs = NULL;

static bool interface_ready(void)
{
	return cbs != NULL;
}

static bt_status_t init(btrc_callbacks_t *callbacks)
{
	struct hal_cmd_register_module cmd;
	int ret;

	DBG("");

	if (interface_ready())
		return BT_STATUS_DONE;

	cbs = callbacks;

	cmd.service_id = HAL_SERVICE_ID_AVRCP;

	ret = hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_REGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);

	if (ret != BT_STATUS_SUCCESS) {
		cbs = NULL;
		hal_ipc_unregister(HAL_SERVICE_ID_AVRCP);
	}

	return ret;
}

static bt_status_t get_play_status_rsp(btrc_play_status_t status,
					uint32_t song_len, uint32_t song_pos)
{
	struct hal_cmd_avrcp_get_play_status cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.status = status;
	cmd.duration = song_len;
	cmd.position = song_pos;

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP, HAL_OP_AVRCP_GET_PLAY_STATUS,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t list_player_app_attr_rsp(int num_attr,
						btrc_player_attr_t *p_attrs)
{
	char buf[BLUEZ_HAL_MTU];
	struct hal_cmd_avrcp_list_player_attrs *cmd = (void *) buf;
	size_t len;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (num_attr < 0)
		return BT_STATUS_PARM_INVALID;

	len = sizeof(*cmd) + num_attr;
	if (len > BLUEZ_HAL_MTU)
		return BT_STATUS_PARM_INVALID;

	cmd->number = num_attr;
	memcpy(cmd->attrs, p_attrs, num_attr);

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP,
					HAL_OP_AVRCP_LIST_PLAYER_ATTRS,
					len, cmd, 0, NULL, NULL);
}

static bt_status_t list_player_app_value_rsp(int num_val, uint8_t *p_vals)
{
	char buf[BLUEZ_HAL_MTU];
	struct hal_cmd_avrcp_list_player_values *cmd = (void *) buf;
	size_t len;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (num_val < 0)
		return BT_STATUS_PARM_INVALID;

	len = sizeof(*cmd) + num_val;

	if (len > BLUEZ_HAL_MTU)
		return BT_STATUS_PARM_INVALID;

	cmd->number = num_val;
	memcpy(cmd->values, p_vals, num_val);

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP,
					HAL_OP_AVRCP_LIST_PLAYER_VALUES,
					len, cmd, 0, NULL, NULL);
}

static bt_status_t get_player_app_value_rsp(btrc_player_settings_t *p_vals)
{
	char buf[BLUEZ_HAL_MTU];
	struct hal_cmd_avrcp_get_player_attrs *cmd = (void *) buf;
	size_t len, attrs_len;
	int i;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!p_vals)
		return BT_STATUS_PARM_INVALID;

	attrs_len = p_vals->num_attr *
				sizeof(struct hal_avrcp_player_attr_value);
	len = sizeof(*cmd) + attrs_len;

	if (len > BLUEZ_HAL_MTU)
		return BT_STATUS_PARM_INVALID;

	cmd->number = p_vals->num_attr;

	for (i = 0; i < p_vals->num_attr; i++) {
		cmd->attrs[i].attr = p_vals->attr_ids[i];
		cmd->attrs[i].value = p_vals->attr_values[i];
	}

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP,
					HAL_OP_AVRCP_GET_PLAYER_ATTRS,
					len, cmd, 0, NULL, NULL);
}

static int write_text(uint8_t *ptr, uint8_t id, uint8_t *text, size_t *len)
{
	struct hal_avrcp_player_setting_text *value = (void *) ptr;
	size_t attr_len = sizeof(*value);

	if (attr_len + *len > BLUEZ_HAL_MTU)
		return 0;

	value->id = id;
	value->len = strnlen((const char *) text, BTRC_MAX_ATTR_STR_LEN);

	*len += attr_len;
	ptr += attr_len;

	if (value->len + *len > BLUEZ_HAL_MTU)
		value->len = BLUEZ_HAL_MTU - *len;

	memcpy(value->text, text, value->len);

	*len += value->len;

	return attr_len + value->len;
}

static uint8_t write_player_setting_text(uint8_t *ptr, uint8_t num_attr,
					btrc_player_setting_text_t *p_attrs,
					size_t *len)
{
	int i;

	for (i = 0; i < num_attr && *len < BLUEZ_HAL_MTU; i++) {
		int ret;

		ret = write_text(ptr, p_attrs[i].id, p_attrs[i].text, len);
		if (ret == 0)
			break;

		ptr += ret;
	}

	return i;
}

static bt_status_t get_player_app_attr_text_rsp(int num_attr,
					btrc_player_setting_text_t *p_attrs)
{
	char buf[BLUEZ_HAL_MTU];
	struct hal_cmd_avrcp_get_player_attrs_text *cmd = (void *) buf;
	uint8_t *ptr;
	size_t len;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (num_attr < 0 || num_attr > BTRC_MAX_APP_SETTINGS)
		return BT_STATUS_PARM_INVALID;

	len = sizeof(*cmd);
	ptr = (uint8_t *) &cmd->attrs[0];
	cmd->number = write_player_setting_text(ptr, num_attr, p_attrs, &len);

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP,
					HAL_OP_AVRCP_GET_PLAYER_ATTRS_TEXT,
					len, cmd, 0, NULL, NULL);
}

static void cleanup()
{
	struct hal_cmd_unregister_module cmd;

	DBG("");

	if (!interface_ready())
		return;

	cbs = NULL;

	cmd.service_id = HAL_SERVICE_ID_AVRCP;

	hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_UNREGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);

	hal_ipc_unregister(HAL_SERVICE_ID_AVRCP);
}

static btrc_interface_t iface = {
	.size = sizeof(iface),
	.init = init,
	.get_play_status_rsp = get_play_status_rsp,
	.list_player_app_attr_rsp = list_player_app_attr_rsp,
	.list_player_app_value_rsp = list_player_app_value_rsp,
	.get_player_app_value_rsp = get_player_app_value_rsp,
	.get_player_app_attr_text_rsp = get_player_app_attr_text_rsp,
	.cleanup = cleanup
};

btrc_interface_t *bt_get_avrcp_interface()
{
	return &iface;
}
