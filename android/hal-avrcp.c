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

static bt_status_t get_player_app_value_text_rsp(int num_val,
					btrc_player_setting_text_t *p_vals)
{
	char buf[BLUEZ_HAL_MTU];
	struct hal_cmd_avrcp_get_player_values_text *cmd = (void *) buf;
	uint8_t *ptr;
	size_t len;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (num_val < 0)
		return BT_STATUS_PARM_INVALID;

	len = sizeof(*cmd);
	ptr = (uint8_t *) &cmd->values[0];
	cmd->number = write_player_setting_text(ptr, num_val, p_vals, &len);

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP,
					HAL_OP_AVRCP_GET_PLAYER_VALUES_TEXT,
					len, cmd, 0, NULL, NULL);
}

static uint8_t write_element_attr_text(uint8_t *ptr, uint8_t num_attr,
					btrc_element_attr_val_t *p_attrs,
					size_t *len)
{
	int i;

	for (i = 0; i < num_attr && *len < BLUEZ_HAL_MTU; i++) {
		int ret;

		ret = write_text(ptr, p_attrs[i].attr_id, p_attrs[i].text, len);
		if (ret == 0)
			break;

		ptr += ret;
	}

	return i;
}

static bt_status_t get_element_attr_rsp(uint8_t num_attr,
					btrc_element_attr_val_t *p_attrs)
{
	char buf[BLUEZ_HAL_MTU];
	struct hal_cmd_avrcp_get_element_attrs_text *cmd = (void *) buf;
	size_t len;
	uint8_t *ptr;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	len = sizeof(*cmd);
	ptr = (uint8_t *) &cmd->values[0];
	cmd->number = write_element_attr_text(ptr, num_attr, p_attrs, &len);

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP,
					HAL_OP_AVRCP_GET_ELEMENT_ATTRS_TEXT,
					len, cmd, 0, NULL, NULL);
}

static bt_status_t set_player_app_value_rsp(btrc_status_t rsp_status)
{
	struct hal_cmd_avrcp_set_player_attrs_value cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.status = rsp_status;

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP,
					HAL_OP_AVRCP_SET_PLAYER_ATTRS_VALUE,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t play_status_changed_rsp(btrc_notification_type_t type,
						btrc_play_status_t *play_status)
{
	char buf[BLUEZ_HAL_MTU];
	struct hal_cmd_avrcp_register_notification *cmd = (void *) buf;
	size_t len;

	cmd->event = BTRC_EVT_PLAY_STATUS_CHANGED;
	cmd->type = type;
	cmd->len = 1;
	memcpy(cmd->data, play_status, cmd->len);

	len = sizeof(*cmd) + cmd->len;

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP,
					HAL_OP_AVRCP_REGISTER_NOTIFICATION,
					len, cmd, 0, NULL, NULL);
}

static bt_status_t track_change_rsp(btrc_notification_type_t type,
							btrc_uid_t *track)
{
	char buf[BLUEZ_HAL_MTU];
	struct hal_cmd_avrcp_register_notification *cmd = (void *) buf;
	size_t len;

	cmd->event = BTRC_EVT_TRACK_CHANGE;
	cmd->type = type;
	cmd->len = sizeof(*track);
	memcpy(cmd->data, track, cmd->len);

	len = sizeof(*cmd) + cmd->len;

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP,
					HAL_OP_AVRCP_REGISTER_NOTIFICATION,
					len, cmd, 0, NULL, NULL);
}

static bt_status_t track_reached_end_rsp(btrc_notification_type_t type)
{
	struct hal_cmd_avrcp_register_notification cmd;

	cmd.event = BTRC_EVT_TRACK_REACHED_END;
	cmd.type = type;
	cmd.len = 0;

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP,
					HAL_OP_AVRCP_REGISTER_NOTIFICATION,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t track_reached_start_rsp(btrc_notification_type_t type)
{
	struct hal_cmd_avrcp_register_notification cmd;

	cmd.event = BTRC_EVT_TRACK_REACHED_START;
	cmd.type = type;
	cmd.len = 0;

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP,
					HAL_OP_AVRCP_REGISTER_NOTIFICATION,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t play_pos_changed_rsp(btrc_notification_type_t type,
							uint32_t *song_pos)
{
	char buf[BLUEZ_HAL_MTU];
	struct hal_cmd_avrcp_register_notification *cmd = (void *) buf;
	size_t len;

	cmd->event = BTRC_EVT_PLAY_POS_CHANGED;
	cmd->type = type;
	cmd->len = sizeof(*song_pos);
	memcpy(cmd->data, song_pos, cmd->len);

	len = sizeof(*cmd) + cmd->len;

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP,
					HAL_OP_AVRCP_REGISTER_NOTIFICATION,
					len, cmd, 0, NULL, NULL);
}

static bt_status_t settings_changed_rsp(btrc_notification_type_t type,
					btrc_player_settings_t *player_setting)
{
	char buf[BLUEZ_HAL_MTU];
	struct hal_cmd_avrcp_register_notification *cmd = (void *) buf;
	struct hal_avrcp_player_attr_value *attrs;
	size_t len, param_len;
	int i;

	param_len = player_setting->num_attr * sizeof(*attrs);
	len = sizeof(*cmd) + param_len;

	if (len > BLUEZ_HAL_MTU)
		return BT_STATUS_PARM_INVALID;

	cmd->event = BTRC_EVT_APP_SETTINGS_CHANGED;
	cmd->type = type;
	cmd->len = param_len;

	attrs = (struct hal_avrcp_player_attr_value *) &cmd->data[0];
	for (i = 0; i < player_setting->num_attr; i++) {
		attrs[i].attr = player_setting->attr_ids[i];
		attrs[i].value = player_setting->attr_values[i];
	}

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP,
					HAL_OP_AVRCP_REGISTER_NOTIFICATION,
					len, cmd, 0, NULL, NULL);
}

static bt_status_t register_notification_rsp(btrc_event_id_t event_id,
					btrc_notification_type_t type,
					btrc_register_notification_t *p_param)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	switch (event_id) {
	case BTRC_EVT_PLAY_STATUS_CHANGED:
		return play_status_changed_rsp(type, &p_param->play_status);
	case BTRC_EVT_TRACK_CHANGE:
		return track_change_rsp(type, &p_param->track);
	case BTRC_EVT_TRACK_REACHED_END:
		return track_reached_end_rsp(type);
	case BTRC_EVT_TRACK_REACHED_START:
		return track_reached_start_rsp(type);
	case BTRC_EVT_PLAY_POS_CHANGED:
		return play_pos_changed_rsp(type, &p_param->song_pos);
	case BTRC_EVT_APP_SETTINGS_CHANGED:
		return settings_changed_rsp(type, &p_param->player_setting);
	default:
		return BT_STATUS_PARM_INVALID;
	}
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
	.get_player_app_value_text_rsp = get_player_app_value_text_rsp,
	.get_element_attr_rsp = get_element_attr_rsp,
	.set_player_app_value_rsp = set_player_app_value_rsp,
	.register_notification_rsp = register_notification_rsp,
	.cleanup = cleanup
};

btrc_interface_t *bt_get_avrcp_interface()
{
	return &iface;
}
