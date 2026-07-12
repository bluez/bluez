/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#pragma once

#include <stdint.h>

struct bt_rap_le_cs_config {
	uint8_t config_id;
	uint8_t main_mode_type;
	uint8_t sub_mode_type;
	uint8_t main_mode_min_steps;
	uint8_t main_mode_max_steps;
	uint8_t main_mode_repetition;
	uint8_t mode0_steps;
	uint8_t role;
	uint8_t rtt_types;
	uint8_t cs_sync_phy;
	uint8_t channel_map[10];
	uint8_t channel_map_repetition;
	uint8_t channel_selection_type;
	uint8_t channel_shape;
	uint8_t channel_jump;
	uint8_t companion_signal_enable;
};

struct bt_rap_le_cs_frequency {
	uint16_t max_procedure_duration;
	uint16_t min_period_between_procedures;
	uint16_t max_period_between_procedures;
	uint16_t max_procedure_count;
	uint8_t  min_sub_event_len[3];
	uint8_t  max_sub_event_len[3];
	uint8_t  tone_antenna_config_selection;
	uint8_t  phy;
	uint8_t  tx_power_delta;
	uint8_t  preferred_peer_antenna;
	uint8_t  snr_control_initiator;
	uint8_t  snr_control_reflector;
};

struct bt_rap_le_cs_default_settings {
	uint8_t role;
	uint8_t cs_sync_ant_sel;
	int8_t  max_tx_power;
};
