/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#pragma once

#include <stdint.h>

#define BT_RAP_CS_MAX_CONFIGS   4
#define BT_RAP_CS_MAX_FREQ_SETS 3

struct bt_rap_le_cs_config {
	uint8_t num_configs;
	uint8_t config_id[BT_RAP_CS_MAX_CONFIGS];
	uint8_t main_mode_type[BT_RAP_CS_MAX_CONFIGS];
	uint8_t sub_mode_type[BT_RAP_CS_MAX_CONFIGS];
	uint8_t main_mode_min_steps[BT_RAP_CS_MAX_CONFIGS];
	uint8_t main_mode_max_steps[BT_RAP_CS_MAX_CONFIGS];
	uint8_t main_mode_repetition[BT_RAP_CS_MAX_CONFIGS];
	uint8_t mode0_steps[BT_RAP_CS_MAX_CONFIGS];
	uint8_t role[BT_RAP_CS_MAX_CONFIGS];
	uint8_t rtt_types[BT_RAP_CS_MAX_CONFIGS];
	uint8_t cs_sync_phy[BT_RAP_CS_MAX_CONFIGS];
	uint8_t channel_map[BT_RAP_CS_MAX_CONFIGS][10];
	uint8_t channel_map_repetition[BT_RAP_CS_MAX_CONFIGS];
	uint8_t channel_selection_type[BT_RAP_CS_MAX_CONFIGS];
	uint8_t channel_shape[BT_RAP_CS_MAX_CONFIGS];
	uint8_t channel_jump[BT_RAP_CS_MAX_CONFIGS];
	uint8_t companion_signal_enable[BT_RAP_CS_MAX_CONFIGS];
};

struct bt_rap_le_cs_frequency {
	uint8_t  num_durations;
	uint16_t max_procedure_duration[BT_RAP_CS_MAX_FREQ_SETS];
	uint16_t min_period_between_procedures[BT_RAP_CS_MAX_FREQ_SETS];
	uint16_t max_period_between_procedures[BT_RAP_CS_MAX_FREQ_SETS];
	uint16_t max_procedure_count[BT_RAP_CS_MAX_FREQ_SETS];
	uint8_t  min_sub_event_len[BT_RAP_CS_MAX_FREQ_SETS][3];
	uint8_t  max_sub_event_len[BT_RAP_CS_MAX_FREQ_SETS][3];
	uint8_t  tone_antenna_config_selection[BT_RAP_CS_MAX_FREQ_SETS];
	uint8_t  phy[BT_RAP_CS_MAX_FREQ_SETS];
	uint8_t  tx_power_delta[BT_RAP_CS_MAX_FREQ_SETS];
	uint8_t  preferred_peer_antenna[BT_RAP_CS_MAX_FREQ_SETS];
	uint8_t  snr_control_initiator[BT_RAP_CS_MAX_FREQ_SETS];
	uint8_t  snr_control_reflector[BT_RAP_CS_MAX_FREQ_SETS];
};

struct bt_rap_le_cs_default_settings {
	uint8_t role;
	uint8_t cs_sync_ant_sel;
	int8_t  max_tx_power;
};
