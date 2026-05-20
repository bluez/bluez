// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

 #include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define CS_MODE_ZERO_WIRE_INIT_SIZE 7
#define CS_MODE_ZERO_WIRE_REF_SIZE 3
#define CS_MODE_ONE_WIRE_SIZE_MIN 6
#define CS_MODE_ONE_WIRE_SIZE_MAX 12

struct cs_step_data;

typedef struct {
	int8_t  mode_type;
	int8_t  sub_mode_type;
	int32_t rtt_type;
	uint8_t channel_map[10];
	int32_t min_main_mode_steps;
	int32_t max_main_mode_steps;
	int8_t  main_mode_repetition;
	int8_t  mode_0_steps;
	int32_t role;
	int8_t  cs_sync_phy_type;
	int8_t  channel_selection_type;
	int8_t  ch3c_shape_type;
	int8_t  ch3c_jump;
	int32_t channel_map_repetition;
	int32_t t_ip1_time_us;
	int32_t t_ip2_time_us;
	int32_t t_fcs_time_us;
	int8_t  t_pm_time_us;
	int8_t  t_sw_time_us_supported_by_local;
	int8_t  t_sw_time_us_supported_by_remote;
	int32_t ble_conn_interval;
} cs_config_param;

typedef struct {
	int8_t  tone_antenna_config_selection;
	int32_t subevent_len_us;
	int8_t  subevents_per_event;
	int32_t subevent_interval;
	int32_t event_interval;
	int32_t procedure_interval;
	int32_t procedure_count;
	int32_t max_procedure_len;
} cs_procedure_enable_config;

typedef struct {
	int32_t i_sample;
	int32_t q_sample;
} cs_pct_iq_sample;

typedef union {
	int32_t toa_tod_initiator;
	int32_t tod_toa_reflector;
} cs_rtt_toa_tod_data;

typedef struct {
	int8_t  packet_quality;
	int8_t  packet_rssi_dbm;
	int8_t  packet_antenna;
	int32_t initiator_measured_freq_offset;
} cs_mode_zero_data;

typedef struct {
	int8_t               packet_quality;
	int8_t               packet_nadm;
	int8_t               packet_rssi_dbm;
	cs_rtt_toa_tod_data  rtt_toa_tod_data;
	int8_t               packet_antenna;
	cs_pct_iq_sample     packet_pct1;
	cs_pct_iq_sample     packet_pct2;
} cs_mode_one_data;

typedef struct {
	int8_t            antenna_permutation_index;
	int32_t           tone_pct_iq_sample_size;
	cs_pct_iq_sample *tone_pct_iq_samples;
	int32_t           tone_quality_indicators_size;
	uint8_t          *tone_quality_indicators;
} cs_mode_two_data;

typedef struct {
	cs_mode_one_data mode_one_data;
	cs_mode_two_data mode_two_data;
} cs_mode_three_data;

typedef union {
	cs_mode_zero_data  mode_zero_data;
	cs_mode_one_data   mode_one_data;
	cs_mode_two_data   mode_two_data;
	cs_mode_three_data mode_three_data;
} cs_mode_data;

typedef struct {
	int8_t       step_channel;
	int8_t       step_mode;
	cs_mode_data step_mode_data;
} cs_step_data;

typedef struct {
	int32_t        start_acl_conn_event_counter;
	int32_t        frequency_compensation;
	int8_t         reference_power_level_dbm;
	int8_t         num_antenna_paths;
	int8_t         subevent_abort_reason;
	int64_t        step_data_size;
	cs_step_data  *step_data;
	int64_t        timestamp_nanos;
} cs_subevent_result_data;

typedef struct bcs_procedure_data {
	int32_t                    procedure_counter;
	int32_t                    procedure_sequence;
	int8_t                     initiator_selected_tx_power;
	int8_t                     reflector_selected_tx_power;
	int32_t                    initiator_subevent_result_data_size;
	cs_subevent_result_data   *initiator_subevent_result_data;
	int8_t                     initiator_procedure_abort_reason;
	int32_t                    reflector_subevent_result_data_size;
	cs_subevent_result_data   *reflector_subevent_result_data;
	int8_t                     reflector_procedure_abort_reason;
	cs_procedure_enable_config procedure_enable_config;
	cs_config_param            cs_config_param;
} bcs_procedure_data;

/* cs_subevent_result_data lifecycle */
cs_subevent_result_data *bcs_subevent_result_data_new(
				int32_t start_acl_conn_event_counter,
				int32_t frequency_compensation,
				int8_t reference_power_level_dbm,
				int8_t num_antenna_paths,
				int8_t subevent_abort_reason,
				int64_t timestamp_nanos,
				const cs_step_data *steps,
				int64_t num_steps);

void bcs_subevent_result_data_free(cs_subevent_result_data *subevent);

/* bcs_procedure_data lifecycle */
bcs_procedure_data *bcs_procedure_data_new(void);
void bcs_procedure_data_free(bcs_procedure_data *proc);
void bcs_procedure_data_clear(bcs_procedure_data *proc);

bool bcs_procedure_data_add_initiator_subevent(bcs_procedure_data *proc,
					cs_subevent_result_data *subevent);
bool bcs_procedure_data_add_reflector_subevent(bcs_procedure_data *proc,
					cs_subevent_result_data *subevent);

/* Set nested config fields */
void bcs_procedure_data_set_config(bcs_procedure_data *proc,
					const cs_config_param *config);
void bcs_procedure_data_set_procedure_config(bcs_procedure_data *proc,
					const cs_procedure_enable_config *config);

void hci_step_to_bcs_step(const struct cs_step_data *src,
			   cs_step_data *dst,
			   uint8_t rtt_type,
			   uint8_t num_antenna_paths);
