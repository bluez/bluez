// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <stdbool.h>
#include <inttypes.h>

#include "src/shared/io.h"
#include "bluetooth/mgmt.h"
#include "src/shared/hci.h"

struct bt_rap;
struct gatt_db;
struct bt_gatt_client;

/* Channel Sounding Events */
struct bt_rap_hci_cs_options {
	uint8_t role;
	uint8_t cs_sync_ant_sel;
	int8_t max_tx_power;
	int rtt_type;
};

#define CS_MODE_ZERO				0x00
#define CS_MODE_ONE				0x01
#define CS_MODE_TWO				0x02
#define CS_MODE_THREE				0x03

#define CS_REFLECTOR			0x01
#define CS_INITIATOR			0x00

#define CS_MAX_ANT_PATHS			0x05
#define CS_MAX_STEPS			0xA0
#define CS_MAX_STEP_DATA_LEN		0xFF

struct rap_ev_cs_config_cmplt {
	uint8_t status;
	uint16_t conn_hdl;
	uint8_t config_id;
	uint8_t action;
	uint8_t main_mode_type;
	uint8_t sub_mode_type;
	uint8_t min_main_mode_steps;
	uint8_t max_main_mode_steps;
	uint8_t main_mode_rep;
	uint8_t mode_0_steps;
	uint8_t role;
	uint8_t rtt_type;
	uint8_t cs_sync_phy;
	uint8_t channel_map[10];
	uint8_t channel_map_rep;
	uint8_t channel_sel_type;
	uint8_t ch3c_shape;
	uint8_t ch3c_jump;
	uint8_t reserved;
	uint8_t t_ip1_time;
	uint8_t t_ip2_time;
	uint8_t t_fcs_time;
	uint8_t t_pm_time;
};

struct rap_ev_cs_sec_enable_cmplt {
	uint8_t status;
	uint16_t conn_hdl;
};

struct rap_ev_cs_proc_enable_cmplt {
	uint8_t status;
	uint16_t conn_hdl;
	uint8_t config_id;
	uint8_t state;
	uint8_t tone_ant_config_sel;
	int8_t sel_tx_pwr;
	uint8_t sub_evt_len[3];
	uint8_t sub_evts_per_evt;
	uint16_t sub_evt_intrvl;
	uint16_t evt_intrvl;
	uint16_t proc_intrvl;
	uint16_t proc_counter;
	uint16_t max_proc_len;
};

struct pct_iq_sample {
	int16_t i_sample;
	int16_t q_sample;
};

struct cs_mode_zero_data {
	uint8_t packet_quality;
	uint8_t packet_rssi_dbm;
	uint8_t packet_ant;
	uint32_t init_measured_freq_offset;
};

struct cs_mode_one_data {
	uint8_t packet_quality;
	uint8_t packet_rssi_dbm;
	uint8_t packet_ant;
	uint8_t packet_nadm;
	int16_t toa_tod_init;
	int16_t tod_toa_refl;
	struct pct_iq_sample packet_pct1;
	struct pct_iq_sample packet_pct2;
};

struct cs_mode_two_data {
	uint8_t ant_perm_index;
	struct pct_iq_sample tone_pct[5];
	uint8_t tone_quality_indicator[5];
};

struct cs_mode_three_data {
	struct cs_mode_one_data mode_one_data;
	struct cs_mode_two_data mode_two_data;
};

union cs_mode_data {
	struct cs_mode_zero_data mode_zero_data;
	struct cs_mode_one_data mode_one_data;
	struct cs_mode_two_data mode_two_data;
	struct cs_mode_three_data mode_three_data;
};

struct cs_step_data {
	uint8_t step_mode;
	uint8_t step_chnl;
	uint8_t step_data_length;
	union cs_mode_data step_mode_data;
};

struct rap_ev_cs_subevent_result {
	uint16_t conn_hdl;
	uint8_t config_id;
	uint16_t start_acl_conn_evt_counter;
	uint16_t proc_counter;
	uint16_t freq_comp;
	uint8_t ref_pwr_lvl;
	uint8_t proc_done_status;
	uint8_t subevt_done_status;
	uint8_t abort_reason;
	uint8_t num_ant_paths;
	uint8_t num_steps_reported;
	struct cs_step_data step_data[];
};

struct rap_ev_cs_subevent_result_cont {
	uint16_t conn_hdl;
	uint8_t config_id;
	uint8_t proc_done_status;
	uint8_t subevt_done_status;
	uint8_t abort_reason;
	uint8_t num_ant_paths;
	uint8_t num_steps_reported;
	struct cs_step_data step_data[];
};

typedef void (*bt_rap_debug_func_t)(const char *str, void *user_data);
typedef void (*bt_rap_ready_func_t)(struct bt_rap *rap, void *user_data);
typedef void (*bt_rap_destroy_func_t)(void *user_data);
typedef void (*bt_rap_func_t)(struct bt_rap *rap, void *user_data);

struct bt_rap *bt_rap_ref(struct bt_rap *rap);
void bt_rap_unref(struct bt_rap *rap);

void bt_rap_add_db(struct gatt_db *db);

bool bt_rap_attach(struct bt_rap *rap, struct bt_gatt_client *client);
void bt_rap_detach(struct bt_rap *rap);

struct bt_att *bt_rap_get_att(struct bt_rap *rap);

bool bt_rap_set_user_data(struct bt_rap *rap, void *user_data);

bool bt_rap_set_debug(struct bt_rap *rap, bt_rap_debug_func_t func,
			void *user_data, bt_rap_destroy_func_t destroy);

/* session related functions */
unsigned int bt_rap_register(bt_rap_func_t attached, bt_rap_func_t detached,
					void *user_data);
unsigned int bt_rap_ready_register(struct bt_rap *rap,
				bt_rap_ready_func_t func, void *user_data,
				bt_rap_destroy_func_t destroy);
bool bt_rap_ready_unregister(struct bt_rap *rap, unsigned int id);

bool bt_rap_unregister(unsigned int id);

struct bt_rap *bt_rap_new(struct gatt_db *ldb, struct gatt_db *rdb);

/* HCI Raw Channel Approach */
void bt_rap_hci_cs_config_complete_callback(uint16_t length,
					     const void *param,
					     void *user_data);
void bt_rap_hci_cs_sec_enable_complete_callback(uint16_t length,
						 const void *param,
						 void *user_data);
void bt_rap_hci_cs_procedure_enable_complete_callback(uint16_t length,
						      const void *param,
						      void *user_data);
void bt_rap_hci_cs_subevent_result_callback(uint16_t length,
					     const void *param,
					     void *user_data);
void bt_rap_hci_cs_subevent_result_cont_callback(uint16_t length,
						  const void *param,
						  void *user_data);

void *bt_rap_attach_hci(struct bt_rap *rap, struct bt_hci *hci,
			uint8_t role, uint8_t cs_sync_ant_sel,
			int8_t max_tx_power);
void bt_rap_detach_hci(struct bt_rap *rap, void *hci_sm);

/* Connection handle mapping functions */
bool bt_rap_set_conn_handle(void *hci_sm, struct bt_rap *rap, uint16_t handle,
				const uint8_t *bdaddr, uint8_t bdaddr_type);
void bt_rap_clear_conn_handle(void *hci_sm, uint16_t handle);
