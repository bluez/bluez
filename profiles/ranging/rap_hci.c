// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <endian.h>

#include "lib/bluetooth/bluetooth.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/rap.h"
#include "src/log.h"
#include "monitor/bt.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* Macro to sign-extend an N-bit value to 16-bit signed integer */
#define SIGN_EXTEND_TO_16(val, bits) \
	((int16_t)((int32_t)((val) << (32 - (bits))) >> (32 - (bits))))

/*  CS State Definitions */
enum cs_state_t {
	CS_INIT,
	CS_STOPPED,
	CS_STARTED,
	CS_WAIT_CONFIG_CMPLT,
	CS_WAIT_SEC_CMPLT,
	CS_WAIT_PROC_CMPLT,
	CS_HOLD,
	CS_UNSPECIFIED
};

const char *state_names[] = {
	"CS_INIT",
	"CS_STOPPED",
	"CS_STARTED",
	"CS_WAIT_CONFIG_CMPLT",
	"CS_WAIT_SEC_CMPLT",
	"CS_WAIT_PROC_CMPLT",
	"CS_HOLD",
	"CS_UNSPECIFIED"
};

/* Callback Function Type */
typedef void (*cs_callback_t)(uint16_t length,
			const void *param, void *user_data);

/* State Machine Context */
struct cs_state_machine_t {
	enum cs_state_t current_state;
	enum cs_state_t old_state;
	struct bt_hci *hci;
	struct bt_rap *rap;
	unsigned int event_id;
	bool initiator;
	bool procedure_active;
};

struct cs_callback_map_t {
	enum cs_state_t state;
	cs_callback_t callback;
};

struct cs_callback_map_t cs_callback_map[] = {
	{ CS_WAIT_CONFIG_CMPLT, bt_rap_hci_cs_config_complete_callback },
	{ CS_WAIT_SEC_CMPLT, bt_rap_hci_cs_sec_enable_complete_callback },
	{ CS_WAIT_PROC_CMPLT, bt_rap_hci_cs_procedure_enable_complete_callback }
};

#define CS_CALLBACK_MAP_SIZE ARRAY_SIZE(cs_callback_map)

struct bt_rap_hci_cs_options cs_opt;
struct cs_state_machine_t *sm;

/* Connection Handle Mapping */
struct rap_conn_mapping {
	uint16_t handle;
	uint8_t bdaddr[6];
	uint8_t bdaddr_type;
	struct bt_att *att;
	struct bt_rap *rap;
};

static struct queue *conn_mappings;

/* Connection Mapping Helper Functions */
static void mapping_free(void *data)
{
	struct rap_conn_mapping *mapping = data;

	if (!mapping)
		return;

	free(mapping);
}

static bool match_mapping_handle(const void *a, const void *b)
{
	const struct rap_conn_mapping *mapping = a;
	uint16_t handle = PTR_TO_UINT(b);

	return mapping->handle == handle;
}

static bool match_mapping_rap(const void *a, const void *b)
{
	const struct rap_conn_mapping *mapping = a;
	const struct bt_rap *rap = b;

	return mapping->rap == rap;
}

static struct rap_conn_mapping *find_mapping_by_handle(uint16_t handle)
{
	if (!conn_mappings)
		return NULL;

	return queue_find(conn_mappings, match_mapping_handle,
				UINT_TO_PTR(handle));
}

static bool add_conn_mapping(uint16_t handle, const uint8_t *bdaddr,
				uint8_t bdaddr_type, struct bt_att *att,
				struct bt_rap *rap)
{
	struct rap_conn_mapping *mapping;

	if (!conn_mappings) {
		conn_mappings = queue_new();
		if (!conn_mappings)
			return false;
	}

	/* Check if mapping already exists */
	mapping = find_mapping_by_handle(handle);
	if (mapping) {
		/* Update existing mapping */
		if (bdaddr)
			memcpy(mapping->bdaddr, bdaddr, 6);
		mapping->bdaddr_type = bdaddr_type;
		mapping->att = att;
		mapping->rap = rap;
		return true;
	}

	/* Create new mapping */
	mapping = new0(struct rap_conn_mapping, 1);
	if (!mapping)
		return false;

	mapping->handle = handle;
	if (bdaddr)
		memcpy(mapping->bdaddr, bdaddr, 6);
	mapping->bdaddr_type = bdaddr_type;
	mapping->att = att;
	mapping->rap = rap;

	return queue_push_tail(conn_mappings, mapping);
}

static void remove_conn_mapping(uint16_t handle)
{
	struct rap_conn_mapping *mapping;

	if (!conn_mappings)
		return;

	mapping = queue_remove_if(conn_mappings, match_mapping_handle,
					UINT_TO_PTR(handle));
	if (mapping)
		mapping_free(mapping);
}

static void remove_rap_mappings(struct bt_rap *rap)
{
	if (!conn_mappings)
		return;

	queue_remove_all(conn_mappings, match_mapping_rap, rap,
				mapping_free);
}

static struct bt_rap *resolve_handle_to_rap(uint16_t handle,
						struct bt_hci *hci)
{
	struct rap_conn_mapping *mapping;

	/* Try to find in mapping cache */
	mapping = find_mapping_by_handle(handle);
	if (mapping && mapping->rap) {
		DBG("Found handle 0x%04X in mapping cache", handle);
		return mapping->rap;
	}

	/* Profile layer should have called bt_rap_set_conn_handle() during
	 * connection establishment. If we reach here, the mapping was not set.
	 */
	DBG("No mapping found for handle 0x%04X", handle);
	DBG("Profile layer should call bt_rap_set_conn_handle() on connect");

	return NULL;
}

/*  State Machine Functions */
static void cs_state_machine_init(struct cs_state_machine_t *sm,
				struct bt_rap *rap, struct bt_hci *hci)
{
	if (!sm)
		return;

	memset(sm, 0, sizeof(struct cs_state_machine_t));
	sm->current_state = CS_UNSPECIFIED;
	sm->rap = rap;
	sm->hci = hci;
	sm->initiator = false;
	sm->procedure_active = false;
}

void bt_rap_hci_sm_cleanup(void)
{
	if (!sm)
		return;

	if (sm->event_id)
		bt_hci_unregister(sm->hci, sm->event_id);

	sm->current_state = CS_UNSPECIFIED;
	sm->rap = NULL;
	sm->hci = NULL;
	sm->procedure_active = false;

	free(sm);
}

void bt_rap_hci_set_options(uint8_t role, uint8_t cs_sync_ant_sel,
					int8_t max_tx_power)
{
	cs_opt.role = role;
	cs_opt.cs_sync_ant_sel = cs_sync_ant_sel;
	cs_opt.max_tx_power = max_tx_power;
}

/* State Transition Logic */
static void cs_set_state(struct cs_state_machine_t *sm,
		enum cs_state_t new_state)
{
	if (!sm)
		return;

	if (sm->current_state == new_state)
		return;

	/* Validate state values before array access */
	if (sm->current_state > CS_UNSPECIFIED || new_state > CS_UNSPECIFIED) {
		error("Invalid state transition attempted\n");
		return;
	}

	DBG("[STATE] Transition: %s → %s\n",
		state_names[sm->current_state],
		state_names[new_state]);

	sm->old_state = sm->current_state;
	sm->current_state = new_state;
}

static enum cs_state_t cs_get_current_state(struct cs_state_machine_t *sm)
{
	return sm ? sm->current_state : CS_UNSPECIFIED;
}

/* HCI Event Callbacks */
static void rap_def_settings_done_cb(const void *data, uint8_t size,
					void *user_data)
{
	struct bt_hci_rsp_le_cs_set_def_settings *rp;
	struct cs_state_machine_t *sm = (struct cs_state_machine_t *)user_data;

	if (!sm || !data ||
		size < sizeof(struct bt_hci_rsp_le_cs_set_def_settings))
		return;

	DBG("size=0x%02X\n", size);

	rp = (struct bt_hci_rsp_le_cs_set_def_settings *)data;

	if (cs_get_current_state(sm) != CS_INIT) {
		DBG("Event received in Wrong State!! Expected : CS_INIT");
		return;
	}

	if (rp->status == 0) {
		/* Success - proceed to configuration */
		cs_set_state(sm, CS_WAIT_CONFIG_CMPLT);

		/* Reflector role */
		DBG("Waiting for CS Config Completed event...\n");
		/* TODO: Initiator role - Send CS Config complete cmd */
	} else {
		/* Error - transition to stopped */
		error("CS Set default setting failed with status 0x%02X\n",
		rp->status);
		cs_set_state(sm, CS_STOPPED);
	}
}

static void rap_send_hci_def_settings_command(struct cs_state_machine_t *sm,
		struct bt_hci_evt_le_cs_rd_rem_supp_cap_complete *ev)
{
	struct bt_hci_cmd_le_cs_set_def_settings cp;
	unsigned int status;

	memset(&cp, 0, sizeof(cp));

	if (ev->handle)
		cp.handle = ev->handle;
	cp.role_enable = cs_opt.role;
	cp.cs_sync_antenna_selection = cs_opt.cs_sync_ant_sel;
	cp.max_tx_power = cs_opt.max_tx_power;

	if (!sm || !sm->hci) {
		error("Set Def Settings: sm or hci is null");
		return;
	}

	status = bt_hci_send(sm->hci, BT_HCI_CMD_LE_CS_SET_DEF_SETTINGS,
				&cp, sizeof(cp), rap_def_settings_done_cb,
				sm, NULL);

	DBG("sending set default settings case, status : %d", status);
	if (!status)
		error("Failed to send default settings cmd");
}

static void rap_rd_rmt_supp_cap_cmplt_evt(const uint8_t *data, uint8_t size,
					   void *user_data)
{
	struct cs_state_machine_t *sm = (struct cs_state_machine_t *)user_data;
	const struct bt_hci_evt_le_cs_rd_rem_supp_cap_complete *evt;
	struct bt_rap *rap;
	struct iovec iov;

	if (!sm || !data ||
		size < sizeof(struct bt_hci_evt_le_cs_rd_rem_supp_cap_complete))
		return;

	/* Initialize iovec with the event data */
	iov.iov_base = (void *)data;
	iov.iov_len = size;

	/* Pull the entire structure at once */
	evt = util_iov_pull_mem(&iov, sizeof(*evt));
	if (!evt) {
		error("Failed to pull remote cap complete struct\n");
		return;
	}

	DBG("status=0x%02X, handle=0x%04X\n", evt->status, evt->handle);

	/* Check status */
	if (evt->status != 0) {
		error("Remote capabilities failed with status 0x%02X\n",
			evt->status);
		cs_set_state(sm, CS_STOPPED);
		return;
	}

	/* Resolve handle to RAP instance */
	rap = resolve_handle_to_rap(evt->handle, sm->hci);
	if (!rap) {
		DBG("[WARN] Could not resolve handle 0x%04X to RAP instance\n",
			evt->handle);
		/* Continue with state machine RAP for now */
		rap = sm->rap;
	}

	DBG("num_config=%u, ",
		evt->num_config_supported);
	DBG("max_consecutive_proc=%u, num_antennas=%u, ",
		evt->max_consecutive_procedures_supported,
		evt->num_antennas_supported);
	DBG("max_antenna_paths=%u, roles=0x%02X, modes=0x%02X\n",
		evt->max_antenna_paths_supported,
		evt->roles_supported,
		evt->modes_supported);

	rap_send_hci_def_settings_command(sm,
		(struct bt_hci_evt_le_cs_rd_rem_supp_cap_complete *)evt);
	cs_set_state(sm, CS_INIT);
}

static void rap_cs_config_cmplt_evt(const uint8_t *data, uint8_t size,
				    void *user_data)
{
	struct cs_state_machine_t *sm = (struct cs_state_machine_t *)user_data;
	const struct bt_hci_evt_le_cs_config_complete *evt;
	struct rap_ev_cs_config_cmplt rap_ev;
	struct iovec iov;

	if (!sm || !data ||
		size < sizeof(struct bt_hci_evt_le_cs_config_complete))
		return;

	/* Initialize iovec with the event data */
	iov.iov_base = (void *)data;
	iov.iov_len = size;

	DBG("size=0x%02X\n", size);

	/* State Check */
	if (cs_get_current_state(sm) != CS_WAIT_CONFIG_CMPLT) {
		DBG("Event received in Wrong State!! ");
		DBG("Expected : CS_WAIT_CONFIG_CMPLT");
		return;
	}

	/* Pull the entire structure at once */
	evt = util_iov_pull_mem(&iov, sizeof(*evt));
	if (!evt) {
		error("Failed to pull config complete struct\n");
		return;
	}

	DBG("status=0x%02X, handle=0x%04X\n", evt->status, evt->handle);

	/* Check status */
	if (evt->status != 0) {
		error("Configuration failed with status 0x%02X\n",
			evt->status);
		cs_set_state(sm, CS_STOPPED);
		return;
	}

	/* Copy fields to rap_ev structure */
	rap_ev.status = evt->status;
	rap_ev.conn_hdl = cpu_to_le16(evt->handle);
	rap_ev.config_id = evt->config_id;
	rap_ev.action = evt->action;
	rap_ev.main_mode_type = evt->main_mode_type;
	rap_ev.sub_mode_type = evt->sub_mode_type;
	rap_ev.min_main_mode_steps = evt->min_main_mode_steps;
	rap_ev.max_main_mode_steps = evt->max_main_mode_steps;
	rap_ev.main_mode_rep = evt->main_mode_repetition;
	rap_ev.mode_0_steps = evt->mode_0_steps;
	rap_ev.role = evt->role;
	rap_ev.rtt_type = evt->rtt_type;
	rap_ev.cs_sync_phy = evt->cs_sync_phy;
	memcpy(rap_ev.channel_map, evt->channel_map, 10);
	rap_ev.channel_map_rep = evt->channel_map_repetition;
	rap_ev.channel_sel_type = evt->channel_selection_type;
	rap_ev.ch3c_shape = evt->ch3c_shape;
	rap_ev.ch3c_jump = evt->ch3c_jump;
	rap_ev.reserved = evt->reserved;
	rap_ev.t_ip1_time = evt->t_ip1_time;
	rap_ev.t_ip2_time = evt->t_ip2_time;
	rap_ev.t_fcs_time = evt->t_fcs_time;
	rap_ev.t_pm_time = evt->t_pm_time;

	/* Store rtt_type in global options */
	cs_opt.rtt_type = rap_ev.rtt_type;

	DBG("config_id=%u, action=%u, ",
		rap_ev.config_id, rap_ev.action);
	DBG("main_mode=%u, sub_mode=%u, role=%u, rtt_type=%u\n",
		rap_ev.main_mode_type, rap_ev.sub_mode_type,
		rap_ev.role, rap_ev.rtt_type);

	/* Success - proceed to Security enable complete */
	cs_set_state(sm, CS_WAIT_SEC_CMPLT);

	/* Reflector role */
	DBG("Waiting for security enable event...\n");
	/* TODO: Initiator role - Send CS Security enable cmd */

	/* Send Callback to RAP Profile */
	for (size_t i = 0; i < CS_CALLBACK_MAP_SIZE; i++) {
		if (cs_callback_map[i].state == sm->old_state) {
			cs_callback_map[i].callback(size, &rap_ev, sm->rap);
			return;
		}
	}
}

static void rap_cs_sec_enable_cmplt_evt(const uint8_t *data, uint8_t size,
					 void *user_data)
{
	struct cs_state_machine_t *sm = (struct cs_state_machine_t *)user_data;
	struct rap_ev_cs_sec_enable_cmplt rap_ev;
	struct iovec iov;
	uint8_t status;
	uint16_t handle;

	if (!sm || !data ||
		size < sizeof(struct bt_hci_evt_le_cs_sec_enable_complete))
		return;

	/* Initialize iovec with the event data */
	iov.iov_base = (void *)data;
	iov.iov_len = size;

	DBG("size=0x%02X\n", size);

	/* State Check */
	if (cs_get_current_state(sm) != CS_WAIT_SEC_CMPLT) {
		DBG("Event received in Wrong State!! ");
		DBG("Expected : CS_WAIT_SEC_CMPLT");
		return;
	}

	/* Parse all fields in order using iovec */
	if (!util_iov_pull_u8(&iov, &status)) {
		error("Failed to parse Status\n");
		return;
	}

	if (!util_iov_pull_le16(&iov, &handle)) {
		error("Failed to parse Connection_Handle\n");
		return;
	}

	rap_ev.status = status;
	rap_ev.conn_hdl = cpu_to_le16(handle);

	DBG("status=0x%02X, handle=0x%04X\n",
		rap_ev.status, handle);

	if (rap_ev.status == 0) {
		/* Success - proceed to configuration */
		cs_set_state(sm, CS_WAIT_PROC_CMPLT);

		/* Reflector role */
		DBG("Waiting for CS Proc complete event...\n");
		/* TODO: Initiator - Send CS Proc Set Parameter and enable */
	} else {
		/* Error - transition to stopped */
		error("Security enable failed with status 0x%02X\n",
			rap_ev.status);
		cs_set_state(sm, CS_STOPPED);
	}

	/* Send Callback to RAP Profile */
	for (size_t i = 0; i < CS_CALLBACK_MAP_SIZE; i++) {
		if (cs_callback_map[i].state == sm->old_state) {
			cs_callback_map[i].callback(size, &rap_ev, sm->rap);
			return;
		}
	}
}

static void rap_cs_proc_enable_cmplt_evt(const uint8_t *data, uint8_t size,
					  void *user_data)
{
	struct cs_state_machine_t *sm = (struct cs_state_machine_t *)user_data;
	const struct bt_hci_evt_le_cs_proc_enable_complete *evt;
	struct rap_ev_cs_proc_enable_cmplt rap_ev;
	struct iovec iov;

	if (!sm || !data ||
		size < sizeof(struct bt_hci_evt_le_cs_proc_enable_complete))
		return;

	/* Initialize iovec with the event data */
	iov.iov_base = (void *)data;
	iov.iov_len = size;

	DBG("size=0x%02X\n", size);

	/* State Check */
	if (cs_get_current_state(sm) != CS_WAIT_PROC_CMPLT) {
		DBG("Event received in Wrong State!! ");
		DBG("Expected : CS_WAIT_PROC_CMPLT");
		return;
	}

	/* Pull the entire structure at once */
	evt = util_iov_pull_mem(&iov, sizeof(*evt));
	if (!evt) {
		error("Failed to pull proc enable complete struct\n");
		return;
	}

	DBG("status=0x%02X, handle=0x%04X\n", evt->status, evt->handle);

	/* Check status */
	if (evt->status != 0) {
		error("Procedure enable failed with status 0x%02X\n",
			evt->status);
		cs_set_state(sm, CS_STOPPED);
		sm->procedure_active = false;
		return;
	}

	/* Copy fields to rap_ev structure */
	rap_ev.status = evt->status;
	rap_ev.conn_hdl = cpu_to_le16(evt->handle);
	rap_ev.config_id = evt->config_id;
	rap_ev.state = evt->state;
	rap_ev.tone_ant_config_sel = evt->tone_antenna_config_selection;
	rap_ev.sel_tx_pwr = evt->selected_tx_power;
	memcpy(rap_ev.sub_evt_len, evt->subevent_len, 3);
	rap_ev.sub_evts_per_evt = evt->subevents_per_event;
	rap_ev.sub_evt_intrvl = evt->subevent_interval;
	rap_ev.evt_intrvl = evt->event_interval;
	rap_ev.proc_intrvl = evt->procedure_interval;
	rap_ev.proc_counter = evt->procedure_count;
	rap_ev.max_proc_len = evt->max_procedure_len;

	DBG("config_id=%u, state=%u, ",
		rap_ev.config_id, rap_ev.state);
	DBG("sub_evts_per_evt=%u, evt_intrvl=%u, proc_intrvl=%u\n",
		rap_ev.sub_evts_per_evt, rap_ev.evt_intrvl,
		rap_ev.proc_intrvl);

	/* Success - procedure started */
	cs_set_state(sm, CS_STARTED);
	sm->procedure_active = true;

	/* Send Callback to RAP Profile */
	for (size_t i = 0; i < CS_CALLBACK_MAP_SIZE; i++) {
		if (cs_callback_map[i].state == sm->old_state) {
			cs_callback_map[i].callback(size, &rap_ev, sm->rap);
			return;
		}
	}
}

static void parse_i_q_sample(struct iovec *iov, int16_t *i_sample,
				int16_t *q_sample)
{
	uint32_t buffer;
	uint32_t i12;
	uint32_t q12;

	/* Pull 24-bit little-endian value from iovec */
	if (!util_iov_pull_le24(iov, &buffer)) {
		*i_sample = 0;
		*q_sample = 0;
		return;
	}

	/* Extract 12-bit I and Q values from 24-bit buffer */
	i12 =  buffer        & 0x0FFFU;   /* bits 0..11 */
	q12 = (buffer >> 12) & 0x0FFFU;   /* bits 12..23 */

	/* Sign-extend 12-bit values to 16-bit using macro */
	*i_sample = SIGN_EXTEND_TO_16(i12, 12);
	*q_sample = SIGN_EXTEND_TO_16(q12, 12);
}

/* Parse CS Mode 0 step data */
static void parse_mode_zero_data(struct iovec *iov,
				 struct cs_mode_zero_data *mode_data,
				 uint8_t cs_role)
{
	uint32_t freq_offset;

	if (iov->iov_len < 3) {
		DBG("Mode 0: too short (<3)");
		return;
	}

	util_iov_pull_u8(iov, &mode_data->packet_quality);
	util_iov_pull_u8(iov, &mode_data->packet_rssi_dbm);
	util_iov_pull_u8(iov, &mode_data->packet_ant);
	DBG("CS Step mode 0");

	if (cs_role == CS_INITIATOR && iov->iov_len >= 4) {
		util_iov_pull_le32(iov, &freq_offset);
		mode_data->init_measured_freq_offset = freq_offset;
	}
}

/* Parse CS Mode 1 step data */
static void parse_mode_one_data(struct iovec *iov,
				struct cs_mode_one_data *mode_data,
				uint8_t cs_role, uint8_t cs_rtt_type)
{
	uint16_t time_val;

	if (iov->iov_len < 4) {
		DBG("Mode 1: too short (<4)");
		return;
	}

	DBG("CS Step mode 1");
	util_iov_pull_u8(iov, &mode_data->packet_quality);
	util_iov_pull_u8(iov, &mode_data->packet_rssi_dbm);
	util_iov_pull_u8(iov, &mode_data->packet_ant);
	util_iov_pull_u8(iov, &mode_data->packet_nadm);

	if (iov->iov_len >= 2) {
		util_iov_pull_le16(iov, &time_val);
		if (cs_role == CS_REFLECTOR)
			mode_data->tod_toa_refl = time_val;
		else
			mode_data->toa_tod_init = time_val;
	}

	if ((cs_rtt_type == 0x01 || cs_rtt_type == 0x02) &&
		iov->iov_len >= 6) {
		int16_t i_val, q_val;

		parse_i_q_sample(iov, &i_val, &q_val);
		mode_data->packet_pct1.i_sample = i_val;
		mode_data->packet_pct1.q_sample = q_val;

		parse_i_q_sample(iov, &i_val, &q_val);
		mode_data->packet_pct2.i_sample = i_val;
		mode_data->packet_pct2.q_sample = q_val;
	}
}

/* Parse CS Mode 2 step data */
static void parse_mode_two_data(struct iovec *iov,
				struct cs_mode_two_data *mode_data,
				uint8_t max_paths)
{
	uint8_t k;

	if (iov->iov_len < 1) {
		DBG("Mode 2: too short (<1)");
		return;
	}

	util_iov_pull_u8(iov, &mode_data->ant_perm_index);
	DBG("CS Step mode 2, max paths : %d", max_paths);

	for (k = 0; k < max_paths; k++) {
		int16_t i_val, q_val;

		if (iov->iov_len < 4) {
			DBG("Mode 2: insufficient PCT for path %u (rem=%zu)",
				k, iov->iov_len);
			break;
		}
		parse_i_q_sample(iov, &i_val, &q_val);
		mode_data->tone_pct[k].i_sample = i_val;
		mode_data->tone_pct[k].q_sample = q_val;

		util_iov_pull_u8(iov, &mode_data->tone_quality_indicator[k]);
		DBG("tone_quality_indicator : %d",
			mode_data->tone_quality_indicator[k]);
		DBG("[i, q] : %d, %d",
			mode_data->tone_pct[k].i_sample,
			mode_data->tone_pct[k].q_sample);
	}
}

/* Parse CS Mode 3 step data */
static void parse_mode_three_data(struct iovec *iov,
				struct cs_mode_three_data *mode_data,
				uint8_t cs_role, uint8_t cs_rtt_type,
				uint8_t max_paths)
{
	uint8_t k;
	struct cs_mode_one_data *mode_one = &mode_data->mode_one_data;
	struct cs_mode_two_data *mode_two = &mode_data->mode_two_data;

	if (iov->iov_len < 4) {
		DBG("Mode 3: mode1 too short (<4)");
		return;
	}

	DBG("CS Step mode 3");

	/* Parse Mode 1 portion */
	parse_mode_one_data(iov, mode_one, cs_role, cs_rtt_type);

	/* Parse Mode 2 portion */
	if (iov->iov_len >= 1) {
		util_iov_pull_u8(iov, &mode_two->ant_perm_index);
		for (k = 0; k < max_paths; k++) {
			int16_t i_val, q_val;

			if (iov->iov_len < 4)
				break;
			parse_i_q_sample(iov, &i_val, &q_val);
			mode_two->tone_pct[k].i_sample = i_val;
			mode_two->tone_pct[k].q_sample = q_val;

			util_iov_pull_u8(iov,
					 &mode_two->tone_quality_indicator[k]);
		}
	}
}

/* Parse a single CS step */
static void parse_cs_step(struct iovec *iov, struct cs_step_data *step,
			uint8_t cs_role, uint8_t cs_rtt_type,
			uint8_t max_paths)
{
	uint8_t mode;
	uint8_t chnl;
	uint8_t length;

	/* Check if we have enough data for the 3-byte header */
	if (iov->iov_len < 3) {
		DBG("Truncated header for step");
		return;
	}

	/* Read mode, channel, and length (3-byte header) */
	if (!util_iov_pull_u8(iov, &mode) ||
		!util_iov_pull_u8(iov, &chnl) ||
		!util_iov_pull_u8(iov, &length)) {
		DBG("Failed to read header for step");
		return;
	}

	DBG("event->step_data_len : %d", length);

	step->step_mode = mode;
	step->step_chnl = chnl;
	step->step_data_length = length;

	DBG("Step: mode=%u chnl=%u data_len=%u", mode, chnl, length);

	if (iov->iov_len < length) {
		DBG("Truncated payload for step (need %u, have %zu)",
			length, iov->iov_len);
		return;
	}

	/* Parse step data based on mode */
	switch (mode) {
	case CS_MODE_ZERO:
		parse_mode_zero_data(iov, &step->step_mode_data.mode_zero_data,
					cs_role);
		break;
	case CS_MODE_ONE:
		parse_mode_one_data(iov, &step->step_mode_data.mode_one_data,
					cs_role, cs_rtt_type);
		break;
	case CS_MODE_TWO:
		parse_mode_two_data(iov, &step->step_mode_data.mode_two_data,
					max_paths);
		break;
	case CS_MODE_THREE:
		parse_mode_three_data(iov,
					&step->step_mode_data.mode_three_data,
					cs_role, cs_rtt_type, max_paths);
		break;
	default:
		DBG("Unknown step mode %d", mode);
		/* Skip the entire step data */
		util_iov_pull(iov, length);
		break;
	}
}

static void rap_cs_subevt_result_evt(const uint8_t *data, uint8_t size,
				void *user_data)
{
	struct cs_state_machine_t *sm = (struct cs_state_machine_t *)user_data;
	struct rap_ev_cs_subevent_result *rap_ev;
	struct iovec iov;
	uint8_t cs_role;
	uint8_t cs_rtt_type;
	uint8_t max_paths;
	uint8_t steps;
	size_t send_len = 0;
	uint16_t handle;
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
	uint8_t i;

	if (!sm || !data ||
		size < sizeof(struct bt_hci_evt_le_cs_subevent_result))
		return;

	/* Initialize iovec with the event data */
	iov.iov_base = (void *)data;
	iov.iov_len = size;

	/* Check if Procedure is active or not */
	if (!sm->procedure_active) {
		DBG("Received Subevent event when Procedure is inactive!");
		return;
	}

	/* Parse header fields using iovec */
	if (!util_iov_pull_le16(&iov, &handle)) {
		error("Failed to parse Connection_Handle\n");
		return;
	}

	if (!util_iov_pull_u8(&iov, &config_id) ||
		!util_iov_pull_le16(&iov, &start_acl_conn_evt_counter) ||
		!util_iov_pull_le16(&iov, &proc_counter) ||
		!util_iov_pull_le16(&iov, &freq_comp) ||
		!util_iov_pull_u8(&iov, &ref_pwr_lvl) ||
		!util_iov_pull_u8(&iov, &proc_done_status) ||
		!util_iov_pull_u8(&iov, &subevt_done_status) ||
		!util_iov_pull_u8(&iov, &abort_reason) ||
		!util_iov_pull_u8(&iov, &num_ant_paths) ||
		!util_iov_pull_u8(&iov, &num_steps_reported)) {
		error("Failed to parse subevent fields\n");
		return;
	}

	cs_role = cs_opt.role;
	cs_rtt_type = cs_opt.rtt_type;
	max_paths = MIN((num_ant_paths + 1), CS_MAX_ANT_PATHS);
	steps = MIN(num_steps_reported, CS_MAX_STEPS);
	send_len = offsetof(struct rap_ev_cs_subevent_result, step_data) +
					steps * sizeof(struct cs_step_data);
	rap_ev = (struct rap_ev_cs_subevent_result *)malloc(send_len);
	if (!rap_ev) {
		error("Failed to allocate memory for subevent result\n");
		return;
	}

	DBG("length=%u\n", size);
	rap_ev->conn_hdl                     = le16_to_cpu(handle);
	rap_ev->config_id                    = config_id;
	rap_ev->start_acl_conn_evt_counter   = start_acl_conn_evt_counter;
	rap_ev->proc_counter                 = proc_counter;
	rap_ev->freq_comp                    = freq_comp;
	rap_ev->ref_pwr_lvl                  = ref_pwr_lvl;
	rap_ev->proc_done_status             = proc_done_status;
	rap_ev->subevt_done_status           = subevt_done_status;
	rap_ev->abort_reason                 = abort_reason;
	rap_ev->num_ant_paths                = num_ant_paths;
	rap_ev->num_steps_reported           = steps;

	if (num_steps_reported > CS_MAX_STEPS) {
		DBG("Too many steps reported: %u (max %u)",
			num_steps_reported, CS_MAX_STEPS);
		goto send_event;
	}

	/* Early exit for error conditions */
	if (rap_ev->subevt_done_status == 0xF ||
	    rap_ev->proc_done_status == 0xF) {
		DBG("CS Procedure/Subevent aborted: ");
		DBG("sub evt status = %d, proc status = %d, reason = %d",
			rap_ev->subevt_done_status, rap_ev->proc_done_status,
			rap_ev->abort_reason);
		goto send_event;
	}

	/* Parse interleaved step data from remaining iovec data */
	for (i = 0; i < steps; i++)
		parse_cs_step(&iov, &rap_ev->step_data[i], cs_role, cs_rtt_type,
			max_paths);

send_event:
	DBG("CS subevent result processed: %zu bytes, ", send_len);
	bt_rap_hci_cs_subevent_result_callback(send_len, rap_ev, sm->rap);
	free(rap_ev);
}

static void rap_cs_subevt_result_cont_evt(const uint8_t *data, uint8_t size,
					void *user_data)
{
	struct cs_state_machine_t *sm = (struct cs_state_machine_t *)user_data;
	struct rap_ev_cs_subevent_result_cont *rap_ev;
	struct iovec iov;
	uint8_t cs_role;
	uint8_t cs_rtt_type;
	uint8_t max_paths;
	uint8_t steps;
	size_t send_len = 0;
	uint16_t handle;
	uint8_t config_id;
	uint8_t proc_done_status;
	uint8_t subevt_done_status;
	uint8_t abort_reason;
	uint8_t num_ant_paths;
	uint8_t num_steps_reported;
	uint8_t i;

	if (!sm || !data ||
		size < sizeof(struct bt_hci_evt_le_cs_subevent_result_continue))
		return;

	/* Initialize iovec with the event data */
	iov.iov_base = (void *)data;
	iov.iov_len = size;

	/* Check if Procedure is active or not */
	if (!sm->procedure_active) {
		error("Received Subevent when CS Procedure is inactive!");
		return;
	}

	/* Parse header fields using iovec */
	if (!util_iov_pull_le16(&iov, &handle)) {
		error("Failed to parse Connection_Handle\n");
		return;
	}

	if (!util_iov_pull_u8(&iov, &config_id) ||
		!util_iov_pull_u8(&iov, &proc_done_status) ||
		!util_iov_pull_u8(&iov, &subevt_done_status) ||
		!util_iov_pull_u8(&iov, &abort_reason) ||
		!util_iov_pull_u8(&iov, &num_ant_paths) ||
		!util_iov_pull_u8(&iov, &num_steps_reported)) {
		error("Failed to parse subevent continue fields ");
		return;
	}

	cs_role = cs_opt.role;
	cs_rtt_type = cs_opt.rtt_type;
	max_paths = MIN((num_ant_paths + 1), CS_MAX_ANT_PATHS);
	steps = MIN(num_steps_reported, CS_MAX_STEPS);
	send_len = offsetof(struct rap_ev_cs_subevent_result_cont, step_data) +
					steps * sizeof(struct cs_step_data);
	rap_ev = (struct rap_ev_cs_subevent_result_cont *)malloc(send_len);
	if (!rap_ev) {
		error("Failed to allocate memory for subevent result\n");
		return;
	}

	DBG("length=%u\n", size);
	rap_ev->conn_hdl                     = le16_to_cpu(handle);
	rap_ev->config_id                    = config_id;
	rap_ev->proc_done_status             = proc_done_status;
	rap_ev->subevt_done_status           = subevt_done_status;
	rap_ev->abort_reason                 = abort_reason;
	rap_ev->num_ant_paths                = num_ant_paths;
	rap_ev->num_steps_reported           = steps;

	if (num_steps_reported > CS_MAX_STEPS) {
		DBG("Too many steps reported: %u (max %u)",
			num_steps_reported, CS_MAX_STEPS);
		goto send_event;
	}

	/* Early exit for error conditions */
	if (rap_ev->subevt_done_status == 0xF ||
	    rap_ev->proc_done_status == 0xF) {
		DBG("CS Procedure/Subevent aborted: ");
		DBG("sub evt status = %d, proc status = %d, reason = %d",
			rap_ev->subevt_done_status, rap_ev->proc_done_status,
			rap_ev->abort_reason);
		goto send_event;
	}

	/* Parse interleaved step data from remaining iovec data */
	for (i = 0; i < steps; i++)
		parse_cs_step(&iov, &rap_ev->step_data[i], cs_role, cs_rtt_type,
			max_paths);

send_event:
	DBG("CS subevent result cont processed: %zu bytes, ", send_len);
	bt_rap_hci_cs_subevent_result_cont_callback(send_len, rap_ev, sm->rap);
	free(rap_ev);
}

/* Subevent handler function type */
typedef void (*subevent_handler_t)(const uint8_t *data, uint8_t size,
				   void *user_data);

/* Subevent table entry */
struct subevent_entry {
	uint8_t opcode;
	uint8_t min_len;
	uint8_t max_len;
	subevent_handler_t handler;
	const char *name;
};

/* Macro to define HCI event entries */
#define HCI_EVT(_opcode, _struct, _handler, _name) \
	{ \
		.opcode = _opcode, \
		.min_len = sizeof(_struct), \
		.max_len = 0xFF, \
		.handler = _handler, \
		.name = _name \
	}

/* Subevent dispatch table */
static const struct subevent_entry subevent_table[] = {
	HCI_EVT(BT_HCI_EVT_LE_CS_RD_REM_SUPP_CAP_COMPLETE,
		struct bt_hci_evt_le_cs_rd_rem_supp_cap_complete,
		rap_rd_rmt_supp_cap_cmplt_evt,
		"CS Read Remote Supported Capabilities Complete"),
	HCI_EVT(BT_HCI_EVT_LE_CS_CONFIG_COMPLETE,
		struct bt_hci_evt_le_cs_config_complete,
		rap_cs_config_cmplt_evt,
		"CS Config Complete"),
	HCI_EVT(BT_HCI_EVT_LE_CS_SEC_ENABLE_COMPLETE,
		struct bt_hci_evt_le_cs_sec_enable_complete,
		rap_cs_sec_enable_cmplt_evt,
		"CS Security Enable Complete"),
	HCI_EVT(BT_HCI_EVT_LE_CS_PROC_ENABLE_COMPLETE,
		struct bt_hci_evt_le_cs_proc_enable_complete,
		rap_cs_proc_enable_cmplt_evt,
		"CS Procedure Enable Complete"),
	HCI_EVT(BT_HCI_EVT_LE_CS_SUBEVENT_RESULT,
		struct bt_hci_evt_le_cs_subevent_result,
		rap_cs_subevt_result_evt,
		"CS Subevent Result"),
	HCI_EVT(BT_HCI_EVT_LE_CS_SUBEVENT_RESULT_CONTINUE,
		struct bt_hci_evt_le_cs_subevent_result_continue,
		rap_cs_subevt_result_cont_evt,
		"CS Subevent Result Continue")
};

#undef HCI_EVT

#define SUBEVENT_TABLE_SIZE ARRAY_SIZE(subevent_table)

/* HCI Event Registration */
static void rap_handle_hci_events(const void *data, uint8_t size,
				void *user_data)
{
	struct iovec iov;
	uint8_t subevent;
	const struct subevent_entry *entry = NULL;
	size_t i;

	/* Initialize iovec with the event data */
	iov.iov_base = (void *)data;
	iov.iov_len = size;

	/* Pull the subevent code */
	if (!util_iov_pull_u8(&iov, &subevent)) {
		DBG("Failed to parse subevent code");
		return;
	}

	/* Find the subevent in the table */
	for (i = 0; i < SUBEVENT_TABLE_SIZE; i++) {
		if (subevent_table[i].opcode == subevent) {
			entry = &subevent_table[i];
			break;
		}
	}

	/* Check if subevent is supported */
	if (!entry) {
		DBG("Unknown subevent: 0x%02X", subevent);
		return;
	}

	/* Validate payload length */
	if (iov.iov_len < entry->min_len) {
		DBG("%s: payload too short (%zu < %u)",
		    entry->name, iov.iov_len, entry->min_len);
		return;
	}

	if (entry->max_len != 0xFF && iov.iov_len > entry->max_len) {
		DBG("%s: payload too long (%zu > %u)",
		    entry->name, iov.iov_len, entry->max_len);
		return;
	}

	/* Call the handler */
	DBG("Handling %s (opcode=0x%02X, len=%zu)",
	    entry->name, subevent, iov.iov_len);

	entry->handler(iov.iov_base, iov.iov_len, user_data);
}

static void bt_rap_hci_register_events(struct bt_rap *rap,
		struct bt_hci *hci)
{
	if (!rap || !hci)
		return;

	sm = new0(struct cs_state_machine_t, 1);
	if (!sm) {
		error("Failed to allocate state machine\n");
		return;
	}

	cs_state_machine_init(sm, rap, hci);
	sm->event_id = bt_hci_register(hci, BT_HCI_EVT_LE_META_EVENT,
					rap_handle_hci_events, sm, NULL);

	DBG("bt_hci_register done, event_id : %d", sm->event_id);

	if (!sm->event_id) {
		DBG("Error: Failed to register hci le meta events ");
		DBG("event_id=0x%02X\n", sm->event_id);
		free(sm);
		return;
	}
}

bool bt_rap_attach_hci(struct bt_rap *rap, struct bt_hci *hci)
{
	if (!rap)
		return false;

	if (!hci) {
		DBG("Failed to create HCI RAW channel ");
		bt_hci_unref(hci);
		return false;
	}

	bt_rap_hci_register_events(rap, hci);

	return true;
}

bool bt_rap_set_conn_handle(struct bt_rap *rap, uint16_t handle,
				const uint8_t *bdaddr, uint8_t bdaddr_type)
{
	struct bt_att *att;

	if (!rap)
		return false;

	att = bt_rap_get_att(rap);
	if (!att)
		return false;

	DBG("Setting connection mapping: handle=0x%04X, ", handle);
	if (bdaddr) {
		DBG("bdaddr=%02x:%02x:%02x:%02x:%02x:%02x type=%u",
			bdaddr[5], bdaddr[4], bdaddr[3],
			bdaddr[2], bdaddr[1], bdaddr[0], bdaddr_type);
	}

	return add_conn_mapping(handle, bdaddr, bdaddr_type, att, rap);
}

void bt_rap_clear_conn_handle(struct bt_rap *rap, uint16_t handle)
{
	if (!rap)
		return;

	DBG("Clearing connection mapping: handle=0x%04X", handle);
	remove_conn_mapping(handle);
}

void bt_rap_detach_hci(struct bt_rap *rap)
{
	if (!rap)
		return;

	DBG("Detaching RAP from HCI, cleaning up mappings");

	/* Remove all mappings associated with this RAP instance */
	remove_rap_mappings(rap);
}
