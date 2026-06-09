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
#include <time.h>

#include "lib/bluetooth/bluetooth.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/rap.h"
#include "src/shared/att.h"
#include "src/log.h"
#include "monitor/bt.h"

/* Macro to sign-extend an N-bit value to 16-bit signed integer */
#define SIGN_EXTEND_TO_16(val, bits) \
	((int16_t)(((val) ^ (1U << ((bits)-1))) - (1U << ((bits)-1))))

/*  CS State Definitions */
enum cs_state {
	CS_STATE_INIT,
	CS_STATE_STOPPED,
	CS_STATE_STARTED,
	CS_STATE_WAIT_CONFIG_CMPLT,
	CS_STATE_WAIT_SEC_CMPLT,
	CS_STATE_WAIT_PROC_CMPLT,
	CS_STATE_HOLD,
	CS_STATE_UNSPECIFIED
};

static const char * const state_names[] = {
	"CS_STATE_INIT",
	"CS_STATE_STOPPED",
	"CS_STATE_STARTED",
	"CS_STATE_WAIT_CONFIG_CMPLT",
	"CS_STATE_WAIT_SEC_CMPLT",
	"CS_STATE_WAIT_PROC_CMPLT",
	"CS_STATE_HOLD",
	"CS_STATE_UNSPECIFIED"
};

/* Callback Function Type */
typedef void (*cs_callback_t)(uint16_t length,
			const void *param, void *user_data);

/* State Machine Context */
struct cs_state_machine {
	enum cs_state current_state;
	enum cs_state old_state;
	struct bt_hci *hci;
	struct bt_rap *rap;
	struct queue *event_ids;
	bool initiator;
	bool procedure_active;
	struct bt_rap_hci_cs_options cs_opt;  /* Per-instance CS options */
	uint8_t role_enable;  /* Role value for HCI commands (1, 2, or 3) */
	struct queue *conn_mappings;  /* Per-instance connection mappings */
	struct timespec last_chan_class_time;  /* For 1-second rate limit */
};

/* Connection Handle Mapping */
struct rap_conn_mapping {
	uint16_t handle;
	uint8_t bdaddr[6];
	uint8_t bdaddr_type;
	bool is_central;  /* true if local device is BLE Central on this link */
	struct bt_att *att;
	struct bt_rap *rap;
};

/* Function declarations */
static bool bt_rap_read_remote_fae_table(void *hci_sm, uint16_t handle);
static void rap_send_hci_cs_create_config_command(struct cs_state_machine *sm,
						uint16_t handle);
static bool bt_rap_read_remote_supported_capabilities(void *hci_sm,
		uint16_t handle);

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

static struct rap_conn_mapping *find_mapping_by_handle(
					struct cs_state_machine *sm,
					uint16_t handle)
{
	if (!sm || !sm->conn_mappings)
		return NULL;

	return queue_find(sm->conn_mappings, match_mapping_handle,
				UINT_TO_PTR(handle));
}

static bool add_conn_mapping(struct cs_state_machine *sm, uint16_t handle,
				const uint8_t *bdaddr, uint8_t bdaddr_type,
				bool is_central, struct bt_att *att,
				struct bt_rap *rap)
{
	struct rap_conn_mapping *mapping;

	if (!sm)
		return false;

	/* Check if mapping already exists */
	mapping = find_mapping_by_handle(sm, handle);
	if (mapping) {
		/* Update existing mapping */
		if (bdaddr)
			memcpy(mapping->bdaddr, bdaddr, 6);
		mapping->bdaddr_type = bdaddr_type;
		mapping->is_central = is_central;
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
	mapping->is_central = is_central;
	mapping->att = att;
	mapping->rap = rap;

	return queue_push_tail(sm->conn_mappings, mapping);
}

static void remove_conn_mapping(struct cs_state_machine *sm, uint16_t handle)
{
	struct rap_conn_mapping *mapping;

	if (!sm || !sm->conn_mappings)
		return;

	mapping = queue_remove_if(sm->conn_mappings, match_mapping_handle,
					UINT_TO_PTR(handle));
	if (mapping)
		mapping_free(mapping);
}

static struct bt_rap *resolve_handle_to_rap(struct cs_state_machine *sm,
						uint16_t handle)
{
	struct rap_conn_mapping *mapping;

	if (!sm)
		return NULL;

	/* Try to find in mapping cache */
	mapping = find_mapping_by_handle(sm, handle);
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
static void cs_state_machine_init(struct cs_state_machine *sm,
				struct bt_rap *rap, struct bt_hci *hci,
				uint8_t role, uint8_t cs_sync_ant_sel,
				int8_t max_tx_power)
{
	if (!sm)
		return;

	sm->current_state = CS_STATE_UNSPECIFIED;
	sm->rap = rap;
	sm->hci = hci;
	sm->initiator = false;
	sm->procedure_active = false;
	sm->conn_mappings = queue_new();

	/* Store role_enable for HCI commands (1, 2, or 3 from config) */
	sm->role_enable = role;

	/* Initialize per-instance CS options
	 * Note: cs_opt.role will be overwritten with actual role (0x00 or 0x01)
	 * from config complete event, but role_enable preserves the HCI value
	 */
	sm->cs_opt.role = role;
	sm->cs_opt.cs_sync_ant_sel = cs_sync_ant_sel;
	sm->cs_opt.max_tx_power = max_tx_power;
	sm->cs_opt.rtt_type = 0;  /* Will be set from config complete event */
}

/* State Transition Logic */
static void cs_set_state(struct cs_state_machine *sm,
		enum cs_state new_state)
{
	if (!sm)
		return;

	if (sm->current_state == new_state)
		return;

	/* Validate state values before array access */
	if ((unsigned int)sm->current_state >= ARRAY_SIZE(state_names) ||
	    (unsigned int)new_state >= ARRAY_SIZE(state_names)) {
		error("Invalid state transition attempted");
		return;
	}

	DBG("[STATE] Transition: %s → %s",
		state_names[sm->current_state],
		state_names[new_state]);

	sm->old_state = sm->current_state;
	sm->current_state = new_state;
}

static enum cs_state cs_get_current_state(struct cs_state_machine *sm)
{
	return sm ? sm->current_state : CS_STATE_UNSPECIFIED;
}

static bool is_initiator_role(const struct cs_state_machine *sm)
{
	return sm->role_enable == 0x01 || sm->role_enable == 0x03;
}

/* Helper function to send read remote capabilities for all connections */
static void send_read_remote_cap_for_mapping(void *data, void *user_data)
{
	struct rap_conn_mapping *mapping = data;
	struct cs_state_machine *sm = user_data;

	if (!mapping || !sm)
		return;

	DBG("Sending read remote capabilities for handle 0x%04X",
		mapping->handle);
	bt_rap_read_remote_supported_capabilities(sm, mapping->handle);
}

/* HCI Event Callbacks */
static void rap_rd_loc_supp_cap_done_cb(const void *data, uint8_t size,
					void *user_data)
{
	const struct bt_hci_rsp_le_cs_rd_loc_supp_cap *rsp;
	struct cs_state_machine *sm = (struct cs_state_machine *) user_data;

	if (!sm || !data ||
		size < sizeof(struct bt_hci_rsp_le_cs_rd_loc_supp_cap))
		return;

	DBG("size=0x%02X", size);

	rsp = (const struct bt_hci_rsp_le_cs_rd_loc_supp_cap *) data;

	if (rsp->status != 0) {
		error("Read Local Supported Capabilities failed: 0x%02X",
			rsp->status);
		return;
	}

	DBG("Local CS Capabilities:");
	DBG("  Num Config Supported: %u", rsp->num_config_supported);
	DBG("  Max Consecutive Procedures: %u",
		rsp->max_consecutive_procedures_supported);
	DBG("  Num Antennas: %u", rsp->num_antennas_supported);
	DBG("  Max Antenna Paths: %u", rsp->max_antenna_paths_supported);
	DBG("  Roles Supported: 0x%02X", rsp->roles_supported);
	DBG("  Modes Supported: 0x%02X", rsp->modes_supported);
	DBG("  RTT Capability: 0x%02X", rsp->rtt_capability);
	DBG("  RTT AA Only N: %u", rsp->rtt_aa_only_n);
	DBG("  RTT Sounding N: %u", rsp->rtt_sounding_n);
	DBG("  RTT Random Payload N: %u", rsp->rtt_random_payload_n);
	DBG("  NADM Sounding Capability: 0x%04X",
		rsp->nadm_sounding_capability);
	DBG("  NADM Random Capability: 0x%04X", rsp->nadm_random_capability);
	DBG("  CS Sync PHYs Supported: 0x%02X", rsp->cs_sync_phys_supported);
	DBG("  Subfeatures Supported: 0x%04X", rsp->subfeatures_supported);
	DBG("  T_IP1 Times Supported: 0x%04X", rsp->t_ip1_times_supported);
	DBG("  T_IP2 Times Supported: 0x%04X", rsp->t_ip2_times_supported);
	DBG("  T_FCS Times Supported: 0x%04X", rsp->t_fcs_times_supported);
	DBG("  T_PM Times Supported: 0x%04X", rsp->t_pm_times_supported);
	DBG("  T_SW Time Supported: %u", rsp->t_sw_time_supported);
	DBG("  TX SNR Capability: 0x%02X", rsp->tx_snr_capability);

	/* Transition to INIT state before reading remote capabilities */
	cs_set_state(sm, CS_STATE_INIT);

	/* Send read remote capabilities for all connected devices */
	if (sm->conn_mappings) {
		DBG("Sending read remote capabilities for all connections");
		queue_foreach(sm->conn_mappings,
				send_read_remote_cap_for_mapping, sm);
	}
}

static void rap_def_settings_done_cb(const void *data, uint8_t size,
					void *user_data)
{
	const struct bt_hci_rsp_le_cs_set_def_settings *rp;
	struct cs_state_machine *sm = user_data;

	if (!sm || !data || size < sizeof(*rp))
		return;

	DBG("size=0x%02X", size);

	rp = (const struct bt_hci_rsp_le_cs_set_def_settings *) data;

	if (cs_get_current_state(sm) == CS_STATE_STOPPED ||
	    cs_get_current_state(sm) == CS_STATE_UNSPECIFIED) {
		DBG("Def settings response in terminal state, ignoring");
		return;
	}

	if (rp->status == 0) {
		/* Success - proceed to configuration */
		cs_set_state(sm, CS_STATE_WAIT_CONFIG_CMPLT);

		/* If role is initiator, send CS Create Config command */
		if (is_initiator_role(sm)) {
			rap_send_hci_cs_create_config_command(sm, rp->handle);
		} else {
			/* Reflector role */
			DBG("Reflector role: Waiting for CS Config Completed");
		}
	} else {
		/* Error - transition to stopped */
		error("CS Set default setting failed with status 0x%02X",
		rp->status);
		cs_set_state(sm, CS_STATE_STOPPED);
	}
}

static void rap_send_hci_cs_create_config_command(struct cs_state_machine *sm,
						uint16_t handle)
{
	struct bt_hci_cmd_le_cs_create_config cmd;
	unsigned int status;

	uint8_t channel_map[10] = {
		0xFC, 0xFF, 0x7F, 0xFC, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0x1F
	};

	if (!sm || !sm->hci) {
		error("CS Create Config: sm or hci is null");
		return;
	}

	DBG("Sending CS Create Config command for handle 0x%04X", handle);

	memset(&cmd, 0, sizeof(cmd));
	cmd.handle = cpu_to_le16(handle);
	cmd.create_context = 1;
	/* Default values, will change to pick user given values later */
	cmd.config_id              = 0x00;
	cmd.main_mode_type         = 0x01;
	cmd.sub_mode_type          = 0xFF;
	cmd.min_main_mode_steps    = 0x02;
	cmd.max_main_mode_steps    = 0x03;
	cmd.main_mode_repetition   = 0x01;
	cmd.mode_0_steps           = 0x02;
	cmd.role                   = 0x00;
	cmd.rtt_type               = 0x00;
	cmd.cs_sync_phy            = 0x01;
	memcpy(cmd.channel_map, channel_map, 10);
	cmd.channel_map_repetition = 0x01;
	cmd.channel_selection_type = 0x00;
	cmd.ch3c_shape             = 0x00;
	cmd.ch3c_jump              = 0x02;
	cmd.reserved               = 0x00;

	status = bt_hci_send(sm->hci, BT_HCI_CMD_LE_CS_CREATE_CONFIG,
				&cmd, sizeof(cmd), NULL, sm, NULL);

	if (!status) {
		error("Failed to send CS Create Config command");
		cs_set_state(sm, CS_STATE_STOPPED);
		return;
	}

	DBG("CS Create Config command sent successfully");
}

static void rap_send_hci_cs_remove_config_command(struct cs_state_machine *sm,
						uint16_t handle)
{
	struct bt_hci_cmd_le_cs_remove_config cmd;
	unsigned int status;

	if (!sm || !sm->hci) {
		error("CS Remove Config: sm or hci is null");
		return;
	}

	DBG("Sending CS Remove Config command for handle 0x%04X", handle);

	memset(&cmd, 0, sizeof(cmd));
	cmd.handle = cpu_to_le16(handle);
	cmd.config_id = 0x00;  /* Default config ID */

	status = bt_hci_send(sm->hci, BT_HCI_CMD_LE_CS_REMOVE_CONFIG,
				&cmd, sizeof(cmd), NULL, sm, NULL);

	if (!status) {
		error("Failed to send CS Remove Config command");
		cs_set_state(sm, CS_STATE_STOPPED);
		return;
	}

	DBG("CS Remove Config command sent successfully");
}

static void rap_send_hci_cs_security_enable_command(
		struct cs_state_machine *sm, uint16_t handle)
{
	struct bt_hci_cmd_le_cs_sec_enable cmd;
	unsigned int status;

	if (!sm || !sm->hci) {
		error("CS Security Enable: sm or hci is null");
		return;
	}

	DBG("Sending CS Security Enable command for handle 0x%04X", handle);

	memset(&cmd, 0, sizeof(cmd));
	cmd.handle = cpu_to_le16(handle);

	status = bt_hci_send(sm->hci, BT_HCI_CMD_LE_CS_SEC_ENABLE,
				&cmd, sizeof(cmd), NULL, sm, NULL);

	if (!status) {
		error("Failed to send CS Security Enable command");
		cs_set_state(sm, CS_STATE_STOPPED);
		return;
	}

	DBG("CS Security Enable command sent successfully");
}

static bool rap_send_hci_cs_set_procedure_parameters(
		struct cs_state_machine *sm, uint16_t handle)
{
	struct bt_hci_cmd_le_cs_set_proc_params cmd;
	unsigned int status;
	uint8_t min_sub_event_len[3] = {
		0x00, 0x20, 0x00
	};

	uint8_t max_sub_event_len[3] = {
		0x03, 0x20, 0x00
	};

	if (!sm || !sm->hci) {
		error("CS Set Procedure Parameters: sm or hci is null");
		return false;
	}

	DBG("Sending CS Set Procedure Parameters for handle 0x%04X", handle);

	memset(&cmd, 0, sizeof(cmd));
	cmd.handle = cpu_to_le16(handle);
	/* Default values, will change to pick user given values later */
	cmd.config_id = 0x00;
	cmd.max_procedure_len = 0x0640;
	cmd.min_procedure_interval = 0x1E;
	cmd.max_procedure_interval = 0x96;
	cmd.max_procedure_count = 0x00;
	memcpy(cmd.min_subevent_len, min_sub_event_len, 3);
	memcpy(cmd.max_subevent_len, max_sub_event_len, 3);
	cmd.tone_antenna_config_selection = 0x07;
	cmd.phy                    = 0x01;
	cmd.tx_power_delta         = 0x80;
	cmd.preferred_peer_antenna = 0x03;
	cmd.snr_control_initiator  = 0xFF;
	cmd.snr_control_reflector  = 0xFF;

	status = bt_hci_send(sm->hci, BT_HCI_CMD_LE_CS_SET_PROC_PARAMS,
				&cmd, sizeof(cmd), NULL, sm, NULL);

	if (!status) {
		error("Failed to send CS Set Procedure Parameters command");
		return false;
	}

	DBG("CS Set Procedure Parameters command sent successfully");
	return true;
}

static bool rap_send_hci_cs_procedure_enable(struct cs_state_machine *sm,
						uint16_t handle,
						bool enable_proc)
{
	struct bt_hci_cmd_le_cs_proc_enable cmd;
	unsigned int status;

	if (!sm || !sm->hci) {
		error("CS Procedure Enable: sm or hci is null");
		return false;
	}

	DBG("Sending CS Procedure Enable for handle 0x%04X", handle);

	memset(&cmd, 0, sizeof(cmd));
	cmd.handle = cpu_to_le16(handle);
	cmd.config_id = 0x00; /* Default config Id */
	cmd.enable = enable_proc ? 0x01 : 0x00;

	status = bt_hci_send(sm->hci, BT_HCI_CMD_LE_CS_PROC_ENABLE,
				&cmd, sizeof(cmd), NULL, sm, NULL);

	if (!status) {
		error("Failed to send CS Procedure Enable command");
		return false;
	}

	DBG("CS Procedure Enable command sent successfully");
	return true;
}

static void rap_send_hci_def_settings_command(struct cs_state_machine *sm,
		const struct bt_hci_evt_le_cs_rd_rem_supp_cap_complete *ev)
{
	struct bt_hci_cmd_le_cs_set_def_settings cp;
	unsigned int status;

	if (!sm || !sm->hci) {
		error("Set Def Settings: sm or hci is null");
		return;
	}

	memset(&cp, 0, sizeof(cp));

	if (ev->handle)
		cp.handle = ev->handle;

	cp.role_enable = sm->role_enable;  /* Use preserved HCI command value */
	cp.cs_sync_antenna_selection = sm->cs_opt.cs_sync_ant_sel;
	cp.max_tx_power = sm->cs_opt.max_tx_power;

	status = bt_hci_send(sm->hci, BT_HCI_CMD_LE_CS_SET_DEF_SETTINGS,
				&cp, sizeof(cp), rap_def_settings_done_cb,
				sm, NULL);

	DBG("sending set default settings case, status : %d", status);

	if (!status)
		error("Failed to send default settings cmd");
}

static void rap_rd_rem_fae_cmplt_evt(const void *data, uint8_t size,
				      void *user_data)
{
	struct cs_state_machine *sm = (struct cs_state_machine *) user_data;
	const struct bt_hci_evt_le_cs_rd_rem_fae_complete *evt;
	struct iovec iov;
	int i;

	if (!sm || !data ||
		size < sizeof(struct bt_hci_evt_le_cs_rd_rem_fae_complete))
		return;

	/* Initialize iovec with the event data */
	iov.iov_base = (void *) data;
	iov.iov_len = size;

	/* Pull the entire structure at once */
	evt = util_iov_pull_mem(&iov, sizeof(*evt));

	if (!evt) {
		error("Failed to pull remote FAE complete struct");
		return;
	}

	DBG("status=0x%02X, handle=0x%04X", evt->status, evt->handle);

	/* Check status */
	if (evt->status != 0) {
		/* Status 0x11 (Unsupported Feature or Parameter Value) means
		 * the remote has zero FAE, the procedure continues
		 * to the Default Settings step.
		 */
		if (evt->status == 0x11) {
			DBG("Remote FAE=0 (No_FAE), proceed to Def Settings");
			if (is_initiator_role(sm)) {
				struct bt_hci_evt_le_cs_rd_rem_supp_cap_complete
								tmp_ev;

				memset(&tmp_ev, 0, sizeof(tmp_ev));
				tmp_ev.handle = evt->handle;
				DBG("Initiator: send def settings (No_FAE)");
				rap_send_hci_def_settings_command(sm, &tmp_ev);
			} else {
				DBG("Reflector role: continuing after No_FAE");
				cs_set_state(sm, CS_STATE_INIT);
			}
			return;
		}
		error("Remote FAE Table read failed with status 0x%02X",
			evt->status);
		cs_set_state(sm, CS_STATE_STOPPED);
		return;
	}

	DBG("Remote FAE Table received:");
	for (i = 0; i < 72; i += 8) {
		DBG("  [%02d-%02d]: %02X %02X %02X %02X %02X %02X %02X %02X",
			i, i+7,
			evt->remote_fae_table[i], evt->remote_fae_table[i+1],
			evt->remote_fae_table[i+2], evt->remote_fae_table[i+3],
			evt->remote_fae_table[i+4], evt->remote_fae_table[i+5],
			evt->remote_fae_table[i+6], evt->remote_fae_table[i+7]);
	}

	/* After receiving FAE Table, send default settings */
	/* Local capabilities already read before this event */
	if (is_initiator_role(sm)) {
		struct bt_hci_evt_le_cs_rd_rem_supp_cap_complete tmp_ev;

		memset(&tmp_ev, 0, sizeof(tmp_ev));
		tmp_ev.handle = evt->handle;
		DBG("Initiator role: send def settings after FAE table");
		rap_send_hci_def_settings_command(sm, &tmp_ev);
	} else {
		DBG("Reflector role: Proceeding after FAE Table");
		cs_set_state(sm, CS_STATE_INIT);
	}
}

static void rap_rd_rmt_supp_cap_cmplt_evt(const void *data, uint8_t size,
					   void *user_data)
{
	struct cs_state_machine *sm = user_data;
	const struct bt_hci_evt_le_cs_rd_rem_supp_cap_complete *evt;
	struct bt_rap *rap;
	struct iovec iov;
	uint16_t subfeatures_supported;

	if (!sm || !data || size < sizeof(*evt))
		return;

	/* Initialize iovec with the event data */
	iov.iov_base = (void *) data;
	iov.iov_len = size;

	/* Pull the entire structure at once */
	evt = util_iov_pull_mem(&iov, sizeof(*evt));

	if (!evt) {
		error("Failed to pull remote cap complete struct");
		return;
	}

	DBG("status=0x%02X, handle=0x%04X", evt->status, evt->handle);

	/* Check status */
	if (evt->status != 0) {
		error("Remote capabilities failed with status 0x%02X",
			evt->status);
		cs_set_state(sm, CS_STATE_STOPPED);
		return;
	}

	/* Resolve handle to RAP instance */
	rap = resolve_handle_to_rap(sm, evt->handle);

	if (!rap) {
		DBG("[WARN] Could not resolve handle 0x%04X to RAP instance",
			evt->handle);
		/* Continue with state machine RAP for now */
		rap = sm->rap;
	}

	DBG("num_config=%u, ",
		evt->num_config_supported);
	DBG("max_consecutive_proc=%u, num_antennas=%u, ",
		evt->max_consecutive_procedures_supported,
		evt->num_antennas_supported);
	DBG("max_antenna_paths=%u, roles=0x%02X, modes=0x%02X",
		evt->max_antenna_paths_supported,
		evt->roles_supported,
		evt->modes_supported);
	subfeatures_supported = le16_to_cpu(evt->subfeatures_supported);
	DBG("subfeatures_supported=0x%04X", subfeatures_supported);

	/* Check Bit 1 of subfeatures_supported (0x0002) */
	if (!(subfeatures_supported & 0x0002)) {
		DBG("Bit 1 not set, sending Read Remote FAE Table");
		bt_rap_read_remote_fae_table(sm, evt->handle);
		return;
	}

	/* Local capabilities already read before this event */
	if (is_initiator_role(sm)) {
		DBG("Initiator role: send def settings cmd for handle 0x%04X",
			evt->handle);
		rap_send_hci_def_settings_command(sm, evt);
	} else {
		DBG("Reflector role: send def settings cmd");
		cs_set_state(sm, CS_STATE_INIT);
		rap_send_hci_def_settings_command(sm, evt);
	}
}

static void rap_cs_config_cmplt_evt(const void *data, uint8_t size,
				    void *user_data)
{
	struct cs_state_machine *sm = user_data;
	const struct bt_hci_evt_le_cs_config_complete *evt;
	struct rap_ev_cs_config_cmplt rap_ev;
	struct iovec iov;

	if (!sm || !data || size < sizeof(*evt))
		return;

	/* Initialize iovec with the event data */
	iov.iov_base = (void *) data;
	iov.iov_len = size;

	DBG("size=0x%02X", size);

	/* State Check */
	if (cs_get_current_state(sm) != CS_STATE_WAIT_CONFIG_CMPLT) {
		DBG("Event received in Wrong State!! ");
		DBG("Expected : CS_STATE_WAIT_CONFIG_CMPLT");
		return;
	}

	/* Pull the entire structure at once */
	evt = util_iov_pull_mem(&iov, sizeof(*evt));
	if (!evt) {
		error("Failed to pull config complete struct");
		return;
	}

	DBG("status=0x%02X, handle=0x%04X", evt->status, evt->handle);

	/* Check status */
	if (evt->status != 0) {
		if (evt->action != 0x00) {
			/* Create/update failed — try to remove the config */
			error("Configuration failed with status 0x%02X",
				evt->status);
			rap_send_hci_cs_remove_config_command(sm, evt->handle);
		} else {
			error("CS Config Remove failed with status 0x%02X",
				evt->status);
		}
		cs_set_state(sm, CS_STATE_STOPPED);
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

	/* Store role and rtt_type from config complete event
	 * Note: evt->role contains actual role
	 * (CS_INITIATOR=0x00, CS_REFLECTOR=0x01)
	 * which is different from the role_enable value sent in HCI command
	 */
	sm->cs_opt.role = rap_ev.role;
	sm->cs_opt.rtt_type = rap_ev.rtt_type;

	DBG("config_id=%u, action=%u, ",
		rap_ev.config_id, rap_ev.action);
	DBG("main_mode=%u, sub_mode=%u, role=%u, rtt_type=%u",
		rap_ev.main_mode_type, rap_ev.sub_mode_type,
		rap_ev.role, rap_ev.rtt_type);

	if (rap_ev.action == 0x00) {
		cs_set_state(sm, CS_STATE_UNSPECIFIED);
		DBG("CS Config Removed !!!");
		bt_rap_hci_cs_config_complete_callback(size, &rap_ev, sm->rap);
		return;
	}
	/* Success - proceed to Security enable complete */
	cs_set_state(sm, CS_STATE_WAIT_SEC_CMPLT);

	/* CS Security Enable may only be issued by the BLE Central */
	if (rap_ev.role == 0x00) {
		/* Initiator role */
		struct rap_conn_mapping *mapping;

		mapping = find_mapping_by_handle(sm, evt->handle);
		if (!mapping || !mapping->is_central) {
			error("CS Security Enable skipped: not BLE Central");
			cs_set_state(sm, CS_STATE_STOPPED);
			return;
		}

		if (bt_att_get_security(mapping->att, NULL) <
						BT_ATT_SECURITY_MEDIUM) {
			error("CS Security Enable skipped: not encrypted");
			cs_set_state(sm, CS_STATE_STOPPED);
			return;
		}

		DBG("Central,encrypted: Sending CS Security Enable command");
		rap_send_hci_cs_security_enable_command(sm, evt->handle);
	} else {
		/* Reflector role */
		DBG("Reflector role: Waiting for security enable event...");
	}

	/* Send callback to RAP Profile */
	bt_rap_hci_cs_config_complete_callback(size, &rap_ev, sm->rap);
}

static void rap_cs_sec_enable_cmplt_evt(const void *data, uint8_t size,
					 void *user_data)
{
	struct cs_state_machine *sm = user_data;
	struct rap_ev_cs_sec_enable_cmplt rap_ev;
	struct iovec iov;
	uint8_t status;
	uint16_t handle;

	if (!sm || !data ||
		size < sizeof(struct bt_hci_evt_le_cs_sec_enable_complete))
		return;

	/* Initialize iovec with the event data */
	iov.iov_base = (void *) data;
	iov.iov_len = size;

	DBG("size=0x%02X", size);

	/* State Check */
	if (cs_get_current_state(sm) != CS_STATE_WAIT_SEC_CMPLT) {
		DBG("Event received in Wrong State!! ");
		DBG("Expected : CS_STATE_WAIT_SEC_CMPLT");
		return;
	}

	/* Parse all fields in order using iovec */
	if (!util_iov_pull_u8(&iov, &status)) {
		error("Failed to parse Status");
		return;
	}

	if (!util_iov_pull_le16(&iov, &handle)) {
		error("Failed to parse Connection_Handle");
		return;
	}

	rap_ev.status = status;
	rap_ev.conn_hdl = cpu_to_le16(handle);

	DBG("status=0x%02X, handle=0x%04X",
		rap_ev.status, handle);

	if (rap_ev.status == 0) {
		/* Success - proceed to configuration */
		cs_set_state(sm, CS_STATE_WAIT_PROC_CMPLT);

		/* Check if role is initiator */
		if (sm->cs_opt.role == CS_INITIATOR) {
			DBG("Initiator role: Sending CS Set Procedure Params");
			if (!rap_send_hci_cs_set_procedure_parameters(
							sm, handle)) {
				error("Failed to send CS Set Procedure Params");
				cs_set_state(sm, CS_STATE_STOPPED);
				return;
			}

			DBG("Initiator role: Sending CS Procedure Enable");
			if (!rap_send_hci_cs_procedure_enable(sm, handle,
								      true)) {
				error("Failed to send CS Procedure Enable");
				cs_set_state(sm, CS_STATE_STOPPED);
				return;
			}
		} else {
			// Reflector role
			DBG("Reflector role: Waiting for CS Proc compl event");
		}
	} else {
		/* Error - transition to stopped */
		error("Security enable failed with status 0x%02X",
			rap_ev.status);
		cs_set_state(sm, CS_STATE_STOPPED);
	}

	/* Send callback to RAP Profile */
	bt_rap_hci_cs_sec_enable_complete_callback(size, &rap_ev, sm->rap);
}

static void rap_cs_proc_enable_cmplt_evt(const void *data, uint8_t size,
					  void *user_data)
{
	struct cs_state_machine *sm = user_data;
	const struct bt_hci_evt_le_cs_proc_enable_complete *evt;
	struct rap_ev_cs_proc_enable_cmplt rap_ev;
	struct iovec iov;

	if (!sm || !data ||
		size < sizeof(struct bt_hci_evt_le_cs_proc_enable_complete))
		return;

	/* Initialize iovec with the event data */
	iov.iov_base = (void *) data;
	iov.iov_len = size;

	DBG("size=0x%02X", size);

	/* State Check */
	if (cs_get_current_state(sm) != CS_STATE_WAIT_PROC_CMPLT) {
		DBG("Event received in Wrong State!! ");
		DBG("Expected : CS_STATE_WAIT_PROC_CMPLT");
		return;
	}

	/* Pull the entire structure at once */
	evt = util_iov_pull_mem(&iov, sizeof(*evt));
	if (!evt) {
		error("Failed to pull proc enable complete struct");
		return;
	}

	DBG("status=0x%02X, handle=0x%04X", evt->status, evt->handle);

	/* Check status */
	if (evt->status != 0) {
		error("Procedure enable failed with status 0x%02X",
			evt->status);
		cs_set_state(sm, CS_STATE_STOPPED);
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
	DBG("sub_evts_per_evt=%u, evt_intrvl=%u, proc_intrvl=%u",
		rap_ev.sub_evts_per_evt, rap_ev.evt_intrvl,
		rap_ev.proc_intrvl);

	/* Success - procedure started */
	if (rap_ev.state == 0x01) {
		cs_set_state(sm, CS_STATE_STARTED);
		sm->procedure_active = true;
	} else if (rap_ev.state == 0x00) {
		cs_set_state(sm, CS_STATE_STOPPED);
		sm->procedure_active = false;
	}

	/* Send callback to RAP Profile */
	bt_rap_hci_cs_procedure_enable_complete_callback(size,
			&rap_ev, sm->rap);
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
	uint16_t freq_offset;

	if (iov->iov_len < 3) {
		DBG("Mode 0: too short (<3)");
		return;
	}

	util_iov_pull_u8(iov, &mode_data->packet_quality);
	util_iov_pull_u8(iov, &mode_data->packet_rssi_dbm);
	util_iov_pull_u8(iov, &mode_data->packet_ant);
	DBG("CS Step mode 0");

	if (cs_role == CS_INITIATOR && iov->iov_len >= 4) {
		util_iov_pull_le16(iov, &freq_offset);
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
	/* Parse fixed fields in specification order */
	if (!util_iov_pull_u8(iov, &mode_data->packet_quality) ||
		!util_iov_pull_u8(iov, &mode_data->packet_nadm) ||
		!util_iov_pull_u8(iov, &mode_data->packet_rssi_dbm) ||
		!util_iov_pull_le16(iov, &time_val) ||
		!util_iov_pull_u8(iov, &mode_data->packet_ant)) {
		DBG("Mode 1: failed to parse basic fields");
		memset(mode_data, 0, sizeof(*mode_data));
		return;
	}

	if (cs_role == CS_REFLECTOR)
		mode_data->tod_toa_refl = time_val;
	else
		mode_data->toa_tod_init = time_val;

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

/*
 * Handle the common step-parsing tail shared by both subevent result variants.
 * Fixes truncation (num_steps_reported > CS_MAX_STEPS) by zeroing the step
 * count and trimming send_len to header_size, matching the abort-status path.
 */
static void cs_parse_steps(struct iovec *iov,
			uint8_t num_steps_reported,
			uint8_t proc_done_status,
			uint8_t subevt_done_status,
			uint8_t abort_reason,
			uint8_t cs_role, uint8_t cs_rtt_type,
			uint8_t max_paths,
			struct cs_step_data *step_data,
			uint8_t *num_steps_out,
			size_t *send_len,
			size_t header_size)
{
	uint8_t steps = MIN(num_steps_reported, CS_MAX_STEPS);
	uint8_t i;

	if (num_steps_reported > CS_MAX_STEPS) {
		DBG("Too many steps reported: %u (max %u)",
			num_steps_reported, CS_MAX_STEPS);
		*num_steps_out = 0;
		*send_len = header_size;
		return;
	}

	if (subevt_done_status == 0xF || proc_done_status == 0xF) {
		DBG("CS Procedure/Subevent aborted: ");
		DBG("sub evt status = %d, proc status = %d, reason = %d",
			subevt_done_status, proc_done_status, abort_reason);
		/*
		 * Step bytes were never parsed; zero-initialised step_data[]
		 * entries would appear as spurious mode-0 quality=0 steps to
		 * the BCS algorithm.  Clear the count so an aborted subevent
		 * carries no fake measurements.
		 */
		*num_steps_out = 0;
		*send_len = header_size;
		return;
	}

	for (i = 0; i < steps; i++)
		parse_cs_step(iov, &step_data[i], cs_role, cs_rtt_type,
			max_paths);
}

static void rap_cs_subevt_result_evt(const void *data, uint8_t size,
				void *user_data)
{
	struct cs_state_machine *sm = (struct cs_state_machine *) user_data;
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

	if (!sm || !data ||
		size < sizeof(struct bt_hci_evt_le_cs_subevent_result))
		return;

	/* Initialize iovec with the event data */
	iov.iov_base = (void *) data;
	iov.iov_len = size;

	/* Check if Procedure is active or not */
	if (!sm->procedure_active) {
		DBG("Received Subevent event when Procedure is inactive!");
		return;
	}

	/* Parse header fields using iovec */
	if (!util_iov_pull_le16(&iov, &handle)) {
		error("Failed to parse Connection_Handle");
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
		error("Failed to parse subevent fields");
		return;
	}

	cs_role = sm->cs_opt.role;
	cs_rtt_type = sm->cs_opt.rtt_type;
	max_paths = MIN((num_ant_paths + 1), CS_MAX_ANT_PATHS);
	steps = MIN(num_steps_reported, CS_MAX_STEPS);
	send_len = offsetof(struct rap_ev_cs_subevent_result, step_data) +
					steps * sizeof(struct cs_step_data);
	rap_ev = malloc0(send_len);
	if (!rap_ev) {
		error("Failed to allocate memory for subevent result\n");
		return;
	}

	DBG("length=%u", size);
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

	cs_parse_steps(&iov, num_steps_reported,
			proc_done_status, subevt_done_status, abort_reason,
			cs_role, cs_rtt_type, max_paths,
			rap_ev->step_data, &rap_ev->num_steps_reported,
			&send_len,
			offsetof(struct rap_ev_cs_subevent_result, step_data));

	DBG("CS subevent result processed: %zu bytes, ", send_len);
	bt_rap_hci_cs_subevent_result_callback(send_len, rap_ev, sm->rap);
	free(rap_ev);
}

static void rap_cs_subevt_result_cont_evt(const void *data, uint8_t size,
					void *user_data)
{
	struct cs_state_machine *sm = (struct cs_state_machine *) user_data;
	struct rap_ev_cs_subevent_result_cont *rap_ev;
	struct iovec iov;
	uint8_t cs_role;
	uint8_t cs_rtt_type;
	uint8_t max_paths;
	uint8_t steps;
	size_t send_len;
	uint16_t handle;
	uint8_t config_id;
	uint8_t proc_done_status;
	uint8_t subevt_done_status;
	uint8_t abort_reason;
	uint8_t num_ant_paths;
	uint8_t num_steps_reported;

	if (!sm || !data ||
		size < sizeof(struct bt_hci_evt_le_cs_subevent_result_continue))
		return;

	/* Initialize iovec with the event data */
	iov.iov_base = (void *) data;
	iov.iov_len = size;

	/* Check if Procedure is active or not */
	if (!sm->procedure_active) {
		error("Received Subevent when CS Procedure is inactive!");
		return;
	}

	/* Parse header fields using iovec */
	if (!util_iov_pull_le16(&iov, &handle)) {
		error("Failed to parse Connection_Handle");
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

	cs_role = sm->cs_opt.role;
	cs_rtt_type = sm->cs_opt.rtt_type;
	max_paths = MIN((num_ant_paths + 1), CS_MAX_ANT_PATHS);
	steps = MIN(num_steps_reported, CS_MAX_STEPS);
	send_len = offsetof(struct rap_ev_cs_subevent_result_cont, step_data) +
					steps * sizeof(struct cs_step_data);
	rap_ev = malloc0(send_len);
	if (!rap_ev) {
		error("Failed to allocate memory for subevent result\n");
		return;
	}

	DBG("length=%u", size);
	rap_ev->conn_hdl                     = le16_to_cpu(handle);
	rap_ev->config_id                    = config_id;
	rap_ev->proc_done_status             = proc_done_status;
	rap_ev->subevt_done_status           = subevt_done_status;
	rap_ev->abort_reason                 = abort_reason;
	rap_ev->num_ant_paths                = num_ant_paths;
	rap_ev->num_steps_reported           = steps;

	cs_parse_steps(&iov, num_steps_reported,
			proc_done_status, subevt_done_status, abort_reason,
			cs_role, cs_rtt_type, max_paths,
			rap_ev->step_data, &rap_ev->num_steps_reported,
			&send_len,
			offsetof(struct rap_ev_cs_subevent_result_cont,
							step_data));

	DBG("CS subevent result cont processed: %zu bytes, ", send_len);
	bt_rap_hci_cs_subevent_result_cont_callback(send_len, rap_ev, sm->rap);
	free(rap_ev);
}

/* Subevent handler function type */

/* Set Ch Class cmd handling to be added after DBus support enabled */

static bool bt_rap_read_remote_fae_table(void *hci_sm, uint16_t handle)
{
	struct cs_state_machine *sm = hci_sm;
	struct bt_hci_cmd_le_cs_rd_rem_fae cmd;
	unsigned int status;

	if (!sm || !sm->hci) {
		error("Invalid state machine or HCI");
		return false;
	}

	DBG("Sending Read Remote FAE Table for handle 0x%04X", handle);

	memset(&cmd, 0, sizeof(cmd));
	cmd.handle = cpu_to_le16(handle);

	status = bt_hci_send(sm->hci, BT_HCI_CMD_LE_CS_RD_REM_FAE,
				&cmd, sizeof(cmd), NULL, sm, NULL);

	if (!status) {
		error("Failed to send Read Remote FAE Table command");
		return false;
	}

	DBG("Read Remote FAE Table command sent successfully");
	return true;
}

/* This cmd is used by host to start cs distance measurement procedure
 * function will be used when user start distance measurement
 * keeping it unused till DBUS API is added
 */
static bool bt_rap_read_local_supported_capabilities(
		void *hci_sm)
{
	struct cs_state_machine *sm = hci_sm;
	unsigned int status;

	if (!sm || !sm->hci) {
		error("Invalid state machine or HCI");
		return false;
	}

	DBG("Sending Read Local Supported Capabilities command");

	status = bt_hci_send(sm->hci, BT_HCI_CMD_LE_CS_RD_LOC_SUPP_CAP,
				NULL, 0, rap_rd_loc_supp_cap_done_cb,
				sm, NULL);

	if (!status) {
		error("Failed to send Read Local Supported Capabilities");
		return false;
	}

	DBG("Read Local Supported Capabilities command sent successfully");
	return true;
}

static bool bt_rap_read_remote_supported_capabilities(void *hci_sm,
		uint16_t handle)
{
	struct cs_state_machine *sm = hci_sm;
	struct bt_hci_cmd_le_cs_rd_rem_supp_cap cmd;
	unsigned int status;

	if (!sm || !sm->hci) {
		error("Invalid state machine or HCI");
		return false;
	}

	DBG("Sending Read Remote Supported Capabilities for handle 0x%04X",
		handle);

	memset(&cmd, 0, sizeof(cmd));
	cmd.handle = cpu_to_le16(handle);

	status = bt_hci_send(sm->hci, BT_HCI_CMD_LE_CS_RD_REM_SUPP_CAP,
				&cmd, sizeof(cmd), NULL, sm, NULL);

	if (!status) {
		error("Failed to send Read Remote Capabilities command");
		return false;
	}

	DBG("Read Remote Capabilities command sent successfully");
	return true;
}

static void unregister_event_id(void *data, void *user_data)
{
	struct bt_hci *hci = user_data;

	bt_hci_unregister_subevent(hci, PTR_TO_UINT(data));
}

void *bt_rap_attach_hci(struct bt_rap *rap, struct bt_hci *hci,
			uint8_t role, uint8_t cs_sync_ant_sel,
			int8_t max_tx_power)
{
	struct cs_state_machine *sm;
	unsigned int id;

	if (!rap || !hci) {
		error("rap or hci null");
		return NULL;
	}

	/* Allocate per-instance state machine */
	sm = new0(struct cs_state_machine, 1);
	if (!sm) {
		error("Failed to allocate state machine");
		return NULL;
	}

	/* Initialize state machine with provided CS options */
	cs_state_machine_init(sm, rap, hci, role, cs_sync_ant_sel,
				max_tx_power);

	/* place holder, need DBus API to be called */
	bt_rap_read_local_supported_capabilities(sm);

	sm->event_ids = queue_new();
	if (!sm->event_ids) {
		error("Failed to allocate event_ids queue");
		free(sm);
		return NULL;
	}

	/* Register each LE Meta subevent individually */
	id = bt_hci_register_subevent(hci,
			BT_HCI_EVT_LE_CS_RD_REM_SUPP_CAP_COMPLETE,
			rap_rd_rmt_supp_cap_cmplt_evt, sm, NULL);
	if (!id)
		goto fail;

	queue_push_tail(sm->event_ids, UINT_TO_PTR(id));

	id = bt_hci_register_subevent(hci,
		BT_HCI_EVT_LE_CS_RD_REM_FAE_COMPLETE,
		rap_rd_rem_fae_cmplt_evt, sm, NULL);

	if (!id)
		goto fail;

	queue_push_tail(sm->event_ids, UINT_TO_PTR(id));

	id = bt_hci_register_subevent(hci,
			BT_HCI_EVT_LE_CS_CONFIG_COMPLETE,
			rap_cs_config_cmplt_evt, sm, NULL);
	if (!id)
		goto fail;

	queue_push_tail(sm->event_ids, UINT_TO_PTR(id));

	id = bt_hci_register_subevent(hci,
			BT_HCI_EVT_LE_CS_SEC_ENABLE_COMPLETE,
			rap_cs_sec_enable_cmplt_evt, sm, NULL);
	if (!id)
		goto fail;

	queue_push_tail(sm->event_ids, UINT_TO_PTR(id));

	id = bt_hci_register_subevent(hci,
			BT_HCI_EVT_LE_CS_PROC_ENABLE_COMPLETE,
			rap_cs_proc_enable_cmplt_evt, sm, NULL);
	if (!id)
		goto fail;

	queue_push_tail(sm->event_ids, UINT_TO_PTR(id));

	id = bt_hci_register_subevent(hci,
			BT_HCI_EVT_LE_CS_SUBEVENT_RESULT,
			rap_cs_subevt_result_evt, sm, NULL);
	if (!id)
		goto fail;

	queue_push_tail(sm->event_ids, UINT_TO_PTR(id));

	id = bt_hci_register_subevent(hci,
			BT_HCI_EVT_LE_CS_SUBEVENT_RESULT_CONTINUE,
			rap_cs_subevt_result_cont_evt, sm, NULL);
	if (!id)
		goto fail;

	queue_push_tail(sm->event_ids, UINT_TO_PTR(id));

	DBG("CS options: role=%u, cs_sync_ant_sel=%u, max_tx_power=%d",
		role, cs_sync_ant_sel, max_tx_power);

	return sm;

fail:
	error("Failed to register hci le meta subevents");
	queue_foreach(sm->event_ids, unregister_event_id, hci);
	queue_destroy(sm->event_ids, NULL);
	queue_destroy(sm->conn_mappings, mapping_free);
	free(sm);
	return NULL;
}

bool bt_rap_set_conn_handle(void *hci_sm, struct bt_rap *rap,
		uint16_t handle, const uint8_t *bdaddr, uint8_t bdaddr_type,
		bool is_central)
{
	struct cs_state_machine *sm = hci_sm;
	struct bt_att *att;

	if (!sm || !rap)
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

	return add_conn_mapping(sm, handle, bdaddr, bdaddr_type, is_central,
				att, rap);
}

void bt_rap_clear_conn_handle(void *hci_sm, uint16_t handle)
{
	struct cs_state_machine *sm = hci_sm;

	if (!sm)
		return;

	DBG("Clearing connection mapping: handle=0x%04X", handle);
	remove_conn_mapping(sm, handle);
}

void bt_rap_detach_hci(struct bt_rap *rap, void *hci_sm)
{
	struct cs_state_machine *sm = hci_sm;

	if (!rap)
		return;

	DBG("Detaching RAP from HCI, cleaning up mappings");

	/* Cleanup the per-instance state machine */
	if (sm) {
		/* Unregister HCI events */
		if (sm->hci)
			queue_foreach(sm->event_ids, unregister_event_id,
								sm->hci);

		queue_destroy(sm->event_ids, NULL);

		/* Clean up per-instance connection mappings */
		queue_destroy(sm->conn_mappings, mapping_free);

		/* Free the state machine */
		free(sm);
	}
}
