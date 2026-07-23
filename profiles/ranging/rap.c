// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stddef.h>
#include <errno.h>

#include <glib.h>

#include "gdbus/gdbus.h"

#include "bluetooth/bluetooth.h"
#include "bluetooth/l2cap.h"
#include "bluetooth/uuid.h"

#include "src/plugin.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/gatt-database.h"
#include "attrib/gattrib.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/rap.h"
#include "attrib/att.h"
#include "src/log.h"
#include "src/shared/cs-types.h"
#include "src/btd.h"
#include "src/dbus-common.h"

#define CS_INTERFACE "org.bluez.ChannelSounding1"

struct rap_adapter_data {
	struct btd_adapter *adapter;
	struct bt_hci *hci;  /* Shared HCI raw channel */
	int ref_count;  /* Number of devices using this adapter */
};

struct cs_session {
	bool active;
	uint32_t duration_secs;
	struct bt_rap_le_cs_default_settings settings;
	struct bt_rap_le_cs_config    cfg;
	struct bt_rap_le_cs_frequency freq;
};

struct rap_data {
	struct btd_device *device;
	struct btd_service *service;
	struct bt_rap *rap;
	unsigned int ready_id;
	struct rap_adapter_data *adapter_data;  /* Shared adapter-level HCI */
	void *hci_sm;  /* Per-device HCI state machine */
	uint16_t conn_handle;  /* Last known connection handle */
	struct cs_session active_session;  /* active==false when idle */
};

static struct queue *sessions;
static struct queue *adapter_list;  /* List of rap_adapter_data */

/* Adapter data management */
static bool match_adapter(const void *data, const void *match_data)
{
	const struct rap_adapter_data *adapter_data = data;
	const struct btd_adapter *adapter = match_data;

	return adapter_data->adapter == adapter;
}

static struct rap_adapter_data *
rap_adapter_data_find(struct btd_adapter *adapter)
{
	return queue_find(adapter_list, match_adapter, adapter);
}

static struct rap_adapter_data *
rap_adapter_data_new(struct btd_adapter *adapter)
{
	struct rap_adapter_data *adapter_data;
	int16_t hci_index;

	hci_index = btd_adapter_get_index(adapter);
	DBG("Creating new adapter_data for hci%d", hci_index);

	adapter_data = new0(struct rap_adapter_data, 1);
	if (!adapter_data) {
		error("Failed to allocate adapter_data");
		return NULL;
	}

	adapter_data->adapter = adapter;
	adapter_data->ref_count = 0;

	/* Create adapter list if needed */
	if (!adapter_list) {
		DBG("Creating new adapter_list");
		adapter_list = queue_new();
	}

	/* Add to queue BEFORE creating HCI to prevent race condition */
	queue_push_tail(adapter_list, adapter_data);
	DBG("Added adapter_data to queue");

	/* Create HCI raw channel for this adapter */
	DBG("Opening HCI raw device for hci%d", hci_index);
	adapter_data->hci = bt_hci_new_raw_device(hci_index);

	if (!adapter_data->hci) {
		error("Failed to create HCI raw device for hci%d", hci_index);
		queue_remove(adapter_list, adapter_data);
		free(adapter_data);
		return NULL;
	}

	DBG("HCI raw channel created successfully for hci%d", hci_index);

	return adapter_data;
}

static struct rap_adapter_data *
rap_adapter_data_ref(struct btd_adapter *adapter)
{
	struct rap_adapter_data *adapter_data;

	adapter_data = rap_adapter_data_find(adapter);
	if (!adapter_data) {
		adapter_data = rap_adapter_data_new(adapter);
		if (!adapter_data)
			return NULL;
	}

	adapter_data->ref_count++;

	return adapter_data;
}

static void rap_adapter_data_unref(struct rap_adapter_data *adapter_data)
{
	if (!adapter_data)
		return;

	adapter_data->ref_count--;

	if (adapter_data->ref_count > 0)
		return;

	/* No more devices using this adapter, clean up */
	DBG("Cleaning up adapter HCI channel");

	if (adapter_data->hci) {
		bt_hci_unref(adapter_data->hci);
		adapter_data->hci = NULL;
	}

	queue_remove(adapter_list, adapter_data);
	free(adapter_data);

	if (queue_isempty(adapter_list)) {
		queue_destroy(adapter_list, NULL);
		adapter_list = NULL;
	}
}

static struct rap_data *rap_data_new(struct btd_device *device)
{
	struct rap_data *data;

	data = new0(struct rap_data, 1);
	data->device = device;

	return data;
}

static void rap_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static void rap_data_add(struct rap_data *data)
{
	DBG("%p", data);

	if (queue_find(sessions, NULL, data)) {
		error("data %p already added", data);
		return;
	}

	bt_rap_set_debug(data->rap, rap_debug, NULL, NULL);

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, data);

	if (data->service)
		btd_service_set_user_data(data->service, data);
}

static bool match_data(const void *data, const void *match_data)
{
	const struct rap_data *mdata = data;
	const struct bt_rap *rap = match_data;

	return mdata->rap == rap;
}

static void rap_data_free(struct rap_data *data)
{
	if (data->service) {
		btd_service_set_user_data(data->service, NULL);
		bt_rap_set_user_data(data->rap, NULL);
	}

	bt_rap_ready_unregister(data->rap, data->ready_id);

	/* Detach per-device HCI state machine */
	if (data->hci_sm) {
		bt_rap_detach_hci(data->rap, data->hci_sm);
		data->hci_sm = NULL;
	}

	/* Release reference to shared adapter HCI channel */
	if (data->adapter_data) {
		rap_adapter_data_unref(data->adapter_data);
		data->adapter_data = NULL;
	}

	bt_rap_unref(data->rap);
	free(data);
}

static void rap_data_remove(struct rap_data *data)
{
	DBG("%p", data);

	if (!queue_remove(sessions, data))
		return;

	rap_data_free(data);

	if (queue_isempty(sessions)) {
		queue_destroy(sessions, NULL);
		sessions = NULL;
	}
}

static void rap_detached(struct bt_rap *rap, void *user_data)
{
	struct rap_data *data;

	DBG("%p", rap);

	data = queue_find(sessions, match_data, rap);
	if (!data) {
		error("unable to find session");
		return;
	}

	rap_data_remove(data);
}

static void rap_ready(struct bt_rap *rap, void *user_data)
{
	DBG("%p", rap);
}

static void rap_attached(struct bt_rap *rap, void *user_data)
{
	struct rap_data *data;
	struct bt_att *att;
	struct btd_device *device;

	DBG("%p", rap);

	data = queue_find(sessions, match_data, rap);
	if (data) {
		DBG("data is already present");
		return;
	}

	att = bt_rap_get_att(rap);
	if (!att) {
		error("Unable to get att");
		return;
	}

	device = btd_adapter_find_device_by_fd(bt_att_get_fd(att));
	if (!device) {
		error("unable to find device");
		return;
	}

	data = rap_data_new(device);
	data->rap = rap;

	rap_data_add(data);
}

enum cs_dict_target {
	CS_TARGET_SETTINGS,
	CS_TARGET_CFG,
	CS_TARGET_FREQ,
};

struct cs_dict_param_desc {
	const char *key;
	enum cs_dict_target target;
	int vtype;
	size_t offset;
};

#define CS_SETTINGS_FIELD(_key, _field) \
	{ _key, CS_TARGET_SETTINGS, DBUS_TYPE_BYTE, \
		offsetof(struct bt_rap_le_cs_default_settings, _field) }
#define CS_CFG_FIELD(_key, _field) \
	{ _key, CS_TARGET_CFG, DBUS_TYPE_BYTE, \
		offsetof(struct bt_rap_le_cs_config, _field) }
#define CS_FREQ_U8_FIELD(_key, _field) \
	{ _key, CS_TARGET_FREQ, DBUS_TYPE_BYTE, \
		offsetof(struct bt_rap_le_cs_frequency, _field) }
#define CS_FREQ_U16_FIELD(_key, _field) \
	{ _key, CS_TARGET_FREQ, DBUS_TYPE_UINT16, \
		offsetof(struct bt_rap_le_cs_frequency, _field) }

static const struct cs_dict_param_desc cs_dict_param_table[] = {
	CS_SETTINGS_FIELD("role", role),
	CS_SETTINGS_FIELD("sync_ant_sel", cs_sync_ant_sel),
	CS_CFG_FIELD("create_context", create_context),
	CS_CFG_FIELD("config_id", config_id),
	CS_CFG_FIELD("main_mode_type", main_mode_type),
	CS_CFG_FIELD("sub_mode_type", sub_mode_type),
	CS_CFG_FIELD("main_mode_min_steps", main_mode_min_steps),
	CS_CFG_FIELD("main_mode_max_steps", main_mode_max_steps),
	CS_CFG_FIELD("main_mode_repetition", main_mode_repetition),
	CS_CFG_FIELD("mode0_steps", mode0_steps),
	CS_CFG_FIELD("rtt_types", rtt_types),
	CS_CFG_FIELD("sync_phy", cs_sync_phy),
	CS_CFG_FIELD("channel_map_repetition", channel_map_repetition),
	CS_CFG_FIELD("channel_selection_type", channel_selection_type),
	CS_CFG_FIELD("channel_shape", channel_shape),
	CS_CFG_FIELD("channel_jump", channel_jump),
	CS_CFG_FIELD("companion_signal_enable", companion_signal_enable),
	CS_FREQ_U16_FIELD("max_procedure_duration", max_procedure_duration),
	CS_FREQ_U16_FIELD("min_period_between_procedures",
				min_period_between_procedures),
	CS_FREQ_U16_FIELD("max_period_between_procedures",
				max_period_between_procedures),
	CS_FREQ_U16_FIELD("max_procedure_count", max_procedure_count),
	CS_FREQ_U8_FIELD("tone_antenna_config_selection",
				tone_antenna_config_selection),
	CS_FREQ_U8_FIELD("phy", phy),
	CS_FREQ_U8_FIELD("tx_power_delta", tx_power_delta),
	CS_FREQ_U8_FIELD("preferred_peer_antenna", preferred_peer_antenna),
	CS_FREQ_U8_FIELD("snr_control_initiator", snr_control_initiator),
	CS_FREQ_U8_FIELD("snr_control_reflector", snr_control_reflector),
};

static const struct cs_dict_param_desc *cs_find_dict_param_desc(
							const char *key)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cs_dict_param_table); i++) {
		if (!strcmp(cs_dict_param_table[i].key, key))
			return &cs_dict_param_table[i];
	}

	return NULL;
}

static void dict_append_byte(DBusMessageIter *dict, const char *key,
				uint8_t val)
{
	DBusMessageIter entry, variant;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
						&entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "y",
						&variant);
	dbus_message_iter_append_basic(&variant, DBUS_TYPE_BYTE, &val);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(dict, &entry);
}

static void dict_append_int32(DBusMessageIter *dict, const char *key,
				dbus_int32_t val)
{
	DBusMessageIter entry, variant;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
						&entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "i",
						&variant);
	dbus_message_iter_append_basic(&variant, DBUS_TYPE_INT32, &val);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(dict, &entry);
}

static void dict_append_uint32(DBusMessageIter *dict, const char *key,
				dbus_uint32_t val)
{
	DBusMessageIter entry, variant;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
						&entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "u",
						&variant);
	dbus_message_iter_append_basic(&variant, DBUS_TYPE_UINT32, &val);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(dict, &entry);
}

static void dict_append_uint64(DBusMessageIter *dict, const char *key,
				dbus_uint64_t val)
{
	DBusMessageIter entry, variant;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
						&entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "t",
						&variant);
	dbus_message_iter_append_basic(&variant, DBUS_TYPE_UINT64, &val);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(dict, &entry);
}

static void dict_append_byte_array(DBusMessageIter *dict, const char *key,
					const uint8_t *data, int len)
{
	DBusMessageIter entry, variant, arr;
	int i;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
						&entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "ay",
						&variant);
	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "y", &arr);
	for (i = 0; i < len; i++)
		dbus_message_iter_append_basic(&arr, DBUS_TYPE_BYTE, &data[i]);
	dbus_message_iter_close_container(&variant, &arr);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(dict, &entry);
}

static void append_mode_zero(DBusMessageIter *dict,
				const struct cs_mode_zero_data *m0)
{
	dict_append_byte(dict, "packetQuality", m0->packet_quality);
	dict_append_byte(dict, "packetRssiDbm", m0->packet_rssi_dbm);
	dict_append_byte(dict, "packetAntenna", m0->packet_ant);
	dict_append_int32(dict, "initiatorMeasuredFreqOffset",
				(dbus_int32_t)m0->init_measured_freq_offset);
}

static void append_pct_iq_pair(DBusMessageIter *dict, const char *key,
				const struct pct_iq_sample *pct)
{
	DBusMessageIter entry, variant, arr;
	dbus_int32_t i_s = pct->i_sample;
	dbus_int32_t q_s = pct->q_sample;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
					 &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "ai",
					 &variant);
	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "i", &arr);
	dbus_message_iter_append_basic(&arr, DBUS_TYPE_INT32, &i_s);
	dbus_message_iter_append_basic(&arr, DBUS_TYPE_INT32, &q_s);
	dbus_message_iter_close_container(&variant, &arr);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(dict, &entry);
}

static void append_mode_one(DBusMessageIter *dict,
				const struct cs_mode_one_data *m1)
{
	dict_append_byte(dict, "packetQuality", m1->packet_quality);
	dict_append_byte(dict, "packetNadm", m1->packet_nadm);
	dict_append_byte(dict, "packetRssiDbm", m1->packet_rssi_dbm);
	dict_append_int32(dict, "toaTodInitiator",
				(dbus_int32_t)m1->toa_tod_init);
	dict_append_int32(dict, "todToaReflector",
				(dbus_int32_t)m1->tod_toa_refl);
	dict_append_byte(dict, "packetAntenna", m1->packet_ant);
	append_pct_iq_pair(dict, "packetPct1", &m1->packet_pct1);
	append_pct_iq_pair(dict, "packetPct2", &m1->packet_pct2);
}

static void append_mode_two(DBusMessageIter *dict,
				const struct cs_mode_two_data *m2,
				uint8_t num_ant_paths)
{
	DBusMessageIter entry, variant, arr;
	const char *key;
	int j;
	int num_paths;

	/*
	 * num_ant_paths is the HCI "number of antenna paths" value
	 * (0-indexed), so actual tone sample count = num_ant_paths + 1,
	 * capped at array size.
	 */
	num_paths = (num_ant_paths + 1) < CS_MAX_ANT_PATHS ?
				(num_ant_paths + 1) : CS_MAX_ANT_PATHS;

	dict_append_byte(dict, "antennaPermutationIndex", m2->ant_perm_index);

	/* tonePctIQSamples: interleaved (i,q) pairs as "ai" */
	key = "tonePctIQSamples";
	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
					 &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "ai",
					 &variant);
	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "i", &arr);
	for (j = 0; j < num_paths; j++) {
		dbus_int32_t i_s = m2->tone_pct[j].i_sample;
		dbus_int32_t q_s = m2->tone_pct[j].q_sample;

		dbus_message_iter_append_basic(&arr, DBUS_TYPE_INT32, &i_s);
		dbus_message_iter_append_basic(&arr, DBUS_TYPE_INT32, &q_s);
	}
	dbus_message_iter_close_container(&variant, &arr);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(dict, &entry);

	/* toneQualityIndicators: "ay" */
	key = "toneQualityIndicators";
	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
					 &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "ay",
					 &variant);
	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "y", &arr);
	for (j = 0; j < num_paths; j++) {
		uint8_t tqi = m2->tone_quality_indicator[j];

		dbus_message_iter_append_basic(&arr, DBUS_TYPE_BYTE, &tqi);
	}
	dbus_message_iter_close_container(&variant, &arr);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(dict, &entry);
}

static void append_proc_enable_config(DBusMessageIter *outer_dict,
				const struct rap_ev_cs_proc_enable_cmplt *cfg)
{
	DBusMessageIter entry, variant, inner;
	const char *key = "procedureEnableConfig";
	dbus_uint32_t sub_evt_len_us;

	sub_evt_len_us = cfg->sub_evt_len[0] |
			 ((uint32_t)cfg->sub_evt_len[1] << 8) |
			 ((uint32_t)cfg->sub_evt_len[2] << 16);

	dbus_message_iter_open_container(outer_dict, DBUS_TYPE_DICT_ENTRY,
					 NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "a{sv}",
					 &variant);
	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "{sv}",
					 &inner);

	dict_append_byte(&inner, "toneAntennaConfigSelection",
			 cfg->tone_ant_config_sel);
	dict_append_uint32(&inner, "subeventLenUs", sub_evt_len_us);
	dict_append_byte(&inner, "subeventsPerEvent", cfg->sub_evts_per_evt);
	dict_append_uint32(&inner, "subeventInterval", cfg->sub_evt_intrvl);
	dict_append_uint32(&inner, "eventInterval", cfg->evt_intrvl);
	dict_append_uint32(&inner, "procedureInterval", cfg->proc_intrvl);
	dict_append_uint32(&inner, "procedureCount", cfg->proc_counter);
	dict_append_uint32(&inner, "maxProcedureLen", cfg->max_proc_len);

	dbus_message_iter_close_container(&variant, &inner);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(outer_dict, &entry);
}

static void append_cs_config_param(DBusMessageIter *outer_dict,
				const struct bcs_procedure_data *bcs)
{
	DBusMessageIter entry, variant, inner;
	const char *key = "csConfigParam";
	const struct rap_ev_cs_config_cmplt *cfg = &bcs->cs_config;

	dbus_message_iter_open_container(outer_dict, DBUS_TYPE_DICT_ENTRY,
					 NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "a{sv}",
					 &variant);
	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "{sv}",
					 &inner);

	dict_append_byte(&inner, "modeType", cfg->main_mode_type);
	dict_append_byte(&inner, "subModeType", cfg->sub_mode_type);
	dict_append_byte(&inner, "rttType", cfg->rtt_type);
	dict_append_byte_array(&inner, "channelMap", cfg->channel_map,
			       sizeof(cfg->channel_map));
	dict_append_byte(&inner, "minMainModeSteps", cfg->min_main_mode_steps);
	dict_append_byte(&inner, "maxMainModeSteps", cfg->max_main_mode_steps);
	dict_append_byte(&inner, "mainModeRepetition", cfg->main_mode_rep);
	dict_append_byte(&inner, "mode0Steps", cfg->mode_0_steps);
	dict_append_byte(&inner, "role", cfg->role);
	dict_append_byte(&inner, "csSyncPhyType", cfg->cs_sync_phy);
	dict_append_byte(&inner, "channelSelectionType", cfg->channel_sel_type);
	dict_append_byte(&inner, "ch3cShapeType", cfg->ch3c_shape);
	dict_append_byte(&inner, "ch3cJump", cfg->ch3c_jump);
	dict_append_byte(&inner, "channelMapRepetition", cfg->channel_map_rep);
	dict_append_byte(&inner, "tIp1TimeUs", cfg->t_ip1_time);
	dict_append_byte(&inner, "tIp2TimeUs", cfg->t_ip2_time);
	dict_append_byte(&inner, "tFcsTimeUs", cfg->t_fcs_time);
	dict_append_byte(&inner, "tPmTimeUs", cfg->t_pm_time);
	dict_append_byte(&inner, "tSwTimeUsSupportedByLocal",
			 bcs->t_sw_time_us_supported_by_local);
	dict_append_byte(&inner, "tSwTimeUsSupportedByRemote",
			 bcs->t_sw_time_us_supported_by_remote);
	dict_append_uint32(&inner, "bleConnInterval", bcs->ble_conn_interval);

	dbus_message_iter_close_container(&variant, &inner);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(outer_dict, &entry);
}

static void append_step_to_dict(DBusMessageIter *dict,
				const struct cs_step_data *step,
				uint8_t num_ant_paths)
{
	DBusMessageIter entry, variant, inner;
	const char *mode_key;

	dict_append_byte(dict, "stepMode", step->step_mode);
	dict_append_byte(dict, "stepChannel", step->step_chnl);

	switch (step->step_mode) {
	case CS_MODE_ZERO:
		mode_key = "modeZeroData";
		dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
						 NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
					       &mode_key);
		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
						 "a{sv}", &variant);
		dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						 "{sv}", &inner);
		append_mode_zero(&inner,
				 &step->step_mode_data.mode_zero_data);
		dbus_message_iter_close_container(&variant, &inner);
		dbus_message_iter_close_container(&entry, &variant);
		dbus_message_iter_close_container(dict, &entry);
		break;

	case CS_MODE_ONE:
		mode_key = "modeOneData";
		dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
						 NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
					       &mode_key);
		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
						 "a{sv}", &variant);
		dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						 "{sv}", &inner);
		append_mode_one(&inner,
				&step->step_mode_data.mode_one_data);
		dbus_message_iter_close_container(&variant, &inner);
		dbus_message_iter_close_container(&entry, &variant);
		dbus_message_iter_close_container(dict, &entry);
		break;

	case CS_MODE_TWO:
		mode_key = "modeTwoData";
		dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
						 NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
					       &mode_key);
		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
						 "a{sv}", &variant);
		dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						 "{sv}", &inner);
		append_mode_two(&inner,
				&step->step_mode_data.mode_two_data,
				num_ant_paths);
		dbus_message_iter_close_container(&variant, &inner);
		dbus_message_iter_close_container(&entry, &variant);
		dbus_message_iter_close_container(dict, &entry);
		break;

	case CS_MODE_THREE:
		mode_key = "modeThreeData";
		dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
						 NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
					       &mode_key);
		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
						 "a{sv}", &variant);
		dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						 "{sv}", &inner);
		append_mode_one(&inner,
			&step->step_mode_data.mode_three_data.mode_one_data);
		append_mode_two(&inner,
			&step->step_mode_data.mode_three_data.mode_two_data,
			num_ant_paths);
		dbus_message_iter_close_container(&variant, &inner);
		dbus_message_iter_close_container(&entry, &variant);
		dbus_message_iter_close_container(dict, &entry);
		break;

	default:
		break;
	}
}

static void append_subevent_to_dict(DBusMessageIter *dict,
				const struct cs_subevent_result_data *sub)
{
	DBusMessageIter entry, variant, arr;
	const char *key;
	uint32_t i;

	dict_append_int32(dict, "startAclConnEvtCounter",
			  (dbus_int32_t)sub->start_acl_conn_evt_counter);
	dict_append_int32(dict, "freqComp", (dbus_int32_t)sub->freq_comp);
	dict_append_byte(dict, "refPwrLvl", (uint8_t)sub->ref_pwr_lvl);
	dict_append_byte(dict, "numAntPaths", sub->num_ant_paths);
	dict_append_byte(dict, "subeventAbortReason",
			 sub->subevent_abort_reason);
	dict_append_uint64(dict, "timestampNanos", sub->timestamp_nanos);
	dict_append_uint32(dict, "numSteps", sub->num_steps);

	/* stepData: av (each element is a{sv}) */
	key = "stepData";
	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
					 &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "av",
					 &variant);
	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "v", &arr);
	if (sub->step_data) {
		for (i = 0; i < sub->num_steps; i++) {
			DBusMessageIter inner, step_dict;

			dbus_message_iter_open_container(&arr,
					DBUS_TYPE_VARIANT, "a{sv}", &inner);
			dbus_message_iter_open_container(&inner,
					DBUS_TYPE_ARRAY, "{sv}", &step_dict);
			append_step_to_dict(&step_dict, &sub->step_data[i],
					    sub->num_ant_paths);
			dbus_message_iter_close_container(&inner, &step_dict);
			dbus_message_iter_close_container(&arr, &inner);
		}
	}
	dbus_message_iter_close_container(&variant, &arr);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(dict, &entry);
}

static void append_subevent_array(DBusMessageIter *outer_dict,
				const char *key,
				const struct cs_subevent_result_data *subevents,
				uint32_t count)
{
	DBusMessageIter entry, variant, arr;
	uint32_t i;

	dbus_message_iter_open_container(outer_dict, DBUS_TYPE_DICT_ENTRY,
					 NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "av",
					 &variant);
	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "v", &arr);
	for (i = 0; i < count; i++) {
		DBusMessageIter inner, sub_dict;

		dbus_message_iter_open_container(&arr, DBUS_TYPE_VARIANT,
						 "a{sv}", &inner);
		dbus_message_iter_open_container(&inner, DBUS_TYPE_ARRAY,
						 "{sv}", &sub_dict);
		append_subevent_to_dict(&sub_dict, &subevents[i]);
		dbus_message_iter_close_container(&inner, &sub_dict);
		dbus_message_iter_close_container(&arr, &inner);
	}
	dbus_message_iter_close_container(&variant, &arr);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(outer_dict, &entry);
}

static void rap_emit_procedure_data(struct rap_data *data,
				const struct bcs_procedure_data *bcs)
{
	DBusMessage *signal;
	DBusMessageIter iter, dict;

	signal = dbus_message_new_signal(device_get_path(data->device),
					 CS_INTERFACE, "ProcedureData");
	if (!signal) {
		error("Failed to allocate ProcedureData signal");
		return;
	}

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

	dict_append_int32(&dict, "procedureCounter",
			  (dbus_int32_t)bcs->procedure_counter);
	dict_append_int32(&dict, "procedureSequence",
			  (dbus_int32_t)bcs->procedure_sequence);
	dict_append_byte(&dict, "initiatorSelectedTxPower",
			 (uint8_t)bcs->initiator_selected_tx_power);
	dict_append_byte(&dict, "reflectorSelectedTxPower",
			 (uint8_t)bcs->reflector_selected_tx_power);

	dict_append_uint32(&dict, "initiatorSubeventCount",
			   bcs->initiator_subevent_count);
	if (bcs->initiator_subevent_results &&
					bcs->initiator_subevent_count > 0)
		append_subevent_array(&dict, "initiatorSubeventResults",
				      bcs->initiator_subevent_results,
				      bcs->initiator_subevent_count);

	dict_append_byte(&dict, "initiatorProcedureAbortReason",
			 bcs->initiator_procedure_abort_reason);

	dict_append_uint32(&dict, "reflectorSubeventCount",
			   bcs->reflector_subevent_count);
	if (bcs->reflector_subevent_results &&
					bcs->reflector_subevent_count > 0)
		append_subevent_array(&dict, "reflectorSubeventResults",
				      bcs->reflector_subevent_results,
				      bcs->reflector_subevent_count);

	dict_append_byte(&dict, "reflectorProcedureAbortReason",
			 bcs->reflector_procedure_abort_reason);

	append_proc_enable_config(&dict, &bcs->proc_enable_config);
	append_cs_config_param(&dict, bcs);

	dbus_message_iter_close_container(&iter, &dict);

	g_dbus_send_message(btd_get_dbus_connection(), signal);
}

static void rap_procedure_data(struct bt_rap *rap,
				struct bcs_procedure_data *bcs,
				void *user_data)
{
	struct rap_data *data = user_data;

	DBG("procedure_counter=%u", bcs->procedure_counter);
	rap_emit_procedure_data(data, bcs);
}

static DBusMessage *start_measurement(DBusConnection *conn,
				DBusMessage *msg, void *user_data)
{
	struct rap_data *data = user_data;
	struct bt_rap_le_cs_config cfg = { 0 };
	struct bt_rap_le_cs_frequency freq = { 0 };
	struct bt_rap_le_cs_default_settings settings = { 0 };
	uint32_t duration_secs = 0;
	DBusMessageIter iter = { 0 }, dict = { 0 };
	DBusMessageIter entry = { 0 }, variant = { 0 };
	const char *key = NULL;
	int vtype = 0;
	const struct cs_dict_param_desc *desc = NULL;
	void *base = NULL;

	if (data->active_session.active)
		return g_dbus_create_error(msg,
					"org.bluez.Error.InProgress",
					"Measurement already active");

	/* Seed locals from current state-machine defaults */
	bt_rap_get_cs_config_params(data->hci_sm, &cfg);
	bt_rap_get_cs_freq_params(data->hci_sm, &freq);
	bt_rap_get_default_settings_params(data->hci_sm, &settings);

	dbus_message_iter_init(msg, &iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
					   "Expected a{sv} dictionary");

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &variant);
		vtype = dbus_message_iter_get_arg_type(&variant);

		if (strcmp(key, "duration_secs") == 0) {
			if (vtype != DBUS_TYPE_UINT32)
				goto bad_type;
			dbus_message_iter_get_basic(&variant, &duration_secs);
		} else if (strcmp(key, "max_tx_power") == 0) {
			uint8_t bval = 0;

			if (vtype != DBUS_TYPE_BYTE)
				goto bad_type;
			dbus_message_iter_get_basic(&variant, &bval);
			settings.max_tx_power = (int8_t)bval;
		} else if (strcmp(key, "channel_map") == 0) {
			DBusMessageIter array = { 0 };
			uint8_t *bytes = NULL;
			int len = 0;

			if (vtype != DBUS_TYPE_ARRAY)
				goto bad_type;
			dbus_message_iter_recurse(&variant, &array);
			dbus_message_iter_get_fixed_array(&array, &bytes, &len);
			if (len != 10)
				return g_dbus_create_error(msg,
						DBUS_ERROR_INVALID_ARGS,
						"channel_map must be 10 bytes");
			memcpy(cfg.channel_map, bytes, 10);
		} else if (strcmp(key, "min_sub_event_len") == 0 ||
			   strcmp(key, "max_sub_event_len") == 0) {
			DBusMessageIter array = { 0 };
			uint8_t *bytes = NULL;
			int len = 0;

			if (vtype != DBUS_TYPE_ARRAY)
				goto bad_type;
			dbus_message_iter_recurse(&variant, &array);
			dbus_message_iter_get_fixed_array(&array, &bytes, &len);
			if (len != 3)
				return g_dbus_create_error(msg,
						DBUS_ERROR_INVALID_ARGS,
						"sub_event_len must be 3 bytes");
			if (strcmp(key, "min_sub_event_len") == 0)
				memcpy(freq.min_sub_event_len, bytes, 3);
			else
				memcpy(freq.max_sub_event_len, bytes, 3);
		} else {
			desc = cs_find_dict_param_desc(key);
			if (!desc)
				goto bad_type;

			if (vtype != desc->vtype)
				goto bad_type;

			switch (desc->target) {
			case CS_TARGET_CFG:
				base = &cfg;
				break;
			case CS_TARGET_FREQ:
				base = &freq;
				break;
			case CS_TARGET_SETTINGS:
				base = &settings;
				break;
			default:
				base = &settings;
				break;
			}

			if (desc->vtype == DBUS_TYPE_UINT16)
				dbus_message_iter_get_basic(&variant,
					(uint16_t *)((uint8_t *)base +
								desc->offset));
			else
				dbus_message_iter_get_basic(&variant,
					(uint8_t *)base + desc->offset);
		}

		dbus_message_iter_next(&dict);
		continue;
bad_type:
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
					   "Unexpected variant type for key");
	}

	if (data->conn_handle == 0)
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
					   "Device not connected");

	if (!bt_rap_set_default_settings_params(data->hci_sm, &settings))
		return g_dbus_create_error(msg, DBUS_ERROR_FAILED,
					   "Set default settings failed");

	if (!bt_rap_set_cs_config_params(data->hci_sm, &cfg))
		return g_dbus_create_error(msg, DBUS_ERROR_FAILED,
					   "Set CS config params failed");

	if (!bt_rap_set_cs_freq_params(data->hci_sm, &freq))
		return g_dbus_create_error(msg, DBUS_ERROR_FAILED,
					   "Set CS freq params failed");

	/* Reflector never initiates a CS procedure locally: apply the
	 * settings so the controller is ready to respond to the remote
	 * Initiator, but do not arm a local measurement session.
	 */
	if (settings.role == 0x02)
		return dbus_message_new_method_return(msg);

	if (!bt_rap_start_measurement(data->hci_sm, data->conn_handle,
							duration_secs))
		return g_dbus_create_error(msg, DBUS_ERROR_FAILED,
					   "Start measurement failed");

	data->active_session.active        = true;
	data->active_session.duration_secs = duration_secs;
	data->active_session.settings      = settings;
	data->active_session.cfg           = cfg;
	data->active_session.freq          = freq;

	bt_rap_hci_set_procedure_data_cb(data->hci_sm, rap_procedure_data,
					 data, NULL);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *stop_measurement(DBusConnection *conn,
				DBusMessage *msg, void *user_data)
{
	struct rap_data *data = user_data;

	if (!data->active_session.active)
		return g_dbus_create_error(msg,
					"org.bluez.Error.NotConnected",
					"No active measurement");

	if (!bt_rap_stop_measurement(data->hci_sm))
		return g_dbus_create_error(msg, DBUS_ERROR_FAILED,
					"Stop measurement failed");

	memset(&data->active_session, 0, sizeof(data->active_session));

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
				device_get_path(data->device),
				CS_INTERFACE, "Active");

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable cs_dbus_methods[] = {
	{ GDBUS_METHOD("StartMeasurement",
			GDBUS_ARGS({ "params", "a{sv}" }),
			NULL,
			start_measurement) },
	{ GDBUS_METHOD("StopMeasurement",
			NULL,
			NULL,
			stop_measurement) },
	{ }
};

static gboolean cs_property_get_active(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct rap_data *data = user_data;
	dbus_bool_t active = data->active_session.active ||
				bt_rap_is_procedure_active(data->hci_sm);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &active);
	return TRUE;
}

static const GDBusPropertyTable cs_dbus_properties[] = {
	{ "Active", "b", cs_property_get_active, NULL, NULL, 0 },
	{ }
};

static const GDBusSignalTable cs_dbus_signals[] = {
	{ GDBUS_SIGNAL("ProcedureData", GDBUS_ARGS({ "data", "a{sv}" })) },
	{ }
};

static void rap_measurement_timeout_cb(void *user_data)
{
	struct rap_data *data = user_data;

	memset(&data->active_session, 0, sizeof(data->active_session));

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
				device_get_path(data->device),
				CS_INTERFACE, "Active");
}

static void rap_proc_active_changed(bool active, void *user_data)
{
	struct rap_data *data = user_data;

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
				device_get_path(data->device),
				CS_INTERFACE, "Active");
}

static int rap_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct btd_adapter *adapter = device_get_adapter(device);
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct rap_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	/* Ignore, if we probed for this device already */
	if (data) {
		error("Profile probed twice for this device");
		return -EINVAL;
	}

	data = rap_data_new(device);
	data->service = service;

	data->rap = bt_rap_new(btd_gatt_database_get_db(database),
				btd_device_get_gatt_db(device));

	if (!data->rap) {
		error("unable to create RAP instance");
		free(data);
		return -EINVAL;
	}

	rap_data_add(data);

	data->ready_id = bt_rap_ready_register(data->rap, rap_ready, service,
								NULL);

	bt_rap_set_user_data(data->rap, service);

	return 0;
}

static void rap_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct rap_data *data;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	data = btd_service_get_user_data(service);
	if (!data) {
		error("RAP Service not handled by profile");
		return;
	}

	g_dbus_unregister_interface(btd_get_dbus_connection(),
				    device_get_path(device),
				    CS_INTERFACE);

	rap_data_remove(data);
}

static int rap_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct btd_adapter *adapter = device_get_adapter(device);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct rap_data *data = btd_service_get_user_data(service);
	struct bt_att *att;
	const bdaddr_t *bdaddr;
	uint8_t bdaddr_type;
	uint16_t handle;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	if (!data) {
		error("RAP Service not handled by profile");
		return -EINVAL;
	}

	/* init shared adapter HCI channel */
	if (!data->adapter_data) {
		data->adapter_data = rap_adapter_data_ref(adapter);
		if (!data->adapter_data) {
			error("Failed to get adapter HCI channel");
			return -EINVAL;
		}
		DBG("Using shared HCI channel for adapter (ref_count=%d)",
			data->adapter_data->ref_count);
	}

	/* per-device HCI state machine */
	if (!data->hci_sm) {
		data->hci_sm = bt_rap_attach_hci(data->rap,
					data->adapter_data->hci,
					btd_opts.defaults.bcs.role,
					btd_opts.defaults.bcs.cs_sync_ant_sel,
					btd_opts.defaults.bcs.max_tx_power);
		if (!data->hci_sm) {
			error("Failed to attach HCI state machine for device");
			rap_adapter_data_unref(data->adapter_data);
			data->adapter_data = NULL;
			return -EINVAL;
		}
		DBG("HCI state machine attached successfully for device");

		bt_rap_set_timeout_cb(data->hci_sm, rap_measurement_timeout_cb,
					data);
		bt_rap_set_proc_active_cb(data->hci_sm, rap_proc_active_changed,
					data);
	}

	if (!bt_rap_attach(data->rap, client)) {
		error("RAP unable to attach");
		return -EINVAL;
	}

	/* Set up connection handle mapping for CS event routing */
	att = bt_rap_get_att(data->rap);
	bdaddr = device_get_address(device);
	bdaddr_type = device_get_le_address_type(device);

	if (att && data->adapter_data->hci && data->hci_sm) {
		if (bt_hci_get_conn_handle(data->adapter_data->hci,
					(const uint8_t *) bdaddr, &handle)) {
			DBG("Found conn handle 0x%04X for %s", handle, addr);
			data->conn_handle = handle;
			bt_rap_set_conn_hndl(data->hci_sm,
					data->rap, handle,
					(const uint8_t *) bdaddr,
					bdaddr_type,
					btd_device_is_initiator(device));
		} else {
			error("Failed to find connection handle for device %s",
				addr);
		}
	}

	btd_service_connecting_complete(service, 0);

	g_dbus_register_interface(btd_get_dbus_connection(),
				  device_get_path(data->device),
				  CS_INTERFACE, cs_dbus_methods,
				  cs_dbus_signals, cs_dbus_properties,
				  data, NULL);

	return 0;
}

static int rap_disconnect(struct btd_service *service)
{
	struct rap_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(btd_service_get_device(service)), addr);
	DBG("%s", addr);
	if (!data) {
		error("RAP Service not handled by profile");
		return -EINVAL;
	}

	if (data && data->hci_sm && data->conn_handle) {
		bt_rap_clear_conn_handle(data->hci_sm, data->conn_handle);
		data->conn_handle = 0;
	}

	memset(&data->active_session, 0, sizeof(data->active_session));

	btd_service_disconnecting_complete(service, 0);
	return 0;
}

static int rap_connect(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	return 0;
}

static int rap_server_probe(struct btd_profile *p,
				  struct btd_adapter *adapter)
{

	struct btd_gatt_database *database = btd_adapter_get_database(adapter);

	DBG("RAP path %s", adapter_get_path(adapter));

	bt_rap_add_db(btd_gatt_database_get_db(database));

	return 0;
}

static void rap_server_remove(struct btd_profile *p,
					struct btd_adapter *adapter)
{
	DBG("");
}

static struct btd_profile rap_profile = {
	.name		= "rap",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.remote_uuid	= GATT_UUID,
	.local_uuid	= RAS_UUID,

	.device_probe	= rap_probe,
	.device_remove	= rap_remove,

	.accept		= rap_accept,
	.connect	= rap_connect,
	.disconnect	= rap_disconnect,

	.adapter_probe = rap_server_probe,
	.adapter_remove = rap_server_remove,

	.experimental	= true,
};

static unsigned int rap_id;

static int rap_init(void)
{
	int err;

	err = btd_profile_register(&rap_profile);
	if (err)
		return err;

	rap_id = bt_rap_register(rap_attached, rap_detached, NULL);

	return 0;
}

static void rap_exit(void)
{
	btd_profile_unregister(&rap_profile);
	bt_rap_unregister(rap_id);
}

BLUETOOTH_PLUGIN_DEFINE(rap, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			rap_init, rap_exit)
