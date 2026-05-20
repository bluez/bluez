// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/uio.h>

#include "bluetooth/bluetooth.h"
#include "src/shared/util.h"
#include "src/shared/rap.h"
#include "src/shared/bcs_util.h"

static void step_data_free_inner(cs_step_data *steps, int64_t count)
{
	int64_t i;
	cs_mode_two_data *m2;

	if (!steps)
		return;

	for (i = 0; i < count; i++) {
		uint8_t mode = steps[i].step_mode & 0x03;

		if (mode == 0x02) /* CS_MODE_TWO */
			m2 = &steps[i].step_mode_data.mode_two_data;
		else if (mode == 0x03) /* CS_MODE_THREE */
			m2 = &steps[i].step_mode_data.mode_three_data.mode_two_data;
		else
			continue;

		free(m2->tone_pct_iq_samples);
		m2->tone_pct_iq_samples = NULL;
		free(m2->tone_quality_indicators);
		m2->tone_quality_indicators = NULL;
	}
}

static void copy_cs_step_mode_zero_data(cs_mode_zero_data *dst,
					const cs_mode_zero_data *src)
{
	struct iovec temp_iov = { 0 };
	struct iovec pull_iov;
	uint32_t tmp32;

	temp_iov.iov_base = malloc(16);
	if (!temp_iov.iov_base)
		return;
	temp_iov.iov_len = 0;

	if (!util_iov_push_u8(&temp_iov, (uint8_t)src->packet_quality)  ||
	    !util_iov_push_u8(&temp_iov, (uint8_t)src->packet_rssi_dbm) ||
	    !util_iov_push_u8(&temp_iov, (uint8_t)src->packet_antenna)  ||
	    !util_iov_push_le32(&temp_iov,
				(uint32_t)src->initiator_measured_freq_offset))
		goto done;

	pull_iov.iov_base = temp_iov.iov_base;
	pull_iov.iov_len  = temp_iov.iov_len;

	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->packet_quality);
	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->packet_rssi_dbm);
	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->packet_antenna);
	if (util_iov_pull_le32(&pull_iov, &tmp32))
		dst->initiator_measured_freq_offset = (int32_t)tmp32;

done:
	free(temp_iov.iov_base);
}

static void copy_cs_step_mode_one_data(cs_mode_one_data *dst,
				       const cs_mode_one_data *src)
{
	struct iovec temp_iov = { 0 };
	struct iovec pull_iov;
	uint32_t tmp32;

	temp_iov.iov_base = malloc(64);
	if (!temp_iov.iov_base)
		return;
	temp_iov.iov_len = 0;

	if (!util_iov_push_u8(&temp_iov, (uint8_t)src->packet_quality)  ||
	    !util_iov_push_u8(&temp_iov, (uint8_t)src->packet_nadm)      ||
	    !util_iov_push_u8(&temp_iov, (uint8_t)src->packet_rssi_dbm)  ||
	    !util_iov_push_le32(&temp_iov,
				(uint32_t)src->rtt_toa_tod_data.toa_tod_initiator) ||
	    !util_iov_push_u8(&temp_iov, (uint8_t)src->packet_antenna)   ||
	    !util_iov_push_le32(&temp_iov, (uint32_t)src->packet_pct1.i_sample) ||
	    !util_iov_push_le32(&temp_iov, (uint32_t)src->packet_pct1.q_sample) ||
	    !util_iov_push_le32(&temp_iov, (uint32_t)src->packet_pct2.i_sample) ||
	    !util_iov_push_le32(&temp_iov, (uint32_t)src->packet_pct2.q_sample))
		goto done;

	pull_iov.iov_base = temp_iov.iov_base;
	pull_iov.iov_len  = temp_iov.iov_len;

	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->packet_quality);
	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->packet_nadm);
	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->packet_rssi_dbm);
	if (util_iov_pull_le32(&pull_iov, &tmp32))
		dst->rtt_toa_tod_data.toa_tod_initiator = (int32_t)tmp32;
	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->packet_antenna);
	if (util_iov_pull_le32(&pull_iov, &tmp32))
		dst->packet_pct1.i_sample = (int32_t)tmp32;
	if (util_iov_pull_le32(&pull_iov, &tmp32))
		dst->packet_pct1.q_sample = (int32_t)tmp32;
	if (util_iov_pull_le32(&pull_iov, &tmp32))
		dst->packet_pct2.i_sample = (int32_t)tmp32;
	if (util_iov_pull_le32(&pull_iov, &tmp32))
		dst->packet_pct2.q_sample = (int32_t)tmp32;

done:
	free(temp_iov.iov_base);
}

static void copy_cs_step_mode_two_data(cs_mode_two_data *dst,
				       const cs_mode_two_data *src)
{
	struct iovec temp_iov = { 0 };
	struct iovec pull_iov;
	uint32_t tmp32;

	temp_iov.iov_base = malloc(16);
	if (!temp_iov.iov_base)
		return;
	temp_iov.iov_len = 0;

	if (!util_iov_push_u8(&temp_iov,
			      (uint8_t)src->antenna_permutation_index) ||
	    !util_iov_push_le32(&temp_iov,
				(uint32_t)src->tone_pct_iq_sample_size)    ||
	    !util_iov_push_le32(&temp_iov,
				(uint32_t)src->tone_quality_indicators_size))
		goto done;

	pull_iov.iov_base = temp_iov.iov_base;
	pull_iov.iov_len  = temp_iov.iov_len;

	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->antenna_permutation_index);
	if (util_iov_pull_le32(&pull_iov, &tmp32))
		dst->tone_pct_iq_sample_size = (int32_t)tmp32;
	if (util_iov_pull_le32(&pull_iov, &tmp32))
		dst->tone_quality_indicators_size = (int32_t)tmp32;

	if (src->tone_pct_iq_samples && dst->tone_pct_iq_sample_size > 0) {
		dst->tone_pct_iq_samples = calloc(dst->tone_pct_iq_sample_size,
						  sizeof(cs_pct_iq_sample));
		if (dst->tone_pct_iq_samples)
			memcpy(dst->tone_pct_iq_samples, src->tone_pct_iq_samples,
			       dst->tone_pct_iq_sample_size *
			       sizeof(cs_pct_iq_sample));
	}

	if (src->tone_quality_indicators && dst->tone_quality_indicators_size > 0) {
		dst->tone_quality_indicators =
			calloc(dst->tone_quality_indicators_size, 1);
		if (dst->tone_quality_indicators)
			memcpy(dst->tone_quality_indicators,
			       src->tone_quality_indicators,
			       dst->tone_quality_indicators_size);
	}

done:
	free(temp_iov.iov_base);
}

static void copy_cs_step_mode_three_data(cs_mode_three_data *dst,
					 const cs_mode_three_data *src)
{
	copy_cs_step_mode_one_data(&dst->mode_one_data, &src->mode_one_data);
	copy_cs_step_mode_two_data(&dst->mode_two_data, &src->mode_two_data);
}

static void copy_cs_step_data(cs_step_data *dst, const cs_step_data *src)
{
	dst->step_channel = src->step_channel;
	dst->step_mode    = src->step_mode;

	switch (src->step_mode & 0x03) {
	case CS_MODE_ZERO:
		copy_cs_step_mode_zero_data(&dst->step_mode_data.mode_zero_data,
					    &src->step_mode_data.mode_zero_data);
		break;
	case CS_MODE_ONE:
		copy_cs_step_mode_one_data(&dst->step_mode_data.mode_one_data,
					   &src->step_mode_data.mode_one_data);
		break;
	case CS_MODE_TWO:
		copy_cs_step_mode_two_data(&dst->step_mode_data.mode_two_data,
					   &src->step_mode_data.mode_two_data);
		break;
	case CS_MODE_THREE:
		copy_cs_step_mode_three_data(
					&dst->step_mode_data.mode_three_data,
					&src->step_mode_data.mode_three_data);
		break;
	default:
		break;
	}
}

cs_subevent_result_data *bcs_subevent_result_data_new(
				int32_t start_acl_conn_event_counter,
				int32_t frequency_compensation,
				int8_t reference_power_level_dbm,
				int8_t num_antenna_paths,
				int8_t subevent_abort_reason,
				int64_t timestamp_nanos,
				const cs_step_data *steps,
				int64_t num_steps)
{
	cs_subevent_result_data *subevent;

	subevent = calloc(1, sizeof(*subevent));
	if (!subevent)
		return NULL;

	subevent->start_acl_conn_event_counter = start_acl_conn_event_counter;
	subevent->frequency_compensation       = frequency_compensation;
	subevent->reference_power_level_dbm    = reference_power_level_dbm;
	subevent->num_antenna_paths            = num_antenna_paths;
	subevent->subevent_abort_reason        = subevent_abort_reason;
	subevent->timestamp_nanos              = timestamp_nanos;

	if (steps && num_steps > 0) {
		int64_t i;

		subevent->step_data = calloc(num_steps, sizeof(cs_step_data));
		if (!subevent->step_data) {
			free(subevent);
			return NULL;
		}
		for (i = 0; i < num_steps; i++)
			copy_cs_step_data(&subevent->step_data[i], &steps[i]);
		subevent->step_data_size = num_steps;
	}

	return subevent;
}

void bcs_subevent_result_data_free(cs_subevent_result_data *subevent)
{
	if (!subevent)
		return;

	step_data_free_inner(subevent->step_data, subevent->step_data_size);
	free(subevent->step_data);
	free(subevent);
}

bcs_procedure_data *bcs_procedure_data_new(void)
{
	return calloc(1, sizeof(bcs_procedure_data));
}

void bcs_procedure_data_free(bcs_procedure_data *proc)
{
	int32_t i;

	if (!proc)
		return;

	for (i = 0; i < proc->initiator_subevent_result_data_size; i++) {
		step_data_free_inner(
			proc->initiator_subevent_result_data[i].step_data,
			proc->initiator_subevent_result_data[i].step_data_size);
		free(proc->initiator_subevent_result_data[i].step_data);
	}
	free(proc->initiator_subevent_result_data);

	for (i = 0; i < proc->reflector_subevent_result_data_size; i++) {
		step_data_free_inner(
			proc->reflector_subevent_result_data[i].step_data,
			proc->reflector_subevent_result_data[i].step_data_size);
		free(proc->reflector_subevent_result_data[i].step_data);
	}
	free(proc->reflector_subevent_result_data);

	free(proc);
}

void bcs_procedure_data_clear(bcs_procedure_data *proc)
{
	int32_t i;

	if (!proc)
		return;

	for (i = 0; i < proc->initiator_subevent_result_data_size; i++) {
		step_data_free_inner(
			proc->initiator_subevent_result_data[i].step_data,
			proc->initiator_subevent_result_data[i].step_data_size);
		free(proc->initiator_subevent_result_data[i].step_data);
	}
	free(proc->initiator_subevent_result_data);
	proc->initiator_subevent_result_data      = NULL;
	proc->initiator_subevent_result_data_size = 0;

	for (i = 0; i < proc->reflector_subevent_result_data_size; i++) {
		step_data_free_inner(
			proc->reflector_subevent_result_data[i].step_data,
			proc->reflector_subevent_result_data[i].step_data_size);
		free(proc->reflector_subevent_result_data[i].step_data);
	}
	free(proc->reflector_subevent_result_data);
	proc->reflector_subevent_result_data      = NULL;
	proc->reflector_subevent_result_data_size = 0;
}

bool bcs_procedure_data_add_initiator_subevent(bcs_procedure_data *proc,
					cs_subevent_result_data *subevent)
{
	cs_subevent_result_data *arr;
	int32_t new_count;

	if (!proc || !subevent)
		return false;

	new_count = proc->initiator_subevent_result_data_size + 1;
	arr = realloc(proc->initiator_subevent_result_data,
					new_count * sizeof(*arr));
	if (!arr)
		return false;

	arr[new_count - 1].start_acl_conn_event_counter =
					subevent->start_acl_conn_event_counter;
	arr[new_count - 1].frequency_compensation  = subevent->frequency_compensation;
	arr[new_count - 1].reference_power_level_dbm = subevent->reference_power_level_dbm;
	arr[new_count - 1].num_antenna_paths       = subevent->num_antenna_paths;
	arr[new_count - 1].subevent_abort_reason   = subevent->subevent_abort_reason;
	arr[new_count - 1].step_data_size          = subevent->step_data_size;
	arr[new_count - 1].step_data               = subevent->step_data;
	arr[new_count - 1].timestamp_nanos         = subevent->timestamp_nanos;
	free(subevent);

	proc->initiator_subevent_result_data      = arr;
	proc->initiator_subevent_result_data_size = new_count;

	return true;
}

bool bcs_procedure_data_add_reflector_subevent(bcs_procedure_data *proc,
					cs_subevent_result_data *subevent)
{
	cs_subevent_result_data *arr;
	int32_t new_count;

	if (!proc || !subevent)
		return false;

	new_count = proc->reflector_subevent_result_data_size + 1;
	arr = realloc(proc->reflector_subevent_result_data,
					new_count * sizeof(*arr));
	if (!arr)
		return false;

	arr[new_count - 1].start_acl_conn_event_counter =
					subevent->start_acl_conn_event_counter;
	arr[new_count - 1].frequency_compensation  = subevent->frequency_compensation;
	arr[new_count - 1].reference_power_level_dbm = subevent->reference_power_level_dbm;
	arr[new_count - 1].num_antenna_paths       = subevent->num_antenna_paths;
	arr[new_count - 1].subevent_abort_reason   = subevent->subevent_abort_reason;
	arr[new_count - 1].step_data_size          = subevent->step_data_size;
	arr[new_count - 1].step_data               = subevent->step_data;
	arr[new_count - 1].timestamp_nanos         = subevent->timestamp_nanos;
	free(subevent);

	proc->reflector_subevent_result_data      = arr;
	proc->reflector_subevent_result_data_size = new_count;

	return true;
}

void bcs_procedure_data_set_config(bcs_procedure_data *proc,
					const cs_config_param *config)
{
	if (!proc || !config)
		return;

	proc->cs_config_param = *config;
}

void bcs_procedure_data_set_procedure_config(bcs_procedure_data *proc,
					const cs_procedure_enable_config *config)
{
	if (!proc || !config)
		return;

	proc->procedure_enable_config = *config;
}

static void hci_step_to_bcs_mode0_step(const struct cs_mode_zero_data *src,
					cs_mode_zero_data *dst)
{
	struct iovec temp_iov = { 0 };
	struct iovec pull_iov;
	uint32_t tmp32;

	temp_iov.iov_base = malloc(16);
	if (!temp_iov.iov_base)
		return;
	temp_iov.iov_len = 0;

	if (!util_iov_push_u8(&temp_iov, src->packet_quality) ||
	    !util_iov_push_u8(&temp_iov, src->packet_rssi_dbm) ||
	    !util_iov_push_u8(&temp_iov, src->packet_ant) ||
	    !util_iov_push_le32(&temp_iov, src->init_measured_freq_offset))
		goto done;

	pull_iov.iov_base = temp_iov.iov_base;
	pull_iov.iov_len  = temp_iov.iov_len;

	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->packet_quality);
	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->packet_rssi_dbm);
	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->packet_antenna);
	if (util_iov_pull_le32(&pull_iov, &tmp32))
		dst->initiator_measured_freq_offset = (int32_t)tmp32;

done:
	free(temp_iov.iov_base);
}

static void hci_step_to_bcs_mode1_step(const struct cs_mode_one_data *src,
					cs_mode_one_data *dst,
					uint8_t rtt_type)
{
	struct iovec temp_iov = { 0 };
	struct iovec pull_iov;
	uint16_t tmp16;
	bool include_pct = (rtt_type != 0x00);

	temp_iov.iov_base = malloc(64);
	if (!temp_iov.iov_base)
		return;
	temp_iov.iov_len = 0;

	if (!util_iov_push_u8(&temp_iov, src->packet_quality) ||
	    !util_iov_push_u8(&temp_iov, src->packet_nadm)     ||
	    !util_iov_push_u8(&temp_iov, src->packet_rssi_dbm) ||
	    !util_iov_push_le16(&temp_iov, (uint16_t)src->toa_tod_init) ||
	    !util_iov_push_u8(&temp_iov, src->packet_ant))
		goto done;

	if (include_pct) {
		if (!util_iov_push_le16(&temp_iov,
					(uint16_t)src->packet_pct1.i_sample) ||
		    !util_iov_push_le16(&temp_iov,
					(uint16_t)src->packet_pct1.q_sample) ||
		    !util_iov_push_le16(&temp_iov,
					(uint16_t)src->packet_pct2.i_sample) ||
		    !util_iov_push_le16(&temp_iov,
					(uint16_t)src->packet_pct2.q_sample))
			goto done;
	}

	pull_iov.iov_base = temp_iov.iov_base;
	pull_iov.iov_len  = temp_iov.iov_len;

	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->packet_quality);
	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->packet_nadm);
	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->packet_rssi_dbm);

	if (util_iov_pull_le16(&pull_iov, &tmp16))
		dst->rtt_toa_tod_data.toa_tod_initiator = (int16_t)tmp16;

	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->packet_antenna);

	if (include_pct) {
		if (util_iov_pull_le16(&pull_iov, &tmp16))
			dst->packet_pct1.i_sample = (int16_t)tmp16;
		if (util_iov_pull_le16(&pull_iov, &tmp16))
			dst->packet_pct1.q_sample = (int16_t)tmp16;
		if (util_iov_pull_le16(&pull_iov, &tmp16))
			dst->packet_pct2.i_sample = (int16_t)tmp16;
		if (util_iov_pull_le16(&pull_iov, &tmp16))
			dst->packet_pct2.q_sample = (int16_t)tmp16;
	}

done:
	free(temp_iov.iov_base);
}

static void hci_step_to_bcs_mode2_step(const struct cs_mode_two_data *src,
					cs_mode_two_data *dst,
					uint8_t num_antenna_paths)
{
	struct iovec temp_iov = { 0 };
	struct iovec pull_iov;
	uint16_t tmp16;
	int k;
	uint8_t num_paths = (num_antenna_paths + 1) < 5 ?
		(num_antenna_paths + 1) : 5;

	temp_iov.iov_base = malloc(128);
	if (!temp_iov.iov_base)
		return;
	temp_iov.iov_len = 0;

	if (!util_iov_push_u8(&temp_iov, src->ant_perm_index))
		goto done;

	for (k = 0; k < num_paths; k++) {
		if (!util_iov_push_le16(&temp_iov,
					(uint16_t)src->tone_pct[k].i_sample) ||
		    !util_iov_push_le16(&temp_iov,
					(uint16_t)src->tone_pct[k].q_sample) ||
		    !util_iov_push_u8(&temp_iov, src->tone_quality_indicator[k]))
			goto done;
	}

	pull_iov.iov_base = temp_iov.iov_base;
	pull_iov.iov_len  = temp_iov.iov_len;

	util_iov_pull_u8(&pull_iov, (uint8_t *)&dst->antenna_permutation_index);

	dst->tone_pct_iq_samples =
		calloc(num_paths, sizeof(cs_pct_iq_sample));
	dst->tone_quality_indicators = calloc(num_paths, 1);

	if (dst->tone_pct_iq_samples && dst->tone_quality_indicators) {
		for (k = 0; k < num_paths; k++) {
			if (util_iov_pull_le16(&pull_iov, &tmp16))
				dst->tone_pct_iq_samples[k].i_sample =
					(int16_t)tmp16;
			if (util_iov_pull_le16(&pull_iov, &tmp16))
				dst->tone_pct_iq_samples[k].q_sample =
					(int16_t)tmp16;
			util_iov_pull_u8(&pull_iov,
					 &dst->tone_quality_indicators[k]);
		}
		dst->tone_pct_iq_sample_size      = num_paths;
		dst->tone_quality_indicators_size = num_paths;
	}

done:
	free(temp_iov.iov_base);
}

static void hci_step_to_bcs_mode3_step(const struct cs_mode_three_data *src,
					cs_mode_three_data *dst,
					uint8_t rtt_type,
					uint8_t num_antenna_paths)
{
	hci_step_to_bcs_mode1_step(&src->mode_one_data, &dst->mode_one_data,
				   rtt_type);
	hci_step_to_bcs_mode2_step(&src->mode_two_data, &dst->mode_two_data,
				   num_antenna_paths);
}

void hci_step_to_bcs_step(const struct cs_step_data *src,
			   cs_step_data *dst,
			   uint8_t rtt_type,
			   uint8_t num_antenna_paths)
{
	dst->step_mode    = src->step_mode;
	dst->step_channel = src->step_chnl;

	switch (src->step_mode & 0x03) {
	case CS_MODE_ZERO:
		hci_step_to_bcs_mode0_step(&src->step_mode_data.mode_zero_data,
					   &dst->step_mode_data.mode_zero_data);
		break;
	case CS_MODE_ONE:
		hci_step_to_bcs_mode1_step(&src->step_mode_data.mode_one_data,
					   &dst->step_mode_data.mode_one_data,
					   rtt_type);
		break;
	case CS_MODE_TWO:
		hci_step_to_bcs_mode2_step(&src->step_mode_data.mode_two_data,
					   &dst->step_mode_data.mode_two_data,
					   num_antenna_paths);
		break;
	case CS_MODE_THREE:
		hci_step_to_bcs_mode3_step(&src->step_mode_data.mode_three_data,
					   &dst->step_mode_data.mode_three_data,
					   rtt_type, num_antenna_paths);
		break;
	default:
		break;
	}
}
