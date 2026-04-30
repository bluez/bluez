// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/hci.h"
#include "bluetooth/uuid.h"

#include "src/shared/queue.h"
#include "src/shared/util.h"
#include "src/shared/timeout.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/gatt-client.h"
#include "src/shared/rap.h"

#define DBG(_rap, fmt, ...) \
	rap_debug(_rap, "%s:%s() " fmt, __FILE__, __func__, ##__VA_ARGS__)

#define RAS_UUID16			0x185B

/* Total number of attribute handles reserved for the RAS service */
#define RAS_TOTAL_NUM_HANDLES		18

/* 2(rc+cfg) + 1(tx_pwr) + 1(4 bits antenna_mask, 2 bits reserved,
 * 2 bits pct_format)
 */
#define RAS_RANGING_HEADER_SIZE 4
#define TOTAL_RAS_RANGING_HEADER_SIZE 5
#define ATT_OVERHEAD 3 /* 1(opcode) + 2(char handle) */
#define RAS_STEP_ABORTED_BIT   0x80/* set step aborted */
#define RAS_SUBEVENT_HEADER_SIZE 8

enum pct_format {
	IQ = 0,
	PHASE = 1,
};

enum ranging_done_status {
	RANGING_DONE_ALL_RESULTS_COMPLETE = 0x0,
	RANGING_DONE_PARTIAL_RESULTS = 0x1,
	RANGING_DONE_ABORTED = 0xF,
};

enum subevent_done_status {
	SUBEVENT_DONE_ALL_RESULTS_COMPLETE = 0x0,
	SUBEVENT_DONE_PARTIAL_RESULTS = 0x1,
	SUBEVENT_DONE_ABORTED = 0xF,
};

enum ranging_abort_reason {
	RANGING_ABORT_NO_ABORT = 0x0,
	RANGING_ABORT_LOCAL_HOST_OR_REMOTE = 0x1,
	RANGING_ABORT_INSUFFICIENT_FILTERED_CHANNELS = 0x2,
	RANGING_ABORT_INSTANT_HAS_PASSED = 0x3,
	RANGING_ABORT_UNSPECIFIED = 0xF,
};

enum subevent_abort_reason {
	SUBEVENT_ABORT_NO_ABORT = 0x0,
	SUBEVENT_ABORT_LOCAL_HOST_OR_REMOTE = 0x1,
	SUBEVENT_ABORT_NO_CS_SYNC_RECEIVED = 0x2,
	SUBEVENT_ABORT_SCHEDULING_CONFLICTS_OR_LIMITED_RESOURCES = 0x3,
	SUBEVENT_ABORT_UNSPECIFIED = 0xF,
};

/* Segmentation header: 1 byte
 * bit 0: first_segment
 * bit 1: last_segment
 * bits 2-7: rolling_segment_counter (6 bits)
 */
struct segmentation_header {
	uint8_t first_segment;
	uint8_t last_segment;
	uint8_t rolling_segment_counter;
};

/* Macros to pack/unpack segmentation header */
#define SEG_HDR_PACK(first, last, counter) \
	((uint8_t)(((first) ? 0x01 : 0x00) | \
		((last) ? 0x02 : 0x00) | \
		(((counter) & 0x3F) << 2)))

struct ranging_header {
	/* Byte 0-1: 12-bit counter + 4-bit config_id */
	uint8_t counter_config[2];
	int8_t selected_tx_power;   /* Byte 2: selected TX power */
	/* Byte 3: 4-bit antenna_mask + 2-bit reserved + 2-bit pct_format */
	uint8_t antenna_pct;
} __packed;

static inline void ranging_header_set_counter(struct ranging_header *hdr,
						uint16_t counter)
{
	/* Counter is 12 bits, stored in lower 12 bits of first 2 bytes */
	hdr->counter_config[0] = counter & 0xFF;
	hdr->counter_config[1] = (hdr->counter_config[1] & 0xF0) |
				((counter >> 8) & 0x0F);
}

static inline void ranging_header_set_config_id(struct ranging_header *hdr,
						uint8_t config_id)
{
	/* Config ID is 4 bits, stored in upper 4 bits of byte 1 */
	hdr->counter_config[1] = (hdr->counter_config[1] & 0x0F) |
				((config_id & 0x0F) << 4);
}

static inline void ranging_header_set_antenna_mask(
					struct ranging_header *hdr,
					uint8_t mask)
{
	/* Antenna mask is 4 bits, stored in lower 4 bits of byte 3 */
	hdr->antenna_pct = (hdr->antenna_pct & 0xF0) | (mask & 0x0F);
}

static inline void ranging_header_set_pct_format(struct ranging_header *hdr,
						uint8_t format)
{
	/* PCT format is 2 bits, stored in bits 6-7 of byte 3 */
	hdr->antenna_pct = (hdr->antenna_pct & 0x3F) |
				((format & 0x03) << 6);
}

struct ras_subevent_header {
	uint16_t start_acl_conn_event;
	uint16_t frequency_compensation;
	uint8_t ranging_done_status;
	uint8_t subevent_done_status;
	uint8_t ranging_abort_reason;
	uint8_t subevent_abort_reason;
	int8_t reference_power_level;
	uint8_t num_steps_reported;
};

/* Macros to pack/unpack RAS subevent header status fields */
#define RAS_DONE_STATUS_PACK(ranging, subevent) \
	((uint8_t)(((ranging) & 0x0F) | (((subevent) & 0x0F) << 4)))

#define RAS_ABORT_REASON_PACK(ranging, subevent) \
	((uint8_t)(((ranging) & 0x0F) | (((subevent) & 0x0F) << 4)))

struct ras_subevent {
	struct ras_subevent_header subevent_header;
	uint8_t subevent_data[];
};

/* Role maps to Core CS roles (initiator/reflector) */
enum cs_role {
	CS_ROLE_INITIATOR = 0x00,
	CS_ROLE_REFLECTOR = 0x01,
};

#define CS_INVALID_CONFIG_ID   0xFF
/* Minimal enums (align to controller values if needed) */
enum cs_procedure_done_status {
	CS_PROC_ALL_RESULTS_COMPLETE = 0x00,
	CS_PROC_PARTIAL_RESULTS      = 0x01,
	CS_PROC_ABORTED              = 0x02
};

/* Main cs_procedure_data  */
struct cs_procedure_data {
	/* Identity and counters */
	uint16_t counter;
	uint8_t  num_antenna_paths;
	/* Flags and status */
	enum cs_procedure_done_status local_status;
	enum cs_procedure_done_status remote_status;
	bool contains_complete_subevent_;
	/* RAS aggregation */
	struct segmentation_header segmentation_header_;
	struct ranging_header      ranging_header_;
	struct iovec       ras_raw_data_;        /* raw concatenated */
	uint16_t           ras_raw_data_index_;
	struct ras_subevent_header  ras_subevent_header_;
	struct iovec       ras_subevent_data_;   /* buffer per subevent */
	uint8_t            ras_subevent_counter_;
	/* Reference power levels */
	int8_t initiator_reference_power_level;
	int8_t reflector_reference_power_level;
	bool ranging_header_prepended_;
	bool ras_subevent_header_emitted;
};

struct cstracker {
	enum cs_role        role;                 /* INITIATOR/REFLECTOR */
	uint8_t             config_id;            /* CS_INVALID_CONFIG_ID */
	int8_t             selected_tx_power;    /* PROC_ENABLE_COMPLETE */
	uint8_t             rtt_type;             /* RTT type */
	struct cs_procedure_data *current_proc;
	/* Cached header values for CONT events (per-connection state) */
	uint16_t last_proc_counter;
	uint16_t last_start_acl_conn_evt_counter;
	uint16_t last_freq_comp;
	int8_t last_ref_pwr_lvl;
};

/* Ranging Service context */
struct ras {
	struct bt_rap_db *rapdb;

	/* Service and characteristic attributes */
	struct gatt_db_attribute *svc;
	struct gatt_db_attribute *feat_chrc;
	struct gatt_db_attribute *realtime_chrc;
	struct gatt_db_attribute *realtime_chrc_ccc;
	struct gatt_db_attribute *ondemand_chrc;
	struct gatt_db_attribute *ondemand_ccc;
	struct gatt_db_attribute *cp_chrc;
	struct gatt_db_attribute *cp_ccc;
	struct gatt_db_attribute *ready_chrc;
	struct gatt_db_attribute *ready_ccc;
	struct gatt_db_attribute *overwritten_chrc;
	struct gatt_db_attribute *overwritten_ccc;

	/* CCC state tracking for mutual exclusivity */
	uint16_t realtime_ccc_value;
	uint16_t ondemand_ccc_value;
};

struct bt_rap_db {
	struct gatt_db *db;
	struct ras *ras;
};

struct bt_rap {
	int ref_count;
	struct bt_rap_db *lrapdb;
	struct bt_rap_db *rrapdb;
	struct bt_gatt_client *client;
	struct bt_att *att;

	unsigned int idle_id;

	struct queue *notify;
	struct queue *pending;
	struct queue *ready_cbs;

	bt_rap_debug_func_t debug_func;
	bt_rap_destroy_func_t debug_destroy;
	void *debug_data;
	void *user_data;
	struct cstracker *resptracker;
};

static struct queue *rap_db;
static struct queue *bt_rap_cbs;
static struct queue *sessions;

struct bt_rap_cb {
	unsigned int id;
	bt_rap_func_t attached;
	bt_rap_func_t detached;
	void *user_data;
};

struct bt_rap_ready {
	unsigned int id;
	bt_rap_ready_func_t func;
	bt_rap_destroy_func_t destroy;
	void *data;
};

uint16_t default_ras_mtu = 247; /*Section 3.1.2 of RAP 1.0*/
uint8_t ras_segment_header_size = 1;

static struct cs_procedure_data *cs_procedure_data_create(
					uint16_t procedure_counter,
					uint8_t num_antenna_paths,
					uint8_t configuration_id,
					int8_t selected_tx_power)
{
	struct cs_procedure_data *d;
	uint8_t i;
	uint8_t antenna_mask = 0;

	d = calloc(1, sizeof(struct cs_procedure_data));

	if (!d)
		return NULL;

	d->counter = procedure_counter;
	d->num_antenna_paths = num_antenna_paths;
	d->local_status = CS_PROC_PARTIAL_RESULTS;
	d->remote_status = CS_PROC_PARTIAL_RESULTS;
	d->contains_complete_subevent_ = false;
	d->segmentation_header_.first_segment = 1;
	d->segmentation_header_.last_segment = 0;
	d->segmentation_header_.rolling_segment_counter = 0;

	/* Initialize ranging header using helper functions */
	memset(&d->ranging_header_, 0, sizeof(d->ranging_header_));
	ranging_header_set_counter(&d->ranging_header_, procedure_counter);
	ranging_header_set_config_id(&d->ranging_header_, configuration_id);
	d->ranging_header_.selected_tx_power = selected_tx_power;

	/* Build antenna mask */
	for (i = 0; i < num_antenna_paths; i++)
		antenna_mask |= (1u << i);
	ranging_header_set_antenna_mask(&d->ranging_header_, antenna_mask);

	ranging_header_set_pct_format(&d->ranging_header_, IQ);
	memset(&d->ras_raw_data_, 0, sizeof(d->ras_raw_data_));
	d->ras_raw_data_index_ = 0;
	memset(&d->ras_subevent_data_, 0, sizeof(d->ras_subevent_data_));
	d->ras_subevent_counter_ = 0;
	d->initiator_reference_power_level = 0;
	d->reflector_reference_power_level = 0;
	d->ranging_header_prepended_ = false;
	d->ras_subevent_header_emitted = false;

	return d;
}

static void cs_procedure_data_destroy(struct cs_procedure_data *d)
{
	if (!d)
		return;

	free(d->ras_raw_data_.iov_base);
	free(d->ras_subevent_data_.iov_base);
	free(d);
}

static void cs_pd_set_local_status(struct cs_procedure_data *d,
				enum cs_procedure_done_status s)
{
	if (d)
		d->local_status = s;
}

static void cs_pd_set_remote_status(struct cs_procedure_data *d,
				enum cs_procedure_done_status s)
{
	if (d)
		d->remote_status = s;
}

static void cs_pd_set_reference_power_levels(struct cs_procedure_data *d,
					int8_t init_lvl, int8_t ref_lvl)
{
	if (!d)
		return;

	d->initiator_reference_power_level = init_lvl;
	d->reflector_reference_power_level = ref_lvl;
}

static void cs_pd_ras_begin_subevent(struct cs_procedure_data *d,
				uint16_t start_acl_conn_event,
				uint16_t frequency_compensation,
				int8_t reference_power_level)
{
	if (!d)
		return;

	d->ras_subevent_counter_++;
	d->ras_subevent_header_.start_acl_conn_event = start_acl_conn_event;
	d->ras_subevent_header_.frequency_compensation =
		frequency_compensation;
	d->ras_subevent_header_.reference_power_level = reference_power_level;
	d->ras_subevent_header_.num_steps_reported = 0;
	d->ras_subevent_header_emitted = false;
	d->ras_subevent_data_.iov_len = 0;
}

static bool cs_pd_ras_append_subevent_bytes(struct cs_procedure_data *d,
					const uint8_t *bytes, size_t len)
{
	if (!d || !bytes || len == 0)
		return false;

	return util_iov_append(&d->ras_subevent_data_, bytes, len) != NULL;
}

static inline size_t serialize_ras_subevent_header(
				const struct ras_subevent_header *h,
				uint8_t *out, size_t out_len)
{

	if (!h || !out || out_len < RAS_SUBEVENT_HEADER_SIZE)
		return 0;

	put_le16(h->start_acl_conn_event, out + 0);
	put_le16(h->frequency_compensation, out + 2);
	out[4] = RAS_DONE_STATUS_PACK(h->ranging_done_status,
					h->subevent_done_status);
	out[5] = RAS_ABORT_REASON_PACK(h->ranging_abort_reason,
					h->subevent_abort_reason);
	out[6] = h->reference_power_level;
	out[7] = h->num_steps_reported;

	return RAS_SUBEVENT_HEADER_SIZE;
}

static bool cs_pd_ras_commit_subevent(struct cs_procedure_data *d,
				uint8_t num_steps_reported,
				uint8_t ranging_done_status,
				uint8_t subevent_done_status,
				uint8_t ranging_abort_reason,
				uint8_t subevent_abort_reason)
{
	size_t hdr_sz;
	size_t payload_sz;
	size_t total;
	uint8_t *buf;
	size_t w;
	bool ok;

	if (!d)
		return false;

	d->ras_subevent_header_.num_steps_reported =
		(uint8_t)(d->ras_subevent_header_.num_steps_reported +
			num_steps_reported);
	d->ras_subevent_header_.ranging_done_status = ranging_done_status;
	d->ras_subevent_header_.subevent_done_status = subevent_done_status;
	d->ras_subevent_header_.ranging_abort_reason = ranging_abort_reason;
	d->ras_subevent_header_.subevent_abort_reason = subevent_abort_reason;

	if (subevent_done_status == SUBEVENT_DONE_ALL_RESULTS_COMPLETE)
		d->contains_complete_subevent_ = true;

	if (subevent_done_status == SUBEVENT_DONE_PARTIAL_RESULTS)
		return true;

	if (!d->ras_subevent_header_emitted) {
		hdr_sz = RAS_SUBEVENT_HEADER_SIZE;
		payload_sz = d->ras_subevent_data_.iov_len;
		total = hdr_sz + payload_sz;
		buf = (uint8_t *)malloc(total);

		if (!buf)
			return false;

		w = serialize_ras_subevent_header(&d->ras_subevent_header_,
						buf, total);

		if (w != hdr_sz) {
			free(buf);
			return false;
		}

		if (payload_sz > 0)
			memcpy(buf + hdr_sz,
				(const uint8_t *)d->ras_subevent_data_.iov_base,
				payload_sz);

		ok = util_iov_append(&d->ras_raw_data_, buf, total) != NULL;
		free(buf);

		if (!ok)
			return false;

		d->ras_subevent_data_.iov_len = 0;
		d->ras_subevent_header_emitted = true;
	}

	return true;
}

static struct ras *rap_get_ras(struct bt_rap *rap)
{
	if (!rap)
		return NULL;

	if (rap->rrapdb->ras)
		return rap->rrapdb->ras;

	rap->rrapdb->ras = new0(struct ras, 1);
	rap->rrapdb->ras->rapdb = rap->rrapdb;

	return rap->rrapdb->ras;
}

static void rap_detached(void *data, void *user_data)
{
	struct bt_rap_cb *cb = data;
	struct bt_rap *rap = user_data;

	cb->detached(rap, cb->user_data);
}

void bt_rap_detach(struct bt_rap *rap)
{
	if (!queue_remove(sessions, rap))
		return;

	bt_gatt_client_idle_unregister(rap->client, rap->idle_id);
	bt_gatt_client_unref(rap->client);
	rap->client = NULL;

	queue_foreach(bt_rap_cbs, rap_detached, rap);
}

static void rap_db_free(void *data)
{
	struct bt_rap_db *rapdb = data;

	if (!rapdb)
		return;

	gatt_db_unref(rapdb->db);

	free(rapdb->ras);
	free(rapdb);
}

static void rap_ready_free(void *data)
{
	struct bt_rap_ready *ready = data;

	if (ready->destroy)
		ready->destroy(ready->data);

	free(ready);
}

static void rap_free(void *data)
{
	struct bt_rap *rap = data;

	bt_rap_detach(rap);

	rap_db_free(rap->rrapdb);

	if (rap->resptracker) {
		free(rap->resptracker);
		rap->resptracker = NULL;
	}

	queue_destroy(rap->notify, free);
	queue_destroy(rap->pending, NULL);
	queue_destroy(rap->ready_cbs, rap_ready_free);

	free(rap);
}

bool bt_rap_set_user_data(struct bt_rap *rap, void *user_data)
{
	if (!rap)
		return false;

	rap->user_data = user_data;

	return true;
}

static bool rap_db_match(const void *data, const void *match_data)
{
	const struct bt_rap_db *rapdb = data;
	const struct gatt_db *db = match_data;

	return rapdb->db == db;
}

struct bt_att *bt_rap_get_att(struct bt_rap *rap)
{
	if (!rap)
		return NULL;

	if (rap->att)
		return rap->att;

	return bt_gatt_client_get_att(rap->client);
}

struct bt_rap *bt_rap_ref(struct bt_rap *rap)
{
	if (!rap)
		return NULL;

	__sync_fetch_and_add(&rap->ref_count, 1);

	return rap;
}

void bt_rap_unref(struct bt_rap *rap)
{
	if (!rap)
		return;

	if (__sync_sub_and_fetch(&rap->ref_count, 1))
		return;

	rap_free(rap);
}

static void rap_debug(struct bt_rap *rap, const char *format, ...)
{
	va_list ap;

	if (!rap || !format || !rap->debug_func)
		return;

	va_start(ap, format);
	util_debug_va(rap->debug_func, rap->debug_data, format, ap);
	va_end(ap);
}

bool bt_rap_set_debug(struct bt_rap *rap, bt_rap_debug_func_t func,
			void *user_data, bt_rap_destroy_func_t destroy)
{
	if (!rap)
		return false;

	if (rap->debug_destroy)
		rap->debug_destroy(rap->debug_data);

	rap->debug_func = func;
	rap->debug_destroy = destroy;
	rap->debug_data = user_data;

	return true;
}

static void cs_tracker_init(struct cstracker *t)
{
	if (!t)
		return;

	memset(t, 0, sizeof(*t));
	t->role = CS_ROLE_REFLECTOR;
	t->config_id = CS_INVALID_CONFIG_ID;
	t->rtt_type = 0;
	t->selected_tx_power = 0;
	t->last_proc_counter = 0;
	t->last_start_acl_conn_evt_counter = 0;
	t->last_freq_comp = 0;
	t->last_ref_pwr_lvl = 0;
}

static void ras_features_read_cb(struct gatt_db_attribute *attrib,
				 unsigned int id, uint16_t offset,
				 uint8_t opcode, struct bt_att *att,
				 void *user_data)
{
	/*
	 * Feature mask: bits 0-2 set:
	 *  - Real-time ranging
	 *  - Retrieve stored results
	 *  - Abort operation
	 */
	uint8_t value[4] = { 0x01, 0x00, 0x00, 0x00 };

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

static void ras_ondemand_read_cb(struct gatt_db_attribute *attrib,
				 unsigned int id, uint16_t offset,
				 uint8_t opcode, struct bt_att *att,
				 void *user_data)
{
	/* No static read data – on‑demand data is pushed via
	 * notifications
	 */
	gatt_db_attribute_read_result(attrib, id, 0, NULL, 0);
}

/*
 * Control point handler.
 * Parses the opcode and acts on queued data (implementation TBD).
 */
static void ras_control_point_write_cb(struct gatt_db_attribute *attrib,
				       unsigned int id, uint16_t offset,
				       const uint8_t *value, size_t len,
				       uint8_t opcode, struct bt_att *att,
				       void *user_data)
{
	/* Control point handler - implementation TBD */
}

/* Data Ready – returns the latest ranging counter. */
static void ras_data_ready_read_cb(struct gatt_db_attribute *attrib,
				   unsigned int id, uint16_t offset,
				   uint8_t opcode, struct bt_att *att,
				   void *user_data)
{
	uint16_t counter = 0;
	uint8_t value[2];

	put_le16(counter, value);
	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

/* Data Overwritten – indicates how many results were overwritten. */
static void ras_data_overwritten_read_cb(struct gatt_db_attribute *attrib,
					 unsigned int id, uint16_t offset,
					 uint8_t opcode, struct bt_att *att,
					 void *user_data)
{
	uint8_t value[2] = { 0x00, 0x00 };

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

static void ras_ranging_data_ccc_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct ras *ras = user_data;
	uint16_t ccc_value;
	bool is_realtime;
	uint16_t *this_ccc;
	uint16_t *other_ccc;

	if (!ras) {
		gatt_db_attribute_write_result(attrib, id,
					BT_ATT_ERROR_UNLIKELY);
		return;
	}

	if (offset) {
		gatt_db_attribute_write_result(attrib, id,
					BT_ATT_ERROR_INVALID_OFFSET);
		return;
	}

	if (len != 2) {
		gatt_db_attribute_write_result(attrib, id,
			BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN);
		return;
	}

	ccc_value = get_le16(value);

	if (ccc_value != 0x0000 && ccc_value != 0x0001 &&
	    ccc_value != 0x0002 && ccc_value != 0x0003) {
		gatt_db_attribute_write_result(attrib, id,
					BT_ERROR_WRITE_REQUEST_REJECTED);
		return;
	}

	/* Determine which CCC this is */
	is_realtime = (attrib == ras->realtime_chrc_ccc);
	this_ccc = is_realtime ? &ras->realtime_ccc_value :
				 &ras->ondemand_ccc_value;
	other_ccc = is_realtime ? &ras->ondemand_ccc_value :
				  &ras->realtime_ccc_value;

	/* Check mutual exclusivity: reject if trying to enable realtime
	 * while ondemand is already enabled.
	 * Test case: RAS/SR/SPE/BI-11-C [Client enables both Real-time
	 * Ranging Data and On-demand Ranging Data notifications or
	 * indications]
	 */
	if (ccc_value != 0x0000 && *other_ccc != 0x0000) {
		gatt_db_attribute_write_result(attrib, id,
					BT_ERROR_CCC_IMPROPERLY_CONFIGURED);
		return;
	}

	/* Update state */
	*this_ccc = ccc_value;

	gatt_db_attribute_write_result(attrib, id, 0);
}

/* Service registration – store attribute pointers */
static struct ras *register_ras_service(struct gatt_db *db)
{
	struct ras *ras;
	struct gatt_db_attribute *service;
	bt_uuid_t uuid;

	if (!db)
		return NULL;

	ras = new0(struct ras, 1);
	if (!ras)
		return NULL;

	/* Primary RAS service */
	bt_uuid16_create(&uuid, RAS_UUID16);
	service = gatt_db_add_service(db, &uuid, true, RAS_TOTAL_NUM_HANDLES);
	if (!service) {
		free(ras);
		return NULL;
	}

	ras->svc = service;

	/* RAS Features */
	bt_uuid16_create(&uuid, RAS_FEATURES_UUID);
		ras->feat_chrc =
		gatt_db_service_add_characteristic(ras->svc, &uuid,
						  BT_ATT_PERM_READ |
						  BT_ATT_PERM_READ_ENCRYPT,
						  BT_GATT_CHRC_PROP_READ,
						  ras_features_read_cb,
						  NULL, ras);

	/* Real-time Ranging Data */
	bt_uuid16_create(&uuid, RAS_REALTIME_DATA_UUID);
	ras->realtime_chrc =
		gatt_db_service_add_characteristic(ras->svc, &uuid,
						  BT_ATT_PERM_READ |
						  BT_ATT_PERM_READ_ENCRYPT,
						  BT_GATT_CHRC_PROP_NOTIFY |
						  BT_GATT_CHRC_PROP_INDICATE,
						  NULL, NULL, ras);

	ras->realtime_chrc_ccc =
		gatt_db_service_add_ccc_custom(ras->svc,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					ras_ranging_data_ccc_write_cb, ras);

	/* On-demand Ranging Data */
	bt_uuid16_create(&uuid, RAS_ONDEMAND_DATA_UUID);
	ras->ondemand_chrc =
		gatt_db_service_add_characteristic(ras->svc, &uuid,
						  BT_ATT_PERM_READ |
						  BT_ATT_PERM_READ_ENCRYPT,
						  BT_GATT_CHRC_PROP_NOTIFY |
						  BT_GATT_CHRC_PROP_INDICATE,
						  ras_ondemand_read_cb, NULL,
						  ras);

	ras->ondemand_ccc = gatt_db_service_add_ccc_custom(ras->svc,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					ras_ranging_data_ccc_write_cb, ras);

	/* RAS Control Point */
	bt_uuid16_create(&uuid, RAS_CONTROL_POINT_UUID);
	ras->cp_chrc =
		gatt_db_service_add_characteristic(ras->svc, &uuid,
						  BT_ATT_PERM_WRITE |
						  BT_ATT_PERM_WRITE_ENCRYPT,
				BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP |
						  BT_GATT_CHRC_PROP_INDICATE,
						  NULL,
						  ras_control_point_write_cb,
						  ras);

	ras->cp_ccc = gatt_db_service_add_ccc(ras->svc,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	/* RAS Data Ready */
	bt_uuid16_create(&uuid, RAS_DATA_READY_UUID);
	ras->ready_chrc =
		gatt_db_service_add_characteristic(ras->svc, &uuid,
						  BT_ATT_PERM_READ |
						  BT_ATT_PERM_READ_ENCRYPT,
						  BT_GATT_CHRC_PROP_READ |
						  BT_GATT_CHRC_PROP_NOTIFY |
						  BT_GATT_CHRC_PROP_INDICATE,
						  ras_data_ready_read_cb, NULL,
						  ras);

	ras->ready_ccc = gatt_db_service_add_ccc(ras->svc,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	/* RAS Data Overwritten */
	bt_uuid16_create(&uuid, RAS_DATA_OVERWRITTEN_UUID);
	ras->overwritten_chrc =
		gatt_db_service_add_characteristic(ras->svc, &uuid,
						  BT_ATT_PERM_READ |
						  BT_ATT_PERM_READ_ENCRYPT,
						  BT_GATT_CHRC_PROP_READ |
						  BT_GATT_CHRC_PROP_NOTIFY |
						  BT_GATT_CHRC_PROP_INDICATE,
						  ras_data_overwritten_read_cb,
						  NULL, ras);

	ras->overwritten_ccc = gatt_db_service_add_ccc(ras->svc,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	/* Activate the service */
	gatt_db_service_set_active(ras->svc, true);

	return ras;
}

static struct bt_rap_db *rap_db_new(struct gatt_db *db)
{
	struct bt_rap_db *rapdb;

	if (!db)
		return NULL;

	rapdb = new0(struct bt_rap_db, 1);
	if (!rapdb)
		return NULL;

	rapdb->db = gatt_db_ref(db);

	if (!rap_db)
		rap_db = queue_new();

	rapdb->ras = register_ras_service(db);
	if (rapdb->ras)
		rapdb->ras->rapdb = rapdb;

	queue_push_tail(rap_db, rapdb);

	return rapdb;
}

static struct bt_rap_db *rap_get_db(struct gatt_db *db)
{
	struct bt_rap_db *rapdb;

	rapdb = queue_find(rap_db, rap_db_match, db);
	if (rapdb)
		return rapdb;

	return rap_db_new(db);
}

void bt_rap_add_db(struct gatt_db *db)
{
	rap_db_new(db);
}

unsigned int bt_rap_register(bt_rap_func_t attached, bt_rap_func_t detached,
			     void *user_data)
{
	struct bt_rap_cb *cb;
	static unsigned int id;

	if (!attached && !detached)
		return 0;

	if (!bt_rap_cbs)
		bt_rap_cbs = queue_new();

	cb = new0(struct bt_rap_cb, 1);
	cb->id = ++id ? id : ++id;
	cb->attached = attached;
	cb->detached = detached;
	cb->user_data = user_data;

	queue_push_tail(bt_rap_cbs, cb);

	return cb->id;
}

static bool match_id(const void *data, const void *match_data)
{
	const struct bt_rap_cb *cb = data;
	unsigned int id = PTR_TO_UINT(match_data);

	return cb->id == id;
}

bool bt_rap_unregister(unsigned int id)
{
	struct bt_rap_cb *cb;

	cb = queue_remove_if(bt_rap_cbs, match_id, UINT_TO_PTR(id));
	if (!cb)
		return false;

	free(cb);

	return true;
}

static inline size_t serialize_segmentation_header(
				const struct segmentation_header *s,
				uint8_t *out, size_t out_len)
{
	if (!s || !out || out_len < 1)
		return 0;

	out[0] = SEG_HDR_PACK(s->first_segment, s->last_segment,
				s->rolling_segment_counter);

	return 1;
}

static inline bool serialize_ranging_header_iov(const struct ranging_header *r,
						struct iovec *iov)
{
	if (!r || !iov)
		return false;

	/* Serialize the per-byte packed fields using util_iov_push functions */
	if (!util_iov_push_le16(iov, get_le16(r->counter_config)))
		return false;

	if (!util_iov_push_u8(iov, r->selected_tx_power))
		return false;

	if (!util_iov_push_u8(iov, r->antenna_pct))
		return false;

	return true;
}

static inline uint16_t ras_att_value_payload_max(struct bt_rap *rap)
{
	struct bt_att *att = bt_rap_get_att(rap);
	uint16_t mtu = att ? bt_att_get_mtu(att) : default_ras_mtu;

	return (uint16_t)(mtu > ATT_OVERHEAD ?
		(mtu - ATT_OVERHEAD - TOTAL_RAS_RANGING_HEADER_SIZE -
		ras_segment_header_size) : 0);
}

/* Prepend data to an iovec - optimized to avoid unnecessary malloc/copy
 * by using realloc and memmove instead of malloc/memcpy/free pattern.
 * This reduces memory allocations and is more cache-friendly.
 */
static bool iov_prepend_bytes(struct iovec *iov, const uint8_t *bytes,
				size_t len)
{
	size_t new_len;
	void *new_base;

	if (!iov || !bytes || len == 0)
		return false;

	new_len = iov->iov_len + len;

	/* Use realloc to potentially expand in-place */
	new_base = realloc(iov->iov_base, new_len);

	if (!new_base)
		return false;

	/* Move existing data forward to make room at the beginning */
	if (iov->iov_len > 0)
		memmove((uint8_t *)new_base + len, new_base, iov->iov_len);

	/* Copy new data to the beginning */
	memcpy(new_base, bytes, len);

	iov->iov_base = new_base;
	iov->iov_len = new_len;

	return true;
}

/* Append the 4-byte RangingHeader to ras_raw_data_ on first segment */
static bool ras_maybe_prepend_ranging_header(struct cs_procedure_data *d)
{
	struct iovec temp_iov = { 0 };
	bool ok;

	if (!d)
		return false;

	if (d->ranging_header_prepended_)
		return false;

	if (!d->segmentation_header_.first_segment)
		return false;

	if (d->ras_raw_data_index_ != 0)
		return false;

	temp_iov.iov_base = malloc(4);
	if (!temp_iov.iov_base)
		return false;
	temp_iov.iov_len = 0;

	/* Serialize ranging header into temporary iovec */
	if (!serialize_ranging_header_iov(&d->ranging_header_, &temp_iov)) {
		free(temp_iov.iov_base);
		return false;
	}

	/* Prepend the serialized header to ras_raw_data_ */
	ok = iov_prepend_bytes(&d->ras_raw_data_, temp_iov.iov_base,
				temp_iov.iov_len);

	/* Free temporary iovec buffer */
	free(temp_iov.iov_base);

	if (ok)
		d->ranging_header_prepended_ = true;

	return ok;
}

static void send_ras_segment_data(struct bt_rap *rap,
				struct cs_procedure_data *proc)
{
	struct ras *ras;
	uint16_t value_max;
	const uint16_t header_len = ras_segment_header_size;
	uint16_t raw_payload_size;
	bool ok;

	if (!rap || !proc)
		return;

	if (!rap->lrapdb || !rap->lrapdb->ras)
		return;

	ras = rap->lrapdb->ras;
	value_max = ras_att_value_payload_max(rap);

	if (value_max == 0) {
		DBG(rap, "value_max=0 (MTU not available?)");
		return;
	}

	if (value_max <= header_len) {
		DBG(rap, "value_max(%u) too small for header", value_max);
		return;
	}

	raw_payload_size = (uint16_t)(value_max - header_len);

	/* Convert tail recursion to loop */
	while (true) {
		size_t total_len = proc->ras_raw_data_.iov_len;
		size_t index = proc->ras_raw_data_index_;
		size_t unsent_data_size;
		uint16_t copy_size;
		uint16_t seg_len;
		uint8_t *seg;
		uint16_t wr = 0;

		if (index > total_len)
			index = total_len;

		unsent_data_size = total_len - index;

		if (unsent_data_size == 0)
			return;

		/* Set last_segment if procedure complete or fits in segment */
		if ((proc->local_status != CS_PROC_PARTIAL_RESULTS &&
				unsent_data_size <= raw_payload_size) ||
			(proc->contains_complete_subevent_ &&
				unsent_data_size <= raw_payload_size)) {
			proc->segmentation_header_.last_segment = 1;
		} else {
			proc->segmentation_header_.last_segment = 0;
		}

		/* Wait for more data if needed and not last segment */
		if (unsent_data_size < raw_payload_size &&
				proc->segmentation_header_.last_segment == 0) {
			DBG(rap, "waiting for more data (unsent=%zu < "
				"payload=%u)", unsent_data_size,
				raw_payload_size);
			return;
		}

		copy_size = (uint16_t)((unsent_data_size < raw_payload_size) ?
				unsent_data_size : raw_payload_size);
		seg_len = (uint16_t)(header_len + copy_size);
		seg = (uint8_t *)malloc(seg_len);

		if (!seg) {
			DBG(rap, "OOM (%u)", seg_len);
			return;
		}

		wr += (uint16_t)serialize_segmentation_header(
				&proc->segmentation_header_, seg + wr,
				seg_len - wr);
		memcpy(seg + wr,
			(const uint8_t *)proc->ras_raw_data_.iov_base + index,
			copy_size);
		wr += copy_size;

		/* Try sending to real-time characteristic */
		if (ras->realtime_chrc)
			ok = gatt_db_attribute_notify(ras->realtime_chrc, seg,
						wr, bt_rap_get_att(rap));

		/* Try sending to on-demand characteristic */
		if (ras->ondemand_chrc)
			ok = gatt_db_attribute_notify(ras->ondemand_chrc, seg,
						wr, bt_rap_get_att(rap));

		free(seg);

		if (!ok) {
			DBG(rap, "Failed to send RAS notification");
			return;
		}

		/* Advance read cursor and update segmentation state */
		proc->ras_raw_data_index_ += copy_size;
		proc->segmentation_header_.first_segment = 0;
		proc->segmentation_header_.rolling_segment_counter =
			(uint8_t)((proc->segmentation_header_
				.rolling_segment_counter + 1) & 0x3F);

		if (proc->segmentation_header_.last_segment ||
				proc->ras_raw_data_index_ >=
				proc->ras_raw_data_.iov_len) {
			DBG(rap, "RAS clear ras buffers");
			proc->ras_raw_data_.iov_len = 0;
			proc->ras_raw_data_index_ = 0;
			proc->ranging_header_prepended_ = false;
			return;
		}
	}
}

static inline void resptracker_reset_current_proc(struct cstracker *t)
{
	if (!t)
		return;

	if (t->current_proc) {
		cs_procedure_data_destroy(t->current_proc);
		t->current_proc = NULL;
	}
}

static void process_cs_mode_zero(struct bt_rap *rap,
				struct cs_procedure_data *proc,
				const struct cs_step_data *step,
				uint8_t idx, uint8_t mode_byte)
{
	const uint8_t *payload;
	uint8_t plen;

	/* Mode 0: use raw structure bytes */
	payload = (const uint8_t *)&step->step_mode_data;
	plen = step->step_data_length;
	cs_pd_ras_append_subevent_bytes(proc, payload, plen);
	DBG(rap, "step[%u]: mode=0x%02x Mode0 payload_len=%u sent",
		idx, mode_byte, (unsigned int)plen);
}

static void process_cs_mode_one(struct bt_rap *rap,
				struct cs_procedure_data *proc,
				const struct cs_step_data *step,
				uint8_t idx, uint8_t mode_byte)
{
	const struct cs_mode_one_data *m1 =
		&step->step_mode_data.mode_one_data;
	struct cstracker *resptracker = rap->resptracker;
	struct iovec temp_iov = { 0 };
	uint16_t time_val;
	uint32_t pct1;
	uint32_t pct2;
	enum cs_role cs_role = resptracker->role;
	uint8_t cs_rtt_type = resptracker->rtt_type;
	bool include_pct;

	temp_iov.iov_base = malloc(64);
	if (!temp_iov.iov_base) {
		DBG(rap, "Mode1 ERROR: malloc failed!");
		return;
	}
	temp_iov.iov_len = 0;

	include_pct = (cs_rtt_type == 0x01 || cs_rtt_type == 0x02);

	if (!util_iov_push_u8(&temp_iov, m1->packet_quality) ||
	    !util_iov_push_u8(&temp_iov, m1->packet_nadm) ||
	    !util_iov_push_u8(&temp_iov, m1->packet_rssi_dbm))
		goto done;

	/* Time value (2 bytes LE) - use the appropriate field based on role */
	if (cs_role == CS_ROLE_REFLECTOR)
		time_val = m1->tod_toa_refl;
	else
		time_val = m1->toa_tod_init;

	if (!util_iov_push_le16(&temp_iov, time_val) ||
	    !util_iov_push_u8(&temp_iov, m1->packet_ant))
		goto done;

	if (include_pct) {
		/* PCT1 (3 bytes LE) - 12-bit I + 12-bit Q */
		pct1 = ((uint32_t)(m1->packet_pct1.i_sample & 0x0FFF)) |
			(((uint32_t)(m1->packet_pct1.q_sample & 0x0FFF)) <<
			12);
		if (!util_iov_push_le24(&temp_iov, pct1))
			goto done;

		/* PCT2 (3 bytes LE) */
		pct2 = ((uint32_t)(m1->packet_pct2.i_sample & 0x0FFF)) |
			(((uint32_t)(m1->packet_pct2.q_sample & 0x0FFF)) <<
			12);
		if (!util_iov_push_le24(&temp_iov, pct2))
			goto done;
	}

	cs_pd_ras_append_subevent_bytes(proc, temp_iov.iov_base,
					temp_iov.iov_len);

done:
	free(temp_iov.iov_base);

	DBG(rap, "step[%u]: mode=0x%02x Mode1 serialized payload_len=%zu "
		"role=%s rtt_type=0x%02x pct=%s",
		idx, mode_byte, temp_iov.iov_len,
		cs_role == CS_ROLE_INITIATOR ? "INIT" : "REFL", cs_rtt_type,
		include_pct ? "YES" : "NO");
}

static void process_cs_mode_two(struct bt_rap *rap,
				struct cs_procedure_data *proc,
				const struct cs_step_data *step,
				uint8_t num_ant_paths,
				uint8_t idx, uint8_t mode_byte)
{
	const struct cs_mode_two_data *m2 =
		&step->step_mode_data.mode_two_data;
	struct iovec temp_iov = { 0 };
	uint8_t k;
	uint8_t num_paths = (num_ant_paths + 1) < 5 ?
		(num_ant_paths + 1) : 5;

	temp_iov.iov_base = malloc(128);
	if (!temp_iov.iov_base) {
		DBG(rap, "Mode2 ERROR: malloc failed!");
		return;
	}
	temp_iov.iov_len = 0;

	if (!util_iov_push_u8(&temp_iov, m2->ant_perm_index))
		goto done;

	/* Serialize each path: PCT (3 bytes LE) + quality (1 byte) */
	for (k = 0; k < num_paths; k++) {
		/* Convert 4-byte structure PCT to 3-byte wire format */
		uint32_t pct = ((uint32_t)(m2->tone_pct[k].i_sample &
				0x0FFF)) |
			(((uint32_t)(m2->tone_pct[k].q_sample &
				0x0FFF)) << 12);
		if (!util_iov_push_le24(&temp_iov, pct) ||
		    !util_iov_push_u8(&temp_iov,
				m2->tone_quality_indicator[k]))
			goto done;
	}

	cs_pd_ras_append_subevent_bytes(proc, temp_iov.iov_base,
					temp_iov.iov_len);

done:
	free(temp_iov.iov_base);

	DBG(rap, "step[%u]: mode=0x%02x Mode2 serialized payload_len=%zu "
		"paths=%u",
		idx, mode_byte, temp_iov.iov_len, num_paths);
}

static void process_cs_mode_three(struct bt_rap *rap,
				struct cs_procedure_data *proc,
				const struct cs_step_data *step,
				uint8_t num_ant_paths,
				uint8_t idx, uint8_t mode_byte)
{
	const struct cs_mode_three_data *m3 =
		&step->step_mode_data.mode_three_data;
	const struct cs_mode_one_data *m1 = &m3->mode_one_data;
	const struct cs_mode_two_data *m2 = &m3->mode_two_data;
	struct cstracker *resptracker = rap->resptracker;
	struct iovec temp_iov = { 0 };
	uint16_t time_val;
	uint32_t pct1;
	uint32_t pct2;
	enum cs_role cs_role = resptracker->role;
	uint8_t cs_rtt_type = resptracker->rtt_type;
	uint8_t k;
	uint8_t num_paths = (num_ant_paths + 1) < 5 ?
		(num_ant_paths + 1) : 5;
	bool include_pct;

	temp_iov.iov_base = malloc(128);
	if (!temp_iov.iov_base) {
		DBG(rap, "Mode3 ERROR: malloc failed!");
		return;
	}
	temp_iov.iov_len = 0;

	/* Determine if PCT samples should be included */
	include_pct = (cs_rtt_type == 0x01 || cs_rtt_type == 0x02);

	if (!util_iov_push_u8(&temp_iov, m1->packet_quality) ||
	    !util_iov_push_u8(&temp_iov, m1->packet_nadm) ||
	    !util_iov_push_u8(&temp_iov, m1->packet_rssi_dbm))
		goto done;

	/* Time value (2 bytes LE) - use the appropriate field based on role */
	if (cs_role == CS_ROLE_REFLECTOR)
		time_val = m1->tod_toa_refl;
	else
		time_val = m1->toa_tod_init;

	if (!util_iov_push_le16(&temp_iov, time_val) ||
	    !util_iov_push_u8(&temp_iov, m1->packet_ant))
		goto done;

	/* PCT samples if RTT type contains sounding sequence */
	if (include_pct) {
		/* PCT1 (3 bytes LE) - 12-bit I + 12-bit Q */
		pct1 = ((uint32_t)(m1->packet_pct1.i_sample & 0x0FFF)) |
			(((uint32_t)(m1->packet_pct1.q_sample & 0x0FFF)) <<
			12);

		if (!util_iov_push_le24(&temp_iov, pct1))
			goto done;

		/* PCT2 (3 bytes LE) */
		pct2 = ((uint32_t)(m1->packet_pct2.i_sample & 0x0FFF)) |
			(((uint32_t)(m1->packet_pct2.q_sample & 0x0FFF)) <<
			12);

		if (!util_iov_push_le24(&temp_iov, pct2))
			goto done;
	}

	if (!util_iov_push_u8(&temp_iov, m2->ant_perm_index))
		goto done;

	for (k = 0; k < num_paths; k++) {
		/* Convert 4-byte structure PCT to 3-byte wire format */
		uint32_t pct = ((uint32_t)(m2->tone_pct[k].i_sample &
				0x0FFF)) |
			(((uint32_t)(m2->tone_pct[k].q_sample &
				0x0FFF)) << 12);
		if (!util_iov_push_le24(&temp_iov, pct) ||
		    !util_iov_push_u8(&temp_iov,
				m2->tone_quality_indicator[k]))
			goto done;
	}

	cs_pd_ras_append_subevent_bytes(proc, temp_iov.iov_base,
					temp_iov.iov_len);

done:
	free(temp_iov.iov_base);

	DBG(rap, "=== Mode3 END: step[%u] payload_len=%zu paths=%u role=%s "
		"rtt_type=0x%02x pct=%s ===",
		idx, temp_iov.iov_len, num_paths,
		cs_role == CS_ROLE_INITIATOR ? "INIT" : "REFL",
		cs_rtt_type, include_pct ? "YES" : "NO");
}

static void process_cs_mode_step(struct bt_rap *rap,
				struct cs_procedure_data *proc,
				const struct cs_step_data *step,
				uint8_t num_ant_paths,
				uint8_t idx)
{
	const uint8_t mode = step->step_mode;
	const uint8_t payload_len = step->step_data_length;
	uint8_t mode_byte;
	uint8_t mode_type;
	const uint8_t *payload;
	uint8_t plen;
	bool step_aborted;

	/* Check if step is aborted: bit 7 of step_mode or 0 payload len */
	step_aborted = (mode & RAS_STEP_ABORTED_BIT) || (payload_len == 0);

	DBG(rap, "step[%u]: mode=0x%02x channel=%u payload_len=%u "
		"aborted=%s", idx, mode, step->step_chnl, payload_len,
		step_aborted ? "YES" : "NO");

	mode_byte = step->step_mode;

	if (step_aborted) {
		/* Ensure abort bit is set */
		mode_byte |= RAS_STEP_ABORTED_BIT;
		cs_pd_ras_append_subevent_bytes(proc, &mode_byte, 1);
		/* No payload when aborted - per RAS spec Table 3.8 */
		DBG(rap, "step[%u]: mode=0x%02x aborted, no payload sent",
			idx, mode_byte);
		return;
	}

	mode_type = mode & 0x03;

	/* Mode byte first (without abort bit) */
	cs_pd_ras_append_subevent_bytes(proc, &mode_byte, 1);

	switch (mode_type) {
	case CS_MODE_ZERO:
		process_cs_mode_zero(rap, proc, step, idx, mode_byte);
		break;
	case CS_MODE_ONE:
		process_cs_mode_one(rap, proc, step, idx, mode_byte);
		break;
	case CS_MODE_TWO:
		process_cs_mode_two(rap, proc, step, num_ant_paths, idx,
					mode_byte);
		break;
	case CS_MODE_THREE:
		process_cs_mode_three(rap, proc, step, num_ant_paths, idx,
					mode_byte);
		break;
	default:
		/* Unknown mode: use raw structure bytes */
		payload = (const uint8_t *)&step->step_mode_data;
		plen = step->step_data_length;
		cs_pd_ras_append_subevent_bytes(proc, payload, plen);
		DBG(rap, "step[%u]: mode=0x%02x unknown mode, "
			"payload_len=%u sent",
			idx, mode_byte, (unsigned int)plen);
		break;
	}
}

/* Unified local subevent handler */
static void handle_local_subevent_result(struct bt_rap *rap,
					bool has_header_fields,
					uint8_t config_id,
					uint8_t num_ant_paths,
					uint16_t proc_counter,
					uint16_t start_acl_conn_evt_counter,
					uint16_t freq_comp,
					int8_t  ref_pwr_lvl,
					uint8_t proc_done_status,
					uint8_t subevt_done_status,
					uint8_t abort_reason,
					uint8_t num_steps_reported,
					const void *step_bytes)
{
	struct cstracker *resptracker;
	struct cs_procedure_data *proc;
	const struct cs_step_data *steps;
	uint8_t idx;

	if (!rap || !rap->resptracker || !step_bytes)
		return;

	resptracker = rap->resptracker;

	if (resptracker->current_proc) {
		struct cs_procedure_data *cur = resptracker->current_proc;

		if (has_header_fields && cur->counter != proc_counter) {
			/* Safety: a new procedure; destroy the previous one */
			resptracker_reset_current_proc(resptracker);
		}
	}

	proc = resptracker->current_proc;
	/* Cache header info from a RESULT event for later CONT usage */
	if (has_header_fields) {
		resptracker->last_proc_counter = proc_counter;
		resptracker->last_start_acl_conn_evt_counter =
			start_acl_conn_evt_counter;
		resptracker->last_freq_comp = freq_comp;
		resptracker->last_ref_pwr_lvl = ref_pwr_lvl;
	}

	/* Create the procedure on first use */
	if (!proc) {
		uint16_t create_counter = has_header_fields ? proc_counter :
					resptracker->last_proc_counter;

		proc = cs_procedure_data_create(create_counter,
						num_ant_paths,
						config_id,
						resptracker->selected_tx_power);
		if (!proc)
			return;

		resptracker->current_proc = proc;

		/* Reference power levels and status defaults */
		cs_pd_set_reference_power_levels(proc,
			has_header_fields ? ref_pwr_lvl :
				resptracker->last_ref_pwr_lvl,
			has_header_fields ? ref_pwr_lvl :
				resptracker->last_ref_pwr_lvl);
		cs_pd_set_local_status(proc,
			(enum cs_procedure_done_status)proc_done_status);
		cs_pd_set_remote_status(proc,
			(enum cs_procedure_done_status)subevt_done_status);
	}

	/* Begin a new RAS subevent only when we have header fields */
	if (has_header_fields) {
		cs_pd_ras_begin_subevent(proc,
					start_acl_conn_evt_counter,
					freq_comp,
					ref_pwr_lvl);
	}

	/* step_bytes points to an array of struct cs_step_data */
	steps = (const struct cs_step_data *)step_bytes;

	/* Process each step using helper function */
	for (idx = 0; idx < num_steps_reported; idx++)
		process_cs_mode_step(rap, proc, &steps[idx], num_ant_paths,
					idx);

	/* Update status for this chunk */
	cs_pd_set_local_status(proc,
			(enum cs_procedure_done_status)proc_done_status);
	cs_pd_set_remote_status(proc,
			(enum cs_procedure_done_status)subevt_done_status);

	/* Commit subevent chunk (RESULT or CONT) */
	cs_pd_ras_commit_subevent(proc,
		num_steps_reported,
		proc_done_status,
		subevt_done_status,
		abort_reason & 0x0F,
		(abort_reason >> 4) & 0x0F);

	/* Ensure first segment body starts with the 4-byte RangingHeader */
	ras_maybe_prepend_ranging_header(proc);

	if (subevt_done_status != SUBEVENT_DONE_PARTIAL_RESULTS)
		/* Send RAS raw segment data */
		send_ras_segment_data(rap, proc);

	/* Procedure complete? Clean up */
	if (proc_done_status == CS_PROC_ALL_RESULTS_COMPLETE) {
		DBG(rap, "Destroying CsProcedureData counter=%u and "
			"clearing current_proc", proc->counter);
		resptracker_reset_current_proc(resptracker);
		/* Reset cached header values for next procedure */
		resptracker->last_proc_counter = 0;
		resptracker->last_start_acl_conn_evt_counter = 0;
		resptracker->last_freq_comp = 0;
		resptracker->last_ref_pwr_lvl = 0;
	}
}

static void form_ras_data_with_cs_subevent_result(struct bt_rap *rap,
		const struct rap_ev_cs_subevent_result *data,
		uint16_t length)
{
	size_t base_len = offsetof(struct rap_ev_cs_subevent_result,
					step_data);

	if (!rap || !rap->resptracker || !data)
		return;

	/* Defensive check: base header must be present */
	if (length < base_len)
		return;

	DBG(rap, "Received CS subevent result subevent: len=%d", length);

	handle_local_subevent_result(rap,
		true,			/* has header fields */
		data->config_id,
		data->num_ant_paths,
		data->proc_counter,
		data->start_acl_conn_evt_counter,
		data->freq_comp,
		data->ref_pwr_lvl,
		data->proc_done_status,
		data->subevt_done_status,
		data->abort_reason,
		data->num_steps_reported,
		data->step_data);	/* start of steps */
}

static void form_ras_data_with_cs_subevent_result_cont(struct bt_rap *rap,
		const struct rap_ev_cs_subevent_result_cont *cont,
		uint16_t length)
{
	size_t base_len = offsetof(struct rap_ev_cs_subevent_result_cont,
					step_data);
	struct cstracker *resptracker;

	if (!rap || !rap->resptracker || !cont)
		return;

	if (length < base_len)
		return;

	DBG(rap, "Received CS subevent result continue subevent: len=%d",
		length);

	resptracker = rap->resptracker;

	/* Use cached header values captured from the last RESULT event */
	handle_local_subevent_result(rap,
		false,			/* CONT has no header fields */
		cont->config_id,
		cont->num_ant_paths,
		resptracker->last_proc_counter,
		resptracker->last_start_acl_conn_evt_counter,
		resptracker->last_freq_comp,
		resptracker->last_ref_pwr_lvl,
		cont->proc_done_status,
		cont->subevt_done_status,
		cont->abort_reason,
		cont->num_steps_reported,
		cont->step_data);
}

void bt_rap_hci_cs_subevent_result_cont_callback(uint16_t length,
						const void *param,
						void *user_data)
{
	const struct rap_ev_cs_subevent_result_cont *cont = param;
	struct bt_rap *rap = user_data;

	DBG(rap, "Received CS subevent CONT: len=%d", length);

	form_ras_data_with_cs_subevent_result_cont(rap, cont, length);
}

void bt_rap_hci_cs_subevent_result_callback(uint16_t length,
					const void *param,
					void *user_data)
{
	const struct rap_ev_cs_subevent_result *data = param;
	struct bt_rap *rap = user_data;

	DBG(rap, "Received CS subevent: len=%d", length);

	/* Populate CsProcedureData and send RAS payload */
	form_ras_data_with_cs_subevent_result(rap, data, length);
}

void bt_rap_hci_cs_procedure_enable_complete_callback(uint16_t length,
						const void *param,
						void *user_data)
{
	const struct rap_ev_cs_proc_enable_cmplt *data = param;
	struct bt_rap *rap = user_data;
	struct cstracker *resptracker;

	DBG(rap, "Received CS procedure enable complete subevent: len=%d",
	    length);

	if (!rap->resptracker) {
		resptracker = new0(struct cstracker, 1);
		cs_tracker_init(resptracker);
		rap->resptracker = resptracker;
	}

	resptracker = rap->resptracker;

	/* Populate responder tracker */
	resptracker->config_id = data->config_id;
	resptracker->selected_tx_power = data->sel_tx_pwr;
}

void bt_rap_hci_cs_sec_enable_complete_callback(uint16_t length,
						 const void *param,
						 void *user_data)
{
	struct bt_rap *rap = user_data;

	DBG(rap, "Received CS security enable subevent: len=%d", length);
}

void bt_rap_hci_cs_config_complete_callback(uint16_t length,
					const void *param,
					void *user_data)
{
	const struct rap_ev_cs_config_cmplt *data = param;
	struct bt_rap *rap = user_data;
	struct cstracker *resptracker;

	if (!rap)
		return;

	DBG(rap, "Received CS config complete subevent: len=%d", length);

	if (!rap->resptracker) {
		resptracker = new0(struct cstracker, 1);
		cs_tracker_init(resptracker);
		rap->resptracker = resptracker;
	}

	resptracker = rap->resptracker;

	/* Basic fields */
	resptracker->config_id = data->config_id;
	resptracker->role = data->role;
	resptracker->rtt_type = data->rtt_type;
}

struct bt_rap *bt_rap_new(struct gatt_db *ldb, struct gatt_db *rdb)
{
	struct bt_rap *rap;
	struct bt_rap_db *rapdb;

	if (!ldb)
		return NULL;

	rapdb = rap_get_db(ldb);
	if (!rapdb)
		return NULL;

	rap = new0(struct bt_rap, 1);
	rap->lrapdb = rapdb;
	rap->pending = queue_new();
	rap->ready_cbs = queue_new();
	rap->notify = queue_new();

	if (!rdb)
		goto done;

	rapdb = new0(struct bt_rap_db, 1);
	rapdb->db = gatt_db_ref(rdb);

	rap->rrapdb = rapdb;

done:
	bt_rap_ref(rap);

	return rap;
}

static void foreach_rap_char(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_rap *rap = user_data;
	uint16_t value_handle;
	bt_uuid_t uuid;
	bt_uuid_t uuid_features;
	bt_uuid_t uuid_realtime;
	bt_uuid_t uuid_ondemand;
	bt_uuid_t uuid_cp;
	bt_uuid_t uuid_dataready;
	bt_uuid_t uuid_overwritten;
	struct ras *ras;

	if (!gatt_db_attribute_get_char_data(attr, NULL, &value_handle,
					     NULL, NULL, &uuid))
		return;

	bt_uuid16_create(&uuid_features, RAS_FEATURES_UUID);
	bt_uuid16_create(&uuid_realtime, RAS_REALTIME_DATA_UUID);
	bt_uuid16_create(&uuid_ondemand, RAS_ONDEMAND_DATA_UUID);
	bt_uuid16_create(&uuid_cp, RAS_CONTROL_POINT_UUID);
	bt_uuid16_create(&uuid_dataready, RAS_DATA_READY_UUID);
	bt_uuid16_create(&uuid_overwritten, RAS_DATA_OVERWRITTEN_UUID);

	if (!bt_uuid_cmp(&uuid, &uuid_features)) {
		DBG(rap, "Features characteristic found: handle 0x%04x",
		    value_handle);

		ras = rap_get_ras(rap);
		if (!ras || ras->feat_chrc)
			return;

		ras->feat_chrc = attr;
	}

	if (!bt_uuid_cmp(&uuid, &uuid_realtime)) {
		DBG(rap, "Real Time Data characteristic found: handle 0x%04x",
		    value_handle);

		ras = rap_get_ras(rap);
		if (!ras || ras->realtime_chrc)
			return;

		ras->realtime_chrc = attr;
	}

	if (!bt_uuid_cmp(&uuid, &uuid_ondemand)) {
		DBG(rap, "On-demand Data characteristic found: handle 0x%04x",
		    value_handle);

		ras = rap_get_ras(rap);
		if (!ras || ras->ondemand_chrc)
			return;

		ras->ondemand_chrc = attr;
	}

	if (!bt_uuid_cmp(&uuid, &uuid_cp)) {
		DBG(rap, "Control Point characteristic found: handle 0x%04x",
		    value_handle);

		ras = rap_get_ras(rap);
		if (!ras || ras->cp_chrc)
			return;

		ras->cp_chrc = attr;
	}

	if (!bt_uuid_cmp(&uuid, &uuid_dataready)) {
		DBG(rap, "Data Ready characteristic found: handle 0x%04x",
		    value_handle);

		ras = rap_get_ras(rap);
		if (!ras || ras->ready_chrc)
			return;

		ras->ready_chrc = attr;
	}

	if (!bt_uuid_cmp(&uuid, &uuid_overwritten)) {
		DBG(rap, "Overwritten characteristic found: handle 0x%04x",
		    value_handle);

		ras = rap_get_ras(rap);
		if (!ras || ras->overwritten_chrc)
			return;

		ras->overwritten_chrc = attr;
	}
}

static void foreach_rap_service(struct gatt_db_attribute *attr,
				void *user_data)
{
	struct bt_rap *rap = user_data;
	struct ras *ras = rap_get_ras(rap);

	ras->svc = attr;

	gatt_db_service_set_claimed(attr, true);

	gatt_db_service_foreach_char(attr, foreach_rap_char, rap);
}

unsigned int bt_rap_ready_register(struct bt_rap *rap,
				   bt_rap_ready_func_t func, void *user_data,
				   bt_rap_destroy_func_t destroy)
{
	struct bt_rap_ready *ready;
	static unsigned int id;

	if (!rap)
		return 0;

	DBG(rap, "bt_rap_ready_register");

	ready = new0(struct bt_rap_ready, 1);
	ready->id = ++id ? id : ++id;
	ready->func = func;
	ready->destroy = destroy;
	ready->data = user_data;

	queue_push_tail(rap->ready_cbs, ready);

	return ready->id;
}

static bool match_ready_id(const void *data, const void *match_data)
{
	const struct bt_rap_ready *ready = data;
	unsigned int id = PTR_TO_UINT(match_data);

	return ready->id == id;
}

bool bt_rap_ready_unregister(struct bt_rap *rap, unsigned int id)
{
	struct bt_rap_ready *ready;

	ready = queue_remove_if(rap->ready_cbs, match_ready_id,
				UINT_TO_PTR(id));
	if (!ready)
		return false;

	rap_ready_free(ready);

	return true;
}

static struct bt_rap *bt_rap_ref_safe(struct bt_rap *rap)
{
	if (!rap || !rap->ref_count)
		return NULL;

	return bt_rap_ref(rap);
}

static void rap_notify_ready(struct bt_rap *rap)
{
	const struct queue_entry *entry;

	if (!bt_rap_ref_safe(rap))
		return;

	for (entry = queue_get_entries(rap->ready_cbs); entry;
	     entry = entry->next) {
		struct bt_rap_ready *ready = entry->data;

		ready->func(rap, ready->data);
	}

	bt_rap_unref(rap);
}

static void rap_idle(void *data)
{
	struct bt_rap *rap = data;

	rap->idle_id = 0;
	rap_notify_ready(rap);
}

bool bt_rap_attach(struct bt_rap *rap, struct bt_gatt_client *client)
{
	bt_uuid_t uuid;

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, rap);

	if (!client)
		return true;

	if (rap->client)
		return false;

	rap->client = bt_gatt_client_clone(client);
	if (!rap->client)
		return false;

	bt_gatt_client_idle_register(rap->client, rap_idle, rap, NULL);

	bt_uuid16_create(&uuid, RAS_UUID16);

	gatt_db_foreach_service(rap->rrapdb->db, &uuid,
				foreach_rap_service, rap);

	return true;
}
