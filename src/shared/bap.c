// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation. All rights reserved.
 *
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#include "lib/bluetooth.h"
#include "lib/uuid.h"

#include "src/shared/io.h"
#include "src/shared/queue.h"
#include "src/shared/util.h"
#include "src/shared/timeout.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/gatt-client.h"
#include "src/shared/bap.h"
#include "src/shared/ascs.h"

/* Maximum number of ASE(s) */
#define NUM_SINKS 2
#define NUM_SOURCE 2
#define NUM_ASES (NUM_SINKS + NUM_SOURCE)
#define ASE_UUID(_id) (_id < NUM_SINKS ? ASE_SINK_UUID : ASE_SOURCE_UUID)
#define DBG(_bap, fmt, arg...) \
	bap_debug(_bap, "%s:%s() " fmt, __FILE__, __func__, ## arg)

#define LTV(_type, _bytes...) \
	{ \
		.len = 1 + sizeof((uint8_t []) { _bytes }), \
		.type = _type, \
		.data = { _bytes }, \
	}

#define BAP_PROCESS_TIMEOUT 10

struct bt_bap_pac_changed {
	bt_bap_pac_func_t added;
	bt_bap_pac_func_t removed;
	bt_bap_destroy_func_t destroy;
	void *data;
};

struct bt_bap_ready {
	unsigned int id;
	bt_bap_ready_func_t func;
	bt_bap_destroy_func_t destroy;
	void *data;
};

struct bt_bap_state {
	unsigned int id;
	bt_bap_state_func_t func;
	bt_bap_connecting_func_t connecting;
	bt_bap_destroy_func_t destroy;
	void *data;
};

struct bt_bap_cb {
	unsigned int id;
	bt_bap_func_t attached;
	bt_bap_func_t detached;
	void *user_data;
};

struct bt_pacs {
	struct bt_bap_db *bdb;
	struct gatt_db_attribute *service;
	struct gatt_db_attribute *sink;
	struct gatt_db_attribute *sink_ccc;
	struct gatt_db_attribute *sink_loc;
	struct gatt_db_attribute *sink_loc_ccc;
	struct gatt_db_attribute *source;
	struct gatt_db_attribute *source_ccc;
	struct gatt_db_attribute *source_loc;
	struct gatt_db_attribute *source_loc_ccc;
	struct gatt_db_attribute *context;
	struct gatt_db_attribute *context_ccc;
	struct gatt_db_attribute *supported_context;
	struct gatt_db_attribute *supported_context_ccc;
};

struct bt_ase {
	struct bt_ascs *ascs;
	uint8_t  id;
	struct gatt_db_attribute *attr;
	struct gatt_db_attribute *ccc;
};

struct bt_ascs {
	struct bt_bap_db *bdb;
	struct gatt_db_attribute *service;
	struct bt_ase *ase[NUM_ASES];
	struct gatt_db_attribute *ase_cp;
	struct gatt_db_attribute *ase_cp_ccc;
};

struct bt_bap_db {
	struct gatt_db *db;
	struct bt_pacs *pacs;
	struct bt_ascs *ascs;
	struct queue *sinks;
	struct queue *sources;
	struct queue *endpoints;
};

struct bt_bap_req {
	unsigned int id;
	struct bt_bap_stream *stream;
	uint8_t op;
	struct queue *group;
	struct iovec *iov;
	size_t len;
	bt_bap_stream_func_t func;
	void *user_data;
};

typedef void (*bap_func_t)(struct bt_bap *bap, bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data);

struct bt_bap_pending {
	unsigned int id;
	struct bt_bap *bap;
	bap_func_t func;
	void *user_data;
};

typedef void (*bap_notify_t)(struct bt_bap *bap, uint16_t value_handle,
				const uint8_t *value, uint16_t length,
				void *user_data);

struct bt_bap_notify {
	unsigned int id;
	struct bt_bap *bap;
	bap_notify_t func;
	void *user_data;
};

struct bt_bap {
	int ref_count;
	struct bt_bap_db *ldb;
	struct bt_bap_db *rdb;
	struct bt_gatt_client *client;
	struct bt_att *att;
	struct bt_bap_req *req;
	unsigned int cp_id;

	unsigned int process_id;
	unsigned int disconn_id;
	struct queue *reqs;
	struct queue *pending;
	struct queue *notify;
	struct queue *streams;

	struct queue *ready_cbs;
	struct queue *state_cbs;

	bt_bap_debug_func_t debug_func;
	bt_bap_destroy_func_t debug_destroy;
	void *debug_data;
	void *user_data;
};

struct bt_bap_pac {
	struct bt_bap_db *bdb;
	char *name;
	uint8_t type;
	uint32_t locations;
	uint16_t contexts;
	struct bt_bap_codec codec;
	struct bt_bap_pac_qos qos;
	struct iovec *data;
	struct iovec *metadata;
	struct bt_bap_pac_ops *ops;
	void *user_data;
};

struct bt_bap_endpoint {
	struct bt_bap_db *bdb;
	struct bt_bap_stream *stream;
	struct gatt_db_attribute *attr;
	uint8_t id;
	uint8_t dir;
	uint8_t old_state;
	uint8_t state;
	unsigned int state_id;
};

struct bt_bap_stream_io {
	struct bt_bap *bap;
	int ref_count;
	struct io *io;
	bool connecting;
};

struct bt_bap_stream {
	struct bt_bap *bap;
	struct bt_bap_endpoint *ep;
	struct queue *pacs;
	struct bt_bap_pac *lpac;
	struct bt_bap_pac *rpac;
	struct iovec *cc;
	struct iovec *meta;
	struct bt_bap_qos qos;
	struct queue *links;
	struct bt_bap_stream_io *io;
	bool client;
	void *user_data;
};

/* TODO: Figure out the capabilities types */
#define BT_CODEC_CAP_PARAMS		0x01
#define BT_CODEC_CAP_DRM		0x0a
#define BT_CODEC_CAP_DRM_VALUE		0x0b

struct bt_pac_metadata {
	uint8_t  len;
	uint8_t  data[0];
} __packed;

struct bt_pac {
	struct bt_bap_codec codec;		/* Codec ID */
	uint8_t  cc_len;		/* Codec Capabilities Length */
	struct bt_ltv cc[0];		/* Codec Specific Capabilities */
	struct bt_pac_metadata meta[0];	/* Metadata */
} __packed;

struct bt_pacs_read_rsp {
	uint8_t  num_pac;
	struct bt_pac pac[0];
} __packed;

struct bt_pacs_context {
	uint16_t  snk;
	uint16_t  src;
} __packed;

/* Contains local bt_bap_db */
static struct queue *bap_db;
static struct queue *pac_cbs;
static struct queue *bap_cbs;
static struct queue *sessions;

static bool bap_db_match(const void *data, const void *match_data)
{
	const struct bt_bap_db *bdb = data;
	const struct gatt_db *db = match_data;

	return (bdb->db == db);
}

static void *iov_add(struct iovec *iov, size_t len)
{
	void *data;

	data = iov->iov_base + iov->iov_len;
	iov->iov_len += len;

	return data;
}

static void *iov_add_mem(struct iovec *iov, size_t len, const void *d)
{
	void *data;

	data = iov->iov_base + iov->iov_len;
	iov->iov_len += len;

	memcpy(data, d, len);

	return data;
}

static void iov_free(void *data)
{
	struct iovec *iov = data;

	if (!iov)
		return;

	free(iov->iov_base);
	free(iov);
}

static void iov_memcpy(struct iovec *iov, void *src, size_t len)
{
	iov->iov_base = realloc(iov->iov_base, len);
	iov->iov_len = len;
	memcpy(iov->iov_base, src, len);
}

static int iov_memcmp(struct iovec *iov1, struct iovec *iov2)
{
	if (!iov1)
		return 1;

	if (!iov2)
		return -1;

	if (iov1->iov_len != iov2->iov_len)
		return iov1->iov_len - iov2->iov_len;

	return memcmp(iov1->iov_base, iov2->iov_base, iov1->iov_len);
}

static struct iovec *iov_dup(struct iovec *iov, size_t len)
{
	struct iovec *dup;
	size_t i;

	if (!iov)
		return NULL;

	dup = new0(struct iovec, len);

	for (i = 0; i < len; i++)
		iov_memcpy(&dup[i], iov[i].iov_base, iov[i].iov_len);

	return dup;
}

unsigned int bt_bap_pac_register(bt_bap_pac_func_t added,
				bt_bap_pac_func_t removed, void *user_data,
				bt_bap_destroy_func_t destroy)
{
	struct bt_bap_pac_changed *changed;

	changed = new0(struct bt_bap_pac_changed, 1);
	changed->added = added;
	changed->removed = removed;
	changed->destroy = destroy;
	changed->data = user_data;

	if (!pac_cbs)
		pac_cbs = queue_new();

	queue_push_tail(pac_cbs, changed);

	return queue_length(pac_cbs);
}

static void pac_changed_free(void *data)
{
	struct bt_bap_pac_changed *changed = data;

	if (changed->destroy)
		changed->destroy(changed->data);

	free(changed);
}

struct match_pac_id {
	unsigned int id;
	unsigned int index;
};

static bool match_index(const void *data, const void *match_data)
{
	struct match_pac_id *match = (void *)match_data;

	match->index++;

	return match->id == match->index;
}

bool bt_bap_pac_unregister(unsigned int id)
{
	struct bt_bap_pac_changed *changed;
	struct match_pac_id match;

	memset(&match, 0, sizeof(match));
	match.id = id;

	changed = queue_remove_if(pac_cbs, match_index, &match);
	if (!changed)
		return false;

	pac_changed_free(changed);

	if (queue_isempty(pac_cbs)) {
		queue_destroy(pac_cbs, NULL);
		pac_cbs = NULL;
	}

	return true;
}

static void pac_foreach(void *data, void *user_data)
{
	struct bt_bap_pac *pac = data;
	struct iovec *iov = user_data;
	struct bt_pacs_read_rsp *rsp;
	struct bt_pac *p;
	struct bt_pac_metadata *meta;

	if (!iov->iov_len) {
		rsp = iov_add(iov, sizeof(*rsp));
		rsp->num_pac = 0;
	} else
		rsp = iov->iov_base;

	rsp->num_pac++;

	p = iov_add(iov, sizeof(*p));
	p->codec.id = pac->codec.id;

	if (pac->data) {
		p->cc_len = pac->data->iov_len;
		iov_add_mem(iov, p->cc_len, pac->data->iov_base);
	} else
		p->cc_len = 0;

	meta = iov_add(iov, sizeof(*meta));

	if (pac->metadata) {
		meta->len = pac->metadata->iov_len;
		iov_add_mem(iov, meta->len, pac->metadata->iov_base);
	} else
		meta->len = 0;
}

static void pacs_sink_read(struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				uint8_t opcode, struct bt_att *att,
				void *user_data)
{
	struct bt_pacs *pacs = user_data;
	struct bt_bap_db *bdb = pacs->bdb;
	struct iovec iov;
	uint8_t value[512];

	memset(value, 0, sizeof(value));

	iov.iov_base = value;
	iov.iov_len = 0;

	queue_foreach(bdb->sinks, pac_foreach, &iov);

	gatt_db_attribute_read_result(attrib, id, 0, iov.iov_base,
							iov.iov_len);
}

static void pacs_sink_loc_read(struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				uint8_t opcode, struct bt_att *att,
				void *user_data)
{
	uint32_t value = 0x00000003;

	gatt_db_attribute_read_result(attrib, id, 0, (void *) &value,
							sizeof(value));
}

static void pacs_source_read(struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				uint8_t opcode, struct bt_att *att,
				void *user_data)
{
	struct bt_pacs *pacs = user_data;
	struct bt_bap_db *bdb = pacs->bdb;
	struct iovec iov;
	uint8_t value[512];

	memset(value, 0, sizeof(value));

	iov.iov_base = value;
	iov.iov_len = 0;

	queue_foreach(bdb->sources, pac_foreach, &iov);

	gatt_db_attribute_read_result(attrib, id, 0, iov.iov_base,
							iov.iov_len);
}

static void pacs_source_loc_read(struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				uint8_t opcode, struct bt_att *att,
				void *user_data)
{
	uint32_t value = 0x00000001;

	gatt_db_attribute_read_result(attrib, id, 0, (void *) &value,
							sizeof(value));
}

static void pacs_context_read(struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				uint8_t opcode, struct bt_att *att,
				void *user_data)
{
	struct bt_pacs_context ctx = {
		.snk = 0x0fff,
		.src = 0x000e
	};

	gatt_db_attribute_read_result(attrib, id, 0, (void *) &ctx,
						sizeof(ctx));
}

static void pacs_supported_context_read(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct bt_pacs_context ctx = {
		.snk = 0x0fff,
		.src = 0x000e
	};

	gatt_db_attribute_read_result(attrib, id, 0, (void *) &ctx,
						sizeof(ctx));
}

static struct bt_pacs *pacs_new(struct gatt_db *db)
{
	struct bt_pacs *pacs;
	bt_uuid_t uuid;

	if (!db)
		return NULL;

	pacs = new0(struct bt_pacs, 1);

	/* Populate DB with PACS attributes */
	bt_uuid16_create(&uuid, PACS_UUID);
	pacs->service = gatt_db_add_service(db, &uuid, true, 19);

	bt_uuid16_create(&uuid, PAC_SINK_CHRC_UUID);
	pacs->sink = gatt_db_service_add_characteristic(pacs->service, &uuid,
					BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_NOTIFY,
					pacs_sink_read, NULL,
					pacs);

	pacs->sink_ccc = gatt_db_service_add_ccc(pacs->service,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, PAC_SINK_LOC_CHRC_UUID);
	pacs->sink_loc = gatt_db_service_add_characteristic(pacs->service,
					&uuid, BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_NOTIFY,
					pacs_sink_loc_read, NULL,
					pacs);

	pacs->sink_loc_ccc = gatt_db_service_add_ccc(pacs->service,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, PAC_SOURCE_CHRC_UUID);
	pacs->sink = gatt_db_service_add_characteristic(pacs->service, &uuid,
					BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_NOTIFY,
					pacs_source_read, NULL,
					pacs);

	pacs->sink_ccc = gatt_db_service_add_ccc(pacs->service,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, PAC_SOURCE_LOC_CHRC_UUID);
	pacs->source_loc = gatt_db_service_add_characteristic(pacs->service,
					&uuid, BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_NOTIFY,
					pacs_source_loc_read, NULL,
					pacs);

	pacs->source_loc_ccc = gatt_db_service_add_ccc(pacs->service,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, PAC_CONTEXT);
	pacs->context = gatt_db_service_add_characteristic(pacs->service,
					&uuid, BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_NOTIFY,
					pacs_context_read, NULL, pacs);

	pacs->context_ccc = gatt_db_service_add_ccc(pacs->service,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, PAC_SUPPORTED_CONTEXT);
	pacs->supported_context =
		gatt_db_service_add_characteristic(pacs->service, &uuid,
					BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_NOTIFY,
					pacs_supported_context_read, NULL,
					pacs);

	pacs->supported_context_ccc = gatt_db_service_add_ccc(pacs->service,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	gatt_db_service_set_active(pacs->service, true);

	return pacs;
}

static void bap_debug(struct bt_bap *bap, const char *format, ...)
{
	va_list ap;

	if (!bap || !format || !bap->debug_func)
		return;

	va_start(ap, format);
	util_debug_va(bap->debug_func, bap->debug_data, format, ap);
	va_end(ap);
}

static void bap_disconnected(int err, void *user_data)
{
	struct bt_bap *bap = user_data;

	bap->disconn_id = 0;

	DBG(bap, "bap %p disconnected err %d", bap, err);

	bt_bap_detach(bap);
}

static struct bt_bap *bap_get_session(struct bt_att *att, struct gatt_db *db)
{
	const struct queue_entry *entry;
	struct bt_bap *bap;

	for (entry = queue_get_entries(sessions); entry; entry = entry->next) {
		struct bt_bap *bap = entry->data;

		if (att == bt_bap_get_att(bap))
			return bap;
	}

	bap = bt_bap_new(db, NULL);
	bap->att = att;

	bt_bap_attach(bap, NULL);

	return bap;
}

static bool bap_endpoint_match(const void *data, const void *match_data)
{
	const struct bt_bap_endpoint *ep = data;
	const struct gatt_db_attribute *attr = match_data;

	return (ep->attr == attr);
}

static struct bt_bap_endpoint *bap_endpoint_new(struct bt_bap_db *bdb,
						struct gatt_db_attribute *attr)
{
	struct bt_bap_endpoint *ep;
	bt_uuid_t uuid, source, sink;

	if (!gatt_db_attribute_get_char_data(attr, NULL, NULL, NULL, NULL,
								&uuid))
		return NULL;

	ep = new0(struct bt_bap_endpoint, 1);
	ep->bdb = bdb;
	ep->attr = attr;

	bt_uuid16_create(&source, ASE_SOURCE_UUID);
	bt_uuid16_create(&sink, ASE_SINK_UUID);

	if (!bt_uuid_cmp(&source, &uuid))
		ep->dir = BT_BAP_SOURCE;
	else if (!bt_uuid_cmp(&sink, &uuid))
		ep->dir = BT_BAP_SINK;

	return ep;
}

static struct bt_bap_endpoint *bap_get_endpoint(struct bt_bap_db *db,
						struct gatt_db_attribute *attr)
{
	struct bt_bap_endpoint *ep;

	if (!db || !attr)
		return NULL;

	ep = queue_find(db->endpoints, bap_endpoint_match, attr);
	if (ep)
		return ep;

	ep = bap_endpoint_new(db, attr);
	if (!ep)
		return NULL;

	queue_push_tail(db->endpoints, ep);

	return ep;
}

static bool bap_endpoint_match_id(const void *data, const void *match_data)
{
	const struct bt_bap_endpoint *ep = data;
	uint8_t id = PTR_TO_UINT(match_data);

	return (ep->id == id);
}

static struct bt_bap_endpoint *bap_get_endpoint_id(struct bt_bap *bap,
						struct bt_bap_db *db,
						uint8_t id)
{
	struct bt_bap_endpoint *ep;
	struct gatt_db_attribute *attr = NULL;
	size_t i;

	if (!bap || !db)
		return NULL;

	ep = queue_find(db->endpoints, bap_endpoint_match_id, UINT_TO_PTR(id));
	if (ep)
		return ep;

	for (i = 0; i < ARRAY_SIZE(db->ascs->ase); i++) {
		struct bt_ase *ase = db->ascs->ase[i];

		if (id) {
			if (ase->id != id)
				continue;
			attr = ase->attr;
			break;
		}

		ep = queue_find(db->endpoints, bap_endpoint_match, ase->attr);
		if (!ep) {
			attr = ase->attr;
			break;
		}
	}

	if (!attr)
		return NULL;

	ep = bap_endpoint_new(db, attr);
	if (!ep)
		return NULL;

	ep->id = id;
	queue_push_tail(db->endpoints, ep);

	return ep;
}

static void ascs_ase_read(struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				uint8_t opcode, struct bt_att *att,
				void *user_data)
{
	struct bt_ase *ase = user_data;
	struct bt_bap *bap = bap_get_session(att, ase->ascs->bdb->db);
	struct bt_bap_endpoint *ep = bap_get_endpoint(bap->ldb, attrib);
	struct bt_ascs_ase_status rsp;

	if (!ase || !bap || !ep) {
		gatt_db_attribute_read_result(attrib, id, BT_ATT_ERROR_UNLIKELY,
								NULL, 0);
		return;
	}

	memset(&rsp, 0, sizeof(rsp));

	/* Initialize Endpoint ID with ASE ID */
	if (ase->id != ep->id)
		ep->id = ase->id;

	rsp.id = ep->id;
	rsp.state = ep->state;

	gatt_db_attribute_read_result(attrib, id, 0, (void *) &rsp,
							sizeof(rsp));
}

static void ase_new(struct bt_ascs *ascs, int i)
{
	struct bt_ase *ase;
	bt_uuid_t uuid;

	if (!ascs)
		return;

	ase = new0(struct bt_ase, 1);
	ase->ascs = ascs;
	ase->id = i + 1;

	bt_uuid16_create(&uuid, ASE_UUID(i));
	ase->attr = gatt_db_service_add_characteristic(ascs->service, &uuid,
					BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_NOTIFY,
					ascs_ase_read, NULL,
					ase);

	ase->ccc = gatt_db_service_add_ccc(ascs->service,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	ascs->ase[i] = ase;
}

static void *iov_pull_mem(struct iovec *iov, size_t len)
{
	void *data = iov->iov_base;

	if (iov->iov_len < len)
		return NULL;

	iov->iov_base += len;
	iov->iov_len -= len;

	return data;
}

static bool bap_codec_equal(const struct bt_bap_codec *c1,
				const struct bt_bap_codec *c2)
{
	/* Compare CID and VID if id is 0xff */
	if (c1->id == 0xff)
		return !memcmp(c1, c2, sizeof(*c1));

	return c1->id == c2->id;
}

static struct bt_bap_stream *bap_stream_new(struct bt_bap *bap,
						struct bt_bap_endpoint *ep,
						struct bt_bap_pac *lpac,
						struct bt_bap_pac *rpac,
						struct iovec *data,
						bool client)
{
	struct bt_bap_stream *stream;

	stream = new0(struct bt_bap_stream, 1);
	stream->bap = bap;
	stream->ep = ep;
	ep->stream = stream;
	stream->lpac = lpac;
	stream->rpac = rpac;
	stream->cc = iov_dup(data, 1);
	stream->client = client;

	queue_push_tail(bap->streams, stream);

	return stream;
}

static void stream_notify_config(struct bt_bap_stream *stream)
{
	struct bt_bap_endpoint *ep = stream->ep;
	struct bt_bap_pac *lpac = stream->lpac;
	struct bt_ascs_ase_status *status;
	struct bt_ascs_ase_status_config *config;
	size_t len;

	DBG(stream->bap, "stream %p", stream);

	len = sizeof(*status) + sizeof(*config) + stream->cc->iov_len;
	status = malloc(len);

	memset(status, 0, len);
	status->id = ep->id;
	status->state = ep->state;

	/* Initialize preffered settings if not set */
	if (!lpac->qos.phy)
		lpac->qos.phy = 0x02;

	if (!lpac->qos.rtn)
		lpac->qos.rtn = 0x05;

	if (!lpac->qos.latency)
		lpac->qos.latency = 10;

	if (!lpac->qos.pd_min)
		lpac->qos.pd_min = 20000;

	if (!lpac->qos.pd_max)
		lpac->qos.pd_max = 40000;

	if (!lpac->qos.ppd_min)
		lpac->qos.ppd_min = lpac->qos.pd_min;

	if (!lpac->qos.ppd_max)
		lpac->qos.ppd_max = lpac->qos.pd_max;

	/* TODO:Add support for setting preffered settings on bt_bap_pac */
	config = (void *)status->params;
	config->framing = lpac->qos.framing;
	config->phy = lpac->qos.phy;
	config->rtn = lpac->qos.rtn;
	config->latency = cpu_to_le16(lpac->qos.latency);
	put_le24(lpac->qos.pd_min, config->pd_min);
	put_le24(lpac->qos.pd_max, config->pd_max);
	put_le24(lpac->qos.ppd_min, config->ppd_min);
	put_le24(lpac->qos.ppd_max, config->ppd_max);
	config->codec = lpac->codec;
	config->cc_len = stream->cc->iov_len;
	memcpy(config->cc, stream->cc->iov_base, stream->cc->iov_len);

	gatt_db_attribute_notify(ep->attr, (void *) status, len,
					bt_bap_get_att(stream->bap));

	free(status);
}

static void stream_notify_qos(struct bt_bap_stream *stream)
{
	struct bt_bap_endpoint *ep = stream->ep;
	struct bt_ascs_ase_status *status;
	struct bt_ascs_ase_status_qos *qos;
	size_t len;

	DBG(stream->bap, "stream %p", stream);

	len = sizeof(*status) + sizeof(*qos);
	status = malloc(len);

	memset(status, 0, len);
	status->id = ep->id;
	status->state = ep->state;

	qos = (void *)status->params;
	qos->cis_id = stream->qos.cis_id;
	qos->cig_id = stream->qos.cig_id;
	put_le24(stream->qos.interval, qos->interval);
	qos->framing = stream->qos.framing;
	qos->phy = stream->qos.phy;
	qos->sdu = cpu_to_le16(stream->qos.sdu);
	qos->rtn = stream->qos.rtn;
	qos->latency = cpu_to_le16(stream->qos.latency);
	put_le24(stream->qos.delay, qos->pd);

	gatt_db_attribute_notify(ep->attr, (void *) status, len,
					bt_bap_get_att(stream->bap));

	free(status);
}

static void stream_notify_metadata(struct bt_bap_stream *stream)
{
	struct bt_bap_endpoint *ep = stream->ep;
	struct bt_ascs_ase_status *status;
	struct bt_ascs_ase_status_metadata *meta;
	size_t len;
	size_t meta_len = 0;

	DBG(stream->bap, "stream %p", stream);

	if (stream->meta)
		meta_len = stream->meta->iov_len;

	len = sizeof(*status) + sizeof(*meta) + meta_len;
	status = malloc(len);

	memset(status, 0, len);
	status->id = ep->id;
	status->state = ep->state;

	meta = (void *)status->params;
	meta->cis_id = stream->qos.cis_id;
	meta->cig_id = stream->qos.cig_id;

	if (stream->meta) {
		meta->len = stream->meta->iov_len;
		memcpy(meta->data, stream->meta->iov_base, meta->len);
	}

	gatt_db_attribute_notify(ep->attr, (void *) status, len,
					bt_bap_get_att(stream->bap));

	free(status);
}

static void bap_stream_clear_cfm(struct bt_bap_stream *stream)
{
	if (!stream->lpac->ops || !stream->lpac->ops->clear)
		return;

	stream->lpac->ops->clear(stream, stream->lpac->user_data);
}

static int stream_io_get_fd(struct bt_bap_stream_io *io)
{
	if (!io)
		return -1;

	return io_get_fd(io->io);
}

static void stream_io_free(void *data)
{
	struct bt_bap_stream_io *io = data;
	int fd;

	fd = stream_io_get_fd(io);

	DBG(io->bap, "fd %d", fd);

	io_destroy(io->io);
	free(io);

	/* Shutdown using SHUT_WR as SHUT_RDWR cause the socket to HUP
	 * immediately instead of waiting for Disconnect Complete event.
	 */
	shutdown(fd, SHUT_WR);
}

static void stream_io_unref(struct bt_bap_stream_io *io)
{
	if (!io)
		return;

	if (__sync_sub_and_fetch(&io->ref_count, 1))
		return;

	stream_io_free(io);
}

static void bap_stream_unlink(void *data, void *user_data)
{
	struct bt_bap_stream *link = data;
	struct bt_bap_stream *stream = user_data;

	queue_remove(link->links, stream);
}

static void bap_stream_free(void *data)
{
	struct bt_bap_stream *stream = data;

	if (stream->ep)
		stream->ep->stream = NULL;

	queue_foreach(stream->links, bap_stream_unlink, stream);
	queue_destroy(stream->links, NULL);
	stream_io_unref(stream->io);
	iov_free(stream->cc);
	iov_free(stream->meta);
	free(stream);
}

static void bap_stream_detach(struct bt_bap_stream *stream)
{
	struct bt_bap_endpoint *ep = stream->ep;

	if (!ep)
		return;

	DBG(stream->bap, "stream %p ep %p", stream, ep);

	queue_remove(stream->bap->streams, stream);
	bap_stream_clear_cfm(stream);

	stream->ep = NULL;
	ep->stream = NULL;
	bap_stream_free(stream);
}

static void bap_stream_io_link(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	struct bt_bap_stream *link = user_data;

	bt_bap_stream_io_link(stream, link);
}

static void bap_stream_update_io_links(struct bt_bap_stream *stream)
{
	struct bt_bap *bap = stream->bap;

	DBG(bap, "stream %p", stream);

	queue_foreach(bap->streams, bap_stream_io_link, stream);
}

static struct bt_bap_stream_io *stream_io_ref(struct bt_bap_stream_io *io)
{
	if (!io)
		return NULL;

	__sync_fetch_and_add(&io->ref_count, 1);

	return io;
}

static struct bt_bap_stream_io *stream_io_new(struct bt_bap *bap, int fd)
{
	struct io *io;
	struct bt_bap_stream_io *sio;

	io = io_new(fd);
	if (!io)
		return NULL;

	DBG(bap, "fd %d", fd);

	sio = new0(struct bt_bap_stream_io, 1);
	sio->bap = bap;
	sio->io = io;

	return stream_io_ref(sio);
}

static void stream_find_io(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	struct bt_bap_stream_io **io = user_data;

	if (*io)
		return;

	*io = stream->io;
}

static struct bt_bap_stream_io *stream_get_io(struct bt_bap_stream *stream)
{
	struct bt_bap_stream_io *io;

	if (!stream)
		return NULL;

	if (stream->io)
		return stream->io;

	io = NULL;
	queue_foreach(stream->links, stream_find_io, &io);

	return io;
}

static bool stream_io_disconnected(struct io *io, void *user_data);

static bool bap_stream_io_attach(struct bt_bap_stream *stream, int fd,
							bool connecting)
{
	struct bt_bap_stream_io *io;

	io = stream_get_io(stream);
	if (io) {
		if (fd == stream_io_get_fd(io)) {
			if (!stream->io)
				stream->io = stream_io_ref(io);

			io->connecting = connecting;
			return true;
		}

		DBG(stream->bap, "stream %p io already set", stream);
		return false;
	}

	DBG(stream->bap, "stream %p connecting %s", stream,
				connecting ? "true" : "false");

	io = stream_io_new(stream->bap, fd);
	if (!io)
		return false;

	io->connecting = connecting;
	stream->io = io;
	io_set_disconnect_handler(io->io, stream_io_disconnected, stream, NULL);

	return true;
}

static bool match_stream_io(const void *data, const void *user_data)
{
	const struct bt_bap_stream *stream = data;
	const struct bt_bap_stream_io *io = user_data;

	if (!stream->io)
		return false;

	return stream->io == io;
}

static bool bap_stream_io_detach(struct bt_bap_stream *stream)
{
	struct bt_bap_stream *link;
	struct bt_bap_stream_io *io;

	if (!stream->io)
		return false;

	DBG(stream->bap, "stream %p", stream);

	io = stream->io;
	stream->io = NULL;

	link = queue_find(stream->links, match_stream_io, io);
	if (link) {
		/* Detach link if in QoS state */
		if (link->ep->state == BT_ASCS_ASE_STATE_QOS)
			bap_stream_io_detach(link);
	}

	stream_io_unref(io);

	return true;
}

static void bap_stream_set_io(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	int fd = PTR_TO_INT(user_data);
	bool ret;

	if (fd >= 0)
		ret = bap_stream_io_attach(stream, fd, false);
	else
		ret = bap_stream_io_detach(stream);

	if (!ret)
		return;

	switch (stream->ep->state) {
	case BT_BAP_STREAM_STATE_ENABLING:
		if (fd < 0)
			bt_bap_stream_disable(stream, false, NULL, NULL);
		else
			bt_bap_stream_start(stream, NULL, NULL);
		break;
	case BT_BAP_STREAM_STATE_DISABLING:
		if (fd < 0)
			bt_bap_stream_stop(stream, NULL, NULL);
		break;
	}
}

static void bap_stream_state_changed(struct bt_bap_stream *stream)
{
	struct bt_bap *bap = stream->bap;
	const struct queue_entry *entry;

	DBG(bap, "stream %p dir 0x%02x: %s -> %s", stream,
			bt_bap_stream_get_dir(stream),
			bt_bap_stream_statestr(stream->ep->old_state),
			bt_bap_stream_statestr(stream->ep->state));

	bt_bap_ref(bap);

	/* Pre notification updates */
	switch (stream->ep->state) {
	case BT_ASCS_ASE_STATE_IDLE:
		break;
	case BT_ASCS_ASE_STATE_CONFIG:
		bap_stream_update_io_links(stream);
		break;
	case BT_ASCS_ASE_STATE_DISABLING:
		bap_stream_io_detach(stream);
		break;
	case BT_ASCS_ASE_STATE_QOS:
		if (stream->io && !stream->io->connecting)
			bap_stream_io_detach(stream);
		else
			bap_stream_update_io_links(stream);
		break;
	case BT_ASCS_ASE_STATE_ENABLING:
	case BT_ASCS_ASE_STATE_STREAMING:
		break;
	}

	for (entry = queue_get_entries(bap->state_cbs); entry;
							entry = entry->next) {
		struct bt_bap_state *state = entry->data;

		if (state->func)
			state->func(stream, stream->ep->old_state,
					stream->ep->state, state->data);
	}

	/* Post notification updates */
	switch (stream->ep->state) {
	case BT_ASCS_ASE_STATE_IDLE:
		bap_stream_detach(stream);
		break;
	case BT_ASCS_ASE_STATE_QOS:
		break;
	case BT_ASCS_ASE_STATE_ENABLING:
		if (bt_bap_stream_get_io(stream))
			bt_bap_stream_start(stream, NULL, NULL);
		break;
	case BT_ASCS_ASE_STATE_DISABLING:
		if (!bt_bap_stream_get_io(stream))
			bt_bap_stream_stop(stream, NULL, NULL);
		break;
	}

	bt_bap_unref(bap);
}

static void stream_set_state(struct bt_bap_stream *stream, uint8_t state)
{
	struct bt_bap_endpoint *ep = stream->ep;

	ep->old_state = ep->state;
	ep->state = state;

	if (stream->client)
		goto done;

	switch (ep->state) {
	case BT_ASCS_ASE_STATE_IDLE:
		break;
	case BT_ASCS_ASE_STATE_CONFIG:
		stream_notify_config(stream);
		break;
	case BT_ASCS_ASE_STATE_QOS:
		stream_notify_qos(stream);
		break;
	case BT_ASCS_ASE_STATE_ENABLING:
	case BT_ASCS_ASE_STATE_STREAMING:
	case BT_ASCS_ASE_STATE_DISABLING:
		stream_notify_metadata(stream);
		break;
	}

done:
	bap_stream_state_changed(stream);
}

static void ascs_ase_rsp_add(struct iovec *iov, uint8_t id,
					uint8_t code, uint8_t reason)
{
	struct bt_ascs_cp_rsp *cp;
	struct bt_ascs_ase_rsp *rsp;

	if (!iov)
		return;

	cp = iov->iov_base;

	if (cp->num_ase == 0xff)
		return;

	switch (code) {
	/* If the Response_Code value is 0x01 or 0x02, Number_of_ASEs shall be
	 * set to 0xFF.
	 */
	case BT_ASCS_RSP_NOT_SUPPORTED:
	case BT_ASCS_RSP_TRUNCATED:
		cp->num_ase = 0xff;
		break;
	default:
		cp->num_ase++;
		break;
	}

	iov->iov_len += sizeof(*rsp);
	iov->iov_base = realloc(iov->iov_base, iov->iov_len);

	rsp = iov->iov_base + (iov->iov_len - sizeof(*rsp));
	rsp->ase = id;
	rsp->code = code;
	rsp->reason = reason;
}

static void ascs_ase_rsp_add_errno(struct iovec *iov, uint8_t id, int err)
{
	struct bt_ascs_cp_rsp *rsp = iov->iov_base;

	switch (err) {
	case -ENOBUFS:
	case -ENOMEM:
		return ascs_ase_rsp_add(iov, id, BT_ASCS_RSP_NO_MEM,
						BT_ASCS_REASON_NONE);
	case -EINVAL:
		switch (rsp->op) {
		case BT_ASCS_CONFIG:
		/* Fallthrough */
		case BT_ASCS_QOS:
			return ascs_ase_rsp_add(iov, id,
						BT_ASCS_RSP_CONF_INVALID,
						BT_ASCS_REASON_NONE);
		case BT_ASCS_ENABLE:
		/* Fallthrough */
		case BT_ASCS_METADATA:
			return ascs_ase_rsp_add(iov, id,
						BT_ASCS_RSP_METADATA_INVALID,
						BT_ASCS_REASON_NONE);
		default:
			return ascs_ase_rsp_add(iov, id,
						BT_ASCS_RSP_UNSPECIFIED,
						BT_ASCS_REASON_NONE);
		}
	case -ENOTSUP:
		switch (rsp->op) {
		case BT_ASCS_CONFIG:
		/* Fallthrough */
		case BT_ASCS_QOS:
			return ascs_ase_rsp_add(iov, id,
						BT_ASCS_RSP_CONF_UNSUPPORTED,
						BT_ASCS_REASON_NONE);
		case BT_ASCS_ENABLE:
		/* Fallthrough */
		case BT_ASCS_METADATA:
			return ascs_ase_rsp_add(iov, id,
					BT_ASCS_RSP_METADATA_UNSUPPORTED,
					BT_ASCS_REASON_NONE);
		default:
			return ascs_ase_rsp_add(iov, id,
						BT_ASCS_RSP_NOT_SUPPORTED,
						BT_ASCS_REASON_NONE);
		}
	case -EBADMSG:
		return ascs_ase_rsp_add(iov, id, BT_ASCS_RSP_INVALID_ASE_STATE,
						BT_ASCS_REASON_NONE);
	case -ENOMSG:
		return ascs_ase_rsp_add(iov, id, BT_ASCS_RSP_TRUNCATED,
						BT_ASCS_REASON_NONE);
	default:
		return ascs_ase_rsp_add(iov, id, BT_ASCS_RSP_UNSPECIFIED,
						BT_ASCS_REASON_NONE);
	}
}

static void ascs_ase_rsp_success(struct iovec *iov, uint8_t id)
{
	return ascs_ase_rsp_add(iov, id, BT_ASCS_RSP_SUCCESS,
					BT_ASCS_REASON_NONE);
}

static void ep_config_cb(struct bt_bap_stream *stream, int err)
{
	if (err)
		return;

	stream_set_state(stream, BT_BAP_STREAM_STATE_CONFIG);
}

static uint8_t stream_config(struct bt_bap_stream *stream, struct iovec *cc,
							struct iovec *rsp)
{
	struct bt_bap_pac *pac = stream->lpac;

	DBG(stream->bap, "stream %p", stream);

	/* TODO: Wait for pac->ops response */
	ascs_ase_rsp_success(rsp, stream->ep->id);

	if (!iov_memcmp(stream->cc, cc)) {
		stream_set_state(stream, BT_BAP_STREAM_STATE_CONFIG);
		return 0;
	}

	iov_free(stream->cc);
	stream->cc = iov_dup(cc, 1);

	if (pac->ops && pac->ops->config)
		pac->ops->config(stream, cc, NULL, ep_config_cb,
						pac->user_data);

	return 0;
}

static uint8_t ep_config(struct bt_bap_endpoint *ep, struct bt_bap *bap,
				 struct bt_ascs_config *req,
				 struct iovec *iov, struct iovec *rsp)
{
	struct iovec cc;
	const struct queue_entry *e;

	DBG(bap, "ep %p id 0x%02x dir 0x%02x", ep, ep->id, ep->dir);

	switch (ep->state) {
	/* Valid only if ASE_State field = 0x00 (Idle) */
	case BT_ASCS_ASE_STATE_IDLE:
	 /* or 0x01 (Codec Configured) */
	case BT_ASCS_ASE_STATE_CONFIG:
	 /* or 0x02 (QoS Configured) */
	case BT_ASCS_ASE_STATE_QOS:
		break;
	default:
		DBG(bap, "Invalid state %s", bt_bap_stream_statestr(ep->state));
		ascs_ase_rsp_add(rsp, req->ase,
				BT_ASCS_RSP_INVALID_ASE_STATE,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	if (iov->iov_len < req->cc_len)
		return BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;

	cc.iov_base = iov_pull_mem(iov, req->cc_len);
	cc.iov_len = req->cc_len;

	if (!bap_print_cc(cc.iov_base, cc.iov_len, bap->debug_func,
						bap->debug_data)) {
		ascs_ase_rsp_add(rsp, req->ase,
				BT_ASCS_RSP_CONF_INVALID,
				BT_ASCS_REASON_CODEC_DATA);
		return 0;
	}

	switch (ep->dir) {
	case BT_BAP_SINK:
		e = queue_get_entries(bap->ldb->sinks);
		break;
	case BT_BAP_SOURCE:
		e = queue_get_entries(bap->ldb->sources);
		break;
	default:
		e = NULL;
	}

	for (; e; e = e->next) {
		struct bt_bap_pac *pac = e->data;

		if (!bap_codec_equal(&req->codec, &pac->codec))
			continue;

		if (!ep->stream)
			ep->stream = bap_stream_new(bap, ep, pac, NULL, NULL,
									false);

		break;
	}

	if (!e) {
		ascs_ase_rsp_add(rsp, req->ase,
				BT_ASCS_RSP_CONF_INVALID,
				BT_ASCS_REASON_CODEC);
		return 0;
	}

	return stream_config(ep->stream, &cc, rsp);
}

static uint8_t ascs_config(struct bt_ascs *ascs, struct bt_bap *bap,
				struct iovec *iov, struct iovec *rsp)
{
	struct bt_bap_endpoint *ep;
	struct bt_ascs_config *req;

	req = iov_pull_mem(iov, sizeof(*req));

	DBG(bap, "codec 0x%02x phy 0x%02x latency %u", req->codec.id, req->phy,
							req->latency);

	ep = bap_get_endpoint_id(bap, bap->ldb, req->ase);
	if (!ep) {
		DBG(bap, "Invalid ASE ID 0x%02x", req->ase);
		ascs_ase_rsp_add(rsp, req->ase,
				BT_ASCS_RSP_INVALID_ASE, BT_ASCS_REASON_NONE);
		return 0;
	}

	return ep_config(ep, bap, req, iov, rsp);
}

static uint8_t stream_qos(struct bt_bap_stream *stream, struct bt_bap_qos *qos,
							struct iovec *rsp)
{
	DBG(stream->bap, "stream %p", stream);

	ascs_ase_rsp_success(rsp, stream->ep->id);

	if (memcmp(&stream->qos, qos, sizeof(*qos)))
		stream->qos = *qos;

	stream_set_state(stream, BT_BAP_STREAM_STATE_QOS);

	return 0;
}

static uint8_t ep_qos(struct bt_bap_endpoint *ep, struct bt_bap *bap,
			 struct bt_bap_qos *qos, struct iovec *rsp)
{
	DBG(bap, "ep %p id 0x%02x dir 0x%02x", ep, ep->id, ep->dir);

	switch (ep->state) {
	/* Valid only if ASE_State field = 0x01 (Codec Configured) */
	case BT_ASCS_ASE_STATE_CONFIG:
	 /* or 0x02 (QoS Configured) */
	case BT_ASCS_ASE_STATE_QOS:
		break;
	default:
		DBG(bap, "Invalid state %s", bt_bap_stream_statestr(ep->state));
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_ASE_STATE,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	if (!ep->stream) {
		DBG(bap, "No stream found");
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_ASE_STATE,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	return stream_qos(ep->stream, qos, rsp);
}

static uint8_t ascs_qos(struct bt_ascs *ascs, struct bt_bap *bap,
					struct iovec *iov, struct iovec *rsp)
{
	struct bt_bap_endpoint *ep;
	struct bt_ascs_qos *req;
	struct bt_bap_qos qos;

	req = iov_pull_mem(iov, sizeof(*req));

	memset(&qos, 0, sizeof(qos));

	qos.cig_id = req->cig;
	qos.cis_id = req->cis;
	qos.interval = get_le24(req->interval);
	qos.framing = req->framing;
	qos.phy = req->phy;
	qos.sdu = le16_to_cpu(req->sdu);
	qos.rtn = req->rtn;
	qos.latency = le16_to_cpu(req->latency);
	qos.delay = get_le24(req->pd);

	DBG(bap, "CIG 0x%02x CIS 0x%02x interval %u framing 0x%02x "
			"phy 0x%02x SDU %u rtn %u latency %u pd %u",
			req->cig, req->cis, qos.interval, qos.framing, qos.phy,
			qos.sdu, qos.rtn, qos.latency, qos.delay);

	ep = bap_get_endpoint_id(bap, bap->ldb, req->ase);
	if (!ep) {
		DBG(bap, "%s: Invalid ASE ID 0x%02x", req->ase);
		ascs_ase_rsp_add(rsp, req->ase,
				BT_ASCS_RSP_INVALID_ASE, BT_ASCS_REASON_NONE);
		return 0;
	}

	return ep_qos(ep, bap, &qos, rsp);
}

static uint8_t stream_enable(struct bt_bap_stream *stream, struct iovec *meta,
							struct iovec *rsp)
{
	DBG(stream->bap, "stream %p", stream);

	ascs_ase_rsp_success(rsp, stream->ep->id);

	iov_free(stream->meta);
	stream->meta = iov_dup(meta, 1);

	stream_set_state(stream, BT_BAP_STREAM_STATE_ENABLING);

	/* Sink can autonomously for to Streaming state if io already exits */
	if (stream->io && stream->ep->dir == BT_BAP_SINK)
		stream_set_state(stream, BT_BAP_STREAM_STATE_STREAMING);

	return 0;
}

static bool bap_print_ltv(const char *label, void *data, size_t len,
				util_debug_func_t func, void *user_data)
{
	struct iovec iov = {
		.iov_base = data,
		.iov_len = len,
	};
	int i;

	util_debug(func, user_data, "Length %zu", iov.iov_len);

	for (i = 0; iov.iov_len > 1; i++) {
		struct bt_ltv *ltv = iov_pull_mem(&iov, sizeof(*ltv));
		uint8_t *data;

		if (!ltv) {
			util_debug(func, user_data, "Unable to parse %s",
								label);
			return false;
		}

		util_debug(func, user_data, "%s #%u: len %u type %u",
					label, i, ltv->len, ltv->type);

		data = iov_pull_mem(&iov, ltv->len - 1);
		if (!data) {
			util_debug(func, user_data, "Unable to parse %s",
								label);
			return false;
		}

		util_hexdump(' ', ltv->value, ltv->len - 1, func, user_data);
	}

	return true;
}

static bool bap_print_metadata(void *data, size_t len, util_debug_func_t func,
						void *user_data)
{
	return bap_print_ltv("Metadata", data, len, func, user_data);
}

static uint8_t ep_enable(struct bt_bap_endpoint *ep, struct bt_bap *bap,
			struct bt_ascs_enable *req, struct iovec *iov,
			struct iovec *rsp)
{
	struct iovec meta;

	DBG(bap, "ep %p id 0x%02x dir 0x%02x", ep, ep->id, ep->dir);

	switch (ep->state) {
	/* Valid only if ASE_State field = 0x02 (QoS Configured) */
	case BT_ASCS_ASE_STATE_QOS:
		break;
	default:
		DBG(bap, "Invalid state %s", bt_bap_stream_statestr(ep->state));
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_ASE_STATE,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	meta.iov_base = iov_pull_mem(iov, req->meta.len);
	meta.iov_len = req->meta.len;

	if (!bap_print_metadata(meta.iov_base, meta.iov_len, bap->debug_func,
							bap->debug_data)) {
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_METADATA_INVALID,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	if (!ep->stream) {
		DBG(bap, "No stream found");
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_ASE_STATE,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	return stream_enable(ep->stream, &meta, rsp);
}

static uint8_t ascs_enable(struct bt_ascs *ascs, struct bt_bap *bap,
				struct iovec *iov, struct iovec *rsp)
{
	struct bt_bap_endpoint *ep;
	struct bt_ascs_enable *req;

	req = iov_pull_mem(iov, sizeof(*req));

	ep = bap_get_endpoint_id(bap, bap->ldb, req->meta.ase);
	if (!ep) {
		DBG(bap, "Invalid ASE ID 0x%02x", req->meta.ase);
		ascs_ase_rsp_add(rsp, req->meta.ase,
				BT_ASCS_RSP_INVALID_ASE, BT_ASCS_REASON_NONE);
		return 0;
	}

	return ep_enable(ep, bap, req, iov, rsp);
}

static uint8_t stream_start(struct bt_bap_stream *stream, struct iovec *rsp)
{
	DBG(stream->bap, "stream %p", stream);

	ascs_ase_rsp_success(rsp, stream->ep->id);

	stream_set_state(stream, BT_BAP_STREAM_STATE_STREAMING);

	return 0;
}

static uint8_t ep_start(struct bt_bap_endpoint *ep, struct iovec *rsp)
{
	struct bt_bap_stream *stream = ep->stream;

	DBG(stream->bap, "ep %p id 0x%02x dir 0x%02x", ep, ep->id, ep->dir);

	switch (ep->state) {
	/* Valid only if ASE_State field = 0x03 (Enabling) */
	case BT_ASCS_ASE_STATE_ENABLING:
		break;
	default:
		DBG(ep->stream->bap, "Invalid state %s",
				bt_bap_stream_statestr(ep->state));
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_ASE_STATE,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	/* If the ASE_ID  written by the client represents a Sink ASE, the
	 * server shall not accept the Receiver Start Ready operation for that
	 * ASE. The server shall send a notification of the ASE Control Point
	 * characteristic to the client, and the server shall set the
	 * Response_Code value for that ASE to 0x05 (Invalid ASE direction).
	 */
	if (ep->dir == BT_BAP_SINK) {
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_DIR, BT_ASCS_REASON_NONE);
		return 0;
	}

	return stream_start(ep->stream, rsp);
}

static uint8_t ascs_start(struct bt_ascs *ascs, struct bt_bap *bap,
				struct iovec *iov, struct iovec *rsp)
{
	struct bt_bap_endpoint *ep;
	struct bt_ascs_start *req;

	req = iov_pull_mem(iov, sizeof(*req));

	ep = bap_get_endpoint_id(bap, bap->ldb, req->ase);
	if (!ep) {
		DBG(bap, "Invalid ASE ID 0x%02x", req->ase);
		ascs_ase_rsp_add(rsp, req->ase,
				BT_ASCS_RSP_INVALID_ASE, BT_ASCS_REASON_NONE);
		return 0;
	}

	if (!ep->stream) {
		DBG(bap, "No stream found for %p", ep);
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_ASE_STATE,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	return ep_start(ep, rsp);
}

static uint8_t stream_disable(struct bt_bap_stream *stream, struct iovec *rsp)
{
	DBG(stream->bap, "stream %p", stream);

	if (!stream || stream->ep->state == BT_BAP_STREAM_STATE_QOS ||
			stream->ep->state == BT_BAP_STREAM_STATE_IDLE)
		return 0;

	ascs_ase_rsp_success(rsp, stream->ep->id);

	/* Sink can autonomously transit to QOS while source needs to go to
	 * Disabling until BT_ASCS_STOP is received.
	 */
	if (stream->ep->dir == BT_BAP_SINK)
		stream_set_state(stream, BT_BAP_STREAM_STATE_QOS);
	else
		stream_set_state(stream, BT_BAP_STREAM_STATE_DISABLING);

	return 0;
}

static uint8_t ep_disable(struct bt_bap_endpoint *ep, struct iovec *rsp)
{
	struct bt_bap_stream *stream = ep->stream;

	DBG(stream->bap, "ep %p id 0x%02x dir 0x%02x", ep, ep->id, ep->dir);

	switch (ep->state) {
	/* Valid only if ASE_State field = 0x03 (Enabling) */
	case BT_ASCS_ASE_STATE_ENABLING:
	 /* or 0x04 (Streaming) */
	case BT_ASCS_ASE_STATE_STREAMING:
		break;
	default:
		DBG(stream->bap, "Invalid state %s",
				bt_bap_stream_statestr(ep->state));
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_ASE_STATE,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	return stream_disable(ep->stream, rsp);
}

static uint8_t ascs_disable(struct bt_ascs *ascs, struct bt_bap *bap,
				struct iovec *iov, struct iovec *rsp)
{
	struct bt_bap_endpoint *ep;
	struct bt_ascs_disable *req;

	req = iov_pull_mem(iov, sizeof(*req));

	ep = bap_get_endpoint_id(bap, bap->ldb, req->ase);
	if (!ep) {
		DBG(bap, "Invalid ASE ID 0x%02x", req->ase);
		ascs_ase_rsp_add(rsp, req->ase,
				BT_ASCS_RSP_INVALID_ASE, BT_ASCS_REASON_NONE);
		return 0;
	}

	if (!ep->stream) {
		DBG(bap, "No stream found");
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_ASE_STATE,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	return ep_disable(ep, rsp);
}

static uint8_t stream_stop(struct bt_bap_stream *stream, struct iovec *rsp)
{
	DBG(stream->bap, "stream %p", stream);

	if (!stream)
		return 0;

	ascs_ase_rsp_success(rsp, stream->ep->id);

	stream_set_state(stream, BT_BAP_STREAM_STATE_QOS);

	return 0;
}

static uint8_t ep_stop(struct bt_bap_endpoint *ep, struct iovec *rsp)
{
	struct bt_bap_stream *stream = ep->stream;

	DBG(stream->bap, "ep %p id 0x%02x dir 0x%02x", ep, ep->id, ep->dir);

	switch (ep->state) {
	/* Valid only if ASE_State field = 0x05 (Disabling) */
	case BT_ASCS_ASE_STATE_DISABLING:
		break;
	default:
		DBG(stream->bap, "Invalid state %s",
				bt_bap_stream_statestr(ep->state));
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_ASE_STATE,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	/* If the ASE_ID  written by the client represents a Sink ASE, the
	 * server shall not accept the Receiver Stop Ready operation for that
	 * ASE. The server shall send a notification of the ASE Control Point
	 * characteristic to the client, and the server shall set the
	 * Response_Code value for that ASE to 0x05 (Invalid ASE direction).
	 */
	if (ep->dir == BT_BAP_SINK) {
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_DIR, BT_ASCS_REASON_NONE);
		return 0;
	}

	return stream_stop(ep->stream, rsp);
}

static uint8_t ascs_stop(struct bt_ascs *ascs, struct bt_bap *bap,
				struct iovec *iov, struct iovec *rsp)
{
	struct bt_bap_endpoint *ep;
	struct bt_ascs_stop *req;

	req = iov_pull_mem(iov, sizeof(*req));

	ep = bap_get_endpoint_id(bap, bap->ldb, req->ase);
	if (!ep) {
		DBG(bap, "Invalid ASE ID 0x%02x", req->ase);
		ascs_ase_rsp_add(rsp, req->ase,
				BT_ASCS_RSP_INVALID_ASE, BT_ASCS_REASON_NONE);
		return 0;
	}

	if (!ep->stream) {
		DBG(bap, "No stream found");
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_ASE_STATE,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	return ep_stop(ep, rsp);
}

static uint8_t stream_metadata(struct bt_bap_stream *stream, struct iovec *meta,
						struct iovec *rsp)
{
	DBG(stream->bap, "stream %p", stream);

	ascs_ase_rsp_success(rsp, stream->ep->id);

	iov_free(stream->meta);
	stream->meta = iov_dup(meta, 1);

	return 0;
}

static uint8_t ep_metadata(struct bt_bap_endpoint *ep, struct iovec *meta,
						struct iovec *rsp)
{
	struct bt_bap_stream *stream = ep->stream;

	DBG(stream->bap, "ep %p id 0x%02x dir 0x%02x", ep, ep->id, ep->dir);

	switch (ep->state) {
	/* Valid only if ASE_State field = 0x03 (Enabling) */
	case BT_ASCS_ASE_STATE_ENABLING:
	 /* or 0x04 (Streaming) */
	case BT_ASCS_ASE_STATE_STREAMING:
		break;
	default:
		DBG(stream->bap, "Invalid state %s",
				bt_bap_stream_statestr(ep->state));
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_ASE_STATE,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	return stream_metadata(ep->stream, meta, rsp);
}

static uint8_t ascs_metadata(struct bt_ascs *ascs, struct bt_bap *bap,
				struct iovec *iov, struct iovec *rsp)
{
	struct bt_bap_endpoint *ep;
	struct bt_ascs_metadata *req;

	req = iov_pull_mem(iov, sizeof(*req));

	ep = bap_get_endpoint_id(bap, bap->ldb, req->ase);
	if (!ep) {
		DBG(bap, "Invalid ASE ID 0x%02x", req->ase);
		ascs_ase_rsp_add(rsp, req->ase,
				BT_ASCS_RSP_INVALID_ASE, BT_ASCS_REASON_NONE);
		return 0;
	}

	if (!ep->stream) {
		DBG(bap, "No stream found");
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_ASE_STATE,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	return ep_metadata(ep, iov, rsp);
}

static uint8_t stream_release(struct bt_bap_stream *stream, struct iovec *rsp)
{
	struct bt_bap_pac *pac;

	DBG(stream->bap, "stream %p", stream);

	ascs_ase_rsp_success(rsp, stream->ep->id);

	pac = stream->lpac;
	if (pac->ops && pac->ops->clear)
		pac->ops->clear(stream, pac->user_data);

	stream_set_state(stream, BT_BAP_STREAM_STATE_IDLE);

	return 0;
}

static uint8_t ascs_release(struct bt_ascs *ascs, struct bt_bap *bap,
				struct iovec *iov, struct iovec *rsp)
{
	struct bt_bap_endpoint *ep;
	struct bt_ascs_release *req;

	req = iov_pull_mem(iov, sizeof(*req));

	ep = bap_get_endpoint_id(bap, bap->ldb, req->ase);
	if (!ep) {
		DBG(bap, "Invalid ASE ID 0x%02x", req->ase);
		ascs_ase_rsp_add(rsp, req->ase,
				BT_ASCS_RSP_INVALID_ASE, BT_ASCS_REASON_NONE);
		return 0;
	}

	if (!ep->stream) {
		DBG(bap, "No stream found");
		ascs_ase_rsp_add(rsp, ep->id,
				BT_ASCS_RSP_INVALID_ASE_STATE,
				BT_ASCS_REASON_NONE);
		return 0;
	}

	return stream_release(ep->stream, rsp);
}

#define ASCS_OP(_str, _op, _size, _func) \
	{ \
		.str = _str, \
		.op = _op, \
		.size = _size, \
		.func = _func, \
	}

struct ascs_op_handler {
	const char *str;
	uint8_t  op;
	size_t   size;
	uint8_t  (*func)(struct bt_ascs *ascs, struct bt_bap *bap,
			struct iovec *iov, struct iovec *rsp);
} handlers[] = {
	ASCS_OP("Codec Config", BT_ASCS_CONFIG,
		sizeof(struct bt_ascs_config), ascs_config),
	ASCS_OP("QoS Config", BT_ASCS_QOS,
		sizeof(struct bt_ascs_qos), ascs_qos),
	ASCS_OP("Enable", BT_ASCS_ENABLE, sizeof(struct bt_ascs_enable),
		ascs_enable),
	ASCS_OP("Receiver Start Ready", BT_ASCS_START,
		sizeof(struct bt_ascs_start), ascs_start),
	ASCS_OP("Disable", BT_ASCS_DISABLE,
		sizeof(struct bt_ascs_disable), ascs_disable),
	ASCS_OP("Receiver Stop Ready", BT_ASCS_STOP,
		sizeof(struct bt_ascs_stop), ascs_stop),
	ASCS_OP("Update Metadata", BT_ASCS_METADATA,
		sizeof(struct bt_ascs_metadata), ascs_metadata),
	ASCS_OP("Release", BT_ASCS_RELEASE,
		sizeof(struct bt_ascs_release), ascs_release),
	{}
};

static struct iovec *ascs_ase_cp_rsp_new(uint8_t op)
{
	struct bt_ascs_cp_rsp *rsp;
	struct iovec *iov;

	iov = new0(struct iovec, 1);
	rsp = new0(struct bt_ascs_cp_rsp, 1);
	rsp->op = op;
	iov->iov_base = rsp;
	iov->iov_len = sizeof(*rsp);

	return iov;
}

static void ascs_ase_cp_write(struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				const uint8_t *value, size_t len,
				uint8_t opcode, struct bt_att *att,
				void *user_data)
{
	struct bt_ascs *ascs = user_data;
	struct bt_bap *bap = bap_get_session(att, ascs->bdb->db);
	struct iovec iov = {
		.iov_base = (void *) value,
		.iov_len = len,
	};
	struct bt_ascs_ase_hdr *hdr;
	struct ascs_op_handler *handler;
	uint8_t ret = BT_ATT_ERROR_REQUEST_NOT_SUPPORTED;
	struct iovec *rsp;

	if (offset) {
		DBG(bap, "invalid offset %u", offset);
		gatt_db_attribute_write_result(attrib, id,
						BT_ATT_ERROR_INVALID_OFFSET);
		return;
	}

	if (len < sizeof(*hdr)) {
		DBG(bap, "invalid len %u < %u sizeof(*hdr)", len,
							sizeof(*hdr));
		gatt_db_attribute_write_result(attrib, id,
				BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN);
		return;
	}

	hdr = iov_pull_mem(&iov, sizeof(*hdr));
	rsp = ascs_ase_cp_rsp_new(hdr->op);

	for (handler = handlers; handler && handler->str; handler++) {
		if (handler->op != hdr->op)
			continue;

		if (iov.iov_len < hdr->num * handler->size) {
			DBG(bap, "invalid len %u < %u "
				  "hdr->num * handler->size", len,
				  hdr->num * handler->size);
			ret = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
			goto respond;
		}

		break;
	}

	if (handler && handler->str) {
		int i;

		DBG(bap, "%s", handler->str);

		for (i = 0; i < hdr->num; i++)
			ret = handler->func(ascs, bap, &iov, rsp);
	} else {
		DBG(bap, "Unknown opcode 0x%02x", hdr->op);
		ascs_ase_rsp_add_errno(rsp, 0x00, -ENOTSUP);
	}

respond:
	if (ret == BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN)
		ascs_ase_rsp_add_errno(rsp, 0x00, -ENOMSG);

	gatt_db_attribute_notify(attrib, rsp->iov_base, rsp->iov_len, att);
	gatt_db_attribute_write_result(attrib, id, ret);

	iov_free(rsp);
}

static struct bt_ascs *ascs_new(struct gatt_db *db)
{
	struct bt_ascs *ascs;
	bt_uuid_t uuid;
	int i;

	if (!db)
		return NULL;

	ascs = new0(struct bt_ascs, 1);

	/* Populate DB with ASCS attributes */
	bt_uuid16_create(&uuid, ASCS_UUID);
	ascs->service = gatt_db_add_service(db, &uuid, true,
						4 + (NUM_ASES * 3));

	for (i = 0; i < NUM_ASES; i++)
		ase_new(ascs, i);

	bt_uuid16_create(&uuid, ASE_CP_UUID);
	ascs->ase_cp = gatt_db_service_add_characteristic(ascs->service,
					&uuid,
					BT_ATT_PERM_WRITE,
					BT_GATT_CHRC_PROP_WRITE |
					BT_GATT_CHRC_PROP_NOTIFY,
					NULL, ascs_ase_cp_write,
					ascs);

	ascs->ase_cp_ccc = gatt_db_service_add_ccc(ascs->service,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	gatt_db_service_set_active(ascs->service, true);

	return ascs;
}

static struct bt_bap_db *bap_db_new(struct gatt_db *db)
{
	struct bt_bap_db *bdb;

	if (!db)
		return NULL;

	bdb = new0(struct bt_bap_db, 1);
	bdb->db = gatt_db_ref(db);
	bdb->sinks = queue_new();
	bdb->sources = queue_new();
	bdb->endpoints = queue_new();

	if (!bap_db)
		bap_db = queue_new();

	bdb->pacs = pacs_new(db);
	bdb->pacs->bdb = bdb;

	bdb->ascs = ascs_new(db);
	bdb->ascs->bdb = bdb;

	queue_push_tail(bap_db, bdb);

	return bdb;
}

static struct bt_bap_db *bap_get_db(struct gatt_db *db)
{
	struct bt_bap_db *bdb;

	bdb = queue_find(bap_db, bap_db_match, db);
	if (bdb)
		return bdb;

	return bap_db_new(db);
}

static struct bt_pacs *bap_get_pacs(struct bt_bap *bap)
{
	if (!bap)
		return NULL;

	if (bap->rdb->pacs)
		return bap->rdb->pacs;

	bap->rdb->pacs = new0(struct bt_pacs, 1);
	bap->rdb->pacs->bdb = bap->rdb;

	return bap->rdb->pacs;
}

static struct bt_ascs *bap_get_ascs(struct bt_bap *bap)
{
	if (!bap)
		return NULL;

	if (bap->rdb->ascs)
		return bap->rdb->ascs;

	bap->rdb->ascs = new0(struct bt_ascs, 1);
	bap->rdb->ascs->bdb = bap->rdb;

	return bap->rdb->ascs;
}

static struct bt_bap_pac *bap_pac_new(struct bt_bap_db *bdb, const char *name,
					uint8_t type,
					struct bt_bap_codec *codec,
					struct bt_bap_pac_qos *qos,
					struct iovec *data,
					struct iovec *metadata)
{
	struct bt_bap_pac *pac;

	pac = new0(struct bt_bap_pac, 1);
	pac->bdb = bdb;
	pac->name = name ? strdup(name) : NULL;
	pac->type = type;
	pac->codec = *codec;
	pac->data = iov_dup(data, 1);
	pac->metadata = iov_dup(metadata, 1);

	if (qos)
		pac->qos = *qos;

	return pac;
}

static void bap_pac_free(void *data)
{
	struct bt_bap_pac *pac = data;

	free(pac->name);
	iov_free(pac->metadata);
	iov_free(pac->data);
	free(pac);
}

static void bap_add_sink(struct bt_bap_pac *pac)
{
	struct iovec iov;
	uint8_t value[512];

	queue_push_tail(pac->bdb->sinks, pac);

	memset(value, 0, sizeof(value));

	iov.iov_base = value;
	iov.iov_len = 0;

	queue_foreach(pac->bdb->sinks, pac_foreach, &iov);

	gatt_db_attribute_notify(pac->bdb->pacs->sink, iov.iov_base,
				iov.iov_len, NULL);
}

static void bap_add_source(struct bt_bap_pac *pac)
{
	struct iovec iov;
	uint8_t value[512];

	queue_push_tail(pac->bdb->sources, pac);

	memset(value, 0, sizeof(value));

	iov.iov_base = value;
	iov.iov_len = 0;

	queue_foreach(pac->bdb->sinks, pac_foreach, &iov);

	gatt_db_attribute_notify(pac->bdb->pacs->source, iov.iov_base,
				iov.iov_len, NULL);
}

static void notify_pac_added(void *data, void *user_data)
{
	struct bt_bap_pac_changed *changed = data;
	struct bt_bap_pac *pac = user_data;

	if (changed->added)
		changed->added(pac, changed->data);
}

struct bt_bap_pac *bt_bap_add_vendor_pac(struct gatt_db *db,
					const char *name, uint8_t type,
					uint8_t id, uint16_t cid, uint16_t vid,
					struct bt_bap_pac_qos *qos,
					struct iovec *data,
					struct iovec *metadata)
{
	struct bt_bap_db *bdb;
	struct bt_bap_pac *pac;
	struct bt_bap_codec codec;

	if (!db)
		return NULL;

	bdb = bap_get_db(db);
	if (!bdb)
		return NULL;

	codec.id = id;
	codec.cid = cid;
	codec.vid = vid;

	pac = bap_pac_new(bdb, name, type, &codec, qos, data, metadata);

	switch (type) {
	case BT_BAP_SINK:
		bap_add_sink(pac);
		break;
	case BT_BAP_SOURCE:
		bap_add_source(pac);
		break;
	default:
		bap_pac_free(pac);
		return NULL;
	}

	queue_foreach(pac_cbs, notify_pac_added, pac);

	return pac;
}

struct bt_bap_pac *bt_bap_add_pac(struct gatt_db *db, const char *name,
					uint8_t type, uint8_t id,
					struct bt_bap_pac_qos *qos,
					struct iovec *data,
					struct iovec *metadata)
{
	return bt_bap_add_vendor_pac(db, name, type, id, 0x0000, 0x0000, qos,
							data, metadata);
}

uint8_t bt_bap_pac_get_type(struct bt_bap_pac *pac)
{
	if (!pac)
		return 0x00;

	return pac->type;
}

static void notify_pac_removed(void *data, void *user_data)
{
	struct bt_bap_pac_changed *changed = data;
	struct bt_bap_pac *pac = user_data;

	if (changed->removed)
		changed->removed(pac, changed->data);
}

bool bt_bap_pac_set_ops(struct bt_bap_pac *pac, struct bt_bap_pac_ops *ops,
					void *user_data)
{
	if (!pac)
		return false;

	pac->ops = ops;
	pac->user_data = user_data;

	return true;
}

static bool match_stream_lpac(const void *data, const void *user_data)
{
	const struct bt_bap_stream *stream = data;
	const struct bt_bap_pac *pac = user_data;

	return stream->lpac == pac;
}

static void remove_streams(void *data, void *user_data)
{
	struct bt_bap *bap = data;
	struct bt_bap_pac *pac = user_data;
	struct bt_bap_stream *stream;

	stream = queue_remove_if(bap->streams, match_stream_lpac, pac);
	if (stream)
		bt_bap_stream_release(stream, NULL, NULL);
}

bool bt_bap_remove_pac(struct bt_bap_pac *pac)
{
	if (!pac)
		return false;

	if (queue_remove_if(pac->bdb->sinks, NULL, pac))
		goto found;

	if (queue_remove_if(pac->bdb->sources, NULL, pac))
		goto found;

	return false;

found:
	queue_foreach(sessions, remove_streams, pac);
	queue_foreach(pac_cbs, notify_pac_removed, pac);
	bap_pac_free(pac);
	return true;
}

static void bap_db_free(void *data)
{
	struct bt_bap_db *bdb = data;

	if (!bdb)
		return;

	queue_destroy(bdb->sinks, bap_pac_free);
	queue_destroy(bdb->sources, bap_pac_free);
	queue_destroy(bdb->endpoints, free);
	gatt_db_unref(bdb->db);

	free(bdb->pacs);
	free(bdb->ascs);
	free(bdb);
}

static void bap_ready_free(void *data)
{
	struct bt_bap_ready *ready = data;

	if (ready->destroy)
		ready->destroy(ready->data);

	free(ready);
}

static void bap_state_free(void *data)
{
	struct bt_bap_state *state = data;

	if (state->destroy)
		state->destroy(state->data);

	free(state);
}

static void bap_req_free(void *data)
{
	struct bt_bap_req *req = data;
	size_t i;

	queue_destroy(req->group, bap_req_free);

	for (i = 0; i < req->len; i++)
		free(req->iov[i].iov_base);

	free(req->iov);
	free(req);
}

static void bap_detached(void *data, void *user_data)
{
	struct bt_bap_cb *cb = data;
	struct bt_bap *bap = user_data;

	cb->detached(bap, cb->user_data);
}

static void bap_free(void *data)
{
	struct bt_bap *bap = data;

	bt_bap_detach(bap);

	bap_db_free(bap->rdb);

	queue_destroy(bap->ready_cbs, bap_ready_free);
	queue_destroy(bap->state_cbs, bap_state_free);

	queue_destroy(bap->reqs, bap_req_free);
	queue_destroy(bap->pending, NULL);
	queue_destroy(bap->notify, NULL);
	queue_destroy(bap->streams, bap_stream_free);

	free(bap);
}

unsigned int bt_bap_register(bt_bap_func_t attached, bt_bap_func_t detached,
							void *user_data)
{
	struct bt_bap_cb *cb;
	static unsigned int id;

	if (!attached && !detached)
		return 0;

	if (!bap_cbs)
		bap_cbs = queue_new();

	cb = new0(struct bt_bap_cb, 1);
	cb->id = ++id ? id : ++id;
	cb->attached = attached;
	cb->detached = detached;
	cb->user_data = user_data;

	queue_push_tail(bap_cbs, cb);

	return cb->id;
}

static bool match_id(const void *data, const void *match_data)
{
	const struct bt_bap_cb *cb = data;
	unsigned int id = PTR_TO_UINT(match_data);

	return (cb->id == id);
}

bool bt_bap_unregister(unsigned int id)
{
	struct bt_bap_cb *cb;

	cb = queue_remove_if(bap_cbs, match_id, UINT_TO_PTR(id));
	if (!cb)
		return false;

	free(cb);

	return true;
}

static void bap_attached(void *data, void *user_data)
{
	struct bt_bap_cb *cb = data;
	struct bt_bap *bap = user_data;

	cb->attached(bap, cb->user_data);
}

struct bt_bap *bt_bap_new(struct gatt_db *ldb, struct gatt_db *rdb)
{
	struct bt_bap *bap;
	struct bt_bap_db *bdb;

	if (!ldb)
		return NULL;

	bdb = bap_get_db(ldb);
	if (!bdb)
		return NULL;

	bap = new0(struct bt_bap, 1);
	bap->ldb = bdb;
	bap->reqs = queue_new();
	bap->pending = queue_new();
	bap->notify = queue_new();
	bap->ready_cbs = queue_new();
	bap->streams = queue_new();
	bap->state_cbs = queue_new();

	if (!rdb)
		goto done;

	bdb = new0(struct bt_bap_db, 1);
	bdb->db = gatt_db_ref(rdb);
	bdb->sinks = queue_new();
	bdb->sources = queue_new();
	bdb->endpoints = queue_new();

	bap->rdb = bdb;

done:
	return bt_bap_ref(bap);
}

bool bt_bap_set_user_data(struct bt_bap *bap, void *user_data)
{
	if (!bap)
		return false;

	bap->user_data = user_data;

	return true;
}

void *bt_bap_get_user_data(struct bt_bap *bap)
{
	if (!bap)
		return NULL;

	return bap->user_data;
}

struct bt_att *bt_bap_get_att(struct bt_bap *bap)
{
	if (!bap)
		return NULL;

	if (bap->att)
		return bap->att;

	return bt_gatt_client_get_att(bap->client);
}

struct bt_bap *bt_bap_ref(struct bt_bap *bap)
{
	if (!bap)
		return NULL;

	__sync_fetch_and_add(&bap->ref_count, 1);

	return bap;
}

void bt_bap_unref(struct bt_bap *bap)
{
	if (!bap)
		return;

	if (__sync_sub_and_fetch(&bap->ref_count, 1))
		return;

	bap_free(bap);
}

static void bap_notify_ready(struct bt_bap *bap)
{
	const struct queue_entry *entry;

	if (!queue_isempty(bap->pending))
		return;

	bt_bap_ref(bap);

	for (entry = queue_get_entries(bap->ready_cbs); entry;
							entry = entry->next) {
		struct bt_bap_ready *ready = entry->data;

		ready->func(bap, ready->data);
	}

	bt_bap_unref(bap);
}

bool bap_print_cc(void *data, size_t len, util_debug_func_t func,
						void *user_data)
{
	return bap_print_ltv("CC", data, len, func, user_data);
}

static void bap_parse_pacs(struct bt_bap *bap, uint8_t type,
				struct queue *queue,
				const uint8_t *value,
				uint16_t len)
{
	struct bt_pacs_read_rsp *rsp;
	struct iovec iov = {
		.iov_base = (void *) value,
		.iov_len = len,
	};
	int i;

	rsp = iov_pull_mem(&iov, sizeof(*rsp));
	if (!rsp) {
		DBG(bap, "Unable to parse PAC");
		return;
	}

	DBG(bap, "PAC(s) %u", rsp->num_pac);

	for (i = 0; i < rsp->num_pac; i++) {
		struct bt_bap_pac *pac;
		struct bt_pac *p;
		struct bt_ltv *cc;
		struct bt_pac_metadata *meta;
		struct iovec data, metadata;

		p = iov_pull_mem(&iov, sizeof(*p));
		if (!p) {
			DBG(bap, "Unable to parse PAC");
			return;
		}

		pac = NULL;

		if (!bap_print_cc(iov.iov_base, p->cc_len, bap->debug_func,
					bap->debug_data))
			return;

		cc = iov_pull_mem(&iov, p->cc_len);
		if (!cc) {
			DBG(bap, "Unable to parse PAC codec capabilities");
			return;
		}

		meta = iov_pull_mem(&iov, sizeof(*meta));
		if (!meta) {
			DBG(bap, "Unable to parse PAC metadata");
			return;
		}

		data.iov_len = p->cc_len;
		data.iov_base = cc;

		metadata.iov_len = meta->len;
		metadata.iov_base = meta->data;

		iov_pull_mem(&iov, meta->len);

		pac = bap_pac_new(bap->rdb, NULL, type, &p->codec, NULL, &data,
								&metadata);
		if (!pac)
			continue;

		DBG(bap, "PAC #%u: type %u codec 0x%02x cc_len %u meta_len %u",
			i, type, p->codec.id, p->cc_len, meta->len);

		queue_push_tail(queue, pac);
	}
}

static void read_source_pac(struct bt_bap *bap, bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	if (!success) {
		DBG(bap, "Unable to read Source PAC: error 0x%02x", att_ecode);
		return;
	}

	bap_parse_pacs(bap, BT_BAP_SOURCE, bap->rdb->sources, value, length);
}

static void read_sink_pac(struct bt_bap *bap, bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	if (!success) {
		DBG(bap, "Unable to read Sink PAC: error 0x%02x", att_ecode);
		return;
	}

	bap_parse_pacs(bap, BT_BAP_SINK, bap->rdb->sinks, value, length);
}

static void read_source_pac_loc(struct bt_bap *bap, bool success,
				uint8_t att_ecode, const uint8_t *value,
				uint16_t length, void *user_data)
{
	struct bt_pacs *pacs = bap_get_pacs(bap);

	if (!success) {
		DBG(bap, "Unable to read Source PAC Location: error 0x%02x",
								att_ecode);
		return;
	}

	gatt_db_attribute_write(pacs->source_loc, 0, value, length, 0, NULL,
							NULL, NULL);
}

static void read_sink_pac_loc(struct bt_bap *bap, bool success,
				uint8_t att_ecode, const uint8_t *value,
				uint16_t length, void *user_data)
{
	struct bt_pacs *pacs = bap_get_pacs(bap);

	if (!success) {
		DBG(bap, "Unable to read Sink PAC Location: error 0x%02x",
								att_ecode);
		return;
	}

	gatt_db_attribute_write(pacs->sink_loc, 0, value, length, 0, NULL,
							NULL, NULL);
}

static void read_pac_context(struct bt_bap *bap, bool success,
				uint8_t att_ecode, const uint8_t *value,
				uint16_t length, void *user_data)
{
	struct bt_pacs *pacs = bap_get_pacs(bap);

	if (!success) {
		DBG(bap, "Unable to read PAC Context: error 0x%02x", att_ecode);
		return;
	}

	gatt_db_attribute_write(pacs->context, 0, value, length, 0, NULL,
							NULL, NULL);
}

static void read_pac_supported_context(struct bt_bap *bap, bool success,
					uint8_t att_ecode, const uint8_t *value,
					uint16_t length, void *user_data)
{
	struct bt_pacs *pacs = bap_get_pacs(bap);

	if (!success) {
		DBG(bap, "Unable to read PAC Supproted Context: error 0x%02x",
								att_ecode);
		return;
	}

	gatt_db_attribute_write(pacs->supported_context, 0, value, length, 0,
							NULL, NULL, NULL);
}

static void bap_pending_destroy(void *data)
{
	struct bt_bap_pending *pending = data;
	struct bt_bap *bap = pending->bap;

	if (queue_remove_if(bap->pending, NULL, pending))
		free(pending);

	bap_notify_ready(bap);
}

static void bap_pending_complete(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_bap_pending *pending = user_data;

	if (pending->func)
		pending->func(pending->bap, success, att_ecode, value, length,
						pending->user_data);
}

static void bap_read_value(struct bt_bap *bap, uint16_t value_handle,
				bap_func_t func, void *user_data)
{
	struct bt_bap_pending *pending;

	pending = new0(struct bt_bap_pending, 1);
	pending->bap = bap;
	pending->func = func;
	pending->user_data = user_data;

	pending->id = bt_gatt_client_read_value(bap->client, value_handle,
						bap_pending_complete, pending,
						bap_pending_destroy);
	if (!pending->id) {
		DBG(bap, "Unable to send Read request");
		free(pending);
		return;
	}

	queue_push_tail(bap->pending, pending);
}

static void foreach_pacs_char(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_bap *bap = user_data;
	uint16_t value_handle;
	bt_uuid_t uuid, uuid_sink, uuid_source, uuid_sink_loc, uuid_source_loc;
	bt_uuid_t uuid_context, uuid_supported_context;
	struct bt_pacs *pacs;

	if (!gatt_db_attribute_get_char_data(attr, NULL, &value_handle,
						NULL, NULL, &uuid))
		return;

	bt_uuid16_create(&uuid_sink, PAC_SINK_CHRC_UUID);
	bt_uuid16_create(&uuid_source, PAC_SOURCE_CHRC_UUID);
	bt_uuid16_create(&uuid_sink_loc, PAC_SINK_LOC_CHRC_UUID);
	bt_uuid16_create(&uuid_source_loc, PAC_SOURCE_LOC_CHRC_UUID);
	bt_uuid16_create(&uuid_context, PAC_CONTEXT);
	bt_uuid16_create(&uuid_supported_context, PAC_SUPPORTED_CONTEXT);

	if (!bt_uuid_cmp(&uuid, &uuid_sink)) {
		DBG(bap, "Sink PAC found: handle 0x%04x", value_handle);

		pacs = bap_get_pacs(bap);
		if (!pacs || pacs->sink)
			return;

		pacs->sink = attr;
		bap_read_value(bap, value_handle, read_sink_pac, bap);
	}

	if (!bt_uuid_cmp(&uuid, &uuid_source)) {
		DBG(bap, "Source PAC found: handle 0x%04x", value_handle);

		pacs = bap_get_pacs(bap);
		if (!pacs || pacs->source)
			return;

		pacs->source = attr;
		bap_read_value(bap, value_handle, read_source_pac, NULL);
	}

	if (!bt_uuid_cmp(&uuid, &uuid_sink_loc)) {
		DBG(bap, "Sink PAC Location found: handle 0x%04x",
						value_handle);

		pacs = bap_get_pacs(bap);
		if (!pacs || pacs->sink_loc)
			return;

		pacs->sink_loc = attr;
		bap_read_value(bap, value_handle, read_sink_pac_loc, NULL);
	}

	if (!bt_uuid_cmp(&uuid, &uuid_source_loc)) {
		DBG(bap, "Source PAC Location found: handle 0x%04x",
						value_handle);

		pacs = bap_get_pacs(bap);
		if (!pacs || pacs->source_loc)
			return;

		pacs->source_loc = attr;
		bap_read_value(bap, value_handle, read_source_pac_loc, NULL);
	}

	if (!bt_uuid_cmp(&uuid, &uuid_context)) {
		DBG(bap, "PAC Context found: handle 0x%04x", value_handle);

		pacs = bap_get_pacs(bap);
		if (!pacs || pacs->context)
			return;

		pacs->context = attr;
		bap_read_value(bap, value_handle, read_pac_context, NULL);
	}

	if (!bt_uuid_cmp(&uuid, &uuid_supported_context)) {
		DBG(bap, "PAC Supported Context found: handle 0x%04x",
							value_handle);

		pacs = bap_get_pacs(bap);
		if (!pacs || pacs->supported_context)
			return;

		pacs->supported_context = attr;
		bap_read_value(bap, value_handle, read_pac_supported_context,
									NULL);
	}
}

static void foreach_pacs_service(struct gatt_db_attribute *attr,
						void *user_data)
{
	struct bt_bap *bap = user_data;
	struct bt_pacs *pacs = bap_get_pacs(bap);

	pacs->service = attr;

	gatt_db_service_foreach_char(attr, foreach_pacs_char, bap);
}

struct match_pac {
	struct bt_bap_codec codec;
	struct bt_bap_pac *lpac;
	struct bt_bap_pac *rpac;
	struct bt_bap_endpoint *ep;
};

static bool match_stream_pac(struct bt_bap_pac *lpac, struct bt_bap_pac *rpac,
							void *user_data)
{
	struct match_pac *match = user_data;

	if (!bap_codec_equal(&match->codec, &lpac->codec))
		return true;

	match->lpac = lpac;
	match->rpac = rpac;

	return false;
}

static void ep_status_config(struct bt_bap *bap, struct bt_bap_endpoint *ep,
							struct iovec *iov)
{
	struct bt_ascs_ase_status_config *cfg;
	struct bt_ltv *cc;
	uint32_t pd_min, pd_max, ppd_min, ppd_max;
	int i;

	cfg = iov_pull_mem(iov, sizeof(*cfg));
	if (!cfg) {
		DBG(bap, "Unable to parse Config Status");
		return;
	}

	pd_min = get_le24(cfg->pd_min);
	pd_max = get_le24(cfg->pd_max);
	ppd_min = get_le24(cfg->ppd_min);
	ppd_max = get_le24(cfg->ppd_max);

	DBG(bap, "codec 0x%02x framing 0x%02x phy 0x%02x rtn %u "
			"latency %u pd %u - %u ppd %u - %u", cfg->codec.id,
			cfg->framing, cfg->phy, cfg->rtn,
			le16_to_cpu(cfg->latency),
			pd_min, pd_max, ppd_min, ppd_max);

	if (iov->iov_len < cfg->cc_len) {
		DBG(bap, "Unable to parse Config Status: len %zu < %u cc_len",
						iov->iov_len, cfg->cc_len);
		return;
	}

	for (i = 0; iov->iov_len >= sizeof(*cc); i++) {
		cc = iov_pull_mem(iov, sizeof(*cc));
		if (!cc)
			break;

		DBG(bap, "Codec Config #%u: type 0x%02x len %u", i,
						cc->type, cc->len);

		iov_pull_mem(iov, cc->len - 1);
	}

	/* Any previously applied codec configuration may be cached by the
	 * server.
	 */
	if (!ep->stream) {
		struct match_pac match;

		match.lpac = NULL;
		match.rpac = NULL;
		match.codec.id = cfg->codec.id;
		match.codec.cid = le16_to_cpu(cfg->codec.cid);
		match.codec.vid = le16_to_cpu(cfg->codec.vid);

		bt_bap_foreach_pac(bap, ep->dir, match_stream_pac, &match);
		if (!match.lpac || !match.rpac)
			return;

		bap_stream_new(bap, ep, match.lpac, match.rpac, NULL, true);
	}

	if (!ep->stream)
		return;

	/* Set preferred settings */
	if (ep->stream->rpac) {
		ep->stream->rpac->qos.framing = cfg->framing;
		ep->stream->rpac->qos.phy = cfg->phy;
		ep->stream->rpac->qos.rtn = cfg->rtn;
		ep->stream->rpac->qos.latency = le16_to_cpu(cfg->latency);
		ep->stream->rpac->qos.pd_min = pd_min;
		ep->stream->rpac->qos.pd_max = pd_max;
		ep->stream->rpac->qos.ppd_min = ppd_min;
		ep->stream->rpac->qos.ppd_max = ppd_max;
	}

	if (!ep->stream->cc)
		ep->stream->cc = new0(struct iovec, 1);

	iov_memcpy(ep->stream->cc, cfg->cc, cfg->cc_len);
}

static void bap_stream_config_cfm_cb(struct bt_bap_stream *stream, int err)
{
	struct bt_bap *bap = stream->bap;

	if (err) {
		DBG(bap, "Config Confirmation failed: %d", err);
		bt_bap_stream_release(stream, NULL, NULL);
		return;
	}
}

static void bap_stream_config_cfm(struct bt_bap_stream *stream)
{
	int err;

	if (!stream->lpac->ops || !stream->lpac->ops->config)
		return;

	err = stream->lpac->ops->config(stream, stream->cc, &stream->qos,
					bap_stream_config_cfm_cb,
					stream->lpac->user_data);
	if (err < 0) {
		DBG(stream->bap, "Unable to send Config Confirmation: %d",
									err);
		bt_bap_stream_release(stream, NULL, NULL);
	}
}

static void ep_status_qos(struct bt_bap *bap, struct bt_bap_endpoint *ep,
							struct iovec *iov)
{
	struct bt_ascs_ase_status_qos *qos;
	uint32_t interval;
	uint32_t pd;
	uint16_t sdu;
	uint16_t latency;

	qos = iov_pull_mem(iov, sizeof(*qos));
	if (!qos) {
		DBG(bap, "Unable to parse QoS Status");
		return;
	}

	interval = get_le24(qos->interval);
	pd = get_le24(qos->pd);
	sdu = le16_to_cpu(qos->sdu);
	latency = le16_to_cpu(qos->latency);

	DBG(bap, "CIG 0x%02x CIS 0x%02x interval %u framing 0x%02x "
			"phy 0x%02x rtn %u latency %u pd %u", qos->cig_id,
			qos->cis_id, interval, qos->framing, qos->phy,
			qos->rtn, latency, pd);

	if (!ep->stream)
		return;

	ep->stream->qos.interval = interval;
	ep->stream->qos.framing = qos->framing;
	ep->stream->qos.phy = qos->phy;
	ep->stream->qos.sdu = sdu;
	ep->stream->qos.rtn = qos->rtn;
	ep->stream->qos.latency = latency;
	ep->stream->qos.delay = pd;

	if (ep->old_state == BT_ASCS_ASE_STATE_CONFIG)
		bap_stream_config_cfm(ep->stream);
}

static void ep_status_metadata(struct bt_bap *bap, struct bt_bap_endpoint *ep,
							struct iovec *iov)
{
	struct bt_ascs_ase_status_metadata *meta;

	meta = iov_pull_mem(iov, sizeof(*meta));
	if (!meta) {
		DBG(bap, "Unable to parse Metadata Status");
		return;
	}

	DBG(bap, "CIS 0x%02x CIG 0x%02x metadata len %u",
			meta->cis_id, meta->cig_id, meta->len);
}

static void bap_ep_set_status(struct bt_bap *bap, struct bt_bap_endpoint *ep,
					const uint8_t *value, uint16_t length)
{
	struct bt_ascs_ase_status *rsp;
	struct iovec iov = {
		.iov_base = (void *) value,
		.iov_len = length,
	};

	rsp = iov_pull_mem(&iov, sizeof(*rsp));
	if (!rsp)
		return;

	ep->id = rsp->id;
	ep->old_state = ep->state;
	ep->state = rsp->state;

	DBG(bap, "ASE status: ep %p id 0x%02x handle 0x%04x state %s "
			"len %zu", ep, ep->id,
			gatt_db_attribute_get_handle(ep->attr),
			bt_bap_stream_statestr(ep->state), iov.iov_len);

	switch (ep->state) {
	case BT_ASCS_ASE_STATE_IDLE:
		break;
	case BT_ASCS_ASE_STATE_CONFIG:
		ep_status_config(bap, ep, &iov);
		break;
	case BT_ASCS_ASE_STATE_QOS:
		ep_status_qos(bap, ep, &iov);
		break;
	case BT_ASCS_ASE_STATE_ENABLING:
	case BT_ASCS_ASE_STATE_STREAMING:
	case BT_ASCS_ASE_STATE_DISABLING:
		ep_status_metadata(bap, ep, &iov);
		break;
	case BT_ASCS_ASE_STATE_RELEASING:
		break;
	}

	/* Only notifify if there is a stream */
	if (!ep->stream)
		return;

	bap_stream_state_changed(ep->stream);
}

static void read_ase_status(struct bt_bap *bap, bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_bap_endpoint *ep = user_data;

	if (!success)
		return;

	bap_ep_set_status(bap, ep, value, length);
}

static void bap_register(uint16_t att_ecode, void *user_data)
{
	struct bt_bap_notify *notify = user_data;

	if (att_ecode)
		DBG(notify->bap, "ASE register failed: 0x%04x", att_ecode);
}

static void bap_endpoint_notify(struct bt_bap *bap, uint16_t value_handle,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_bap_endpoint *ep = user_data;

	bap_ep_set_status(bap, ep, value, length);
}

static void bap_notify(uint16_t value_handle, const uint8_t *value,
				uint16_t length, void *user_data)
{
	struct bt_bap_notify *notify = user_data;

	if (notify->func)
		notify->func(notify->bap, value_handle, value, length,
						notify->user_data);
}

static void bap_notify_destroy(void *data)
{
	struct bt_bap_notify *notify = data;
	struct bt_bap *bap = notify->bap;

	if (queue_remove_if(bap->notify, NULL, notify))
		free(notify);
}

static unsigned int bap_register_notify(struct bt_bap *bap,
					uint16_t value_handle,
					bap_notify_t func,
					void *user_data)
{
	struct bt_bap_notify *notify;

	notify = new0(struct bt_bap_notify, 1);
	notify->bap = bap;
	notify->func = func;
	notify->user_data = user_data;

	notify->id = bt_gatt_client_register_notify(bap->client,
						value_handle, bap_register,
						bap_notify, notify,
						bap_notify_destroy);
	if (!notify->id) {
		DBG(bap, "Unable to register for notifications");
		free(notify);
		return 0;
	}

	queue_push_tail(bap->notify, notify);

	return notify->id;
}

static void bap_endpoint_attach(struct bt_bap *bap, struct bt_bap_endpoint *ep)
{
	uint16_t value_handle;

	if (!gatt_db_attribute_get_char_data(ep->attr, NULL, &value_handle,
						NULL, NULL, NULL))
		return;

	DBG(bap, "ASE handle 0x%04x", value_handle);

	bap_read_value(bap, value_handle, read_ase_status, ep);

	ep->state_id = bap_register_notify(bap, value_handle,
						bap_endpoint_notify, ep);
}

static void append_group(void *data, void *user_data)
{
	struct bt_bap_req *req = data;
	struct iovec *iov = user_data;
	size_t i;

	for (i = 0; i < req->len; i++)
		iov_add_mem(iov, req->iov[i].iov_len, req->iov[i].iov_base);
}

static bool bap_send(struct bt_bap *bap, struct bt_bap_req *req)
{
	struct bt_ascs *ascs = bap_get_ascs(bap);
	int ret;
	uint16_t handle;
	uint8_t buf[64];
	struct bt_ascs_ase_hdr hdr;
	struct iovec iov  = {
		.iov_base = buf,
		.iov_len = 0,
	};
	size_t i;

	if (!gatt_db_attribute_get_char_data(ascs->ase_cp, NULL, &handle,
						NULL, NULL, NULL))
		return false;

	hdr.op = req->op;
	hdr.num = 1 + queue_length(req->group);

	iov_add_mem(&iov, sizeof(hdr), &hdr);

	for (i = 0; i < req->len; i++)
		iov_add_mem(&iov, req->iov[i].iov_len, req->iov[i].iov_base);

	/* Append the request group with the same opcode */
	queue_foreach(req->group, append_group, &iov);

	ret = bt_gatt_client_write_without_response(bap->client, handle,
							false, iov.iov_base,
							iov.iov_len);
	if (!ret)
		return false;

	bap->req = req;

	return false;
}

static bool bap_process_queue(void *data)
{
	struct bt_bap *bap = data;
	struct bt_bap_req *req;

	if (bap->process_id) {
		timeout_remove(bap->process_id);
		bap->process_id = 0;
	}

	while ((req = queue_pop_head(bap->reqs))) {
		if (!bap_send(bap, req))
			break;
	}

	return false;
}

static bool match_req(const void *data, const void *match_data)
{
	const struct bt_bap_req *pend = data;
	const struct bt_bap_req *req = match_data;

	return pend->op == req->op;
}

static bool bap_queue_req(struct bt_bap *bap, struct bt_bap_req *req)
{
	struct bt_bap_req *pend;
	struct queue *queue;

	pend = queue_find(bap->reqs, match_req, req);
	if (pend) {
		if (!pend->group)
			pend->group = queue_new();
		/* Group requests with the same opcode */
		queue = pend->group;
	} else {
		queue = bap->reqs;
	}

	DBG(bap, "req %p (op 0x%2.2x) queue %p", req, req->op, queue);

	if (!queue_push_tail(queue, req)) {
		DBG(bap, "Unable to queue request");
		return false;
	}

	/* Only attempot to process queue if there is no outstanding request
	 * and it has not been scheduled.
	 */
	if (!bap->req && !bap->process_id)
		bap->process_id = timeout_add(BAP_PROCESS_TIMEOUT,
						bap_process_queue, bap, NULL);

	return true;
}

static void bap_req_complete(struct bt_bap_req *req,
				const struct bt_ascs_ase_rsp *rsp)
{
	struct queue *group;

	if (!req->func)
		goto done;

	if (rsp)
		req->func(req->stream, rsp->code, rsp->reason, req->user_data);
	else
		req->func(req->stream, BT_ASCS_RSP_UNSPECIFIED, 0x00,
						req->user_data);

done:
	/* Detach from request so it can be freed separately */
	group = req->group;
	req->group = NULL;

	queue_foreach(group, (queue_foreach_func_t)bap_req_complete,
							(void *)rsp);

	queue_destroy(group, NULL);

	bap_req_free(req);
}

static void bap_cp_notify(struct bt_bap *bap, uint16_t value_handle,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	const struct bt_ascs_cp_rsp *rsp = (void *)value;
	const struct bt_ascs_ase_rsp *ase_rsp = NULL;
	struct bt_bap_req *req;
	int i;

	if (!bap->req)
		return;

	req = bap->req;
	bap->req = NULL;

	if (length < sizeof(*rsp)) {
		DBG(bap, "Invalid ASE CP notification: length %u < %zu",
						length, sizeof(*rsp));
		goto done;
	}

	if (rsp->op != req->op) {
		DBG(bap, "Invalid ASE CP notification: op 0x%02x != 0x%02x",
						rsp->op, req->op);
		goto done;
	}

	length -= sizeof(*rsp);

	if (rsp->num_ase == 0xff) {
		ase_rsp = rsp->rsp;
		goto done;
	}

	for (i = 0; i < rsp->num_ase; i++) {
		if (length < sizeof(*ase_rsp)) {
			DBG(bap, "Invalid ASE CP notification: length %u < %zu",
					length, sizeof(*ase_rsp));
			goto done;
		}

		ase_rsp = &rsp->rsp[i];
	}

done:
	bap_req_complete(req, ase_rsp);
	bap_process_queue(bap);
}

static void bap_cp_attach(struct bt_bap *bap)
{
	uint16_t value_handle;
	struct bt_ascs *ascs = bap_get_ascs(bap);

	if (!gatt_db_attribute_get_char_data(ascs->ase_cp, NULL,
						&value_handle,
						NULL, NULL, NULL))
		return;

	DBG(bap, "ASE CP handle 0x%04x", value_handle);

	bap->cp_id = bap_register_notify(bap, value_handle, bap_cp_notify,
								NULL);
}

static void foreach_ascs_char(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_bap *bap = user_data;
	uint16_t value_handle;
	bt_uuid_t uuid, uuid_sink, uuid_source, uuid_cp;
	struct bt_ascs *ascs;

	if (!gatt_db_attribute_get_char_data(attr, NULL, &value_handle,
						NULL, NULL, &uuid))
		return;

	bt_uuid16_create(&uuid_sink, ASE_SINK_UUID);
	bt_uuid16_create(&uuid_source, ASE_SOURCE_UUID);
	bt_uuid16_create(&uuid_cp, ASE_CP_UUID);

	if (!bt_uuid_cmp(&uuid, &uuid_sink) ||
			!bt_uuid_cmp(&uuid, &uuid_source)) {
		struct bt_bap_endpoint *ep;

		ep = bap_get_endpoint(bap->rdb, attr);
		if (!ep)
			return;

		if (!bt_uuid_cmp(&uuid, &uuid_sink))
			DBG(bap, "ASE Sink found: handle 0x%04x", value_handle);
		else
			DBG(bap, "ASE Source found: handle 0x%04x",
							value_handle);

		bap_endpoint_attach(bap, ep);

		return;
	}

	if (!bt_uuid_cmp(&uuid, &uuid_cp)) {
		ascs = bap_get_ascs(bap);
		if (!ascs || ascs->ase_cp)
			return;

		ascs->ase_cp = attr;

		DBG(bap, "ASE Control Point found: handle 0x%04x",
							value_handle);

		bap_cp_attach(bap);
	}
}

static void foreach_ascs_service(struct gatt_db_attribute *attr,
						void *user_data)
{
	struct bt_bap *bap = user_data;
	struct bt_ascs *ascs = bap_get_ascs(bap);

	ascs->service = attr;

	gatt_db_service_set_claimed(attr, true);

	gatt_db_service_foreach_char(attr, foreach_ascs_char, bap);
}

static void bap_endpoint_foreach(void *data, void *user_data)
{
	struct bt_bap_endpoint *ep = data;
	struct bt_bap *bap = user_data;

	bap_endpoint_attach(bap, ep);
}

static void bap_attach_att(struct bt_bap *bap, struct bt_att *att)
{
	if (bap->disconn_id) {
		if (att == bt_bap_get_att(bap))
			return;
		bt_att_unregister_disconnect(bap->att, bap->disconn_id);
	}

	bap->disconn_id = bt_att_register_disconnect(bap->att,
							bap_disconnected,
							bap, NULL);
}

bool bt_bap_attach(struct bt_bap *bap, struct bt_gatt_client *client)
{
	bt_uuid_t uuid;

	if (queue_find(sessions, NULL, bap)) {
		/* If instance already been set but there is no client proceed
		 * to clone it otherwise considered it already attached.
		 */
		if (client && !bap->client)
			goto clone;
		return true;
	}

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, bap);

	queue_foreach(bap_cbs, bap_attached, bap);

	if (!client) {
		bap_attach_att(bap, bap->att);
		return true;
	}

	if (bap->client)
		return false;

clone:
	bap->client = bt_gatt_client_clone(client);
	if (!bap->client)
		return false;

	bap_attach_att(bap, bt_gatt_client_get_att(client));

	if (bap->rdb->pacs) {
		uint16_t value_handle;
		struct bt_pacs *pacs = bap->rdb->pacs;

		/* Resume reading sinks if supported */
		if (pacs->sink && queue_isempty(bap->rdb->sinks)) {
			if (gatt_db_attribute_get_char_data(pacs->sink,
							NULL, &value_handle,
							NULL, NULL, NULL)) {
				bap_read_value(bap, value_handle,
							read_sink_pac, bap);
			}
		}

		/* Resume reading sources if supported */
		if (pacs->source && queue_isempty(bap->rdb->sources)) {
			if (gatt_db_attribute_get_char_data(pacs->source,
							NULL, &value_handle,
							NULL, NULL, NULL)) {
				bap_read_value(bap, value_handle,
							read_source_pac, bap);
			}
		}

		queue_foreach(bap->rdb->endpoints, bap_endpoint_foreach, bap);

		bap_cp_attach(bap);

		bap_notify_ready(bap);

		return true;
	}

	bt_uuid16_create(&uuid, PACS_UUID);
	gatt_db_foreach_service(bap->rdb->db, &uuid, foreach_pacs_service, bap);

	bt_uuid16_create(&uuid, ASCS_UUID);
	gatt_db_foreach_service(bap->rdb->db, &uuid, foreach_ascs_service, bap);

	return true;
}

static void stream_foreach_detach(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;

	stream_set_state(stream, BT_BAP_STREAM_STATE_IDLE);
}

void bt_bap_detach(struct bt_bap *bap)
{
	DBG(bap, "%p", bap);

	if (!queue_remove(sessions, bap))
		return;

	bt_gatt_client_unref(bap->client);
	bap->client = NULL;

	bt_att_unregister_disconnect(bap->att, bap->disconn_id);
	bap->att = NULL;

	queue_foreach(bap->streams, stream_foreach_detach, bap);
	queue_foreach(bap_cbs, bap_detached, bap);
}

bool bt_bap_set_debug(struct bt_bap *bap, bt_bap_debug_func_t func,
			void *user_data, bt_bap_destroy_func_t destroy)
{
	if (!bap)
		return false;

	if (bap->debug_destroy)
		bap->debug_destroy(bap->debug_data);

	bap->debug_func = func;
	bap->debug_destroy = destroy;
	bap->debug_data = user_data;

	return true;
}

unsigned int bt_bap_ready_register(struct bt_bap *bap,
				bt_bap_ready_func_t func, void *user_data,
				bt_bap_destroy_func_t destroy)
{
	struct bt_bap_ready *ready;
	static unsigned int id;

	if (!bap)
		return 0;

	ready = new0(struct bt_bap_ready, 1);
	ready->id = ++id ? id : ++id;
	ready->func = func;
	ready->destroy = destroy;
	ready->data = user_data;

	queue_push_tail(bap->ready_cbs, ready);

	return ready->id;
}

static bool match_ready_id(const void *data, const void *match_data)
{
	const struct bt_bap_ready *ready = data;
	unsigned int id = PTR_TO_UINT(match_data);

	return (ready->id == id);
}

bool bt_bap_ready_unregister(struct bt_bap *bap, unsigned int id)
{
	struct bt_bap_ready *ready;

	ready = queue_remove_if(bap->ready_cbs, match_ready_id,
						UINT_TO_PTR(id));
	if (!ready)
		return false;

	bap_ready_free(ready);

	return true;
}

unsigned int bt_bap_state_register(struct bt_bap *bap,
				bt_bap_state_func_t func,
				bt_bap_connecting_func_t connecting,
				void *user_data, bt_bap_destroy_func_t destroy)
{
	struct bt_bap_state *state;
	static unsigned int id;

	if (!bap)
		return 0;

	state = new0(struct bt_bap_state, 1);
	state->id = ++id ? id : ++id;
	state->func = func;
	state->connecting = connecting;
	state->destroy = destroy;
	state->data = user_data;

	queue_push_tail(bap->state_cbs, state);

	return state->id;
}

static bool match_state_id(const void *data, const void *match_data)
{
	const struct bt_bap_state *state = data;
	unsigned int id = PTR_TO_UINT(match_data);

	return (state->id == id);
}

bool bt_bap_state_unregister(struct bt_bap *bap, unsigned int id)
{
	struct bt_bap_state *state;

	if (!bap)
		return false;

	state = queue_remove_if(bap->state_cbs, match_state_id,
						UINT_TO_PTR(id));
	if (!state)
		return false;

	bap_state_free(state);

	return false;
}

const char *bt_bap_stream_statestr(uint8_t state)
{
	switch (state) {
	case BT_BAP_STREAM_STATE_IDLE:
		return "idle";
	case BT_BAP_STREAM_STATE_CONFIG:
		return "config";
	case BT_BAP_STREAM_STATE_QOS:
		return "qos";
	case BT_BAP_STREAM_STATE_ENABLING:
		return "enabling";
	case BT_BAP_STREAM_STATE_STREAMING:
		return "streaming";
	case BT_BAP_STREAM_STATE_DISABLING:
		return "disabling";
	case BT_BAP_STREAM_STATE_RELEASING:
		return "releasing";
	}

	return "unknown";
}

static void bap_foreach_pac(struct queue *l, struct queue *r,
				bt_bap_pac_foreach_t func, void *user_data)
{
	const struct queue_entry *el;

	for (el = queue_get_entries(l); el; el = el->next) {
		struct bt_bap_pac *lpac = el->data;
		const struct queue_entry *er;

		for (er = queue_get_entries(r); er; er = er->next) {
			struct bt_bap_pac *rpac = er->data;

			if (!bap_codec_equal(&lpac->codec, &rpac->codec))
				continue;

			if (!func(lpac, rpac, user_data))
				return;
		}
	}
}

void bt_bap_foreach_pac(struct bt_bap *bap, uint8_t type,
			bt_bap_pac_foreach_t func, void *user_data)
{
	if (!bap || !func || !bap->rdb || queue_isempty(bap_db))
		return;

	switch (type) {
	case BT_BAP_SINK:
		return bap_foreach_pac(bap->ldb->sources, bap->rdb->sinks,
							func, user_data);
	case BT_BAP_SOURCE:
		return bap_foreach_pac(bap->ldb->sinks, bap->rdb->sources,
							func, user_data);
	}
}

int bt_bap_pac_get_vendor_codec(struct bt_bap_pac *pac, uint8_t *id,
				uint16_t *cid, uint16_t *vid,
				struct iovec **data, struct iovec **metadata)
{
	if (!pac)
		return -EINVAL;

	if (id)
		*id = pac->codec.id;

	if (cid)
		*cid = pac->codec.cid;

	if (vid)
		*vid = pac->codec.cid;

	if (data)
		*data = pac->data;

	if (metadata)
		*metadata = pac->metadata;

	return 0;
}

int bt_bap_pac_get_codec(struct bt_bap_pac *pac, uint8_t *id,
				struct iovec **data, struct iovec **metadata)
{
	return bt_bap_pac_get_vendor_codec(pac, id, NULL, NULL, data, metadata);
}

void bt_bap_pac_set_user_data(struct bt_bap_pac *pac, void *user_data)
{
	pac->user_data = user_data;
}

void *bt_bap_pac_get_user_data(struct bt_bap_pac *pac)
{
	return pac->user_data;
}

static bool find_ep_unused(const void *data, const void *user_data)
{
	const struct bt_bap_endpoint *ep = data;
	const struct match_pac *match = user_data;

	if (ep->stream)
		return false;

	return ep->dir == match->rpac->type;
}

static bool find_ep_pacs(const void *data, const void *user_data)
{
	const struct bt_bap_endpoint *ep = data;
	const struct match_pac *match = user_data;

	if (!ep->stream)
		return false;

	if (ep->stream->lpac != match->lpac)
		return false;

	return ep->stream->rpac == match->rpac;
}

static struct bt_bap_req *bap_req_new(struct bt_bap_stream *stream,
					uint8_t op, struct iovec *iov,
					size_t len,
					bt_bap_stream_func_t func,
					void *user_data)
{
	struct bt_bap_req *req;
	static unsigned int id;

	req = new0(struct bt_bap_req, 1);
	req->id = ++id;
	req->stream = stream;
	req->op = op;
	req->iov = iov_dup(iov, len);
	req->len = len;
	req->func = func;
	req->user_data = user_data;

	return req;
}

static bool bap_stream_valid(struct bt_bap_stream *stream)
{
	if (!stream || !stream->bap)
		return false;

	return queue_find(stream->bap->streams, NULL, stream);
}

unsigned int bt_bap_stream_config(struct bt_bap_stream *stream,
					struct bt_bap_qos *qos,
					struct iovec *data,
					bt_bap_stream_func_t func,
					void *user_data)
{
	struct iovec iov[2];
	struct bt_ascs_config config;
	uint8_t iovlen = 1;
	struct bt_bap_req *req;

	if (!bap_stream_valid(stream))
		return 0;

	if (!stream->client) {
		stream_config(stream, data, NULL);
		return 0;
	}

	memset(&config, 0, sizeof(config));

	config.ase = stream->ep->id;
	config.latency = qos->target_latency;
	config.phy = qos->phy;
	config.codec = stream->rpac->codec;

	iov[0].iov_base = &config;
	iov[0].iov_len = sizeof(config);

	if (data) {
		if (!bap_print_cc(data->iov_base, data->iov_len,
					stream->bap->debug_func,
					stream->bap->debug_data))
			return 0;

		config.cc_len = data->iov_len;
		iov[1] = *data;
		iovlen++;
	}

	req = bap_req_new(stream, BT_ASCS_CONFIG, iov, iovlen, func, user_data);

	if (!bap_queue_req(stream->bap, req)) {
		bap_req_free(req);
		return 0;
	}

	stream->qos = *qos;

	return req->id;
}

static bool match_pac(struct bt_bap_pac *lpac, struct bt_bap_pac *rpac,
							void *user_data)
{
	struct match_pac *match = user_data;

	if (match->lpac && match->lpac != lpac)
		return true;

	if (match->rpac && match->rpac != rpac)
		return true;

	match->lpac = lpac;
	match->rpac = rpac;

	return false;
}

int bt_bap_select(struct bt_bap_pac *lpac, struct bt_bap_pac *rpac,
			bt_bap_pac_select_t func, void *user_data)
{
	if (!lpac || !rpac || !func)
		return -EINVAL;

	if (!lpac->ops || !lpac->ops->select)
		return -EOPNOTSUPP;

	lpac->ops->select(lpac, rpac, &rpac->qos,
					func, user_data, lpac->user_data);

	return 0;
}

struct bt_bap_stream *bt_bap_config(struct bt_bap *bap,
					struct bt_bap_pac *lpac,
					struct bt_bap_pac *rpac,
					struct bt_bap_qos *pqos,
					struct iovec *data,
					bt_bap_stream_func_t func,
					void *user_data)
{
	struct bt_bap_stream *stream;
	struct bt_bap_endpoint *ep;
	struct match_pac match;
	int id;

	if (!bap || !bap->rdb || queue_isempty(bap->rdb->endpoints))
		return NULL;

	if (lpac && rpac) {
		if (!bap_codec_equal(&lpac->codec, &rpac->codec))
			return NULL;
	} else {
		uint8_t type;

		match.lpac = lpac;
		match.rpac = rpac;
		memset(&match.codec, 0, sizeof(match.codec));

		if (rpac)
			type = rpac->type;
		else if (lpac) {
			switch(lpac->type) {
			case BT_BAP_SINK:
				type = BT_BAP_SOURCE;
				break;
			case BT_BAP_SOURCE:
				type = BT_BAP_SINK;
				break;
			default:
				return NULL;
			}
		} else
			return NULL;

		bt_bap_foreach_pac(bap, type, match_pac, &match);
		if (!match.lpac || !match.rpac)
			return NULL;

		lpac = match.lpac;
		rpac = match.rpac;
	}

	match.lpac = lpac;
	match.rpac = rpac;

	/* Check for existing stream */
	ep = queue_find(bap->rdb->endpoints, find_ep_pacs, &match);
	if (!ep) {
		/* Check for unused ASE */
		ep = queue_find(bap->rdb->endpoints, find_ep_unused, &match);
		if (!ep) {
			DBG(bap, "Unable to find unused ASE");
			return NULL;
		}
	}

	stream = ep->stream;
	if (!stream)
		stream = bap_stream_new(bap, ep, lpac, rpac, data, true);

	id = bt_bap_stream_config(stream, pqos, data, func, user_data);
	if (!id) {
		DBG(bap, "Unable to config stream");
		queue_remove(bap->streams, stream);
		ep->stream = NULL;
		free(stream);
		return NULL;
	}

	return stream;
}

struct bt_bap *bt_bap_stream_get_session(struct bt_bap_stream *stream)
{
	if (!stream)
		return NULL;

	return stream->bap;
}

uint8_t bt_bap_stream_get_state(struct bt_bap_stream *stream)
{
	if (!stream)
		return BT_BAP_STREAM_STATE_IDLE;

	return stream->ep->state;
}

bool bt_bap_stream_set_user_data(struct bt_bap_stream *stream, void *user_data)
{
	if (!stream)
		return false;

	stream->user_data = user_data;

	return true;
}

void *bt_bap_stream_get_user_data(struct bt_bap_stream *stream)
{
	if (!stream)
		return NULL;

	return stream->user_data;
}

unsigned int bt_bap_stream_qos(struct bt_bap_stream *stream,
					struct bt_bap_qos *data,
					bt_bap_stream_func_t func,
					void *user_data)
{
	struct iovec iov;
	struct bt_ascs_qos qos;
	struct bt_bap_req *req;

	if (!bap_stream_valid(stream))
		return 0;

	if (!stream->client) {
		stream_qos(stream, data, NULL);
		return 0;
	}

	memset(&qos, 0, sizeof(qos));

	/* TODO: Figure out how to pass these values around */
	qos.ase = stream->ep->id;
	qos.cig = data->cig_id;
	qos.cis = data->cis_id;
	put_le24(data->interval, qos.interval);
	qos.framing = data->framing;
	qos.phy = data->phy;
	qos.sdu = cpu_to_le16(data->sdu);
	qos.rtn = data->rtn;
	qos.latency = cpu_to_le16(data->latency);
	put_le24(data->delay, qos.pd);

	iov.iov_base = &qos;
	iov.iov_len = sizeof(qos);

	req = bap_req_new(stream, BT_ASCS_QOS, &iov, 1, func, user_data);

	if (!bap_queue_req(stream->bap, req)) {
		bap_req_free(req);
		return 0;
	}

	stream->qos = *data;

	return req->id;
}

static int bap_stream_metadata(struct bt_bap_stream *stream, uint8_t op,
					struct iovec *data,
					bt_bap_stream_func_t func,
					void *user_data)
{
	struct iovec iov[2];
	struct bt_ascs_metadata meta;
	struct bt_bap_req *req;
	struct metadata {
		uint8_t len;
		uint8_t type;
		uint8_t data[2];
	} ctx = LTV(0x02, 0x01, 0x00); /* Context = Unspecified */

	memset(&meta, 0, sizeof(meta));

	meta.ase = stream->ep->id;

	iov[0].iov_base = &meta;
	iov[0].iov_len = sizeof(meta);

	if (data)
		iov[1] = *data;
	else {
		iov[1].iov_base = &ctx;
		iov[1].iov_len = sizeof(ctx);
	}

	meta.len = iov[1].iov_len;

	req = bap_req_new(stream, op, iov, 2, func, user_data);

	if (!bap_queue_req(stream->bap, req)) {
		bap_req_free(req);
		return 0;
	}

	return req->id;
}

static void bap_stream_enable_link(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	struct iovec *metadata = user_data;

	bap_stream_metadata(stream, BT_ASCS_ENABLE, metadata, NULL, NULL);
}

unsigned int bt_bap_stream_enable(struct bt_bap_stream *stream,
					bool enable_links,
					struct iovec *metadata,
					bt_bap_stream_func_t func,
					void *user_data)
{
	int ret;

	if (!bap_stream_valid(stream))
		return 0;

	if (!stream->client) {
		stream_enable(stream, metadata, NULL);
		return 0;
	}

	ret = bap_stream_metadata(stream, BT_ASCS_ENABLE, metadata, func,
								user_data);
	if (!ret || !enable_links)
		return ret;

	queue_foreach(stream->links, bap_stream_enable_link, metadata);

	return ret;
}

unsigned int bt_bap_stream_start(struct bt_bap_stream *stream,
					bt_bap_stream_func_t func,
					void *user_data)
{
	struct iovec iov;
	struct bt_ascs_start start;
	struct bt_bap_req *req;

	if (!bap_stream_valid(stream))
		return 0;

	if (!stream->client) {
		if (stream->ep->dir == BT_BAP_SINK)
			stream_start(stream, NULL);
		return 0;
	}

	if (stream->ep->dir == BT_BAP_SINK)
		return 0;

	memset(&start, 0, sizeof(start));

	start.ase = stream->ep->id;

	iov.iov_base = &start;
	iov.iov_len = sizeof(start);

	req = bap_req_new(stream, BT_ASCS_START, &iov, 1, func, user_data);

	if (!bap_queue_req(stream->bap, req)) {
		bap_req_free(req);
		return 0;
	}

	return req->id;
}

static void bap_stream_disable_link(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	struct bt_bap_req *req;
	struct iovec iov;
	struct bt_ascs_disable disable;

	memset(&disable, 0, sizeof(disable));

	disable.ase = stream->ep->id;

	iov.iov_base = &disable;
	iov.iov_len = sizeof(disable);

	req = bap_req_new(stream, BT_ASCS_DISABLE, &iov, 1, NULL, NULL);

	if (!bap_queue_req(stream->bap, req))
		bap_req_free(req);
}

unsigned int bt_bap_stream_disable(struct bt_bap_stream *stream,
					bool disable_links,
					bt_bap_stream_func_t func,
					void *user_data)
{
	struct iovec iov;
	struct bt_ascs_disable disable;
	struct bt_bap_req *req;

	if (!bap_stream_valid(stream))
		return 0;

	if (!stream->client) {
		stream_disable(stream, NULL);
		return 0;
	}

	memset(&disable, 0, sizeof(disable));

	disable.ase = stream->ep->id;

	iov.iov_base = &disable;
	iov.iov_len = sizeof(disable);

	req = bap_req_new(stream, BT_ASCS_DISABLE, &iov, 1, func, user_data);

	if (!bap_queue_req(stream->bap, req)) {
		bap_req_free(req);
		return 0;
	}

	if (disable_links)
		queue_foreach(stream->links, bap_stream_disable_link, NULL);

	return req->id;
}

unsigned int bt_bap_stream_stop(struct bt_bap_stream *stream,
					bt_bap_stream_func_t func,
					void *user_data)
{
	struct iovec iov;
	struct bt_ascs_stop stop;
	struct bt_bap_req *req;

	if (!bap_stream_valid(stream))
		return 0;

	if (!stream->client) {
		if (stream->ep->dir == BT_BAP_SINK)
			stream_stop(stream, NULL);
		return 0;
	}

	if (stream->ep->dir == BT_BAP_SINK)
		return 0;

	memset(&stop, 0, sizeof(stop));

	stop.ase = stream->ep->id;

	iov.iov_base = &stop;
	iov.iov_len = sizeof(stop);

	req = bap_req_new(stream, BT_ASCS_STOP, &iov, 1, func, user_data);

	if (!bap_queue_req(stream->bap, req)) {
		bap_req_free(req);
		return 0;
	}

	return req->id;
}

unsigned int bt_bap_stream_metadata(struct bt_bap_stream *stream,
					struct iovec *metadata,
					bt_bap_stream_func_t func,
					void *user_data)
{
	if (!stream)
		return 0;

	if (!stream->client) {
		stream_metadata(stream, metadata, NULL);
		return 0;
	}

	return bap_stream_metadata(stream, BT_ASCS_METADATA, metadata, func,
								user_data);
}

unsigned int bt_bap_stream_release(struct bt_bap_stream *stream,
					bt_bap_stream_func_t func,
					void *user_data)
{
	struct iovec iov;
	struct bt_ascs_release rel;
	struct bt_bap_req *req;

	if (!stream)
		return 0;

	if (!stream->client) {
		stream_release(stream, NULL);
		return 0;
	}

	memset(&req, 0, sizeof(req));

	rel.ase = stream->ep->id;

	iov.iov_base = &rel;
	iov.iov_len = sizeof(rel);

	req = bap_req_new(stream, BT_ASCS_RELEASE, &iov, 1, func, user_data);

	if (!bap_queue_req(stream->bap, req)) {
		bap_req_free(req);
		return 0;
	}

	return req->id;
}

uint8_t bt_bap_stream_get_dir(struct bt_bap_stream *stream)
{
	if (!stream)
		return 0x00;

	return stream->ep->dir;
}

uint32_t bt_bap_stream_get_location(struct bt_bap_stream *stream)
{
	struct bt_bap_pac *pac;

	if (!stream)
		return 0x00000000;

	pac = stream->rpac ? stream->rpac : stream->lpac;

	return pac->locations;
}

struct iovec *bt_bap_stream_get_config(struct bt_bap_stream *stream)
{
	if (!stream)
		return NULL;

	return stream->cc;
}

struct bt_bap_qos *bt_bap_stream_get_qos(struct bt_bap_stream *stream)
{
	if (!stream)
		return NULL;

	return &stream->qos;
}

struct iovec *bt_bap_stream_get_metadata(struct bt_bap_stream *stream)
{
	if (!stream)
		return NULL;

	return stream->meta;
}

struct io *bt_bap_stream_get_io(struct bt_bap_stream *stream)
{
	struct bt_bap_stream_io *io;

	io = stream_get_io(stream);
	if (!io || io->connecting)
		return NULL;

	return io->io;
}

static bool stream_io_disconnected(struct io *io, void *user_data)
{
	struct bt_bap_stream *stream = user_data;

	DBG(stream->bap, "stream %p io disconnected", stream);

	bt_bap_stream_set_io(stream, -1);

	return false;
}

bool bt_bap_stream_set_io(struct bt_bap_stream *stream, int fd)
{
	if (!stream || (fd >= 0 && stream->io && !stream->io->connecting))
		return false;

	bap_stream_set_io(stream, INT_TO_PTR(fd));

	queue_foreach(stream->links, bap_stream_set_io, INT_TO_PTR(fd));

	return true;
}

static bool match_req_id(const void *data, const void *match_data)
{
	const struct bt_bap_req *req = data;
	unsigned int id = PTR_TO_UINT(match_data);

	return (req->id == id);
}

int bt_bap_stream_cancel(struct bt_bap_stream *stream, unsigned int id)
{
	struct bt_bap_req *req;

	if (!stream)
		return -EINVAL;

	if (stream->bap->req && stream->bap->req->id == id) {
		req = stream->bap->req;
		stream->bap->req = NULL;
		bap_req_free(req);
		return 0;
	}

	req = queue_remove_if(stream->bap->reqs, match_req_id,
						UINT_TO_PTR(id));
	if (!req)
		return 0;

	bap_req_free(req);

	return 0;
}

int bt_bap_stream_io_link(struct bt_bap_stream *stream,
				struct bt_bap_stream *link)
{
	struct bt_bap *bap = stream->bap;

	if (!stream || !link || stream == link)
		return -EINVAL;

	if (queue_find(stream->links, NULL, link))
		return -EALREADY;

	if (stream->client != link->client ||
			stream->qos.cig_id != link->qos.cig_id ||
			stream->qos.cis_id != link->qos.cis_id)
		return -EINVAL;

	if (!stream->links)
		stream->links = queue_new();

	if (!link->links)
		link->links = queue_new();

	queue_push_tail(stream->links, link);
	queue_push_tail(link->links, stream);

	/* Link IOs if already set on stream/link */
	if (stream->io && !link->io)
		link->io = stream_io_ref(stream->io);
	else if (link->io && !stream->io)
		stream->io = stream_io_ref(link->io);

	DBG(bap, "stream %p link %p", stream, link);

	return 0;
}

struct queue *bt_bap_stream_io_get_links(struct bt_bap_stream *stream)
{
	if (!stream)
		return NULL;

	return stream->links;
}

static void bap_stream_get_in_qos(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	struct bt_bap_qos **qos = user_data;

	if (!qos || *qos || stream->ep->dir != BT_BAP_SOURCE ||
						!stream->qos.sdu)
		return;

	*qos = &stream->qos;
}

static void bap_stream_get_out_qos(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	struct bt_bap_qos **qos = user_data;

	if (!qos || *qos || stream->ep->dir != BT_BAP_SINK || !stream->qos.sdu)
		return;

	*qos = &stream->qos;
}

bool bt_bap_stream_io_get_qos(struct bt_bap_stream *stream,
					struct bt_bap_qos **in,
					struct bt_bap_qos **out)
{
	if (!stream || (!in && !out))
		return false;

	switch (stream->ep->dir) {
	case BT_BAP_SOURCE:
		bap_stream_get_in_qos(stream, in);
		queue_foreach(stream->links, bap_stream_get_out_qos, out);
		break;
	case BT_BAP_SINK:
		bap_stream_get_out_qos(stream, out);
		queue_foreach(stream->links, bap_stream_get_in_qos, in);
		break;
	default:
		return false;
	}

	DBG(stream->bap, "in %p out %p", in ? *in : NULL, out ? *out : NULL);

	return in && out;
}

static void bap_stream_get_dir(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	uint8_t *dir = user_data;

	*dir |= stream->ep->dir;
}

uint8_t bt_bap_stream_io_dir(struct bt_bap_stream *stream)
{
	uint8_t dir;

	if (!stream)
		return 0x00;

	dir = stream->ep->dir;

	queue_foreach(stream->links, bap_stream_get_dir, &dir);

	return dir;
}

static void bap_stream_io_connecting(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	int fd = PTR_TO_INT(user_data);
	const struct queue_entry *entry;

	if (fd >= 0)
		bap_stream_io_attach(stream, fd, true);
	else
		bap_stream_io_detach(stream);

	for (entry = queue_get_entries(stream->bap->state_cbs); entry;
							entry = entry->next) {
		struct bt_bap_state *state = entry->data;

		if (state->connecting)
			state->connecting(stream, stream->io ? true : false,
							fd, state->data);
	}
}

int bt_bap_stream_io_connecting(struct bt_bap_stream *stream, int fd)
{
	if (!stream)
		return -EINVAL;

	bap_stream_io_connecting(stream, INT_TO_PTR(fd));

	queue_foreach(stream->links, bap_stream_io_connecting, INT_TO_PTR(fd));

	return 0;
}

bool bt_bap_stream_io_is_connecting(struct bt_bap_stream *stream, int *fd)
{
	struct bt_bap_stream_io *io;

	if (!stream)
		return false;

	io = stream_get_io(stream);
	if (!io)
		return false;

	if (fd)
		*fd = stream_io_get_fd(io);

	return io->connecting;
}
