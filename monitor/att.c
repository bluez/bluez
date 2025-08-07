// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright 2023 NXP
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"
#include "bluetooth/hci.h"
#include "bluetooth/hci_lib.h"

#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/textfile.h"
#include "src/settings.h"
#include "bt.h"
#include "packet.h"
#include "display.h"
#include "l2cap.h"
#include "att.h"
#include "keys.h"

struct att_read {
	struct att_conn_data *conn;
	struct gatt_db_attribute *attr;
	bool in;
	uint16_t chan;
	void (*func)(const struct l2cap_frame *frame);
	struct iovec *iov;
};

struct att_conn_data {
	struct gatt_db *ldb;
	struct timespec ldb_mtim;
	struct gatt_db *rdb;
	struct timespec rdb_mtim;
	struct queue *reads;
	uint16_t mtu;
};

struct gatt_cache {
	bdaddr_t id;
	struct gatt_db *db;
};

static struct queue *cache_list;

static void print_uuid(const char *label, const void *data, uint16_t size)
{
	const char *str;
	char uuidstr[MAX_LEN_UUID_STR];

	switch (size) {
	case 2:
		str = bt_uuid16_to_str(get_le16(data));
		print_field("%s: %s (0x%4.4x)", label, str, get_le16(data));
		break;
	case 4:
		str = bt_uuid32_to_str(get_le32(data));
		print_field("%s: %s (0x%8.8x)", label, str, get_le32(data));
		break;
	case 16:
		sprintf(uuidstr, "%8.8x-%4.4x-%4.4x-%4.4x-%8.8x%4.4x",
				get_le32(data + 12), get_le16(data + 10),
				get_le16(data + 8), get_le16(data + 6),
				get_le32(data + 2), get_le16(data + 0));
		str = bt_uuidstr_to_str(uuidstr);
		print_field("%s: %s (%s)", label, str, uuidstr);
		break;
	default:
		packet_hexdump(data, size);
		break;
	}
}

static void print_handle_range(const char *label, const void *data)
{
	print_field("%s: 0x%4.4x-0x%4.4x", label,
				get_le16(data), get_le16(data + 2));
}

static bool match_read_frame(const void *data, const void *match_data)
{
	const struct att_read *read = data;
	const struct l2cap_frame *frame = match_data;

	/* Read frame and response frame shall be in the opposite direction to
	 * match.
	 */
	if (read->in == frame->in)
		return false;

	return read->chan == frame->chan;
}

static struct att_read *att_get_read(const struct l2cap_frame *frame)
{
	struct packet_conn_data *conn;
	struct att_conn_data *data;

	conn = packet_get_conn_data(frame->handle);
	if (!conn)
		return NULL;

	data = conn->data;
	if (!data)
		return NULL;

	return queue_remove_if(data->reads, match_read_frame, (void *)frame);
}

static void print_value(struct gatt_db_attribute *attr)
{
	uint16_t handle;
	struct gatt_db_attribute *val;
	const bt_uuid_t *uuid;
	bt_uuid_t chrc = {
		.type = BT_UUID16,
		.value.u16 = 0x2803,
	};
	char label[27];

	uuid = gatt_db_attribute_get_type(attr);
	if (!uuid)
		return;

	/* Skip in case of characteristic declaration since it already prints
	 * the value handle and properties.
	 */
	if (!bt_uuid_cmp(uuid, &chrc))
		return;

	val = gatt_db_attribute_get_value(attr);
	if (!val || val == attr)
		return;

	uuid = gatt_db_attribute_get_type(val);
	if (!uuid)
		return;

	handle = gatt_db_attribute_get_handle(val);
	if (!handle)
		return;

	switch (uuid->type) {
	case BT_UUID16:
		sprintf(label, "Value Handle: 0x%4.4x Type", handle);
		print_field("%s: %s (0x%4.4x)", label,
				bt_uuid16_to_str(uuid->value.u16),
				uuid->value.u16);
		return;
	case BT_UUID128:
		sprintf(label, "Value Handle: 0x%4.4x Type", handle);
		print_uuid(label, &uuid->value.u128, 16);
		return;
	case BT_UUID_UNSPEC:
	case BT_UUID32:
		break;
	}
}

static void print_attribute(struct gatt_db_attribute *attr)
{
	uint16_t handle;
	const bt_uuid_t *uuid;
	char label[21];

	handle = gatt_db_attribute_get_handle(attr);
	if (!handle)
		goto done;

	uuid = gatt_db_attribute_get_type(attr);
	if (!uuid)
		goto done;

	switch (uuid->type) {
	case BT_UUID16:
		sprintf(label, "Handle: 0x%4.4x Type", handle);
		print_field("%s: %s (0x%4.4x)", label,
				bt_uuid16_to_str(uuid->value.u16),
				uuid->value.u16);
		print_value(attr);
		return;
	case BT_UUID128:
		sprintf(label, "Handle: 0x%4.4x Type", handle);
		print_uuid(label, &uuid->value.u128, 16);
		print_value(attr);
		return;
	case BT_UUID_UNSPEC:
	case BT_UUID32:
		break;
	}

done:
	print_field("Handle: 0x%4.4x", handle);
}

static void att_read_free(struct att_read *read)
{
	if (!read)
		return;

	util_iov_free(read->iov, 1);
	free(read);
}

static void print_data_list(const char *label, uint8_t length,
					const struct l2cap_frame *frame)
{
	struct att_read *read;
	uint8_t count;

	if (length == 0)
		return;

	read = att_get_read(frame);

	count = frame->size / length;

	print_field("%s: %u entr%s", label, count, count == 1 ? "y" : "ies");

	while (frame->size >= length) {
		if (!l2cap_frame_print_le16((void *)frame, "Handle"))
			break;

		print_hex_field("Value", frame->data, length - 2);

		if (read && read->func) {
			struct l2cap_frame f;

			l2cap_frame_clone_size(&f, frame, length - 2);

			read->func(&f);
		}

		if (!l2cap_frame_pull((void *)frame, frame, length - 2))
			break;
	}

	packet_hexdump(frame->data, frame->size);
	att_read_free(read);
}

static void print_attribute_info(uint16_t type, const void *data, uint16_t len)
{
	const char *str = bt_uuid16_to_str(type);

	print_field("%s: %s (0x%4.4x)", "Attribute type", str, type);

	switch (type) {
	case 0x2800:	/* Primary Service */
	case 0x2801:	/* Secondary Service */
		print_uuid("  UUID", data, len);
		break;
	case 0x2802:	/* Include */
		if (len < 4) {
			print_hex_field("  Value", data, len);
			break;
		}
		print_handle_range("  Handle range", data);
		print_uuid("  UUID", data + 4, len - 4);
		break;
	case 0x2803:	/* Characteristic */
		if (len < 3) {
			print_hex_field("  Value", data, len);
			break;
		}
		print_field("  Properties: 0x%2.2x", *((uint8_t *) data));
		print_field("  Handle: 0x%2.2x", get_le16(data + 1));
		print_uuid("  UUID", data + 3, len - 3);
		break;
	default:
		print_hex_field("Value", data, len);
		break;
	}
}

static const char *att_opcode_to_str(uint8_t opcode);

static void att_error_response(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_att_error_response *pdu = frame->data;
	const char *str;

	switch (pdu->error) {
	case 0x01:
		str = "Invalid Handle";
		break;
	case 0x02:
		str = "Read Not Permitted";
		break;
	case 0x03:
		str = "Write Not Permitted";
		break;
	case 0x04:
		str = "Invalid PDU";
		break;
	case 0x05:
		str = "Insufficient Authentication";
		break;
	case 0x06:
		str = "Request Not Supported";
		break;
	case 0x07:
		str = "Invalid Offset";
		break;
	case 0x08:
		str = "Insufficient Authorization";
		break;
	case 0x09:
		str = "Prepare Queue Full";
		break;
	case 0x0a:
		str = "Attribute Not Found";
		break;
	case 0x0b:
		str = "Attribute Not Long";
		break;
	case 0x0c:
		str = "Insufficient Encryption Key Size";
		break;
	case 0x0d:
		str = "Invalid Attribute Value Length";
		break;
	case 0x0e:
		str = "Unlikely Error";
		break;
	case 0x0f:
		str = "Insufficient Encryption";
		break;
	case 0x10:
		str = "Unsupported Group Type";
		break;
	case 0x11:
		str = "Insufficient Resources";
		break;
	case 0x12:
		str = "Database Out of Sync";
		break;
	case 0x13:
		str = "Value Not Allowed";
		break;
	case 0xfd:
		str = "CCC Improperly Configured";
		break;
	case 0xfe:
		str = "Procedure Already in Progress";
		break;
	case 0xff:
		str = "Out of Range";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("%s (0x%2.2x)", att_opcode_to_str(pdu->request),
							pdu->request);
	print_field("Handle: 0x%4.4x", le16_to_cpu(pdu->handle));
	print_field("Error: %s (0x%2.2x)", str, pdu->error);

	/* Read/Read By Type/Read By Group Type may create a read object which
	 * needs to be dequeued and freed in case the operation fails.
	 */
	if (pdu->request == 0x08 || pdu->request == 0x0a ||
					pdu->request == 0x10)
		att_read_free(att_get_read(frame));
}

static const struct bitfield_data chrc_prop_table[] = {
	{  0, "Broadcast (0x01)"		},
	{  1, "Read (0x02)"			},
	{  2, "Write Without Response (0x04)"	},
	{  3, "Write (0x08)"			},
	{  4, "Notify (0x10)"			},
	{  5, "Indicate (0x20)"			},
	{  6, "Authorize (0x40)"		},
	{  6, "Extended Properties (0x80)"	},
	{ }
};

static bool match_cache_id(const void *data, const void *match_data)
{
	const struct gatt_cache *cache = data;
	const bdaddr_t *id = match_data;

	return !bacmp(&cache->id, id);
}

static void gatt_cache_add(struct packet_conn_data *conn, struct gatt_db *db)
{
	struct gatt_cache *cache;
	bdaddr_t id;
	uint8_t id_type;

	if (!keys_resolve_identity(conn->dst, id.b, &id_type))
		bacpy(&id, (bdaddr_t *)conn->dst);

	if (queue_find(cache_list, match_cache_id, &id))
		return;

	if (!cache_list)
		cache_list = queue_new();

	cache = new0(struct gatt_cache, 1);
	bacpy(&cache->id, &id);
	cache->db = gatt_db_ref(db);
	queue_push_tail(cache_list, cache);
}

static void att_conn_data_free(struct packet_conn_data *conn, void *data)
{
	struct att_conn_data *att_data = data;

	if (!gatt_db_isempty(att_data->rdb))
		gatt_cache_add(conn, att_data->rdb);

	gatt_db_unref(att_data->rdb);
	gatt_db_unref(att_data->ldb);
	queue_destroy(att_data->reads, free);
	free(att_data);
}

static struct att_conn_data *att_get_conn_data(struct packet_conn_data *conn)
{
	struct att_conn_data *data;

	if (!conn)
		return NULL;

	data = conn->data;

	if (data)
		return data;

	data = new0(struct att_conn_data, 1);
	data->rdb = gatt_db_new();
	data->ldb = gatt_db_new();
	conn->data = data;
	conn->destroy = att_conn_data_free;

	return data;
}

static void gatt_load_db(struct gatt_db *db, const char *filename,
						struct timespec *mtim)
{
	struct stat st;

	if (lstat(filename, &st))
		return;

	if (!gatt_db_isempty(db)) {
		/* Check if file has been modified since last time */
		if (st.st_mtim.tv_sec == mtim->tv_sec &&
				    st.st_mtim.tv_nsec == mtim->tv_nsec)
			return;
		/* Clear db before reloading */
		gatt_db_clear(db);
	}

	*mtim = st.st_mtim;

	btd_settings_gatt_db_load(db, filename);
}

static void load_gatt_db(struct packet_conn_data *conn)
{
	struct att_conn_data *data = att_get_conn_data(conn);
	char filename[PATH_MAX];
	char local[18];
	char peer[18];
	bdaddr_t id;
	uint8_t id_type;

	ba2str((bdaddr_t *)conn->src, local);

	if (keys_resolve_identity(conn->dst, id.b, &id_type)) {
		ba2str(&id, peer);
	} else {
		bacpy(&id, (bdaddr_t *)conn->dst);
		ba2str((bdaddr_t *)conn->dst, peer);
	}

	create_filename(filename, PATH_MAX, "/%s/attributes", local);
	gatt_load_db(data->ldb, filename, &data->ldb_mtim);

	create_filename(filename, PATH_MAX, "/%s/cache/%s", local, peer);
	gatt_load_db(data->rdb, filename, &data->rdb_mtim);

	/* If rdb cannot be loaded from file try local cache */
	if (gatt_db_isempty(data->rdb)) {
		struct gatt_cache *cache;

		cache = queue_find(cache_list, match_cache_id, &id);
		if (cache)
			data->rdb = gatt_db_ref(cache->db);
	}
}

static struct gatt_db *get_db(const struct l2cap_frame *frame, bool rsp)
{
	struct packet_conn_data *conn;
	struct att_conn_data *data;
	struct gatt_db *db;

	conn = packet_get_conn_data(frame->handle);
	if (!conn)
		return NULL;

	/* Try loading local and remote gatt_db if not loaded yet */
	load_gatt_db(conn);

	data = conn->data;
	if (!data)
		return NULL;

	if (frame->in) {
		if (rsp)
			db = data->rdb;
		else
			db = data->ldb;
	} else {
		if (rsp)
			db = data->ldb;
		else
			db = data->rdb;
	}

	return db;
}

static struct gatt_db_attribute *insert_chrc(const struct l2cap_frame *frame,
						uint16_t handle,
						uint16_t value_handle,
						bt_uuid_t *uuid, uint8_t prop,
						bool rsp)
{
	struct gatt_db *db;

	db = get_db(frame, rsp);
	if (!db)
		return NULL;

	return gatt_db_insert_characteristic(db, handle, value_handle, uuid, 0,
						prop, NULL, NULL, NULL);
}

static int bt_uuid_from_data(bt_uuid_t *uuid, const void *data, uint16_t size)
{
	uint128_t u128;

	if (!uuid)
		return -EINVAL;

	switch (size) {
	case 2:
		return bt_uuid16_create(uuid, get_le16(data));
	case 4:
		return bt_uuid32_create(uuid, get_le32(data));
	case 16:
		memcpy(u128.data, data, sizeof(u128.data));
		return bt_uuid128_create(uuid, u128);
	}

	return -EINVAL;
}

static bool svc_read(const struct l2cap_frame *frame, uint16_t *start,
			uint16_t *end, bt_uuid_t *uuid)
{
	if (!l2cap_frame_get_le16((void *)frame, start))
		return false;

	if (!l2cap_frame_get_le16((void *)frame, end))
		return false;

	return !bt_uuid_from_data(uuid, frame->data, frame->size);
}

static struct gatt_db_attribute *insert_svc(const struct l2cap_frame *frame,
						uint16_t handle,
						bt_uuid_t *uuid, bool primary,
						bool rsp, uint16_t num_handles)
{
	struct gatt_db *db;

	db = get_db(frame, rsp);
	if (!db)
		return NULL;

	return gatt_db_insert_service(db, handle, uuid, primary, num_handles);
}

static void pri_svc_read(const struct l2cap_frame *frame)
{
	uint16_t start, end;
	bt_uuid_t uuid;

	if (!svc_read(frame, &start, &end, &uuid))
		return;

	insert_svc(frame, start, &uuid, true, true, end - start + 1);
}

static void sec_svc_read(const struct l2cap_frame *frame)
{
	uint16_t start, end;
	bt_uuid_t uuid;

	if (!svc_read(frame, &start, &end, &uuid))
		return;

	insert_svc(frame, start, &uuid, true, false, end - start + 1);
}

static void print_chrc(const struct l2cap_frame *frame)
{
	uint8_t prop;
	uint8_t mask;
	uint16_t handle;
	bt_uuid_t uuid;

	if (!l2cap_frame_get_u8((void *)frame, &prop)) {
		print_text(COLOR_ERROR, "Property: invalid size");
		return;
	}

	print_field("    Properties: 0x%2.2x", prop);

	mask = print_bitfield(6, prop, chrc_prop_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%2.2x)",
								mask);

	if (!l2cap_frame_get_le16((void *)frame, &handle)) {
		print_text(COLOR_ERROR, "    Value Handle: invalid size");
		return;
	}

	print_field("    Value Handle: 0x%4.4x", handle);
	print_uuid("    Value UUID", frame->data, frame->size);
	bt_uuid_from_data(&uuid, frame->data, frame->size);

	insert_chrc(frame, handle - 1, handle, &uuid, prop, true);
}

static void chrc_read(const struct l2cap_frame *frame)
{
	print_chrc(frame);
}

static const struct bitfield_data ccc_value_table[] = {
	{  0, "Notification (0x01)"		},
	{  1, "Indication (0x02)"		},
	{ }
};

static void print_ccc_value(const struct l2cap_frame *frame)
{
	uint8_t value;
	uint8_t mask;

	if (!l2cap_frame_get_u8((void *)frame, &value)) {
		print_text(COLOR_ERROR, "invalid size");
		return;
	}

	mask = print_bitfield(4, value, ccc_value_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%2.2x)",
								mask);
}

static void ccc_read(const struct l2cap_frame *frame)
{
	print_ccc_value(frame);
}

static void ccc_write(const struct l2cap_frame *frame)
{
	print_ccc_value(frame);
}

static bool print_ase_codec(const struct l2cap_frame *frame)
{
	uint8_t codec_id;
	uint16_t codec_cid, codec_vid;

	if (!l2cap_frame_get_u8((void *)frame, &codec_id)) {
		print_text(COLOR_ERROR, "Codec: invalid size");
		return false;
	}

	packet_print_codec_id("    Codec", codec_id);

	if (!l2cap_frame_get_le16((void *)frame, &codec_cid)) {
		print_text(COLOR_ERROR, "Codec Company ID: invalid size");
		return false;
	}

	if (!l2cap_frame_get_le16((void *)frame, &codec_vid)) {
		print_text(COLOR_ERROR, "Codec Vendor ID: invalid size");
		return false;
	}

	if (codec_id == 0xff) {
		print_field("    Codec Company ID: %s (0x%04x)",
						bt_compidtostr(codec_cid),
						codec_cid);
		print_field("    Codec Vendor ID: 0x%04x", codec_vid);
	}

	return true;
}

static void print_ltv(const char *str, void *user_data)
{
	const char *label = user_data;

	print_field("%s: %s", label, str);
}

static bool print_ase_lv(const struct l2cap_frame *frame, const char *label,
			const struct util_ltv_debugger *decoder,
			size_t decoder_len)
{
	struct bt_hci_lv_data *lv;

	lv = l2cap_frame_pull((void *)frame, frame, sizeof(*lv));
	if (!lv) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	if (!l2cap_frame_pull((void *)frame, frame, lv->len)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	util_debug_ltv(lv->data, lv->len, decoder, decoder_len, print_ltv,
			(void *) label);

	return true;
}

static bool print_ase_cc(const struct l2cap_frame *frame, const char *label,
			const struct util_ltv_debugger *decoder,
			size_t decoder_len)
{
	return print_ase_lv(frame, label, decoder, decoder_len);
}

static const struct bitfield_data pac_context_table[] = {
	{  0, "Unspecified (0x0001)"			},
	{  1, "Conversational (0x0002)"			},
	{  2, "Media (0x0004)"				},
	{  3, "Game (0x0008)"				},
	{  4, "Instructional (0x0010)"			},
	{  5, "Voice Assistants (0x0020)"		},
	{  6, "Live (0x0040)"				},
	{  7, "Sound Effects (0x0080)"			},
	{  8, "Notifications (0x0100)"			},
	{  9, "Ringtone (0x0200)"			},
	{  10, "Alerts (0x0400)"			},
	{  11, "Emergency alarm (0x0800)"		},
	{  12, "RFU (0x1000)"				},
	{  13, "RFU (0x2000)"				},
	{  14, "RFU (0x4000)"				},
	{  15, "RFU (0x8000)"				},
	{ }
};

static void print_context(const struct l2cap_frame *frame, const char *label)
{
	uint16_t value;
	uint16_t mask;

	if (!l2cap_frame_get_le16((void *)frame, &value)) {
		print_text(COLOR_ERROR, "    value: invalid size");
		goto done;
	}

	print_field("%s: 0x%4.4x", label, value);

	mask = print_bitfield(8, value, pac_context_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%4.4x)",
								mask);

done:
	if (frame->size)
		print_hex_field("    Data", frame->data, frame->size);
}

static void ase_debug_preferred_context(const uint8_t *data, uint8_t len,
				util_debug_func_t func, void *user_data)
{
	struct l2cap_frame frame;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	print_context(&frame, "      Preferred Context");
}

static void ase_debug_context(const uint8_t *data, uint8_t len,
				util_debug_func_t func, void *user_data)
{
	struct l2cap_frame frame;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	print_context(&frame, "      Context");
}

static void ase_debug_program_info(const uint8_t *data, uint8_t len,
				util_debug_func_t func, void *user_data)
{
	struct l2cap_frame frame;
	const char *str;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	str = l2cap_frame_pull(&frame, &frame, len);
	if (!str) {
		print_text(COLOR_ERROR, "    value: invalid size");
		goto done;
	}

	print_field("      Program Info: %s", str);

done:
	if (frame.size)
		print_hex_field("    Data", frame.data, frame.size);
}

static void ase_debug_language(const uint8_t *data, uint8_t len,
				util_debug_func_t func, void *user_data)
{
	struct l2cap_frame frame;
	uint32_t value;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	if (!l2cap_frame_get_le24(&frame, &value)) {
		print_text(COLOR_ERROR, "    value: invalid size");
		goto done;
	}

	print_field("      Language: 0x%6.6x", value);

done:
	if (frame.size)
		print_hex_field("    Data", frame.data, frame.size);
}

static const struct util_ltv_debugger ase_metadata_table[] = {
	UTIL_LTV_DEBUG(0x01, ase_debug_preferred_context),
	UTIL_LTV_DEBUG(0x02, ase_debug_context),
	UTIL_LTV_DEBUG(0x03, ase_debug_program_info),
	UTIL_LTV_DEBUG(0x04, ase_debug_language)
};

static bool print_ase_metadata(const struct l2cap_frame *frame)
{
	return print_ase_lv(frame, "    Metadata", ase_metadata_table,
					ARRAY_SIZE(ase_metadata_table));
}

static const struct bitfield_data pac_freq_table[] = {
	{  0, "8 Khz (0x0001)"				},
	{  1, "11.25 Khz (0x0002)"			},
	{  2, "16 Khz (0x0004)"				},
	{  3, "22.05 Khz (0x0008)"			},
	{  4, "24 Khz (0x0010)"				},
	{  5, "32 Khz (0x0020)"				},
	{  6, "44.1 Khz (0x0040)"			},
	{  7, "48 Khz (0x0080)"				},
	{  8, "88.2 Khz (0x0100)"			},
	{  9, "96 Khz (0x0200)"				},
	{  10, "176.4 Khz (0x0400)"			},
	{  11, "192 Khz (0x0800)"			},
	{  12, "384 Khz (0x1000)"			},
	{  13, "RFU (0x2000)"				},
	{  14, "RFU (0x4000)"				},
	{  15, "RFU (0x8000)"				},
	{ }
};

static void pac_decode_freq(const uint8_t *data, uint8_t len,
				util_debug_func_t func, void *user_data)
{
	struct l2cap_frame frame;
	uint16_t value;
	uint16_t mask;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	if (!l2cap_frame_get_le16(&frame, &value)) {
		print_text(COLOR_ERROR, "    value: invalid size");
		goto done;
	}

	print_field("      Sampling Frequencies: 0x%4.4x", value);

	mask = print_bitfield(8, value, pac_freq_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%4.4x)",
								mask);

done:
	if (frame.size)
		print_hex_field("    Data", frame.data, frame.size);
}

static const struct bitfield_data pac_duration_table[] = {
	{  0, "7.5 ms (0x01)"				},
	{  1, "10 ms (0x02)"				},
	{  2, "RFU (0x04)"				},
	{  3, "RFU (0x08)"				},
	{  4, "7.5 ms preferred (0x10)"			},
	{  5, "10 ms preferred (0x20)"			},
	{  6, "RFU (0x40)"				},
	{  7, "RFU (0x80)"				},
	{ }
};

static void pac_decode_duration(const uint8_t *data, uint8_t len,
				util_debug_func_t func, void *user_data)
{
	struct l2cap_frame frame;
	uint8_t value;
	uint8_t mask;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	if (!l2cap_frame_get_u8(&frame, &value)) {
		print_text(COLOR_ERROR, "    value: invalid size");
		goto done;
	}

	print_field("      Frame Duration: 0x%4.4x", value);

	mask = print_bitfield(8, value, pac_duration_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%2.2x)",
								mask);

done:
	if (frame.size)
		print_hex_field("    Data", frame.data, frame.size);
}

static const struct bitfield_data pac_channel_table[] = {
	{  0, "1 channel (0x01)"			},
	{  1, "2 channels (0x02)"			},
	{  2, "3 channels (0x04)"			},
	{  3, "4 chanenls (0x08)"			},
	{  4, "5 channels (0x10)"			},
	{  5, "6 channels (0x20)"			},
	{  6, "7 channels (0x40)"			},
	{  7, "8 channels (0x80)"			},
	{ }
};

static void pac_decode_channels(const uint8_t *data, uint8_t len,
				util_debug_func_t func, void *user_data)
{
	struct l2cap_frame frame;
	uint8_t value;
	uint8_t mask;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	if (!l2cap_frame_get_u8(&frame, &value)) {
		print_text(COLOR_ERROR, "    value: invalid size");
		goto done;
	}

	print_field("      Audio Channel Count: 0x%2.2x", value);

	mask = print_bitfield(8, value, pac_channel_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%2.2x)",
								mask);

done:
	if (frame.size)
		print_hex_field("    Data", frame.data, frame.size);
}

static void pac_decode_frame_length(const uint8_t *data, uint8_t len,
				util_debug_func_t func, void *user_data)
{
	struct l2cap_frame frame;
	uint16_t min, max;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	if (!l2cap_frame_get_le16(&frame, &min)) {
		print_text(COLOR_ERROR, "    min: invalid size");
		goto done;
	}

	if (!l2cap_frame_get_le16(&frame, &max)) {
		print_text(COLOR_ERROR, "    min: invalid size");
		goto done;
	}

	print_field("      Frame Length: %u (0x%4.4x) - %u (0x%4.4x)",
							min, min, max, max);

done:
	if (frame.size)
		print_hex_field("    Data", frame.data, frame.size);
}

static void pac_decode_sdu(const uint8_t *data, uint8_t len,
				util_debug_func_t func, void *user_data)
{
	struct l2cap_frame frame;
	uint8_t value;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	if (!l2cap_frame_get_u8(&frame, &value)) {
		print_text(COLOR_ERROR, "    value: invalid size");
		goto done;
	}

	print_field("      Max SDU: %u (0x%2.2x)", value, value);

done:
	if (frame.size)
		print_hex_field("    Data", frame.data, frame.size);
}

static const struct util_ltv_debugger pac_cap_table[] = {
	UTIL_LTV_DEBUG(0x01, pac_decode_freq),
	UTIL_LTV_DEBUG(0x02, pac_decode_duration),
	UTIL_LTV_DEBUG(0x03, pac_decode_channels),
	UTIL_LTV_DEBUG(0x04, pac_decode_frame_length),
	UTIL_LTV_DEBUG(0x05, pac_decode_sdu)
};

static void print_pac(const struct l2cap_frame *frame)
{
	uint8_t num = 0, i;

	if (!l2cap_frame_get_u8((void *)frame, &num)) {
		print_text(COLOR_ERROR, "Number of PAC(s): invalid size");
		goto done;
	}

	print_field("  Number of PAC(s): %u", num);

	for (i = 0; i < num; i++) {
		print_field("  PAC #%u:", i);

		if (!print_ase_codec(frame))
			goto done;

		if (!print_ase_cc(frame, "    Codec Specific Capabilities",
				pac_cap_table, ARRAY_SIZE(pac_cap_table)))
			break;

		if (!print_ase_metadata(frame))
			break;
	}

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void pac_read(const struct l2cap_frame *frame)
{
	print_pac(frame);
}

static void pac_notify(const struct l2cap_frame *frame)
{
	print_pac(frame);
}

static bool print_prefer_framing(const struct l2cap_frame *frame)
{
	uint8_t framing;

	if (!l2cap_frame_get_u8((void *)frame, &framing)) {
		print_text(COLOR_ERROR, "    Framing: invalid size");
		return false;
	}

	switch (framing) {
	case 0x00:
		print_field("    Framing: Unframed PDUs supported (0x00)");
		break;
	case 0x01:
		print_field("    Framing: Unframed PDUs not supported (0x01)");
		break;
	default:
		print_field("    Framing: Reserved (0x%2.2x)", framing);
		break;
	}

	return true;
}

static const struct bitfield_data prefer_phy_table[] = {
	{  0, "LE 1M PHY preferred (0x01)"		},
	{  1, "LE 2M PHY preferred (0x02)"		},
	{  2, "LE Codec PHY preferred (0x04)"		},
	{ }
};

static bool print_prefer_phy(const struct l2cap_frame *frame)
{
	uint8_t phy, mask;

	if (!l2cap_frame_get_u8((void *)frame, &phy)) {
		print_text(COLOR_ERROR, "PHY: invalid size");
		return false;
	}

	print_field("    PHY: 0x%2.2x", phy);

	mask = print_bitfield(4, phy, prefer_phy_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%2.2x)",
								mask);

	return true;
}

static bool print_ase_rtn(const struct l2cap_frame *frame, const char *label)
{
	uint8_t rtn;

	if (!l2cap_frame_get_u8((void *)frame, &rtn)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: %u", label, rtn);

	return true;
}

static bool print_ase_latency(const struct l2cap_frame *frame,
						const char *label)
{
	uint16_t latency;

	if (!l2cap_frame_get_le16((void *)frame, &latency)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: %u", label, latency);

	return true;
}

static bool print_ase_pd(const struct l2cap_frame *frame, const char *label)
{
	uint32_t pd;

	if (!l2cap_frame_get_le24((void *)frame, &pd)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: %u us", label, pd);

	return true;
}

static void ase_debug_freq(const uint8_t *data, uint8_t len,
				util_debug_func_t func, void *user_data)
{
	struct l2cap_frame frame;
	uint8_t value;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	if (!l2cap_frame_get_u8(&frame, &value)) {
		print_text(COLOR_ERROR, "    value: invalid size");
		goto done;
	}

	switch (value) {
	case 0x01:
		print_field("      Sampling Frequency: 8 Khz (0x01)");
		break;
	case 0x02:
		print_field("      Sampling Frequency: 11.25 Khz (0x02)");
		break;
	case 0x03:
		print_field("      Sampling Frequency: 16 Khz (0x03)");
		break;
	case 0x04:
		print_field("      Sampling Frequency: 22.05 Khz (0x04)");
		break;
	case 0x05:
		print_field("      Sampling Frequency: 24 Khz (0x05)");
		break;
	case 0x06:
		print_field("      Sampling Frequency: 32 Khz (0x06)");
		break;
	case 0x07:
		print_field("      Sampling Frequency: 44.1 Khz (0x07)");
		break;
	case 0x08:
		print_field("      Sampling Frequency: 48 Khz (0x08)");
		break;
	case 0x09:
		print_field("      Sampling Frequency: 88.2 Khz (0x09)");
		break;
	case 0x0a:
		print_field("      Sampling Frequency: 96 Khz (0x0a)");
		break;
	case 0x0b:
		print_field("      Sampling Frequency: 176.4 Khz (0x0b)");
		break;
	case 0x0c:
		print_field("      Sampling Frequency: 192 Khz (0x0c)");
		break;
	case 0x0d:
		print_field("      Sampling Frequency: 384 Khz (0x0d)");
		break;
	default:
		print_field("      Sampling Frequency: RFU (0x%2.2x)", value);
		break;
	}

done:
	if (frame.size)
		print_hex_field("    Data", frame.data, frame.size);
}

static void ase_debug_duration(const uint8_t *data, uint8_t len,
				util_debug_func_t func, void *user_data)
{
	struct l2cap_frame frame;
	uint8_t value;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	if (!l2cap_frame_get_u8(&frame, &value)) {
		print_text(COLOR_ERROR, "    value: invalid size");
		goto done;
	}

	switch (value) {
	case 0x00:
		print_field("      Frame Duration: 7.5 ms (0x00)");
		break;
	case 0x01:
		print_field("      Frame Duration: 10 ms (0x01)");
		break;
	default:
		print_field("      Frame Duration: RFU (0x%2.2x)", value);
		break;
	}

done:
	if (frame.size)
		print_hex_field("    Data", frame.data, frame.size);
}

static const struct bitfield_data channel_location_table[] = {
	{  0, "Front Left (0x00000001)"			},
	{  1, "Front Right (0x00000002)"		},
	{  2, "Front Center (0x00000004)"		},
	{  3, "Low Frequency Effects 1 (0x00000008)"	},
	{  4, "Back Left (0x00000010)"			},
	{  5, "Back Right (0x00000020)"			},
	{  6, "Front Left of Center (0x00000040)"	},
	{  7, "Front Right of Center (0x00000080)"	},
	{  8, "Back Center (0x00000100)"		},
	{  9, "Low Frequency Effects 2 (0x00000200)"	},
	{  10, "Side Left (0x00000400)"			},
	{  11, "Side Right (0x00000800)"		},
	{  12, "Top Front Left (0x00001000)"		},
	{  13, "Top Front Right (0x00002000)"		},
	{  14, "Top Front Center (0x00004000)"		},
	{  15, "Top Center (0x00008000)"		},
	{  16, "Top Back Left (0x00010000)"		},
	{  17, "Top Back Right (0x00020000)"		},
	{  18, "Top Side Left (0x00040000)"		},
	{  19, "Top Side Right (0x00080000)"		},
	{  20, "Top Back Center (0x00100000)"		},
	{  21, "Bottom Front Center (0x00200000)"	},
	{  22, "Bottom Front Left (0x00400000)"		},
	{  23, "Bottom Front Right (0x00800000)"	},
	{  24, "Front Left Wide (0x01000000)"		},
	{  25, "Front Right Wide (0x02000000)"		},
	{  26, "Left Surround (0x04000000)"		},
	{  27, "Right Surround (0x08000000)"		},
	{  28, "RFU (0x10000000)"			},
	{  29, "RFU (0x20000000)"			},
	{  30, "RFU (0x40000000)"			},
	{  31, "RFU (0x80000000)"			},
	{ }
};

static void print_location(const struct l2cap_frame *frame)
{
	uint32_t value;
	uint32_t mask;

	if (!l2cap_frame_get_le32((void *)frame, &value)) {
		print_text(COLOR_ERROR, "    value: invalid size");
		goto done;
	}

	print_field("   Location: 0x%8.8x", value);

	mask = print_bitfield(6, value, channel_location_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%8.8x)",
								mask);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void ase_debug_location(const uint8_t *data, uint8_t len,
				util_debug_func_t func, void *user_data)
{
	struct l2cap_frame frame;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	print_location(&frame);
}

static void ase_debug_frame_length(const uint8_t *data, uint8_t len,
				util_debug_func_t func, void *user_data)
{
	struct l2cap_frame frame;
	uint16_t value;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	if (!l2cap_frame_get_le16(&frame, &value)) {
		print_text(COLOR_ERROR, "    value: invalid size");
		goto done;
	}

	print_field("      Frame Length: %u (0x%4.4x)", value, value);

done:
	if (frame.size)
		print_hex_field("    Data", frame.data, frame.size);
}

static void ase_debug_blocks(const uint8_t *data, uint8_t len,
				util_debug_func_t func, void *user_data)
{
	struct l2cap_frame frame;
	uint8_t value;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	if (!l2cap_frame_get_u8(&frame, &value)) {
		print_text(COLOR_ERROR, "    value: invalid size");
		goto done;
	}

	print_field("      Frame Blocks per SDU: %u (0x%2.2x)", value, value);

done:
	if (frame.size)
		print_hex_field("    Data", frame.data, frame.size);
}

static const struct util_ltv_debugger ase_cc_table[] = {
	UTIL_LTV_DEBUG(0x01, ase_debug_freq),
	UTIL_LTV_DEBUG(0x02, ase_debug_duration),
	UTIL_LTV_DEBUG(0x03, ase_debug_location),
	UTIL_LTV_DEBUG(0x04, ase_debug_frame_length),
	UTIL_LTV_DEBUG(0x05, ase_debug_blocks)
};

static void print_ase_config(const struct l2cap_frame *frame)
{
	if (!print_prefer_framing(frame))
		return;

	if (!print_prefer_phy(frame))
		return;

	if (!print_ase_rtn(frame, "    RTN"))
		return;

	if (!print_ase_latency(frame, "    Max Transport Latency"))
		return;

	if (!print_ase_pd(frame, "    Presentation Delay Min"))
		return;

	if (!print_ase_pd(frame, "    Presentation Delay Max"))
		return;

	if (!print_ase_pd(frame, "    Preferred Presentation Delay Min"))
		return;

	if (!print_ase_pd(frame, "    Preferred Presentation Delay Max"))
		return;

	if (!print_ase_codec(frame))
		return;

	print_ase_cc(frame, "    Codec Specific Configuration",
			ase_cc_table, ARRAY_SIZE(ase_cc_table));
}

static bool print_ase_framing(const struct l2cap_frame *frame,
						const char *label)
{
	uint8_t framing;

	if (!l2cap_frame_get_u8((void *)frame, &framing)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	switch (framing) {
	case 0x00:
		print_field("%s: Unframed (0x00)", label);
		break;
	case 0x01:
		print_field("%s: Framed (0x01)", label);
		break;
	default:
		print_field("%s: Reserved (0x%2.2x)", label, framing);
	}

	return true;
}

static const struct bitfield_data phy_table[] = {
	{  0, "LE 1M PHY (0x01)"		},
	{  1, "LE 2M PHY (0x02)"		},
	{  2, "LE Codec PHY (0x04)"		},
	{ }
};

static bool print_ase_phy(const struct l2cap_frame *frame, const char *label)
{
	uint8_t phy, mask;

	if (!l2cap_frame_get_u8((void *)frame, &phy)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: 0x%2.2x", label, phy);

	mask = print_bitfield(4, phy, phy_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%2.2x)",
								mask);

	return true;
}

static bool print_ase_interval(const struct l2cap_frame *frame,
						const char *label)
{
	uint32_t interval;

	if (!l2cap_frame_get_le24((void *)frame, &interval)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: %u usec", label, interval);

	return true;
}

static bool print_ase_sdu(const struct l2cap_frame *frame, const char *label)
{
	uint16_t sdu;

	if (!l2cap_frame_get_le16((void *)frame, &sdu)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: %u", label, sdu);

	return true;
}

static void print_ase_qos(const struct l2cap_frame *frame)
{
	if (!l2cap_frame_print_u8((void *)frame, "    CIG ID"))
		return;

	if (!l2cap_frame_print_u8((void *)frame, "    CIS ID"))
		return;

	if (!print_ase_interval(frame, "    SDU Interval"))
		return;

	if (!print_ase_framing(frame, "    Framing"))
		return;

	if (!print_ase_phy(frame, "    PHY"))
		return;

	if (!print_ase_sdu(frame, "    Max SDU"))
		return;

	if (!print_ase_rtn(frame, "    RTN"))
		return;

	if (!print_ase_latency(frame, "    Max Transport Latency"))
		return;

	print_ase_pd(frame, "    Presentation Delay");
}

static void print_ase_metadata_status(const struct l2cap_frame *frame)
{
	if (!l2cap_frame_print_u8((void *)frame, "    CIG ID"))
		return;

	if (!l2cap_frame_print_u8((void *)frame, "    CIS ID"))
		return;

	print_ase_metadata(frame);
}

static void print_ase_status(const struct l2cap_frame *frame)
{
	uint8_t id, state;

	if (!l2cap_frame_get_u8((void *)frame, &id)) {
		print_text(COLOR_ERROR, "ASE ID: invalid size");
		goto done;
	}

	print_field("    ASE ID: %u", id);

	if (!l2cap_frame_get_u8((void *)frame, &state)) {
		print_text(COLOR_ERROR, "ASE State: invalid size");
		goto done;
	}

	switch (state) {
	/* ASE_State = 0x00 (Idle) */
	case 0x00:
		print_field("    State: Idle (0x00)");
		break;
	/* ASE_State = 0x01 (Codec Configured) */
	case 0x01:
		print_field("    State: Codec Configured (0x01)");
		print_ase_config(frame);
		break;
	/* ASE_State = 0x02 (QoS Configured) */
	case 0x02:
		print_field("    State: QoS Configured (0x02)");
		print_ase_qos(frame);
		break;
	/* ASE_Status = 0x03 (Enabling) */
	case 0x03:
		print_field("    State: Enabling (0x03)");
		print_ase_metadata_status(frame);
		break;
	/* ASE_Status = 0x04 (Streaming) */
	case 0x04:
		print_field("    State: Streaming (0x04)");
		print_ase_metadata_status(frame);
		break;
	/* ASE_Status = 0x05 (Disabling) */
	case 0x05:
		print_field("    State: Disabling (0x05)");
		print_ase_metadata_status(frame);
		break;
	/* ASE_Status = 0x06 (Releasing) */
	case 0x06:
		print_field("    State: Releasing (0x06)");
		break;
	default:
		print_field("    State: Reserved (0x%2.2x)", state);
		break;
	}

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void ase_read(const struct l2cap_frame *frame)
{
	print_ase_status(frame);
}

static void ase_notify(const struct l2cap_frame *frame)
{
	print_ase_status(frame);
}

static bool print_ase_target_latency(const struct l2cap_frame *frame)
{
	uint8_t latency;

	if (!l2cap_frame_get_u8((void *)frame, &latency)) {
		print_text(COLOR_ERROR, "    Target Latency: invalid size");
		return false;
	}

	switch (latency) {
	case 0x01:
		print_field("    Target Latency: Low Latency (0x01)");
		break;
	case 0x02:
		print_field("    Target Latency: Balance Latency/Reliability "
								"(0x02)");
		break;
	case 0x03:
		print_field("    Target Latency: High Reliability (0x03)");
		break;
	default:
		print_field("    Target Latency: Reserved (0x%2.2x)", latency);
		break;
	}

	return true;
}

static bool ase_config_cmd(const struct l2cap_frame *frame)
{
	if (!l2cap_frame_print_u8((void *)frame, "    ASE ID"))
		return false;

	if (!print_ase_target_latency(frame))
		return false;

	if (!print_ase_phy(frame, "    PHY"))
		return false;

	if (!print_ase_codec(frame))
		return false;

	if (!print_ase_cc(frame, "    Codec Specific Configuration",
				ase_cc_table, ARRAY_SIZE(ase_cc_table)))
		return false;

	return true;
}

static bool ase_qos_cmd(const struct l2cap_frame *frame)
{
	if (!l2cap_frame_print_u8((void *)frame, "    ASE ID"))
		return false;

	if (!l2cap_frame_print_u8((void *)frame, "    CIG ID"))
		return false;

	if (!l2cap_frame_print_u8((void *)frame, "    CIS ID"))
		return false;

	if (!print_ase_interval(frame, "    SDU Interval"))
		return false;

	if (!print_ase_framing(frame, "    Framing"))
		return false;

	if (!print_ase_phy(frame, "    PHY"))
		return false;

	if (!print_ase_sdu(frame, "    Max SDU"))
		return false;

	if (!print_ase_rtn(frame, "    RTN"))
		return false;

	if (!print_ase_latency(frame, "    Max Transport Latency"))
		return false;

	if (!print_ase_pd(frame, "    Presentation Delay"))
		return false;

	return true;
}

static bool ase_enable_cmd(const struct l2cap_frame *frame)
{
	if (!l2cap_frame_print_u8((void *)frame, "    ASE ID"))
		return false;

	if (!print_ase_metadata(frame))
		return false;

	return true;
}

static bool ase_start_cmd(const struct l2cap_frame *frame)
{
	if (!l2cap_frame_print_u8((void *)frame, "    ASE ID"))
		return false;

	return true;
}

static bool ase_disable_cmd(const struct l2cap_frame *frame)
{
	if (!l2cap_frame_print_u8((void *)frame, "    ASE ID"))
		return false;

	return true;
}

static bool ase_stop_cmd(const struct l2cap_frame *frame)
{
	if (!l2cap_frame_print_u8((void *)frame, "    ASE ID"))
		return false;

	return true;
}

static bool ase_metadata_cmd(const struct l2cap_frame *frame)
{
	if (!l2cap_frame_print_u8((void *)frame, "    ASE ID"))
		return false;

	if (!print_ase_metadata(frame))
		return false;

	return true;
}

static bool ase_release_cmd(const struct l2cap_frame *frame)
{
	if (!l2cap_frame_print_u8((void *)frame, "    ASE ID"))
		return false;

	return true;
}

#define ASE_CMD(_op, _desc, _func) \
[_op] = { \
	.desc = _desc, \
	.func = _func, \
}

static const struct ase_cmd {
	const char *desc;
	bool (*func)(const struct l2cap_frame *frame);
} ase_cmd_table[] = {
	/* Opcode = 0x01 (Codec Configuration) */
	ASE_CMD(0x01, "Codec Configuration", ase_config_cmd),
	/* Opcode = 0x02 (QoS Configuration) */
	ASE_CMD(0x02, "QoS Configuration", ase_qos_cmd),
	/* Opcode = 0x03 (Enable) */
	ASE_CMD(0x03, "Enable", ase_enable_cmd),
	/* Opcode = 0x04 (Receiver Start Ready) */
	ASE_CMD(0x04, "Receiver Start Ready", ase_start_cmd),
	/* Opcode = 0x05 (Disable) */
	ASE_CMD(0x05, "Disable", ase_disable_cmd),
	/* Opcode = 0x06 (Receiver Stop Ready) */
	ASE_CMD(0x06, "Receiver Stop Ready", ase_stop_cmd),
	/* Opcode = 0x07 (Update Metadata) */
	ASE_CMD(0x07, "Update Metadata", ase_metadata_cmd),
	/* Opcode = 0x08 (Release) */
	ASE_CMD(0x08, "Release", ase_release_cmd),
};

static const struct ase_cmd *ase_get_cmd(uint8_t op)
{
	if (op > ARRAY_SIZE(ase_cmd_table))
		return NULL;

	return &ase_cmd_table[op];
}

static void print_ase_cmd(const struct l2cap_frame *frame)
{
	uint8_t op, num, i;
	const struct ase_cmd *cmd;

	if (!l2cap_frame_get_u8((void *)frame, &op)) {
		print_text(COLOR_ERROR, "opcode: invalid size");
		goto done;
	}

	if (!l2cap_frame_get_u8((void *)frame, &num)) {
		print_text(COLOR_ERROR, "num: invalid size");
		goto done;
	}

	cmd = ase_get_cmd(op);
	if (!cmd) {
		print_field("    Opcode: Reserved (0x%2.2x)", op);
		goto done;
	}

	print_field("    Opcode: %s (0x%2.2x)", cmd->desc, op);
	print_field("    Number of ASE(s): %u", num);

	for (i = 0; i < num && frame->size; i++) {
		print_field("    ASE: #%u", i);

		if (!cmd->func(frame))
			break;
	}

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void ase_cp_write(const struct l2cap_frame *frame)
{
	print_ase_cmd(frame);
}

static bool print_ase_cp_rsp_code(const struct l2cap_frame *frame)
{
	uint8_t code;

	if (!l2cap_frame_get_u8((void *)frame, &code)) {
		print_text(COLOR_ERROR, "    ASE Response Code: invalid size");
		return false;
	}

	switch (code) {
	case 0x00:
		print_field("    ASE Response Code: Success (0x00)");
		break;
	case 0x01:
		print_field("    ASE Response Code: Unsupported Opcode (0x01)");
		break;
	case 0x02:
		print_field("    ASE Response Code: Invalid Length (0x02)");
		break;
	case 0x03:
		print_field("    ASE Response Code: Invalid ASE ID (0x03)");
		break;
	case 0x04:
		print_field("    ASE Response Code: Invalid ASE State (0x04)");
		break;
	case 0x05:
		print_field("    ASE Response Code: Invalid ASE Direction "
								"(0x05)");
		break;
	case 0x06:
		print_field("    ASE Response Code: Unsupported Audio "
							"Capabilities (0x06)");
		break;
	case 0x07:
		print_field("    ASE Response Code: Unsupported Configuration "
								"(0x07)");
		break;
	case 0x08:
		print_field("    ASE Response Code: Rejected Configuration "
								"(0x08)");
		break;
	case 0x09:
		print_field("    ASE Response Code: Invalid Configuration "
								"(0x09)");
		break;
	case 0x0a:
		print_field("    ASE Response Code: Unsupported Metadata "
								"(0x0a)");
		break;
	case 0x0b:
		print_field("    ASE Response Code: Rejected Metadata (0x0b)");
		break;
	case 0x0c:
		print_field("    ASE Response Code: Invalid Metadata (0x0c)");
		break;
	case 0x0d:
		print_field("    ASE Response Code: Insufficient Resources "
								"(0x0d)");
		break;
	case 0x0e:
		print_field("    ASE Response Code: Unspecified Error (0x0e)");
		break;
	default:
		print_field("    ASE Response Code: Reserved (0x%2.2x)", code);
		break;
	}

	return true;
}

static bool print_ase_cp_rsp_reason(const struct l2cap_frame *frame)
{
	uint8_t reason;

	if (!l2cap_frame_get_u8((void *)frame, &reason)) {
		print_text(COLOR_ERROR,
				"    ASE Response Reason: invalid size");
		return false;
	}

	switch (reason) {
	case 0x00:
		print_field("    ASE Response Reason: None (0x00)");
		break;
	case 0x01:
		print_field("    ASE Response Reason: ASE ID (0x01)");
		break;
	case 0x02:
		print_field("    ASE Response Reason: Codec Specific "
						"Configuration (0x02)");
		break;
	case 0x03:
		print_field("    ASE Response Reason: SDU Interval (0x03)");
		break;
	case 0x04:
		print_field("    ASE Response Reason: Framing (0x04)");
		break;
	case 0x05:
		print_field("    ASE Response Reason: PHY (0x05)");
		break;
	case 0x06:
		print_field("    ASE Response Reason: Max SDU (0x06)");
		break;
	case 0x07:
		print_field("    ASE Response Reason: RTN (0x07)");
		break;
	case 0x08:
		print_field("    ASE Response Reason: Max Transport Latency "
								"(0x08)");
		break;
	case 0x09:
		print_field("    ASE Response Reason: Presentation Delay "
								"(0x09)");
		break;
	case 0x0a:
		print_field("    ASE Response Reason: Invalid ASE/CIS Mapping "
								"(0x0a)");
		break;
	default:
		print_field("    ASE Response Reason: Reserved (0x%2.2x)",
								reason);
		break;
	}

	return true;
}

static void print_ase_cp_rsp(const struct l2cap_frame *frame)
{
	uint8_t op, num, i;
	const struct ase_cmd *cmd;

	if (!l2cap_frame_get_u8((void *)frame, &op)) {
		print_text(COLOR_ERROR, "    opcode: invalid size");
		goto done;
	}

	if (!l2cap_frame_get_u8((void *)frame, &num)) {
		print_text(COLOR_ERROR, "    Number of ASE(s): invalid size");
		goto done;
	}

	cmd = ase_get_cmd(op);
	if (!cmd) {
		print_field("    Opcode: Reserved (0x%2.2x)", op);
		goto done;
	}

	print_field("    Opcode: %s (0x%2.2x)", cmd->desc, op);
	print_field("    Number of ASE(s): %u", num);

	for (i = 0; i < num && frame->size; i++) {
		print_field("    ASE: #%u", i);

		if (!l2cap_frame_print_u8((void *)frame, "    ASE ID"))
			break;

		if (!print_ase_cp_rsp_code(frame))
			break;

		if (!print_ase_cp_rsp_reason(frame))
			break;
	}

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void ase_cp_notify(const struct l2cap_frame *frame)
{
	print_ase_cp_rsp(frame);
}

static void pac_loc_read(const struct l2cap_frame *frame)
{
	print_location(frame);
}

static void pac_loc_notify(const struct l2cap_frame *frame)
{
	print_location(frame);
}

static void print_pac_context(const struct l2cap_frame *frame)
{
	uint16_t snk, src;
	uint16_t mask;

	if (!l2cap_frame_get_le16((void *)frame, &snk)) {
		print_text(COLOR_ERROR, "  sink: invalid size");
		goto done;
	}

	print_field("  Sink Context: 0x%4.4x", snk);

	mask = print_bitfield(4, snk, pac_context_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "  Unknown fields (0x%4.4x)",
								mask);

	if (!l2cap_frame_get_le16((void *)frame, &src)) {
		print_text(COLOR_ERROR, "  source: invalid size");
		goto done;
	}

	print_field("  Source Context: 0x%4.4x", src);

	mask = print_bitfield(4, src, pac_context_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "  Unknown fields (0x%4.4x)",
								mask);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void pac_context_read(const struct l2cap_frame *frame)
{
	print_pac_context(frame);
}

static void pac_context_notify(const struct l2cap_frame *frame)
{
	print_pac_context(frame);
}

static void csip_rank_read(const struct l2cap_frame *frame)
{
	uint8_t rank;

	if (!l2cap_frame_get_u8((void *)frame, &rank)) {
		print_text(COLOR_ERROR, "Rank: invalid size");
		goto done;
	}

	print_field("    Rank: 0x%02x", rank);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void csip_lock_read(const struct l2cap_frame *frame)
{
	uint8_t lock;

	if (!l2cap_frame_get_u8((void *)frame, &lock)) {
		print_text(COLOR_ERROR, "Lock: invalid size");
		goto done;
	}

	switch (lock) {
	case 0x01:
		print_field("    Unlocked (0x%02x)", lock);
		break;
	case 0x02:
		print_field("    Locked (0x%02x)", lock);
		break;
	default:
		print_field("    RFU (0x%02x)", lock);
		break;
	}

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void print_csip_size(const struct l2cap_frame *frame)
{
	uint8_t size;

	if (!l2cap_frame_get_u8((void *)frame, &size)) {
		print_text(COLOR_ERROR, "Size: invalid size");
		goto done;
	}
	print_field("    Size: 0x%02x", size);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void csip_size_read(const struct l2cap_frame *frame)
{
	print_csip_size(frame);
}

static void csip_size_notify(const struct l2cap_frame *frame)
{
	print_csip_size(frame);
}

static void csip_sirk_read(const struct l2cap_frame *frame)
{
	if (frame->size)
		print_hex_field("  SIRK", frame->data, frame->size);
}

static void csip_sirk_notify(const struct l2cap_frame *frame)
{
	if (frame->size)
		print_hex_field("  SIRK", frame->data, frame->size);
}

static void print_vcs_state(const struct l2cap_frame *frame)
{
	uint8_t vol_set, mute, chng_ctr;

	if (!l2cap_frame_get_u8((void *)frame, &vol_set)) {
		print_text(COLOR_ERROR, "Volume Settings: invalid size");
		goto done;
	}
	print_field("    Volume Setting: %u", vol_set);

	if (!l2cap_frame_get_u8((void *)frame, &mute)) {
		print_text(COLOR_ERROR, "Mute Filed: invalid size");
		goto done;
	}

	switch (mute) {
	case 0x00:
		print_field("    Not Muted: %u", mute);
		break;
	case 0x01:
		print_field("    Muted: %u", mute);
		break;
	default:
		print_field("    Unknown Mute Value: %u", mute);
		break;
	}

	if (!l2cap_frame_get_u8((void *)frame, &chng_ctr)) {
		print_text(COLOR_ERROR, "Change Counter: invalid size");
		goto done;
	}
	print_field("    Change Counter: %u", chng_ctr);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void vol_state_read(const struct l2cap_frame *frame)
{
	print_vcs_state(frame);
}

static void vol_state_notify(const struct l2cap_frame *frame)
{
	print_vcs_state(frame);
}

static bool vcs_config_cmd(const struct l2cap_frame *frame)
{
	if (!l2cap_frame_print_u8((void *)frame, "    Change Counter"))
		return false;

	return true;
}

static bool vcs_absolute_cmd(const struct l2cap_frame *frame)
{
	if (!l2cap_frame_print_u8((void *)frame, "    Change Counter"))
		return false;

	if (!l2cap_frame_print_u8((void *)frame, "    Volume Setting"))
		return false;

	return true;
}

#define VCS_CMD(_op, _desc, _func) \
[_op] = { \
	.desc = _desc, \
	.func = _func, \
}

static const struct vcs_cmd {
	const char *desc;
	bool (*func)(const struct l2cap_frame *frame);
} vcs_cmd_table[] = {
	/* Opcode = 0x00 (Relative Volume Down) */
	VCS_CMD(0x00, "Relative Volume Down", vcs_config_cmd),
	/* Opcode = 0x01 (Relative Volume Up) */
	VCS_CMD(0x01, "Relative Volume Up", vcs_config_cmd),
	/* Opcode = 0x02 (Unmute/Relative Volume Down) */
	VCS_CMD(0x02, "Unmute/Relative Volume Down", vcs_config_cmd),
	/* Opcode = 0x03 (Unmute/Relative Volume Up) */
	VCS_CMD(0x03, "Unmute/Relative Volume Up", vcs_config_cmd),
	/* Opcode = 0x04 (Set Absolute Volume) */
	VCS_CMD(0x04, "Set Absolute Volume", vcs_absolute_cmd),
	/* Opcode = 0x05 (Unmute) */
	VCS_CMD(0x05, "Unmute", vcs_config_cmd),
	/* Opcode = 0x06 (Mute) */
	VCS_CMD(0x06, "Mute", vcs_config_cmd),
};

static const struct vcs_cmd *vcs_get_cmd(uint8_t op)
{
	if (op > ARRAY_SIZE(vcs_cmd_table))
		return NULL;

	return &vcs_cmd_table[op];
}

static void print_vcs_cmd(const struct l2cap_frame *frame)
{
	uint8_t op;
	const struct vcs_cmd *cmd;

	if (!l2cap_frame_get_u8((void *)frame, &op)) {
		print_text(COLOR_ERROR, "opcode: invalid size");
		goto done;
	}

	cmd = vcs_get_cmd(op);
	if (!cmd) {
		print_field("    Opcode: Reserved (0x%2.2x)", op);
		goto done;
	}

	print_field("    Opcode: %s (0x%2.2x)", cmd->desc, op);
	if (!cmd->func(frame))
		print_field("    Unknown Opcode");

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void vol_cp_write(const struct l2cap_frame *frame)
{
	print_vcs_cmd(frame);
}

static void print_vcs_flag(const struct l2cap_frame *frame)
{
	uint8_t vol_flag;

	if (!l2cap_frame_get_u8((void *)frame, &vol_flag)) {
		print_text(COLOR_ERROR, "Volume Flag: invalid size");
		goto done;
	}
	print_field("    Volume Flag: %u", vol_flag);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void vol_flag_read(const struct l2cap_frame *frame)
{
	print_vcs_flag(frame);
}

static void vol_flag_notify(const struct l2cap_frame *frame)
{
	print_vcs_flag(frame);
}

static char *name2utf8(const uint8_t *name, uint16_t len)
{
	char utf8_name[HCI_MAX_NAME_LENGTH + 2];
	int i;

	if (g_utf8_validate((const char *) name, len, NULL))
		return g_strndup((char *) name, len);

	len = MIN(len, sizeof(utf8_name) - 1);

	memset(utf8_name, 0, sizeof(utf8_name));
	strncpy(utf8_name, (char *) name, len);

	/* Assume ASCII, and replace all non-ASCII with spaces */
	for (i = 0; utf8_name[i] != '\0'; i++) {
		if (!isascii(utf8_name[i]))
			utf8_name[i] = ' ';
	}

	/* Remove leading and trailing whitespace characters */
	g_strstrip(utf8_name);

	return g_strdup(utf8_name);
}

static void print_mp_name(const struct l2cap_frame *frame)
{
	char *name;

	name = name2utf8((uint8_t *)frame->data, frame->size);

	print_field("  Media Player Name: %s", name);

	g_free(name);
}

static void mp_name_read(const struct l2cap_frame *frame)
{
	print_mp_name(frame);
}

static void mp_name_notify(const struct l2cap_frame *frame)
{
	print_mp_name(frame);
}

static void print_track_changed(const struct l2cap_frame *frame)
{
	print_field("  Track Changed");
}

static void track_changed_notify(const struct l2cap_frame *frame)
{
	print_track_changed(frame);
}

static void print_track_title(const struct l2cap_frame *frame)
{
	char *name;

	name = name2utf8((uint8_t *)frame->data, frame->size);

	print_field("  Track Title: %s", name);

	g_free(name);
}

static void track_title_read(const struct l2cap_frame *frame)
{
	print_track_title(frame);
}

static void track_title_notify(const struct l2cap_frame *frame)
{
	print_track_title(frame);
}

static void print_track_duration(const struct l2cap_frame *frame)
{
	int32_t duration;

	if (!l2cap_frame_get_le32((void *)frame, (uint32_t *)&duration)) {
		print_text(COLOR_ERROR, "  Track Duration: invalid size");
		goto done;
	}

	print_field("  Track Duration: %u", duration);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void track_duration_read(const struct l2cap_frame *frame)
{
	print_track_duration(frame);
}

static void track_duration_notify(const struct l2cap_frame *frame)
{
	print_track_duration(frame);
}

static void print_track_position(const struct l2cap_frame *frame)
{
	int32_t position;

	if (!l2cap_frame_get_le32((void *)frame, (uint32_t *)&position)) {
		print_text(COLOR_ERROR, "  Track Position: invalid size");
		goto done;
	}

	print_field("  Track Position: %u", position);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void track_position_read(const struct l2cap_frame *frame)
{
	print_track_position(frame);
}

static void track_position_write(const struct l2cap_frame *frame)
{
	print_track_position(frame);
}

static void track_position_notify(const struct l2cap_frame *frame)
{
	print_track_position(frame);
}

static void print_playback_speed(const struct l2cap_frame *frame)
{
	int8_t playback_speed;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&playback_speed)) {
		print_text(COLOR_ERROR, "  Playback Speed: invalid size");
		goto done;
	}

	print_field("  Playback Speed: %u", playback_speed);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void playback_speed_read(const struct l2cap_frame *frame)
{
	print_playback_speed(frame);
}

static void playback_speed_write(const struct l2cap_frame *frame)
{
	print_playback_speed(frame);
}

static void playback_speed_notify(const struct l2cap_frame *frame)
{
	print_playback_speed(frame);
}

static void print_seeking_speed(const struct l2cap_frame *frame)
{
	int8_t seeking_speed;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&seeking_speed)) {
		print_text(COLOR_ERROR, "  Seeking Speed: invalid size");
		goto done;
	}

	print_field("  Seeking Speed: %u", seeking_speed);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void seeking_speed_read(const struct l2cap_frame *frame)
{
	print_seeking_speed(frame);
}

static void seeking_speed_notify(const struct l2cap_frame *frame)
{
	print_seeking_speed(frame);
}

static void print_bearer_name(const struct l2cap_frame *frame)
{
	char *name;

	name = name2utf8((uint8_t *)frame->data, frame->size);

	print_field("  Bearer Name: %s", name);

	g_free(name);
}

static void bearer_name_read(const struct l2cap_frame *frame)
{
	print_bearer_name(frame);
}

static void bearer_name_notify(const struct l2cap_frame *frame)
{
	print_bearer_name(frame);
}

static void bearer_uci_read(const struct l2cap_frame *frame)
{
	char *name;

	name = name2utf8((uint8_t *)frame->data, frame->size);

	print_field("  Bearer Uci Name: %s", name);

	g_free(name);
}

static void print_technology_name(const struct l2cap_frame *frame)
{
	int8_t tech_id;
	const char *str;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&tech_id)) {
		print_text(COLOR_ERROR, "  Technology id:: invalid size");
		goto done;
	}

	switch (tech_id) {
	case 0x01:
		str = "3G";
		break;
	case 0x02:
		str = "4G";
		break;
	case 0x03:
		str = "LTE";
		break;
	case 0x04:
		str = "WiFi";
		break;
	case 0x05:
		str = "5G";
		break;
	case 0x06:
		str = "GSM";
		break;
	case 0x07:
		str = "CDMA";
		break;
	case 0x08:
		str = "2G";
		break;
	case 0x09:
		str = "WCDMA";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Technology: %s  (0x%2.2x)", str, tech_id);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void bearer_technology_read(const struct l2cap_frame *frame)
{
	print_technology_name(frame);
}

static void bearer_technology_notify(const struct l2cap_frame *frame)
{
	print_technology_name(frame);
}

static void print_uri_scheme_list(const struct l2cap_frame *frame)
{
	char *name;

	name = name2utf8((uint8_t *)frame->data, frame->size);

	print_field("  Uri scheme Name: %s", name);

	g_free(name);
}

static void bearer_uri_schemes_list_read(const struct l2cap_frame *frame)
{
	print_uri_scheme_list(frame);
}

static void print_signal_strength(const struct l2cap_frame *frame)
{
	uint8_t signal_strength;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&signal_strength)) {
		print_text(COLOR_ERROR, " signal_strength:: invalid size");
		goto done;
	}

	print_field("  signal_strength: %x", signal_strength);

	if (signal_strength == 0)
		print_field("  No Service");
	else if (signal_strength == 0x64)
		print_field("  Maximum signal strength");
	else if ((signal_strength > 0) && (signal_strength < 0x64))
		print_field("  Implementation specific");
	else if (signal_strength == 0xFF)
		print_field("  Signal strength is unavailable");
	else
		print_field("  RFU");

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void bearer_signal_strength_read(const struct l2cap_frame *frame)
{
	print_signal_strength(frame);
}

static void bearer_signal_strength_notify(const struct l2cap_frame *frame)
{
	print_signal_strength(frame);
}

static void
print_signal_strength_rep_intrvl(const struct l2cap_frame *frame)
{
	int8_t reporting_intrvl;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&reporting_intrvl)) {
		print_text(COLOR_ERROR, "Reporting_interval:: invalid size");
		goto done;
	}

	print_field("  Reporting_interval: 0x%x", reporting_intrvl);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void
bearer_signal_strength_rep_intrvl_read(const struct l2cap_frame *frame)
{
	print_signal_strength_rep_intrvl(frame);
}

static void
bearer_signal_strength_rep_intrvl_write(const struct l2cap_frame *frame)
{
	print_signal_strength_rep_intrvl(frame);
}

static void print_call_list(const struct l2cap_frame *frame)
{
	uint8_t list_item_length;
	uint8_t call_index;
	uint8_t call_state;
	uint8_t call_flag;
	char *call_uri;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&list_item_length)) {
		print_text(COLOR_ERROR, "    list_item_length:: invalid size");
		goto done;
	}

	print_field("  list_item_length: 0x%x", list_item_length);

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&call_index)) {
		print_text(COLOR_ERROR, "  call_index:: invalid size");
		goto done;
	}

	print_field("  call_index: 0x%x", call_index);

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&call_state)) {
		print_text(COLOR_ERROR, "  call_state:: invalid size");
		goto done;
	}

	print_field("  call_state: 0x%x", call_state);

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&call_flag)) {
		print_text(COLOR_ERROR, "  call_flag:: invalid size");
		goto done;
	}

	print_field("  call_flag: 0x%x", call_flag);

	call_uri = name2utf8((uint8_t *)frame->data, frame->size);

	print_field("  call_uri: %s", call_uri);

	g_free(call_uri);

done:
	if (frame->size)
		print_hex_field("  call_list Data", frame->data, frame->size);
}

static void bearer_current_call_list_read(const struct l2cap_frame *frame)
{
	print_call_list(frame);
}

static void bearer_current_call_list_notify(const struct l2cap_frame *frame)
{
	print_call_list(frame);
}

static void print_ccid(const struct l2cap_frame *frame)
{
	int8_t ccid;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&ccid)) {
		print_text(COLOR_ERROR, "  ccid:: invalid size");
		goto done;
	}

	print_field("  ccid: %x", ccid);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void call_content_control_id_read(const struct l2cap_frame *frame)
{
	print_ccid(frame);
}

static void print_status_flag(const struct l2cap_frame *frame)
{
	int16_t flag;

	if (!l2cap_frame_get_le16((void *)frame, (uint16_t *)&flag)) {
		print_text(COLOR_ERROR, "  status flag:: invalid size");
		goto done;
	}

	print_field("  status flag:");

	if (flag & 0x1)
		print_field("  Inband Ringtone Enabled:");
	else
		print_field("  Inband Ringtone Disabled:");

	if (flag & 0x2)
		print_field("  Server in silent Mode");
	else
		print_field("  Server Not in silent Mode");

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void status_flag_read(const struct l2cap_frame *frame)
{
	print_status_flag(frame);
}

static void status_flag_notify(const struct l2cap_frame *frame)
{
	print_status_flag(frame);
}

static void print_target_uri(const struct l2cap_frame *frame)
{
	char *name;
	uint8_t call_idx;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&call_idx)) {
		print_text(COLOR_ERROR, "  call_idx:: invalid size");
		goto done;
	}

	print_field("  call_idx: %x", call_idx);

	name = name2utf8((uint8_t *)frame->data, frame->size);

	print_field("  Uri: %s", name);

	g_free(name);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void incom_target_bearer_uri_read(const struct l2cap_frame *frame)
{
	print_target_uri(frame);
}

static void incom_target_bearer_uri_notify(const struct l2cap_frame *frame)
{
	print_target_uri(frame);
}

static void print_call_state(const struct l2cap_frame *frame)
{
	uint8_t call_Index;
	uint8_t call_state;
	uint8_t call_flag;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&call_Index)) {
		print_text(COLOR_ERROR, "  call_Index:: invalid index");
		goto done;
	}

	print_field("  call_Index: 0x%2.2x", call_Index);

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&call_state)) {
		print_text(COLOR_ERROR, "  call_state:: invalid state");
		goto done;
	}

	print_field("  call_state: 0x%2.2x", call_state);

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&call_flag)) {
		print_text(COLOR_ERROR, "  call_flag:: invalid flag");
		goto done;
	}

	print_field("  call_flag: 0x%2.2x", call_flag);

done:
	if (frame->size)
		print_hex_field("   call_state Data", frame->data, frame->size);
}

static void call_state_read(const struct l2cap_frame *frame)
{
	print_call_state(frame);
}

static void call_state_notify(const struct l2cap_frame *frame)
{
	print_call_state(frame);
}

static void print_call_cp(const struct l2cap_frame *frame)
{
	uint8_t opcode;
	uint8_t parameter;
	const char *str;
	char *name;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&opcode)) {
		print_text(COLOR_ERROR, "  opcode:: invalid size");
		goto done;
	}

	print_field("  opcode: 0x%2.2x", opcode);

	switch (opcode) {
	case 0x00:
		str = "Accept";
		if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&parameter)) {
			print_text(COLOR_ERROR, "  parameter:: invalid size");
			goto done;
		}
		print_field("  Operation: %s  (0x%2.2x)", str, parameter);
		break;
	case 0x01:
		str = "Terminate";
		if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&parameter)) {
			print_text(COLOR_ERROR, "  parameter:: invalid size");
			goto done;
		}
		print_field("  Operation: %s  (0x%2.2x)", str, parameter);
		break;
	case 0x02:
		str = "Local Hold";
		if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&parameter)) {
			print_text(COLOR_ERROR, "  parameter:: invalid size");
			goto done;
		}
		print_field("  Operation: %s  (0x%2.2x)", str, parameter);
		break;
	case 0x03:
		str = "Local Retrieve";
		if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&parameter)) {
			print_text(COLOR_ERROR, "  parameter:: invalid size");
			goto done;
		}
		print_field("  Operation: %s  (0x%2.2x)", str, parameter);
		break;
	case 0x04:
		str = "Originate";
		name = name2utf8((uint8_t *)frame->data, frame->size);
		print_field("  Operation: %s  Uri: %s", str, name);
		g_free(name);
		break;
	case 0x05:
		str = "Join";
		if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&parameter)) {
			print_text(COLOR_ERROR, "  parameter:: invalid size");
			goto done;
		}
		print_field("  Operation: %s  (0x%2.2x)", str, parameter);
		break;
	default:
		str = "RFU";
		print_field("  Operation: %s", str);
		break;
	}

done:
	if (frame->size)
		print_hex_field("call_cp Data", frame->data, frame->size);
}

static void print_call_cp_notification(const struct l2cap_frame *frame)
{
	uint8_t opcode;
	uint8_t result_code;
	const char *str;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&opcode)) {
		print_text(COLOR_ERROR, "  result_code:: invalid opcode");
		goto done;
	}

	print_field("  opcode: 0x%2.2x", opcode);

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&result_code)) {
		print_text(COLOR_ERROR, "  result_code:: invalid result_code");
		goto done;
	}

	print_field("  result_code: 0x%2.2x", result_code);

	switch (result_code) {
	case 0x00:
		str = "SUCCESS";
		break;
	case 0x01:
		str = "OPCODE NOT SUPPORTED";
		break;
	case 0x02:
		str = "OPERATION NOT POSSIBLE";
		break;
	case 0x03:
		str = "INVALID CALL INDEX";
		break;
	case 0x04:
		str = "STATE MISMATCH";
		break;
	case 0x05:
		str = "LACK OF RESOURCES";
		break;
	case 0x06:
		str = "INVALID OUTGOING URI";
		break;
	default:
		str = "RFU";
		break;
	}

	print_field("  Status: %s", str);

done:
	if (frame->size)
		print_hex_field("  call_cp Data", frame->data, frame->size);
}

static void call_cp_write(const struct l2cap_frame *frame)
{
	print_call_cp(frame);
}

static void call_cp_notify(const struct l2cap_frame *frame)
{
	print_call_cp_notification(frame);
}

static void print_call_cp_opt(const struct l2cap_frame *frame)
{
	uint16_t operation;

	if (!l2cap_frame_get_le16((void *)frame, (uint16_t *)&operation)) {
		print_text(COLOR_ERROR, "  status operation:: invalid size");
		goto done;
	}

	print_field("  operation: 0x%2x", operation);

	if (operation & 0x1) {
		print_field("  Local Hold and Local Retrieve "
								"Call Control Point Opcodes supported");
	} else {
		print_field("  Local Hold and Local Retrieve "
								"Call Control Point Opcodes not supported");
	}

	if (operation & 0x2)
		print_field("  Join Call Control Point Opcode supported");
	else
		print_field("  Join Call Control Point Opcode not supported");

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void call_cp_opt_opcodes_read(const struct l2cap_frame *frame)
{
	print_call_cp_opt(frame);
}

static void print_term_reason(const struct l2cap_frame *frame)
{
	uint8_t call_id, reason;

	if (!l2cap_frame_get_u8((void *)frame, &call_id)) {
		print_text(COLOR_ERROR, "Call Index: invalid size");
		goto done;
	}
	print_field("  call Index: %u", call_id);

	if (!l2cap_frame_get_u8((void *)frame, &reason)) {
		print_text(COLOR_ERROR, "Reason: invalid size");
		goto done;
	}

	print_field("  Reason:");

	switch (reason) {
	case 0x00:
		print_field("  Improper URI");
		break;
	case 0x01:
		print_field("  Call Failed");
		break;
	case 0x02:
		print_field("  Remote party ended the call");
		break;
	case 0x03:
		print_field("  Server  ended the call");
		break;
	case 0x04:
		print_field("  Line was Busy");
		break;
	case 0x05:
		print_field("  Network Congestion");
		break;
	case 0x06:
		print_field("  Client terminated the call");
		break;
	case 0x07:
		print_field("  No service");
		break;
	case 0x08:
		print_field("  No answer");
		break;
	case 0x09:
		print_field("  Unspecified");
		break;
	default:
		print_field("  RFU");
		break;
	}

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void call_termination_reason_notify(const struct l2cap_frame *frame)
{
	print_term_reason(frame);
}

static void print_incom_call(const struct l2cap_frame *frame)
{
	char *name;
	uint8_t call_id;

	if (!l2cap_frame_get_u8((void *)frame, &call_id)) {
		print_text(COLOR_ERROR, "Call Index: invalid size");
		goto done;
	}

	print_field("  Call Index: %u", call_id);

	name = name2utf8((uint8_t *)frame->data, frame->size);

	print_field("  call_string: %s", name);

	g_free(name);

done:
	if (frame->size)
		print_hex_field(" Data", frame->data, frame->size);
}

static void incoming_call_read(const struct l2cap_frame *frame)
{
	print_incom_call(frame);
}

static void incoming_call_notify(const struct l2cap_frame *frame)
{
	print_incom_call(frame);
}

static void print_call_friendly_name(const struct l2cap_frame *frame)
{
	char *name;
	uint8_t call_id;

	if (!l2cap_frame_get_u8((void *)frame, &call_id)) {
		print_text(COLOR_ERROR, "Call Index: invalid size");
		goto done;
	}

	print_field("  Call Index: %u", call_id);

	name = name2utf8((uint8_t *)frame->data, frame->size);

	print_field("  Friendly Name: %s", name);

	g_free(name);

done:
	if (frame->size)
		print_hex_field(" Data", frame->data, frame->size);
}

static void call_friendly_name_read(const struct l2cap_frame *frame)
{
	print_call_friendly_name(frame);
}

static void call_friendly_name_notify(const struct l2cap_frame *frame)
{
	print_call_friendly_name(frame);
}

static const char *play_order_str(uint8_t order)
{
	switch (order) {
	case 0x01:
		return "Single once";
	case 0x02:
		return "Single repeat";
	case 0x03:
		return "In order once";
	case 0x04:
		return "In order repeat";
	case 0x05:
		return "Oldest once";
	case 0x06:
		return "Oldest repeat";
	case 0x07:
		return "Newest once";
	case 0x08:
		return "Newest repeat";
	case 0x09:
		return "Shuffle once";
	case 0x0A:
		return "Shuffle repeat";
	default:
		return "RFU";
	}
}

static void print_playing_order(const struct l2cap_frame *frame)
{
	int8_t playing_order;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&playing_order)) {
		print_text(COLOR_ERROR, "  Playing Order: invalid size");
		goto done;
	}

	print_field("  Playing Order: %s", play_order_str(playing_order));

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void playing_order_read(const struct l2cap_frame *frame)
{
	print_playing_order(frame);
}

static void playing_order_write(const struct l2cap_frame *frame)
{
	print_playing_order(frame);
}

static void playing_order_notify(const struct l2cap_frame *frame)
{
	print_playing_order(frame);
}

static const struct bitfield_data playing_orders_table[] = {
	{  0, "Single once (0x0001)"	    },
	{  1, "Single repeat (0x0002)"		},
	{  2, "In order once (0x0004)"		},
	{  3, "In Order Repeat (0x0008)"	},
	{  4, "Oldest once (0x0010)"		},
	{  5, "Oldest repeat (0x0020)"		},
	{  6, "Newest once (0x0040)"		},
	{  7, "Newest repeat (0x0080)"	    },
	{  8, "Shuffle once (0x0100)"		},
	{  9, "Shuffle repeat (0x0200)"		},
	{  10, "RFU (0x0400)"			    },
	{  11, "RFU (0x0800)"		        },
	{  12, "RFU (0x1000)"				},
	{  13, "RFU (0x2000)"				},
	{  14, "RFU (0x4000)"				},
	{  15, "RFU (0x8000)"				},
	{ }
};

static void print_playing_orders_supported(const struct l2cap_frame *frame)
{
	uint16_t supported_orders;
	uint16_t mask;

	if (!l2cap_frame_get_le16((void *)frame, &supported_orders)) {
		print_text(COLOR_ERROR,
				"    Supported Playing Orders: invalid size");
		goto done;
	}

	print_field("      Supported Playing Orders: 0x%4.4x",
				supported_orders);

	mask = print_bitfield(8, supported_orders, playing_orders_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%4.4x)",
								mask);

done:
	if (frame->size)
		print_hex_field("    Data", frame->data, frame->size);
}

static void playing_orders_supported_read(const struct l2cap_frame *frame)
{
	print_playing_orders_supported(frame);
}

static const char *media_state_str(uint8_t state)
{
	switch (state) {
	case 0x00:
		return "Inactive";
	case 0x01:
		return "Playing";
	case 0x02:
		return "Paused";
	case 0x03:
		return "Seeking";
	default:
		return "RFU";
	}
}

static void print_media_state(const struct l2cap_frame *frame)
{
	int8_t state;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&state)) {
		print_text(COLOR_ERROR, "  Media State: invalid size");
		goto done;
	}

	print_field("  Media State: %s", media_state_str(state));

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void media_state_read(const struct l2cap_frame *frame)
{
	print_media_state(frame);
}

static void media_state_notify(const struct l2cap_frame *frame)
{
	print_media_state(frame);
}

static const struct media_cp_opcode {
	uint8_t opcode;
	const char *opcode_str;
} media_cp_opcode_table[] = {
	{0x01,	"Play"},
	{0x02,	"Pause"},
	{0x03,	"Fast Rewind"},
	{0x04,	"Fast Forward"},
	{0x05,	"Stop"},
	{0x10,	"Move Relative"},
	{0x20,	"Previous Segment"},
	{0x21,	"Next Segment"},
	{0x22,	"First Segment"},
	{0x23,	"Last Segment"},
	{0x24,	"Goto Segment"},
	{0x30,	"Previous Track"},
	{0x31,	"Next Track"},
	{0x32,	"First Track"},
	{0x33,	"Last Track"},
	{0x34,	"Goto Track"},
	{0x40,	"Previous Group"},
	{0x41,	"Next Group"},
	{0x42,	"First Group"},
	{0x43,	"Last Group"},
	{0x44,	"Goto Group"},
};

static const char *cp_opcode_str(uint8_t opcode)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(media_cp_opcode_table); i++) {
		const char *str = media_cp_opcode_table[i].opcode_str;

		if (opcode == media_cp_opcode_table[i].opcode)
			return str;
	}

	return "RFU";
}

static void print_media_cp(const struct l2cap_frame *frame)
{
	int8_t opcode;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&opcode)) {
		print_text(COLOR_ERROR, "  Media Control Point: invalid size");
		goto done;
	}

	print_field("  Media Control Point: %s", cp_opcode_str(opcode));

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void media_cp_write(const struct l2cap_frame *frame)
{
	print_media_cp(frame);
}

static void media_cp_notify(const struct l2cap_frame *frame)
{
	print_media_cp(frame);
}

static const struct bitfield_data supported_opcodes_table[] = {
	{0, "Play (0x00000001)"				},
	{1, "Pause (0x00000002)"			},
	{2, "Fast Rewind	(0x00000004)"	},
	{3, "Fast Forward (0x00000008)"		},
	{4, "Stop (0x00000010)"				},
	{5, "Move Relative (0x00000020)"	},
	{6, "Previous Segment (0x00000040)"	},
	{7, "Next Segment (0x00000080)"		},
	{8, "First Segment (0x00000100)"	},
	{9, "Last Segment (0x00000200)"		},
	{10, "Goto Segment (0x00000400)"	},
	{11, "Previous Track (0x00000800)"	},
	{12, "Next Track (0x00001000)"		},
	{13, "First Track (0x00002000)"		},
	{14, "Last Track (0x00004000)"		},
	{15, "Goto Track (0x00008000)"		},
	{16, "Previous Group (0x00010000)"	},
	{17, "Next Group (0x00020000)"		},
	{18, "First Group (0x00040000)"		},
	{19, "Last Group (0x00080000)"		},
	{20, "Goto Group (0x00100000)"		},
	{21, "RFU (0x00200000)"				},
	{22, "RFU (0x00400000)"				},
	{23, "RFU (0x00800000)"				},
	{24, "RFU (0x01000000)"				},
	{25, "RFU (0x02000000)"				},
	{26, "RFU (0x04000000)"				},
	{27, "RFU (0x08000000)"				},
	{28, "RFU (0x10000000)"				},
	{29, "RFU (0x20000000)"				},
	{30, "RFU (0x40000000)"				},
	{31, "RFU (0x80000000)"				},
	{ }
};

static void print_media_cp_op_supported(const struct l2cap_frame *frame)
{
	uint32_t supported_opcodes;
	uint32_t mask;

	if (!l2cap_frame_get_le32((void *)frame, &supported_opcodes)) {
		print_text(COLOR_ERROR, "    value: invalid size");
		goto done;
	}

	print_field("      Supported Opcodes: 0x%8.8x", supported_opcodes);

	mask = print_bitfield(8, supported_opcodes, supported_opcodes_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%4.4x)",
								mask);

done:
	if (frame->size)
		print_hex_field("    Data", frame->data, frame->size);
}

static void media_cp_op_supported_read(const struct l2cap_frame *frame)
{
	print_media_cp_op_supported(frame);
}

static void media_cp_op_supported_notify(const struct l2cap_frame *frame)
{
	print_media_cp_op_supported(frame);
}

static void print_content_control_id(const struct l2cap_frame *frame)
{
	int8_t ccid;

	if (!l2cap_frame_get_u8((void *)frame, (uint8_t *)&ccid)) {
		print_text(COLOR_ERROR, "  Content Control ID: invalid size");
		goto done;
	}

	print_field("  Content Control ID: 0x%2.2x", ccid);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void content_control_id_read(const struct l2cap_frame *frame)
{
	print_content_control_id(frame);
}

static const struct pa_sync_state_decoder {
	uint8_t code;
	const char *value;
} pa_sync_state_decoders[] = {
	{ 0x00, "Not synchronized to PA" },
	{ 0x01, "SyncInfo Request" },
	{ 0x02, "Synchronized to PA" },
	{ 0x03, "Failed to synchronize to PA" },
	{ 0x04, "No PAST" },
};

static const struct cp_pa_sync_state_decoder {
	uint8_t code;
	const char *value;
} cp_pa_sync_state_decoders[] = {
	{ 0x00, "Do not synchronize to PA" },
	{ 0x01, "Synchronize to PA - PAST available" },
	{ 0x02, "Synchronize to PA - PAST not available" },
};

static const struct big_enc_decoder {
	uint8_t code;
	const char *value;
} big_enc_decoders[] = {
	{ 0x00, "Not encrypted" },
	{ 0x01, "Broadcast_Code required" },
	{ 0x02, "Decrypting" },
	{ 0x03, "Bad_Code (incorrect encryption key)" },
};

static bool print_subgroup_lv(const struct l2cap_frame *frame,
				const char *label,
				const struct util_ltv_debugger *debugger,
				size_t debugger_len)
{
	struct bt_hci_lv_data *lv;

	lv = l2cap_frame_pull((void *)frame, frame, sizeof(*lv));
	if (!lv) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	if (!l2cap_frame_pull((void *)frame, frame, lv->len)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	util_debug_ltv(lv->data, lv->len, debugger, debugger_len,
			       print_ltv, (void *)label);

	return true;
}

static bool print_subgroup_metadata(const char *label,
				const struct l2cap_frame *frame)
{
	return print_subgroup_lv(frame, label, NULL, 0);
}

static void print_bcast_recv_state(const struct l2cap_frame *frame)
{
	uint8_t i;
	uint8_t id;
	uint8_t addr_type;
	uint8_t *addr;
	uint8_t sid;
	uint32_t bid;
	uint8_t pa_sync_state;
	uint8_t enc;
	uint8_t *bad_code;
	uint8_t num_subgroups = 0;
	uint32_t bis_sync_state;

	if (frame->size == 0) {
		print_field("  Empty characteristic");
		goto done;
	}

	if (!l2cap_frame_get_u8((void *)frame, &id)) {
		print_text(COLOR_ERROR, "Source_ID: invalid size");
		goto done;
	}

	print_field("  Source_ID: %u", id);

	if (!l2cap_frame_get_u8((void *)frame, &addr_type)) {
		print_text(COLOR_ERROR, "Source_Address_Type: invalid size");
		goto done;
	}

	print_field("  Source_Address_Type: %u", addr_type);

	addr = l2cap_frame_pull((void *)frame, frame, sizeof(bdaddr_t));
	if (!addr) {
		print_text(COLOR_ERROR, "Source_Address: invalid size");
		goto done;
	}

	print_field("  Source_Address: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
					addr[5], addr[4],
					addr[3], addr[2],
					addr[1], addr[0]);

	if (!l2cap_frame_get_u8((void *)frame, &sid)) {
		print_text(COLOR_ERROR, "Source_Adv_SID: invalid size");
		goto done;
	}

	print_field("  Source_Adv_SID: %u", sid);

	if (!l2cap_frame_get_le24((void *)frame, &bid)) {
		print_text(COLOR_ERROR, "Broadcast_ID: invalid size");
		goto done;
	}

	print_field("  Broadcast_ID: 0x%06x", bid);

	if (!l2cap_frame_get_u8((void *)frame, &pa_sync_state)) {
		print_text(COLOR_ERROR, "PA_Sync_State: invalid size");
		goto done;
	}

	for (i = 0; i < ARRAY_SIZE(pa_sync_state_decoders); i++) {
		const struct pa_sync_state_decoder *decoder;

		decoder = &pa_sync_state_decoders[i];

		if (decoder->code == pa_sync_state) {
			print_field("  PA_Sync_State: %s", decoder->value);
			break;
		}
	}

	if (i == ARRAY_SIZE(pa_sync_state_decoders))
		print_field("  PA_Sync_State: %s", "Invalid value");

	if (!l2cap_frame_get_u8((void *)frame, &enc)) {
		print_text(COLOR_ERROR, "BIG_Encryption: invalid size");
		goto done;
	}

	for (i = 0; i < ARRAY_SIZE(big_enc_decoders); i++) {
		const struct big_enc_decoder *decoder;

		decoder = &big_enc_decoders[i];

		if (decoder->code == enc) {
			print_field("  BIG_Encryption: %s", decoder->value);
			break;
		}
	}

	if (i == ARRAY_SIZE(big_enc_decoders))
		print_field("  BIG_Encryption: %s", "Invalid value");

	if (enc == 0x03) {
		bad_code = l2cap_frame_pull((void *)frame, frame, 16);
		if (!bad_code) {
			print_text(COLOR_ERROR, "Bad_Code: invalid size");
			goto done;
		}

		print_hex_field("  Bad_Code", bad_code, 16);
	}

	if (!l2cap_frame_get_u8((void *)frame, &num_subgroups)) {
		print_text(COLOR_ERROR, "Num_Subgroups: invalid size");
		goto done;
	}

	print_field("  Num_Subgroups: %u", num_subgroups);

	for (i = 0; i < num_subgroups; i++) {
		print_field("  Subgroup #%u:", i);

		if (!l2cap_frame_get_le32((void *)frame, &bis_sync_state)) {
			print_text(COLOR_ERROR, "BIS_Sync State: invalid size");
			goto done;
		}

		print_field("    BIS_Sync State: 0x%8.8x", bis_sync_state);

		if (!print_subgroup_metadata("    Metadata", frame))
			goto done;
	}

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void bcast_recv_state_read(const struct l2cap_frame *frame)
{
	print_bcast_recv_state(frame);
}

static void bcast_recv_state_notify(const struct l2cap_frame *frame)
{
	print_bcast_recv_state(frame);
}

#define BCAST_AUDIO_SCAN_CP_CMD(_op, _desc, _func) \
[_op] = { \
	.desc = _desc, \
	.func = _func, \
}

static void bcast_audio_scan_cp_add_src_cmd(const struct l2cap_frame *frame)
{
	uint8_t i;
	uint8_t addr_type;
	uint8_t *addr;
	uint8_t sid;
	uint32_t bid;
	uint8_t pa_sync_state;
	uint16_t pa_interval;
	uint8_t num_subgroups = 0;
	uint32_t bis_sync_state;

	if (!l2cap_frame_get_u8((void *)frame, &addr_type)) {
		print_text(COLOR_ERROR, "Source_Address_Type: invalid size");
		return;
	}

	print_field("    Source_Address_Type: %u", addr_type);

	addr = l2cap_frame_pull((void *)frame, frame, sizeof(bdaddr_t));
	if (!addr) {
		print_text(COLOR_ERROR, "Source_Address: invalid size");
		return;
	}

	print_field("    Source_Address: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
					addr[5], addr[4],
					addr[3], addr[2],
					addr[1], addr[0]);

	if (!l2cap_frame_get_u8((void *)frame, &sid)) {
		print_text(COLOR_ERROR, "Source_Adv_SID: invalid size");
		return;
	}

	print_field("    Source_Adv_SID: %u", sid);

	if (!l2cap_frame_get_le24((void *)frame, &bid)) {
		print_text(COLOR_ERROR, "Broadcast_ID: invalid size");
		return;
	}

	print_field("    Broadcast_ID: 0x%06x", bid);

	if (!l2cap_frame_get_u8((void *)frame, &pa_sync_state)) {
		print_text(COLOR_ERROR, "PA_Sync_State: invalid size");
		return;
	}

	for (i = 0; i < ARRAY_SIZE(cp_pa_sync_state_decoders); i++) {
		const struct cp_pa_sync_state_decoder *decoder;

		decoder = &cp_pa_sync_state_decoders[i];

		if (decoder->code == pa_sync_state) {
			print_field("    PA_Sync_State: %s", decoder->value);
			break;
		}
	}

	if (i == ARRAY_SIZE(cp_pa_sync_state_decoders))
		print_field("    PA_Sync_State: %s", "Invalid value");

	if (!l2cap_frame_get_le16((void *)frame, &pa_interval)) {
		print_text(COLOR_ERROR, "PA_Interval: invalid size");
		return;
	}

	print_field("    PA_Interval: 0x%04x", pa_interval);

	if (!l2cap_frame_get_u8((void *)frame, &num_subgroups)) {
		print_text(COLOR_ERROR, "Num_Subgroups: invalid size");
		return;
	}

	print_field("    Num_Subgroups: %u", num_subgroups);

	for (i = 0; i < num_subgroups; i++) {
		print_field("    Subgroup #%u:", i);

		if (!l2cap_frame_get_le32((void *)frame, &bis_sync_state)) {
			print_text(COLOR_ERROR, "BIS_Sync State: invalid size");
			return;
		}

		print_field("      BIS_Sync State: 0x%8.8x", bis_sync_state);

		if (!print_subgroup_metadata("      Metadata", frame))
			return;
	}
}

static void bcast_audio_scan_cp_mod_src_cmd(const struct l2cap_frame *frame)
{
	uint8_t i;
	uint8_t id;
	uint8_t pa_sync_state;
	uint16_t pa_interval;
	uint8_t num_subgroups = 0;
	uint32_t bis_sync_state;

	if (!l2cap_frame_get_u8((void *)frame, &id)) {
		print_text(COLOR_ERROR, "Source_ID: invalid size");
		return;
	}

	print_field("    Source_ID: %u", id);

	if (!l2cap_frame_get_u8((void *)frame, &pa_sync_state)) {
		print_text(COLOR_ERROR, "PA_Sync_State: invalid size");
		return;
	}

	for (i = 0; i < ARRAY_SIZE(cp_pa_sync_state_decoders); i++) {
		const struct cp_pa_sync_state_decoder *decoder;

		decoder = &cp_pa_sync_state_decoders[i];

		if (decoder->code == pa_sync_state) {
			print_field("    PA_Sync_State: %s", decoder->value);
			break;
		}
	}

	if (i == ARRAY_SIZE(cp_pa_sync_state_decoders))
		print_field("    PA_Sync_State: %s", "Invalid value");

	if (!l2cap_frame_get_le16((void *)frame, &pa_interval)) {
		print_text(COLOR_ERROR, "PA_Interval: invalid size");
		return;
	}

	print_field("    PA_Interval: 0x%04x", pa_interval);

	if (!l2cap_frame_get_u8((void *)frame, &num_subgroups)) {
		print_text(COLOR_ERROR, "Num_Subgroups: invalid size");
		return;
	}

	print_field("    Num_Subgroups: %u", num_subgroups);

	for (i = 0; i < num_subgroups; i++) {
		print_field("    Subgroup #%u:", i);

		if (!l2cap_frame_get_le32((void *)frame, &bis_sync_state)) {
			print_text(COLOR_ERROR, "BIS_Sync State: invalid size");
			return;
		}

		print_field("      BIS_Sync State: 0x%8.8x", bis_sync_state);

		if (!print_subgroup_metadata("      Metadata", frame))
			return;
	}
}

static void bcast_audio_scan_cp_set_bcode_cmd(const struct l2cap_frame *frame)
{
	uint8_t id;
	uint8_t *bcast_code;

	if (!l2cap_frame_get_u8((void *)frame, &id)) {
		print_text(COLOR_ERROR, "Source_ID: invalid size");
		return;
	}

	print_field("    Source_ID: %u", id);

	bcast_code = l2cap_frame_pull((void *)frame, frame, 16);
	if (!bcast_code) {
		print_text(COLOR_ERROR, "Broadcast_Code: invalid size");
		return;
	}

	print_hex_field("    Broadcast_Code", bcast_code, 16);

}

static void bcast_audio_scan_cp_remove_src_cmd(const struct l2cap_frame *frame)
{
	uint8_t id;

	if (!l2cap_frame_get_u8((void *)frame, &id)) {
		print_text(COLOR_ERROR, "Source_ID: invalid size");
		return;
	}

	print_field("    Source_ID: %u", id);
}

static const struct bcast_audio_scan_cp_cmd {
	const char *desc;
	void (*func)(const struct l2cap_frame *frame);
} bcast_audio_scan_cp_cmd_table[] = {
	/* Opcode = 0x00 (Remote Scan Stopped) */
	BCAST_AUDIO_SCAN_CP_CMD(0x00, "Remote Scan Stopped", NULL),
	/* Opcode = 0x01 (Remote Scan Started) */
	BCAST_AUDIO_SCAN_CP_CMD(0x01, "Remote Scan Started", NULL),
	/* Opcode = 0x02 (Add Source) */
	BCAST_AUDIO_SCAN_CP_CMD(0x02, "Add Source",
					bcast_audio_scan_cp_add_src_cmd),
	/* Opcode = 0x03 (Modify Source) */
	BCAST_AUDIO_SCAN_CP_CMD(0x03, "Modify Source",
					bcast_audio_scan_cp_mod_src_cmd),
	/* Opcode = 0x04 (Set Broadcast_Code) */
	BCAST_AUDIO_SCAN_CP_CMD(0x04, "Set Broadcast_Code",
					bcast_audio_scan_cp_set_bcode_cmd),
	/* Opcode = 0x05 (Remove Source) */
	BCAST_AUDIO_SCAN_CP_CMD(0x05, "Remove Source",
					bcast_audio_scan_cp_remove_src_cmd),
};

static const struct bcast_audio_scan_cp_cmd *
bcast_audio_scan_cp_get_cmd(uint8_t op)
{
	if (op > ARRAY_SIZE(bcast_audio_scan_cp_cmd_table))
		return NULL;

	return &bcast_audio_scan_cp_cmd_table[op];
}

static void print_bcast_audio_scan_cp_cmd(const struct l2cap_frame *frame)
{
	uint8_t op;
	const struct bcast_audio_scan_cp_cmd *cmd;

	if (!l2cap_frame_get_u8((void *)frame, &op)) {
		print_text(COLOR_ERROR, "Opcode: invalid size");
		goto done;
	}

	cmd = bcast_audio_scan_cp_get_cmd(op);
	if (!cmd) {
		print_field("    Opcode: Reserved (0x%2.2x)", op);
		goto done;
	}

	print_field("    Opcode: %s (0x%2.2x)", cmd->desc, op);
	if (cmd->func)
		cmd->func(frame);

done:
	if (frame->size)
		print_hex_field("  Data", frame->data, frame->size);
}

static void bcast_audio_scan_cp_write(const struct l2cap_frame *frame)
{
	print_bcast_audio_scan_cp_cmd(frame);
}

static const struct bitfield_data gmap_role_table[] = {
	{  0, "Unicast Game Gateway (UGG) (0x0001)"	},
	{  1, "Unicast Game Terminal (UGT) (0x0002)"	},
	{  2, "Broadcast Game Sender (BGS) (0x0004)"	},
	{  3, "Broadcast Game Receiver (BGR) (0x0008)"	},
	{ }
};

static void gmap_role_read(const struct l2cap_frame *frame)
{
	uint8_t role;
	uint8_t mask;

	if (!l2cap_frame_get_u8((void *)frame, &role)) {
		print_text(COLOR_ERROR, "    invalid size");
		return;
	}

	print_field("    Role: 0x%2.2x", role);

	mask = print_bitfield(6, role, gmap_role_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%2.2x)",
								mask);
}

static const struct bitfield_data ugg_features_table[] = {
	{  0, "UGG Multiplex (0x0001)"	},
	{  1, "UGG 96 kbps Source (0x0002)"	},
	{  2, "UGG Multilink (0x0004)"	},
	{ }
};

static void ugg_features_read(const struct l2cap_frame *frame)
{
	uint8_t value;
	uint8_t mask;

	if (!l2cap_frame_get_u8((void *)frame, &value)) {
		print_text(COLOR_ERROR, "    invalid size");
		return;
	}

	print_field("    Value: 0x%2.2x", value);

	mask = print_bitfield(6, value, ugg_features_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%2.2x)",
								mask);
}

static const struct bitfield_data ugt_features_table[] = {
	{  0, "UGT Source (0x0001)"		},
	{  1, "UGT 80 kbps Source (0x0002)"	},
	{  2, "UGT Sink (0x0004)"		},
	{  3, "UGT 64 kbps Sink (0x0008)"	},
	{  4, "UGT Multiplex (0x0010)"		},
	{  5, "UGT Multisink (0x0020)"		},
	{  6, "UGT Multisource (0x0040)"	},
	{ }
};

static void ugt_features_read(const struct l2cap_frame *frame)
{
	uint8_t value;
	uint8_t mask;

	if (!l2cap_frame_get_u8((void *)frame, &value)) {
		print_text(COLOR_ERROR, "    invalid size");
		return;
	}

	print_field("    Value: 0x%2.2x", value);

	mask = print_bitfield(6, value, ugt_features_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%2.2x)",
								mask);
}

static const struct bitfield_data bgs_features_table[] = {
	{  0, "BGS 96 kbps (0x0001)"		},
	{ }
};

static void bgs_features_read(const struct l2cap_frame *frame)
{
	uint8_t value;
	uint8_t mask;

	if (!l2cap_frame_get_u8((void *)frame, &value)) {
		print_text(COLOR_ERROR, "    invalid size");
		return;
	}

	print_field("    Value: 0x%2.2x", value);

	mask = print_bitfield(6, value, bgs_features_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%2.2x)",
								mask);
}

static const struct bitfield_data bgr_features_table[] = {
	{  0, "BGR Multisink (0x0001)"		},
	{  1, "BGR Multiplex (0x0002)"		},
	{ }
};

static void bgr_features_read(const struct l2cap_frame *frame)
{
	uint8_t value;
	uint8_t mask;

	if (!l2cap_frame_get_u8((void *)frame, &value)) {
		print_text(COLOR_ERROR, "    invalid size");
		return;
	}

	print_field("    Value: 0x%2.2x", value);

	mask = print_bitfield(6, value, bgr_features_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%2.2x)",
								mask);
}

#define GMAS \
	GATT_HANDLER(0x2c00, gmap_role_read, NULL, NULL), \
	GATT_HANDLER(0x2c01, ugg_features_read, NULL, NULL), \
	GATT_HANDLER(0x2c02, ugt_features_read, NULL, NULL), \
	GATT_HANDLER(0x2c02, bgs_features_read, NULL, NULL), \
	GATT_HANDLER(0x2c03, bgr_features_read, NULL, NULL)

#define GATT_HANDLER(_uuid, _read, _write, _notify) \
{ \
	.uuid = { \
		.type = BT_UUID16, \
		.value.u16 = _uuid, \
	}, \
	.read = _read, \
	.write = _write, \
	.notify = _notify \
}

static const struct gatt_handler {
	bt_uuid_t uuid;
	void (*read)(const struct l2cap_frame *frame);
	void (*write)(const struct l2cap_frame *frame);
	void (*notify)(const struct l2cap_frame *frame);
} gatt_handlers[] = {
	GATT_HANDLER(0x2800, pri_svc_read, NULL, NULL),
	GATT_HANDLER(0x2801, sec_svc_read, NULL, NULL),
	GATT_HANDLER(0x2803, chrc_read, NULL, NULL),
	GATT_HANDLER(0x2902, ccc_read, ccc_write, NULL),
	GATT_HANDLER(0x2bc4, ase_read, NULL, ase_notify),
	GATT_HANDLER(0x2bc5, ase_read, NULL, ase_notify),
	GATT_HANDLER(0x2bc6, NULL, ase_cp_write, ase_cp_notify),
	GATT_HANDLER(0x2bc9, pac_read, NULL, pac_notify),
	GATT_HANDLER(0x2bca, pac_loc_read, NULL, pac_loc_notify),
	GATT_HANDLER(0x2bcb, pac_read, NULL, pac_notify),
	GATT_HANDLER(0x2bcc, pac_loc_read, NULL, pac_loc_notify),
	GATT_HANDLER(0x2bcd, pac_context_read, NULL, pac_context_notify),
	GATT_HANDLER(0x2bce, pac_context_read, NULL, pac_context_notify),
	GATT_HANDLER(0x2b7d, vol_state_read, NULL, vol_state_notify),
	GATT_HANDLER(0x2b7e, NULL, vol_cp_write, NULL),
	GATT_HANDLER(0x2b7f, vol_flag_read, NULL, vol_flag_notify),

	GATT_HANDLER(0x2b84, csip_sirk_read, NULL, csip_sirk_notify),
	GATT_HANDLER(0x2b85, csip_size_read, NULL, csip_size_notify),
	GATT_HANDLER(0x2b86, csip_lock_read, NULL, NULL),
	GATT_HANDLER(0x2b87, csip_rank_read, NULL, NULL),

	GATT_HANDLER(0x2b93, mp_name_read, NULL, mp_name_notify),
	GATT_HANDLER(0x2b96, NULL, NULL, track_changed_notify),
	GATT_HANDLER(0x2b97, track_title_read, NULL, track_title_notify),
	GATT_HANDLER(0x2b98, track_duration_read, NULL, track_duration_notify),
	GATT_HANDLER(0x2b99, track_position_read, track_position_write,
					track_position_notify),
	GATT_HANDLER(0x2b9a, playback_speed_read, playback_speed_write,
					playback_speed_notify),
	GATT_HANDLER(0x2b9b, seeking_speed_read, NULL, seeking_speed_notify),
	GATT_HANDLER(0x2ba1, playing_order_read, playing_order_write,
					playing_order_notify),
	GATT_HANDLER(0x2ba2, playing_orders_supported_read, NULL, NULL),
	GATT_HANDLER(0x2ba3, media_state_read, NULL, media_state_notify),
	GATT_HANDLER(0x2ba4, NULL, media_cp_write, media_cp_notify),
	GATT_HANDLER(0x2ba5, media_cp_op_supported_read, NULL,
					media_cp_op_supported_notify),
	GATT_HANDLER(0x2bba, content_control_id_read, NULL, NULL),

	GATT_HANDLER(0x2bc7, NULL, bcast_audio_scan_cp_write, NULL),
	GATT_HANDLER(0x2bc8, bcast_recv_state_read, NULL,
					bcast_recv_state_notify),
	GATT_HANDLER(0x2bb3, bearer_name_read, NULL, bearer_name_notify),
	GATT_HANDLER(0x2bb4, bearer_uci_read, NULL, NULL),
	GATT_HANDLER(0x2bb5, bearer_technology_read, NULL,
					bearer_technology_notify),
	GATT_HANDLER(0x2bb6, bearer_uri_schemes_list_read, NULL, NULL),
	GATT_HANDLER(0x2bb7, bearer_signal_strength_read, NULL,
					bearer_signal_strength_notify),
	GATT_HANDLER(0x2bb8, bearer_signal_strength_rep_intrvl_read,
			bearer_signal_strength_rep_intrvl_write, NULL),
	GATT_HANDLER(0x2bb9, bearer_current_call_list_read, NULL,
					bearer_current_call_list_notify),
	GATT_HANDLER(0x2bba, call_content_control_id_read, NULL, NULL),
	GATT_HANDLER(0x2bbb, status_flag_read, NULL, status_flag_notify),
	GATT_HANDLER(0x2bbc, incom_target_bearer_uri_read, NULL,
					incom_target_bearer_uri_notify),
	GATT_HANDLER(0x2bbd, call_state_read, NULL, call_state_notify),
	GATT_HANDLER(0x2bbe, NULL, call_cp_write, call_cp_notify),
	GATT_HANDLER(0x2bbf, call_cp_opt_opcodes_read, NULL, NULL),
	GATT_HANDLER(0x2bc0, NULL, NULL, call_termination_reason_notify),
	GATT_HANDLER(0x2bc1, incoming_call_read, NULL, incoming_call_notify),
	GATT_HANDLER(0x2bc2, call_friendly_name_read, NULL,
					call_friendly_name_notify),
	GMAS
};

static const struct gatt_handler *get_handler_uuid(const bt_uuid_t *uuid)
{
	size_t i;

	if (!uuid)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(gatt_handlers); i++) {
		const struct gatt_handler *handler = &gatt_handlers[i];

		if (!bt_uuid_cmp(&handler->uuid, uuid))
			return handler;
	}

	return NULL;
}

static const struct gatt_handler *get_handler(struct gatt_db_attribute *attr)
{
	return get_handler_uuid(gatt_db_attribute_get_type(attr));
}

static void att_exchange_mtu_req(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_att_exchange_mtu_req *pdu = frame->data;

	print_field("Client RX MTU: %d", le16_to_cpu(pdu->mtu));
}

static void att_exchange_mtu_rsp(const struct l2cap_frame *frame)
{
	struct packet_conn_data *conn;
	struct att_conn_data *data;
	uint16_t mtu;

	if (!l2cap_frame_get_le16((void *)frame, &mtu)) {
		print_text(COLOR_ERROR, "  invalid size");
		return;
	}

	print_field("Server RX MTU: %d", mtu);

	conn = packet_get_conn_data(frame->handle);
	data = att_get_conn_data(conn);
	if (!data)
		return;

	data->mtu = mtu;
}

static void att_find_info_req(const struct l2cap_frame *frame)
{
	print_handle_range("Handle range", frame->data);
}

static const char *att_format_str(uint8_t format)
{
	switch (format) {
	case 0x01:
		return "UUID-16";
	case 0x02:
		return "UUID-128";
	default:
		return "unknown";
	}
}

static struct gatt_db_attribute *insert_desc(const struct l2cap_frame *frame,
						uint16_t handle,
						bt_uuid_t *uuid, bool rsp)
{
	struct gatt_db *db;

	db = get_db(frame, rsp);
	if (!db)
		return NULL;

	return gatt_db_insert_descriptor(db, handle, uuid, 0, NULL, NULL, NULL);
}

static void att_find_info_rsp_16(const struct l2cap_frame *frame)
{
	while (frame->size >= 4) {
		uint16_t handle;
		uint16_t u16;
		bt_uuid_t uuid;

		if (!l2cap_frame_get_le16((void *)frame, &handle)) {
			print_text(COLOR_ERROR, "    Handle: invalid size");
			return;
		}

		if (!l2cap_frame_get_le16((void *)frame, &u16)) {
			print_text(COLOR_ERROR, "    UUID: invalid size");
			return;
		}

		print_field("Handle: 0x%4.4x", handle);
		print_uuid("UUID", &u16, 2);

		bt_uuid16_create(&uuid, u16);

		insert_desc(frame, handle, &uuid, true);
	}
}

static void att_find_info_rsp_128(const struct l2cap_frame *frame)
{
	while (frame->size >= 18) {
		uint16_t handle;
		bt_uuid_t uuid;

		if (!l2cap_frame_get_le16((void *)frame, &handle)) {
			print_text(COLOR_ERROR, "    Handle: invalid size");
			return;
		}

		if (frame->size < 16) {
			print_text(COLOR_ERROR, "    UUID: invalid size");
			return;
		}

		print_field("Handle: 0x%4.4x", handle);
		print_uuid("UUID", frame->data, 16);

		bt_uuid_from_data(&uuid, frame->data, 16);

		if (!l2cap_frame_pull((void *)frame, frame, 16))
			return;

		insert_desc(frame, handle, &uuid, true);
	}
}

static void att_find_info_rsp(const struct l2cap_frame *frame)
{
	uint8_t format;

	if (!l2cap_frame_get_u8((void *)frame, &format)) {
		print_text(COLOR_ERROR, "    Format: invalid size");
		goto done;
	}

	print_field("Format: %s (0x%2.2x)", att_format_str(format), format);

	switch (format) {
	case 0x01:
		att_find_info_rsp_16(frame);
		break;
	case 0x02:
		att_find_info_rsp_128(frame);
		break;
	}

done:
	if (frame->size)
		packet_hexdump(frame->data, frame->size);
}

static void att_find_by_type_val_req(const struct l2cap_frame *frame)
{
	uint16_t type;

	print_handle_range("Handle range", frame->data);

	type = get_le16(frame->data + 4);
	print_attribute_info(type, frame->data + 6, frame->size - 6);
}

static void att_find_by_type_val_rsp(const struct l2cap_frame *frame)
{
	const uint8_t *ptr = frame->data;
	uint16_t len = frame->size;

	while (len >= 4) {
		print_handle_range("Handle range", ptr);
		ptr += 4;
		len -= 4;
	}

	packet_hexdump(ptr, len);
}

static struct gatt_db_attribute *get_attribute(const struct l2cap_frame *frame,
						uint16_t handle, bool rsp)
{
	struct gatt_db *db;

	db = get_db(frame, rsp);
	if (!db)
		return NULL;

	return gatt_db_get_attribute(db, handle);
}

static void queue_read(const struct l2cap_frame *frame, bt_uuid_t *uuid,
					uint16_t handle)
{
	struct packet_conn_data *conn;
	struct att_conn_data *data;
	struct att_read *read;
	struct gatt_db_attribute *attr = NULL;
	const struct gatt_handler *handler;

	if (handle) {
		attr = get_attribute(frame, handle, false);
		if (!attr)
			return;
	}

	handler = attr ? get_handler(attr) : get_handler_uuid(uuid);

	conn = packet_get_conn_data(frame->handle);
	data = att_get_conn_data(conn);
	if (!data)
		return;

	if (!data->reads)
		data->reads = queue_new();

	read = new0(struct att_read, 1);
	read->conn = data;
	read->attr = attr;
	read->in = frame->in;
	read->chan = frame->chan;
	read->func = handler ? handler->read : NULL;

	queue_push_tail(data->reads, read);
}

static void att_read_type_req(const struct l2cap_frame *frame)
{
	bt_uuid_t uuid;

	print_handle_range("Handle range", frame->data);
	print_uuid("Attribute type", frame->data + 4, frame->size - 4);

	if (bt_uuid_from_data(&uuid, frame->data + 4, frame->size - 4))
		return;

	queue_read(frame, &uuid, 0x0000);
}

static void att_read_type_rsp(const struct l2cap_frame *frame)
{
	uint8_t len;

	if (!l2cap_frame_get_u8((void *)frame, &len)) {
		print_text(COLOR_ERROR, "invalid size");
		return;
	}

	print_field("Attribute data length: %d", len);
	print_data_list("Attribute data list", len, frame);
}

static void print_handle(const struct l2cap_frame *frame, uint16_t handle,
								bool rsp)
{
	struct gatt_db_attribute *attr;

	attr = get_attribute(frame, handle, rsp);
	if (!attr) {
		print_field("Handle: 0x%4.4x", handle);
		return;
	}

	print_attribute(attr);
}

static void att_read_req(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_att_read_req *pdu = frame->data;
	uint16_t handle;

	l2cap_frame_pull((void *)frame, frame, sizeof(*pdu));

	handle = le16_to_cpu(pdu->handle);
	print_handle(frame, handle, false);

	queue_read(frame, NULL, handle);
}

static void att_read_append(struct att_read *read,
				const struct l2cap_frame *frame)
{
	if (!read->iov)
		read->iov = new0(struct iovec, 1);
	util_iov_append(read->iov, frame->data, frame->size);
}

static void att_read_func(struct att_read *read,
				const struct l2cap_frame *frame)
{
	att_read_append(read, frame);

	print_attribute(read->attr);
	print_hex_field("Value", read->iov->iov_base, read->iov->iov_len);

	if (read->func) {
		struct l2cap_frame f = *frame;

		f.data = read->iov->iov_base;
		f.size = read->iov->iov_len;

		read->func(&f);
	}

	att_read_free(read);
}

static void att_read_rsp(const struct l2cap_frame *frame)
{
	struct att_read *read;

	print_hex_field("Value", frame->data, frame->size);

	read = att_get_read(frame);
	if (!read)
		return;

	/* Check if the data size is equal to the MTU then read long procedure
	 * maybe used.
	 */
	if (frame->size == read->conn->mtu - 1) {
		att_read_append(read, frame);
		print_hex_field("Long Value", read->iov->iov_base,
					read->iov->iov_len);
		queue_push_head(read->conn->reads, read);
		return;
	}

	att_read_func(read, frame);
}

static void att_read_blob_req(const struct l2cap_frame *frame)
{
	uint16_t handle, offset;
	struct att_read *read;

	if (!l2cap_frame_get_le16((void *)frame, &handle)) {
		print_text(COLOR_ERROR, "invalid size");
		return;
	}

	if (!l2cap_frame_get_le16((void *)frame, &offset)) {
		print_text(COLOR_ERROR, "invalid size");
		return;
	}

	print_handle(frame, handle, false);
	print_field("Offset: 0x%4.4x", offset);

	read = att_get_read(frame);
	if (!read)
		return;

	/* Check if attribute handle and offset match so the read object shall
	 * be keeped.
	 */
	if (gatt_db_attribute_get_handle(read->attr) == handle &&
				offset == read->iov->iov_len) {
		queue_push_head(read->conn->reads, read);
		return;
	}

	att_read_func(read, frame);
}

static void att_read_blob_rsp(const struct l2cap_frame *frame)
{
	att_read_rsp(frame);
}

static void att_read_multiple_req(const struct l2cap_frame *frame)
{
	int i, count;

	count = frame->size / 2;

	for (i = 0; i < count; i++)
		print_handle(frame, get_le16(frame->data + (i * 2)), false);
}

static void att_read_group_type_req(const struct l2cap_frame *frame)
{
	bt_uuid_t uuid;

	print_handle_range("Handle range", frame->data);
	print_uuid("Attribute group type", frame->data + 4, frame->size - 4);

	if (bt_uuid_from_data(&uuid, frame->data + 4, frame->size - 4))
		return;

	queue_read(frame, &uuid, 0x0000);
}

static void print_group_list(const char *label, uint8_t length,
					const struct l2cap_frame *frame)
{
	struct att_read *read;
	uint8_t count;

	if (length == 0)
		return;

	read = att_get_read(frame);

	count = frame->size / length;

	print_field("%s: %u entr%s", label, count, count == 1 ? "y" : "ies");

	while (frame->size >= length) {
		print_handle_range("Handle range", frame->data);
		print_uuid("UUID", frame->data + 4, length - 4);

		if (read && read->func) {
			struct l2cap_frame f;

			l2cap_frame_clone_size(&f, frame, length);

			read->func(&f);
		}

		if (!l2cap_frame_pull((void *)frame, frame, length))
			break;
	}

	packet_hexdump(frame->data, frame->size);
	att_read_free(read);
}

static void att_read_group_type_rsp(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_att_read_group_type_rsp *pdu = frame->data;

	l2cap_frame_pull((void *)frame, frame, sizeof(*pdu));

	print_field("Attribute data length: %d", pdu->length);
	print_group_list("Attribute group list", pdu->length, frame);
}

static void print_write(const struct l2cap_frame *frame, uint16_t handle,
							size_t len)
{
	struct gatt_db_attribute *attr;
	const struct gatt_handler *handler;

	print_handle(frame, handle, false);

	if (len > frame->size) {
		print_text(COLOR_ERROR, "invalid size");
		return;
	}

	print_hex_field("  Data", frame->data, len);

	attr = get_attribute(frame, handle, false);
	if (!attr)
		return;

	handler = get_handler(attr);
	if (!handler || !handler->write)
		return;

	handler->write(frame);
}

static void att_write_req(const struct l2cap_frame *frame)
{
	uint16_t handle;

	if (!l2cap_frame_get_le16((void *)frame, &handle)) {
		print_text(COLOR_ERROR, "invalid size");
		return;
	}

	print_write(frame, handle, frame->size);
}

static void att_write_rsp(const struct l2cap_frame *frame)
{
}

static void att_prepare_write_req(const struct l2cap_frame *frame)
{
	print_handle(frame, get_le16(frame->data), false);
	print_field("Offset: 0x%4.4x", get_le16(frame->data + 2));
	print_hex_field("  Data", frame->data + 4, frame->size - 4);
}

static void att_prepare_write_rsp(const struct l2cap_frame *frame)
{
	print_handle(frame, get_le16(frame->data), true);
	print_field("Offset: 0x%4.4x", get_le16(frame->data + 2));
	print_hex_field("  Data", frame->data + 4, frame->size - 4);
}

static void att_execute_write_req(const struct l2cap_frame *frame)
{
	uint8_t flags = *(uint8_t *) frame->data;
	const char *flags_str;

	switch (flags) {
	case 0x00:
		flags_str = "Cancel all prepared writes";
		break;
	case 0x01:
		flags_str = "Immediately write all pending values";
		break;
	default:
		flags_str = "Unknown";
		break;
	}

	print_field("Flags: %s (0x%02x)", flags_str, flags);
}

static void print_notify(const struct l2cap_frame *frame, uint16_t handle,
								size_t len)
{
	struct gatt_db_attribute *attr;
	const struct gatt_handler *handler;
	struct l2cap_frame clone;

	print_handle(frame, handle, true);
	print_hex_field("  Data", frame->data, len);

	if (len > frame->size) {
		print_text(COLOR_ERROR, "invalid size");
		return;
	}

	attr = get_attribute(frame, handle, true);
	if (!attr)
		return;

	handler = get_handler(attr);
	if (!handler)
		return;

	/* Use a clone if the callback is not expected to parse the whole
	 * frame.
	 */
	if (len != frame->size) {
		l2cap_frame_clone(&clone, frame);
		clone.size = len;
		frame = &clone;
	}

	if (handler->notify)
		handler->notify(frame);
}

static void att_handle_value_notify(const struct l2cap_frame *frame)
{
	uint16_t handle;
	const struct bt_l2cap_att_handle_value_notify *pdu = frame->data;

	l2cap_frame_pull((void *)frame, frame, sizeof(*pdu));

	handle = le16_to_cpu(pdu->handle);
	print_notify(frame, handle, frame->size);
}

static void att_handle_value_ind(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_att_handle_value_ind *pdu = frame->data;

	l2cap_frame_pull((void *)frame, frame, sizeof(*pdu));

	print_notify(frame, le16_to_cpu(pdu->handle), frame->size);
}

static void att_handle_value_conf(const struct l2cap_frame *frame)
{
}

static void att_multiple_vl_rsp(const struct l2cap_frame *frame)
{
	struct l2cap_frame *f = (void *) frame;

	while (frame->size) {
		uint16_t handle;
		uint16_t len;

		if (!l2cap_frame_get_le16(f, &handle))
			return;

		if (!l2cap_frame_get_le16(f, &len))
			return;

		print_field("Length: 0x%4.4x", len);

		print_notify(frame, handle, len);

		l2cap_frame_pull(f, f, len);
	}
}

static void att_write_command(const struct l2cap_frame *frame)
{
	uint16_t handle;

	if (!l2cap_frame_get_le16((void *)frame, &handle)) {
		print_text(COLOR_ERROR, "invalid size");
		return;
	}

	print_write(frame, handle, frame->size);
}

static void att_signed_write_command(const struct l2cap_frame *frame)
{
	uint16_t handle;

	if (!l2cap_frame_get_le16((void *)frame, &handle)) {
		print_text(COLOR_ERROR, "invalid size");
		return;
	}

	print_write(frame, handle, frame->size - 12);
	print_hex_field("  Signature", frame->data + frame->size - 12, 12);
}

struct att_opcode_data {
	uint8_t opcode;
	const char *str;
	void (*func) (const struct l2cap_frame *frame);
	uint8_t size;
	bool fixed;
};

static const struct att_opcode_data att_opcode_table[] = {
	{ 0x01, "Error Response",
			att_error_response, 4, true },
	{ 0x02, "Exchange MTU Request",
			att_exchange_mtu_req, 2, true },
	{ 0x03, "Exchange MTU Response",
			att_exchange_mtu_rsp, 2, true },
	{ 0x04, "Find Information Request",
			att_find_info_req, 4, true },
	{ 0x05, "Find Information Response",
			att_find_info_rsp, 5, false },
	{ 0x06, "Find By Type Value Request",
			att_find_by_type_val_req, 6, false },
	{ 0x07, "Find By Type Value Response",
			att_find_by_type_val_rsp, 4, false },
	{ 0x08, "Read By Type Request",
			att_read_type_req, 6, false },
	{ 0x09, "Read By Type Response",
			att_read_type_rsp, 3, false },
	{ 0x0a, "Read Request",
			att_read_req, 2, true },
	{ 0x0b, "Read Response",
			att_read_rsp, 0, false },
	{ 0x0c, "Read Blob Request",
			att_read_blob_req, 4, true },
	{ 0x0d, "Read Blob Response",
			att_read_blob_rsp, 0, false },
	{ 0x0e, "Read Multiple Request",
			att_read_multiple_req, 4, false },
	{ 0x0f, "Read Multiple Response"	},
	{ 0x10, "Read By Group Type Request",
			att_read_group_type_req, 6, false },
	{ 0x11, "Read By Group Type Response",
			att_read_group_type_rsp, 4, false },
	{ 0x12, "Write Request"	,
			att_write_req, 2, false	},
	{ 0x13, "Write Response",
			att_write_rsp, 0, true	},
	{ 0x16, "Prepare Write Request",
			att_prepare_write_req, 4, false },
	{ 0x17, "Prepare Write Response",
			att_prepare_write_rsp, 4, false },
	{ 0x18, "Execute Write Request",
			att_execute_write_req, 1, true },
	{ 0x19, "Execute Write Response"	},
	{ 0x1b, "Handle Value Notification",
			att_handle_value_notify, 2, false },
	{ 0x1d, "Handle Value Indication",
			att_handle_value_ind, 2, false },
	{ 0x1e, "Handle Value Confirmation",
			att_handle_value_conf, 0, true },
	{ 0x20, "Read Multiple Request Variable Length",
			att_read_multiple_req, 4, false },
	{ 0x21, "Read Multiple Response Variable Length",
			att_multiple_vl_rsp, 4, false },
	{ 0x23, "Handle Multiple Value Notification",
			att_multiple_vl_rsp, 4, false },
	{ 0x52, "Write Command",
			att_write_command, 2, false },
	{ 0xd2, "Signed Write Command", att_signed_write_command, 14, false },
	{ }
};

static const char *att_opcode_to_str(uint8_t opcode)
{
	int i;

	for (i = 0; att_opcode_table[i].str; i++) {
		if (att_opcode_table[i].opcode == opcode)
			return att_opcode_table[i].str;
	}

	return "Unknown";
}

void att_packet(uint16_t index, bool in, uint16_t handle, uint16_t cid,
					const void *data, uint16_t size)
{
	struct l2cap_frame frame;
	uint8_t opcode = *((const uint8_t *) data);
	const struct att_opcode_data *opcode_data = NULL;
	const char *opcode_color, *opcode_str;
	int i;

	if (size < 1) {
		print_text(COLOR_ERROR, "malformed attribute packet");
		packet_hexdump(data, size);
		return;
	}

	for (i = 0; att_opcode_table[i].str; i++) {
		if (att_opcode_table[i].opcode == opcode) {
			opcode_data = &att_opcode_table[i];
			break;
		}
	}

	if (opcode_data) {
		if (opcode_data->func) {
			if (in)
				opcode_color = COLOR_MAGENTA;
			else
				opcode_color = COLOR_BLUE;
		} else
			opcode_color = COLOR_WHITE_BG;
		opcode_str = opcode_data->str;
	} else {
		opcode_color = COLOR_WHITE_BG;
		opcode_str = "Unknown";
	}

	print_indent(6, opcode_color, "ATT: ", opcode_str, COLOR_OFF,
				" (0x%2.2x) len %d", opcode, size - 1);

	if (!opcode_data || !opcode_data->func) {
		packet_hexdump(data + 1, size - 1);
		return;
	}

	if (opcode_data->fixed) {
		if (size - 1 != opcode_data->size) {
			print_text(COLOR_ERROR, "invalid size");
			packet_hexdump(data + 1, size - 1);
			return;
		}
	} else {
		if (size - 1 < opcode_data->size) {
			print_text(COLOR_ERROR, "too short packet");
			packet_hexdump(data + 1, size - 1);
			return;
		}
	}

	l2cap_frame_init(&frame, index, in, handle, 0, cid, 0,
						data + 1, size - 1);
	opcode_data->func(&frame);
}
