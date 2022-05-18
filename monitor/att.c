// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>
#include <linux/limits.h>

#include "lib/bluetooth.h"
#include "lib/uuid.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"

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

static void print_data_list(const char *label, uint8_t length,
					const void *data, uint16_t size)
{
	uint8_t count;

	if (length == 0)
		return;

	count = size / length;

	print_field("%s: %u entr%s", label, count, count == 1 ? "y" : "ies");

	while (size >= length) {
		print_field("Handle: 0x%4.4x", get_le16(data));
		print_hex_field("Value", data + 2, length - 2);

		data += length;
		size -= length;
	}

	packet_hexdump(data, size);
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
}

static void att_exchange_mtu_req(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_att_exchange_mtu_req *pdu = frame->data;

	print_field("Client RX MTU: %d", le16_to_cpu(pdu->mtu));
}

static void att_exchange_mtu_rsp(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_att_exchange_mtu_rsp *pdu = frame->data;

	print_field("Server RX MTU: %d", le16_to_cpu(pdu->mtu));
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

static uint16_t print_info_data_16(const void *data, uint16_t len)
{
	while (len >= 4) {
		print_field("Handle: 0x%4.4x", get_le16(data));
		print_uuid("UUID", data + 2, 2);
		data += 4;
		len -= 4;
	}

	return len;
}

static uint16_t print_info_data_128(const void *data, uint16_t len)
{
	while (len >= 18) {
		print_field("Handle: 0x%4.4x", get_le16(data));
		print_uuid("UUID", data + 2, 16);
		data += 18;
		len -= 18;
	}

	return len;
}

static void att_find_info_rsp(const struct l2cap_frame *frame)
{
	const uint8_t *format = frame->data;
	uint16_t len;

	print_field("Format: %s (0x%2.2x)", att_format_str(*format), *format);

	if (*format == 0x01)
		len = print_info_data_16(frame->data + 1, frame->size - 1);
	else if (*format == 0x02)
		len = print_info_data_128(frame->data + 1, frame->size - 1);
	else
		len = frame->size - 1;

	packet_hexdump(frame->data + (frame->size - len), len);
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

static void att_read_type_req(const struct l2cap_frame *frame)
{
	print_handle_range("Handle range", frame->data);
	print_uuid("Attribute type", frame->data + 4, frame->size - 4);
}

static void att_read_type_rsp(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_att_read_group_type_rsp *pdu = frame->data;

	print_field("Attribute data length: %d", pdu->length);
	print_data_list("Attribute data list", pdu->length,
					frame->data + 1, frame->size - 1);
}

struct att_conn_data {
	struct gatt_db *ldb;
	struct gatt_db *rdb;
};

static void att_conn_data_free(void *data)
{
	struct att_conn_data *att_data = data;

	gatt_db_unref(att_data->rdb);
	gatt_db_unref(att_data->ldb);
	free(att_data);
}

static void load_gatt_db(struct packet_conn_data *conn)
{
	struct att_conn_data *data;
	char filename[PATH_MAX];
	bdaddr_t src;
	char local[18];
	char peer[18];

	if (hci_devba(conn->index, &src) < 0)
		return;

	data = new0(struct att_conn_data, 1);
	data->rdb = gatt_db_new();
	data->ldb = gatt_db_new();
	conn->data = data;
	conn->destroy = att_conn_data_free;

	ba2str(&src, local);

	create_filename(filename, PATH_MAX, "/%s/attributes", local);

	btd_settings_gatt_db_load(data->ldb, filename);

	ba2str((bdaddr_t *)conn->dst, peer);

	create_filename(filename, PATH_MAX, "/%s/cache/%s", local, peer);

	btd_settings_gatt_db_load(data->rdb, filename);
}

static struct gatt_db_attribute *get_attribute(const struct l2cap_frame *frame,
						uint16_t handle, bool rsp)
{
	struct packet_conn_data *conn;
	struct att_conn_data *data;
	struct gatt_db *db;

	conn = packet_get_conn_data(frame->handle);
	if (!conn)
		return NULL;

	data = conn->data;
	/* Try loading local and remote gatt_db if not loaded yet */
	if (!data) {
		load_gatt_db(conn);
		data = conn->data;
		if (!data)
			return NULL;
	}

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

	return gatt_db_get_attribute(db, handle);
}

static void print_handle(const struct l2cap_frame *frame, uint16_t handle,
								bool rsp)
{
	struct gatt_db_attribute *attr;
	const bt_uuid_t *uuid;
	char label[21];

	attr = get_attribute(frame, handle, rsp);
	if (!attr)
		goto done;

	uuid = gatt_db_attribute_get_type(attr);
	if (!uuid)
		goto done;

	switch (uuid->type) {
	case BT_UUID16:
		sprintf(label, "Handle: 0x%4.4x Type", handle);
		print_uuid(label, &cpu_to_le16(uuid->value.u16), 2);
		return;
	case BT_UUID128:
		sprintf(label, "Handle: 0x%4.4x Type", handle);
		print_uuid(label, &uuid->value.u128, 16);
		return;
	case BT_UUID_UNSPEC:
	case BT_UUID32:
		break;
	}

done:
	print_field("Handle: 0x%4.4x", handle);
}

static void att_read_req(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_att_read_req *pdu = frame->data;

	print_handle(frame, le16_to_cpu(pdu->handle), false);
}

static void att_read_rsp(const struct l2cap_frame *frame)
{
	print_hex_field("Value", frame->data, frame->size);
}

static void att_read_blob_req(const struct l2cap_frame *frame)
{
	print_handle(frame, get_le16(frame->data), false);
	print_field("Offset: 0x%4.4x", get_le16(frame->data + 2));
}

static void att_read_blob_rsp(const struct l2cap_frame *frame)
{
	packet_hexdump(frame->data, frame->size);
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
	print_handle_range("Handle range", frame->data);
	print_uuid("Attribute group type", frame->data + 4, frame->size - 4);
}

static void print_group_list(const char *label, uint8_t length,
					const void *data, uint16_t size)
{
	uint8_t count;

	if (length == 0)
		return;

	count = size / length;

	print_field("%s: %u entr%s", label, count, count == 1 ? "y" : "ies");

	while (size >= length) {
		print_handle_range("Handle range", data);
		print_uuid("UUID", data + 4, length - 4);

		data += length;
		size -= length;
	}

	packet_hexdump(data, size);
}

static void att_read_group_type_rsp(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_att_read_group_type_rsp *pdu = frame->data;

	print_field("Attribute data length: %d", pdu->length);
	print_group_list("Attribute group list", pdu->length,
					frame->data + 1, frame->size - 1);
}

static void att_write_req(const struct l2cap_frame *frame)
{
	print_handle(frame, get_le16(frame->data), false);
	print_hex_field("  Data", frame->data + 2, frame->size - 2);
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

static void att_handle_value_notify(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_att_handle_value_notify *pdu = frame->data;

	print_handle(frame, le16_to_cpu(pdu->handle), true);
	print_hex_field("  Data", frame->data + 2, frame->size - 2);
}

static void att_handle_value_ind(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_att_handle_value_ind *pdu = frame->data;

	print_handle(frame, le16_to_cpu(pdu->handle), true);
	print_hex_field("  Data", frame->data + 2, frame->size - 2);
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

		print_handle(frame, get_le16(frame->data), true);

		if (!l2cap_frame_get_le16(f, &len))
			return;

		print_field("Length: 0x%4.4x", len);

		print_hex_field("  Data", f->data,
				len < f->size ? len : f->size);

		if (len > f->size) {
			print_text(COLOR_ERROR, "invalid size");
			return;
		}

		l2cap_frame_pull(f, f, len);
	}
}

static void att_write_command(const struct l2cap_frame *frame)
{
	print_handle(frame, get_le16(frame->data), false);
	print_hex_field("  Data", frame->data + 2, frame->size - 2);
}

static void att_signed_write_command(const struct l2cap_frame *frame)
{
	print_handle(frame, get_le16(frame->data), false);
	print_hex_field("  Data", frame->data + 2, frame->size - 2 - 12);
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
