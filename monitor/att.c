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
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>
#include <linux/limits.h>
#include <sys/stat.h>

#include <glib.h>

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

struct att_read {
	struct gatt_db_attribute *attr;
	bool in;
	uint16_t chan;
	void (*func)(const struct l2cap_frame *frame);
};

struct att_conn_data {
	struct gatt_db *ldb;
	struct timespec ldb_mtim;
	struct gatt_db *rdb;
	struct timespec rdb_mtim;
	struct queue *reads;
};

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

static void print_data_list(const char *label, uint8_t length,
					const struct l2cap_frame *frame)
{
	struct packet_conn_data *conn;
	struct att_conn_data *data;
	struct att_read *read;
	uint8_t count;

	if (length == 0)
		return;

	conn = packet_get_conn_data(frame->handle);
	if (conn) {
		data = conn->data;
		if (data)
			read = queue_remove_if(data->reads, match_read_frame,
						(void *)frame);
		else
			read = NULL;
	} else
		read = NULL;

	count = frame->size / length;

	print_field("%s: %u entr%s", label, count, count == 1 ? "y" : "ies");

	while (frame->size >= length) {
		if (!l2cap_frame_print_le16((void *)frame, "Handle"))
			break;

		print_hex_field("Value", frame->data, length - 2);

		if (read) {
			struct l2cap_frame f;

			l2cap_frame_clone_size(&f, frame, length - 2);

			read->func(&f);
		}

		if (!l2cap_frame_pull((void *)frame, frame, length - 2))
			break;
	}

	packet_hexdump(frame->data, frame->size);
	free(read);
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

static void print_chrc(const struct l2cap_frame *frame)
{
	uint8_t prop;
	uint8_t mask;

	if (!l2cap_frame_get_u8((void *)frame, &prop)) {
		print_text(COLOR_ERROR, "Property: invalid size");
		return;
	}

	print_field("    Properties: 0x%2.2x", prop);

	mask = print_bitfield(6, prop, chrc_prop_table);
	if (mask)
		print_text(COLOR_WHITE_BG, "    Unknown fields (0x%2.2x)",
								mask);

	if (!l2cap_frame_print_le16((void *)frame, "    Value Handle"))
		return;

	print_uuid("    Value UUID", frame->data, frame->size);
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

static bool print_ase_lv(const struct l2cap_frame *frame, const char *label,
			struct packet_ltv_decoder *decoder, size_t decoder_len)
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

	packet_print_ltv(label, lv->data, lv->len, decoder, decoder_len);

	return true;
}

static bool print_ase_cc(const struct l2cap_frame *frame, const char *label,
			struct packet_ltv_decoder *decoder, size_t decoder_len)
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

static void ase_decode_preferred_context(const uint8_t *data, uint8_t len)
{
	struct l2cap_frame frame;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	print_context(&frame, "      Preferred Context");
}

static void ase_decode_context(const uint8_t *data, uint8_t len)
{
	struct l2cap_frame frame;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	print_context(&frame, "      Context");
}

static void ase_decode_program_info(const uint8_t *data, uint8_t len)
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

static void ase_decode_language(const uint8_t *data, uint8_t len)
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

struct packet_ltv_decoder ase_metadata_table[] = {
	LTV_DEC(0x01, ase_decode_preferred_context),
	LTV_DEC(0x02, ase_decode_context),
	LTV_DEC(0x03, ase_decode_program_info),
	LTV_DEC(0x04, ase_decode_language)
};

static bool print_ase_metadata(const struct l2cap_frame *frame)
{
	return print_ase_lv(frame, "    Metadata", NULL, 0);
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

static void pac_decode_freq(const uint8_t *data, uint8_t len)
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

static void pac_decode_duration(const uint8_t *data, uint8_t len)
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

static void pac_decode_channels(const uint8_t *data, uint8_t len)
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

static void pac_decode_frame_length(const uint8_t *data, uint8_t len)
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

static void pac_decode_sdu(const uint8_t *data, uint8_t len)
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

struct packet_ltv_decoder pac_cap_table[] = {
	LTV_DEC(0x01, pac_decode_freq),
	LTV_DEC(0x02, pac_decode_duration),
	LTV_DEC(0x03, pac_decode_channels),
	LTV_DEC(0x04, pac_decode_frame_length),
	LTV_DEC(0x05, pac_decode_sdu)
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
	{  0, "LE 1M PHY preffered (0x01)"		},
	{  1, "LE 2M PHY preffered (0x02)"		},
	{  2, "LE Codec PHY preffered (0x04)"		},
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

static void ase_decode_freq(const uint8_t *data, uint8_t len)
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
		print_field("      Sampling Frequency: 24 Khz (0x04)");
		break;
	case 0x06:
		print_field("      Sampling Frequency: 32 Khz (0x04)");
		break;
	case 0x07:
		print_field("      Sampling Frequency: 44.1 Khz (0x04)");
		break;
	case 0x08:
		print_field("      Sampling Frequency: 48 Khz (0x04)");
		break;
	case 0x09:
		print_field("      Sampling Frequency: 88.2 Khz (0x04)");
		break;
	case 0x0a:
		print_field("      Sampling Frequency: 96 Khz (0x04)");
		break;
	case 0x0b:
		print_field("      Sampling Frequency: 176.4 Khz (0x04)");
		break;
	case 0x0c:
		print_field("      Sampling Frequency: 192 Khz (0x04)");
		break;
	case 0x0d:
		print_field("      Sampling Frequency: 384 Khz (0x04)");
		break;
	default:
		print_field("      Sampling Frequency: RFU (0x%2.2x)", value);
		break;
	}

done:
	if (frame.size)
		print_hex_field("    Data", frame.data, frame.size);
}

static void ase_decode_duration(const uint8_t *data, uint8_t len)
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

static void ase_decode_location(const uint8_t *data, uint8_t len)
{
	struct l2cap_frame frame;

	l2cap_frame_init(&frame, 0, 0, 0, 0, 0, 0, data, len);

	print_location(&frame);
}

static void ase_decode_frame_length(const uint8_t *data, uint8_t len)
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

static void ase_decode_blocks(const uint8_t *data, uint8_t len)
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

struct packet_ltv_decoder ase_cc_table[] = {
	LTV_DEC(0x01, ase_decode_freq),
	LTV_DEC(0x02, ase_decode_duration),
	LTV_DEC(0x03, ase_decode_location),
	LTV_DEC(0x04, ase_decode_frame_length),
	LTV_DEC(0x05, ase_decode_blocks)
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

struct ase_cmd {
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

static struct ase_cmd *ase_get_cmd(uint8_t op)
{
	if (op > ARRAY_SIZE(ase_cmd_table))
		return NULL;

	return &ase_cmd_table[op];
}

static void print_ase_cmd(const struct l2cap_frame *frame)
{
	uint8_t op, num, i;
	struct ase_cmd *cmd;

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
	struct ase_cmd *cmd;

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

struct vcs_cmd {
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

static struct vcs_cmd *vcs_get_cmd(uint8_t op)
{
	if (op > ARRAY_SIZE(vcs_cmd_table))
		return NULL;

	return &vcs_cmd_table[op];
}

static void print_vcs_cmd(const struct l2cap_frame *frame)
{
	uint8_t op;
	struct vcs_cmd *cmd;

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
	print_field("    Volume Falg: %u", vol_flag);

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

struct media_cp_opcode {
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

struct gatt_handler {
	bt_uuid_t uuid;
	void (*read)(const struct l2cap_frame *frame);
	void (*write)(const struct l2cap_frame *frame);
	void (*notify)(const struct l2cap_frame *frame);
} gatt_handlers[] = {
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
};

static struct gatt_handler *get_handler_uuid(const bt_uuid_t *uuid)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(gatt_handlers); i++) {
		struct gatt_handler *handler = &gatt_handlers[i];

		if (!bt_uuid_cmp(&handler->uuid, uuid))
			return handler;
	}

	return NULL;
}

static struct gatt_handler *get_handler(struct gatt_db_attribute *attr)
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

static int bt_uuid_from_data(bt_uuid_t *uuid, const void *data, uint16_t size)
{
	uint128_t u128;

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

static void att_conn_data_free(void *data)
{
	struct att_conn_data *att_data = data;

	gatt_db_unref(att_data->rdb);
	gatt_db_unref(att_data->ldb);
	queue_destroy(att_data->reads, free);
	free(att_data);
}

static struct att_conn_data *att_get_conn_data(struct packet_conn_data *conn)
{
	struct att_conn_data *data = conn->data;

	if (data)
		return data;

	data = new0(struct att_conn_data, 1);
	data->rdb = gatt_db_new();
	data->ldb = gatt_db_new();
	conn->data = data;
	conn->destroy = att_conn_data_free;

	return data;
}

static void att_read_type_req(const struct l2cap_frame *frame)
{
	bt_uuid_t uuid;
	struct packet_conn_data *conn;
	struct att_conn_data *data;
	struct att_read *read;
	struct gatt_handler *handler;

	print_handle_range("Handle range", frame->data);
	print_uuid("Attribute type", frame->data + 4, frame->size - 4);

	if (bt_uuid_from_data(&uuid, frame->data + 4, frame->size - 4))
		return;

	handler = get_handler_uuid(&uuid);
	if (!handler || !handler->read)
		return;

	conn = packet_get_conn_data(frame->handle);
	data = att_get_conn_data(conn);

	if (!data->reads)
		data->reads = queue_new();

	read = new0(struct att_read, 1);
	read->in = frame->in;
	read->chan = frame->chan;
	read->func = handler->read;

	queue_push_tail(data->reads, read);
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

	ba2str((bdaddr_t *)conn->src, local);
	ba2str((bdaddr_t *)conn->dst, peer);

	create_filename(filename, PATH_MAX, "/%s/attributes", local);
	gatt_load_db(data->ldb, filename, &data->ldb_mtim);

	create_filename(filename, PATH_MAX, "/%s/cache/%s", local, peer);
	gatt_load_db(data->rdb, filename, &data->rdb_mtim);
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

	return gatt_db_get_attribute(db, handle);
}

static void print_attribute(struct gatt_db_attribute *attr)
{
	uint16_t handle = gatt_db_attribute_get_handle(attr);
	const bt_uuid_t *uuid;
	char label[21];

	uuid = gatt_db_attribute_get_type(attr);
	if (!uuid)
		goto done;

	switch (uuid->type) {
	case BT_UUID16:
		sprintf(label, "Handle: 0x%4.4x Type", handle);
		print_field("%s: %s (0x%4.4x)", label,
				bt_uuid16_to_str(uuid->value.u16),
				uuid->value.u16);
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
	struct packet_conn_data *conn;
	struct att_conn_data *data;
	struct att_read *read;
	struct gatt_db_attribute *attr;
	struct gatt_handler *handler;

	l2cap_frame_pull((void *)frame, frame, sizeof(*pdu));

	handle = le16_to_cpu(pdu->handle);
	print_handle(frame, handle, false);

	attr = get_attribute(frame, handle, false);
	if (!attr)
		return;

	handler = get_handler(attr);
	if (!handler || !handler->read)
		return;

	conn = packet_get_conn_data(frame->handle);
	data = conn->data;

	if (!data->reads)
		data->reads = queue_new();

	read = new0(struct att_read, 1);
	read->attr = attr;
	read->in = frame->in;
	read->chan = frame->chan;
	read->func = handler->read;

	queue_push_tail(data->reads, read);
}

static void att_read_rsp(const struct l2cap_frame *frame)
{
	struct packet_conn_data *conn;
	struct att_conn_data *data;
	struct att_read *read;

	print_hex_field("Value", frame->data, frame->size);

	conn = packet_get_conn_data(frame->handle);
	if (!conn)
		return;

	data = conn->data;

	read = queue_remove_if(data->reads, match_read_frame, (void *)frame);
	if (!read)
		return;

	print_attribute(read->attr);

	read->func(frame);

	free(read);
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

static void print_write(const struct l2cap_frame *frame, uint16_t handle,
							size_t len)
{
	struct gatt_db_attribute *attr;
	struct gatt_handler *handler;

	print_handle(frame, handle, false);
	print_hex_field("  Data", frame->data, frame->size);

	if (len > frame->size) {
		print_text(COLOR_ERROR, "invalid size");
		return;
	}

	attr = get_attribute(frame, handle, false);
	if (!attr)
		return;

	handler = get_handler(attr);
	if (!handler)
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
	struct gatt_handler *handler;
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
	print_hex_field("  Data", frame->data, frame->size - 12);
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
