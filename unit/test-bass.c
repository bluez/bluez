// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright 2023 NXP
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"
#include "src/shared/util.h"
#include "src/shared/io.h"
#include "src/shared/tester.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gatt-server.h"
#include "src/shared/bass.h"

struct test_data {
	struct gatt_db *db;
	struct bt_bass *bass;
	struct bt_gatt_server *server;
	struct queue *ccc_states;
	size_t iovcnt;
	struct iovec *iov;
};

struct ccc_state {
	uint16_t handle;
	uint16_t value;
};

/* ATT: Exchange MTU Request (0x02) len 2
 *   Client RX MTU: 64
 * ATT: Exchange MTU Response (0x03) len 2
 *   Server RX MTU: 64
 */
#define EXCHANGE_MTU \
	IOV_DATA(0x02, 0x40, 0x00), \
	IOV_DATA(0x03, 0x40, 0x00)

/* ATT: Find By Type Value Request (0x06) len 8
 *   Handle range: 0x0001-0xffff
 *   Attribute Type(UUID): Primary Service (0x2800)
 *   Value to find: Broadcast Audio Scan Service (0x184f)
 * ATT: Find By Type Value Response (0x07) len 4
 *   Handle range: 0x0001-0x0009
 * ATT: Find By Type Value Request (0x06) len 8
 *   Handle range: 0x000a-0xffff
 *   Attribute Type(UUID): Primary Service (0x2800)
 *   Value to find: Broadcast Audio Scan Service (0x184f)
 * ATT: Error Response (0x01) len 4
 *   Find By Type Value Request (0x06)
 *   Handle: 0x000a
 *   Error: Attribute Not Found (0x0a)
 */
#define BASS_FIND_BY_TYPE_VALUE \
	IOV_DATA(0x06, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28, 0x4f, 0x18), \
	IOV_DATA(0x07, 0x01, 0x00, 0x09, 0x00), \
	IOV_DATA(0x06, 0x0a, 0x00, 0xff, 0xff, 0x00, 0x28, 0x4f, 0x18), \
	IOV_DATA(0x01, 0x06, 0x0a, 0x00, 0x0a)

/* ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0001-0x0009
 *   Attribute type: Characteristic (0x2803)
 * ATT: Read By Type Response (0x09) len 22
 * Attribute data length: 7
 * Attribute data list: 3 entries
 *   Handle: 0x0002
 *   Value: 120300c82b
 *   Properties: 0x12
 *     Read (0x02)
 *     Notify (0x10)
 *   Value Handle: 0x0003
 *   Value UUID: Broadcast Receive State (0x2bc8)
 *   Handle: 0x0005
 *   Value: 120600c82b
 *   Properties: 0x12
 *     Read (0x02)
 *     Notify (0x10)
 *   Value Handle: 0x0006
 *   Value UUID: Broadcast Receive State (0x2bc8)
 *   Handle: 0x0008
 *   Value: 0c0900c72b
 *   Properties: 0x0c
 *     Write (0x08)
 *     Write Without Response (0x04)
 *   Value Handle: 0x0009
 *   Value UUID: Broadcast Audio Scan Control Point (0x2bc7)
 * ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0009-0x0009
 *   Attribute type: Characteristic (0x2803)
 * ATT: Error Response (0x01) len 4
 *   Read By Type Request (0x08)
 *   Handle: 0x0009
 *   Error: Attribute Not Found (0x0a)
 */
#define DISC_BASS_CHAR \
	IOV_DATA(0x08, 0x01, 0x00, 0x09, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		0x02, 0x00, 0x12, 0x03, 0x00, 0xc8, 0x2b, \
		0x05, 0x00, 0x12, 0x06, 0x00, 0xc8, 0x2b, \
		0x08, 0x00, 0x0c, 0x09, 0x00, 0xc7, 0x2b), \
	IOV_DATA(0x08, 0x09, 0x00, 0x09, 0x00, 0x03, 0x28), \
	IOV_DATA(0x01, 0x08, 0x09, 0x00, 0x0a)

/* ATT: Read By Group Type Request (0x10) len 6
 *   Handle range: 0x0001-0xffff
 *   Attribute group type: Primary Service (0x2800)
 * ATT: Read By Group Type Response (0x11) len 7
 *   Attribute data length: 6
 *   Attribute group list: 1 entry
 *   Handle range: 0x0001-0x0009
 *   UUID: Broadcast Audio Scan Service (0x184f)
 * ATT: Read By Group Type Request (0x10) len 6
 *   Handle range: 0x000a-0xffff
 *   Attribute group type: Primary Service (0x2800)
 * ATT: Error Response (0x01) len 4
 *   Read By Group Type Request (0x10)
 *   Handle: 0x000a
 *   Error: Attribute Not Found (0x0a)
 */
#define DISC_BASS_SER \
	EXCHANGE_MTU,\
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28), \
	IOV_DATA(0x11, 0x06, 0x01, 0x00, 0x09, 0x00, 0x4f, 0x18), \
	IOV_DATA(0x10, 0x0a, 0x00, 0xff, 0xff, 0x00, 0x28), \
	IOV_DATA(0x01, 0x10, 0x0a, 0x00, 0x0a), \
	BASS_FIND_BY_TYPE_VALUE, \
	DISC_BASS_CHAR

/* ATT: Find Information Request (0x04) len 4
 *   Handle range: 0x0004-0x0004
 * ATT: Find Information Response (0x05) len 5
 *   Format: Handle(s) and 16 bit bluetooth UUID(s) (0x01)
 *   Handle: 0x0004
 *   Attribute: Client Characteristic Configuration (0x2902)
 * ATT: Find Information Request (0x04) len 4
 *   Handle range: 0x0007-0x0007
 * ATT: Find Information Response (0x05) len 5
 *   Format: Handle(s) and 16 bit bluetooth UUID(s) (0x01)
 *   Handle: 0x0007
 *   Attribute: Client Characteristic Configuration (0x2902)
 */
#define BASS_FIND_INFO \
	IOV_DATA(0x04, 0x04, 0x00, 0x04, 0x00), \
	IOV_DATA(0x05, 0x01, 0x04, 0x00, 0x02, 0x29), \
	IOV_DATA(0x04, 0x07, 0x00, 0x07, 0x00), \
	IOV_DATA(0x05, 0x01, 0x07, 0x00, 0x02, 0x29)

#define DISC_BCAST_AUDIO_SCAN_CP \
	BASS_FIND_BY_TYPE_VALUE, \
	DISC_BASS_CHAR, \
	BASS_FIND_INFO

/* ATT: Read Request (0x0a) len 2
 *   Handle: 0x0004 Type: Client Characteristic Configuration (0x2902)
 * ATT: Read Response (0x0b) len 2
 *   Value: 0000
 *   Handle: 0x0004 Type: Client Characteristic Configuration (0x2902)
 * ATT: Read Request (0x0a) len 2
 *   Handle: 0x0007 Type: Client Characteristic Configuration (0x2902)
 * ATT: Read Response (0x0b) len 2
 *   Value: 0000
 *   Handle: 0x0007 Type: Client Characteristic Configuration (0x2902)
 */
#define BASS_READ_CHAR_DESC \
	IOV_DATA(0x0a, 0x04, 0x00), \
	IOV_DATA(0x0b, 0x00, 0x00), \
	IOV_DATA(0x0a, 0x07, 0x00), \
	IOV_DATA(0x0b, 0x00, 0x00)

#define DISC_BCAST_RECV_STATE \
	DISC_BCAST_AUDIO_SCAN_CP, \
	BASS_READ_CHAR_DESC

/* ATT: Write Request (0x12) len 4
 *   Handle: 0x0004 Type: Client Characteristic Configuration (0x2902)
 *     Data: 0100
 *       Notification (0x01)
 * ATT: Write Response (0x13) len 0
 * ATT: Write Request (0x12) len 4
 *   Handle: 0x0007 Type: Client Characteristic Configuration (0x2902)
 *     Data: 0100
 *       Notification (0x01)
 * ATT: Write Response (0x13) len 0
 */
#define BASS_WRITE_CHAR_DESC \
	IOV_DATA(0x12, 0x04, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13), \
	IOV_DATA(0x12, 0x07, 0x00, 0x01, 0x00), \
	IOV_DATA(0x13)

/* ATT: Read Request (0x0a) len 2
 *   Handle: 0x0003 Type: Broadcast Receive State (0x2bc8)
 * ATT: Read Response (0x0b) len 0
 *   Handle: 0x0003 Broadcast Receive State (0x2bc8)
 * ATT: Read Request (0x0a) len 2
 *   Handle: 0x0006 Type: Broadcast Receive State (0x2bc8)
 * ATT: Read Response (0x0b) len 0
 *   Handle: 0x0006 Broadcast Receive State (0x2bc8)
 */
#define BASS_READ_BCAST_RECV_STATE_CHARS \
	IOV_DATA(0x0a, 0x03, 0x00), \
	IOV_DATA(0x0b), \
	IOV_DATA(0x0a, 0x06, 0x00), \
	IOV_DATA(0x0b)

#define BASS_CP_WRITE_CMD(_op, _args...) \
	IOV_DATA(0x52, 0x09, 0x00, _op, _args)

#define BASS_CP_WRITE_REQ(_op, _args...) \
	IOV_DATA(0x12, 0x09, 0x00, _op, _args)

/* ATT: Write Command (0x52) len 19
 *   Handle: 0x0009 Type: Broadcast Audio Scan Control Point (0x2bc7)
 *     Data: 0401693C4572685526613465597073275455
 *       Opcode: Set Broadcast_Code
 *       Source_ID: 1
 *       Broadcast_Code: 0x55542773705965346126556872453c69
 * ATT: Write Command (0x52) len 2
 *   Handle: 0x0009 Type: Broadcast Audio Scan Control Point (0x2bc7)
 *     Data: 0501
 *       Opcode: Remove Source
 *       Source_ID: 1
 */
#define IGNORE_INVALID_SRC_ID \
	EXCHANGE_MTU, \
	BASS_FIND_BY_TYPE_VALUE, \
	DISC_BASS_CHAR, \
	BASS_FIND_INFO, \
	BASS_WRITE_CHAR_DESC, \
	BASS_READ_BCAST_RECV_STATE_CHARS, \
	BASS_CP_WRITE_CMD(0x04, 0x01, 0x69, 0x3C, 0x45, 0x72, 0x68, \
			0x55, 0x26, 0x61, 0x34, 0x65, 0x59, 0x70, \
			0x73, 0x27, 0x54, 0x55), \
	IOV_NULL, \
	BASS_CP_WRITE_CMD(0x05, 0x01)

/* ATT: Write Command (0x52) len 26
 *   Handle: 0x0009 Type: Broadcast Audio Scan Control Point (0x2bc7)
 *     Data: 0200F2698BE807C0003412000610270200000000000000000000
 *       Opcode: Add Source
 *       Advertiser_Address_Type: Public Device or Public Identity Address
 *       Advertiser_Address: c0:07:e8:8b:69:f2
 *       Advertising_SID: 0x00
 *       Broadcast_ID: 0x001234
 *       PA_Sync: 0x06 (Reserved for Future Use)
 *       PA_Interval: 0x2710
 *       Num_Subgroups: 2
 *         Subgroup #0:
 *           BIS_Sync: 00000000000000000000000000000000
 *           Metadata_Length: 0
 *         Subgroup #1:
 *           BIS_Sync: 00000000000000000000000000000000
 *           Metadata_Length: 0
 * ATT: Write Command (0x52) len 26
 *   Handle: 0x0009 Type: Broadcast Audio Scan Control Point (0x2bc7)
 *     Data: 0205F2698BE807C0003412000210270200000000000000000000
 *       Opcode: Add Source
 *       Advertiser_Address_Type: 0x05 (Reserved for Future Use)
 *       Advertiser_Address: c0:07:e8:8b:69:f2
 *       Advertising_SID: 0x00
 *       Broadcast_ID: 0x001234
 *       PA_Sync: Synchronize to PA (PAST not available)
 *       PA_Interval: 0x2710
 *       Num_Subgroups: 2
 *         Subgroup #0:
 *           BIS_Sync: 00000000000000000000000000000000
 *           Metadata_Length: 0
 *         Subgroup #1:
 *           BIS_Sync: 00000000000000000000000000000000
 *           Metadata_Length: 0
 * ATT: Write Command (0x52) len 26
 *   Handle: 0x0009 Type: Broadcast Audio Scan Control Point (0x2bc7)
 *     Data: 0200F2698BE807C0003412000210270201000000000100000000
 *       Opcode: Add Source
 *       Advertiser_Address_Type: Public Device or Public Identity Address
 *       Advertiser_Address: c0:07:e8:8b:69:f2
 *       Advertising_SID: 0x00
 *       Broadcast_ID: 0x001234
 *       PA_Sync: Synchronize to PA (PAST not available)
 *       PA_Interval: 0x2710
 *       Num_Subgroups: 2
 *         Subgroup #0:
 *           BIS_Sync: 00000000000000000000000000000001
 *           Metadata_Length: 0
 *         Subgroup #1:
 *           BIS_Sync: 00000000000000000000000000000001
 *           Metadata_Length: 0
 */
#define ADD_SRC_INVALID_PARAMS \
	EXCHANGE_MTU, \
	BASS_FIND_BY_TYPE_VALUE, \
	DISC_BASS_CHAR, \
	BASS_FIND_INFO, \
	BASS_WRITE_CHAR_DESC,\
	BASS_READ_BCAST_RECV_STATE_CHARS, \
	BASS_CP_WRITE_CMD(0x02, 0x00, 0xF2, 0x69, 0x8B, 0xE8, 0x07, 0xC0, \
			0x00, 0x34, 0x12, 0x00, 0x06, 0x10, 0x27, 0x02, \
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
			0x00, 0x00), \
	IOV_NULL, \
	BASS_CP_WRITE_CMD(0x02, 0x05, 0xF2, 0x69, 0x8B, 0xE8, 0x07, 0xC0, \
			0x00, 0x34, 0x12, 0x00, 0x02, 0x10, 0x27, 0x02, \
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
			0x00, 0x00), \
	IOV_NULL, \
	BASS_CP_WRITE_CMD(0x02, 0x05, 0xF2, 0x69, 0x8B, 0xE8, 0x07, 0xC0, \
			0x3F, 0x34, 0x12, 0x00, 0x02, 0x10, 0x27, 0x02, \
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
			0x00, 0x00), \
	IOV_NULL, \
	BASS_CP_WRITE_CMD(0x02, 0x00, 0xF2, 0x69, 0x8B, 0xE8, 0x07, 0xC0, \
			0x00, 0x34, 0x12, 0x00, 0x02, 0x10, 0x27, 0x02, \
			0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, \
			0x00, 0x00)

/* ATT: Write Request (0x12) len 3
 *   Handle: 0x0009 Type: Broadcast Audio Scan Control Point (0x2bc7)
 *     Data: FF
 *       Opcode: 0xff (Reserved  For Future Use)
 * ATT: Error Response (0x01) len 4
 *   Write Request (0x12)
 *   Handle: 0x0009
 *   Error: Opcode Not Supported (0x80)
 */
#define OPCODE_NOT_SUPPORTED \
	EXCHANGE_MTU, \
	BASS_FIND_BY_TYPE_VALUE, \
	DISC_BASS_CHAR, \
	BASS_FIND_INFO, \
	BASS_WRITE_CHAR_DESC,\
	BASS_READ_BCAST_RECV_STATE_CHARS, \
	BASS_CP_WRITE_REQ(0xFF), \
	IOV_DATA(0x01, 0x12, 0x09, 0x00, 0x80)

/* ATT: Write Request (0x12) len 5
 *   Handle: 0x0009 Type: Broadcast Audio Scan Control Point (0x2bc7)
 *     Data: 006dfe
 *       Opcode: Remote Scan Stopped
 *       Extra Data: 0xfe6d
 * ATT: Error Response (0x01) len 4
 *   Write Request (0x12)
 *   Handle: 0x0009
 *   Error: Write Request Rejected (0xFC)
 * ATT: Write Request (0x12) len 5
 *   Handle: 0x0009 Type: Broadcast Audio Scan Control Point (0x2bc7)
 *     Data: 006dfe
 *       Opcode: Remote Scan Started
 *       Extra Data: 0xa2c2
 * ATT: Error Response (0x01) len 4
 *   Write Request (0x12)
 *   Handle: 0x0009
 *   Error: Write Request Rejected (0xFC)
 * ATT: Write Request (0x12) len 25
 *   Handle: 0x0009 Type: Broadcast Audio Scan Control Point (0x2bc7)
 *     Data: 0200F2698BE807C0003412000210270100000000000000
 *       Opcode: Add Source
 *       Advertiser_Address_Type: Public Device or Public Identity Address
 *       Advertiser_Address: c0:07:e8:8b:69:f2
 *       Advertising_SID: 0x00
 *       Broadcast_ID: 0x001234
 *       PA_Sync: Synchronize to PA (PAST not available)
 *       PA_Interval: 0x2710
 *       Num_Subgroups: 1
 *         Subgroup #0:
 *           BIS_Sync: 00000000000000000000000000000001
 *           Metadata_Length: 0
 *       Extra Data: 0x0000
 * ATT: Error Response (0x01) len 4
 *   Write Request (0x12)
 *   Handle: 0x0009
 *   Error: Write Request Rejected (0xFC)
 * ATT: Write Request (0x12) len 13
 *   Handle: 0x0009 Type: Broadcast Audio Scan Control Point (0x2bc7)
 *     Data: 03000210270100000000001500
 *       Opcode: Modify Source
 *       Source_ID: 0x00
 *       PA_Sync: Synchronize to PA (PAST not available)
 *       PA_Interval: 0x2710
 *       Num_Subgroups: 1
 *         Subgroup #0:
 *           BIS_Sync: 00000000000000000000000000000001
 *           Metadata_Length: 0
 *       Extra Data: 0x0015
 * ATT: Error Response (0x01) len 4
 *   Write Request (0x12)
 *   Handle: 0x0009
 *   Error: Write Request Rejected (0xFC)
 * ATT: Write Request (0x12) len 20
 *   Handle: 0x0009 Type: Broadcast Audio Scan Control Point (0x2bc7)
 *     Data: 0400B803EAC6AFBB65A25A41F153056802010000
 *       Opcode: Set Broadcast_Code
 *       Source_ID: 0x00
 *       Broadcast_Code: 0x0102680553f1415aa265bbafc6ea03b8
 *       Extra Data: 0x0000
 * ATT: Error Response (0x01) len 4
 *   Write Request (0x12)
 *   Handle: 0x0009
 *   Error: Write Request Rejected (0xFC)
 * ATT: Write Request (0x12) len 4
 *   Handle: 0x0009 Type: Broadcast Audio Scan Control Point (0x2bc7)
 *     Data: 05008F13
 *       Opcode: Remove Source
 *       Source_ID: 0x00
 *       Extra Data: 0x138f
 * ATT: Error Response (0x01) len 4
 *   Write Request (0x12)
 *   Handle: 0x0009
 *   Error: Write Request Rejected (0xFC)
 */
#define INVALID_LEN \
	EXCHANGE_MTU, \
	BASS_FIND_BY_TYPE_VALUE, \
	DISC_BASS_CHAR, \
	BASS_FIND_INFO, \
	BASS_WRITE_CHAR_DESC,\
	BASS_READ_BCAST_RECV_STATE_CHARS, \
	BASS_CP_WRITE_REQ(0x00, 0x6D, 0xFE), \
	IOV_DATA(0x01, 0x12, 0x09, 0x00, 0xFC), \
	BASS_CP_WRITE_REQ(0x01, 0xC2, 0xA2), \
	IOV_DATA(0x01, 0x12, 0x09, 0x00, 0xFC), \
	BASS_CP_WRITE_REQ(0x02, 0x00, 0xF2, 0x69, 0x8B, 0xE8, 0x07, 0xC0, \
			0x00, 0x34, 0x12, 0x00, 0x02, 0x10, 0x27, 0x01, \
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00), \
	IOV_DATA(0x01, 0x12, 0x09, 0x00, 0xFC), \
	BASS_CP_WRITE_REQ(0x03, 0x00, 0x02, 0x10, 0x27, 0x01, 0x00, 0x00, \
			0x00, 0x00, 0x00, 0x15, 0x00), \
	IOV_DATA(0x01, 0x12, 0x09, 0x00, 0xFC), \
	BASS_CP_WRITE_REQ(0x04, 0x00, 0xB8, 0x03, 0xEA, 0xC6, 0xAF, 0xBB, \
			0x65, 0xA2, 0x5A, 0x41, 0xF1, 0x53, 0x05, 0x68, \
			0x02, 0x01, 0x00, 0x00), \
	IOV_DATA(0x01, 0x12, 0x09, 0x00, 0xFC), \
	BASS_CP_WRITE_REQ(0x05, 0x00, 0x8F, 0x13), \
	IOV_DATA(0x01, 0x12, 0x09, 0x00, 0xFC)

/* ATT: Write Request (0x12) len 20
 *   Handle: 0x0009 Type: Broadcast Audio Scan Control Point (0x2bc7)
 *     Data: 0400B803EAC6AFBB65A25A41F153056802010000
 *       Opcode: Set Broadcast_Code
 *       Source_ID: 0x05
 *       Broadcast_Code: 0x0102680553f1415aa265bbafc6ea03b
 * ATT: Error Response (0x01) len 4
 *   Write Request (0x12)
 *   Handle: 0x0009
 *   Error: Invalid Source ID (0x81)
 * ATT: Write Request (0x12) len 4
 *   Handle: 0x0009 Type: Broadcast Audio Scan Control Point (0x2bc7)
 *     Data: 005
 *       Opcode: Remove Source
 *       Source_ID: 0x05
 * ATT: Error Response (0x01) len 4
 *   Write Request (0x12)
 *   Handle: 0x0009
 *   Error: Invalid Source ID (0x81)
 */
#define INVALID_SRC_ID \
	EXCHANGE_MTU, \
	BASS_FIND_BY_TYPE_VALUE, \
	DISC_BASS_CHAR, \
	BASS_FIND_INFO, \
	BASS_WRITE_CHAR_DESC, \
	BASS_READ_BCAST_RECV_STATE_CHARS, \
	BASS_CP_WRITE_REQ(0x04, 0x05, 0xB8, 0x03, 0xEA, 0xC6, 0xAF, 0xBB, \
			0x65, 0xA2, 0x5A, 0x41, 0xF1, 0x53, 0x05, 0x68, \
			0x02, 0x01), \
	IOV_DATA(0x01, 0x12, 0x09, 0x00, 0x81), \
	BASS_CP_WRITE_REQ(0x05, 0x05), \
	IOV_DATA(0x01, 0x12, 0x09, 0x00, 0x81)

#define iov_data(args...) ((const struct iovec[]) { args })

#define define_test(name, function, _cfg, args...)		\
	do {							\
		const struct iovec iov[] = { args };		\
		static struct test_data data;			\
		data.iovcnt = ARRAY_SIZE(iov_data(args));	\
		data.iov = util_iov_dup(iov, ARRAY_SIZE(iov_data(args))); \
		tester_add(name, &data, NULL, function,	\
				test_teardown);			\
	} while (0)

static void test_complete_cb(const void *user_data)
{
	tester_test_passed();
}

static void print_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	if (tester_use_debug())
		tester_debug("%s%s", prefix, str);
}

static void test_teardown(const void *user_data)
{
	struct test_data *data = (void *)user_data;

	bt_bass_unref(data->bass);
	bt_gatt_server_unref(data->server);
	util_iov_free(data->iov, data->iovcnt);

	gatt_db_unref(data->db);

	queue_destroy(data->ccc_states, free);

	tester_teardown_complete();
}

static bool ccc_state_match(const void *a, const void *b)
{
	const struct ccc_state *ccc = a;
	uint16_t handle = PTR_TO_UINT(b);

	return ccc->handle == handle;
}

static struct ccc_state *find_ccc_state(struct test_data *data,
				uint16_t handle)
{
	return queue_find(data->ccc_states, ccc_state_match,
				UINT_TO_PTR(handle));
}

static struct ccc_state *get_ccc_state(struct test_data *data, uint16_t handle)
{
	struct ccc_state *ccc;

	ccc = find_ccc_state(data, handle);
	if (ccc)
		return ccc;

	ccc = new0(struct ccc_state, 1);
	ccc->handle = handle;
	queue_push_tail(data->ccc_states, ccc);

	return ccc;
}

static void gatt_ccc_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct test_data *data = user_data;
	struct ccc_state *ccc;
	uint16_t handle;
	uint8_t ecode = 0;
	const uint8_t *value = NULL;
	size_t len = 0;

	handle = gatt_db_attribute_get_handle(attrib);

	ccc = get_ccc_state(data, handle);
	if (!ccc) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto done;
	}

	len = sizeof(ccc->value);
	value = (void *) &ccc->value;

done:
	gatt_db_attribute_read_result(attrib, id, ecode, value, len);
}

static void gatt_ccc_write_cb(struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				const uint8_t *value, size_t len,
				uint8_t opcode, struct bt_att *att,
				void *user_data)
{
	struct test_data *data = (void *)user_data;
	struct ccc_state *ccc_state;
	uint16_t val;
	uint8_t ecode = 0;

	if (!value || len > 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset > 2) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (len == 1)
		val = *value;
	else
		val = get_le16(value);

	ccc_state = get_ccc_state(data, gatt_db_attribute_get_handle(attrib));
	if (!ccc_state)
		return;

	/* If value is identical, then just succeed */
	if (val == ccc_state->value)
		goto done;

	ccc_state->value = val;

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void gatt_notify_cb(struct gatt_db_attribute *attrib,
				struct gatt_db_attribute *ccc,
				const uint8_t *value, size_t len,
				struct bt_att *att, void *user_data)
{
	struct test_data *data = user_data;
	struct ccc_state *ccc_state;

	ccc_state = find_ccc_state(data, gatt_db_attribute_get_handle(ccc));
	if (!ccc_state || !(ccc_state->value & 0x0001))
		return;

	bt_gatt_server_send_notification(data->server,
		gatt_db_attribute_get_handle(attrib),
		value, len, false);
}

static void test_server(const void *user_data)
{
	struct test_data *data = (void *)user_data;
	struct bt_att *att;
	struct io *io;

	io = tester_setup_io(data->iov, data->iovcnt);
	g_assert(io);

	tester_io_set_complete_func(test_complete_cb);

	att = bt_att_new(io_get_fd(io), false);
	g_assert(att);

	bt_att_set_security(att, BT_ATT_SECURITY_MEDIUM);
	bt_att_set_debug(att, BT_ATT_DEBUG, print_debug, "bt_att:", NULL);

	data->db = gatt_db_new();
	g_assert(data->db);

	gatt_db_ccc_register(data->db, gatt_ccc_read_cb, gatt_ccc_write_cb,
					gatt_notify_cb, data);

	data->bass = bt_bass_new(data->db, NULL, BDADDR_ANY);
	g_assert(data->bass);

	bt_bass_set_att(data->bass, att);
	bt_bass_attach(data->bass, NULL);

	bt_bass_set_debug(data->bass, print_debug, "bt_bass:", NULL);

	data->server = bt_gatt_server_new(data->db, att, 64, 0);
	g_assert(data->server);

	bt_gatt_server_set_debug(data->server, print_debug, "bt_gatt_server:",
						NULL);

	data->ccc_states = queue_new();

	tester_io_send();

	bt_att_unref(att);
}

static void test_sggit(void)
{
	/* BASS/SR/SGGIT/SER/BV-01-C [Service GGIT - Broadcast Scan]
	 *
	 * For each ATT_Read_By_Group_Type_Request, the IUT sends a correctly
	 * formatted ATT_Read_By_Group_Type_Response reporting BASS to the
	 * Lower Tester, or an ATT_Error_Response if there is no handle/UUID
	 * pair matching the request.
	 *
	 * For each ATT_Find_By_Type_Value_Request, the IUT sends one
	 * ATT_Find_By_Type_Value_Response reporting BASS to the Lower Tester,
	 * or an ATT_Error_Response when there are no more services matching
	 * the request.
	 *
	 * The IUT sends one ATT_Read_By_Type_Response to the Lower Tester for
	 * each received ATT_Read_By_Type_Request, if it has characteristic
	 * declarations within the handle range, or an ATT_Error_Response if
	 * there are no further characteristic declarations within the
	 * handle range of the request. The IUT reports all BASS
	 * characteristics.
	 */
	define_test("BASS/SR/SGGIT/SER/BV-01-C", test_server, NULL,
							DISC_BASS_SER);

	/* BASS/SR/SGGIT/CHA/BV-01-C [Service GGIT -
	 * Broadcast Audio Scan Control Point]
	 *
	 * The IUT sends one ATT_Read_By_Type_Response to the Lower Tester for
	 * each received ATT_Read_By_Type_Request, if it has characteristic
	 * declarations within the handle range, or an ATT_Error_Response if
	 * there are no further characteristic declarations within the
	 * handle range of the request. The IUT reports one instance of the
	 * Broadcast Audio Scan Control Point characteristic.
	 */
	define_test("BASS/SR/SGGIT/CHA/BV-01-C", test_server, NULL,
						DISC_BCAST_AUDIO_SCAN_CP);

	/* BASS/SR/SGGIT/CHA/BV-02-C [Service GGIT -
	 * Broadcast Receive State]
	 *
	 * The IUT sends one ATT_Read_By_Type_Response to the Lower Tester for
	 * each received ATT_Read_By_Type_Request, if it has characteristic
	 * declarations within the handle range, or an ATT_Error_Response if
	 * there are no further characteristic declarations within the
	 * handle range of the request. The IUT reports two instances of the
	 * Broadcast Receive State characteristic.
	 *
	 * The IUT sends one ATT_Find_Information_Response to the Lower Tester
	 * for each received ATT_Find_Information_Request, if it has
	 * characteristic descriptors within the handle range, or an
	 * ATT_Error_Response if there are no characteristic descriptors within
	 * the handle range of the request. For each Broadcast Receive State
	 * characteristic, the IUT reports one Client Characteristic
	 * Configuration descriptor.
	 *
	 * The IUT sends an ATT_Read_Response to the Lower Tester for each
	 * ATT_Read_Request.
	 */
	define_test("BASS/SR/SGGIT/CHA/BV-02-C", test_server, NULL,
						DISC_BCAST_RECV_STATE);
}

static void test_spe(void)
{
	/* BASS/SR/SPE/BI-01-C [Ignore Invalid Source ID]
	 *
	 * Test Purpose:
	 * Verify that the BASS Server IUT does not respond to a control point
	 * procedure call that uses an invalid Source_ID parameter.
	 *
	 * Pass verdict:
	 * The IUT does not send a notification of the Broadcast Receive State
	 * characteristic.
	 */
	define_test("BASS/SR/SPE/BI-01-C", test_server, NULL,
				IGNORE_INVALID_SRC_ID);

	/* BASS/SR/SPE/BI-03-C [Add Source - Ignore Invalid Values]
	 *
	 * Test Purpose:
	 * Verify that the BASS Server IUT ignores Add Source control point
	 * procedure calls that include an RFU or Invalid parameter.
	 *
	 * Pass verdict:
	 * The IUT does not send a notification of the Broadcast Receive State
	 * characteristic.
	 */
	define_test("BASS/SR/SPE/BI-03-C", test_server, NULL,
				ADD_SRC_INVALID_PARAMS);

	/* BASS/SR/SPE/BI-04-C [Opcode Not Supported]
	 *
	 * Test Purpose:
	 * Verify that the BASS Server IUT returns an Opcode Not Supported error
	 * response when the opcode written is not supported by the IUT or is
	 * within a range that is reserved for future use being written to the
	 * Broadcast Audio Scan Control Point.
	 *
	 * Pass verdict:
	 * The IUT sends an error response of OPCODE NOT SUPPORTED.
	 */
	define_test("BASS/SR/SPE/BI-04-C", test_server, NULL,
				OPCODE_NOT_SUPPORTED);

	/* BASS/SR/SPE/BI-06-C [Invalid Length]
	 *
	 * Test Purpose:
	 * Verify that the BASS Server IUT rejects writing of an opcode with
	 * an invalid length.
	 *
	 * Pass verdict:
	 * The IUT rejects the opcode.
	 */
	define_test("BASS/SR/SPE/BI-06-C", test_server, NULL,
				INVALID_LEN);

	/* BASS/SR/SPE/BI-07-C [Invalid Source ID]
	 *
	 * Test Purpose:
	 * Verify that the BASS Server IUT returns an error when a control
	 * point procedure passing an invalid Source_ID parameter is called.
	 *
	 * Pass verdict:
	 * The IUT sends an ATT Error Response with the Error Code set to
	 * Invalid Source_ID.
	 */
	define_test("BASS/SR/SPE/BI-07-C", test_server, NULL,
				INVALID_SRC_ID);
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_sggit();
	test_spe();

	return tester_run();
}
