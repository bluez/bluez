/* 
   BlueZ - Bluetooth protocol stack for Linux
   Copyright (C) 2000-2001 Qualcomm Incorporated

   Written 2000,2001 by Maxim Krasnyansky <maxk@qualcomm.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation;

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
   IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
   CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

   ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
   COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
   SOFTWARE IS DISCLAIMED.
*/

/*
	SDP parser.
	Copyright (C) 2001 Ricky Yuen <ryuen@qualcomm.com>
*/

/*
 *  $Id$
 */

#ifndef __SDP_H
#define __SDP_H

#define SDP_ERROR_RSP                                  0x01
#define SDP_SERVICE_SEARCH_REQ                         0x02
#define SDP_SERVICE_SEARCH_RSP                         0x03
#define SDP_SERVICE_ATTR_REQ                           0x04
#define SDP_SERVICE_ATTR_RSP                           0x05
#define SDP_SERVICE_SEARCH_ATTR_REQ                    0x06
#define SDP_SERVICE_SEARCH_ATTR_RSP                    0x07

/* Bluetooth assigned UUIDs for protocols */
#define SDP_UUID_SDP                                   0x0001
#define SDP_UUID_UDP                                   0x0002
#define SDP_UUID_RFCOMM                                0x0003
#define SDP_UUID_TCP                                   0x0004
#define SDP_UUID_TCS_BIN                               0x0005
#define SDP_UUID_TCS_AT                                0x0006
#define SDP_UUID_OBEX                                  0x0008
#define SDP_UUID_IP                                    0x0009
#define SDP_UUID_FTP                                   0x000A
#define SDP_UUID_HTTP                                  0x000C
#define SDP_UUID_WSP                                   0x000E
#define SDP_UUID_BNEP                                  0x000F /* PAN */
#define SDP_UUID_HIDP                                  0x0011 /* HID */
#define SDP_UUID_CMTP                                  0x001B /* CIP */
#define SDP_UUID_L2CAP                                 0x0100

/* Bluetooth assigned UUIDs for Service Classes */
#define SDP_UUID_SERVICE_DISCOVERY_SERVER              0x1000
#define SDP_UUID_BROWSE_GROUP_DESCRIPTOR               0x1001
#define SDP_UUID_PUBLIC_BROWSE_GROUP                   0x1002
#define SDP_UUID_SERIAL_PORT                           0x1101
#define SDP_UUID_LAN_ACCESS_PPP                        0x1102
#define SDP_UUID_DIALUP_NETWORKING                     0x1103
#define SDP_UUID_IR_MC_SYNC                            0x1104
#define SDP_UUID_OBEX_OBJECT_PUSH                      0x1105
#define SDP_UUID_OBEX_FILE_TRANSFER                    0x1106
#define SDP_UUID_IR_MC_SYNC_COMMAND                    0x1107
#define SDP_UUID_HEADSET                               0x1108
#define SDP_UUID_CORDLESS_TELEPHONY                    0x1109
#define SDP_UUID_INTERCOM                              0x1110
#define SDP_UUID_FAX                                   0x1111
#define SDP_UUID_HEADSET_AUDIO_GATEWAY                 0x1112
#define SDP_UUID_PANU                                  0x1115 /* PAN */
#define SDP_UUID_NAP                                   0x1116 /* PAN */
#define SDP_UUID_GN                                    0x1117 /* PAN */
#define SDP_UUID_IMAGING                               0x111a /* BIP */
#define SDP_UUID_IMAGING_RESPONDER                     0x111b /* BIP */
#define SDP_UUID_IMAGING_AUTOMATIC_ARCHIVE             0x111c /* BIP */
#define SDP_UUID_IMAGING_REFERENCED_OBJECTS            0x111d /* BIP */
#define SDP_UUID_HUMAN_INTERFACE_DEVICE                0x1124 /* HID */
#define SDP_UUID_COMMON_ISDN_ACCESS                    0x1128 /* CIP */
#define SDP_UUID_PNP_INFORMATION                       0x1200
#define SDP_UUID_GENERIC_NETWORKING                    0x1201
#define SDP_UUID_GENERIC_FILE_TRANSFER                 0x1202
#define SDP_UUID_GENERIC_AUDIO                         0x1203
#define SDP_UUID_GENERIC_TELEPHONY                     0x1204

/* Bluetooth assigned numbers for Attribute IDs */
#define SDP_ATTR_ID_SERVICE_RECORD_HANDLE              0x0000
#define SDP_ATTR_ID_SERVICE_CLASS_ID_LIST              0x0001
#define SDP_ATTR_ID_SERVICE_RECORD_STATE               0x0002
#define SDP_ATTR_ID_SERVICE_SERVICE_ID                 0x0003
#define SDP_ATTR_ID_PROTOCOL_DESCRIPTOR_LIST           0x0004
#define SDP_ATTR_ID_BROWSE_GROUP_LIST                  0x0005
#define SDP_ATTR_ID_LANGUAGE_BASE_ATTRIBUTE_ID_LIST    0x0006
#define SDP_ATTR_ID_SERVICE_INFO_TIME_TO_LIVE          0x0007
#define SDP_ATTR_ID_SERVICE_AVAILABILITY               0x0008
#define SDP_ATTR_ID_BLUETOOTH_PROFILE_DESCRIPTOR_LIST  0x0009
#define SDP_ATTR_ID_DOCUMENTATION_URL                  0x000A
#define SDP_ATTR_ID_CLIENT_EXECUTABLE_URL              0x000B
#define SDP_ATTR_ID_ICON_10                            0x000C
#define SDP_ATTR_ID_ICON_URL                           0x000D
#define SDP_ATTR_ID_SERVICE_NAME                       0x0100
#define SDP_ATTR_ID_SERVICE_DESCRIPTION                0x0101
#define SDP_ATTR_ID_PROVIDER_NAME                      0x0102
#define SDP_ATTR_ID_VERSION_NUMBER_LIST                0x0200
#define SDP_ATTR_ID_GROUP_ID                           0x0200
#define SDP_ATTR_ID_SERVICE_DATABASE_STATE             0x0201
#define SDP_ATTR_ID_SERVICE_VERSION                    0x0300

#define SDP_ATTR_ID_EXTERNAL_NETWORK                   0x0301 /* Cordless Telephony */
#define SDP_ATTR_ID_SUPPORTED_DATA_STORES_LIST         0x0301 /* Synchronization */
#define SDP_ATTR_ID_REMOTE_AUDIO_VOLUME_CONTROL        0x0302 /* GAP */
#define SDP_ATTR_ID_SUPPORTED_FORMATS_LIST             0x0303 /* OBEX Object Push */
#define SDP_ATTR_ID_FAX_CLASS_1_SUPPORT                0x0302 /* Fax */
#define SDP_ATTR_ID_FAX_CLASS_2_0_SUPPORT              0x0303
#define SDP_ATTR_ID_FAX_CLASS_2_SUPPORT                0x0304
#define SDP_ATTR_ID_AUDIO_FEEDBACK_SUPPORT             0x0305
#define SDP_ATTR_ID_SECURITY_DESCRIPTION               0x030a /* PAN */
#define SDP_ATTR_ID_NET_ACCESS_TYPE                    0x030b /* PAN */
#define SDP_ATTR_ID_MAX_NET_ACCESS_RATE                0x030c /* PAN */
#define SDP_ATTR_ID_IPV4_SUBNET                        0x030d /* PAN */
#define SDP_ATTR_ID_IPV6_SUBNET                        0x030e /* PAN */

/* Data element type descriptor */
#define SDP_DE_NULL   0
#define SDP_DE_UINT   1
#define SDP_DE_INT    2
#define SDP_DE_UUID   3
#define SDP_DE_STRING 4
#define SDP_DE_BOOL   5
#define SDP_DE_SEQ    6
#define SDP_DE_ALT    7
#define SDP_DE_URL    8

/* SDP structures */

typedef struct {
	uint8_t  pid;
	uint16_t tid;
	uint16_t len;
} __attribute__ ((packed)) sdp_pdu_hdr;
#define SDP_PDU_HDR_SIZE 5

/* Data element size index lookup table */
typedef struct {
	int addl_bits;
	int num_bytes;
} sdp_siz_idx_lookup_table_t;
extern sdp_siz_idx_lookup_table_t sdp_siz_idx_lookup_table[];

/* UUID name lookup table */
typedef struct {
	int   uuid;
	char* name;
} sdp_uuid_nam_lookup_table_t;
extern sdp_uuid_nam_lookup_table_t sdp_uuid_nam_lookup_table[];
#define SDP_UUID_NAM_LOOKUP_TABLE_SIZE \
	(sizeof(sdp_uuid_nam_lookup_table)/sizeof(sdp_uuid_nam_lookup_table_t))

/* AttrID name lookup table */
typedef struct {
	int   attr_id;
	char* name;
} sdp_attr_id_nam_lookup_table_t;
extern sdp_attr_id_nam_lookup_table_t sdp_attr_id_nam_lookup_table[];
#define SDP_ATTR_ID_NAM_LOOKUP_TABLE_SIZE \
	(sizeof(sdp_attr_id_nam_lookup_table)/sizeof(sdp_attr_id_nam_lookup_table_t))

#endif /* __SDP_H */
