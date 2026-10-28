/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation. All rights reserved.
 *  Copyright 2023-2024 NXP
 *
 */

#ifndef SRC_SHARED_BAP_DEFS_H_
#define SRC_SHARED_BAP_DEFS_H_

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define BT_BAP_SINK			BIT(0)
#define	BT_BAP_SOURCE			BIT(1)
#define	BT_BAP_BCAST_SOURCE		BIT(2)
#define	BT_BAP_BCAST_SINK		BIT(3)

#define BT_BAP_STREAM_TYPE_UCAST	0x01
#define	BT_BAP_STREAM_TYPE_BCAST	0x02

#define BT_BAP_STREAM_STATE_IDLE	0x00
#define BT_BAP_STREAM_STATE_CONFIG	0x01
#define BT_BAP_STREAM_STATE_QOS		0x02
#define BT_BAP_STREAM_STATE_ENABLING	0x03
#define BT_BAP_STREAM_STATE_STREAMING	0x04
#define BT_BAP_STREAM_STATE_DISABLING	0x05
#define BT_BAP_STREAM_STATE_RELEASING	0x06

#define BT_BAP_CONFIG_LATENCY_LOW	0x01
#define BT_BAP_CONFIG_LATENCY_BALANCED	0x02
#define BT_BAP_CONFIG_LATENCY_HIGH	0x03

#define BT_BAP_CONFIG_PHY_1M		BIT(0)
#define BT_BAP_CONFIG_PHY_2M		BIT(1)
#define BT_BAP_CONFIG_PHY_CODEC		BIT(2)

/* Assigned Numbers 6.12.4 Codec_Specific_Capabilities LTV structures */
/* Supported_Sampling_Frequencies */
#define BT_BAP_CAP_FREQ			0x01
/* Supported_Frame_Durations */
#define BT_BAP_CAP_DURATION		0x02
/* Supported_Audio_Channel_Counts */
#define BT_BAP_CAP_CHANNELS		0x03
/* Supported_Octets_Per_Codec_Frame */
#define BT_BAP_CAP_FRAME_LENGTH		0x04
/* Supported_Max_Codec_Frames_Per_SDU */
#define BT_BAP_CAP_SDU			0x05

/* Assigned Numbers 6.12.5 Codec_Specific_Configuration LTV structures */
/* Sampling_Frequency */
#define BT_BAP_CC_FREQ			0x01
/* Frame_Duration */
#define BT_BAP_CC_DURATION		0x02
/* Audio_Channel_Allocation */
#define BT_BAP_CC_LOCATION		0x03
/* Octets_Per_Codec_Frame */
#define BT_BAP_CC_FRAME_LENGTH		0x04
/* Codec_Frame_Blocks_Per_SDU */
#define BT_BAP_CC_SDU			0x05

/* Assigned Numbers 6.12.6 Metadata LTV structures */
/* Preferred_Audio_Contexts */
#define BT_BAP_META_PREFERRED_CONTEXT	0x01
/* Streaming_Audio_Contexts */
#define BT_BAP_META_CONTEXT		0x02
/* Program_Info */
#define BT_BAP_META_PROGRAM_INFO	0x03
/* Language */
#define BT_BAP_META_LANGUAGE		0x04
/* CCID_List */
#define BT_BAP_META_CCID_LIST		0x05
/* Parental_Rating */
#define BT_BAP_META_PARENTAL_RATING	0x06
/* Program_Info_URI */
#define BT_BAP_META_PROGRAM_INFO_URI	0x07
/* Audio_Active_State */
#define BT_BAP_META_AUDIO_ACTIVE_STATE	0x08
/* Broadcast_Audio_Immediate_Rendering_Flag */
#define BT_BAP_META_BCAST_IMMEDIATE	0x09
/* Assisted_Listening_Stream */
#define BT_BAP_META_ASSISTED_LISTENING	0x0a
/* Broadcast_Name */
#define BT_BAP_META_BROADCAST_NAME	0x0b
/* Extended_Metadata */
#define BT_BAP_META_EXTENDED		0xfe
/* Vendor_Specific */
#define BT_BAP_META_VENDOR		0xff

struct bt_bap_codec {
	uint8_t  id;
	uint16_t cid;
	uint16_t vid;
} __packed;

struct bt_ltv {
	uint8_t  len;
	uint8_t  type;
	uint8_t  value[];
} __packed;

struct bt_bap_io_qos {
	uint32_t interval;	/* Frame interval */
	uint16_t latency;	/* Transport Latency */
	uint16_t sdu;		/* Maximum SDU Size */
	uint8_t  phys;		/* PHY */
	uint8_t  rtn;		/* Retransmission Effort */
};

struct bt_bap_ucast_qos {
	uint8_t  cig_id;
	uint8_t  cis_id;
	uint8_t  framing;		/* Frame framing */
	uint32_t delay;			/* Presentation Delay */
	uint8_t  target_latency;	/* Target Latency */
	struct bt_bap_io_qos io_qos;
};

struct bt_bap_bcast_qos {
	uint8_t  big;
	uint8_t  bis;
	uint8_t  sync_factor;
	uint8_t  packing;
	uint8_t  framing;
	uint8_t  encryption;
	struct iovec *bcode;
	uint8_t  options;
	uint16_t skip;
	uint16_t sync_timeout;
	uint8_t  sync_cte_type;
	uint8_t  mse;
	uint16_t timeout;
	uint8_t  pa_sync;
	struct bt_bap_io_qos io_qos;
	uint32_t delay;			/* Presentation Delay */
};

struct bt_bap_qos {
	union {
		struct bt_bap_ucast_qos ucast;
		struct bt_bap_bcast_qos bcast;
	};
};

#endif /* SRC_SHARED_BAP_DEFS_H_ */
