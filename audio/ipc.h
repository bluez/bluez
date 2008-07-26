/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

/*
  Message sequence chart of streaming sequence for A2DP transport

  Audio daemon                       User
                             on snd_pcm_open
                 <--BT_GETCAPABILITIES_REQ

  BT_GETCAPABILITIES_RSP-->

                        on snd_pcm_hw_params
                <--BT_SETCONFIGURATION_REQ

  BT_SETCONFIGURATION_RSP-->

			on snd_pcm_prepare
                <--BT_STREAMSTART_REQ

  <Moves to streaming state>
  BT_STREAMSTART_RSP-->

  BT_STREAMFD_IND -->

                          <  streams data >
                             ..........

               on snd_pcm_drop/snd_pcm_drain

                <--BT_STREAMSTOP_REQ

  <Moves to open state>
  BT_STREAMSTOP_RSP-->

			on IPC close or appl crash
  <Moves to idle>

 */

#ifndef BT_AUDIOCLIENT_H
#define BT_AUDIOCLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define BT_AUDIO_IPC_PACKET_SIZE   128
#define BT_IPC_SOCKET_NAME "\0/org/bluez/audio"

/* Generic message header definition, except for RSP messages */
typedef struct {
	uint8_t msg_type;
} __attribute__ ((packed)) bt_audio_msg_header_t;

/* Generic message header definition, for all RSP messages */
typedef struct {
	bt_audio_msg_header_t	msg_h;
	uint8_t			posix_errno;
} __attribute__ ((packed)) bt_audio_rsp_msg_header_t;

/* Messages list */
#define BT_GETCAPABILITIES_REQ		0
#define BT_GETCAPABILITIES_RSP		1

#define BT_SETCONFIGURATION_REQ		2
#define BT_SETCONFIGURATION_RSP		3

#define BT_STREAMSTART_REQ		4
#define BT_STREAMSTART_RSP		5

#define BT_STREAMSTOP_REQ		6
#define BT_STREAMSTOP_RSP		7

#define BT_STREAMSUSPEND_IND		8
#define BT_STREAMRESUME_IND		9

#define BT_CONTROL_REQ		       10
#define BT_CONTROL_RSP		       11
#define BT_CONTROL_IND		       12

#define BT_STREAMFD_IND		       13

/* BT_GETCAPABILITIES_REQ */

#define BT_CAPABILITIES_TRANSPORT_A2DP	0
#define BT_CAPABILITIES_TRANSPORT_SCO	1
#define BT_CAPABILITIES_TRANSPORT_ANY	2

#define BT_CAPABILITIES_ACCESS_MODE_READ	1
#define BT_CAPABILITIES_ACCESS_MODE_WRITE	2
#define BT_CAPABILITIES_ACCESS_MODE_READWRITE	3

#define BT_FLAG_AUTOCONNECT	1

struct bt_getcapabilities_req {
	bt_audio_msg_header_t	h;
	char			device[18];	/* Address of the remote Device */
	uint8_t			transport;	/* Requested transport */
	uint8_t			flags;		/* Requested flags */
} __attribute__ ((packed));

/* BT_GETCAPABILITIES_RSP */

/**
 * SBC Codec parameters as per A2DP profile 1.0 § 4.3
 */

#define BT_SBC_SAMPLING_FREQ_16000		(1 << 3)
#define BT_SBC_SAMPLING_FREQ_32000		(1 << 2)
#define BT_SBC_SAMPLING_FREQ_44100		(1 << 1)
#define BT_SBC_SAMPLING_FREQ_48000		1

#define BT_A2DP_CHANNEL_MODE_MONO		(1 << 3)
#define BT_A2DP_CHANNEL_MODE_DUAL_CHANNEL	(1 << 2)
#define BT_A2DP_CHANNEL_MODE_STEREO		(1 << 1)
#define BT_A2DP_CHANNEL_MODE_JOINT_STEREO	1

#define BT_A2DP_BLOCK_LENGTH_4			(1 << 3)
#define BT_A2DP_BLOCK_LENGTH_8			(1 << 2)
#define BT_A2DP_BLOCK_LENGTH_12			(1 << 1)
#define BT_A2DP_BLOCK_LENGTH_16			1

#define BT_A2DP_SUBBANDS_4			(1 << 1)
#define BT_A2DP_SUBBANDS_8			1

#define BT_A2DP_ALLOCATION_SNR			(1 << 1)
#define BT_A2DP_ALLOCATION_LOUDNESS		1

#define BT_MPEG_SAMPLING_FREQ_16000		(1 << 5)
#define BT_MPEG_SAMPLING_FREQ_22050		(1 << 4)
#define BT_MPEG_SAMPLING_FREQ_24000		(1 << 3)
#define BT_MPEG_SAMPLING_FREQ_32000		(1 << 2)
#define BT_MPEG_SAMPLING_FREQ_44100		(1 << 1)
#define BT_MPEG_SAMPLING_FREQ_48000		1

#define BT_MPEG_LAYER_1				(1 << 2)
#define BT_MPEG_LAYER_2				(1 << 1)
#define BT_MPEG_LAYER_3				1

typedef struct {
	uint8_t channel_mode;
	uint8_t frequency;
	uint8_t allocation_method;
	uint8_t subbands;
	uint8_t block_length;
	uint8_t min_bitpool;
	uint8_t max_bitpool;
} __attribute__ ((packed)) sbc_capabilities_t;

typedef struct {
	uint8_t channel_mode;
	uint8_t crc;
	uint8_t layer;
	uint8_t frequency;
	uint8_t mpf;
	uint16_t bitrate;
} __attribute__ ((packed)) mpeg_capabilities_t;

struct bt_getcapabilities_rsp {
	bt_audio_rsp_msg_header_t	rsp_h;
	uint8_t				transport;	   /* Granted transport */
	sbc_capabilities_t		sbc_capabilities;  /* A2DP only */
	mpeg_capabilities_t		mpeg_capabilities; /* A2DP only */
	uint16_t			sampling_rate;	   /* SCO only */
} __attribute__ ((packed));

/* BT_SETCONFIGURATION_REQ */
struct bt_setconfiguration_req {
	bt_audio_msg_header_t	h;
	char			device[18];		/* Address of the remote Device */
	uint8_t			transport;		/* Requested transport */
	uint8_t			access_mode;		/* Requested access mode */
	sbc_capabilities_t	sbc_capabilities;	/* A2DP only - only one of this field
							and next one must be filled */
	mpeg_capabilities_t	mpeg_capabilities;	/* A2DP only */
} __attribute__ ((packed));

/* BT_SETCONFIGURATION_RSP */
struct bt_setconfiguration_rsp {
	bt_audio_rsp_msg_header_t	rsp_h;
	uint8_t				transport;	/* Granted transport */
	uint8_t				access_mode;	/* Granted access mode */
	uint16_t			link_mtu;	/* Max length that transport supports */
} __attribute__ ((packed));

/* BT_STREAMSTART_REQ */
#define BT_STREAM_ACCESS_READ		0
#define BT_STREAM_ACCESS_WRITE		1
#define BT_STREAM_ACCESS_READWRITE	2
struct bt_streamstart_req {
	bt_audio_msg_header_t	h;
} __attribute__ ((packed));

/* BT_STREAMSTART_RSP */
struct bt_streamstart_rsp {
	bt_audio_rsp_msg_header_t	rsp_h;
} __attribute__ ((packed));

/* BT_STREAMFD_IND */
/* This message is followed by one byte of data containing the stream data fd
   as ancilliary data */
struct bt_streamfd_ind {
	bt_audio_msg_header_t	h;
} __attribute__ ((packed));

/* BT_STREAMSTOP_REQ */
struct bt_streamstop_req {
	bt_audio_msg_header_t	h;
} __attribute__ ((packed));

/* BT_STREAMSTOP_RSP */
struct bt_streamstop_rsp {
	bt_audio_rsp_msg_header_t	rsp_h;
} __attribute__ ((packed));

/* BT_STREAMSUSPEND_IND */
struct bt_streamsuspend_ind {
	bt_audio_msg_header_t	h;
} __attribute__ ((packed));

/* BT_STREAMRESUME_IND */
struct bt_streamresume_ind {
	bt_audio_msg_header_t	h;
} __attribute__ ((packed));

/* BT_CONTROL_REQ */

#define BT_CONTROL_KEY_POWER			0x40
#define BT_CONTROL_KEY_VOL_UP			0x41
#define BT_CONTROL_KEY_VOL_DOWN			0x42
#define BT_CONTROL_KEY_MUTE			0x43
#define BT_CONTROL_KEY_PLAY			0x44
#define BT_CONTROL_KEY_STOP			0x45
#define BT_CONTROL_KEY_PAUSE			0x46
#define BT_CONTROL_KEY_RECORD			0x47
#define BT_CONTROL_KEY_REWIND			0x48
#define BT_CONTROL_KEY_FAST_FORWARD		0x49
#define BT_CONTROL_KEY_EJECT			0x4A
#define BT_CONTROL_KEY_FORWARD			0x4B
#define BT_CONTROL_KEY_BACKWARD			0x4C

struct bt_control_req {
	bt_audio_msg_header_t	h;
	uint8_t			mode;		/* Control Mode */
	uint8_t			key;		/* Control Key */
} __attribute__ ((packed));

/* BT_CONTROL_RSP */
struct bt_control_rsp {
	bt_audio_rsp_msg_header_t	rsp_h;
	uint8_t				mode;	/* Control Mode */
	uint8_t				key;	/* Control Key */
} __attribute__ ((packed));

/* BT_CONTROL_IND */
struct bt_control_ind {
	bt_audio_msg_header_t	h;
	uint8_t			mode;		/* Control Mode */
	uint8_t			key;		/* Control Key */
} __attribute__ ((packed));

/* Function declaration */

/* Opens a connection to the audio service: return a socket descriptor */
int bt_audio_service_open();

/* Closes a connection to the audio service */
int bt_audio_service_close(int sk);

/* Receives stream data file descriptor : must be called after a
BT_STREAMFD_IND message is returned */
int bt_audio_service_get_data_fd(int sk);

/* Human readable message type string */
const char *bt_audio_strmsg(int type);

#ifdef __cplusplus
}
#endif

#endif /* BT_AUDIOCLIENT_H */
