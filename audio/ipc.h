/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#define IPC_TYPE_CONNECT  0x0001

#define IPC_MTU 32

#define IPC_SOCKET_NAME "\0/org/bluez/audio"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

/* Supported roles */
#define PKT_ROLE_NONE			0
#define PKT_ROLE_AUTO			1
#define PKT_ROLE_VOICE			2
#define PKT_ROLE_HIFI			3

/* Packet types */
#define PKT_TYPE_CFG_REQ		0
#define PKT_TYPE_CFG_RSP		1
#define PKT_TYPE_STATE_REQ		2
#define PKT_TYPE_STATE_RSP		3
#define PKT_TYPE_CTL_REQ		4
#define PKT_TYPE_CTL_RSP		5
#define PKT_TYPE_CTL_NTFY		6

/* Errors codes */
#define PKT_ERROR_NONE			0

struct ipc_packet {
	uint8_t id;		/* Device id */
	uint8_t role;		/* Audio role eg: voice, wifi, auto... */
	uint8_t type;		/* Packet type */
	uint8_t error;		/* Packet error code */
	uint8_t length;		/* Payload length in bytes */
	uint8_t data[0];	/* Packet payload */
} __attribute__ ((packed));

/* File descriptor options */
#define CFG_FD_OPT_READ			0
#define CFG_FD_OPT_WRITE		1
#define CFG_FD_OPT_READWRITE		2

/* Audio channel mode */
#define CFG_CHANNEL_MODE_MONO		(1 << 3)
#define CFG_CHANNEL_MODE_DUAL_CHANNEL	(1 << 2)
#define CFG_CHANNEL_MODE_STEREO		(1 << 1)
#define CFG_CHANNEL_MODE_JOINT_STEREO	1

/* Codec options */
#define CFG_CODEC_NONE			0
#define CFG_CODEC_SBC			1

struct ipc_data_cfg {
	uint8_t fd_opt;		/* Stream file descriptor options: read,
				   write or readwrite */
	uint8_t channels;	/* Number of audio channel */
	uint8_t channel_mode;	/* Audio channel mode*/
	uint16_t pkt_len;	/* Stream packet length */
	uint8_t sample_size;	/* Sample size in bytes */
	uint16_t rate;		/* Stream sample rate */
	uint8_t codec;		/* Stream codec */
	uint8_t data[0];	/* Codec payload */
} __attribute__ ((packed));

/* SBC codec options */
#define CODEC_SBC_ALLOCATION_SNR	(1 << 1)
#define CODEC_SBC_ALLOCATION_LOUDNESS	1

struct ipc_codec_sbc {
	uint8_t allocation;
	uint8_t subbands;
	uint8_t blocks;
	uint8_t bitpool;
} __attribute__ ((packed));

/* Device status */
#define STATE_DISCONNECTED		0
#define STATE_CONNECTING		1
#define STATE_CONNECTED			2
#define STATE_STREAM_STARTING		3
#define STATE_STREAMING			4

struct ipc_data_state {
	uint8_t state;		/* Stream state */
} __attribute__ ((packed));

#define CTL_MODE_PLAYBACK		0
#define CTL_MODE_CAPTURE		1
#define CTL_MODE_GENERAL		2

/* Supported control operations */
#define CTL_KEY_POWER			0x40
#define CTL_KEY_VOL_UP			0x41
#define CTL_KEY_VOL_DOWN		0x42
#define CTL_KEY_MUTE			0x43
#define CTL_KEY_PLAY			0x44
#define CTL_KEY_STOP			0x45
#define CTL_KEY_PAUSE			0x46
#define CTL_KEY_RECORD			0x47
#define CTL_KEY_REWIND			0x48
#define CTL_KEY_FAST_FORWARD		0x49
#define CTL_KEY_EJECT			0x4A
#define CTL_KEY_FORWARD			0x4B
#define CTL_KEY_BACKWARD		0x4C

struct ipc_data_ctl {
	uint8_t mode;		/* Control Mode */
	uint8_t key;		/* Control Key */
}  __attribute__ ((packed));
