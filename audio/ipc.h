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

#include <stdint.h>

#define IPC_TYPE_CONNECT  0x0001

#define IPC_SOCKET_NAME "/org/bluez/audio"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

/* Supported roles */
#define PKT_ROLE_NONE		0
#define PKT_ROLE_AUTO		1
#define PKT_ROLE_VOICE		2
#define PKT_ROLE_HIFI		3

/* Packet types */
#define PKT_TYPE_CFG_REQ	0
#define PKT_TYPE_CFG_RSP	1
#define PKT_TYPE_STATUS_REQ	3
#define PKT_TYPE_STATUS_RSP	4
#define PKT_TYPE_CTL_REQ	5
#define PKT_TYPE_CTL_RSP	6

/* Errors codes */
#define PKT_ERROR_NONE		0

struct ipc_packet {
	uint8_t id;		/* Device id */
	uint8_t role;		/* Audio role eg: voice, wifi, auto... */
	uint8_t type;		/* Packet type */
	uint8_t error;		/* Packet error code */
	uint8_t length;		/* Payload length in bytes */
	uint8_t data[0];	/* Packet payload */
} __attribute__ ((packed));

/* File descriptor options */
#define CFG_FD_OPT_READ		0
#define CFG_FD_OPT_WRITE	1
#define CFG_FD_OPT_READWRITE	2

struct ipc_data_cfg {
	int fd;			/* Stream file descriptor */
	uint8_t fd_opt;		/* Stream file descriptor options: read, write or readwrite*/
	uint8_t encoding;	/* Stream encoding */
	uint8_t bitpool;	/* Encoding bitpool */
	uint8_t channels;	/* Number of audio channel */
	uint16_t rate;		/* Stream sample rate */
} __attribute__ ((packed));

/* Device status */
#define STATUS_DISCONNECTED	0
#define STATUS_CONNECTING	1
#define STATUS_CONNECTED	2
#define STATUS_STREAMING	3

struct ipc_data_status {
	uint8_t status;		/* Stream status */
} __attribute__ ((packed));

/* Supported control operations */
#define DATA_CTL_POWER		0x40
#define DATA_CTL_VOL_UP		0x41
#define DATA_CTL_VOL_DOWN	0x42
#define DATA_CTL_MUTE		0x43
#define DATA_CTL_PLAY		0x44
#define DATA_CTL_STOP		0x45
#define DATA_CTL_PAUSE		0x46
#define DATA_CTL_RECORD		0x47
#define DATA_CTL_REWIND		0x48
#define DATA_CTL_FAST_FORWARD	0x49
#define DATA_CTL_EJECT		0x4A
#define DATA_CTL_FORWARD	0x4B
#define DATA_CTL_BACKWARD	0x4C

struct ipc_data_ctl {
	uint8_t operation;	/* Operation ID */
}  __attribute__ ((packed));
