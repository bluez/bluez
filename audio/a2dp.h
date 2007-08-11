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

#include <dbus.h>
#include <glib.h>
#include "avdtp.h"

#define A2DP_CODEC_SBC			0x00
#define A2DP_CODEC_MPEG12		0x01
#define A2DP_CODEC_MPEG24		0x02
#define A2DP_CODEC_ATRAC		0x03

#define A2DP_SAMPLING_FREQ_16000	(1 << 3)
#define A2DP_SAMPLING_FREQ_32000	(1 << 2)
#define A2DP_SAMPLING_FREQ_44100	(1 << 1)
#define A2DP_SAMPLING_FREQ_48000	1

#define A2DP_CHANNEL_MODE_MONO		(1 << 3)
#define A2DP_CHANNEL_MODE_DUAL_CHANNEL	(1 << 2)
#define A2DP_CHANNEL_MODE_STEREO	(1 << 1)
#define A2DP_CHANNEL_MODE_JOINT_STEREO	1

#define A2DP_BLOCK_LENGTH_4		(1 << 3)
#define A2DP_BLOCK_LENGTH_8		(1 << 2)
#define A2DP_BLOCK_LENGTH_12		(1 << 1)
#define A2DP_BLOCK_LENGTH_16		1

#define A2DP_SUBBANDS_4			(1 << 1)
#define A2DP_SUBBANDS_8			1

#define A2DP_ALLOCATION_SNR		(1 << 1)
#define A2DP_ALLOCATION_LOUDNESS	1

struct sbc_codec_cap {
	struct avdtp_media_codec_capability cap;
	uint8_t channel_mode:4;
	uint8_t frequency:4;
	uint8_t allocation_method:2;
	uint8_t subbands:2;
	uint8_t block_length:4;
	uint8_t min_bitpool;
	uint8_t max_bitpool;
} __attribute__ ((packed));

int a2dp_init(DBusConnection *conn, gboolean enable_sink,
			gboolean enable_source);
void a2dp_exit(void);

gboolean a2dp_select_capabilities(struct avdtp_remote_sep *rsep, GSList **caps);

gboolean a2dp_get_config(struct avdtp_stream *stream,
				struct ipc_data_cfg **cfg, int *fd);
