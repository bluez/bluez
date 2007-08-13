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

#define AUDIO_SINK_INTERFACE "org.bluez.audio.Sink"

struct sink *sink_init(struct device *dev);
void sink_free(struct device *dev);
int sink_get_config(struct device *dev, int sock, struct ipc_packet *req,
			int pkt_len, struct ipc_data_cfg **rsp, int *fd);
gboolean sink_is_active(struct device *dev);
void sink_set_state(struct device *dev, avdtp_state_t state);
avdtp_state_t sink_get_state(struct device *dev);
gboolean sink_new_stream(struct device *dev, struct avdtp *session,
				struct avdtp_stream *stream);
