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
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <dbus/dbus.h>

#include "ipc.h"
#include "device.h"

#define AUDIO_HEADSET_INTERFACE "org.bluez.audio.Headset"

#define DEFAULT_HS_AG_CHANNEL 12
#define DEFAULT_HF_AG_CHANNEL 13

typedef enum {
	HEADSET_EVENT_KEYPRESS,
	HEADSET_EVENT_GAIN,
	HEADSET_EVENT_UNKNOWN,
	HEADSET_EVENT_INVALID
} headset_event_t;

typedef enum {
	HEADSET_STATE_DISCONNECTED,
	HEADSET_STATE_CONNECT_IN_PROGRESS,
	HEADSET_STATE_CONNECTED,
	HEADSET_STATE_PLAY_IN_PROGRESS,
	HEADSET_STATE_PLAYING
} headset_state_t;

typedef enum {
	SVC_HEADSET,
	SVC_HANDSFREE
} headset_type_t;

struct headset *headset_init(struct device *dev, sdp_record_t *record,
				uint16_t svc);

void headset_free(struct device *dev);

void headset_update(struct device *dev, sdp_record_t *record, uint16_t svc);

int headset_get_config(struct device *dev, int sock, struct ipc_packet *pkt,
			int pkt_len, struct ipc_data_cfg **rsp, int *fd);

headset_type_t headset_get_type(struct device *dev);
void headset_set_type(struct device *dev, headset_type_t type);

int headset_connect_rfcomm(struct device *dev, int sock);
int headset_close_rfcomm(struct device *dev);

headset_state_t headset_get_state(struct device *dev);
void headset_set_state(struct device *dev, headset_state_t state);

int headset_get_channel(struct device *dev);

gboolean headset_is_active(struct device *dev);
