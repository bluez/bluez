/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#define AUDIO_HEADSET_INTERFACE "org.bluez.audio.Headset"

#define DEFAULT_HS_AG_CHANNEL 12
#define DEFAULT_HF_AG_CHANNEL 13

typedef enum {
	HEADSET_STATE_DISCONNECTED,
	HEADSET_STATE_CONNECT_IN_PROGRESS,
	HEADSET_STATE_CONNECTED,
	HEADSET_STATE_PLAY_IN_PROGRESS,
	HEADSET_STATE_PLAYING
} headset_state_t;

typedef enum {
	HEADSET_LOCK_READ = 1,
	HEADSET_LOCK_WRITE = 1 << 1,
} headset_lock_t;

typedef void (*headset_stream_cb_t) (struct device *dev, void *user_data);

struct headset *headset_init(struct device *dev, sdp_record_t *record,
				uint16_t svc);

void headset_free(struct device *dev);

uint32_t headset_config_init(GKeyFile *config);

void headset_update(struct device *dev, sdp_record_t *record, uint16_t svc);

unsigned int headset_request_stream(struct device *dev, headset_stream_cb_t cb,
					void *user_data);
gboolean headset_cancel_stream(struct device *dev, unsigned int id);

gboolean get_hfp_active(struct device *dev);
void set_hfp_active(struct device *dev, gboolean active);

int headset_connect_rfcomm(struct device *dev, int sock);
int headset_close_rfcomm(struct device *dev);

headset_state_t headset_get_state(struct device *dev);
void headset_set_state(struct device *dev, headset_state_t state);

int headset_get_channel(struct device *dev);

int headset_get_sco_fd(struct device *dev);

gboolean headset_is_active(struct device *dev);

gboolean headset_lock(struct device *dev, headset_lock_t lock);
gboolean headset_unlock(struct device *dev, headset_lock_t lock);
gboolean headset_suspend(struct device *dev, void *data);
gboolean headset_play(struct device *dev, void *data);
