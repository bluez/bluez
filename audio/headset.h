/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#define AUDIO_HEADSET_INTERFACE "org.bluez.Headset"

#define DEFAULT_HS_AG_CHANNEL 12
#define DEFAULT_HF_AG_CHANNEL 13

typedef enum {
	HEADSET_STATE_DISCONNECTED,
	HEADSET_STATE_CONNECTING,
	HEADSET_STATE_CONNECTED,
	HEADSET_STATE_PLAY_IN_PROGRESS,
	HEADSET_STATE_PLAYING
} headset_state_t;

typedef enum {
	HEADSET_LOCK_READ = 1,
	HEADSET_LOCK_WRITE = 1 << 1,
} headset_lock_t;

typedef void (*headset_state_cb) (struct audio_device *dev,
					headset_state_t old_state,
					headset_state_t new_state,
					void *user_data);
typedef void (*headset_nrec_cb) (struct audio_device *dev,
					gboolean nrec,
					void *user_data);

unsigned int headset_add_state_cb(headset_state_cb cb, void *user_data);
gboolean headset_remove_state_cb(unsigned int id);

typedef void (*headset_stream_cb_t) (struct audio_device *dev, void *user_data);

void headset_connect_cb(GIOChannel *chan, GError *err, gpointer user_data);

GIOChannel *headset_get_rfcomm(struct audio_device *dev);

struct headset *headset_init(struct audio_device *dev, uint16_t svc,
				const char *uuidstr);

void headset_unregister(struct audio_device *dev);

uint32_t headset_config_init(GKeyFile *config);

void headset_update(struct audio_device *dev, uint16_t svc,
			const char *uuidstr);

unsigned int headset_config_stream(struct audio_device *dev,
					gboolean auto_dc,
					headset_stream_cb_t cb,
					void *user_data);
unsigned int headset_request_stream(struct audio_device *dev,
					headset_stream_cb_t cb,
					void *user_data);
unsigned int headset_suspend_stream(struct audio_device *dev,
					headset_stream_cb_t cb,
					void *user_data);
gboolean headset_cancel_stream(struct audio_device *dev, unsigned int id);

gboolean get_hfp_active(struct audio_device *dev);
void set_hfp_active(struct audio_device *dev, gboolean active);

void headset_set_authorized(struct audio_device *dev);
int headset_connect_rfcomm(struct audio_device *dev, GIOChannel *chan);
int headset_connect_sco(struct audio_device *dev, GIOChannel *io);

headset_state_t headset_get_state(struct audio_device *dev);
void headset_set_state(struct audio_device *dev, headset_state_t state);

int headset_get_channel(struct audio_device *dev);

int headset_get_sco_fd(struct audio_device *dev);
gboolean headset_get_nrec(struct audio_device *dev);
unsigned int headset_add_nrec_cb(struct audio_device *dev,
					headset_nrec_cb cb, void *user_data);
gboolean headset_remove_nrec_cb(struct audio_device *dev, unsigned int id);
gboolean headset_get_inband(struct audio_device *dev);
gboolean headset_get_sco_hci(struct audio_device *dev);

gboolean headset_is_active(struct audio_device *dev);

headset_lock_t headset_get_lock(struct audio_device *dev);
gboolean headset_lock(struct audio_device *dev, headset_lock_t lock);
gboolean headset_unlock(struct audio_device *dev, headset_lock_t lock);
gboolean headset_suspend(struct audio_device *dev, void *data);
gboolean headset_play(struct audio_device *dev, void *data);
void headset_shutdown(struct audio_device *dev);
