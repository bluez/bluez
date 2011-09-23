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

#define AUDIO_GATEWAY_INTERFACE "org.bluez.HandsfreeGateway"

#define DEFAULT_HFP_HS_CHANNEL 7

typedef enum {
	GATEWAY_STATE_DISCONNECTED,
	GATEWAY_STATE_CONNECTING,
	GATEWAY_STATE_CONNECTED,
	GATEWAY_STATE_PLAYING,
} gateway_state_t;

typedef enum {
	GATEWAY_LOCK_READ = 1,
	GATEWAY_LOCK_WRITE = 1 << 1,
} gateway_lock_t;

typedef enum {
	GATEWAY_ERROR_DISCONNECTED,
	GATEWAY_ERROR_SUSPENDED,
} gateway_error_t;

#define GATEWAY_ERROR gateway_error_quark()

GQuark gateway_error_quark(void);

typedef void (*gateway_state_cb) (struct audio_device *dev,
					gateway_state_t old_state,
					gateway_state_t new_state,
					void *user_data);
typedef void (*gateway_stream_cb_t) (struct audio_device *dev, GError *err,
		void *user_data);

void gateway_set_state(struct audio_device *dev, gateway_state_t new_state);
void gateway_unregister(struct audio_device *dev);
struct gateway *gateway_init(struct audio_device *device);
gboolean gateway_is_active(struct audio_device *dev);
gboolean gateway_is_connected(struct audio_device *dev);
int gateway_connect_rfcomm(struct audio_device *dev, GIOChannel *io);
int gateway_connect_sco(struct audio_device *dev, GIOChannel *chan);
void gateway_start_service(struct audio_device *device);
unsigned int gateway_request_stream(struct audio_device *dev,
			gateway_stream_cb_t cb, void *user_data);
int gateway_config_stream(struct audio_device *dev, gateway_stream_cb_t cb,
			void *user_data);
gboolean gateway_cancel_stream(struct audio_device *dev, unsigned int id);
int gateway_get_sco_fd(struct audio_device *dev);
void gateway_suspend_stream(struct audio_device *dev);
unsigned int gateway_add_state_cb(gateway_state_cb cb, void *user_data);
gboolean gateway_remove_state_cb(unsigned int id);
gateway_lock_t gateway_get_lock(struct audio_device *dev);
gboolean gateway_lock(struct audio_device *dev, gateway_lock_t lock);
gboolean gateway_unlock(struct audio_device *dev, gateway_lock_t lock);
