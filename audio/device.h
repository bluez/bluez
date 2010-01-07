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

#define GENERIC_AUDIO_UUID	"00001203-0000-1000-8000-00805F9B34FB"

#define HSP_HS_UUID		"00001108-0000-1000-8000-00805F9B34FB"
#define HSP_AG_UUID		"00001112-0000-1000-8000-00805F9B34FB"

#define HFP_HS_UUID		"0000111E-0000-1000-8000-00805F9B34FB"
#define HFP_AG_UUID		"0000111F-0000-1000-8000-00805F9B34FB"

#define ADVANCED_AUDIO_UUID	"0000110D-0000-1000-8000-00805F9B34FB"

#define A2DP_SOURCE_UUID	"0000110A-0000-1000-8000-00805F9B34FB"
#define A2DP_SINK_UUID		"0000110B-0000-1000-8000-00805F9B34FB"

#define AVRCP_REMOTE_UUID	"0000110E-0000-1000-8000-00805F9B34FB"
#define AVRCP_TARGET_UUID	"0000110C-0000-1000-8000-00805F9B34FB"

/* Move these to respective .h files once they exist */
#define AUDIO_SOURCE_INTERFACE		"org.bluez.AudioSource"
#define AUDIO_CONTROL_INTERFACE		"org.bluez.Control"

struct source;
struct control;
struct target;
struct sink;
struct headset;
struct gateway;
struct dev_priv;

struct audio_device {
	struct btd_device *btd_dev;

	DBusConnection *conn;
	char *path;
	bdaddr_t src;
	bdaddr_t dst;

	gboolean auto_connect;

	struct headset *headset;
	struct gateway *gateway;
	struct sink *sink;
	struct source *source;
	struct control *control;
	struct target *target;

	guint hs_preauth_id;

	struct dev_priv *priv;
};

struct audio_device *audio_device_register(DBusConnection *conn,
					struct btd_device *device,
					const char *path, const bdaddr_t *src,
					const bdaddr_t *dst);

void audio_device_unregister(struct audio_device *device);

gboolean audio_device_is_active(struct audio_device *dev,
						const char *interface);

typedef void (*authorization_cb) (DBusError *derr, void *user_data);

int audio_device_cancel_authorization(struct audio_device *dev,
					authorization_cb cb, void *user_data);

int audio_device_request_authorization(struct audio_device *dev,
					const char *uuid, authorization_cb cb,
					void *user_data);

void audio_device_set_authorized(struct audio_device *dev, gboolean auth);
