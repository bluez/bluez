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

#define AUDIO_DEVICE_INTERFACE	"org.bluez.audio.Device"

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
#define AUDIO_SOURCE_INTERFACE		"org.bluez.audio.Source"
#define AUDIO_CONTROL_INTERFACE		"org.bluez.audio.Control"
#define AUDIO_TARGET_INTERFACE		"org.bluez.audio.Target"

struct source;
struct control;
struct target;
struct sink;
struct headset;
struct gateway;

struct audio_device {
	DBusConnection *conn;
	char *adapter_path;
	char *path;
	char *name;
	bdaddr_t store;
	bdaddr_t src;
	bdaddr_t dst;

	struct headset *headset;
	struct gateway *gateway;
	struct sink *sink;
	struct source *source;
	struct control *control;
	struct target *target;
};

struct audio_device *device_register(DBusConnection *conn,
					const char *path, const bdaddr_t *bda);

int device_store(struct audio_device *device, gboolean is_default);

int device_remove_stored(struct audio_device *dev);

void device_finish_sdp_transaction(struct audio_device *device);

uint8_t device_get_state(struct audio_device *dev);

gboolean device_is_connected(struct audio_device *dev, const char *interface);
