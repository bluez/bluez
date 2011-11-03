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

/* player attributes */
#define AVRCP_ATTRIBUTE_ILEGAL		0x00
#define AVRCP_ATTRIBUTE_EQUALIZER	0x01
#define AVRCP_ATTRIBUTE_REPEAT_MODE	0x02
#define AVRCP_ATTRIBUTE_SHUFFLE		0x03
#define AVRCP_ATTRIBUTE_SCAN		0x04

/* equalizer values */
#define AVRCP_EQUALIZER_OFF		0x01
#define AVRCP_EQUALIZER_ON		0x02

/* repeat mode values */
#define AVRCP_REPEAT_MODE_OFF		0x01
#define AVRCP_REPEAT_MODE_SINGLE	0x02
#define AVRCP_REPEAT_MODE_ALL		0x03
#define AVRCP_REPEAT_MODE_GROUP		0x04

/* shuffle values */
#define AVRCP_SHUFFLE_OFF		0x01
#define AVRCP_SHUFFLE_ALL		0x02
#define AVRCP_SHUFFLE_GROUP		0x03

/* scan values */
#define AVRCP_SCAN_OFF			0x01
#define AVRCP_SCAN_ALL			0x02
#define AVRCP_SCAN_GROUP		0x03

/* media attributes */
#define AVRCP_MEDIA_ATTRIBUTE_ILLEGAL	0x00
#define AVRCP_MEDIA_ATTRIBUTE_TITLE	0x01
#define AVRCP_MEDIA_ATTRIBUTE_ARTIST	0x02
#define AVRCP_MEDIA_ATTRIBUTE_ALBUM	0x03
#define AVRCP_MEDIA_ATTRIBUTE_TRACK	0x04
#define AVRCP_MEDIA_ATTRIBUTE_N_TRACKS	0x05
#define AVRCP_MEDIA_ATTRIBUTE_GENRE	0x06
#define AVRCP_MEDIA_ATTRIBUTE_DURATION	0x07
#define AVRCP_MEDIA_ATTRIBUTE_LAST	AVRCP_MEDIA_ATTRIBUTE_DURATION

/* play status */
#define AVRCP_PLAY_STATUS_STOPPED	0x00
#define AVRCP_PLAY_STATUS_PLAYING	0x01
#define AVRCP_PLAY_STATUS_PAUSED	0x02
#define AVRCP_PLAY_STATUS_FWD_SEEK	0x03
#define AVRCP_PLAY_STATUS_REV_SEEK	0x04
#define AVRCP_PLAY_STATUS_ERROR		0xFF

/* Notification events */
#define AVRCP_EVENT_STATUS_CHANGED	0x01
#define AVRCP_EVENT_TRACK_CHANGED	0x02
#define AVRCP_EVENT_TRACK_REACHED_END	0x03
#define AVRCP_EVENT_TRACK_REACHED_START	0x04
#define AVRCP_EVENT_LAST		AVRCP_EVENT_TRACK_REACHED_START

struct avrcp_player_cb {
	int (*get_setting) (uint8_t attr, void *user_data);
	int (*set_setting) (uint8_t attr, uint8_t value, void *user_data);
	uint64_t (*get_uid) (void *user_data);
	void *(*get_metadata) (uint32_t id, void *user_data);
	GList *(*list_metadata) (void *user_data);
	uint8_t (*get_status) (void *user_data);
	uint32_t (*get_position) (void *user_data);
};

int avrcp_register(DBusConnection *conn, const bdaddr_t *src, GKeyFile *config);
void avrcp_unregister(const bdaddr_t *src);

gboolean avrcp_connect(struct audio_device *dev);
void avrcp_disconnect(struct audio_device *dev);

struct avrcp_player *avrcp_register_player(const bdaddr_t *src,
						struct avrcp_player_cb *cb,
						void *user_data,
						GDestroyNotify destroy);
void avrcp_unregister_player(struct avrcp_player *player);

int avrcp_player_event(struct avrcp_player *player, uint8_t id, void *data);
