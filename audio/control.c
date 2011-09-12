/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2011  Texas Instruments, Inc.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "log.h"
#include "error.h"
#include "device.h"
#include "manager.h"
#include "avctp.h"
#include "control.h"
#include "sdpd.h"
#include "glib-helper.h"
#include "dbus-common.h"

/* Company IDs for vendor dependent commands */
#define IEEEID_BTSIG		0x001958

/* Error codes for metadata transfer */
#define E_INVALID_COMMAND	0x00
#define E_INVALID_PARAM		0x01
#define E_PARAM_NOT_FOUND	0x02
#define E_INTERNAL		0x03

/* PDU types for metadata transfer */
#define AVRCP_GET_CAPABILITIES		0x10
#define AVRCP_LIST_PLAYER_ATTRIBUTES	0X11
#define AVRCP_LIST_PLAYER_VALUES	0x12
#define AVRCP_GET_CURRENT_PLAYER_VALUE	0x13
#define AVRCP_SET_PLAYER_VALUE		0x14
#define AVRCP_GET_PLAYER_ATTRIBUTE_TEXT	0x15
#define AVRCP_GET_PLAYER_VALUE_TEXT	0x16
#define AVRCP_DISPLAYABLE_CHARSET	0x17
#define AVRCP_CT_BATTERY_STATUS		0x18
#define AVRCP_GET_ELEMENT_ATTRIBUTES	0x20
#define AVRCP_GET_PLAY_STATUS		0x30
#define AVRCP_REGISTER_NOTIFICATION	0x31

/* Notification events */
#define AVRCP_EVENT_PLAYBACK_STATUS_CHANGED		0x01
#define AVRCP_EVENT_TRACK_CHANGED			0x02

/* Capabilities for AVRCP_GET_CAPABILITIES pdu */
#define CAP_COMPANY_ID		0x02
#define CAP_EVENTS_SUPPORTED	0x03

enum player_setting {
	PLAYER_SETTING_EQUALIZER =	1,
	PLAYER_SETTING_REPEAT =		2,
	PLAYER_SETTING_SHUFFLE =	3,
	PLAYER_SETTING_SCAN =		4,
};

enum equalizer_mode {
	EQUALIZER_MODE_OFF =	1,
	EQUALIZER_MODE_ON =	2,
};

enum repeat_mode {
	REPEAT_MODE_OFF =	1,
	REPEAT_MODE_SINGLE =	2,
	REPEAT_MODE_ALL =	3,
	REPEAT_MODE_GROUP =	4,
};

enum shuffle_mode {
	SHUFFLE_MODE_OFF =	1,
	SHUFFLE_MODE_ALL =	2,
	SHUFFLE_MODE_GROUP =	3,
};

enum scan_mode {
	SCAN_MODE_OFF =		1,
	SCAN_MODE_ALL =		2,
	SCAN_MODE_GROUP =	3,
};

enum play_status {
	PLAY_STATUS_STOPPED =		0x00,
	PLAY_STATUS_PLAYING =		0x01,
	PLAY_STATUS_PAUSED =		0x02,
	PLAY_STATUS_FWD_SEEK =		0x03,
	PLAY_STATUS_REV_SEEK =		0x04,
	PLAY_STATUS_ERROR =		0xFF
};

enum battery_status {
	BATTERY_STATUS_NORMAL =		0,
	BATTERY_STATUS_WARNING =	1,
	BATTERY_STATUS_CRITICAL =	2,
	BATTERY_STATUS_EXTERNAL =	3,
	BATTERY_STATUS_FULL_CHARGE =	4,
};

enum media_info_id {
	MEDIA_INFO_TITLE =		1,
	MEDIA_INFO_ARTIST =		2,
	MEDIA_INFO_ALBUM =		3,
	MEDIA_INFO_TRACK =		4,
	MEDIA_INFO_N_TRACKS =		5,
	MEDIA_INFO_GENRE =		6,
	MEDIA_INFO_CURRENT_POSITION =	7,
};

static DBusConnection *connection = NULL;

static GSList *servers = NULL;
static unsigned int avctp_id = 0;

#if __BYTE_ORDER == __LITTLE_ENDIAN

struct avrcp_header {
	uint8_t company_id[3];
	uint8_t pdu_id;
	uint8_t packet_type:2;
	uint8_t rsvd:6;
	uint16_t params_len;
	uint8_t params[0];
} __attribute__ ((packed));
#define AVRCP_HEADER_LENGTH 7

#elif __BYTE_ORDER == __BIG_ENDIAN

struct avrcp_header {
	uint8_t company_id[3];
	uint8_t pdu_id;
	uint8_t rsvd:6;
	uint8_t packet_type:2;
	uint16_t params_len;
	uint8_t params[0];
} __attribute__ ((packed));
#define AVRCP_HEADER_LENGTH 7

#else
#error "Unknown byte order"
#endif

struct avrcp_server {
	bdaddr_t src;
	uint32_t tg_record_id;
	uint32_t ct_record_id;
};

struct media_info {
	char *title;
	char *artist;
	char *album;
	char *genre;
	uint32_t ntracks;
	uint32_t track;
	uint32_t track_len;
	uint32_t elapsed;
};

struct media_player {
	uint8_t settings[PLAYER_SETTING_SCAN + 1];
	enum play_status status;

	struct media_info mi;
	GTimer *timer;
	unsigned int handler;
};

struct control {
	struct audio_device *dev;
	struct media_player *mp;
	struct avctp *session;

	gboolean target;

	uint16_t registered_events;
	uint8_t transaction_events[AVRCP_EVENT_TRACK_CHANGED + 1];
};

/* Company IDs supported by this device */
static uint32_t company_ids[] = {
	IEEEID_BTSIG,
};

static sdp_record_t *avrcp_ct_record(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avctp, avrct;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVCTP_PSM;
	uint16_t avrcp_ver = 0x0100, avctp_ver = 0x0103, feat = 0x000f;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	/* Service Class ID List */
	sdp_uuid16_create(&avrct, AV_REMOTE_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &avrct);
	sdp_set_service_classes(record, svclass_id);

	/* Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&avctp, AVCTP_UUID);
	proto[1] = sdp_list_append(0, &avctp);
	version = sdp_data_alloc(SDP_UINT16, &avctp_ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile[0].uuid, AV_REMOTE_PROFILE_ID);
	profile[0].version = avrcp_ver;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(record, "AVRCP CT", 0, 0);

	free(psm);
	free(version);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

static sdp_record_t *avrcp_tg_record(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avctp, avrtg;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVCTP_PSM;
	uint16_t avrcp_ver = 0x0103, avctp_ver = 0x0103, feat = 0x000f;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	/* Service Class ID List */
	sdp_uuid16_create(&avrtg, AV_REMOTE_TARGET_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &avrtg);
	sdp_set_service_classes(record, svclass_id);

	/* Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&avctp, AVCTP_UUID);
	proto[1] = sdp_list_append(0, &avctp);
	version = sdp_data_alloc(SDP_UINT16, &avctp_ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile[0].uuid, AV_REMOTE_PROFILE_ID);
	profile[0].version = avrcp_ver;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(record, "AVRCP TG", 0, 0);

	free(psm);
	free(version);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

static unsigned int attr_get_max_val(uint8_t attr)
{
	switch (attr) {
	case PLAYER_SETTING_EQUALIZER:
		return EQUALIZER_MODE_ON;
	case PLAYER_SETTING_REPEAT:
		return REPEAT_MODE_GROUP;
	case PLAYER_SETTING_SHUFFLE:
		return SHUFFLE_MODE_GROUP;
	case PLAYER_SETTING_SCAN:
		return SCAN_MODE_GROUP;
	}

	return 0;
}

static const char *attrval_to_str(uint8_t attr, uint8_t value)
{
	switch (attr) {
	case PLAYER_SETTING_EQUALIZER:
		switch (value) {
		case EQUALIZER_MODE_ON:
			return "on";
		case EQUALIZER_MODE_OFF:
			return "off";
		}

		break;
	case PLAYER_SETTING_REPEAT:
		switch (value) {
		case REPEAT_MODE_OFF:
			return "off";
		case REPEAT_MODE_SINGLE:
			return "singletrack";
		case REPEAT_MODE_ALL:
			return "alltracks";
		case REPEAT_MODE_GROUP:
			return "group";
		}

		break;
	/* Shuffle and scan have the same values */
	case PLAYER_SETTING_SHUFFLE:
	case PLAYER_SETTING_SCAN:
		switch (value) {
		case SCAN_MODE_OFF:
			return "off";
		case SCAN_MODE_ALL:
			return "alltracks";
		case SCAN_MODE_GROUP:
			return "group";
		}

		break;
	}

	return NULL;
}

static int attrval_to_val(uint8_t attr, const char *value)
{
	int ret;

	switch (attr) {
	case PLAYER_SETTING_EQUALIZER:
		if (!strcmp(value, "off"))
			ret = EQUALIZER_MODE_OFF;
		else if (!strcmp(value, "on"))
			ret = EQUALIZER_MODE_ON;
		else
			ret = -EINVAL;

		return ret;
	case PLAYER_SETTING_REPEAT:
		if (!strcmp(value, "off"))
			ret = REPEAT_MODE_OFF;
		else if (!strcmp(value, "singletrack"))
			ret = REPEAT_MODE_SINGLE;
		else if (!strcmp(value, "alltracks"))
			ret = REPEAT_MODE_ALL;
		else if (!strcmp(value, "group"))
			ret = REPEAT_MODE_GROUP;
		else
			ret = -EINVAL;

		return ret;
	case PLAYER_SETTING_SHUFFLE:
		if (!strcmp(value, "off"))
			ret = SHUFFLE_MODE_OFF;
		else if (!strcmp(value, "alltracks"))
			ret = SHUFFLE_MODE_ALL;
		else if (!strcmp(value, "group"))
			ret = SHUFFLE_MODE_GROUP;
		else
			ret = -EINVAL;

		return ret;
	case PLAYER_SETTING_SCAN:
		if (!strcmp(value, "off"))
			ret = SCAN_MODE_OFF;
		else if (!strcmp(value, "alltracks"))
			ret = SCAN_MODE_ALL;
		else if (!strcmp(value, "group"))
			ret = SCAN_MODE_GROUP;
		else
			ret = -EINVAL;

		return ret;
	}

	return -EINVAL;
}

static const char *attr_to_str(uint8_t attr)
{
	switch (attr) {
	case PLAYER_SETTING_EQUALIZER:
		return "Equalizer";
	case PLAYER_SETTING_REPEAT:
		return "Repeat";
	case PLAYER_SETTING_SHUFFLE:
		return "Shuffle";
	case PLAYER_SETTING_SCAN:
		return "Scan";
	}

	return NULL;
}

static int attr_to_val(const char *str)
{
	if (!strcmp(str, "Equalizer"))
		return PLAYER_SETTING_EQUALIZER;
	else if (!strcmp(str, "Repeat"))
		return PLAYER_SETTING_REPEAT;
	else if (!strcmp(str, "Shuffle"))
		return PLAYER_SETTING_SHUFFLE;
	else if (!strcmp(str, "Scan"))
		return PLAYER_SETTING_SCAN;

	return -EINVAL;
}

static int play_status_to_val(const char *status)
{
	if (!strcmp(status, "stopped"))
		return PLAY_STATUS_STOPPED;
	else if (!strcmp(status, "playing"))
		return PLAY_STATUS_PLAYING;
	else if (!strcmp(status, "paused"))
		return PLAY_STATUS_PAUSED;
	else if (!strcmp(status, "forward-seek"))
		return PLAY_STATUS_FWD_SEEK;
	else if (!strcmp(status, "reverse-seek"))
		return PLAY_STATUS_REV_SEEK;
	else if (!strcmp(status, "error"))
		return PLAY_STATUS_ERROR;

	return -EINVAL;
}

static const char *battery_status_to_str(enum battery_status status)
{
	switch (status) {
	case BATTERY_STATUS_NORMAL:
		return "normal";
	case BATTERY_STATUS_WARNING:
		return "warning";
	case BATTERY_STATUS_CRITICAL:
		return "critical";
	case BATTERY_STATUS_EXTERNAL:
		return "external";
	case BATTERY_STATUS_FULL_CHARGE:
		return "fullcharge";
	}

	return NULL;
}

static int avrcp_send_event(struct control *control, uint8_t id, void *data)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + 9];
	struct avrcp_header *pdu = (void *) buf;
	uint16_t size;
	int err;

	if (control->session)
		return -ENOTCONN;

	if (!(control->registered_events & (1 << id)))
		return 0;

	memset(buf, 0, sizeof(buf));

	pdu->company_id[0] = IEEEID_BTSIG >> 16;
	pdu->company_id[1] = (IEEEID_BTSIG >> 8) & 0xFF;
	pdu->company_id[2] = IEEEID_BTSIG & 0xFF;

	pdu->pdu_id = AVRCP_REGISTER_NOTIFICATION;
	pdu->params[0] = id;

	DBG("id=%u", id);

	switch (id) {
	case AVRCP_EVENT_PLAYBACK_STATUS_CHANGED:
		size = 2;
		pdu->params[1] = *((uint8_t *)data);

		break;
	case AVRCP_EVENT_TRACK_CHANGED: {
		size = 9;

		/*
		 * AVRCP 1.3 supports only one track identifier: PLAYING
		 * (0x0). When 1.4 version is added, this shall be changed to
		 * contain the identifier of the track.
		 */
		memset(&pdu->params[1], 0, 8);

		break;
	}
	default:
		error("Unknown event %u", id);
		return -EINVAL;
	}

	pdu->params_len = htons(size);

	err = avctp_send_vendordep(control->session, control->transaction_events[id],
					AVC_CTYPE_CHANGED, AVC_SUBUNIT_PANEL,
					buf, size);
	if (err < 0)
		return err;

	/* Unregister event as per AVRCP 1.3 spec, section 5.4.2 */
	control->registered_events ^= 1 << id;

	return 0;
}

static void mp_get_playback_status(struct media_player *mp, uint8_t *status,
					uint32_t *elapsed, uint32_t *track_len)
{
	if (status)
		*status = mp->status;
	if (track_len)
		*track_len = mp->mi.track_len;

	if (!elapsed)
		return;

	*elapsed = mp->mi.elapsed;

	if (mp->status == PLAY_STATUS_PLAYING) {
		double timedelta = g_timer_elapsed(mp->timer, NULL);
		uint32_t sec, msec;

		sec = (uint32_t) timedelta;
		msec = (uint32_t)((timedelta - sec) * 1000);

		*elapsed += sec * 1000 + msec;
	}
}

static void mp_set_playback_status(struct control *control, uint8_t status,
							uint32_t elapsed)
{
	struct media_player *mp = control->mp;

	DBG("Change playback: %u %u", status, elapsed);

	mp->mi.elapsed = elapsed;
	g_timer_start(mp->timer);

	if (status == mp->status)
		return;

	mp->status = status;

	avrcp_send_event(control, AVRCP_EVENT_PLAYBACK_STATUS_CHANGED,
								&status);
}

/*
 * Copy media_info field to a buffer, intended to be used in a response to
 * GetElementAttributes message.
 *
 * It assumes there's enough space in the buffer and on success it returns the
 * size written.
 *
 * If @param id is not valid, -EINVAL is returned. If there's no such media
 * attribute, -ENOENT is returned.
 */
static int mp_get_media_attribute(struct media_player *mp,
						uint32_t id, uint8_t *buf)
{
	struct media_info_elem {
		uint32_t id;
		uint16_t charset;
		uint16_t len;
		uint8_t val[];
	};
	const struct media_info *mi = &mp->mi;
	struct media_info_elem *elem = (void *)buf;
	uint16_t len;
	char valstr[20];

	switch (id) {
	case MEDIA_INFO_TITLE:
		if (mi->title) {
			len = strlen(mi->title);
			memcpy(elem->val, mi->title, len);
		} else {
			len = 0;
		}

		break;
	case MEDIA_INFO_ARTIST:
		if (mi->artist == NULL)
			return -ENOENT;

		len = strlen(mi->artist);
		memcpy(elem->val, mi->artist, len);
		break;
	case MEDIA_INFO_ALBUM:
		if (mi->album == NULL)
			return -ENOENT;

		len = strlen(mi->album);
		memcpy(elem->val, mi->album, len);
		break;
	case MEDIA_INFO_GENRE:
		if (mi->genre == NULL)
			return -ENOENT;

		len = strlen(mi->genre);
		memcpy(elem->val, mi->genre, len);
		break;

	case MEDIA_INFO_TRACK:
		if (!mi->track)
			return -ENOENT;

		snprintf(valstr, 20, "%u", mi->track);
		len = strlen(valstr);
		memcpy(elem->val, valstr, len);
		break;
	case MEDIA_INFO_N_TRACKS:
		if (!mi->ntracks)
			return -ENOENT;

		snprintf(valstr, 20, "%u", mi->ntracks);
		len = strlen(valstr);
		memcpy(elem->val, valstr, len);
		break;
	case MEDIA_INFO_CURRENT_POSITION:
		if (mi->elapsed != 0xFFFFFFFF) {
			uint32_t elapsed;

			mp_get_playback_status(mp, NULL, &elapsed, NULL);

			snprintf(valstr, 20, "%u", elapsed);
			len = strlen(valstr);
			memcpy(elem->val, valstr, len);
		} else {
			return -ENOENT;
		}

		break;
	default:
		return -EINVAL;
	}

	elem->id = htonl(id);
	elem->charset = htons(0x6A); /* Always use UTF-8 */
	elem->len = htons(len);

	return sizeof(struct media_info_elem) + len;
}

static void mp_set_attribute(struct media_player *mp,
						uint8_t attr, uint8_t val)
{
	DBG("Change attribute: %u %u", attr, val);

	mp->settings[attr] = val;
}

static int mp_get_attribute(struct media_player *mp, uint8_t attr)
{
	DBG("Get attribute: %u", attr);

	return mp->settings[attr];
}

static void mp_set_media_attributes(struct control *control,
							struct media_info *mi)
{
	struct media_player *mp = control->mp;

	g_free(mp->mi.title);
	mp->mi.title = g_strdup(mi->title);

	g_free(mp->mi.artist);
	mp->mi.artist = g_strdup(mi->artist);

	g_free(mp->mi.album);
	mp->mi.album = g_strdup(mi->album);

	g_free(mp->mi.genre);
	mp->mi.genre = g_strdup(mi->genre);

	mp->mi.ntracks = mi->ntracks;
	mp->mi.track = mi->track;
	mp->mi.track_len = mi->track_len;

	/*
	 * elapsed is special. Whenever the track changes, we reset it to 0,
	 * so client doesn't have to make another call to change_playback
	 */
	mp->mi.elapsed = 0;
	g_timer_start(mp->timer);

	DBG("Track changed:\n\ttitle: %s\n\tartist: %s\n\talbum: %s\n"
			"\tgenre: %s\n\tNumber of tracks: %u\n"
			"\tTrack number: %u\n\tTrack duration: %u",
			mi->title, mi->artist, mi->album, mi->genre,
			mi->ntracks, mi->track, mi->track_len);

	avrcp_send_event(control, AVRCP_EVENT_TRACK_CHANGED, NULL);
}

static uint8_t avrcp_handle_get_capabilities(struct control *control,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	unsigned int i;

	if (len != 1)
		goto err;

	DBG("id=%u", pdu->params[0]);

	switch (pdu->params[0]) {
	case CAP_COMPANY_ID:
		for (i = 0; i < G_N_ELEMENTS(company_ids); i++) {
			pdu->params[2 + i * 3] = company_ids[i] >> 16;
			pdu->params[3 + i * 3] = (company_ids[i] >> 8) & 0xFF;
			pdu->params[4 + i * 3] = company_ids[i] & 0xFF;
		}

		pdu->params_len = htons(2 + (3 * G_N_ELEMENTS(company_ids)));
		pdu->params[1] = G_N_ELEMENTS(company_ids);

		return AVC_CTYPE_STABLE;
	case CAP_EVENTS_SUPPORTED:
		pdu->params_len = htons(4);
		pdu->params[1] = 2;
		pdu->params[2] = AVRCP_EVENT_PLAYBACK_STATUS_CHANGED;
		pdu->params[3] = AVRCP_EVENT_TRACK_CHANGED;

		return AVC_CTYPE_STABLE;
	}

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;

	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_list_player_attributes(struct control *control,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	struct media_player *mp = control->mp;
	unsigned int i;

	if (len != 0) {
		pdu->params_len = htons(1);
		pdu->params[0] = E_INVALID_PARAM;
		return AVC_CTYPE_REJECTED;
	}

	if (!mp)
		goto done;

	for (i = 1; i <= PLAYER_SETTING_SCAN; i++) {
		if (!mp_get_attribute(mp, i)) {
			DBG("Ignoring setting %u: not supported by player", i);
			continue;
		}

		len++;
		pdu->params[len] = i;
	}

done:
	pdu->params[0] = len;
	pdu->params_len = htons(len + 1);

	return AVC_CTYPE_STABLE;
}

static uint8_t avrcp_handle_list_player_values(struct control *control,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	struct media_player *mp = control->mp;
	unsigned int i;

	if (len != 1 || !mp)
		goto err;

	len = attr_get_max_val(pdu->params[0]);
	if (!len) {
		error("Attribute is invalid: %u", pdu->params[0]);
		goto err;
	}

	for (i = 1; i <= len; i++)
		pdu->params[i] = i;

	pdu->params[0] = len;
	pdu->params_len = htons(len + 1);

	return AVC_CTYPE_STABLE;

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_get_element_attributes(struct control *control,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	uint64_t *identifier = (void *) &pdu->params[0];
	uint16_t pos;
	uint8_t nattr;
	int size;
	unsigned int i;

	if (len < 8 || *identifier != 0 || !control->mp)
		goto err;

	len = 0;
	pos = 1; /* Keep track of current position in reponse */
	nattr = pdu->params[8];

	if (!control->mp)
		goto done;

	if (!nattr) {
		/*
		 * Return all available information, at least
		 * title must be returned.
		 */
		for (i = 1; i <= MEDIA_INFO_CURRENT_POSITION; i++) {
			size = mp_get_media_attribute(control->mp, i,
							&pdu->params[pos]);

			if (size > 0) {
				len++;
				pos += size;
			}
		}
	} else {
		uint32_t *attr_ids;

		attr_ids = g_memdup(&pdu->params[9], sizeof(uint32_t) * nattr);

		for (i = 0; i < nattr; i++) {
			uint32_t attr = ntohl(attr_ids[i]);

			size = mp_get_media_attribute(control->mp, attr,
							&pdu->params[pos]);

			if (size > 0) {
				len++;
				pos += size;
			}
		}

		g_free(attr_ids);

		if (!len)
			goto err;
	}

done:
	pdu->params[0] = len;
	pdu->params_len = htons(pos);

	return AVC_CTYPE_STABLE;
err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_get_current_player_value(struct control *control,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	struct media_player *mp = control->mp;
	uint8_t *settings;
	unsigned int i;

	if (mp == NULL || len <= 1 || pdu->params[0] != len - 1)
		goto err;

	/*
	 * Save a copy of requested settings because we can override them
	 * while responding
	 */
	settings = g_malloc(pdu->params[0]);
	memcpy(settings, &pdu->params[1], pdu->params[0]);
	len = 0;

	/*
	 * From sec. 5.7 of AVRCP 1.3 spec, we should igore non-existent IDs
	 * and send a response with the existent ones. Only if all IDs are
	 * non-existent we should send an error.
	 */
	for (i = 0; i < pdu->params[0]; i++) {
		uint8_t val;

		if (settings[i] < PLAYER_SETTING_EQUALIZER ||
					settings[i] > PLAYER_SETTING_SCAN) {
			DBG("Ignoring %u", settings[i]);
			continue;
		}

		val = mp_get_attribute(mp, settings[i]);
		if (!val) {
			DBG("Ignoring %u: not supported by player",
								settings[i]);
			continue;
		}

		pdu->params[len] = settings[i];
		pdu->params[len + 1] = val;
		len += 2;
	}

	g_free(settings);

	if (len) {
		pdu->params[0] = len;
		pdu->params_len = htons(2 * len + 1);

		return AVC_CTYPE_STABLE;
	}

	error("No valid attributes in request");

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;

	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_set_player_value(struct control *control,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	unsigned int i;

	if (len < 3 || !control->mp)
		goto err;

	len = 0;

	/*
	 * From sec. 5.7 of AVRCP 1.3 spec, we should igore non-existent IDs
	 * and set the existent ones. Sec. 5.2.4 is not clear however how to
	 * indicate that a certain ID was not accepted. If at least one
	 * attribute is valid, we respond with no parameters. Otherwise an
	 * E_INVALID_PARAM is sent.
	 */
	for (i = 1; i < pdu->params[0]; i += 2) {
		uint8_t attr = pdu->params[i];
		uint8_t val = pdu->params[i + 1];
		const char *attrstr;
		const char *valstr;

		attrstr = attr_to_str(attr);
		if (!attrstr)
			continue;

		valstr = attrval_to_str(attr, val);
		if (!valstr)
			continue;

		len++;

		mp_set_attribute(control->mp, attr, val);
		emit_property_changed(control->dev->conn, control->dev->path,
					MEDIA_PLAYER_INTERFACE, attrstr,
					DBUS_TYPE_STRING, &valstr);
	}

	if (len) {
		pdu->params_len = 0;

		return AVC_CTYPE_STABLE;
	}

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_displayable_charset(struct control *control,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);

	if (len < 3) {
		pdu->params_len = htons(1);
		pdu->params[0] = E_INVALID_PARAM;
		return AVC_CTYPE_REJECTED;
	}

	/*
	 * We acknowledge the commands, but we always use UTF-8 for
	 * encoding since CT is obliged to support it.
	 */
	pdu->params_len = 0;
	return AVC_CTYPE_STABLE;
}

static uint8_t avrcp_handle_ct_battery_status(struct control *control,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	const char *valstr;

	if (len != 1)
		goto err;

	valstr = battery_status_to_str(pdu->params[0]);
	if (valstr == NULL)
		goto err;

	emit_property_changed(control->dev->conn, control->dev->path,
					MEDIA_PLAYER_INTERFACE, "Battery",
					DBUS_TYPE_STRING, &valstr);
	pdu->params_len = 0;

	return AVC_CTYPE_STABLE;

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_get_play_status(struct control *control,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	uint32_t elapsed;
	uint32_t track_len;
	uint8_t status;

	if (len != 0) {
		pdu->params_len = htons(1);
		pdu->params[0] = E_INVALID_PARAM;
		return AVC_CTYPE_REJECTED;
	}

	if (control->mp) {
		mp_get_playback_status(control->mp, &status,
							&elapsed, &track_len);
		track_len = htonl(track_len);
		elapsed = htonl(elapsed);
	} else {
		track_len = 0xFFFFFFFF;
		elapsed = 0xFFFFFFFF;
		status = PLAY_STATUS_ERROR;
	}

	memcpy(&pdu->params[0], &track_len, 4);
	memcpy(&pdu->params[4], &elapsed, 4);
	pdu->params[8] = status;

	pdu->params_len = htons(9);

	return AVC_CTYPE_STABLE;
}

static uint8_t avrcp_handle_register_notification(struct control *control,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	uint8_t status;

	/*
	 * 1 byte for EventID, 4 bytes for Playback interval but the latest
	 * one is applicable only for EVENT_PLAYBACK_POS_CHANGED. See AVRCP
	 * 1.3 spec, section 5.4.2.
	 */
	if (len != 5)
		goto err;

	switch (pdu->params[0]) {
	case AVRCP_EVENT_PLAYBACK_STATUS_CHANGED:
		len = 2;
		if (control->mp) {
			mp_get_playback_status(control->mp, &status,
								NULL, NULL);
			pdu->params[1] = status;
		} else {
			pdu->params[1] = PLAY_STATUS_ERROR;
		}

		break;
	case AVRCP_EVENT_TRACK_CHANGED:
		len = 9;

		if (!control->mp)
			memset(&pdu->params[1], 0xFF, 8);
		else
			memset(&pdu->params[1], 0, 8);

		break;
	default:
		/* All other events are not supported yet */
		goto err;
	}

	/* Register event and save the transaction used */
	control->registered_events |= (1 << pdu->params[0]);
	control->transaction_events[pdu->params[0]] = transaction;

	pdu->params_len = htons(len);

	return AVC_CTYPE_INTERIM;

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static struct pdu_handler {
	uint8_t pdu_id;
	uint8_t code;
	uint8_t (*func) (struct control *control,
					struct avrcp_header *pdu,
					uint8_t transaction);
} handlers[] = {
		{ AVRCP_GET_CAPABILITIES, AVC_CTYPE_STATUS,
					avrcp_handle_get_capabilities },
		{ AVRCP_LIST_PLAYER_ATTRIBUTES, AVC_CTYPE_STATUS,
					avrcp_handle_list_player_attributes },
		{ AVRCP_LIST_PLAYER_VALUES, AVC_CTYPE_STATUS,
					avrcp_handle_list_player_values },
		{ AVRCP_GET_ELEMENT_ATTRIBUTES, AVC_CTYPE_STATUS,
					avrcp_handle_get_element_attributes },
		{ AVRCP_GET_CURRENT_PLAYER_VALUE, AVC_CTYPE_STATUS,
					avrcp_handle_get_current_player_value },
		{ AVRCP_SET_PLAYER_VALUE, AVC_CTYPE_CONTROL,
					avrcp_handle_set_player_value },
		{ AVRCP_GET_PLAYER_ATTRIBUTE_TEXT, AVC_CTYPE_STATUS,
					NULL },
		{ AVRCP_GET_PLAYER_VALUE_TEXT, AVC_CTYPE_STATUS,
					NULL },
		{ AVRCP_DISPLAYABLE_CHARSET, AVC_CTYPE_STATUS,
					avrcp_handle_displayable_charset },
		{ AVRCP_CT_BATTERY_STATUS, AVC_CTYPE_STATUS,
					avrcp_handle_ct_battery_status },
		{ AVRCP_GET_PLAY_STATUS, AVC_CTYPE_STATUS,
					avrcp_handle_get_play_status },
		{ AVRCP_REGISTER_NOTIFICATION, AVC_CTYPE_NOTIFY,
					avrcp_handle_register_notification },
		{ },
};

/* handle vendordep pdu inside an avctp packet */
static size_t handle_vendordep_pdu(struct avctp *session, uint8_t transaction,
					uint8_t *code, uint8_t *subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct control *control = user_data;
	struct pdu_handler *handler;
	struct avrcp_header *pdu = (void *) operands;
	uint32_t company_id = (pdu->company_id[0] << 16) |
				(pdu->company_id[1] << 8) |
				(pdu->company_id[2]);

	if (company_id != IEEEID_BTSIG) {
		*code = AVC_CTYPE_NOT_IMPLEMENTED;
		return 0;
	}

	DBG("AVRCP PDU 0x%02X, company 0x%06X len 0x%04X",
			pdu->pdu_id, company_id, pdu->params_len);

	pdu->packet_type = 0;
	pdu->rsvd = 0;

	if (operand_count + 3 < AVRCP_HEADER_LENGTH)
		goto err_metadata;

	for (handler = handlers; handler; handler++) {
		if (handler->pdu_id == pdu->pdu_id)
			break;
	}

	if (!handler || handler->code != *code) {
		pdu->params[0] = E_INVALID_COMMAND;
		goto err_metadata;
	}

	if (!handler->func) {
		pdu->params[0] = E_INVALID_PARAM;
		goto err_metadata;
	}

	*code = handler->func(control, pdu, transaction);

	return AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);

err_metadata:
	pdu->params_len = htons(1);
	*code = AVC_CTYPE_REJECTED;

	return AVRCP_HEADER_LENGTH + 1;
}

static void state_changed(struct audio_device *dev, avctp_state_t old_state,
				avctp_state_t new_state, void *user_data)
{
	struct control *control = dev->control;
	gboolean value;

	switch (new_state) {
	case AVCTP_STATE_DISCONNECTED:
		control->session = NULL;

		if (control->mp && control->mp->handler) {
			avctp_unregister_pdu_handler(control->mp->handler);
			control->mp->handler = 0;
		}

		if (old_state != AVCTP_STATE_CONNECTED)
			break;

		value = FALSE;
		g_dbus_emit_signal(dev->conn, dev->path,
					AUDIO_CONTROL_INTERFACE,
					"Disconnected", DBUS_TYPE_INVALID);
		emit_property_changed(dev->conn, dev->path,
					AUDIO_CONTROL_INTERFACE, "Connected",
					DBUS_TYPE_BOOLEAN, &value);

		break;
	case AVCTP_STATE_CONNECTING:
		if (control->session)
			break;

		control->session = avctp_connect(&dev->src, &dev->dst);
		if (!control->mp)
			break;

		control->mp->handler = avctp_register_pdu_handler(
							AVC_OP_VENDORDEP,
							handle_vendordep_pdu,
							control);
		break;
	case AVCTP_STATE_CONNECTED:
		value = TRUE;
		g_dbus_emit_signal(dev->conn, dev->path,
				AUDIO_CONTROL_INTERFACE, "Connected",
				DBUS_TYPE_INVALID);
		emit_property_changed(dev->conn, dev->path,
				AUDIO_CONTROL_INTERFACE, "Connected",
				DBUS_TYPE_BOOLEAN, &value);
		break;
	default:
		return;
	}
}

static void media_info_init(struct media_info *mi)
{
	memset(mi, 0, sizeof(*mi));

	/*
	 * As per section 5.4.1 of AVRCP 1.3 spec, return 0xFFFFFFFF if TG
	 * does not support these attributes (i.e. they were never set via
	 * D-Bus)
	 */
	mi->track_len = 0xFFFFFFFF;
	mi->elapsed = 0xFFFFFFFF;
}

gboolean avrcp_connect(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (control->session)
		return TRUE;

	control->session = avctp_connect(&dev->src, &dev->dst);
	if (!control->session)
		return FALSE;

	return TRUE;
}

void avrcp_disconnect(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (!(control && control->session))
		return;

	avctp_disconnect(control->session);
}

int avrcp_register(DBusConnection *conn, const bdaddr_t *src, GKeyFile *config)
{
	sdp_record_t *record;
	gboolean tmp, master = TRUE;
	GError *err = NULL;
	struct avrcp_server *server;

	if (config) {
		tmp = g_key_file_get_boolean(config, "General",
							"Master", &err);
		if (err) {
			DBG("audio.conf: %s", err->message);
			g_error_free(err);
		} else
			master = tmp;
	}

	server = g_new0(struct avrcp_server, 1);
	if (!server)
		return -ENOMEM;

	if (!connection)
		connection = dbus_connection_ref(conn);

	record = avrcp_tg_record();
	if (!record) {
		error("Unable to allocate new service record");
		g_free(server);
		return -1;
	}

	if (add_record_to_server(src, record) < 0) {
		error("Unable to register AVRCP target service record");
		g_free(server);
		sdp_record_free(record);
		return -1;
	}
	server->tg_record_id = record->handle;

	record = avrcp_ct_record();
	if (!record) {
		error("Unable to allocate new service record");
		g_free(server);
		return -1;
	}

	if (add_record_to_server(src, record) < 0) {
		error("Unable to register AVRCP controller service record");
		sdp_record_free(record);
		g_free(server);
		return -1;
	}
	server->ct_record_id = record->handle;

	if (avctp_register(src, master) < 0) {
		remove_record_from_server(server->ct_record_id);
		remove_record_from_server(server->tg_record_id);
		g_free(server);
		return -1;
	}

	bacpy(&server->src, src);

	servers = g_slist_append(servers, server);

	return 0;
}

static struct avrcp_server *find_server(GSList *list, const bdaddr_t *src)
{
	for (; list; list = list->next) {
		struct avrcp_server *server = list->data;

		if (bacmp(&server->src, src) == 0)
			return server;
	}

	return NULL;
}

void avrcp_unregister(const bdaddr_t *src)
{
	struct avrcp_server *server;

	server = find_server(servers, src);
	if (!server)
		return;

	servers = g_slist_remove(servers, server);

	remove_record_from_server(server->ct_record_id);
	remove_record_from_server(server->tg_record_id);

	avctp_unregister(&server->src);
	g_free(server);

	if (servers)
		return;

	if (avctp_id)
		avctp_remove_state_cb(avctp_id);

	dbus_connection_unref(connection);
	connection = NULL;
}

static DBusMessage *control_is_connected(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	DBusMessage *reply;
	dbus_bool_t connected;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	connected = (control->session != NULL);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connected,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *volume_up(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	int err;

	if (!control->session)
		return btd_error_not_connected(msg);

	if (!control->target)
		return btd_error_not_supported(msg);

	err = avctp_send_passthrough(control->session, VOL_UP_OP);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return dbus_message_new_method_return(msg);
}

static DBusMessage *volume_down(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	int err;

	if (!control->session)
		return btd_error_not_connected(msg);

	if (!control->target)
		return btd_error_not_supported(msg);

	err = avctp_send_passthrough(control->session, VOL_DOWN_OP);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return dbus_message_new_method_return(msg);
}

static DBusMessage *control_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	gboolean value;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Connected */
	value = (device->control->session != NULL);
	dict_append_entry(&dict, "Connected", DBUS_TYPE_BOOLEAN, &value);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static GDBusMethodTable control_methods[] = {
	{ "IsConnected",	"",	"b",	control_is_connected,
						G_DBUS_METHOD_FLAG_DEPRECATED },
	{ "GetProperties",	"",	"a{sv}",control_get_properties },
	{ "VolumeUp",		"",	"",	volume_up },
	{ "VolumeDown",		"",	"",	volume_down },
	{ NULL, NULL, NULL, NULL }
};

static GDBusSignalTable control_signals[] = {
	{ "Connected",			"",	G_DBUS_SIGNAL_FLAG_DEPRECATED},
	{ "Disconnected",		"",	G_DBUS_SIGNAL_FLAG_DEPRECATED},
	{ "PropertyChanged",		"sv"	},
	{ NULL, NULL }
};

static DBusMessage *mp_set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	DBusMessageIter iter;
	DBusMessageIter var;
	const char *attrstr, *valstr;
	int attr, val;

	if (!dbus_message_iter_init(msg, &iter))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &attrstr);

	attr = attr_to_val(attrstr);
	if (attr < 0)
		return btd_error_not_supported(msg);

	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return btd_error_invalid_args(msg);

	dbus_message_iter_recurse(&iter, &var);

	/* Only string arguments are supported for now */
	if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_STRING)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&var, &valstr);

	val = attrval_to_val(attr, valstr);
	if (val < 0)
		return btd_error_not_supported(msg);

	mp_set_attribute(control->mp, attr, val);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *mp_change_playback(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	const char *statusstr;
	int status;
	uint32_t elapsed;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &statusstr,
						DBUS_TYPE_UINT32, &elapsed,
						DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	status = play_status_to_val(statusstr);
	if (status < 0)
		return btd_error_invalid_args(msg);

	mp_set_playback_status(control, status, elapsed);

	return dbus_message_new_method_return(msg);
}

static gboolean media_info_parse(DBusMessageIter *iter, struct media_info *mi)
{
	DBusMessageIter dict;
	DBusMessageIter var;
	int ctype;

	ctype = dbus_message_iter_get_arg_type(iter);
	if (ctype != DBUS_TYPE_ARRAY)
		return FALSE;

	media_info_init(mi);
	dbus_message_iter_recurse(iter, &dict);

	while ((ctype = dbus_message_iter_get_arg_type(&dict)) !=
							DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char *key;

		if (ctype != DBUS_TYPE_DICT_ENTRY)
			return FALSE;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return FALSE;

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			return FALSE;

		dbus_message_iter_recurse(&entry, &var);

		if (!strcmp(key, "Title")) {
			if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_STRING)
				return FALSE;

			dbus_message_iter_get_basic(&var, &mi->title);
		} else if (!strcmp(key, "Artist")) {
			if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_STRING)
				return FALSE;

			dbus_message_iter_get_basic(&var, &mi->artist);
		} else if (!strcmp(key, "Album")) {
			if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_STRING)
				return FALSE;

			dbus_message_iter_get_basic(&var, &mi->album);
		} else if (!strcmp(key, "Genre")) {
			if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_STRING)
				return FALSE;

			dbus_message_iter_get_basic(&var, &mi->genre);
		} else if (!strcmp(key, "NumberOfTracks")) {
			if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_UINT32)
				return FALSE;

			dbus_message_iter_get_basic(&var, &mi->ntracks);
		} else if (!strcmp(key, "TrackNumber")) {
			if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_UINT32)
				return FALSE;

			dbus_message_iter_get_basic(&var, &mi->track);
		} else if (!strcmp(key, "TrackDuration")) {
			if (dbus_message_iter_get_arg_type(&var) !=
							DBUS_TYPE_UINT32)
				return FALSE;

			dbus_message_iter_get_basic(&var, &mi->track_len);
		} else {
			return FALSE;
		}

		dbus_message_iter_next(&dict);
	}

	if (mi->title == NULL)
		return FALSE;

	return TRUE;
}

static DBusMessage *mp_change_track(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	DBusMessageIter iter;
	struct media_info mi;


	dbus_message_iter_init(msg, &iter);
	if (!media_info_parse(&iter, &mi))
		return btd_error_invalid_args(msg);

	mp_set_media_attributes(control, &mi);

	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable mp_methods[] = {
	{ "SetProperty",	"sv",		"",	mp_set_property },
	{ "ChangePlayback",	"su",		"",	mp_change_playback },
	{ "ChangeTrack",	"a{sv}",	"",	mp_change_track },
	{ }
};

static GDBusSignalTable mp_signals[] = {
	{ "PropertyChanged",		"sv"	},
	{ }
};

static void path_unregister(void *data)
{
	struct audio_device *dev = data;
	struct control *control = dev->control;

	DBG("Unregistered interface %s on path %s",
		AUDIO_CONTROL_INTERFACE, dev->path);

	if (control->session)
		avctp_disconnect(control->session);

	g_free(control);
	dev->control = NULL;
}

static void mp_path_unregister(void *data)
{
	struct audio_device *dev = data;
	struct control *control = dev->control;
	struct media_player *mp = control->mp;

	DBG("Unregistered interface %s on path %s",
		MEDIA_PLAYER_INTERFACE, dev->path);

	if (mp->handler)
		avctp_unregister_pdu_handler(mp->handler);

	g_timer_destroy(mp->timer);
	g_free(mp);
	control->mp = NULL;
}

static void mp_unregister(struct control *control)
{
	struct audio_device *dev = control->dev;

	g_dbus_unregister_interface(dev->conn, dev->path,
						MEDIA_PLAYER_INTERFACE);
}

void control_unregister(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (control->mp)
		mp_unregister(control);

	g_dbus_unregister_interface(dev->conn, dev->path,
						AUDIO_CONTROL_INTERFACE);
}

static void mp_register(struct control *control)
{
	struct audio_device *dev = control->dev;
	struct media_player *mp;

	mp = g_new0(struct media_player, 1);

	if (!g_dbus_register_interface(dev->conn, dev->path,
						MEDIA_PLAYER_INTERFACE,
						mp_methods, mp_signals, NULL,
						dev, mp_path_unregister)) {
		error("D-Bus failed do register %s on path %s",
					MEDIA_PLAYER_INTERFACE, dev->path);
		g_free(mp);
		return;
	}

	DBG("Registered interface %s on path %s",
					MEDIA_PLAYER_INTERFACE, dev->path);

	mp->timer = g_timer_new();
	media_info_init(&mp->mi);
	control->mp = mp;
}

void control_update(struct control *control, uint16_t uuid16,
							gboolean media_player)
{
	if (uuid16 == AV_REMOTE_TARGET_SVCLASS_ID)
		control->target = TRUE;
	else if (media_player && !control->mp)
		mp_register(control);
}

struct control *control_init(struct audio_device *dev, uint16_t uuid16,
							gboolean media_player)
{
	struct control *control;

	if (!g_dbus_register_interface(dev->conn, dev->path,
					AUDIO_CONTROL_INTERFACE,
					control_methods, control_signals, NULL,
					dev, path_unregister))
		return NULL;

	DBG("Registered interface %s on path %s",
		AUDIO_CONTROL_INTERFACE, dev->path);

	control = g_new0(struct control, 1);
	control->dev = dev;

	control_update(control, uuid16, media_player);

	if (!avctp_id)
		avctp_id = avctp_add_state_cb(state_changed, NULL);

	return control;
}

gboolean control_is_active(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (control && control->session)
		return TRUE;

	return FALSE;
}
