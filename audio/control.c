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
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "log.h"
#include "error.h"
#include "uinput.h"
#include "adapter.h"
#include "../src/device.h"
#include "device.h"
#include "manager.h"
#include "avdtp.h"
#include "control.h"
#include "sdpd.h"
#include "glib-helper.h"
#include "btio.h"
#include "dbus-common.h"

#define AVCTP_PSM 23

/* Message types */
#define AVCTP_COMMAND		0
#define AVCTP_RESPONSE		1

/* Packet types */
#define AVCTP_PACKET_SINGLE	0
#define AVCTP_PACKET_START	1
#define AVCTP_PACKET_CONTINUE	2
#define AVCTP_PACKET_END	3

/* ctype entries */
#define CTYPE_CONTROL		0x0
#define CTYPE_STATUS		0x1
#define CTYPE_NOTIFY		0x3
#define CTYPE_NOT_IMPLEMENTED	0x8
#define CTYPE_ACCEPTED		0x9
#define CTYPE_REJECTED		0xA
#define CTYPE_STABLE		0xC
#define CTYPE_INTERIM		0xF

/* opcodes */
#define OP_VENDORDEP		0x00
#define OP_UNITINFO		0x30
#define OP_SUBUNITINFO		0x31
#define OP_PASSTHROUGH		0x7c

/* subunits of interest */
#define SUBUNIT_PANEL		0x09

/* operands in passthrough commands */
#define VOL_UP_OP		0x41
#define VOL_DOWN_OP		0x42
#define MUTE_OP			0x43
#define PLAY_OP			0x44
#define STOP_OP			0x45
#define PAUSE_OP		0x46
#define RECORD_OP		0x47
#define REWIND_OP		0x48
#define FAST_FORWARD_OP		0x49
#define EJECT_OP		0x4a
#define FORWARD_OP		0x4b
#define BACKWARD_OP		0x4c

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
#define AVRCP_GET_PLAY_STATUS		0x30
#define AVRCP_REGISTER_NOTIFICATION	0x31

/* Notification events */
#define AVRCP_EVENT_PLAYBACK_STATUS_CHANGED		0x01
#define AVRCP_EVENT_TRACK_CHANGED			0x02

/* Capabilities for AVRCP_GET_CAPABILITIES pdu */
#define CAP_COMPANY_ID		0x02

#define QUIRK_NO_RELEASE	1 << 0

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

static DBusConnection *connection = NULL;

static GSList *servers = NULL;

#if __BYTE_ORDER == __LITTLE_ENDIAN

struct avctp_header {
	uint8_t ipid:1;
	uint8_t cr:1;
	uint8_t packet_type:2;
	uint8_t transaction:4;
	uint16_t pid;
} __attribute__ ((packed));
#define AVCTP_HEADER_LENGTH 3

struct avrcp_header {
	uint8_t code:4;
	uint8_t _hdr0:4;
	uint8_t subunit_id:3;
	uint8_t subunit_type:5;
	uint8_t opcode;
} __attribute__ ((packed));
#define AVRCP_HEADER_LENGTH 3

struct avrcp_spec_avc_pdu {
	uint8_t company_id[3];
	uint8_t pdu_id;
	uint8_t packet_type:2;
	uint8_t rsvd:6;
	uint16_t params_len;
	uint8_t params[0];
} __attribute__ ((packed));
#define AVRCP_SPECAVCPDU_HEADER_LENGTH 7

#elif __BYTE_ORDER == __BIG_ENDIAN

struct avctp_header {
	uint8_t transaction:4;
	uint8_t packet_type:2;
	uint8_t cr:1;
	uint8_t ipid:1;
	uint16_t pid;
} __attribute__ ((packed));
#define AVCTP_HEADER_LENGTH 3

struct avrcp_header {
	uint8_t _hdr0:4;
	uint8_t code:4;
	uint8_t subunit_type:5;
	uint8_t subunit_id:3;
	uint8_t opcode;
} __attribute__ ((packed));
#define AVRCP_HEADER_LENGTH 3

struct avrcp_spec_avc_pdu {
	uint8_t company_id[3];
	uint8_t pdu_id;
	uint8_t rsvd:6;
	uint8_t packet_type:2;
	uint16_t params_len;
	uint8_t params[0];
} __attribute__ ((packed));
#define AVRCP_SPECAVCPDU_HEADER_LENGTH 7

#else
#error "Unknown byte order"
#endif

struct avctp_state_callback {
	avctp_state_cb cb;
	void *user_data;
	unsigned int id;
};

struct avctp_server {
	bdaddr_t src;
	GIOChannel *io;
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
};

struct control {
	struct audio_device *dev;
	struct media_player *mp;

	avctp_state_t state;

	int uinput;

	GIOChannel *io;
	guint io_id;

	uint16_t mtu;

	gboolean target;

	uint8_t key_quirks[256];

	uint16_t registered_events;
};

static struct {
	const char *name;
	uint8_t avrcp;
	uint16_t uinput;
} key_map[] = {
	{ "PLAY",		PLAY_OP,		KEY_PLAYCD },
	{ "STOP",		STOP_OP,		KEY_STOPCD },
	{ "PAUSE",		PAUSE_OP,		KEY_PAUSECD },
	{ "FORWARD",		FORWARD_OP,		KEY_NEXTSONG },
	{ "BACKWARD",		BACKWARD_OP,		KEY_PREVIOUSSONG },
	{ "REWIND",		REWIND_OP,		KEY_REWIND },
	{ "FAST FORWARD",	FAST_FORWARD_OP,	KEY_FASTFORWARD },
	{ NULL }
};

/* Company IDs supported by this device */
static uint32_t company_ids[] = {
	IEEEID_BTSIG,
};

static GSList *avctp_callbacks = NULL;

static void auth_cb(DBusError *derr, void *user_data);

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
	uint16_t avrcp_ver = 0x0100, avctp_ver = 0x0103, feat = 0x000f;

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

static int send_event(int fd, uint16_t type, uint16_t code, int32_t value)
{
	struct uinput_event event;

	memset(&event, 0, sizeof(event));
	event.type	= type;
	event.code	= code;
	event.value	= value;

	return write(fd, &event, sizeof(event));
}

static void send_key(int fd, uint16_t key, int pressed)
{
	if (fd < 0)
		return;

	send_event(fd, EV_KEY, key, pressed);
	send_event(fd, EV_SYN, SYN_REPORT, 0);
}

static void handle_panel_passthrough(struct control *control,
					const unsigned char *operands,
					int operand_count)
{
	const char *status;
	int pressed, i;

	if (operand_count == 0)
		return;

	if (operands[0] & 0x80) {
		status = "released";
		pressed = 0;
	} else {
		status = "pressed";
		pressed = 1;
	}

	for (i = 0; key_map[i].name != NULL; i++) {
		uint8_t key_quirks;

		if ((operands[0] & 0x7F) != key_map[i].avrcp)
			continue;

		DBG("AVRCP: %s %s", key_map[i].name, status);

		key_quirks = control->key_quirks[key_map[i].avrcp];

		if (key_quirks & QUIRK_NO_RELEASE) {
			if (!pressed) {
				DBG("AVRCP: Ignoring release");
				break;
			}

			DBG("AVRCP: treating key press as press + release");
			send_key(control->uinput, key_map[i].uinput, 1);
			send_key(control->uinput, key_map[i].uinput, 0);
			break;
		}

		send_key(control->uinput, key_map[i].uinput, pressed);
		break;
	}

	if (key_map[i].name == NULL)
		DBG("AVRCP: unknown button 0x%02X %s",
						operands[0] & 0x7F, status);
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
}

static int avrcp_handle_get_capabilities(struct control *control,
						struct avrcp_spec_avc_pdu *pdu)
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

		return 2 + (3 * G_N_ELEMENTS(company_ids));
	}

err:
	pdu->params[0] = E_INVALID_PARAM;
	return -EINVAL;
}

static int avrcp_handle_list_player_attributes(struct control *control,
						struct avrcp_spec_avc_pdu *pdu)
{
	uint16_t len = ntohs(pdu->params_len);
	struct media_player *mp = control->mp;
	unsigned int i;

	if (len != 0) {
		pdu->params[0] = E_INVALID_PARAM;
		return -EINVAL;
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

	return len + 1;
}

static int avrcp_handle_list_player_values(struct control *control,
						struct avrcp_spec_avc_pdu *pdu)
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

	return len + 1;

err:
	pdu->params[0] = E_INVALID_PARAM;
	return -EINVAL;
}

static int avrcp_handle_get_current_player_value(struct control *control,
						struct avrcp_spec_avc_pdu *pdu)
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

		return 2 * len + 1;
	}

	error("No valid attributes in request");

err:
	pdu->params[0] = E_INVALID_PARAM;

	return -EINVAL;
}

static int avrcp_handle_set_player_value(struct control *control,
						struct avrcp_spec_avc_pdu *pdu)
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

		return 0;
	}

err:
	pdu->params[0] = E_INVALID_PARAM;
	return -EINVAL;
}

static int avrcp_handle_ct_battery_status(struct control *control,
						struct avrcp_spec_avc_pdu *pdu)
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

	return 0;

err:
	pdu->params[0] = E_INVALID_PARAM;
	return -EINVAL;
}

static int avrcp_handle_get_play_status(struct control *control,
						struct avrcp_spec_avc_pdu *pdu)
{
	uint16_t len = ntohs(pdu->params_len);
	uint32_t elapsed;
	uint32_t track_len;
	uint8_t status;

	if (len != 0) {
		pdu->params[0] = E_INVALID_PARAM;
		return -EINVAL;
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

	return 9;
}

static int avrcp_handle_register_notification(struct control *control,
						struct avrcp_spec_avc_pdu *pdu)
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

	/* Register event */
	control->registered_events |= (1 << pdu->params[0]);

	pdu->params_len = htons(len);

	return len;

err:
	pdu->params[0] = E_INVALID_PARAM;
	return -EINVAL;
}

/* handle vendordep pdu inside an avctp packet */
static int handle_vendordep_pdu(struct control *control,
					struct avrcp_header *avrcp,
					int operand_count)
{
	struct avrcp_spec_avc_pdu *pdu = (void *) avrcp + AVRCP_HEADER_LENGTH;
	uint32_t company_id = (pdu->company_id[0] << 16) |
				(pdu->company_id[1] << 8) |
				(pdu->company_id[2]);
	int len;

	if (company_id != IEEEID_BTSIG ||
				pdu->packet_type != AVCTP_PACKET_SINGLE) {
		avrcp->code = CTYPE_NOT_IMPLEMENTED;
		return AVRCP_HEADER_LENGTH;
	}

	pdu->packet_type = 0;
	pdu->rsvd = 0;

	if (operand_count + 3 < AVRCP_SPECAVCPDU_HEADER_LENGTH) {
		pdu->params[0] = E_INVALID_COMMAND;
		goto err_metadata;
	}

	switch (pdu->pdu_id) {
	case AVRCP_GET_CAPABILITIES:
		if (avrcp->code != CTYPE_STATUS) {
			pdu->params[0] = E_INVALID_COMMAND;
			goto err_metadata;
		}

		len = avrcp_handle_get_capabilities(control, pdu);
		if (len < 0)
			goto err_metadata;

		avrcp->code = CTYPE_STABLE;

		break;
	case AVRCP_LIST_PLAYER_ATTRIBUTES:
		if (avrcp->code != CTYPE_STATUS) {
			pdu->params[0] = E_INVALID_COMMAND;
			goto err_metadata;
		}

		len = avrcp_handle_list_player_attributes(control, pdu);
		if (len < 0)
			goto err_metadata;

		avrcp->code = CTYPE_STABLE;

		break;
	case AVRCP_LIST_PLAYER_VALUES:
		if (avrcp->code != CTYPE_STATUS) {
			pdu->params[0] = E_INVALID_COMMAND;
			goto err_metadata;
		}

		len = avrcp_handle_list_player_values(control, pdu);
		if (len < 0)
			goto err_metadata;

		avrcp->code = CTYPE_STABLE;

		break;
	case AVRCP_GET_CURRENT_PLAYER_VALUE:
		if (avrcp->code != CTYPE_STATUS) {
			pdu->params[0] = E_INVALID_COMMAND;
			goto err_metadata;
		}

		len = avrcp_handle_get_current_player_value(control, pdu);
		if (len < 0)
			goto err_metadata;

		avrcp->code = CTYPE_STABLE;

		break;
	case AVRCP_SET_PLAYER_VALUE:
		if (avrcp->code != CTYPE_CONTROL) {
			pdu->params[0] = E_INVALID_COMMAND;
			goto err_metadata;
		}

		len = avrcp_handle_set_player_value(control, pdu);
		if (len < 0)
			goto err_metadata;

		avrcp->code = CTYPE_STABLE;

		break;
	case AVRCP_GET_PLAYER_ATTRIBUTE_TEXT:
	case AVRCP_GET_PLAYER_VALUE_TEXT:
		if (avrcp->code != CTYPE_STATUS) {
			pdu->params[0] = E_INVALID_COMMAND;
			goto err_metadata;
		}

		/*
		 * As per sec. 5.2.5 of AVRCP 1.3 spec, this command is
		 * expected to be used only for extended attributes, i.e.
		 * custom attributes defined by the application. As we
		 * currently don't have any such attribute, we respond with
		 * invalid param id.
		 */
		pdu->params[0] = E_INVALID_PARAM;
		goto err_metadata;
	case AVRCP_DISPLAYABLE_CHARSET:
		if (avrcp->code != CTYPE_STATUS) {
			pdu->params[0] = E_INVALID_COMMAND;
			goto err_metadata;
		}

		if (pdu->params[0] < 3) {
			pdu->params[0] = E_INVALID_PARAM;
			goto err_metadata;
		}

		/*
		 * We acknowledge the commands, but we always use UTF-8 for
		 * encoding since CT is obliged to support it.
		 */
		pdu->params_len = 0;
		avrcp->code = CTYPE_STABLE;
		len = 0;

		break;
	case AVRCP_CT_BATTERY_STATUS:
		if (avrcp->code != CTYPE_STATUS) {
			pdu->params[0] = E_INVALID_COMMAND;
			goto err_metadata;
		}

		len = avrcp_handle_ct_battery_status(control, pdu);
		if (len < 0)
			goto err_metadata;

		avrcp->code = CTYPE_STABLE;

		break;
	case AVRCP_GET_PLAY_STATUS:
		if (avrcp->code != CTYPE_STATUS) {
			pdu->params[0] = E_INVALID_COMMAND;
			goto err_metadata;
		}

		len = avrcp_handle_get_play_status(control, pdu);
		if (len < 0)
			goto err_metadata;

		avrcp->code = CTYPE_STABLE;

		break;
	case AVRCP_REGISTER_NOTIFICATION:
		if (avrcp->code != CTYPE_NOTIFY) {
			pdu->params[0] = E_INVALID_COMMAND;
			goto err_metadata;
		}

		len = avrcp_handle_register_notification(control, pdu);
		if (len < 0)
			goto err_metadata;

		avrcp->code = CTYPE_INTERIM;

		break;
	default:
		/* Invalid pdu_id */
		pdu->params[0] = E_INVALID_COMMAND;
		goto err_metadata;
	}

	return AVRCP_HEADER_LENGTH + AVRCP_SPECAVCPDU_HEADER_LENGTH + len;

err_metadata:
	avrcp->code = CTYPE_REJECTED;
	pdu->params_len = htons(1);

	return AVRCP_HEADER_LENGTH + AVRCP_SPECAVCPDU_HEADER_LENGTH + 1;
}

static void avctp_disconnected(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (!control)
		return;

	if (control->io) {
		g_io_channel_shutdown(control->io, TRUE, NULL);
		g_io_channel_unref(control->io);
		control->io = NULL;
	}

	if (control->io_id) {
		g_source_remove(control->io_id);
		control->io_id = 0;

		if (control->state == AVCTP_STATE_CONNECTING)
			audio_device_cancel_authorization(dev, auth_cb,
								control);
	}

	if (control->uinput >= 0) {
		char address[18];

		ba2str(&dev->dst, address);
		DBG("AVRCP: closing uinput for %s", address);

		ioctl(control->uinput, UI_DEV_DESTROY);
		close(control->uinput);
		control->uinput = -1;
	}
}

static void avctp_set_state(struct control *control, avctp_state_t new_state)
{
	GSList *l;
	struct audio_device *dev = control->dev;
	avctp_state_t old_state = control->state;
	gboolean value;

	switch (new_state) {
	case AVCTP_STATE_DISCONNECTED:
		DBG("AVCTP Disconnected");

		avctp_disconnected(control->dev);

		if (old_state != AVCTP_STATE_CONNECTED)
			break;

		value = FALSE;
		g_dbus_emit_signal(dev->conn, dev->path,
					AUDIO_CONTROL_INTERFACE,
					"Disconnected", DBUS_TYPE_INVALID);
		emit_property_changed(dev->conn, dev->path,
					AUDIO_CONTROL_INTERFACE, "Connected",
					DBUS_TYPE_BOOLEAN, &value);

		if (!audio_device_is_active(dev, NULL))
			audio_device_set_authorized(dev, FALSE);

		break;
	case AVCTP_STATE_CONNECTING:
		DBG("AVCTP Connecting");
		break;
	case AVCTP_STATE_CONNECTED:
		DBG("AVCTP Connected");
		value = TRUE;
		g_dbus_emit_signal(control->dev->conn, control->dev->path,
				AUDIO_CONTROL_INTERFACE, "Connected",
				DBUS_TYPE_INVALID);
		emit_property_changed(control->dev->conn, control->dev->path,
				AUDIO_CONTROL_INTERFACE, "Connected",
				DBUS_TYPE_BOOLEAN, &value);
		break;
	default:
		error("Invalid AVCTP state %d", new_state);
		return;
	}

	control->state = new_state;

	for (l = avctp_callbacks; l != NULL; l = l->next) {
		struct avctp_state_callback *cb = l->data;
		cb->cb(control->dev, old_state, new_state, cb->user_data);
	}
}

static gboolean control_cb(GIOChannel *chan, GIOCondition cond,
				gpointer data)
{
	struct control *control = data;
	unsigned char buf[1024], *operands;
	struct avctp_header *avctp;
	struct avrcp_header *avrcp;
	int ret, packet_size, operand_count, sock;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		goto failed;

	sock = g_io_channel_unix_get_fd(control->io);

	ret = read(sock, buf, sizeof(buf));
	if (ret <= 0)
		goto failed;

	DBG("Got %d bytes of data for AVCTP session %p", ret, control);

	if ((unsigned int) ret < sizeof(struct avctp_header)) {
		error("Too small AVCTP packet");
		goto failed;
	}

	packet_size = ret;

	avctp = (struct avctp_header *) buf;

	DBG("AVCTP transaction %u, packet type %u, C/R %u, IPID %u, "
			"PID 0x%04X",
			avctp->transaction, avctp->packet_type,
			avctp->cr, avctp->ipid, ntohs(avctp->pid));

	ret -= sizeof(struct avctp_header);
	if ((unsigned int) ret < sizeof(struct avrcp_header)) {
		error("Too small AVRCP packet");
		goto failed;
	}

	avrcp = (struct avrcp_header *) (buf + sizeof(struct avctp_header));

	ret -= sizeof(struct avrcp_header);

	operands = buf + sizeof(struct avctp_header) + sizeof(struct avrcp_header);
	operand_count = ret;

	DBG("AVRCP %s 0x%01X, subunit_type 0x%02X, subunit_id 0x%01X, "
			"opcode 0x%02X, %d operands",
			avctp->cr ? "response" : "command",
			avrcp->code, avrcp->subunit_type, avrcp->subunit_id,
			avrcp->opcode, operand_count);

	if (avctp->packet_type != AVCTP_PACKET_SINGLE) {
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_NOT_IMPLEMENTED;
	} else if (avctp->pid != htons(AV_REMOTE_SVCLASS_ID)) {
		avctp->ipid = 1;
		avctp->cr = AVCTP_RESPONSE;
		packet_size = sizeof(*avctp);
	} else if (avctp->cr == AVCTP_COMMAND &&
			avrcp->code == CTYPE_CONTROL &&
			avrcp->subunit_type == SUBUNIT_PANEL &&
			avrcp->opcode == OP_PASSTHROUGH) {
		handle_panel_passthrough(control, operands, operand_count);
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_ACCEPTED;
	} else if (avctp->cr == AVCTP_COMMAND &&
			avrcp->code == CTYPE_STATUS &&
			(avrcp->opcode == OP_UNITINFO
			|| avrcp->opcode == OP_SUBUNITINFO)) {
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_STABLE;
		/* The first operand should be 0x07 for the UNITINFO response.
		 * Neither AVRCP (section 22.1, page 117) nor AVC Digital
		 * Interface Command Set (section 9.2.1, page 45) specs
		 * explain this value but both use it */
		if (operand_count >= 1 && avrcp->opcode == OP_UNITINFO)
			operands[0] = 0x07;
		if (operand_count >= 2)
			operands[1] = SUBUNIT_PANEL << 3;
		DBG("reply to %s", avrcp->opcode == OP_UNITINFO ?
				"OP_UNITINFO" : "OP_SUBUNITINFO");
	} else if (avctp->cr == AVCTP_COMMAND &&
			avrcp->opcode == OP_VENDORDEP) {
		int r_size;
		operand_count -= 3;
		avctp->cr = AVCTP_RESPONSE;
		r_size = handle_vendordep_pdu(control, avrcp, operand_count);
		packet_size = AVCTP_HEADER_LENGTH + r_size;
	} else {
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_REJECTED;
	}
	ret = write(sock, buf, packet_size);
	if (ret != packet_size)
		goto failed;

	return TRUE;

failed:
	DBG("AVCTP session %p got disconnected", control);
	avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
	return FALSE;
}

static int uinput_create(char *name)
{
	struct uinput_dev dev;
	int fd, err, i;

	fd = open("/dev/uinput", O_RDWR);
	if (fd < 0) {
		fd = open("/dev/input/uinput", O_RDWR);
		if (fd < 0) {
			fd = open("/dev/misc/uinput", O_RDWR);
			if (fd < 0) {
				err = errno;
				error("Can't open input device: %s (%d)",
							strerror(err), err);
				return -err;
			}
		}
	}

	memset(&dev, 0, sizeof(dev));
	if (name)
		strncpy(dev.name, name, UINPUT_MAX_NAME_SIZE - 1);

	dev.id.bustype = BUS_BLUETOOTH;
	dev.id.vendor  = 0x0000;
	dev.id.product = 0x0000;
	dev.id.version = 0x0000;

	if (write(fd, &dev, sizeof(dev)) < 0) {
		err = errno;
		error("Can't write device information: %s (%d)",
						strerror(err), err);
		close(fd);
		errno = err;
		return -err;
	}

	ioctl(fd, UI_SET_EVBIT, EV_KEY);
	ioctl(fd, UI_SET_EVBIT, EV_REL);
	ioctl(fd, UI_SET_EVBIT, EV_REP);
	ioctl(fd, UI_SET_EVBIT, EV_SYN);

	for (i = 0; key_map[i].name != NULL; i++)
		ioctl(fd, UI_SET_KEYBIT, key_map[i].uinput);

	if (ioctl(fd, UI_DEV_CREATE, NULL) < 0) {
		err = errno;
		error("Can't create uinput device: %s (%d)",
						strerror(err), err);
		close(fd);
		errno = err;
		return -err;
	}

	return fd;
}

static void init_uinput(struct control *control)
{
	struct audio_device *dev = control->dev;
	char address[18], name[248 + 1];

	device_get_name(dev->btd_dev, name, sizeof(name));
	if (g_str_equal(name, "Nokia CK-20W")) {
		control->key_quirks[FORWARD_OP] |= QUIRK_NO_RELEASE;
		control->key_quirks[BACKWARD_OP] |= QUIRK_NO_RELEASE;
		control->key_quirks[PLAY_OP] |= QUIRK_NO_RELEASE;
		control->key_quirks[PAUSE_OP] |= QUIRK_NO_RELEASE;
	}

	ba2str(&dev->dst, address);

	control->uinput = uinput_create(address);
	if (control->uinput < 0)
		error("AVRCP: failed to init uinput for %s", address);
	else
		DBG("AVRCP: uinput initialized for %s", address);
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

static void avctp_connect_cb(GIOChannel *chan, GError *err, gpointer data)
{
	struct control *control = data;
	char address[18];
	uint16_t imtu;
	GError *gerr = NULL;

	if (err) {
		avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
		error("%s", err->message);
		return;
	}

	bt_io_get(chan, BT_IO_L2CAP, &gerr,
			BT_IO_OPT_DEST, &address,
			BT_IO_OPT_IMTU, &imtu,
			BT_IO_OPT_INVALID);
	if (gerr) {
		avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
		error("%s", gerr->message);
		g_error_free(gerr);
		return;
	}

	DBG("AVCTP: connected to %s", address);

	if (!control->io)
		control->io = g_io_channel_ref(chan);

	init_uinput(control);

	avctp_set_state(control, AVCTP_STATE_CONNECTED);
	control->mtu = imtu;
	control->io_id = g_io_add_watch(chan,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) control_cb, control);
}

static void auth_cb(DBusError *derr, void *user_data)
{
	struct control *control = user_data;
	GError *err = NULL;

	if (control->io_id) {
		g_source_remove(control->io_id);
		control->io_id = 0;
	}

	if (derr && dbus_error_is_set(derr)) {
		error("Access denied: %s", derr->message);
		avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
		return;
	}

	if (!bt_io_accept(control->io, avctp_connect_cb, control,
								NULL, &err)) {
		error("bt_io_accept: %s", err->message);
		g_error_free(err);
		avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
	}
}

static void avctp_confirm_cb(GIOChannel *chan, gpointer data)
{
	struct control *control = NULL;
	struct audio_device *dev;
	char address[18];
	bdaddr_t src, dst;
	GError *err = NULL;

	bt_io_get(chan, BT_IO_L2CAP, &err,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		g_io_channel_shutdown(chan, TRUE, NULL);
		return;
	}

	dev = manager_get_device(&src, &dst, TRUE);
	if (!dev) {
		error("Unable to get audio device object for %s", address);
		goto drop;
	}

	if (!dev->control) {
		btd_device_add_uuid(dev->btd_dev, AVRCP_REMOTE_UUID);
		if (!dev->control)
			goto drop;
	}

	control = dev->control;

	if (control->io) {
		error("Refusing unexpected connect from %s", address);
		goto drop;
	}

	avctp_set_state(control, AVCTP_STATE_CONNECTING);
	control->io = g_io_channel_ref(chan);

	if (audio_device_request_authorization(dev, AVRCP_TARGET_UUID,
						auth_cb, dev->control) < 0)
		goto drop;

	control->io_id = g_io_add_watch(chan, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
							control_cb, control);
	return;

drop:
	if (!control || !control->io)
		g_io_channel_shutdown(chan, TRUE, NULL);
	if (control)
		avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
}

static GIOChannel *avctp_server_socket(const bdaddr_t *src, gboolean master)
{
	GError *err = NULL;
	GIOChannel *io;

	io = bt_io_listen(BT_IO_L2CAP, NULL, avctp_confirm_cb, NULL,
				NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, src,
				BT_IO_OPT_PSM, AVCTP_PSM,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_MASTER, master,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("%s", err->message);
		g_error_free(err);
	}

	return io;
}

gboolean avrcp_connect(struct audio_device *dev)
{
	struct control *control = dev->control;
	GError *err = NULL;
	GIOChannel *io;

	if (control->state > AVCTP_STATE_DISCONNECTED)
		return TRUE;

	avctp_set_state(control, AVCTP_STATE_CONNECTING);

	io = bt_io_connect(BT_IO_L2CAP, avctp_connect_cb, control, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &dev->src,
				BT_IO_OPT_DEST_BDADDR, &dev->dst,
				BT_IO_OPT_PSM, AVCTP_PSM,
				BT_IO_OPT_INVALID);
	if (err) {
		avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
		error("%s", err->message);
		g_error_free(err);
		return FALSE;
	}

	control->io = io;

	return TRUE;
}

void avrcp_disconnect(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (!(control && control->io))
		return;

	avctp_set_state(control, AVCTP_STATE_DISCONNECTED);
}

int avrcp_register(DBusConnection *conn, const bdaddr_t *src, GKeyFile *config)
{
	sdp_record_t *record;
	gboolean tmp, master = TRUE;
	GError *err = NULL;
	struct avctp_server *server;

	if (config) {
		tmp = g_key_file_get_boolean(config, "General",
							"Master", &err);
		if (err) {
			DBG("audio.conf: %s", err->message);
			g_error_free(err);
		} else
			master = tmp;
	}

	server = g_new0(struct avctp_server, 1);
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

	server->io = avctp_server_socket(src, master);
	if (!server->io) {
		remove_record_from_server(server->ct_record_id);
		remove_record_from_server(server->tg_record_id);
		g_free(server);
		return -1;
	}

	bacpy(&server->src, src);

	servers = g_slist_append(servers, server);

	return 0;
}

static struct avctp_server *find_server(GSList *list, const bdaddr_t *src)
{
	for (; list; list = list->next) {
		struct avctp_server *server = list->data;

		if (bacmp(&server->src, src) == 0)
			return server;
	}

	return NULL;
}

void avrcp_unregister(const bdaddr_t *src)
{
	struct avctp_server *server;

	server = find_server(servers, src);
	if (!server)
		return;

	servers = g_slist_remove(servers, server);

	remove_record_from_server(server->ct_record_id);
	remove_record_from_server(server->tg_record_id);

	g_io_channel_shutdown(server->io, TRUE, NULL);
	g_io_channel_unref(server->io);
	g_free(server);

	if (servers)
		return;

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

	connected = (control->state == AVCTP_STATE_CONNECTED);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connected,
					DBUS_TYPE_INVALID);

	return reply;
}

static int avctp_send_passthrough(struct control *control, uint8_t op)
{
	unsigned char buf[AVCTP_HEADER_LENGTH + AVRCP_HEADER_LENGTH + 2];
	struct avctp_header *avctp = (void *) buf;
	struct avrcp_header *avrcp = (void *) &buf[AVCTP_HEADER_LENGTH];
	uint8_t *operands = &buf[AVCTP_HEADER_LENGTH + AVRCP_HEADER_LENGTH];
	int sk = g_io_channel_unix_get_fd(control->io);
	static uint8_t transaction = 0;

	memset(buf, 0, sizeof(buf));

	avctp->transaction = transaction++;
	avctp->packet_type = AVCTP_PACKET_SINGLE;
	avctp->cr = AVCTP_COMMAND;
	avctp->pid = htons(AV_REMOTE_SVCLASS_ID);

	avrcp->code = CTYPE_CONTROL;
	avrcp->subunit_type = SUBUNIT_PANEL;
	avrcp->opcode = OP_PASSTHROUGH;

	operands[0] = op & 0x7f;
	operands[1] = 0;

	if (write(sk, buf, sizeof(buf)) < 0)
		return -errno;

	/* Button release */
	avctp->transaction = transaction++;
	operands[0] |= 0x80;

	if (write(sk, buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

static DBusMessage *volume_up(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	int err;

	if (control->state != AVCTP_STATE_CONNECTED)
		return btd_error_not_connected(msg);

	if (!control->target)
		return btd_error_not_supported(msg);

	err = avctp_send_passthrough(control, VOL_UP_OP);
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

	if (control->state != AVCTP_STATE_CONNECTED)
		return btd_error_not_connected(msg);

	if (!control->target)
		return btd_error_not_supported(msg);

	err = avctp_send_passthrough(control, VOL_DOWN_OP);
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
	value = (device->control->state == AVCTP_STATE_CONNECTED);
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

	if (control->state != AVCTP_STATE_DISCONNECTED)
		avctp_disconnected(dev);

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
	control->state = AVCTP_STATE_DISCONNECTED;
	control->uinput = -1;

	control_update(control, uuid16, media_player);

	return control;
}

gboolean control_is_active(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (control && control->state != AVCTP_STATE_DISCONNECTED)
		return TRUE;

	return FALSE;
}

unsigned int avctp_add_state_cb(avctp_state_cb cb, void *user_data)
{
	struct avctp_state_callback *state_cb;
	static unsigned int id = 0;

	state_cb = g_new(struct avctp_state_callback, 1);
	state_cb->cb = cb;
	state_cb->user_data = user_data;
	state_cb->id = ++id;

	avctp_callbacks = g_slist_append(avctp_callbacks, state_cb);

	return state_cb->id;
}

gboolean avctp_remove_state_cb(unsigned int id)
{
	GSList *l;

	for (l = avctp_callbacks; l != NULL; l = l->next) {
		struct avctp_state_callback *cb = l->data;
		if (cb && cb->id == id) {
			avctp_callbacks = g_slist_remove(avctp_callbacks, cb);
			g_free(cb);
			return TRUE;
		}
	}

	return FALSE;
}
