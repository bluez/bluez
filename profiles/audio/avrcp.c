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
#include <stdbool.h>
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
#include <gdbus/gdbus.h>

#include "lib/uuid.h"
#include "../src/adapter.h"
#include "../src/device.h"

#include "log.h"
#include "error.h"
#include "device.h"
#include "manager.h"
#include "avctp.h"
#include "avrcp.h"
#include "sdpd.h"
#include "dbus-common.h"
#include "control.h"
#include "avdtp.h"
#include "sink.h"
#include "player.h"
#include "transport.h"

/* Company IDs for vendor dependent commands */
#define IEEEID_BTSIG		0x001958

/* Status codes */
#define AVRCP_STATUS_INVALID_COMMAND		0x00
#define AVRCP_STATUS_INVALID_PARAM		0x01
#define AVRCP_STATUS_PARAM_NOT_FOUND		0x02
#define AVRCP_STATUS_INTERNAL_ERROR		0x03
#define AVRCP_STATUS_SUCCESS			0x04
#define AVRCP_STATUS_INVALID_PLAYER_ID		0x11
#define AVRCP_STATUS_PLAYER_NOT_BROWSABLE	0x12
#define AVRCP_STATUS_NO_AVAILABLE_PLAYERS	0x15
#define AVRCP_STATUS_ADDRESSED_PLAYER_CHANGED	0x16

/* Packet types */
#define AVRCP_PACKET_TYPE_SINGLE	0x00
#define AVRCP_PACKET_TYPE_START		0x01
#define AVRCP_PACKET_TYPE_CONTINUING	0x02
#define AVRCP_PACKET_TYPE_END		0x03

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
#define AVRCP_REQUEST_CONTINUING	0x40
#define AVRCP_ABORT_CONTINUING		0x41
#define AVRCP_SET_ABSOLUTE_VOLUME	0x50
#define AVRCP_SET_BROWSED_PLAYER	0x70
#define AVRCP_GET_ITEM_ATTRIBUTES	0x73
#define AVRCP_GET_FOLDER_ITEMS		0x71
#define AVRCP_GENERAL_REJECT		0xA0

/* Capabilities for AVRCP_GET_CAPABILITIES pdu */
#define CAP_COMPANY_ID		0x02
#define CAP_EVENTS_SUPPORTED	0x03

#define AVRCP_REGISTER_NOTIFICATION_PARAM_LENGTH 5
#define AVRCP_GET_CAPABILITIES_PARAM_LENGTH 1

#define AVRCP_FEATURE_CATEGORY_1	0x0001
#define AVRCP_FEATURE_CATEGORY_2	0x0002
#define AVRCP_FEATURE_CATEGORY_3	0x0004
#define AVRCP_FEATURE_CATEGORY_4	0x0008
#define AVRCP_FEATURE_PLAYER_SETTINGS	0x0010
#define AVRCP_FEATURE_BROWSING			0x0040

#define AVRCP_BATTERY_STATUS_NORMAL		0
#define AVRCP_BATTERY_STATUS_WARNING		1
#define AVRCP_BATTERY_STATUS_CRITICAL		2
#define AVRCP_BATTERY_STATUS_EXTERNAL		3
#define AVRCP_BATTERY_STATUS_FULL_CHARGE	4

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

#define AVRCP_MTU	(AVC_MTU - AVC_HEADER_LENGTH)
#define AVRCP_PDU_MTU	(AVRCP_MTU - AVRCP_HEADER_LENGTH)

struct avrcp_browsing_header {
	uint8_t pdu_id;
	uint16_t param_len;
	uint8_t params[0];
} __attribute__ ((packed));
#define AVRCP_BROWSING_HEADER_LENGTH 3

struct avrcp_server {
	struct btd_adapter *adapter;
	uint32_t tg_record_id;
	uint32_t ct_record_id;
	GSList *players;
	GSList *sessions;
};

struct pending_pdu {
	uint8_t pdu_id;
	GList *attr_ids;
	uint16_t offset;
};

struct avrcp_player {
	struct avrcp_server *server;
	GSList *sessions;
	uint16_t id;
	uint16_t uid_counter;
	uint8_t *features;

	struct avrcp_player_cb *cb;
	void *user_data;
	GDestroyNotify destroy;
};

struct avrcp {
	struct avrcp_server *server;
	struct avctp *conn;
	struct audio_device *dev;
	struct avrcp_player *player;
	gboolean target;
	uint16_t version;
	int features;
	GSList *players;

	void (*init_control) (struct avrcp *session);
	void (*init_browsing) (struct avrcp *session);
	void (*destroy) (struct avrcp *sesion);

	const struct control_pdu_handler *control_handlers;

	unsigned int control_id;
	unsigned int browsing_id;
	uint16_t supported_events;
	uint16_t registered_events;
	uint8_t transaction;
	uint8_t transaction_events[AVRCP_EVENT_LAST + 1];
	struct pending_pdu *pending_pdu;
};

struct control_pdu_handler {
	uint8_t pdu_id;
	uint8_t code;
	uint8_t (*func) (struct avrcp *session, struct avrcp_header *pdu,
							uint8_t transaction);
};

static GSList *servers = NULL;
static unsigned int avctp_id = 0;

/* Company IDs supported by this device */
static uint32_t company_ids[] = {
	IEEEID_BTSIG,
};

static void avrcp_register_notification(struct avrcp *session, uint8_t event);

static sdp_record_t *avrcp_ct_record(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avctp, avrct;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVCTP_CONTROL_PSM;
	uint16_t avrcp_ver = 0x0105, avctp_ver = 0x0103;
	uint16_t feat = ( AVRCP_FEATURE_CATEGORY_1 |
						AVRCP_FEATURE_CATEGORY_2 |
						AVRCP_FEATURE_CATEGORY_3 |
						AVRCP_FEATURE_CATEGORY_4 );

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
	sdp_list_t *svclass_id, *pfseq, *apseq, *root, *apseq_browsing;
	uuid_t root_uuid, l2cap, avctp, avrtg;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto_control, *proto_control[2];
	sdp_record_t *record;
	sdp_data_t *psm_control, *version, *features, *psm_browsing;
	sdp_list_t *aproto_browsing, *proto_browsing[2] = {0};
	uint16_t lp = AVCTP_CONTROL_PSM;
	uint16_t lp_browsing = AVCTP_BROWSING_PSM;
	uint16_t avrcp_ver = 0x0104, avctp_ver = 0x0103;
	uint16_t feat = ( AVRCP_FEATURE_CATEGORY_1 |
					AVRCP_FEATURE_CATEGORY_2 |
					AVRCP_FEATURE_CATEGORY_3 |
					AVRCP_FEATURE_CATEGORY_4 |
					AVRCP_FEATURE_BROWSING |
					AVRCP_FEATURE_PLAYER_SETTINGS );

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
	proto_control[0] = sdp_list_append(0, &l2cap);
	psm_control = sdp_data_alloc(SDP_UINT16, &lp);
	proto_control[0] = sdp_list_append(proto_control[0], psm_control);
	apseq = sdp_list_append(0, proto_control[0]);

	sdp_uuid16_create(&avctp, AVCTP_UUID);
	proto_control[1] = sdp_list_append(0, &avctp);
	version = sdp_data_alloc(SDP_UINT16, &avctp_ver);
	proto_control[1] = sdp_list_append(proto_control[1], version);
	apseq = sdp_list_append(apseq, proto_control[1]);

	aproto_control = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto_control);
	proto_browsing[0] = sdp_list_append(0, &l2cap);
	psm_browsing = sdp_data_alloc(SDP_UINT16, &lp_browsing);
	proto_browsing[0] = sdp_list_append(proto_browsing[0], psm_browsing);
	apseq_browsing = sdp_list_append(0, proto_browsing[0]);

	proto_browsing[1] = sdp_list_append(0, &avctp);
	proto_browsing[1] = sdp_list_append(proto_browsing[1], version);
	apseq_browsing = sdp_list_append(apseq_browsing, proto_browsing[1]);

	aproto_browsing = sdp_list_append(0, apseq_browsing);
	sdp_set_add_access_protos(record, aproto_browsing);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile[0].uuid, AV_REMOTE_PROFILE_ID);
	profile[0].version = avrcp_ver;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(record, "AVRCP TG", 0, 0);

	free(psm_browsing);
	sdp_list_free(proto_browsing[0], 0);
	sdp_list_free(proto_browsing[1], 0);
	sdp_list_free(apseq_browsing, 0);
	sdp_list_free(aproto_browsing, 0);

	free(psm_control);
	free(version);
	sdp_list_free(proto_control[0], 0);
	sdp_list_free(proto_control[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto_control, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

static unsigned int attr_get_max_val(uint8_t attr)
{
	switch (attr) {
	case AVRCP_ATTRIBUTE_EQUALIZER:
		return AVRCP_EQUALIZER_ON;
	case AVRCP_ATTRIBUTE_REPEAT_MODE:
		return AVRCP_REPEAT_MODE_GROUP;
	case AVRCP_ATTRIBUTE_SHUFFLE:
		return AVRCP_SHUFFLE_GROUP;
	case AVRCP_ATTRIBUTE_SCAN:
		return AVRCP_SCAN_GROUP;
	}

	return 0;
}

static const char *battery_status_to_str(uint8_t status)
{
	switch (status) {
	case AVRCP_BATTERY_STATUS_NORMAL:
		return "normal";
	case AVRCP_BATTERY_STATUS_WARNING:
		return "warning";
	case AVRCP_BATTERY_STATUS_CRITICAL:
		return "critical";
	case AVRCP_BATTERY_STATUS_EXTERNAL:
		return "external";
	case AVRCP_BATTERY_STATUS_FULL_CHARGE:
		return "fullcharge";
	}

	return NULL;
}

/*
 * get_company_id:
 *
 * Get three-byte Company_ID from incoming AVRCP message
 */
static uint32_t get_company_id(const uint8_t cid[3])
{
	return cid[0] << 16 | cid[1] << 8 | cid[2];
}

/*
 * set_company_id:
 *
 * Set three-byte Company_ID into outgoing AVRCP message
 */
static void set_company_id(uint8_t cid[3], const uint32_t cid_in)
{
	cid[0] = cid_in >> 16;
	cid[1] = cid_in >> 8;
	cid[2] = cid_in;
}

static const char *attr_to_str(uint8_t attr)
{
	switch (attr) {
	case AVRCP_ATTRIBUTE_EQUALIZER:
		return "Equalizer";
	case AVRCP_ATTRIBUTE_REPEAT_MODE:
		return "Repeat";
	case AVRCP_ATTRIBUTE_SHUFFLE:
		return "Shuffle";
	case AVRCP_ATTRIBUTE_SCAN:
		return "Scan";
	}

	return NULL;
}

static int attrval_to_val(uint8_t attr, const char *value)
{
	int ret;

	switch (attr) {
	case AVRCP_ATTRIBUTE_EQUALIZER:
		if (!strcmp(value, "off"))
			ret = AVRCP_EQUALIZER_OFF;
		else if (!strcmp(value, "on"))
			ret = AVRCP_EQUALIZER_ON;
		else
			ret = -EINVAL;

		return ret;
	case AVRCP_ATTRIBUTE_REPEAT_MODE:
		if (!strcmp(value, "off"))
			ret = AVRCP_REPEAT_MODE_OFF;
		else if (!strcmp(value, "singletrack"))
			ret = AVRCP_REPEAT_MODE_SINGLE;
		else if (!strcmp(value, "alltracks"))
			ret = AVRCP_REPEAT_MODE_ALL;
		else if (!strcmp(value, "group"))
			ret = AVRCP_REPEAT_MODE_GROUP;
		else
			ret = -EINVAL;

		return ret;
	case AVRCP_ATTRIBUTE_SHUFFLE:
		if (!strcmp(value, "off"))
			ret = AVRCP_SHUFFLE_OFF;
		else if (!strcmp(value, "alltracks"))
			ret = AVRCP_SHUFFLE_ALL;
		else if (!strcmp(value, "group"))
			ret = AVRCP_SHUFFLE_GROUP;
		else
			ret = -EINVAL;

		return ret;
	case AVRCP_ATTRIBUTE_SCAN:
		if (!strcmp(value, "off"))
			ret = AVRCP_SCAN_OFF;
		else if (!strcmp(value, "alltracks"))
			ret = AVRCP_SCAN_ALL;
		else if (!strcmp(value, "group"))
			ret = AVRCP_SCAN_GROUP;
		else
			ret = -EINVAL;

		return ret;
	}

	return -EINVAL;
}

static int attr_to_val(const char *str)
{
	if (!strcasecmp(str, "Equalizer"))
		return AVRCP_ATTRIBUTE_EQUALIZER;
	else if (!strcasecmp(str, "Repeat"))
		return AVRCP_ATTRIBUTE_REPEAT_MODE;
	else if (!strcasecmp(str, "Shuffle"))
		return AVRCP_ATTRIBUTE_SHUFFLE;
	else if (!strcasecmp(str, "Scan"))
		return AVRCP_ATTRIBUTE_SCAN;

	return -EINVAL;
}

static int player_get_setting(struct avrcp_player *player, uint8_t id)
{
	const char *key;
	const char *value;

	if (player == NULL)
		return -ENOENT;

	key = attr_to_str(id);
	if (key == NULL)
		return -EINVAL;

	value = player->cb->get_setting(key, player->user_data);

	return attrval_to_val(id, value);
}

static int play_status_to_val(const char *status)
{
	if (!strcasecmp(status, "stopped"))
		return AVRCP_PLAY_STATUS_STOPPED;
	else if (!strcasecmp(status, "playing"))
		return AVRCP_PLAY_STATUS_PLAYING;
	else if (!strcasecmp(status, "paused"))
		return AVRCP_PLAY_STATUS_PAUSED;
	else if (!strcasecmp(status, "forward-seek"))
		return AVRCP_PLAY_STATUS_FWD_SEEK;
	else if (!strcasecmp(status, "reverse-seek"))
		return AVRCP_PLAY_STATUS_REV_SEEK;
	else if (!strcasecmp(status, "error"))
		return AVRCP_PLAY_STATUS_ERROR;

	return -EINVAL;
}

void avrcp_player_event(struct avrcp_player *player, uint8_t id, void *data)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + 9];
	struct avrcp_header *pdu = (void *) buf;
	uint16_t size;
	GSList *l;
	GList *settings;

	if (player->sessions == NULL)
		return;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);

	pdu->pdu_id = AVRCP_REGISTER_NOTIFICATION;
	pdu->params[0] = id;

	DBG("id=%u", id);

	switch (id) {
	case AVRCP_EVENT_STATUS_CHANGED:
		size = 2;
		pdu->params[1] = play_status_to_val(data);

		break;
	case AVRCP_EVENT_TRACK_CHANGED:
		size = 9;
		memcpy(&pdu->params[1], data, sizeof(uint64_t));

		break;
	case AVRCP_EVENT_TRACK_REACHED_END:
	case AVRCP_EVENT_TRACK_REACHED_START:
		size = 1;
		break;
	case AVRCP_EVENT_SETTINGS_CHANGED:
		size = 2;
		settings = data;
		pdu->params[1] = g_list_length(settings);
		for (; settings; settings = settings->next) {
			const char *key = settings->data;
			int attr;
			int val;

			attr = attr_to_val(key);
			if (attr < 0)
				continue;

			val = player_get_setting(player, attr);
			if (val < 0)
				continue;

			pdu->params[++size] = attr;
			pdu->params[++size] = val;
		}
		break;
	default:
		error("Unknown event %u", id);
		return;
	}

	pdu->params_len = htons(size);

	for (l = player->sessions; l; l = l->next) {
		struct avrcp *session = l->data;
		int err;

		if (!(session->registered_events & (1 << id)))
			continue;

		err = avctp_send_vendordep(session->conn,
					session->transaction_events[id],
					AVC_CTYPE_CHANGED, AVC_SUBUNIT_PANEL,
					buf, size + AVRCP_HEADER_LENGTH);
		if (err < 0)
			continue;

		/* Unregister event as per AVRCP 1.3 spec, section 5.4.2 */
		session->registered_events ^= 1 << id;
	}

	return;
}

static const char *metadata_to_str(uint32_t id)
{
	switch (id) {
	case AVRCP_MEDIA_ATTRIBUTE_TITLE:
		return "Title";
	case AVRCP_MEDIA_ATTRIBUTE_ARTIST:
		return "Artist";
	case AVRCP_MEDIA_ATTRIBUTE_ALBUM:
		return "Album";
	case AVRCP_MEDIA_ATTRIBUTE_GENRE:
		return "Genre";
	case AVRCP_MEDIA_ATTRIBUTE_TRACK:
		return "TrackNumber";
	case AVRCP_MEDIA_ATTRIBUTE_N_TRACKS:
		return "NumberOfTracks";
	case AVRCP_MEDIA_ATTRIBUTE_DURATION:
		return "Duration";
	}

	return NULL;
}

static const char *player_get_metadata(struct avrcp_player *player,
								uint32_t id)
{
	const char *key;

	key = metadata_to_str(id);
	if (key == NULL)
		return NULL;

	if (player != NULL)
		return player->cb->get_metadata(key, player->user_data);

	if (id == AVRCP_MEDIA_ATTRIBUTE_TITLE)
		return "";

	return NULL;
}

static uint16_t player_write_media_attribute(struct avrcp_player *player,
						uint32_t id, uint8_t *buf,
						uint16_t *pos,
						uint16_t *offset)
{
	uint16_t len;
	uint16_t attr_len;
	const char *value = NULL;

	DBG("%u", id);

	value = player_get_metadata(player, id);
	if (value == NULL) {
		*offset = 0;
		return 0;
	}

	attr_len = strlen(value);
	value = ((char *) value) + *offset;
	len = attr_len - *offset;

	if (len > AVRCP_PDU_MTU - *pos) {
		len = AVRCP_PDU_MTU - *pos;
		*offset += len;
	} else {
		*offset = 0;
	}

	memcpy(&buf[*pos], value, len);
	*pos += len;

	return attr_len;
}

static GList *player_fill_media_attribute(struct avrcp_player *player,
					GList *attr_ids, uint8_t *buf,
					uint16_t *pos, uint16_t *offset)
{
	struct media_attribute_header {
		uint32_t id;
		uint16_t charset;
		uint16_t len;
	} *hdr = NULL;
	GList *l;

	for (l = attr_ids; l != NULL; l = g_list_delete_link(l, l)) {
		uint32_t attr = GPOINTER_TO_UINT(l->data);
		uint16_t attr_len;

		if (*offset == 0) {
			if (*pos + sizeof(*hdr) >= AVRCP_PDU_MTU)
				break;

			hdr = (void *) &buf[*pos];
			hdr->id = htonl(attr);
			hdr->charset = htons(0x6A); /* Always use UTF-8 */
			*pos += sizeof(*hdr);
		}

		attr_len = player_write_media_attribute(player, attr, buf,
								pos, offset);

		if (hdr != NULL)
			hdr->len = htons(attr_len);

		if (*offset > 0)
			break;
	}

	return l;
}

static struct pending_pdu *pending_pdu_new(uint8_t pdu_id, GList *attr_ids,
							unsigned int offset)
{
	struct pending_pdu *pending = g_new(struct pending_pdu, 1);

	pending->pdu_id = pdu_id;
	pending->attr_ids = attr_ids;
	pending->offset = offset;

	return pending;
}

static gboolean session_abort_pending_pdu(struct avrcp *session)
{
	if (session->pending_pdu == NULL)
		return FALSE;

	g_list_free(session->pending_pdu->attr_ids);
	g_free(session->pending_pdu);
	session->pending_pdu = NULL;

	return TRUE;
}

static const char *attrval_to_str(uint8_t attr, uint8_t value)
{
	switch (attr) {
	case AVRCP_ATTRIBUTE_EQUALIZER:
		switch (value) {
		case AVRCP_EQUALIZER_ON:
			return "on";
		case AVRCP_EQUALIZER_OFF:
			return "off";
		}

		break;
	case AVRCP_ATTRIBUTE_REPEAT_MODE:
		switch (value) {
		case AVRCP_REPEAT_MODE_OFF:
			return "off";
		case AVRCP_REPEAT_MODE_SINGLE:
			return "singletrack";
		case AVRCP_REPEAT_MODE_ALL:
			return "alltracks";
		case AVRCP_REPEAT_MODE_GROUP:
			return "group";
		}

		break;
	/* Shuffle and scan have the same values */
	case AVRCP_ATTRIBUTE_SHUFFLE:
	case AVRCP_ATTRIBUTE_SCAN:
		switch (value) {
		case AVRCP_SCAN_OFF:
			return "off";
		case AVRCP_SCAN_ALL:
			return "alltracks";
		case AVRCP_SCAN_GROUP:
			return "group";
		}

		break;
	}

	return NULL;
}

static int player_set_setting(struct avrcp_player *player, uint8_t id,
								uint8_t val)
{
	const char *key, *value;

	key = attr_to_str(id);
	if (key == NULL)
		return -EINVAL;

	value = attrval_to_str(id, val);
	if (value == NULL)
		return -EINVAL;

	if (player == NULL)
		return -ENOENT;

	return player->cb->set_setting(key, value, player->user_data);
}

static uint8_t avrcp_handle_get_capabilities(struct avrcp *session,
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
			set_company_id(&pdu->params[2 + i * 3],
							company_ids[i]);
		}

		pdu->params_len = htons(2 + (3 * G_N_ELEMENTS(company_ids)));
		pdu->params[1] = G_N_ELEMENTS(company_ids);

		return AVC_CTYPE_STABLE;
	case CAP_EVENTS_SUPPORTED:
		for (i = 0; i <= AVRCP_EVENT_LAST; i++) {
			if (session->supported_events & (1 << i)) {
				pdu->params[1]++;
				pdu->params[pdu->params[1] + 1] = i;
			}
		}

		pdu->params_len = htons(2 + pdu->params[1]);
		return AVC_CTYPE_STABLE;
	}

err:
	pdu->params_len = htons(1);
	pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;

	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_list_player_attributes(struct avrcp *session,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	struct avrcp_player *player = session->player;
	uint16_t len = ntohs(pdu->params_len);
	unsigned int i;

	if (len != 0) {
		pdu->params_len = htons(1);
		pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
		return AVC_CTYPE_REJECTED;
	}

	if (!player)
		goto done;

	for (i = 1; i <= AVRCP_ATTRIBUTE_SCAN; i++) {
		if (player_get_setting(player, i) < 0)
			continue;

		len++;
		pdu->params[len] = i;
	}

done:
	pdu->params[0] = len;
	pdu->params_len = htons(len + 1);

	return AVC_CTYPE_STABLE;
}

static uint8_t avrcp_handle_list_player_values(struct avrcp *session,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	struct avrcp_player *player = session->player;
	uint16_t len = ntohs(pdu->params_len);
	unsigned int i;

	if (len != 1)
		goto err;

	if (player_get_setting(player, pdu->params[0]) < 0)
		goto err;

	len = attr_get_max_val(pdu->params[0]);

	for (i = 1; i <= len; i++)
		pdu->params[i] = i;

	pdu->params[0] = len;
	pdu->params_len = htons(len + 1);

	return AVC_CTYPE_STABLE;

err:
	pdu->params_len = htons(1);
	pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static GList *player_list_metadata(struct avrcp_player *player)
{
	if (player != NULL)
		return player->cb->list_metadata(player->user_data);

	return g_list_prepend(NULL,
				GUINT_TO_POINTER(AVRCP_MEDIA_ATTRIBUTE_TITLE));
}

static uint8_t avrcp_handle_get_element_attributes(struct avrcp *session,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	struct avrcp_player *player = session->player;
	uint16_t len = ntohs(pdu->params_len);
	uint64_t identifier = bt_get_le64(&pdu->params[0]);
	uint16_t pos;
	uint8_t nattr;
	GList *attr_ids;
	uint16_t offset;

	if (len < 9 || identifier != 0)
		goto err;

	nattr = pdu->params[8];

	if (len < nattr * sizeof(uint32_t) + 1)
		goto err;

	if (!nattr) {
		/*
		 * Return all available information, at least
		 * title must be returned if there's a track selected.
		 */
		attr_ids = player_list_metadata(player);
		len = g_list_length(attr_ids);
	} else {
		unsigned int i;
		for (i = 0, len = 0, attr_ids = NULL; i < nattr; i++) {
			uint32_t id;

			id = bt_get_be32(&pdu->params[9] + (i * sizeof(id)));

			/* Don't add invalid attributes */
			if (id == AVRCP_MEDIA_ATTRIBUTE_ILLEGAL ||
					id > AVRCP_MEDIA_ATTRIBUTE_LAST)
				continue;

			len++;
			attr_ids = g_list_prepend(attr_ids,
							GUINT_TO_POINTER(id));
		}

		attr_ids = g_list_reverse(attr_ids);
	}

	if (!len)
		goto err;

	session_abort_pending_pdu(session);
	pos = 1;
	offset = 0;
	attr_ids = player_fill_media_attribute(player, attr_ids, pdu->params,
								&pos, &offset);

	if (attr_ids != NULL) {
		session->pending_pdu = pending_pdu_new(pdu->pdu_id, attr_ids,
								offset);
		pdu->packet_type = AVRCP_PACKET_TYPE_START;
	}

	pdu->params[0] = len;
	pdu->params_len = htons(pos);

	return AVC_CTYPE_STABLE;
err:
	pdu->params_len = htons(1);
	pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_get_current_player_value(struct avrcp *session,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	struct avrcp_player *player = session->player;
	uint16_t len = ntohs(pdu->params_len);
	uint8_t *settings;
	unsigned int i;

	if (len <= 1 || pdu->params[0] != len - 1)
		goto err;

	/*
	 * Save a copy of requested settings because we can override them
	 * while responding
	 */
	settings = g_memdup(&pdu->params[1], pdu->params[0]);
	len = 0;

	/*
	 * From sec. 5.7 of AVRCP 1.3 spec, we should igore non-existent IDs
	 * and send a response with the existent ones. Only if all IDs are
	 * non-existent we should send an error.
	 */
	for (i = 0; i < pdu->params[0]; i++) {
		int val;

		if (settings[i] < AVRCP_ATTRIBUTE_EQUALIZER ||
					settings[i] > AVRCP_ATTRIBUTE_SCAN) {
			DBG("Ignoring %u", settings[i]);
			continue;
		}

		val = player_get_setting(player, settings[i]);
		if (val < 0)
			continue;

		pdu->params[++len] = settings[i];
		pdu->params[++len] = val;
	}

	g_free(settings);

	if (len) {
		pdu->params[0] = len / 2;
		pdu->params_len = htons(len + 1);

		return AVC_CTYPE_STABLE;
	}

	error("No valid attributes in request");

err:
	pdu->params_len = htons(1);
	pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;

	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_set_player_value(struct avrcp *session,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	struct avrcp_player *player = session->player;
	uint16_t len = ntohs(pdu->params_len);
	unsigned int i;
	uint8_t *param;

	if (len < 3 || len > 2 * pdu->params[0] + 1U || player == NULL)
		goto err;

	/*
	 * From sec. 5.7 of AVRCP 1.3 spec, we should igore non-existent IDs
	 * and set the existent ones. Sec. 5.2.4 is not clear however how to
	 * indicate that a certain ID was not accepted. If at least one
	 * attribute is valid, we respond with no parameters. Otherwise an
	 * AVRCP_STATUS_INVALID_PARAM is sent.
	 */
	for (len = 0, i = 0, param = &pdu->params[1]; i < pdu->params[0];
							i++, param += 2) {
		if (player_set_setting(player, param[0], param[1]) < 0)
			continue;

		len++;
	}

	if (len) {
		pdu->params_len = 0;

		return AVC_CTYPE_ACCEPTED;
	}

err:
	pdu->params_len = htons(1);
	pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_displayable_charset(struct avrcp *session,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);

	if (len < 3) {
		pdu->params_len = htons(1);
		pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
		return AVC_CTYPE_REJECTED;
	}

	/*
	 * We acknowledge the commands, but we always use UTF-8 for
	 * encoding since CT is obliged to support it.
	 */
	pdu->params_len = 0;
	return AVC_CTYPE_STABLE;
}

static uint8_t avrcp_handle_ct_battery_status(struct avrcp *session,
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

	pdu->params_len = 0;

	return AVC_CTYPE_STABLE;

err:
	pdu->params_len = htons(1);
	pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint32_t player_get_position(struct avrcp_player *player)
{
	if (player == NULL)
		return 0;

	return player->cb->get_position(player->user_data);
}

static uint32_t player_get_duration(struct avrcp_player *player)
{
	uint32_t num;

	if (player == NULL)
		return UINT32_MAX;

	num = player->cb->get_duration(player->user_data);
	if (num == 0)
		return UINT32_MAX;

	return num;
}

static uint8_t player_get_status(struct avrcp_player *player)
{
	const char *value;

	if (player == NULL)
		return AVRCP_PLAY_STATUS_STOPPED;

	value = player->cb->get_status(player->user_data);

	return play_status_to_val(value);
}

static uint8_t avrcp_handle_get_play_status(struct avrcp *session,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	struct avrcp_player *player = session->player;
	uint16_t len = ntohs(pdu->params_len);
	uint32_t position;
	uint32_t duration;

	if (len != 0) {
		pdu->params_len = htons(1);
		pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
		return AVC_CTYPE_REJECTED;
	}

	position = player_get_position(player);
	duration = player_get_duration(player);

	position = htonl(position);
	duration = htonl(duration);

	memcpy(&pdu->params[0], &duration, 4);
	memcpy(&pdu->params[4], &position, 4);
	pdu->params[8] = player_get_status(player);

	pdu->params_len = htons(9);

	return AVC_CTYPE_STABLE;
}

static uint64_t player_get_uid(struct avrcp_player *player)
{
	if (player == NULL)
		return UINT64_MAX;

	return player->cb->get_uid(player->user_data);
}

static GList *player_list_settings(struct avrcp_player *player)
{
	if (player == NULL)
		return NULL;

	return player->cb->list_settings(player->user_data);
}

static uint8_t avrcp_handle_register_notification(struct avrcp *session,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	struct avrcp_player *player = session->player;
	struct audio_device *dev = session->dev;
	uint16_t len = ntohs(pdu->params_len);
	uint64_t uid;
	GList *settings;

	/*
	 * 1 byte for EventID, 4 bytes for Playback interval but the latest
	 * one is applicable only for EVENT_PLAYBACK_POS_CHANGED. See AVRCP
	 * 1.3 spec, section 5.4.2.
	 */
	if (len != 5)
		goto err;

	switch (pdu->params[0]) {
	case AVRCP_EVENT_STATUS_CHANGED:
		len = 2;
		pdu->params[1] = player_get_status(player);

		break;
	case AVRCP_EVENT_TRACK_CHANGED:
		len = 9;
		uid = player_get_uid(player);
		memcpy(&pdu->params[1], &uid, sizeof(uint64_t));

		break;
	case AVRCP_EVENT_TRACK_REACHED_END:
	case AVRCP_EVENT_TRACK_REACHED_START:
		len = 1;
		break;
	case AVRCP_EVENT_SETTINGS_CHANGED:
		settings = player_list_settings(player);

		pdu->params[++len] = g_list_length(settings);
		for (; settings; settings = settings->next) {
			const char *key = settings->data;
			uint8_t attr = attr_to_val(key);
			int val;

			val = player_get_setting(player, attr);
			if (val < 0)
				continue;

			pdu->params[++len] = attr;
			pdu->params[++len] = val;
		}

		break;
	case AVRCP_EVENT_VOLUME_CHANGED:
		if (session->version < 0x0104)
			goto err;

		pdu->params[1] = media_transport_get_device_volume(dev);
		if (pdu->params[1] > 127)
			goto err;

		len = 2;

		break;
	default:
		/* All other events are not supported yet */
		goto err;
	}

	/* Register event and save the transaction used */
	session->registered_events |= (1 << pdu->params[0]);
	session->transaction_events[pdu->params[0]] = transaction;

	pdu->params_len = htons(len);

	return AVC_CTYPE_INTERIM;

err:
	pdu->params_len = htons(1);
	pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_request_continuing(struct avrcp *session,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	struct avrcp_player *player = session->player;
	uint16_t len = ntohs(pdu->params_len);
	struct pending_pdu *pending;

	if (len != 1 || session->pending_pdu == NULL)
		goto err;

	pending = session->pending_pdu;

	if (pending->pdu_id != pdu->params[0])
		goto err;


	len = 0;
	pending->attr_ids = player_fill_media_attribute(player,
							pending->attr_ids,
							pdu->params, &len,
							&pending->offset);
	pdu->pdu_id = pending->pdu_id;

	if (pending->attr_ids == NULL) {
		g_free(session->pending_pdu);
		session->pending_pdu = NULL;
		pdu->packet_type = AVRCP_PACKET_TYPE_END;
	} else {
		pdu->packet_type = AVRCP_PACKET_TYPE_CONTINUING;
	}

	pdu->params_len = htons(len);

	return AVC_CTYPE_STABLE;
err:
	pdu->params_len = htons(1);
	pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_abort_continuing(struct avrcp *session,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	struct pending_pdu *pending;

	if (len != 1 || session->pending_pdu == NULL)
		goto err;

	pending = session->pending_pdu;

	if (pending->pdu_id != pdu->params[0])
		goto err;

	session_abort_pending_pdu(session);
	pdu->params_len = 0;

	return AVC_CTYPE_ACCEPTED;

err:
	pdu->params_len = htons(1);
	pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_set_absolute_volume(struct avrcp *session,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	struct avrcp_player *player = session->player;
	uint16_t len = ntohs(pdu->params_len);
	uint8_t volume;

	if (len != 1)
		goto err;

	volume = pdu->params[0] & 0x7F;
	if (volume > 127)
		goto err;

	if (!player)
		goto err;

	media_transport_update_device_volume(session->dev, pdu->params[0]);

	return AVC_CTYPE_ACCEPTED;

err:
	pdu->params_len = htons(1);
	pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static const struct control_pdu_handler tg_control_handlers[] = {
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
		{ AVRCP_REQUEST_CONTINUING, AVC_CTYPE_CONTROL,
					avrcp_handle_request_continuing },
		{ AVRCP_ABORT_CONTINUING, AVC_CTYPE_CONTROL,
					avrcp_handle_abort_continuing },
		{ },
};

static const struct control_pdu_handler ct_control_handlers[] = {
		{ AVRCP_GET_CAPABILITIES, AVC_CTYPE_STATUS,
					avrcp_handle_get_capabilities },
		{ AVRCP_REGISTER_NOTIFICATION, AVC_CTYPE_NOTIFY,
					avrcp_handle_register_notification },
		{ AVRCP_SET_ABSOLUTE_VOLUME, AVC_CTYPE_CONTROL,
					avrcp_handle_set_absolute_volume },
		{ },
};

/* handle vendordep pdu inside an avctp packet */
static size_t handle_vendordep_pdu(struct avctp *conn, uint8_t transaction,
					uint8_t *code, uint8_t *subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	const struct control_pdu_handler *handler;
	struct avrcp_header *pdu = (void *) operands;
	uint32_t company_id = get_company_id(pdu->company_id);

	if (company_id != IEEEID_BTSIG) {
		*code = AVC_CTYPE_NOT_IMPLEMENTED;
		return 0;
	}

	DBG("AVRCP PDU 0x%02X, company 0x%06X len 0x%04X",
			pdu->pdu_id, company_id, pdu->params_len);

	pdu->packet_type = 0;
	pdu->rsvd = 0;

	if (operand_count < AVRCP_HEADER_LENGTH) {
		pdu->params[0] = AVRCP_STATUS_INVALID_COMMAND;
		goto err_metadata;
	}

	for (handler = session->control_handlers; handler->pdu_id; handler++) {
		if (handler->pdu_id == pdu->pdu_id)
			break;
	}

	if (!handler || handler->code != *code) {
		pdu->params[0] = AVRCP_STATUS_INVALID_COMMAND;
		goto err_metadata;
	}

	if (!handler->func) {
		pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
		goto err_metadata;
	}

	*code = handler->func(session, pdu, transaction);

	if (*code != AVC_CTYPE_REJECTED &&
				pdu->pdu_id != AVRCP_GET_ELEMENT_ATTRIBUTES &&
				pdu->pdu_id != AVRCP_REQUEST_CONTINUING &&
				pdu->pdu_id != AVRCP_ABORT_CONTINUING)
		session_abort_pending_pdu(session);

	return AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);

err_metadata:
	pdu->params_len = htons(1);
	*code = AVC_CTYPE_REJECTED;

	return AVRCP_HEADER_LENGTH + 1;
}

static struct browsing_pdu_handler {
	uint8_t pdu_id;
	void (*func) (struct avrcp *session, struct avrcp_browsing_header *pdu,
							uint8_t transaction);
} browsing_handlers[] = {
		{ },
};

size_t avrcp_browsing_general_reject(uint8_t *operands)
{
	struct avrcp_browsing_header *pdu = (void *) operands;
	uint8_t status;

	pdu->pdu_id = AVRCP_GENERAL_REJECT;
	status = AVRCP_STATUS_INVALID_COMMAND;

	pdu->param_len = htons(sizeof(status));
	memcpy(pdu->params, &status, (sizeof(status)));
	return AVRCP_BROWSING_HEADER_LENGTH + sizeof(status);
}

static size_t handle_browsing_pdu(struct avctp *conn,
					uint8_t transaction, uint8_t *operands,
					size_t operand_count, void *user_data)
{
	struct avrcp *session = user_data;
	struct browsing_pdu_handler *handler;
	struct avrcp_browsing_header *pdu = (void *) operands;

	DBG("AVRCP Browsing PDU 0x%02X, len 0x%04X", pdu->pdu_id,
							pdu->param_len);

	for (handler = browsing_handlers; handler->pdu_id; handler++) {
		if (handler->pdu_id == pdu->pdu_id)
			break;
	}

	if (handler == NULL || handler->func == NULL)
		return avrcp_browsing_general_reject(operands);

	session->transaction = transaction;
	handler->func(session, pdu, transaction);
	return AVRCP_BROWSING_HEADER_LENGTH + ntohs(pdu->param_len);
}

size_t avrcp_handle_vendor_reject(uint8_t *code, uint8_t *operands)
{
	struct avrcp_header *pdu = (void *) operands;
	uint32_t company_id = get_company_id(pdu->company_id);

	*code = AVC_CTYPE_REJECTED;
	pdu->params_len = htons(1);
	pdu->params[0] = AVRCP_STATUS_INTERNAL_ERROR;

	DBG("rejecting AVRCP PDU 0x%02X, company 0x%06X len 0x%04X",
				pdu->pdu_id, company_id, pdu->params_len);

	return AVRCP_HEADER_LENGTH + 1;
}

static struct avrcp_server *find_server(GSList *list, struct btd_adapter *a)
{
	for (; list; list = list->next) {
		struct avrcp_server *server = list->data;

		if (server->adapter == a)
			return server;
	}

	return NULL;
}

static const char *status_to_string(uint8_t status)
{
	switch (status) {
	case AVRCP_PLAY_STATUS_STOPPED:
		return "stopped";
	case AVRCP_PLAY_STATUS_PLAYING:
		return "playing";
	case AVRCP_PLAY_STATUS_PAUSED:
		return "paused";
	case AVRCP_PLAY_STATUS_FWD_SEEK:
		return "forward-seek";
	case AVRCP_PLAY_STATUS_REV_SEEK:
		return "reverse-seek";
	case AVRCP_PLAY_STATUS_ERROR:
		return "error";
	default:
		return NULL;
	}
}

static gboolean avrcp_get_play_status_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct media_player *mp = player->user_data;
	struct avrcp_header *pdu = (void *) operands;
	uint32_t duration;
	uint32_t position;
	uint8_t status;

	if (code == AVC_CTYPE_REJECTED || ntohs(pdu->params_len) != 9)
		return FALSE;

	memcpy(&duration, pdu->params, sizeof(uint32_t));
	duration = ntohl(duration);
	media_player_set_duration(mp, duration);

	memcpy(&position, pdu->params + 4, sizeof(uint32_t));
	position = ntohl(position);
	media_player_set_position(mp, position);

	memcpy(&status, pdu->params + 8, sizeof(uint8_t));
	media_player_set_status(mp, status_to_string(status));

	return FALSE;
}

static void avrcp_get_play_status(struct avrcp *session)
{
	uint8_t buf[AVRCP_HEADER_LENGTH];
	struct avrcp_header *pdu = (void *) buf;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = AVRCP_GET_PLAY_STATUS;
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;

	avctp_send_vendordep_req(session->conn, AVC_CTYPE_STATUS,
					AVC_SUBUNIT_PANEL, buf, sizeof(buf),
					avrcp_get_play_status_rsp,
					session);
}

static const char *status_to_str(uint8_t status)
{
	switch (status) {
	case AVRCP_STATUS_INVALID_COMMAND:
		return "Invalid Command";
	case AVRCP_STATUS_INVALID_PARAM:
		return "Invalid Parameter";
	case AVRCP_STATUS_INTERNAL_ERROR:
		return "Internal Error";
	case AVRCP_STATUS_SUCCESS:
		return "Success";
	default:
		return "Unknown";
	}
}

static gboolean avrcp_player_value_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct media_player *mp = player->user_data;
	struct avrcp_header *pdu = (void *) operands;
	uint8_t count;
	int i;

	if (code == AVC_CTYPE_REJECTED) {
		media_player_set_setting(mp, "Error",
					status_to_str(pdu->params[0]));
		return FALSE;
	}

	count = pdu->params[0];

	if (pdu->params_len < count * 2)
		return FALSE;

	for (i = 1; count > 0; count--, i += 2) {
		const char *key;
		const char *value;

		key = attr_to_str(pdu->params[i]);
		if (key == NULL)
			continue;

		value = attrval_to_str(pdu->params[i], pdu->params[i + 1]);
		if (value == NULL)
			continue;

		media_player_set_setting(mp, key, value);
	}

	return FALSE;
}

static void avrcp_get_current_player_value(struct avrcp *session,
						uint8_t *attrs, uint8_t count)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + 5];
	struct avrcp_header *pdu = (void *) buf;
	int i;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = AVRCP_GET_CURRENT_PLAYER_VALUE;
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;
	pdu->params_len = htons(count + 1);
	pdu->params[0] = count;

	for (i = 0; count > 0; count--, i++)
		pdu->params[i + 1] = attrs[i];

	avctp_send_vendordep_req(session->conn, AVC_CTYPE_STATUS,
					AVC_SUBUNIT_PANEL, buf, sizeof(buf),
					avrcp_player_value_rsp, session);
}

static gboolean avrcp_list_player_attributes_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_header *pdu = (void *) operands;
	uint8_t count;

	if (code == AVC_CTYPE_REJECTED)
		return FALSE;

	count = pdu->params[0];

	if (ntohs(pdu->params_len) < count) {
		error("Invalid parameters");
		return FALSE;
	}

	avrcp_get_current_player_value(session, &pdu->params[1],
							pdu->params[0]);

	return FALSE;
}

static void avrcp_list_player_attributes(struct avrcp *session)
{
	uint8_t buf[AVRCP_HEADER_LENGTH];
	struct avrcp_header *pdu = (void *) buf;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = AVRCP_LIST_PLAYER_ATTRIBUTES;
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;

	avctp_send_vendordep_req(session->conn, AVC_CTYPE_STATUS,
					AVC_SUBUNIT_PANEL, buf, sizeof(buf),
					avrcp_list_player_attributes_rsp,
					session);
}

static void avrcp_parse_attribute_list(struct avrcp_player *player,
					uint8_t *operands, uint8_t count)
{
	struct media_player *mp = player->user_data;
	int i;

	for (i = 0; count > 0; count--) {
		uint32_t id;
		uint16_t charset, len;

		id = bt_get_be32(&operands[i]);
		i += sizeof(uint32_t);

		charset = bt_get_be16(&operands[i]);
		i += sizeof(uint16_t);

		len = bt_get_be16(&operands[i]);
		i += sizeof(uint16_t);

		if (charset == 106) {
			const char *key = metadata_to_str(id);

			if (key != NULL)
				media_player_set_metadata(mp,
							metadata_to_str(id),
							&operands[i], len);
		}

		i += len;
	}
}

static gboolean avrcp_get_element_attributes_rsp(struct avctp *conn,
						uint8_t code, uint8_t subunit,
						uint8_t *operands,
						size_t operand_count,
						void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_header *pdu = (void *) operands;
	uint8_t count;

	if (code == AVC_CTYPE_REJECTED)
		return FALSE;

	count = pdu->params[0];

	if (ntohs(pdu->params_len) - 1 < count * 8) {
		error("Invalid parameters");
		return FALSE;
	}

	avrcp_parse_attribute_list(player, &pdu->params[1], count);

	avrcp_get_play_status(session);

	return FALSE;
}

static void avrcp_get_element_attributes(struct avrcp *session)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + 9];
	struct avrcp_header *pdu = (void *) buf;
	uint16_t length;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = AVRCP_GET_ELEMENT_ATTRIBUTES;
	pdu->params_len = htons(9);
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;

	length = AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);

	avctp_send_vendordep_req(session->conn, AVC_CTYPE_STATUS,
					AVC_SUBUNIT_PANEL, buf, length,
					avrcp_get_element_attributes_rsp,
					session);
}

static const char *type_to_string(uint8_t type)
{
	switch (type & 0x0F) {
	case 0x01:
		return "Audio";
	case 0x02:
		return "Video";
	case 0x03:
		return "Audio, Video";
	case 0x04:
		return "Audio Broadcasting";
	case 0x05:
		return "Audio, Audio Broadcasting";
	case 0x06:
		return "Video, Audio Broadcasting";
	case 0x07:
		return "Audio, Video, Audio Broadcasting";
	case 0x08:
		return "Video Broadcasting";
	case 0x09:
		return "Audio, Video Broadcasting";
	case 0x0A:
		return "Video, Video Broadcasting";
	case 0x0B:
		return "Audio, Video, Video Broadcasting";
	case 0x0C:
		return "Audio Broadcasting, Video Broadcasting";
	case 0x0D:
		return "Audio, Audio Broadcasting, Video Broadcasting";
	case 0x0E:
		return "Video, Audio Broadcasting, Video Broadcasting";
	case 0x0F:
		return "Audio, Video, Audio Broadcasting, Video Broadcasting";
	}

	return "None";
}

static const char *subtype_to_string(uint32_t subtype)
{
	switch (subtype & 0x03) {
	case 0x01:
		return "Audio Book";
	case 0x02:
		return "Podcast";
	case 0x03:
		return "Audio Book, Podcast";
	}

	return "None";
}

static gboolean avrcp_set_browsed_player_rsp(struct avctp *conn,
						uint8_t *operands,
						size_t operand_count,
						void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct media_player *mp = player->user_data;
	struct avrcp_browsing_header *pdu = (void *) operands;
	uint32_t items;
	char **folders, *path;
	uint8_t depth, count;
	size_t i;

	if (pdu->params[0] != AVRCP_STATUS_SUCCESS || operand_count < 13)
		return FALSE;

	player->uid_counter = bt_get_be16(&pdu->params[1]);

	items = bt_get_be32(&pdu->params[3]);

	depth = pdu->params[9];

	folders = g_new0(char *, depth + 2);
	folders[0] = g_strdup("/Filesystem");

	for (i = 10, count = 1; count - 1 < depth && i < operand_count;
								count++) {
		uint8_t len;

		len = pdu->params[i++];

		if (i + len > operand_count || len == 0) {
			error("Invalid folder length");
			break;
		}

		folders[count] = g_memdup(&pdu->params[i], len);
		i += len;
	}

	path = g_build_pathv("/", folders);
	g_strfreev(folders);

	media_player_set_folder(mp, path, items);

	g_free(path);

	return FALSE;
}

static void avrcp_set_browsed_player(struct avrcp *session,
						struct avrcp_player *player)
{
	uint8_t buf[AVRCP_BROWSING_HEADER_LENGTH + 2];
	struct avrcp_browsing_header *pdu = (void *) buf;
	uint16_t id;

	memset(buf, 0, sizeof(buf));

	pdu->pdu_id = AVRCP_SET_BROWSED_PLAYER;
	id = htons(player->id);
	memcpy(pdu->params, &id, 2);
	pdu->param_len = htons(2);

	avctp_send_browsing_req(session->conn, buf, sizeof(buf),
				avrcp_set_browsed_player_rsp, session);
}

static gboolean avrcp_get_item_attributes_rsp(struct avctp *conn,
						uint8_t *operands,
						size_t operand_count,
						void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_browsing_header *pdu = (void *) operands;
	uint8_t count;

	if (pdu->params[0] != AVRCP_STATUS_SUCCESS || operand_count < 4) {
		if (pdu->params[0] == AVRCP_STATUS_PLAYER_NOT_BROWSABLE)
			avrcp_get_element_attributes(session);
		return FALSE;
	}

	count = pdu->params[1];

	if (ntohs(pdu->param_len) - 1 < count * 8) {
		error("Invalid parameters");
		return FALSE;
	}

	avrcp_parse_attribute_list(player, &pdu->params[2], count);

	avrcp_get_play_status(session);

	return FALSE;
}

static void avrcp_get_item_attributes(struct avrcp *session, uint64_t uid)
{
	uint8_t buf[AVRCP_BROWSING_HEADER_LENGTH + 12];
	struct avrcp_browsing_header *pdu = (void *) buf;

	memset(buf, 0, sizeof(buf));

	pdu->pdu_id = AVRCP_GET_ITEM_ATTRIBUTES;
	pdu->params[0] = 0x03;
	bt_put_be64(uid, &pdu->params[1]);
	bt_put_be16(session->player->uid_counter, &pdu->params[9]);
	pdu->param_len = htons(12);

	avctp_send_browsing_req(session->conn, buf, sizeof(buf),
				avrcp_get_item_attributes_rsp, session);
}

static void avrcp_player_parse_features(struct avrcp_player *player,
							uint8_t *features)
{
	struct media_player *mp = player->user_data;

	player->features = g_memdup(features, 16);

	if (features[7] & 0x08) {
		media_player_set_browsable(mp, true);
		media_player_create_folder(mp, "/Filesystem",
						PLAYER_FOLDER_TYPE_MIXED);
	}

	if (features[7] & 0x10)
		media_player_set_searchable(mp, true);

	if (features[8] & 0x02) {
		media_player_create_folder(mp, "/NowPlaying",
						PLAYER_FOLDER_TYPE_MIXED);
		media_player_set_playlist(mp, "/NowPlaying");
	}
}

static void avrcp_set_player_value(struct avrcp *session, uint8_t attr,
								uint8_t val)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + 3];
	struct avrcp_header *pdu = (void *) buf;
	uint8_t length;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = AVRCP_SET_PLAYER_VALUE;
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;
	pdu->params[0] = 1;
	pdu->params[1] = attr;
	pdu->params[2] = val;
	pdu->params_len = htons(3);

	length = AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);

	avctp_send_vendordep_req(session->conn, AVC_CTYPE_NOTIFY,
					AVC_SUBUNIT_PANEL, buf, length,
					avrcp_player_value_rsp, session);
}

static bool ct_set_setting(struct media_player *mp, const char *key,
					const char *value, void *user_data)
{
	struct avrcp_player *player = user_data;
	int attr;
	int val;
	struct avrcp *session;

	session = player->sessions->data;
	if (session == NULL)
		return false;

	if (session->version < 0x0103)
		return false;

	attr = attr_to_val(key);
	if (attr < 0)
		return false;

	val = attrval_to_val(attr, value);
	if (val < 0)
		return false;

	avrcp_set_player_value(session, attr, val);

	return true;
}

static int ct_press(struct avrcp_player *player, uint8_t op)
{
	int err;
	struct avrcp *session;

	session = player->sessions->data;
	if (session == NULL)
		return -ENOTCONN;

	err = avctp_send_passthrough(session->conn, op);
	if (err < 0)
		return err;

	return 0;
}

static int ct_play(struct media_player *mp, void *user_data)
{
	struct avrcp_player *player = user_data;

	return ct_press(player, AVC_PLAY);
}

static int ct_pause(struct media_player *mp, void *user_data)
{
	struct avrcp_player *player = user_data;

	return ct_press(player, AVC_PAUSE);
}

static int ct_stop(struct media_player *mp, void *user_data)
{
	struct avrcp_player *player = user_data;

	return ct_press(player, AVC_STOP);
}

static int ct_next(struct media_player *mp, void *user_data)
{
	struct avrcp_player *player = user_data;

	return ct_press(player, AVC_FORWARD);
}

static int ct_previous(struct media_player *mp, void *user_data)
{
	struct avrcp_player *player = user_data;

	return ct_press(player, AVC_BACKWARD);
}

static int ct_fast_forward(struct media_player *mp, void *user_data)
{
	struct avrcp_player *player = user_data;

	return ct_press(player, AVC_FAST_FORWARD);
}

static int ct_rewind(struct media_player *mp, void *user_data)
{
	struct avrcp_player *player = user_data;

	return ct_press(player, AVC_REWIND);
}

static const struct media_player_callback ct_cbs = {
	.set_setting	= ct_set_setting,
	.play		= ct_play,
	.pause		= ct_pause,
	.stop		= ct_stop,
	.next		= ct_next,
	.previous	= ct_previous,
	.fast_forward	= ct_fast_forward,
	.rewind		= ct_rewind,
};

static struct avrcp_player *create_ct_player(struct avrcp *session,
								uint16_t id)
{
	struct avrcp_player *player;
	struct media_player *mp;
	const char *path;

	player = g_new0(struct avrcp_player, 1);
	player->sessions = g_slist_prepend(player->sessions, session);

	path = device_get_path(session->dev->btd_dev);

	mp = media_player_controller_create(path, id);
	if (mp == NULL)
		return NULL;

	media_player_set_callbacks(mp, &ct_cbs, player);
	player->user_data = mp;
	player->destroy = (GDestroyNotify) media_player_destroy;

	if (session->player == NULL)
		session->player = player;

	session->players = g_slist_prepend(session->players, player);

	return player;
}

static struct avrcp_player *find_ct_player(struct avrcp *session, uint16_t id)
{
	GSList *l;

	for (l = session->players; l; l = l->next) {
		struct avrcp_player *player = l->data;

		if (player->id == 0) {
			player->id = id;
			return player;
		}

		if (player->id == id)
			return player;
	}

	return NULL;
}

static struct avrcp_player *
avrcp_parse_media_player_item(struct avrcp *session, uint8_t *operands,
							uint16_t len)
{
	struct avrcp_player *player;
	struct media_player *mp;
	uint16_t id, namelen;
	uint32_t subtype;
	const char *curval, *strval;
	char name[255];

	if (len < 28)
		return NULL;

	id = bt_get_be16(&operands[0]);

	player = find_ct_player(session, id);
	if (player == NULL) {
		player = create_ct_player(session, id);
		if (player == NULL)
			return NULL;
	}

	mp = player->user_data;

	media_player_set_type(mp, type_to_string(operands[2]));

	subtype = bt_get_be32(&operands[3]);

	media_player_set_subtype(mp, subtype_to_string(subtype));

	curval = media_player_get_status(mp);
	strval = status_to_string(operands[7]);

	if (g_strcmp0(curval, strval) != 0) {
		media_player_set_status(mp, strval);
		avrcp_get_play_status(session);
	}

	avrcp_player_parse_features(player, &operands[8]);

	namelen = bt_get_be16(&operands[26]);
	if (namelen > 0 && namelen + 28 == len) {
		namelen = MIN(namelen, sizeof(name) - 1);
		memcpy(name, &operands[28], namelen);
		name[namelen] = '\0';
		media_player_set_name(mp, name);
	}

	if (session->player == player)
		avrcp_set_browsed_player(session, player);

	return player;
}

static void player_destroy(gpointer data)
{
	struct avrcp_player *player = data;

	if (player->destroy)
		player->destroy(player->user_data);

	g_slist_free(player->sessions);
	g_free(player->features);
	g_free(player);
}

static gboolean avrcp_get_media_player_list_rsp(struct avctp *conn,
						uint8_t *operands,
						size_t operand_count,
						void *user_data)
{
	struct avrcp_browsing_header *pdu = (void *) operands;
	struct avrcp *session = user_data;
	uint16_t count;
	size_t i;
	GSList *removed;

	if (pdu->params[0] != AVRCP_STATUS_SUCCESS || operand_count < 5)
		return FALSE;

	removed = g_slist_copy(session->players);
	count = bt_get_be16(&operands[6]);

	for (i = 8; count && i < operand_count; count--) {
		struct avrcp_player *player;
		uint8_t type;
		uint16_t len;

		type = operands[i++];
		len = bt_get_be16(&operands[i]);
		i += 2;

		if (type != 0x01) {
			i += len;
			continue;
		}

		if (i + len > operand_count) {
			error("Invalid player item length");
			return FALSE;
		}

		player = avrcp_parse_media_player_item(session, &operands[i],
									len);
		if (player)
			removed = g_slist_remove(removed, player);

		i += len;
	}

	g_slist_free_full(removed, player_destroy);

	return FALSE;
}

static void avrcp_get_media_player_list(struct avrcp *session)
{
	uint8_t buf[AVRCP_BROWSING_HEADER_LENGTH + 10];
	struct avrcp_browsing_header *pdu = (void *) buf;

	memset(buf, 0, sizeof(buf));

	pdu->pdu_id = AVRCP_GET_FOLDER_ITEMS;
	pdu->param_len = htons(10);

	avctp_send_browsing_req(session->conn, buf, sizeof(buf),
				avrcp_get_media_player_list_rsp, session);
}

static void avrcp_volume_changed(struct avrcp *session,
						struct avrcp_header *pdu)
{
	struct avrcp_player *player = session->player;
	uint8_t volume;

	if (player == NULL)
		return;

	volume = pdu->params[1] & 0x7F;

	player->cb->set_volume(volume, session->dev, player->user_data);
}

static void avrcp_status_changed(struct avrcp *session,
						struct avrcp_header *pdu)
{
	struct avrcp_player *player = session->player;
	struct media_player *mp = player->user_data;
	uint8_t value;
	const char *curval, *strval;

	value = pdu->params[1];

	curval = media_player_get_status(mp);
	strval = status_to_string(value);

	if (g_strcmp0(curval, strval) == 0)
		return;

	media_player_set_status(mp, strval);
	avrcp_get_play_status(session);
}

static void avrcp_track_changed(struct avrcp *session,
						struct avrcp_header *pdu)
{
	uint64_t uid;

	if (session->browsing_id) {
		uid = bt_get_be64(&pdu->params[1]);
		avrcp_get_item_attributes(session, uid);
	} else
		avrcp_get_element_attributes(session);
}

static void avrcp_setting_changed(struct avrcp *session,
						struct avrcp_header *pdu)
{
	struct avrcp_player *player = session->player;
	struct media_player *mp = player->user_data;
	uint8_t count = pdu->params[1];
	int i;

	for (i = 2; count > 0; count--, i += 2) {
		const char *key;
		const char *value;

		key = attr_to_str(pdu->params[i]);
		if (key == NULL)
			continue;

		value = attrval_to_str(pdu->params[i], pdu->params[i + 1]);
		if (value == NULL)
			continue;

		media_player_set_setting(mp, key, value);
	}
}

static void avrcp_available_players_changed(struct avrcp *session,
						struct avrcp_header *pdu)
{
	avrcp_get_media_player_list(session);
}

static void avrcp_addressed_player_changed(struct avrcp *session,
						struct avrcp_header *pdu)
{
	struct avrcp_player *player = session->player;
	uint16_t id = bt_get_be16(&pdu->params[1]);

	if (player->id == id)
		return;

	player = find_ct_player(session, id);
	if (player == NULL)
		return;

	player->uid_counter = bt_get_be16(&pdu->params[3]);
	session->player = player;

	if (player->features != NULL)
		return;

	avrcp_get_media_player_list(session);
}

static void avrcp_uids_changed(struct avrcp *session, struct avrcp_header *pdu)
{
	struct avrcp_player *player = session->player;

	player->uid_counter = bt_get_be16(&pdu->params[1]);
}

static gboolean avrcp_handle_event(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_header *pdu = (void *) operands;
	uint8_t event;

	if (code != AVC_CTYPE_INTERIM && code != AVC_CTYPE_CHANGED)
		return FALSE;

	event = pdu->params[0];

	if (code == AVC_CTYPE_CHANGED) {
		session->registered_events ^= (1 << event);
		avrcp_register_notification(session, event);
		return FALSE;
	}

	switch (event) {
	case AVRCP_EVENT_VOLUME_CHANGED:
		avrcp_volume_changed(session, pdu);
		break;
	case AVRCP_EVENT_STATUS_CHANGED:
		avrcp_status_changed(session, pdu);
		break;
	case AVRCP_EVENT_TRACK_CHANGED:
		avrcp_track_changed(session, pdu);
		break;
	case AVRCP_EVENT_SETTINGS_CHANGED:
		avrcp_setting_changed(session, pdu);
		break;
	case AVRCP_EVENT_AVAILABLE_PLAYERS_CHANGED:
		avrcp_available_players_changed(session, pdu);
		break;
	case AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED:
		avrcp_addressed_player_changed(session, pdu);
		break;
	case AVRCP_EVENT_UIDS_CHANGED:
		avrcp_uids_changed(session, pdu);
		break;
	}

	session->registered_events |= (1 << event);

	return TRUE;
}

static void avrcp_register_notification(struct avrcp *session, uint8_t event)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + AVRCP_REGISTER_NOTIFICATION_PARAM_LENGTH];
	struct avrcp_header *pdu = (void *) buf;
	uint8_t length;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = AVRCP_REGISTER_NOTIFICATION;
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;
	pdu->params[0] = event;
	pdu->params_len = htons(AVRCP_REGISTER_NOTIFICATION_PARAM_LENGTH);

	length = AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);

	avctp_send_vendordep_req(session->conn, AVC_CTYPE_NOTIFY,
					AVC_SUBUNIT_PANEL, buf, length,
					avrcp_handle_event, session);
}

static gboolean avrcp_get_capabilities_resp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_header *pdu = (void *) operands;
	uint16_t events = 0;
	uint8_t count;

	if (pdu->params[0] != CAP_EVENTS_SUPPORTED)
		return FALSE;

	count = pdu->params[1];

	for (; count > 0; count--) {
		uint8_t event = pdu->params[1 + count];

		events |= (1 << event);

		switch (event) {
		case AVRCP_EVENT_STATUS_CHANGED:
		case AVRCP_EVENT_TRACK_CHANGED:
		case AVRCP_EVENT_SETTINGS_CHANGED:
		case AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED:
		case AVRCP_EVENT_UIDS_CHANGED:
		case AVRCP_EVENT_AVAILABLE_PLAYERS_CHANGED:
			avrcp_register_notification(session, event);
			break;
		}
	}

	if (!(events & (1 << AVRCP_EVENT_SETTINGS_CHANGED)))
		avrcp_list_player_attributes(session);

	if (!(events & (1 << AVRCP_EVENT_STATUS_CHANGED)))
		avrcp_get_play_status(session);

	if (!(events & (1 << AVRCP_EVENT_STATUS_CHANGED)))
		avrcp_get_element_attributes(session);

	return FALSE;
}

static void avrcp_get_capabilities(struct avrcp *session)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + AVRCP_GET_CAPABILITIES_PARAM_LENGTH];
	struct avrcp_header *pdu = (void *) buf;
	uint8_t length;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = AVRCP_GET_CAPABILITIES;
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;
	pdu->params[0] = CAP_EVENTS_SUPPORTED;
	pdu->params_len = htons(AVRCP_GET_CAPABILITIES_PARAM_LENGTH);

	length = AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);

	avctp_send_vendordep_req(session->conn, AVC_CTYPE_STATUS,
					AVC_SUBUNIT_PANEL, buf, length,
					avrcp_get_capabilities_resp,
					session);
}

static struct avrcp *find_session(GSList *list, struct audio_device *dev)
{
	for (; list; list = list->next) {
		struct avrcp *session = list->data;

		if (session->dev == dev)
			return session;
	}

	return NULL;
}

static void destroy_browsing(void *data)
{
	struct avrcp *session = data;

	session->browsing_id = 0;
}

static void session_tg_init_browsing(struct avrcp *session)
{
	session->browsing_id = avctp_register_browsing_pdu_handler(
							session->conn,
							handle_browsing_pdu,
							session,
							destroy_browsing);
}

static void session_tg_init_control(struct avrcp *session)
{
	struct avrcp_server *server = session->server;
	struct avrcp_player *player;

	if (session->version < 0x0103)
		return;

	DBG("%p version 0x%04x", session, session->version);

	player = g_slist_nth_data(server->players, 0);
	if (player != NULL) {
		session->player = player;
		player->sessions = g_slist_prepend(player->sessions, session);
	}

	session->control_id = avctp_register_pdu_handler(session->conn,
							AVC_OP_VENDORDEP,
							handle_vendordep_pdu,
							session);
	session->control_handlers = tg_control_handlers;
	session->supported_events = (1 << AVRCP_EVENT_STATUS_CHANGED) |
				(1 << AVRCP_EVENT_TRACK_CHANGED) |
				(1 << AVRCP_EVENT_TRACK_REACHED_START) |
				(1 << AVRCP_EVENT_TRACK_REACHED_END) |
				(1 << AVRCP_EVENT_SETTINGS_CHANGED);

	if (session->version >= 0x0104)
		avrcp_register_notification(session,
						AVRCP_EVENT_VOLUME_CHANGED);

	audio_controller_connected(session->dev->btd_dev, 0);
}

static void session_ct_init_browsing(struct avrcp *session)
{
	session->browsing_id = avctp_register_browsing_pdu_handler(
							session->conn,
							handle_browsing_pdu,
							session,
							destroy_browsing);
}

static void session_ct_init_control(struct avrcp *session)
{
	struct avrcp_player *player;

	DBG("%p version 0x%04x", session, session->version);

	session->control_id = avctp_register_pdu_handler(session->conn,
							AVC_OP_VENDORDEP,
							handle_vendordep_pdu,
							session);
	session->control_handlers = ct_control_handlers;
	if (session->version >= 0x0104)
		session->supported_events = (1 << AVRCP_EVENT_VOLUME_CHANGED);

	audio_target_connected(session->dev->btd_dev, 0);

	player = create_ct_player(session, 0);
	if (player == NULL)
		return;

	if (session->version < 0x0103)
		return;

	avrcp_get_capabilities(session);
}

static void session_destroy(struct avrcp *session)
{
	struct avrcp_server *server = session->server;

	server->sessions = g_slist_remove(server->sessions, session);

	if (session->control_id > 0)
		avctp_unregister_pdu_handler(session->control_id);

	if (session->browsing_id > 0)
		avctp_unregister_browsing_pdu_handler(session->browsing_id);

	g_free(session);
}

static void session_tg_destroy(struct avrcp *session)
{
	struct avrcp_player *player = session->player;

	DBG("%p", session);

	if (player != NULL)
		player->sessions = g_slist_remove(player->sessions, session);

	if (session->control_id == 0)
		audio_controller_connected(session->dev->btd_dev, -EIO);

	audio_controller_disconnected(session->dev->btd_dev, 0);

	session_destroy(session);
}

static void session_ct_destroy(struct avrcp *session)
{
	DBG("%p", session);

	g_slist_free_full(session->players, player_destroy);

	if (session->control_id == 0)
		audio_target_connected(session->dev->btd_dev, -EIO);

	audio_target_disconnected(session->dev->btd_dev, 0);

	session_destroy(session);
}

static struct avrcp *session_create(struct avrcp_server *server,
						struct audio_device *dev)
{
	struct avrcp *session;
	const sdp_record_t *rec;
	sdp_list_t *list;
	sdp_profile_desc_t *desc;

	session = g_new0(struct avrcp, 1);
	session->server = server;
	session->conn = avctp_connect(dev);
	session->dev = dev;

	server->sessions = g_slist_append(server->sessions, session);

	if (dev->sink && !dev->source)
		session->target = TRUE;
	else if (dev->source && !dev->sink)
		session->target = FALSE;
	else if (dev->sink && sink_is_active(dev))
		session->target = TRUE;
	else
		session->target = FALSE;

	if (session->target) {
		session->init_control = session_tg_init_control;
		session->init_browsing = session_tg_init_browsing;
		session->destroy = session_tg_destroy;
		rec = btd_device_get_record(dev->btd_dev, AVRCP_REMOTE_UUID);
	} else {
		session->init_control = session_ct_init_control;
		session->init_browsing = session_ct_init_browsing;
		session->destroy = session_ct_destroy;
		rec = btd_device_get_record(dev->btd_dev, AVRCP_TARGET_UUID);
	}

	if (rec == NULL)
		return session;

	if (sdp_get_profile_descs(rec, &list) < 0)
		return session;

	desc = list->data;
	session->version = desc->version;
	sdp_get_int_attr(rec, SDP_ATTR_SUPPORTED_FEATURES, &session->features);

	sdp_list_free(list, free);

	return session;
}

static void state_changed(struct audio_device *dev, avctp_state_t old_state,
							avctp_state_t new_state)
{
	struct avrcp_server *server;
	struct avrcp *session;

	server = find_server(servers, device_get_adapter(dev->btd_dev));
	if (!server)
		return;

	session = find_session(server->sessions, dev);

	switch (new_state) {
	case AVCTP_STATE_DISCONNECTED:
		if (session == NULL)
			break;

		session->destroy(session);

		break;
	case AVCTP_STATE_CONNECTING:
		if (session != NULL)
			break;

		session_create(server, dev);

		break;
	case AVCTP_STATE_CONNECTED:
		if (session == NULL || session->control_id > 0)
			break;

		session->init_control(session);

		if (session->version >= 0x0104 &&
				session->features & AVRCP_FEATURE_BROWSING)
			avctp_connect_browsing(session->conn);

		break;
	case AVCTP_STATE_BROWSING_CONNECTED:
		if (session == NULL || session->browsing_id > 0)
			break;

		session->init_browsing(session);
		break;
	default:
		return;
	}
}

gboolean avrcp_connect(struct audio_device *dev)
{
	struct avctp *session;

	session = avctp_connect(dev);
	if (session)
		return FALSE;

	return TRUE;
}

void avrcp_disconnect(struct audio_device *dev)
{
	struct avctp *session;

	session = avctp_get(dev);
	if (!session)
		return;

	avctp_disconnect(session);
}

static struct avrcp_server *avrcp_server_register(struct btd_adapter *adapter,
							GKeyFile *config)
{
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

	if (avctp_register(adapter, master) < 0)
		return NULL;

	server = g_new0(struct avrcp_server, 1);
	server->adapter = btd_adapter_ref(adapter);

	servers = g_slist_append(servers, server);

	if (!avctp_id)
		avctp_id = avctp_add_state_cb(NULL, state_changed);

	return server;
}

int avrcp_target_register(struct btd_adapter *adapter, GKeyFile *config)
{
	sdp_record_t *record;
	struct avrcp_server *server;

	server = find_server(servers, adapter);
	if (server != NULL)
		goto done;

	server = avrcp_server_register(adapter, config);
	if (server == NULL)
		return -EPROTONOSUPPORT;

done:
	record = avrcp_tg_record();
	if (!record) {
		error("Unable to allocate new service record");
		avrcp_target_unregister(adapter);
		return -1;
	}

	if (add_record_to_server(adapter_get_address(adapter), record) < 0) {
		error("Unable to register AVRCP target service record");
		avrcp_target_unregister(adapter);
		sdp_record_free(record);
		return -1;
	}
	server->tg_record_id = record->handle;

	return 0;
}

int avrcp_remote_register(struct btd_adapter *adapter, GKeyFile *config)
{
	sdp_record_t *record;
	struct avrcp_server *server;

	server = find_server(servers, adapter);
	if (server != NULL)
		goto done;

	server = avrcp_server_register(adapter, config);
	if (server == NULL)
		return -EPROTONOSUPPORT;

done:
	record = avrcp_ct_record();
	if (!record) {
		error("Unable to allocate new service record");
		avrcp_remote_unregister(adapter);
		return -1;
	}

	if (add_record_to_server(adapter_get_address(adapter), record) < 0) {
		error("Unable to register AVRCP service record");
		sdp_record_free(record);
		avrcp_remote_unregister(adapter);
		return -1;
	}
	server->ct_record_id = record->handle;

	return 0;
}

static void avrcp_server_unregister(struct avrcp_server *server)
{
	g_slist_free_full(server->sessions, g_free);
	g_slist_free_full(server->players, player_destroy);

	servers = g_slist_remove(servers, server);

	avctp_unregister(server->adapter);
	btd_adapter_unref(server->adapter);
	g_free(server);

	if (servers)
		return;

	if (avctp_id) {
		avctp_remove_state_cb(avctp_id);
		avctp_id = 0;
	}
}

void avrcp_target_unregister(struct btd_adapter *adapter)
{
	struct avrcp_server *server;

	server = find_server(servers, adapter);
	if (!server)
		return;

	if (server->tg_record_id != 0) {
		remove_record_from_server(server->tg_record_id);
		server->tg_record_id = 0;
	}

	if (server->ct_record_id == 0)
		avrcp_server_unregister(server);
}

void avrcp_remote_unregister(struct btd_adapter *adapter)
{
	struct avrcp_server *server;

	server = find_server(servers, adapter);
	if (!server)
		return;

	if (server->ct_record_id != 0) {
		remove_record_from_server(server->ct_record_id);
		server->ct_record_id = 0;
	}

	if (server->tg_record_id == 0)
		avrcp_server_unregister(server);
}

struct avrcp_player *avrcp_register_player(struct btd_adapter *adapter,
						struct avrcp_player_cb *cb,
						void *user_data,
						GDestroyNotify destroy)
{
	struct avrcp_server *server;
	struct avrcp_player *player;
	GSList *l;

	server = find_server(servers, adapter);
	if (!server)
		return NULL;

	player = g_new0(struct avrcp_player, 1);
	player->server = server;
	player->cb = cb;
	player->user_data = user_data;
	player->destroy = destroy;

	server->players = g_slist_append(server->players, player);

	/* Assign player to session without current player */
	for (l = server->sessions; l; l = l->next) {
		struct avrcp *session = l->data;

		if (session->player == NULL) {
			session->player = player;
			player->sessions = g_slist_append(player->sessions,
								session);
		}
	}

	return player;
}

void avrcp_unregister_player(struct avrcp_player *player)
{
	struct avrcp_server *server = player->server;
	GSList *l;

	server->players = g_slist_remove(server->players, player);

	/* Remove player from sessions using it */
	for (l = player->sessions; l; l = l->next) {
		struct avrcp *session = l->data;

		if (session->player == player)
			session->player = g_slist_nth_data(server->players, 0);
	}

	player_destroy(player);
}

static gboolean avrcp_handle_set_volume(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_header *pdu = (void *) operands;
	uint8_t volume;

	if (code == AVC_CTYPE_REJECTED || code == AVC_CTYPE_NOT_IMPLEMENTED)
		return FALSE;

	volume = pdu->params[0] & 0x7F;

	player->cb->set_volume(volume, session->dev, player->user_data);

	return FALSE;
}

int avrcp_set_volume(struct audio_device *dev, uint8_t volume)
{
	struct avrcp_server *server;
	struct avrcp *session;
	uint8_t buf[AVRCP_HEADER_LENGTH + 2];
	struct avrcp_header *pdu = (void *) buf;

	server = find_server(servers, device_get_adapter(dev->btd_dev));
	if (server == NULL)
		return -EINVAL;

	session = find_session(server->sessions, dev);
	if (session == NULL)
		return -ENOTCONN;

	if (session->version < 0x0104)
		return -ENOTSUP;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);

	DBG("volume=%u", volume);

	if (session->target) {
		pdu->pdu_id = AVRCP_SET_ABSOLUTE_VOLUME;
		pdu->params[0] = volume;
		pdu->params_len = htons(1);

		return avctp_send_vendordep_req(session->conn,
					AVC_CTYPE_CONTROL, AVC_SUBUNIT_PANEL,
					buf, sizeof(buf),
					avrcp_handle_set_volume, session);
	} else if (session->registered_events &
					(1 << AVRCP_EVENT_VOLUME_CHANGED)) {
		uint8_t id = AVRCP_EVENT_VOLUME_CHANGED;
		pdu->pdu_id = AVRCP_REGISTER_NOTIFICATION;
		pdu->params[0] = AVRCP_EVENT_VOLUME_CHANGED;
		pdu->params[1] = volume;
		pdu->params_len = htons(2);

		return avctp_send_vendordep(session->conn,
					session->transaction_events[id],
					AVC_CTYPE_CHANGED, AVC_SUBUNIT_PANEL,
					buf, sizeof(buf));
	}

	return 0;
}
