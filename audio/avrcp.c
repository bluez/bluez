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
#include "avrcp.h"
#include "sdpd.h"
#include "glib-compat.h"
#include "dbus-common.h"

/* Company IDs for vendor dependent commands */
#define IEEEID_BTSIG		0x001958

/* Error codes for metadata transfer */
#define E_INVALID_COMMAND	0x00
#define E_INVALID_PARAM		0x01
#define E_PARAM_NOT_FOUND	0x02
#define E_INTERNAL		0x03

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

/* Capabilities for AVRCP_GET_CAPABILITIES pdu */
#define CAP_COMPANY_ID		0x02
#define CAP_EVENTS_SUPPORTED	0x03

enum battery_status {
	BATTERY_STATUS_NORMAL =		0,
	BATTERY_STATUS_WARNING =	1,
	BATTERY_STATUS_CRITICAL =	2,
	BATTERY_STATUS_EXTERNAL =	3,
	BATTERY_STATUS_FULL_CHARGE =	4,
};

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

struct avrcp_server {
	bdaddr_t src;
	uint32_t tg_record_id;
	uint32_t ct_record_id;
	GSList *players;
	struct avrcp_player *active_player;
};

struct pending_pdu {
	uint8_t pdu_id;
	GList *attr_ids;
	uint16_t offset;
};

struct avrcp_player {
	struct avrcp_server *server;
	struct avctp *session;
	struct audio_device *dev;

	unsigned int handler;
	uint16_t registered_events;
	uint8_t transaction_events[AVRCP_EVENT_LAST + 1];
	struct pending_pdu *pending_pdu;

	struct avrcp_player_cb *cb;
	void *user_data;
	GDestroyNotify destroy;
};

static GSList *servers = NULL;
static unsigned int avctp_id = 0;

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

int avrcp_player_event(struct avrcp_player *player, uint8_t id, void *data)
{
	uint8_t buf[AVRCP_HEADER_LENGTH + 9];
	struct avrcp_header *pdu = (void *) buf;
	uint16_t size;
	int err;

	if (player->session == NULL)
		return -ENOTCONN;

	if (!(player->registered_events & (1 << id)))
		return 0;

	memset(buf, 0, sizeof(buf));

	set_company_id(pdu->company_id, IEEEID_BTSIG);

	pdu->pdu_id = AVRCP_REGISTER_NOTIFICATION;
	pdu->params[0] = id;

	DBG("id=%u", id);

	switch (id) {
	case AVRCP_EVENT_STATUS_CHANGED:
		size = 2;
		pdu->params[1] = *((uint8_t *)data);

		break;
	case AVRCP_EVENT_TRACK_CHANGED:
		size = 9;
		memcpy(&pdu->params[1], data, sizeof(uint64_t));

		break;
	case AVRCP_EVENT_TRACK_REACHED_END:
	case AVRCP_EVENT_TRACK_REACHED_START:
		size = 1;
		break;
	default:
		error("Unknown event %u", id);
		return -EINVAL;
	}

	pdu->params_len = htons(size);

	err = avctp_send_vendordep(player->session, player->transaction_events[id],
					AVC_CTYPE_CHANGED, AVC_SUBUNIT_PANEL,
					buf, size + AVRCP_HEADER_LENGTH);
	if (err < 0)
		return err;

	/* Unregister event as per AVRCP 1.3 spec, section 5.4.2 */
	player->registered_events ^= 1 << id;

	return 0;
}

static uint16_t player_write_media_attribute(struct avrcp_player *player,
						uint32_t id, uint8_t *buf,
						uint16_t *pos,
						uint16_t *offset)
{
	uint16_t len;
	uint16_t attr_len;
	char valstr[20];
	void *value;

	DBG("%u", id);

	value = player->cb->get_metadata(id, player->user_data);
	if (value == NULL) {
		*offset = 0;
		return 0;
	}

	switch (id) {
	case AVRCP_MEDIA_ATTRIBUTE_TRACK:
	case AVRCP_MEDIA_ATTRIBUTE_N_TRACKS:
	case AVRCP_MEDIA_ATTRIBUTE_DURATION:
		snprintf(valstr, 20, "%u", GPOINTER_TO_UINT(value));
		value = valstr;
		break;
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

static gboolean player_abort_pending_pdu(struct avrcp_player *player)
{
	if (player->pending_pdu == NULL)
		return FALSE;

	g_list_free(player->pending_pdu->attr_ids);
	g_free(player->pending_pdu);
	player->pending_pdu = NULL;

	return TRUE;
}

static int player_set_attribute(struct avrcp_player *player,
						uint8_t attr, uint8_t val)
{
	DBG("Change attribute: %u %u", attr, val);

	return player->cb->set_setting(attr, val, player->user_data);
}

static int player_get_attribute(struct avrcp_player *player, uint8_t attr)
{
	int value;

	DBG("attr %u", attr);

	value = player->cb->get_setting(attr, player->user_data);
	if (value < 0)
		DBG("attr %u not supported by player", attr);

	return value;
}

static uint8_t avrcp_handle_get_capabilities(struct avrcp_player *player,
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
		pdu->params_len = htons(5);
		pdu->params[1] = 3;
		pdu->params[2] = AVRCP_EVENT_STATUS_CHANGED;
		pdu->params[3] = AVRCP_EVENT_TRACK_CHANGED;
		pdu->params[4] = AVRCP_EVENT_TRACK_REACHED_START;

		return AVC_CTYPE_STABLE;
	}

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;

	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_list_player_attributes(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	unsigned int i;

	if (len != 0) {
		pdu->params_len = htons(1);
		pdu->params[0] = E_INVALID_PARAM;
		return AVC_CTYPE_REJECTED;
	}

	if (!player)
		goto done;

	for (i = 1; i <= AVRCP_ATTRIBUTE_SCAN; i++) {
		if (player_get_attribute(player, i) < 0)
			continue;

		len++;
		pdu->params[len] = i;
	}

done:
	pdu->params[0] = len;
	pdu->params_len = htons(len + 1);

	return AVC_CTYPE_STABLE;
}

static uint8_t avrcp_handle_list_player_values(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	unsigned int i;

	if (len != 1 || !player)
		goto err;

	if (player_get_attribute(player, pdu->params[0]) < 0)
		goto err;

	len = attr_get_max_val(pdu->params[0]);

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

static uint8_t avrcp_handle_get_element_attributes(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	uint64_t *identifier = (uint64_t *) &pdu->params[0];
	uint16_t pos;
	uint8_t nattr;
	GList *attr_ids;
	uint16_t offset;

	if (len < 9 || *identifier != 0)
		goto err;

	nattr = pdu->params[8];

	if (len < nattr * sizeof(uint32_t) + 1)
		goto err;

	if (!nattr) {
		/*
		 * Return all available information, at least
		 * title must be returned if there's a track selected.
		 */
		attr_ids = player->cb->list_metadata(player->user_data);
		len = g_list_length(attr_ids);
	} else {
		unsigned int i;
		uint32_t *attr = (uint32_t *) &pdu->params[9];

		for (i = 0, len = 0, attr_ids = NULL; i < nattr; i++, attr++) {
			uint32_t id = ntohl(bt_get_unaligned(attr));

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

	player_abort_pending_pdu(player);
	pos = 1;
	offset = 0;
	attr_ids = player_fill_media_attribute(player, attr_ids, pdu->params,
								&pos, &offset);

	if (attr_ids != NULL) {
		player->pending_pdu = pending_pdu_new(pdu->pdu_id, attr_ids,
								offset);
		pdu->packet_type = AVRCP_PACKET_TYPE_START;
	}

	pdu->params[0] = len;
	pdu->params_len = htons(pos);

	return AVC_CTYPE_STABLE;
err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_get_current_player_value(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	uint8_t *settings;
	unsigned int i;

	if (player == NULL || len <= 1 || pdu->params[0] != len - 1)
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

		val = player_get_attribute(player, settings[i]);
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
	pdu->params[0] = E_INVALID_PARAM;

	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_set_player_value(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	unsigned int i;
	uint8_t *param;

	if (len < 3 || len > 2 * pdu->params[0] + 1U)
		goto err;

	/*
	 * From sec. 5.7 of AVRCP 1.3 spec, we should igore non-existent IDs
	 * and set the existent ones. Sec. 5.2.4 is not clear however how to
	 * indicate that a certain ID was not accepted. If at least one
	 * attribute is valid, we respond with no parameters. Otherwise an
	 * E_INVALID_PARAM is sent.
	 */
	for (len = 0, i = 0, param = &pdu->params[1]; i < pdu->params[0];
							i++, param += 2) {
		if (player_set_attribute(player, param[0], param[1]) < 0)
			continue;

		len++;
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

static uint8_t avrcp_handle_displayable_charset(struct avrcp_player *player,
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

static uint8_t avrcp_handle_ct_battery_status(struct avrcp_player *player,
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
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_get_play_status(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	uint32_t position;
	uint32_t duration;
	void *pduration;

	if (len != 0) {
		pdu->params_len = htons(1);
		pdu->params[0] = E_INVALID_PARAM;
		return AVC_CTYPE_REJECTED;
	}

	position = player->cb->get_position(player->user_data);
	pduration = player->cb->get_metadata(AVRCP_MEDIA_ATTRIBUTE_DURATION,
							player->user_data);
	if (pduration != NULL)
		duration = htonl(GPOINTER_TO_UINT(pduration));
	else
		duration = htonl(UINT32_MAX);

	position = htonl(position);

	memcpy(&pdu->params[0], &duration, 4);
	memcpy(&pdu->params[4], &position, 4);
	pdu->params[8] = player->cb->get_status(player->user_data);;

	pdu->params_len = htons(9);

	return AVC_CTYPE_STABLE;
}

static uint8_t avrcp_handle_register_notification(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	uint64_t uid;

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
		pdu->params[1] = player->cb->get_status(player->user_data);

		break;
	case AVRCP_EVENT_TRACK_CHANGED:
		len = 9;
		uid = player->cb->get_uid(player->user_data);
		memcpy(&pdu->params[1], &uid, sizeof(uint64_t));

		break;
	case AVRCP_EVENT_TRACK_REACHED_END:
	case AVRCP_EVENT_TRACK_REACHED_START:
		len = 1;
		break;
	default:
		/* All other events are not supported yet */
		goto err;
	}

	/* Register event and save the transaction used */
	player->registered_events |= (1 << pdu->params[0]);
	player->transaction_events[pdu->params[0]] = transaction;

	pdu->params_len = htons(len);

	return AVC_CTYPE_INTERIM;

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_request_continuing(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	struct pending_pdu *pending;

	if (len != 1 || player->pending_pdu == NULL)
		goto err;

	pending = player->pending_pdu;

	if (pending->pdu_id != pdu->params[0])
		goto err;


	len = 0;
	pending->attr_ids = player_fill_media_attribute(player,
							pending->attr_ids,
							pdu->params, &len,
							&pending->offset);
	pdu->pdu_id = pending->pdu_id;

	if (pending->attr_ids == NULL) {
		g_free(player->pending_pdu);
		player->pending_pdu = NULL;
		pdu->packet_type = AVRCP_PACKET_TYPE_END;
	} else {
		pdu->packet_type = AVRCP_PACKET_TYPE_CONTINUING;
	}

	pdu->params_len = htons(len);

	return AVC_CTYPE_STABLE;
err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}

static uint8_t avrcp_handle_abort_continuing(struct avrcp_player *player,
						struct avrcp_header *pdu,
						uint8_t transaction)
{
	uint16_t len = ntohs(pdu->params_len);
	struct pending_pdu *pending;

	if (len != 1 || player->pending_pdu == NULL)
		goto err;

	pending = player->pending_pdu;

	if (pending->pdu_id != pdu->params[0])
		goto err;

	player_abort_pending_pdu(player);
	pdu->params_len = 0;

	return AVC_CTYPE_STABLE;

err:
	pdu->params_len = htons(1);
	pdu->params[0] = E_INVALID_PARAM;
	return AVC_CTYPE_REJECTED;
}


static struct pdu_handler {
	uint8_t pdu_id;
	uint8_t code;
	uint8_t (*func) (struct avrcp_player *player,
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
		{ AVRCP_REQUEST_CONTINUING, AVC_CTYPE_CONTROL,
					avrcp_handle_request_continuing },
		{ AVRCP_ABORT_CONTINUING, AVC_CTYPE_CONTROL,
					avrcp_handle_abort_continuing },
		{ },
};

/* handle vendordep pdu inside an avctp packet */
static size_t handle_vendordep_pdu(struct avctp *session, uint8_t transaction,
					uint8_t *code, uint8_t *subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp_player *player = user_data;
	struct pdu_handler *handler;
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
		pdu->params[0] = E_INVALID_COMMAND;
		goto err_metadata;
	}

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

	*code = handler->func(player, pdu, transaction);

	if (*code != AVC_CTYPE_REJECTED &&
				pdu->pdu_id != AVRCP_GET_ELEMENT_ATTRIBUTES &&
				pdu->pdu_id != AVRCP_REQUEST_CONTINUING &&
				pdu->pdu_id != AVRCP_ABORT_CONTINUING)
		player_abort_pending_pdu(player);

	return AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);

err_metadata:
	pdu->params_len = htons(1);
	*code = AVC_CTYPE_REJECTED;

	return AVRCP_HEADER_LENGTH + 1;
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

static void state_changed(struct audio_device *dev, avctp_state_t old_state,
				avctp_state_t new_state, void *user_data)
{
	struct avrcp_server *server;
	struct avrcp_player *player;

	server = find_server(servers, &dev->src);
	if (!server)
		return;

	player = server->active_player;
	if (!player)
		return;

	switch (new_state) {
	case AVCTP_STATE_DISCONNECTED:
		player->session = NULL;
		player->registered_events = 0;

		if (player->handler) {
			avctp_unregister_pdu_handler(player->handler);
			player->handler = 0;
		}

		break;
	case AVCTP_STATE_CONNECTING:
		player->session = avctp_connect(&dev->src, &dev->dst);

		if (!player->handler)
			player->handler = avctp_register_pdu_handler(
							AVC_OP_VENDORDEP,
							handle_vendordep_pdu,
							player);
		break;
	default:
		return;
	}
}

gboolean avrcp_connect(struct audio_device *dev)
{
	struct avctp *session;

	session = avctp_connect(&dev->src, &dev->dst);
	if (session)
		return FALSE;

	return TRUE;
}

void avrcp_disconnect(struct audio_device *dev)
{
	struct avctp *session;

	session = avctp_get(&dev->src, &dev->dst);
	if (!session)
		return;

	avctp_disconnect(session);
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
		error("Unable to register AVRCP service record");
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

static void player_destroy(gpointer data)
{
	struct avrcp_player *player = data;

	if (player->destroy)
		player->destroy(player->user_data);

	player_abort_pending_pdu(player);

	if (player->handler)
		avctp_unregister_pdu_handler(player->handler);

	g_free(player);
}

void avrcp_unregister(const bdaddr_t *src)
{
	struct avrcp_server *server;

	server = find_server(servers, src);
	if (!server)
		return;

	g_slist_free_full(server->players, player_destroy);

	servers = g_slist_remove(servers, server);

	remove_record_from_server(server->ct_record_id);
	remove_record_from_server(server->tg_record_id);

	avctp_unregister(&server->src);
	g_free(server);

	if (servers)
		return;

	if (avctp_id) {
		avctp_remove_state_cb(avctp_id);
		avctp_id = 0;
	}
}

struct avrcp_player *avrcp_register_player(const bdaddr_t *src,
						struct avrcp_player_cb *cb,
						void *user_data,
						GDestroyNotify destroy)
{
	struct avrcp_server *server;
	struct avrcp_player *player;

	server = find_server(servers, src);
	if (!server)
		return NULL;

	player = g_new0(struct avrcp_player, 1);
	player->server = server;
	player->cb = cb;
	player->user_data = user_data;
	player->destroy = destroy;

	if (!server->players)
		server->active_player = player;

	if (!avctp_id)
		avctp_id = avctp_add_state_cb(state_changed, NULL);

	server->players = g_slist_append(server->players, player);

	return player;
}

void avrcp_unregister_player(struct avrcp_player *player)
{
	struct avrcp_server *server = player->server;

	server->players = g_slist_remove(server->players, player);

	if (server->active_player == player)
		server->active_player = g_slist_nth_data(server->players, 0);

	player_destroy(player);
}
