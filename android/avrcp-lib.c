/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <glib.h>
#include <errno.h>
#include <string.h>

#include "lib/bluetooth.h"

#include "src/shared/util.h"
#include "src/log.h"

#include "avctp.h"
#include "avrcp-lib.h"


/* Packet types */
#define AVRCP_PACKET_TYPE_SINGLE		0x00
#define AVRCP_PACKET_TYPE_START			0x01
#define AVRCP_PACKET_TYPE_CONTINUING		0x02
#define AVRCP_PACKET_TYPE_END			0x03

#define AVRCP_CHARSET_UTF8	0x006a

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

struct avrcp_browsing_header {
	uint8_t pdu_id;
	uint16_t params_len;
	uint8_t params[0];
} __attribute__ ((packed));
#define AVRCP_BROWSING_HEADER_LENGTH 3

struct avrcp_control_handler {
	uint8_t id;
	uint8_t code;
	uint8_t rsp;
	ssize_t (*func) (struct avrcp *session, uint8_t transaction,
			uint16_t params_len, uint8_t *params, void *user_data);
};

struct avrcp_browsing_handler {
	uint8_t id;
	ssize_t (*func) (struct avrcp *session, uint8_t transaction,
			uint16_t params_len, uint8_t *params, void *user_data);
};

struct avrcp {
	struct avctp *conn;
	struct avrcp_player *player;

	const struct avrcp_control_handler *control_handlers;
	void *control_data;
	unsigned int control_id;

	const struct avrcp_passthrough_handler *passthrough_handlers;
	void *passthrough_data;
	unsigned int passthrough_id;

	const struct avrcp_browsing_handler *browsing_handlers;
	void *browsing_data;
	unsigned int browsing_id;

	avrcp_destroy_cb_t destroy;
	void *destroy_data;
};

struct avrcp_player {
	const struct avrcp_control_ind *ind;
	const struct avrcp_control_cfm *cfm;

	void *user_data;
};

static inline uint32_t ntoh24(const uint8_t src[3])
{
	return src[0] << 16 | src[1] << 8 | src[2];
}

static inline void hton24(uint8_t dst[3], uint32_t src)
{
	dst[0] = (src & 0xff0000) >> 16;
	dst[1] = (src & 0x00ff00) >> 8;
	dst[2] = (src & 0x0000ff);
}

void avrcp_shutdown(struct avrcp *session)
{
	if (session->conn) {
		if (session->control_id > 0)
			avctp_unregister_pdu_handler(session->conn,
							session->control_id);
		if (session->passthrough_id > 0)
			avctp_unregister_passthrough_handler(session->conn,
						session->passthrough_id);

		/* clear destroy callback that would call shutdown again */
		avctp_set_destroy_cb(session->conn, NULL, NULL);
		avctp_shutdown(session->conn);
	}

	if (session->destroy)
		session->destroy(session->destroy_data);

	g_free(session->player);
	g_free(session);
}

static struct avrcp_header *parse_pdu(uint8_t *operands, size_t operand_count)
{
	struct avrcp_header *pdu;

	if (!operands || operand_count < sizeof(*pdu)) {
		error("AVRCP: packet too small (%zu bytes)", operand_count);
		return NULL;
	}

	pdu = (void *) operands;
	pdu->params_len = ntohs(pdu->params_len);

	if (operand_count != pdu->params_len + sizeof(*pdu)) {
		error("AVRCP: invalid parameter length (%u bytes)",
							pdu->params_len);
		return NULL;
	}

	return pdu;
}

static struct avrcp_browsing_header *parse_browsing_pdu(uint8_t *operands,
							size_t operand_count)
{
	struct avrcp_browsing_header *pdu;

	if (!operands || operand_count < sizeof(*pdu)) {
		error("AVRCP: packet too small (%zu bytes)", operand_count);
		return NULL;
	}

	pdu = (void *) operands;
	pdu->params_len = ntohs(pdu->params_len);

	if (operand_count != pdu->params_len + sizeof(*pdu)) {
		error("AVRCP: invalid parameter length (%u bytes)",
							pdu->params_len);
		return NULL;
	}

	return pdu;
}

static uint8_t errno2status(int err)
{
	switch (err) {
	case -ENOSYS:
		return AVRCP_STATUS_INVALID_COMMAND;
	case -EINVAL:
		return AVRCP_STATUS_INVALID_PARAM;
	case 0:
		return AVRCP_STATUS_SUCCESS;
	case -ENOTDIR:
		return AVRCP_STATUS_NOT_DIRECTORY;
	case -EBADRQC:
		return AVRCP_STATUS_INVALID_SCOPE;
	case -ERANGE:
		return AVRCP_STATUS_OUT_OF_BOUNDS;
	case -ENOENT:
		return AVRCP_STATUS_DOES_NOT_EXIST;
	default:
		return AVRCP_STATUS_INTERNAL_ERROR;
	}
}

static ssize_t handle_vendordep_pdu(struct avctp *conn, uint8_t transaction,
					uint8_t *code, uint8_t *subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	const struct avrcp_control_handler *handler;
	struct avrcp_header *pdu;
	uint32_t company_id;
	ssize_t ret;

	pdu = parse_pdu(operands, operand_count);
	if (!pdu) {
		pdu = (void *) operands;
		pdu->params[0] = AVRCP_STATUS_INVALID_COMMAND;
		goto reject;
	}

	company_id = ntoh24(pdu->company_id);
	if (company_id != IEEEID_BTSIG) {
		*code = AVC_CTYPE_NOT_IMPLEMENTED;
		return 0;
	}

	DBG("AVRCP PDU 0x%02X, len 0x%04X", pdu->pdu_id, pdu->params_len);

	pdu->packet_type = 0;
	pdu->rsvd = 0;

	if (!session->control_handlers)
		goto reject;

	for (handler = session->control_handlers; handler->id; handler++) {
		if (handler->id == pdu->pdu_id)
			break;
	}

	if (handler->id != pdu->pdu_id || handler->code != *code) {
		pdu->params[0] = AVRCP_STATUS_INVALID_COMMAND;
		goto reject;
	}

	if (!handler->func) {
		pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
		goto reject;
	}

	ret = handler->func(session, transaction, pdu->params_len, pdu->params,
							session->control_data);
	if (ret < 0) {
		if (ret == -EAGAIN)
			return ret;
		pdu->params[0] = errno2status(ret);
		goto reject;
	}

	*code = handler->rsp;
	pdu->params_len = htons(ret);

	return AVRCP_HEADER_LENGTH + ret;

reject:
	pdu->params_len = htons(1);
	*code = AVC_CTYPE_REJECTED;

	return AVRCP_HEADER_LENGTH + 1;
}

static bool handle_passthrough_pdu(struct avctp *conn, uint8_t op,
						bool pressed, void *user_data)
{
	struct avrcp *session = user_data;
	const struct avrcp_passthrough_handler *handler;

	if (!session->passthrough_handlers)
		return false;

	for (handler = session->passthrough_handlers; handler->func;
								handler++) {
		if (handler->op == op)
			break;
	}

	if (handler->func == NULL)
		return false;

	return handler->func(session, pressed, session->passthrough_data);
}

static void disconnect_cb(void *data)
{
	struct avrcp *session = data;

	session->conn = NULL;

	avrcp_shutdown(session);
}

struct avrcp *avrcp_new(int fd, size_t imtu, size_t omtu, uint16_t version)
{
	struct avrcp *session;

	session = g_new0(struct avrcp, 1);

	session->conn = avctp_new(fd, imtu, omtu, version);
	if (!session->conn) {
		g_free(session);
		return NULL;
	}

	session->passthrough_id = avctp_register_passthrough_handler(
							session->conn,
							handle_passthrough_pdu,
							session);
	session->control_id = avctp_register_pdu_handler(session->conn,
							AVC_OP_VENDORDEP,
							handle_vendordep_pdu,
							session);

	avctp_set_destroy_cb(session->conn, disconnect_cb, session);

	return session;
}

static ssize_t handle_browsing_pdu(struct avctp *conn,
					uint8_t transaction, uint8_t *operands,
					size_t operand_count, void *user_data)
{
	struct avrcp *session = user_data;
	const struct avrcp_browsing_handler *handler;
	struct avrcp_browsing_header *pdu;
	int ret;

	pdu = parse_browsing_pdu(operands, operand_count);
	if (!pdu) {
		pdu = (void *) operands;
		pdu->params[0] = AVRCP_STATUS_INVALID_COMMAND;
		goto reject;
	}

	DBG("AVRCP Browsing PDU 0x%02X, len 0x%04X", pdu->pdu_id,
							pdu->params_len);

	if (!session->browsing_handlers) {
		pdu->pdu_id = AVRCP_GENERAL_REJECT;
		pdu->params[0] = AVRCP_STATUS_INTERNAL_ERROR;
		goto reject;
	}

	for (handler = session->browsing_handlers; handler->id; handler++) {
		if (handler->id == pdu->pdu_id)
			break;
	}

	if (handler->id != pdu->pdu_id) {
		pdu->pdu_id = AVRCP_GENERAL_REJECT;
		pdu->params[0] = AVRCP_STATUS_INVALID_COMMAND;
		goto reject;
	}

	if (!handler->func) {
		pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
		goto reject;
	}

	ret = handler->func(session, transaction, pdu->params_len, pdu->params,
							session->control_data);
	if (ret < 0) {
		if (ret == -EAGAIN)
			return ret;
		pdu->params[0] = errno2status(ret);
		goto reject;
	}

	pdu->params_len = htons(ret);

	return AVRCP_BROWSING_HEADER_LENGTH + ret;

reject:
	pdu->params_len = htons(1);

	return AVRCP_BROWSING_HEADER_LENGTH + 1;
}

static void browsing_disconnect_cb(void *data)
{
	struct avrcp *session = data;

	session->browsing_id = 0;
}

int avrcp_connect_browsing(struct avrcp *session, int fd, size_t imtu,
								size_t omtu)
{
	int err;

	err = avctp_connect_browsing(session->conn, fd, imtu, omtu);
	if (err < 0)
		return err;

	session->browsing_id = avctp_register_browsing_pdu_handler(
							session->conn,
							handle_browsing_pdu,
							session,
							browsing_disconnect_cb);

	return 0;
}

void avrcp_set_destroy_cb(struct avrcp *session, avrcp_destroy_cb_t cb,
							void *user_data)
{
	session->destroy = cb;
	session->destroy_data = user_data;
}

static ssize_t get_capabilities(struct avrcp *session, uint8_t transaction,
				uint16_t params_len, uint8_t *params,
				void *user_data)
{
	struct avrcp_player *player = user_data;

	if (!params || params_len != 1)
		return -EINVAL;

	switch (params[0]) {
	case CAP_COMPANY_ID:
		params[1] = 1;
		hton24(&params[2], IEEEID_BTSIG);
		return 5;
	case CAP_EVENTS_SUPPORTED:
		if (!player->ind || !player->ind->get_capabilities)
			return -ENOSYS;
		return player->ind->get_capabilities(session, transaction,
							player->user_data);
	}

	return -EINVAL;
}

static ssize_t list_attributes(struct avrcp *session, uint8_t transaction,
				uint16_t params_len, uint8_t *params,
				void *user_data)
{
	struct avrcp_player *player = user_data;

	DBG("");

	if (!player->ind || !player->ind->list_attributes)
		return -ENOSYS;

	return player->ind->list_attributes(session, transaction,
							player->user_data);
}

static bool check_attributes(uint8_t number, const uint8_t *attrs)
{
	int i;

	for (i = 0; i < number; i++) {
		if (attrs[i] > AVRCP_ATTRIBUTE_LAST ||
					attrs[i] == AVRCP_ATTRIBUTE_ILEGAL)
			return false;
	}

	return true;
}

static ssize_t get_attribute_text(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;

	DBG("");

	if (!params || params_len != 1 + params[0])
		return -EINVAL;

	if (!check_attributes(params[0], &params[1]))
		return -EINVAL;

	if (!player->ind || !player->ind->get_attribute_text)
		return -ENOSYS;

	return player->ind->get_attribute_text(session, transaction, params[0],
						&params[1], player->user_data);
}

static ssize_t list_values(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;

	DBG("");

	if (!params || params_len != 1)
		return -EINVAL;

	if (params[0] > AVRCP_ATTRIBUTE_LAST ||
					params[0] == AVRCP_ATTRIBUTE_ILEGAL)
		return -EINVAL;

	if (!player->ind || !player->ind->list_values)
		return -ENOSYS;

	return player->ind->list_values(session, transaction, params[0],
							player->user_data);
}

static bool check_value(uint8_t attr, uint8_t number, const uint8_t *values)
{
	int i;

	for (i = 0; i < number; i++) {
		/* Check for invalid value */
		switch (attr) {
		case AVRCP_ATTRIBUTE_EQUALIZER:
			if (values[i] < AVRCP_EQUALIZER_OFF ||
						values[i] > AVRCP_EQUALIZER_ON)
				return false;
		case AVRCP_ATTRIBUTE_REPEAT_MODE:
			if (values[i] < AVRCP_REPEAT_MODE_OFF ||
					values[i] > AVRCP_REPEAT_MODE_GROUP)
				return false;
		case AVRCP_ATTRIBUTE_SHUFFLE:
			if (values[i] < AVRCP_SHUFFLE_OFF ||
					values[i] > AVRCP_SHUFFLE_GROUP)
				return false;
		case AVRCP_ATTRIBUTE_SCAN:
			if (values[i] < AVRCP_SCAN_OFF ||
					values[i] > AVRCP_SCAN_GROUP)
				return false;
		}
	}

	return true;
}

static ssize_t get_value_text(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;

	DBG("");

	if (params_len != 2 + params[1])
		return -EINVAL;

	if (params[0] > AVRCP_ATTRIBUTE_LAST ||
					params[0] == AVRCP_ATTRIBUTE_ILEGAL)
		return -EINVAL;

	if (!check_value(params[0], params[1], &params[2]))
		return -EINVAL;

	if (!player->ind || !player->ind->get_value_text)
		return -ENOSYS;

	return player->ind->get_value_text(session, transaction, params[0],
						params[1], &params[2],
						player->user_data);
}

static ssize_t get_value(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;

	DBG("");

	if (!params || params_len < 1 + params[0])
		return -EINVAL;

	if (!check_attributes(params[0], &params[1]))
		return -EINVAL;

	if (!player->ind || !player->ind->get_value)
		return -ENOSYS;

	return player->ind->get_value(session, transaction, params[0],
					&params[1], player->user_data);
}

static ssize_t set_value(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;
	int i;

	DBG("");

	if (!params || params_len != params[0] * 2 + 1)
		return -EINVAL;

	for (i = 0; i < params[0]; i++) {
		uint8_t attr = params[i * 2 + 1];
		uint8_t val = params[i * 2 + 2];

		if (!check_value(attr, 1, &val))
			return -EINVAL;
	}

	if (!player->ind || !player->ind->set_value)
		return -ENOSYS;

	return player->ind->set_value(session, transaction, params[0],
					&params[1], player->user_data);
}

static ssize_t get_play_status(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;

	DBG("");

	if (!player->ind || !player->ind->get_play_status)
		return -ENOSYS;

	return player->ind->get_play_status(session, transaction,
							player->user_data);
}

static ssize_t get_element_attributes(struct avrcp *session,
						uint8_t transaction,
						uint16_t params_len,
						uint8_t *params,
						void *user_data)
{
	struct avrcp_player *player = user_data;
	uint64_t uid;
	uint8_t number;
	uint32_t attrs[AVRCP_MEDIA_ATTRIBUTE_LAST];
	int i;

	DBG("");

	if (!params || params_len != 9 + params[8] * 4)
		return -EINVAL;

	uid = get_be64(params);
	number = params[8];

	for (i = 0; i < number; i++) {
		attrs[i] = get_be32(&params[9 + i * 4]);

		if (attrs[i] == AVRCP_MEDIA_ATTRIBUTE_ILLEGAL ||
				attrs[i] > AVRCP_MEDIA_ATTRIBUTE_LAST)
			return -EINVAL;
	}

	if (!player->ind || !player->ind->get_element_attributes)
		return -ENOSYS;

	return player->ind->get_element_attributes(session, transaction, uid,
							number, attrs,
							player->user_data);
}

static ssize_t register_notification(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;
	uint32_t interval;

	DBG("");

	if (!params || params_len != 5)
		return -EINVAL;

	if (!player->ind || !player->ind->register_notification)
		return -ENOSYS;

	interval = get_be32(&params[1]);

	return player->ind->register_notification(session, transaction,
							params[0], interval,
							player->user_data);
}

static ssize_t set_volume(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;
	uint8_t volume;

	DBG("");

	if (!player->ind || !player->ind->set_volume)
		return -ENOSYS;

	if (!params || params_len != sizeof(volume))
		return -EINVAL;

	volume = params[0] & 0x7f;

	return player->ind->set_volume(session, transaction, volume,
							player->user_data);
}

static ssize_t set_addressed(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;
	uint16_t id;

	DBG("");

	if (!params || params_len != 2)
		return -EINVAL;

	if (!player->ind || !player->ind->set_addressed)
		return -ENOSYS;

	id = get_be16(params);

	return player->ind->set_addressed(session, transaction, id,
							player->user_data);
}

static const struct avrcp_control_handler player_handlers[] = {
		{ AVRCP_GET_CAPABILITIES,
					AVC_CTYPE_STATUS, AVC_CTYPE_STABLE,
					get_capabilities },
		{ AVRCP_LIST_PLAYER_ATTRIBUTES,
					AVC_CTYPE_STATUS, AVC_CTYPE_STABLE,
					list_attributes },
		{ AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
					AVC_CTYPE_STATUS, AVC_CTYPE_STABLE,
					get_attribute_text },
		{ AVRCP_LIST_PLAYER_VALUES,
					AVC_CTYPE_STATUS, AVC_CTYPE_STABLE,
					list_values },
		{ AVRCP_GET_PLAYER_VALUE_TEXT,
					AVC_CTYPE_STATUS, AVC_CTYPE_STABLE,
					get_value_text },
		{ AVRCP_GET_CURRENT_PLAYER_VALUE,
					AVC_CTYPE_STATUS, AVC_CTYPE_STABLE,
					get_value },
		{ AVRCP_SET_PLAYER_VALUE,
					AVC_CTYPE_CONTROL, AVC_CTYPE_STABLE,
					set_value },
		{ AVRCP_GET_PLAY_STATUS,
					AVC_CTYPE_STATUS, AVC_CTYPE_STABLE,
					get_play_status },
		{ AVRCP_GET_ELEMENT_ATTRIBUTES,
					AVC_CTYPE_STATUS, AVC_CTYPE_STABLE,
					get_element_attributes },
		{ AVRCP_REGISTER_NOTIFICATION,
					AVC_CTYPE_NOTIFY, AVC_CTYPE_INTERIM,
					register_notification },
		{ AVRCP_SET_ABSOLUTE_VOLUME,
					AVC_CTYPE_CONTROL, AVC_CTYPE_STABLE,
					set_volume },
		{ AVRCP_SET_ADDRESSED_PLAYER,
					AVC_CTYPE_CONTROL, AVC_CTYPE_STABLE,
					set_addressed },
		{ },
};

static void avrcp_set_control_handlers(struct avrcp *session,
				const struct avrcp_control_handler *handlers,
				void *user_data)
{
	session->control_handlers = handlers;
	session->control_data = user_data;
}

static ssize_t get_folder_items(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;
	uint8_t scope;
	uint32_t start, end;
	uint16_t number;
	uint32_t attrs[AVRCP_MEDIA_ATTRIBUTE_LAST];
	int i;

	DBG("");

	if (!player->ind || !player->ind->get_folder_items)
		return -ENOSYS;

	if (!params || params_len < 10)
		return -EINVAL;

	scope = params[0];
	if (scope > AVRCP_MEDIA_NOW_PLAYING)
		return -EBADRQC;

	start = get_be32(&params[1]);
	end = get_be32(&params[5]);

	if (start > end)
		return -ERANGE;

	number = get_be16(&params[9]);

	for (i = 0; i < number; i++) {
		attrs[i] = get_be32(&params[11 + i * 4]);

		if (attrs[i] == AVRCP_MEDIA_ATTRIBUTE_ILLEGAL ||
				attrs[i] > AVRCP_MEDIA_ATTRIBUTE_LAST)
			return -EINVAL;
	}

	return player->ind->get_folder_items(session, transaction, scope, start,
							end, number, attrs,
							player->user_data);
}

static ssize_t change_path(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;
	uint8_t direction;
	uint16_t counter;
	uint64_t uid;

	DBG("");

	if (!player->ind || !player->ind->change_path)
		return -ENOSYS;

	if (!params || params_len < 11)
		return -EINVAL;

	counter = get_be16(&params[0]);
	direction = params[2];
	uid = get_be64(&params[3]);

	return player->ind->change_path(session, transaction, counter,
					direction, uid, player->user_data);
}

static ssize_t get_item_attributes(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;
	uint8_t scope;
	uint64_t uid;
	uint16_t counter;
	uint8_t number;
	uint32_t attrs[AVRCP_MEDIA_ATTRIBUTE_LAST];
	int i;

	DBG("");

	if (!player->ind || !player->ind->get_item_attributes)
		return -ENOSYS;

	if (!params || params_len < 12)
		return -EINVAL;

	scope = params[0];
	if (scope > AVRCP_MEDIA_NOW_PLAYING)
		return -EBADRQC;

	uid = get_be64(&params[1]);
	counter = get_be16(&params[9]);
	number = params[11];

	for (i = 0; i < number; i++) {
		attrs[i] = get_be32(&params[12 + i * 4]);

		if (attrs[i] == AVRCP_MEDIA_ATTRIBUTE_ILLEGAL ||
				attrs[i] > AVRCP_MEDIA_ATTRIBUTE_LAST)
			return -EINVAL;
	}

	return player->ind->get_item_attributes(session, transaction, scope,
						uid, counter, number, attrs,
						player->user_data);
}

static ssize_t play_item(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;
	uint8_t scope;
	uint64_t uid;
	uint16_t counter;

	DBG("");

	if (!player->ind || !player->ind->play_item)
		return -ENOSYS;

	if (!params || params_len < 11)
		return -EINVAL;

	scope = params[0];
	if (scope > AVRCP_MEDIA_NOW_PLAYING)
		return -EBADRQC;

	uid = get_be64(&params[1]);
	counter = get_be16(&params[9]);

	return player->ind->play_item(session, transaction, scope, uid,
						counter, player->user_data);
}

static ssize_t search(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;
	char *string;
	uint16_t len;
	int ret;

	DBG("");

	if (!player->ind || !player->ind->search)
		return -ENOSYS;

	if (!params || params_len < 4)
		return -EINVAL;

	len = get_be16(&params[2]);
	if (!len)
		return -EINVAL;

	string = strndup((void *) &params[4], len);

	ret = player->ind->search(session, transaction, string,
							player->user_data);

	free(string);

	return ret;
}

static ssize_t add_to_now_playing(struct avrcp *session, uint8_t transaction,
					uint16_t params_len, uint8_t *params,
					void *user_data)
{
	struct avrcp_player *player = user_data;
	uint8_t scope;
	uint64_t uid;
	uint16_t counter;

	DBG("");

	if (!player->ind || !player->ind->add_to_now_playing)
		return -ENOSYS;

	if (!params || params_len < 11)
		return -EINVAL;

	scope = params[0];
	if (scope > AVRCP_MEDIA_NOW_PLAYING)
		return -EBADRQC;

	uid = get_be64(&params[1]);
	counter = get_be16(&params[9]);

	return player->ind->add_to_now_playing(session, transaction, scope, uid,
						counter, player->user_data);
}

static const struct avrcp_browsing_handler browsing_handlers[] = {
		{ AVRCP_GET_FOLDER_ITEMS, get_folder_items },
		{ AVRCP_CHANGE_PATH, change_path },
		{ AVRCP_GET_ITEM_ATTRIBUTES, get_item_attributes },
		{ AVRCP_PLAY_ITEM, play_item },
		{ AVRCP_SEARCH, search },
		{ AVRCP_ADD_TO_NOW_PLAYING, add_to_now_playing },
		{ },
};

static void avrcp_set_browsing_handlers(struct avrcp *session,
				const struct avrcp_browsing_handler *handlers,
				void *user_data)
{
	session->browsing_handlers = handlers;
	session->browsing_data = user_data;
}

void avrcp_register_player(struct avrcp *session,
				const struct avrcp_control_ind *ind,
				const struct avrcp_control_cfm *cfm,
				void *user_data)
{
	struct avrcp_player *player;

	player = g_new0(struct avrcp_player, 1);
	player->ind = ind;
	player->cfm = cfm;
	player->user_data = user_data;

	avrcp_set_control_handlers(session, player_handlers, player);
	avrcp_set_browsing_handlers(session, browsing_handlers, player);
	session->player = player;
}

void avrcp_set_passthrough_handlers(struct avrcp *session,
			const struct avrcp_passthrough_handler *handlers,
			void *user_data)
{
	session->passthrough_handlers = handlers;
	session->passthrough_data = user_data;
}

int avrcp_init_uinput(struct avrcp *session, const char *name,
							const char *address)
{
	return avctp_init_uinput(session->conn, name, address);
}

int avrcp_send(struct avrcp *session, uint8_t transaction, uint8_t code,
					uint8_t subunit, uint8_t pdu_id,
					const struct iovec *iov, int iov_cnt)
{
	struct iovec pdu[iov_cnt + 1];
	struct avrcp_header hdr;
	int i;

	memset(&hdr, 0, sizeof(hdr));

	pdu[0].iov_base = &hdr;
	pdu[0].iov_len = sizeof(hdr);

	for (i = 0; i < iov_cnt; i++) {
		pdu[i + 1].iov_base = iov[i].iov_base;
		pdu[i + 1].iov_len = iov[i].iov_len;
		hdr.params_len += iov[i].iov_len;
	}

	hton24(hdr.company_id, IEEEID_BTSIG);
	hdr.pdu_id = pdu_id;
	hdr.packet_type = AVRCP_PACKET_TYPE_SINGLE;
	hdr.params_len = htons(hdr.params_len);

	return avctp_send_vendor(session->conn, transaction, code, subunit,
							pdu, iov_cnt + 1);
}

static int status2errno(uint8_t status)
{
	switch (status) {
	case AVRCP_STATUS_INVALID_COMMAND:
		return -ENOSYS;
	case AVRCP_STATUS_INVALID_PARAM:
		return -EINVAL;
	case AVRCP_STATUS_SUCCESS:
		return 0;
	case AVRCP_STATUS_NOT_DIRECTORY:
		return -ENOTDIR;
	case AVRCP_STATUS_INVALID_SCOPE:
		return -EBADRQC;
	case AVRCP_STATUS_OUT_OF_BOUNDS:
		return -ERANGE;
	case AVRCP_STATUS_INTERNAL_ERROR:
	case AVRCP_STATUS_INVALID_PLAYER_ID:
	case AVRCP_STATUS_PLAYER_NOT_BROWSABLE:
	case AVRCP_STATUS_NO_AVAILABLE_PLAYERS:
	case AVRCP_STATUS_ADDRESSED_PLAYER_CHANGED:
		return -EPERM;
	default:
		return -EPROTO;
	}
}

static int parse_status(struct avrcp_header *pdu)
{
	if (pdu->params_len < 1)
		return -EPROTO;

	return status2errno(pdu->params[0]);
}

static int parse_browsing_status(struct avrcp_browsing_header *pdu)
{
	if (pdu->params_len < 1)
		return -EPROTO;

	return status2errno(pdu->params[0]);
}

static int avrcp_send_req(struct avrcp *session, uint8_t code, uint8_t subunit,
					uint8_t pdu_id, const struct iovec *iov,
					int iov_cnt, avctp_rsp_cb func,
					void *user_data)
{
	struct iovec pdu[iov_cnt + 1];
	struct avrcp_header hdr;
	int i;

	memset(&hdr, 0, sizeof(hdr));

	pdu[0].iov_base = &hdr;
	pdu[0].iov_len = sizeof(hdr);

	for (i = 0; i < iov_cnt; i++) {
		pdu[i + 1].iov_base = iov[i].iov_base;
		pdu[i + 1].iov_len = iov[i].iov_len;
		hdr.params_len += iov[i].iov_len;
	}

	hton24(hdr.company_id, IEEEID_BTSIG);
	hdr.pdu_id = pdu_id;
	hdr.packet_type = AVRCP_PACKET_TYPE_SINGLE;
	hdr.params_len = htons(hdr.params_len);

	return avctp_send_vendor_req(session->conn, code, subunit, pdu,
						iov_cnt + 1, func, user_data);
}

static int avrcp_send_browsing_req(struct avrcp *session, uint8_t pdu_id,
					const struct iovec *iov, int iov_cnt,
					avctp_browsing_rsp_cb func,
					void *user_data)
{
	struct iovec pdu[iov_cnt + 1];
	struct avrcp_browsing_header hdr;
	int i;

	memset(&hdr, 0, sizeof(hdr));

	for (i = 0; i < iov_cnt; i++) {
		pdu[i + 1].iov_base = iov[i].iov_base;
		pdu[i + 1].iov_len = iov[i].iov_len;
		hdr.params_len += iov[i].iov_len;
	}

	hdr.pdu_id = pdu_id;
	hdr.params_len = htons(hdr.params_len);

	pdu[0].iov_base = &hdr;
	pdu[0].iov_len = sizeof(hdr);

	return avctp_send_browsing_req(session->conn, pdu, iov_cnt + 1,
							func, user_data);
}

static int avrcp_send_browsing(struct avrcp *session, uint8_t transaction,
				uint8_t pdu_id, const struct iovec *iov,
				int iov_cnt)
{
	struct iovec pdu[iov_cnt + 1];
	struct avrcp_browsing_header hdr;
	int i;

	memset(&hdr, 0, sizeof(hdr));

	for (i = 0; i < iov_cnt; i++) {
		pdu[i + 1].iov_base = iov[i].iov_base;
		pdu[i + 1].iov_len = iov[i].iov_len;
		hdr.params_len += iov[i].iov_len;
	}

	hdr.pdu_id = pdu_id;
	hdr.params_len = htons(hdr.params_len);

	pdu[0].iov_base = &hdr;
	pdu[0].iov_len = sizeof(hdr);

	return avctp_send_browsing(session->conn, transaction, pdu,
								iov_cnt + 1);
}

static gboolean get_capabilities_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_header *pdu;
	uint8_t number = 0;
	uint8_t *params = NULL;
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->get_capabilities)
		return FALSE;

	pdu = parse_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	if (code == AVC_CTYPE_REJECTED) {
		err = parse_status(pdu);
		goto done;
	}

	if (pdu->params_len < 2) {
		err = -EPROTO;
		goto done;
	}

	switch (pdu->params[0]) {
	case CAP_COMPANY_ID:
	case CAP_EVENTS_SUPPORTED:
		break;
	default:
		err = -EPROTO;
		goto done;
	}

	number = pdu->params[1];

	if (number > 0)
		params = &pdu->params[2];

	err = 0;

done:
	player->cfm->get_capabilities(session, err, number, params,
							player->user_data);

	return FALSE;
}


int avrcp_get_capabilities(struct avrcp *session, uint8_t param)
{
	struct iovec iov;

	iov.iov_base = &param;
	iov.iov_len = sizeof(param);

	return avrcp_send_req(session, AVC_CTYPE_STATUS, AVC_SUBUNIT_PANEL,
					AVRCP_GET_CAPABILITIES, &iov, 1,
					get_capabilities_rsp, session);
}

static gboolean register_notification_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_header *pdu;
	uint8_t event = 0;
	uint16_t value16;
	uint32_t value32;
	uint64_t value64;
	uint8_t *params = NULL;
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->register_notification)
		return FALSE;

	pdu = parse_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	if (code == AVC_CTYPE_REJECTED) {
		err = parse_status(pdu);
		goto done;
	}

	if (pdu->params_len < 1) {
		err = -EPROTO;
		goto done;
	}

	event = pdu->params[0];

	switch (event) {
	case AVRCP_EVENT_STATUS_CHANGED:
	case AVRCP_EVENT_VOLUME_CHANGED:
		if (pdu->params_len != 2) {
			err = -EPROTO;
			goto done;
		}
		params = &pdu->params[1];
		break;
	case AVRCP_EVENT_TRACK_CHANGED:
		if (pdu->params_len != 9) {
			err = -EPROTO;
			goto done;
		}
		value64 = get_be64(&pdu->params[1]);
		params = (uint8_t *) &value64;
		break;
	case AVRCP_EVENT_PLAYBACK_POS_CHANGED:
		if (pdu->params_len != 5) {
			err = -EPROTO;
			goto done;
		}
		value32 = get_be32(&pdu->params[1]);
		params = (uint8_t *) &value32;
		break;
	case AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED:
	case AVRCP_EVENT_SETTINGS_CHANGED:
		if (pdu->params_len < 2) {
			err = -EPROTO;
			goto done;
		}
		params = &pdu->params[1];
		break;
	case AVRCP_EVENT_UIDS_CHANGED:
		if (pdu->params_len != 3) {
			err = -EPROTO;
			goto done;
		}
		value16 = get_be16(&pdu->params[1]);
		params = (uint8_t *) &value16;
		break;
	}

	err = 0;

done:
	return player->cfm->register_notification(session, err, code, event,
						params, player->user_data);
}

int avrcp_register_notification(struct avrcp *session, uint8_t event,
							uint32_t interval)
{
	struct iovec iov;
	uint8_t pdu[5];

	pdu[0] = event;
	put_be32(interval, &pdu[1]);

	iov.iov_base = pdu;
	iov.iov_len = sizeof(pdu);

	return avrcp_send_req(session, AVC_CTYPE_NOTIFY, AVC_SUBUNIT_PANEL,
				AVRCP_REGISTER_NOTIFICATION, &iov, 1,
				register_notification_rsp, session);
}

static gboolean list_attributes_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_header *pdu = (void *) operands;
	uint8_t number = 0;
	uint8_t *attrs = NULL;
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->list_attributes)
		return FALSE;

	pdu = parse_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	if (code == AVC_CTYPE_REJECTED) {
		err = parse_status(pdu);
		goto done;
	}

	number = pdu->params[0];
	if (number > 0)
		attrs = &pdu->params[1];

	err = 0;

done:
	player->cfm->list_attributes(session, err, number, attrs,
							player->user_data);

	return FALSE;
}

int avrcp_list_player_attributes(struct avrcp *session)
{
	return avrcp_send_req(session, AVC_CTYPE_STATUS, AVC_SUBUNIT_PANEL,
				AVRCP_LIST_PLAYER_ATTRIBUTES, NULL, 0,
				list_attributes_rsp, session);
}

static int parse_text_rsp(struct avrcp_header *pdu, uint8_t *number,
					uint8_t *attrs, char **text)
{
	uint8_t *ptr;
	uint16_t params_len;
	int i;

	if (pdu->params_len < 1)
		return -EPROTO;

	*number = pdu->params[0];
	if (*number > AVRCP_ATTRIBUTE_LAST) {
		*number = 0;
		return -EPROTO;
	}

	params_len = pdu->params_len - 1;
	for (i = 0, ptr = &pdu->params[1]; i < *number && params_len > 0; i++) {
		uint8_t len;

		if (params_len < 4)
			goto fail;

		attrs[i] = ptr[0];
		len = ptr[3];

		params_len -= 4;
		ptr += 4;

		if (len > params_len)
			goto fail;

		if (len > 0) {
			text[i] = g_strndup((const char *) &ptr[4], len);
			params_len -= len;
			ptr += len;
		}
	}

	if (i != *number)
		goto fail;

	return 0;

fail:
	for (i -= 1; i >= 0; i--)
		g_free(text[i]);

	*number = 0;

	return -EPROTO;
}

static gboolean get_attribute_text_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_header *pdu;
	uint8_t number = 0;
	uint8_t attrs[AVRCP_ATTRIBUTE_LAST];
	char *text[AVRCP_ATTRIBUTE_LAST];
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->get_attribute_text)
		return FALSE;

	pdu = parse_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	if (code == AVC_CTYPE_REJECTED) {
		err = parse_status(pdu);
		goto done;
	}

	err = parse_text_rsp(pdu, &number, attrs, text);

done:
	player->cfm->get_attribute_text(session, err, number, attrs, text,
							player->user_data);

	return FALSE;
}

int avrcp_get_player_attribute_text(struct avrcp *session, uint8_t number,
								uint8_t *attrs)
{
	struct iovec iov[2];

	if (!number || number > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	iov[0].iov_base = &number;
	iov[0].iov_len = sizeof(number);

	iov[1].iov_base = attrs;
	iov[1].iov_len = number;

	return avrcp_send_req(session, AVC_CTYPE_STATUS, AVC_SUBUNIT_PANEL,
				AVRCP_GET_PLAYER_ATTRIBUTE_TEXT, iov, 2,
				get_attribute_text_rsp, session);
}

static gboolean list_values_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_header *pdu;
	uint8_t number = 0;
	uint8_t *values = NULL;
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->list_values)
		return FALSE;

	pdu = parse_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	if (code == AVC_CTYPE_REJECTED) {
		err = parse_status(pdu);
		goto done;
	}

	number = pdu->params[0];
	if (number > 0)
		values = &pdu->params[1];

	err = 0;

done:
	player->cfm->list_values(session, err, number, values,
							player->user_data);

	return FALSE;
}

int avrcp_list_player_values(struct avrcp *session, uint8_t attr)
{
	struct iovec iov;

	iov.iov_base = &attr;
	iov.iov_len = sizeof(attr);

	return avrcp_send_req(session, AVC_CTYPE_STATUS, AVC_SUBUNIT_PANEL,
					AVRCP_LIST_PLAYER_VALUES, &iov, 1,
					list_values_rsp, session);
}

static gboolean get_value_text_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_header *pdu;
	uint8_t number = 0;
	uint8_t values[AVRCP_ATTRIBUTE_LAST];
	char *text[AVRCP_ATTRIBUTE_LAST];
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->get_value_text)
		return FALSE;

	pdu = parse_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	if (code == AVC_CTYPE_REJECTED) {
		err = parse_status(pdu);
		goto done;
	}

	err = parse_text_rsp(pdu, &number, values, text);

done:
	player->cfm->get_value_text(session, err, number, values, text,
							player->user_data);

	return FALSE;
}

int avrcp_get_player_value_text(struct avrcp *session, uint8_t attr,
					uint8_t number, uint8_t *values)
{
	struct iovec iov[2];
	uint8_t pdu[2];

	if (!number)
		return -EINVAL;

	pdu[0] = attr;
	pdu[1] = number;

	iov[0].iov_base = pdu;
	iov[0].iov_len = sizeof(pdu);

	iov[1].iov_base = values;
	iov[1].iov_len = number;

	return avrcp_send_req(session, AVC_CTYPE_STATUS, AVC_SUBUNIT_PANEL,
					AVRCP_GET_PLAYER_VALUE_TEXT, iov, 2,
					get_value_text_rsp, session);
}

static int parse_value(struct avrcp_header *pdu, uint8_t *number,
					uint8_t *attrs, uint8_t *values)
{
	int i;

	if (pdu->params_len < 1)
		return -EPROTO;

	*number = pdu->params[0];

	/*
	 * Check if PDU is big enough to hold the number of (attribute, value)
	 * tuples.
	 */
	if (*number > AVRCP_ATTRIBUTE_LAST ||
					1 + *number * 2 != pdu->params_len) {
		number = 0;
		return -EPROTO;
	}

	for (i = 0; i < *number; i++) {
		attrs[i] = pdu->params[i * 2 + 1];
		values[i] = pdu->params[i * 2 + 2];
	}

	return 0;
}

static gboolean get_value_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_header *pdu = (void *) operands;
	uint8_t number = 0;
	uint8_t attrs[AVRCP_ATTRIBUTE_LAST];
	uint8_t values[AVRCP_ATTRIBUTE_LAST];
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->get_value)
		return FALSE;

	pdu = parse_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	if (code == AVC_CTYPE_REJECTED) {
		err = parse_status(pdu);
		goto done;
	}

	err = parse_value(pdu, &number, attrs, values);

done:
	player->cfm->get_value(session, err, number, attrs, values,
							player->user_data);

	return FALSE;
}

int avrcp_get_current_player_value(struct avrcp *session, uint8_t number,
							uint8_t *attrs)

{
	struct iovec iov[2];

	if (number > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	iov[0].iov_base = &number;
	iov[0].iov_len = sizeof(number);

	iov[1].iov_base = attrs;
	iov[1].iov_len = number;

	return avrcp_send_req(session, AVC_CTYPE_STATUS, AVC_SUBUNIT_PANEL,
				AVRCP_GET_CURRENT_PLAYER_VALUE, iov, 2,
				get_value_rsp, session);
}

static gboolean set_value_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_header *pdu;
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->set_value)
		return FALSE;

	pdu = parse_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	if (code == AVC_CTYPE_REJECTED) {
		err = parse_status(pdu);
		goto done;
	}

	err = 0;

done:
	player->cfm->set_value(session, err, player->user_data);

	return FALSE;
}

int avrcp_set_player_value(struct avrcp *session, uint8_t number,
					uint8_t *attrs, uint8_t *values)
{
	struct iovec iov;
	uint8_t pdu[2 * AVRCP_ATTRIBUTE_LAST + 1];
	int i;

	if (number > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	pdu[0] = number;

	for (i = 0; i < number; i++) {
		pdu[i * 2 + 1] = attrs[i];
		pdu[i * 2 + 2] = values[i];
	}

	iov.iov_base = pdu;
	iov.iov_len = 1 + number * 2;

	return avrcp_send_req(session, AVC_CTYPE_CONTROL, AVC_SUBUNIT_PANEL,
					AVRCP_SET_PLAYER_VALUE, &iov, 1,
					set_value_rsp, session);
}

static gboolean get_play_status_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_header *pdu;
	uint8_t status = 0;
	uint32_t position = 0;
	uint32_t duration = 0;
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->get_play_status)
		return FALSE;

	pdu = parse_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	if (code == AVC_CTYPE_REJECTED) {
		err = parse_status(pdu);
		goto done;
	}

	if (pdu->params_len < 5) {
		err = -EPROTO;
		goto done;
	}

	duration = get_be32(&pdu->params[0]);
	position = get_be32(&pdu->params[4]);
	status = pdu->params[8];
	err = 0;

done:
	player->cfm->get_play_status(session, err, status, position, duration,
							player->user_data);

	return FALSE;
}

int avrcp_get_play_status(struct avrcp *session)
{
	return avrcp_send_req(session, AVC_CTYPE_STATUS, AVC_SUBUNIT_PANEL,
				AVRCP_GET_PLAY_STATUS, NULL, 0,
				get_play_status_rsp, session);
}

static gboolean set_volume_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_header *pdu;
	uint8_t value = 0;
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->set_volume)
		return FALSE;

	pdu = parse_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	if (code == AVC_CTYPE_REJECTED) {
		err = parse_status(pdu);
		goto done;
	}

	if (pdu->params_len < 1) {
		err = -EPROTO;
		goto done;
	}

	value = pdu->params[0] & 0x7f;
	err = 0;

done:
	player->cfm->set_volume(session, err, value, player->user_data);

	return FALSE;
}

int avrcp_set_volume(struct avrcp *session, uint8_t volume)
{
	struct iovec iov;

	iov.iov_base = &volume;
	iov.iov_len = sizeof(volume);

	return avrcp_send_req(session, AVC_CTYPE_CONTROL, AVC_SUBUNIT_PANEL,
				AVRCP_SET_ABSOLUTE_VOLUME, &iov, 1,
				set_volume_rsp, session);
}

static int parse_attribute_list(uint8_t *params, uint16_t params_len,
				uint8_t number, uint32_t *attrs, char **text)
{
	int i;

	if (number > AVRCP_MEDIA_ATTRIBUTE_LAST)
		return -EPROTO;

	for (i = 0; number > 0 && params_len > i; number--) {
		uint16_t charset, len;

		if (params_len < 8)
			goto fail;

		attrs[i] = get_be32(&params[i]);
		i += sizeof(uint32_t);

		charset = get_be16(&params[i]);
		i += sizeof(uint16_t);

		len = get_be16(&params[i]);
		i += sizeof(uint16_t);

		if (len > params_len)
			goto fail;

		if (charset == AVRCP_CHARSET_UTF8)
			text[i] = g_strndup((const char *) &params[i], len);

		i += len;
	}

	return 0;

fail:
	for (i -= 1; i >= 0; i--)
		g_free(text[i]);

	return -EPROTO;
}

static int parse_elements(struct avrcp_header *pdu, uint8_t *number,
						uint32_t *attrs, char **text)
{
	if (pdu->params_len < 1)
		return -EPROTO;

	*number = pdu->params[0];
	if (*number > AVRCP_MEDIA_ATTRIBUTE_LAST) {
		*number = 0;
		return -EPROTO;
	}

	return parse_attribute_list(&pdu->params[1], pdu->params_len - 1,
							*number, attrs, text);
}

static int parse_items(struct avrcp_browsing_header *pdu, uint8_t *number,
						uint32_t *attrs, char **text)
{
	if (pdu->params_len < 2)
		return -EPROTO;

	*number = pdu->params[1];
	if (*number > AVRCP_MEDIA_ATTRIBUTE_LAST) {
		*number = 0;
		return -EPROTO;
	}

	return parse_attribute_list(&pdu->params[2], pdu->params_len - 2,
							*number, attrs, text);
}

static gboolean get_element_attributes_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_header *pdu;
	uint8_t number = 0;
	uint32_t attrs[AVRCP_MEDIA_ATTRIBUTE_LAST];
	char *text[AVRCP_MEDIA_ATTRIBUTE_LAST];
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->get_element_attributes)
		return FALSE;

	pdu = parse_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	if (code == AVC_CTYPE_REJECTED) {
		err = parse_status(pdu);
		goto done;
	}

	err = parse_elements(pdu, &number, attrs, text);

done:
	player->cfm->get_element_attributes(session, err, number, attrs, text,
							player->user_data);

	return FALSE;
}

int avrcp_get_element_attributes(struct avrcp *session)
{
	struct iovec iov;
	uint8_t pdu[9];

	/* This returns all attributes */
	memset(pdu, 0, sizeof(pdu));

	iov.iov_base = pdu;
	iov.iov_len = sizeof(pdu);

	return avrcp_send_req(session, AVC_CTYPE_STATUS, AVC_SUBUNIT_PANEL,
				AVRCP_GET_ELEMENT_ATTRIBUTES, &iov, 1,
				get_element_attributes_rsp, session);
}

static gboolean set_addressed_rsp(struct avctp *conn,
					uint8_t code, uint8_t subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_header *pdu;
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->set_addressed)
		return FALSE;

	pdu = parse_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	err = parse_status(pdu);

done:
	player->cfm->set_addressed(session, err, player->user_data);

	return FALSE;
}

int avrcp_set_addressed_player(struct avrcp *session, uint16_t player_id)
{
	struct iovec iov;
	uint8_t pdu[2];

	put_be16(player_id, pdu);

	iov.iov_base = pdu;
	iov.iov_len = sizeof(pdu);

	return avrcp_send_req(session, AVC_CTYPE_CONTROL, AVC_SUBUNIT_PANEL,
					AVRCP_SET_ADDRESSED_PLAYER, &iov, 1,
					set_addressed_rsp, session);
}

static gboolean set_browsed_rsp(struct avctp *conn, uint8_t *operands,
					size_t operand_count, void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_browsing_header *pdu;
	uint16_t counter = 0;
	uint32_t items = 0;
	uint8_t depth = 0, count;
	char **folders, *path = NULL;
	int err;
	size_t i;

	DBG("");

	if (!player || !player->cfm || !player->cfm->set_browsed)
		return FALSE;

	pdu = parse_browsing_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	err = parse_browsing_status(pdu);
	if (err < 0)
		goto done;

	if (pdu->params_len < 10) {
		err = -EPROTO;
		goto done;
	}

	counter = get_be16(&pdu->params[1]);
	items = get_be32(&pdu->params[3]);
	depth = pdu->params[9];

	folders = g_new0(char *, depth + 2);
	folders[0] = g_strdup("/Filesystem");

	for (i = 10, count = 1; count - 1 < depth && i < pdu->params_len;
								count++) {
		uint8_t len;

		len = pdu->params[i++];

		if (i + len > pdu->params_len || len == 0) {
			g_strfreev(folders);
			err = -EPROTO;
			goto done;
		}

		folders[count] = g_memdup(&pdu->params[i], len);
		i += len;
	}

	path = g_build_pathv("/", folders);
	g_strfreev(folders);

done:
	player->cfm->set_browsed(session, err, counter, items, path,
							player->user_data);

	return FALSE;
}

int avrcp_set_browsed_player(struct avrcp *session, uint16_t player_id)
{
	struct iovec iov;
	uint8_t pdu[2];

	put_be16(player_id, pdu);

	iov.iov_base = pdu;
	iov.iov_len = sizeof(pdu);

	return avrcp_send_browsing_req(session, AVRCP_SET_BROWSED_PLAYER,
					&iov, 1, set_browsed_rsp, session);
}

static gboolean get_folder_items_rsp(struct avctp *conn,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_browsing_header *pdu;
	uint16_t counter = 0, number = 0;
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->get_folder_items)
		return FALSE;

	pdu = parse_browsing_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	err = parse_browsing_status(pdu);
	if (err < 0)
		goto done;

	if (pdu->params_len < 5) {
		err = -EPROTO;
		goto done;
	}

	counter = get_be16(&pdu->params[1]);
	number = get_be16(&pdu->params[3]);

	/* FIXME: Add proper parsing for each item type */

done:
	player->cfm->get_folder_items(session, err, counter, number,
					&pdu->params[5], player->user_data);

	return FALSE;
}

int avrcp_get_folder_items(struct avrcp *session, uint8_t scope,
				uint32_t start, uint32_t end, uint8_t number,
				uint32_t *attrs)
{

	struct iovec iov[2];
	uint8_t pdu[10];
	int i;

	pdu[0] = scope;
	put_be32(start, &pdu[1]);
	put_be32(end, &pdu[5]);
	pdu[9] = number;

	iov[0].iov_base = pdu;
	iov[0].iov_len = sizeof(pdu);

	if (!number)
		return avrcp_send_browsing_req(session, AVRCP_GET_FOLDER_ITEMS,
						iov, 1, get_folder_items_rsp,
						session);

	for (i = 0; i < number; i++)
		put_be32(attrs[i], &attrs[i]);

	iov[1].iov_base = attrs;
	iov[1].iov_len = number * sizeof(*attrs);

	return avrcp_send_browsing_req(session, AVRCP_GET_FOLDER_ITEMS,
					iov, 2, get_folder_items_rsp, session);
}

static gboolean change_path_rsp(struct avctp *conn, uint8_t *operands,
					size_t operand_count, void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_browsing_header *pdu;
	uint32_t items = 0;
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->change_path)
		return FALSE;

	pdu = parse_browsing_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	err = parse_browsing_status(pdu);
	if (err < 0)
		goto done;

	if (pdu->params_len < 5) {
		err = -EPROTO;
		goto done;
	}

	items = get_be32(&pdu->params[1]);

done:
	player->cfm->change_path(session, err, items, player->user_data);

	return FALSE;
}

int avrcp_change_path(struct avrcp *session, uint8_t direction, uint64_t uid,
							uint16_t counter)
{
	struct iovec iov;
	uint8_t pdu[11];

	put_be16(counter, &pdu[0]);
	pdu[2] = direction;
	put_be64(uid, &pdu[3]);

	iov.iov_base = pdu;
	iov.iov_len = sizeof(pdu);

	return avrcp_send_browsing_req(session, AVRCP_CHANGE_PATH,
					&iov, 1, change_path_rsp, session);
}

static gboolean get_item_attributes_rsp(struct avctp *conn, uint8_t *operands,
					size_t operand_count, void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_browsing_header *pdu;
	uint8_t number = 0;
	uint32_t attrs[AVRCP_MEDIA_ATTRIBUTE_LAST];
	char *text[AVRCP_MEDIA_ATTRIBUTE_LAST];
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->get_item_attributes)
		return FALSE;

	pdu = parse_browsing_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	err = parse_browsing_status(pdu);
	if (err < 0)
		goto done;

	err = parse_items(pdu, &number, attrs, text);

done:
	player->cfm->get_item_attributes(session, err, number, attrs, text,
							player->user_data);

	return FALSE;
}

int avrcp_get_item_attributes(struct avrcp *session, uint8_t scope,
				uint64_t uid, uint16_t counter, uint8_t number,
				uint32_t *attrs)
{
	struct iovec iov[2];
	uint8_t pdu[12];
	int i;

	pdu[0] = scope;
	put_be64(uid, &pdu[1]);
	put_be16(counter, &pdu[9]);
	pdu[11] = number;

	iov[0].iov_base = pdu;
	iov[0].iov_len = sizeof(pdu);

	if (!number)
		return avrcp_send_browsing_req(session,
						AVRCP_GET_ITEM_ATTRIBUTES,
						iov, 1, get_item_attributes_rsp,
						session);

	if (number > AVRCP_MEDIA_ATTRIBUTE_LAST)
		return -EINVAL;

	for (i = 0; i < number; i++) {
		if (attrs[i] > AVRCP_MEDIA_ATTRIBUTE_LAST ||
				attrs[i] == AVRCP_MEDIA_ATTRIBUTE_ILLEGAL)
			return -EINVAL;
		put_be32(attrs[i], &attrs[i]);
	}

	iov[1].iov_base = attrs;
	iov[1].iov_len = number * sizeof(*attrs);

	return avrcp_send_browsing_req(session, AVRCP_GET_ITEM_ATTRIBUTES,
					iov, 2, get_item_attributes_rsp,
					session);
}

static gboolean play_item_rsp(struct avctp *conn, uint8_t *operands,
					size_t operand_count, void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_browsing_header *pdu;
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->play_item)
		return FALSE;

	pdu = parse_browsing_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	err = parse_browsing_status(pdu);

done:
	player->cfm->play_item(session, err, player->user_data);

	return FALSE;
}

int avrcp_play_item(struct avrcp *session, uint8_t scope, uint64_t uid,
							uint16_t counter)
{
	struct iovec iov;
	uint8_t pdu[11];

	if (scope > AVRCP_MEDIA_NOW_PLAYING)
		return -EINVAL;

	pdu[0] = scope;
	put_be64(uid, &pdu[1]);
	put_be16(counter, &pdu[9]);

	iov.iov_base = pdu;
	iov.iov_len = sizeof(pdu);

	return avrcp_send_browsing_req(session, AVRCP_PLAY_ITEM, &iov, 1,
						play_item_rsp, session);
}

static gboolean search_rsp(struct avctp *conn, uint8_t *operands,
					size_t operand_count, void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_browsing_header *pdu;
	uint16_t counter = 0;
	uint32_t items = 0;
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->search)
		return FALSE;

	pdu = parse_browsing_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	err = parse_browsing_status(pdu);
	if (err < 0)
		goto done;

	if (pdu->params_len < 7) {
		err = -EPROTO;
		goto done;
	}

	counter = get_be16(&pdu->params[1]);
	items = get_be32(&pdu->params[3]);

	err = 0;

done:
	player->cfm->search(session, err, counter, items, player->user_data);

	return FALSE;
}

int avrcp_search(struct avrcp *session, const char *string)
{
	struct iovec iov[2];
	uint8_t pdu[4];
	size_t len;

	if (!string)
		return -EINVAL;

	len = strnlen(string, UINT8_MAX);

	put_be16(AVRCP_CHARSET_UTF8, &pdu[0]);
	put_be16(len, &pdu[2]);

	iov[0].iov_base = pdu;
	iov[0].iov_len = sizeof(pdu);

	iov[1].iov_base = (void *) string;
	iov[1].iov_len = len;

	return avrcp_send_browsing_req(session, AVRCP_SEARCH, iov, 2,
							search_rsp, session);
}

static gboolean add_to_now_playing_rsp(struct avctp *conn, uint8_t *operands,
					size_t operand_count, void *user_data)
{
	struct avrcp *session = user_data;
	struct avrcp_player *player = session->player;
	struct avrcp_browsing_header *pdu;
	int err;

	DBG("");

	if (!player || !player->cfm || !player->cfm->add_to_now_playing)
		return FALSE;

	pdu = parse_browsing_pdu(operands, operand_count);
	if (!pdu) {
		err = -EPROTO;
		goto done;
	}

	err = parse_browsing_status(pdu);

done:
	player->cfm->add_to_now_playing(session, err, player->user_data);

	return FALSE;
}

int avrcp_add_to_now_playing(struct avrcp *session, uint8_t scope, uint64_t uid,
							uint16_t counter)
{
	struct iovec iov;
	uint8_t pdu[11];

	if (scope > AVRCP_MEDIA_NOW_PLAYING)
		return -EINVAL;

	pdu[0] = scope;
	put_be64(uid, &pdu[1]);
	put_be16(counter, &pdu[9]);

	iov.iov_base = pdu;
	iov.iov_len = sizeof(pdu);

	return avrcp_send_browsing_req(session, AVRCP_ADD_TO_NOW_PLAYING,
					&iov, 1, add_to_now_playing_rsp,
					session);
}

int avrcp_get_capabilities_rsp(struct avrcp *session, uint8_t transaction,
						uint8_t number, uint8_t *events)
{
	uint8_t pdu[2];
	struct iovec iov[2];

	if (number > AVRCP_EVENT_LAST)
		return -EINVAL;

	pdu[0] = CAP_EVENTS_SUPPORTED;
	pdu[1] = number;

	iov[0].iov_base = pdu;
	iov[0].iov_len = sizeof(pdu);

	iov[1].iov_base = events;
	iov[1].iov_len = number;

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
				AVC_SUBUNIT_PANEL, AVRCP_GET_CAPABILITIES,
				iov, 2);
}

int avrcp_list_player_attributes_rsp(struct avrcp *session, uint8_t transaction,
					uint8_t number, uint8_t *attrs)
{
	struct iovec iov[2];

	if (number > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	iov[0].iov_base = &number;
	iov[0].iov_len = sizeof(number);

	if (!number)
		return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
				AVC_SUBUNIT_PANEL, AVRCP_LIST_PLAYER_ATTRIBUTES,
				iov, 1);

	iov[1].iov_base = attrs;
	iov[1].iov_len = number;

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
				AVC_SUBUNIT_PANEL, AVRCP_LIST_PLAYER_ATTRIBUTES,
				iov, 2);
}

int avrcp_get_player_attribute_text_rsp(struct avrcp *session,
					uint8_t transaction, uint8_t number,
					uint8_t *attrs, const char **text)
{
	struct iovec iov[1 + AVRCP_ATTRIBUTE_LAST * 2];
	uint8_t val[AVRCP_ATTRIBUTE_LAST][4];
	int i;

	if (number > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	iov[0].iov_base = &number;
	iov[0].iov_len = sizeof(number);

	for (i = 0; i < number; i++) {
		uint8_t len = 0;

		if (attrs[i] > AVRCP_ATTRIBUTE_LAST ||
					attrs[i] == AVRCP_ATTRIBUTE_ILEGAL)
			return -EINVAL;

		if (text[i])
			len = strlen(text[i]);

		val[i][0] = attrs[i];
		put_be16(AVRCP_CHARSET_UTF8, &val[i][1]);
		val[i][3] = len;

		iov[i + 1].iov_base = val[i];
		iov[i + 1].iov_len = sizeof(val[i]);

		iov[i + 2].iov_base = (void *) text[i];
		iov[i + 2].iov_len = len;
	}

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
			AVC_SUBUNIT_PANEL, AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
			iov, 1 + i * 2);
}

int avrcp_list_player_values_rsp(struct avrcp *session, uint8_t transaction,
					uint8_t number, uint8_t *values)
{
	struct iovec iov[2];

	if (number > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	iov[0].iov_base = &number;
	iov[0].iov_len = sizeof(number);

	iov[1].iov_base = values;
	iov[1].iov_len = number;

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
				AVC_SUBUNIT_PANEL, AVRCP_LIST_PLAYER_VALUES,
				iov, 2);
}

int avrcp_get_play_status_rsp(struct avrcp *session, uint8_t transaction,
				uint32_t position, uint32_t duration,
				uint8_t status)
{
	struct iovec iov;
	uint8_t pdu[9];

	put_be32(duration, &pdu[0]);
	put_be32(position, &pdu[4]);
	pdu[8] = status;

	iov.iov_base = &pdu;
	iov.iov_len = sizeof(pdu);

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
				AVC_SUBUNIT_PANEL, AVRCP_GET_PLAY_STATUS,
				&iov, 1);
}

int avrcp_get_player_values_text_rsp(struct avrcp *session,
					uint8_t transaction, uint8_t number,
					uint8_t *values, const char **text)
{
	struct iovec iov[1 + AVRCP_ATTRIBUTE_LAST * 2];
	uint8_t val[AVRCP_ATTRIBUTE_LAST][4];
	int i;

	if (number > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	iov[0].iov_base = &number;
	iov[0].iov_len = sizeof(number);

	for (i = 0; i < number; i++) {
		uint8_t len = 0;

		if (text[i])
			len = strlen(text[i]);

		val[i][0] = values[i];
		put_be16(AVRCP_CHARSET_UTF8, &val[i][1]);
		val[i][3] = len;

		iov[i + 1].iov_base = val[i];
		iov[i + 1].iov_len = sizeof(val[i]);

		iov[i + 2].iov_base = (void *) text[i];
		iov[i + 2].iov_len = len;
	}

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
				AVC_SUBUNIT_PANEL, AVRCP_GET_PLAYER_VALUE_TEXT,
				iov, 1 + i * 2);
}

int avrcp_get_current_player_value_rsp(struct avrcp *session,
					uint8_t transaction, uint8_t number,
					uint8_t *attrs, uint8_t *values)
{
	struct iovec iov[1 + AVRCP_ATTRIBUTE_LAST];
	uint8_t val[AVRCP_ATTRIBUTE_LAST][2];
	int i;

	if (number > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	iov[0].iov_base = &number;
	iov[0].iov_len = sizeof(number);

	for (i = 0; i < number; i++) {
		val[i][0] = attrs[i];
		val[i][1] = values[i];

		iov[i + 1].iov_base = val[i];
		iov[i + 1].iov_len = sizeof(val[i]);
	}

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
			AVC_SUBUNIT_PANEL, AVRCP_GET_CURRENT_PLAYER_VALUE,
			iov, 1 + i);
}

int avrcp_set_player_value_rsp(struct avrcp *session, uint8_t transaction)
{
	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
			AVC_SUBUNIT_PANEL, AVRCP_SET_PLAYER_VALUE, NULL, 0);
}

int avrcp_get_element_attrs_rsp(struct avrcp *session, uint8_t transaction,
					uint8_t *params, size_t params_len)
{
	struct iovec iov;

	iov.iov_base = params;
	iov.iov_len = params_len;

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
				AVC_SUBUNIT_PANEL, AVRCP_GET_ELEMENT_ATTRIBUTES,
				&iov, 1);
}

int avrcp_register_notification_rsp(struct avrcp *session, uint8_t transaction,
					uint8_t code, uint8_t *params,
					size_t params_len)
{
	struct iovec iov;

	iov.iov_base = params;
	iov.iov_len = params_len;

	return avrcp_send(session, transaction, code,
				AVC_SUBUNIT_PANEL, AVRCP_REGISTER_NOTIFICATION,
				&iov, 1);
}

int avrcp_set_volume_rsp(struct avrcp *session, uint8_t transaction,
							uint8_t volume)
{
	struct iovec iov;

	if (volume > 127)
		return -EINVAL;

	iov.iov_base = &volume;
	iov.iov_len = sizeof(volume);

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
				AVC_SUBUNIT_PANEL, AVRCP_SET_ABSOLUTE_VOLUME,
				&iov, 1);
}

int avrcp_set_addressed_player_rsp(struct avrcp *session, uint8_t transaction,
							uint8_t status)
{
	struct iovec iov;

	iov.iov_base = &status;
	iov.iov_len = sizeof(status);

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
				AVC_SUBUNIT_PANEL, AVRCP_SET_ADDRESSED_PLAYER,
				&iov, 1);
}

int avrcp_get_folder_items_rsp(struct avrcp *session, uint8_t transaction,
					uint16_t counter, uint8_t number,
					uint8_t *type, uint16_t *len,
					uint8_t **params)
{
	struct iovec iov[UINT8_MAX * 2 + 1];
	uint8_t pdu[5];
	uint8_t item[UINT8_MAX][3];
	int i;

	pdu[0] = AVRCP_STATUS_SUCCESS;
	put_be16(counter, &pdu[1]);
	put_be16(number, &pdu[3]);

	iov[0].iov_base = pdu;
	iov[0].iov_len = sizeof(pdu);

	for (i = 0; i < number; i++) {
		item[i][0] = type[i];
		put_be16(len[i], &item[i][1]);

		iov[i * 2 + 1].iov_base = item[i];
		iov[i * 2 + 1].iov_len = sizeof(item[i]);

		iov[i * 2 + 2].iov_base = params[i];
		iov[i * 2 + 2].iov_len = len[i];
	}

	return avrcp_send_browsing(session, transaction, AVRCP_GET_FOLDER_ITEMS,
							iov, number * 2 + 1);
}

int avrcp_change_path_rsp(struct avrcp *session, uint8_t transaction,
								uint32_t items)
{
	struct iovec iov;
	uint8_t pdu[5];

	pdu[0] = AVRCP_STATUS_SUCCESS;
	put_be32(items, &pdu[1]);

	iov.iov_base = pdu;
	iov.iov_len = sizeof(pdu);

	return avrcp_send_browsing(session, transaction, AVRCP_CHANGE_PATH,
								&iov, 1);
}

int avrcp_get_item_attributes_rsp(struct avrcp *session, uint8_t transaction,
					uint8_t number, uint32_t *attrs,
					const char **text)
{
	struct iovec iov[AVRCP_MEDIA_ATTRIBUTE_LAST * 2 + 1];
	uint8_t val[AVRCP_MEDIA_ATTRIBUTE_LAST][8];
	uint8_t pdu[2];
	int i;

	if (number > AVRCP_MEDIA_ATTRIBUTE_LAST)
		return -EINVAL;

	pdu[0] = AVRCP_STATUS_SUCCESS;
	pdu[1] = number;

	iov[0].iov_base = pdu;
	iov[0].iov_len = sizeof(pdu);

	for (i = 0; i < number; i++) {
		uint16_t len = 0;

		if (attrs[i] > AVRCP_MEDIA_ATTRIBUTE_LAST ||
				attrs[i] == AVRCP_MEDIA_ATTRIBUTE_ILLEGAL)
			return -EINVAL;

		if (text[i])
			len = strlen(text[i]);

		put_be32(attrs[i], &val[i][0]);
		put_be16(AVRCP_CHARSET_UTF8, &val[i][4]);
		put_be16(len, &val[i][6]);

		iov[i + 1].iov_base = val[i];
		iov[i + 1].iov_len = sizeof(val[i]);

		iov[i + 2].iov_base = (void *) text[i];
		iov[i + 2].iov_len = len;
	}

	return avrcp_send_browsing(session, transaction,
					AVRCP_GET_ITEM_ATTRIBUTES, iov,
					number * 2 + 1);
}

int avrcp_play_item_rsp(struct avrcp *session, uint8_t transaction)
{
	struct iovec iov;
	uint8_t pdu;

	pdu = AVRCP_STATUS_SUCCESS;

	iov.iov_base = &pdu;
	iov.iov_len = sizeof(pdu);

	return avrcp_send_browsing(session, transaction, AVRCP_PLAY_ITEM,
								&iov, 1);
}

int avrcp_search_rsp(struct avrcp *session, uint8_t transaction,
					uint16_t counter, uint32_t items)
{
	struct iovec iov;
	uint8_t pdu[7];

	pdu[0] = AVRCP_STATUS_SUCCESS;
	put_be16(counter, &pdu[1]);
	put_be32(items, &pdu[3]);

	iov.iov_base = pdu;
	iov.iov_len = sizeof(pdu);

	return avrcp_send_browsing(session, transaction, AVRCP_SEARCH,
								&iov, 1);
}

int avrcp_add_to_now_playing_rsp(struct avrcp *session, uint8_t transaction)
{
	struct iovec iov;
	uint8_t pdu;

	pdu = AVRCP_STATUS_SUCCESS;

	iov.iov_base = &pdu;
	iov.iov_len = sizeof(pdu);

	return avrcp_send_browsing(session, transaction,
					AVRCP_ADD_TO_NOW_PLAYING, &iov, 1);
}

int avrcp_send_passthrough(struct avrcp *session, uint32_t vendor, uint8_t op)
{
	uint8_t params[5];

	if (!vendor)
		return avctp_send_passthrough(session->conn, op, NULL, 0);

	hton24(params, vendor);
	put_be16(op, &params[3]);

	return avctp_send_passthrough(session->conn, AVC_VENDOR_UNIQUE, params,
								sizeof(params));
}
