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

#define AVRCP_CHARSET_UTF8			106

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

struct avrcp {
	struct avctp *conn;
	struct avrcp_player *player;

	size_t tx_mtu;
	uint8_t *tx_buf;

	const struct avrcp_control_handler *control_handlers;
	void *control_data;
	unsigned int control_id;

	const struct avrcp_passthrough_handler *passthrough_handlers;
	void *passthrough_data;
	unsigned int passthrough_id;

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
	g_free(session->tx_buf);
	g_free(session);
}

static ssize_t handle_vendordep_pdu(struct avctp *conn, uint8_t transaction,
					uint8_t *code, uint8_t *subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	const struct avrcp_control_handler *handler;
	struct avrcp_header *pdu = (void *) operands;
	uint32_t company_id = ntoh24(pdu->company_id);
	uint16_t params_len = ntohs(pdu->params_len);
	ssize_t ret;

	if (company_id != IEEEID_BTSIG) {
		*code = AVC_CTYPE_NOT_IMPLEMENTED;
		return 0;
	}

	DBG("AVRCP PDU 0x%02X, len 0x%04X", pdu->pdu_id, params_len);

	pdu->packet_type = 0;
	pdu->rsvd = 0;

	if (operand_count < AVRCP_HEADER_LENGTH) {
		pdu->params[0] = AVRCP_STATUS_INVALID_COMMAND;
		goto reject;
	}

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

	ret = handler->func(session, transaction, params_len, pdu->params,
							session->control_data);
	if (ret < 0) {
		switch (ret) {
		case -EAGAIN:
			return ret;
		case -ENOSYS:
			pdu->params[0] = AVRCP_STATUS_INVALID_COMMAND;
			goto reject;
		case -EINVAL:
			pdu->params[0] = AVRCP_STATUS_INVALID_PARAM;
			goto reject;
		default:
			pdu->params[0] = AVRCP_STATUS_INTERNAL_ERROR;
			goto reject;
		}
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

	session->tx_mtu = omtu;
	session->tx_buf = g_malloc(omtu);

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
					uint8_t *params, size_t params_len)
{
	struct avrcp_header *pdu = (void *) session->tx_buf;
	size_t len = sizeof(*pdu);

	memset(pdu, 0, len);

	hton24(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = pdu_id;
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;

	if (params_len > 0) {
		len += params_len;

		if (len > session->tx_mtu)
			return -ENOBUFS;

		memcpy(pdu->params, params, params_len);
		pdu->params_len = htons(params_len);
	}

	return avctp_send_vendordep(session->conn, transaction, code, subunit,
							session->tx_buf, len);
}

static int avrcp_send_req(struct avrcp *session, uint8_t code, uint8_t subunit,
					uint8_t pdu_id, uint8_t *params,
					size_t params_len, avctp_rsp_cb func,
					void *user_data)
{
	struct avrcp_header *pdu = (void *) session->tx_buf;
	size_t len = sizeof(*pdu);

	memset(pdu, 0, len);

	hton24(pdu->company_id, IEEEID_BTSIG);
	pdu->pdu_id = pdu_id;
	pdu->packet_type = AVRCP_PACKET_TYPE_SINGLE;

	if (params_len > 0) {
		len += params_len;

		if (len > session->tx_mtu)
			return -ENOBUFS;

		memcpy(pdu->params, params, params_len);
		pdu->params_len = htons(params_len);
	}

	return avctp_send_vendordep_req(session->conn, code, subunit,
					session->tx_buf, len, func, user_data);
}

int avrcp_get_capabilities(struct avrcp *session, uint8_t param,
					avctp_rsp_cb func, void *user_data)
{
	return avrcp_send_req(session, AVC_CTYPE_STATUS, AVC_SUBUNIT_PANEL,
				AVRCP_GET_CAPABILITIES, &param, sizeof(param),
				func, user_data);
}

int avrcp_register_notification(struct avrcp *session, uint8_t event,
					uint32_t interval, avctp_rsp_cb func,
					void *user_data)
{
	uint8_t params[5];

	params[0] = event;
	put_be32(interval, &params[1]);

	return avrcp_send_req(session, AVC_CTYPE_NOTIFY, AVC_SUBUNIT_PANEL,
					AVRCP_REGISTER_NOTIFICATION,
					params, sizeof(params),
					func, user_data);
}

int avrcp_list_player_attributes(struct avrcp *session, avctp_rsp_cb func,
								void *user_data)
{
	return avrcp_send_req(session, AVC_CTYPE_STATUS, AVC_SUBUNIT_PANEL,
				AVRCP_LIST_PLAYER_ATTRIBUTES, NULL, 0,
				func, user_data);
}

int avrcp_get_player_attribute_text(struct avrcp *session, uint8_t *attributes,
					uint8_t attr_len, avctp_rsp_cb func,
					void *user_data)
{
	return avrcp_send_req(session, AVC_CTYPE_STATUS, AVC_SUBUNIT_PANEL,
				AVRCP_GET_PLAYER_ATTRIBUTE_TEXT, attributes,
				attr_len, func, user_data);
}

int avrcp_get_current_player_value(struct avrcp *session, uint8_t *attrs,
					uint8_t attr_count, avctp_rsp_cb func,
					void *user_data)

{
	uint8_t buf[AVRCP_ATTRIBUTE_LAST + 1];

	if (attr_count > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	if (attrs && attr_count) {
		buf[0] = attr_count;
		memcpy(buf + 1, attrs, attr_count);
	}

	return avrcp_send_req(session, AVC_CTYPE_STATUS, AVC_SUBUNIT_PANEL,
				AVRCP_GET_CURRENT_PLAYER_VALUE, buf,
				attr_count + 1, func, user_data);
}

int avrcp_set_player_value(struct avrcp *session, uint8_t *attributes,
					uint8_t attr_count, uint8_t *values,
					avctp_rsp_cb func, void *user_data)
{
	uint8_t buf[2 * AVRCP_ATTRIBUTE_LAST + 1];
	int i;

	if (attr_count > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	buf[0] = attr_count;

	for (i = 0; i < attr_count; i++) {
		buf[i * 2 + 1] = attributes[i];
		buf[i * 2 + 2] = values[i];
	}

	return avrcp_send_req(session, AVC_CTYPE_CONTROL, AVC_SUBUNIT_PANEL,
				AVRCP_SET_PLAYER_VALUE, buf, 2 * attr_count + 1,
				func, user_data);
}

int avrcp_get_play_status(struct avrcp *session, avctp_rsp_cb func,
								void *user_data)
{
	return avrcp_send_req(session, AVC_CTYPE_STATUS, AVC_SUBUNIT_PANEL,
				AVRCP_GET_PLAY_STATUS, NULL, 0, func,
				user_data);
}

int avrcp_set_volume(struct avrcp *session, uint8_t volume, avctp_rsp_cb func,
							void *user_data)
{
	return avrcp_send_req(session, AVC_CTYPE_CONTROL, AVC_SUBUNIT_PANEL,
						AVRCP_SET_ABSOLUTE_VOLUME,
						&volume, sizeof(volume),
						func, user_data);
}

int avrcp_get_element_attributes(struct avrcp *session, avctp_rsp_cb func,
								void *user_data)
{
	uint8_t buf[9];

	/* This returns all attributes */
	memset(buf, 0, sizeof(buf));

	return avrcp_send_req(session, AVC_CTYPE_STATUS, AVC_SUBUNIT_PANEL,
				AVRCP_GET_ELEMENT_ATTRIBUTES, buf, sizeof(buf),
				func, user_data);
}

int avrcp_set_addressed_player(struct avrcp *session, uint16_t player_id,
					avctp_rsp_cb func, void *user_data)
{
	uint8_t params[2];

	put_be16(player_id, params);

	return avrcp_send_req(session, AVC_CTYPE_CONTROL, AVC_SUBUNIT_PANEL,
				AVRCP_SET_ADDRESSED_PLAYER, params,
				sizeof(params), func, user_data);
}

int avrcp_get_capabilities_rsp(struct avrcp *session, uint8_t transaction,
						uint8_t number, uint8_t *events)
{
	uint8_t pdu[AVRCP_EVENT_LAST + 1];

	if (number > AVRCP_EVENT_LAST)
		return -EINVAL;

	pdu[0] = number;
	memcpy(&pdu[1], events, number);

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
				AVC_SUBUNIT_PANEL, AVRCP_GET_CAPABILITIES,
				pdu, number + 1);
}

int avrcp_list_player_attributes_rsp(struct avrcp *session, uint8_t transaction,
					uint8_t number, uint8_t *attrs)
{
	uint8_t pdu[AVRCP_ATTRIBUTE_LAST + 1];

	if (number > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	pdu[0] = number;

	if (number > 0)
		memcpy(&pdu[1], attrs, number);

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
				AVC_SUBUNIT_PANEL, AVRCP_LIST_PLAYER_ATTRIBUTES,
				pdu, number + 1);
}

int avrcp_get_player_attribute_text_rsp(struct avrcp *session,
					uint8_t transaction, uint8_t number,
					uint8_t *attrs, const char **text)
{
	uint8_t pdu[AVRCP_ATTRIBUTE_LAST * (4 + 255)];
	uint8_t *ptr;
	uint16_t length;
	int i;

	if (number > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	pdu[0] = number;
	length = 1;
	for (i = 0, ptr = &pdu[1]; i < number; i++) {
		uint8_t len = 0;

		if (attrs[i] > AVRCP_ATTRIBUTE_LAST ||
					attrs[i] == AVRCP_ATTRIBUTE_ILEGAL)
			return -EINVAL;

		if (text[i])
			len = strlen(text[i]);

		ptr[0] = attrs[i];
		put_be16(AVRCP_CHARSET_UTF8, &ptr[1]);
		ptr[3] = len;
		memcpy(&ptr[4], text[i], len);
		ptr += 4 + len;
		length += 4 + len;
	}

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
			AVC_SUBUNIT_PANEL, AVRCP_GET_PLAYER_ATTRIBUTE_TEXT,
			pdu, length);
}

int avrcp_list_player_values_rsp(struct avrcp *session, uint8_t transaction,
					uint8_t number, uint8_t *values)
{
	uint8_t pdu[AVRCP_ATTRIBUTE_LAST + 1];

	if (number > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	pdu[0] = number;
	memcpy(&pdu[1], values, number);

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
			AVC_SUBUNIT_PANEL, AVRCP_LIST_PLAYER_VALUES,
			pdu, number + 1);
}

int avrcp_get_play_status_rsp(struct avrcp *session, uint8_t transaction,
				uint32_t position, uint32_t duration,
				uint8_t status)
{
	uint8_t pdu[9];

	put_be32(position, &pdu[0]);
	put_be32(duration, &pdu[4]);
	pdu[8] = status;

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
				AVC_SUBUNIT_PANEL, AVRCP_GET_PLAY_STATUS,
				pdu, sizeof(pdu));
}

int avrcp_get_player_values_text_rsp(struct avrcp *session,
					uint8_t transaction, uint8_t number,
					uint8_t *values, const char **text)
{
	uint8_t pdu[AVRCP_ATTRIBUTE_LAST * (4 + 255)];
	uint8_t *ptr;
	uint16_t length;
	int i;

	if (number > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	pdu[0] = number;
	length = 1;
	for (i = 0, ptr = &pdu[1]; i < number; i++) {
		uint8_t len = 0;

		if (text[i])
			len = strlen(text[i]);

		ptr[0] = values[i];
		put_be16(AVRCP_CHARSET_UTF8, &ptr[1]);
		ptr[3] = len;
		memcpy(&ptr[4], text[i], len);
		ptr += 4 + len;
		length += 4 + len;
	}

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
			AVC_SUBUNIT_PANEL, AVRCP_GET_PLAYER_VALUE_TEXT,
			pdu, length);
}

int avrcp_get_current_player_value_rsp(struct avrcp *session,
					uint8_t transaction, uint8_t number,
					uint8_t *attrs, uint8_t *values)
{
	uint8_t pdu[AVRCP_ATTRIBUTE_LAST * 2  + 1];
	uint8_t *ptr;
	uint16_t length;
	int i;

	if (number > AVRCP_ATTRIBUTE_LAST)
		return -EINVAL;

	pdu[0] = number;
	length = 1;
	for (i = 0, ptr = &pdu[1]; i < number; i++) {
		ptr[0] = attrs[i];
		ptr[1] = values[i];
		ptr += 2;
		length += 2;
	}

	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
			AVC_SUBUNIT_PANEL, AVRCP_GET_CURRENT_PLAYER_VALUE,
			pdu, length);
}

int avrcp_get_element_attrs_rsp(struct avrcp *session, uint8_t transaction,
					uint8_t *params, size_t params_len)
{
	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
				AVC_SUBUNIT_PANEL, AVRCP_GET_ELEMENT_ATTRIBUTES,
				params, params_len);
}

int avrcp_register_notification_rsp(struct avrcp *session, uint8_t transaction,
					uint8_t code, uint8_t *params,
					size_t params_len)
{
	return avrcp_send(session, transaction, code,
				AVC_SUBUNIT_PANEL, AVRCP_REGISTER_NOTIFICATION,
				params, params_len);
}

int avrcp_set_addressed_player_rsp(struct avrcp *session, uint8_t transaction,
							uint8_t status)
{
	return avrcp_send(session, transaction, AVC_CTYPE_STABLE,
				AVC_SUBUNIT_PANEL, AVRCP_SET_ADDRESSED_PLAYER,
				&status, sizeof(status));
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
