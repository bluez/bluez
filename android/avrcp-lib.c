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

#include "lib/bluetooth.h"

#include "src/log.h"

#include "avctp.h"
#include "avrcp-lib.h"

/* Company IDs for vendor dependent commands */
#define IEEEID_BTSIG		0x001958

/* Status codes */
#define AVRCP_STATUS_INVALID_COMMAND		0x00
#define AVRCP_STATUS_INVALID_PARAM		0x01
#define AVRCP_STATUS_PARAM_NOT_FOUND		0x02
#define AVRCP_STATUS_INTERNAL_ERROR		0x03
#define AVRCP_STATUS_SUCCESS			0x04
#define AVRCP_STATUS_OUT_OF_BOUNDS		0x0b
#define AVRCP_STATUS_INVALID_PLAYER_ID		0x11
#define AVRCP_STATUS_PLAYER_NOT_BROWSABLE	0x12
#define AVRCP_STATUS_NO_AVAILABLE_PLAYERS	0x15
#define AVRCP_STATUS_ADDRESSED_PLAYER_CHANGED	0x16

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

static inline uint32_t ntoh24(const uint8_t src[3])
{
	return src[0] << 16 | src[1] << 8 | src[2];
}

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

static inline uint32_t ntoh24(const uint8_t src[3])
{
	uint32_t dst;

	memcpy(&dst, src, sizeof(src));

	return dst;
}

#else
#error "Unknown byte order"
#endif

struct avrcp {
	struct avctp *conn;

	const struct avrcp_control_handler *control_handlers;
	void *control_data;
	unsigned int control_id;

	const struct avrcp_passthrough_handler *passthrough_handlers;
	void *passthrough_data;
	unsigned int passthrough_id;
};

void avrcp_shutdown(struct avrcp *session)
{
	if (session->conn) {
		if (session->control_id > 0)
			avctp_unregister_pdu_handler(session->conn,
							session->control_id);
		if (session->passthrough_id > 0)
			avctp_unregister_passthrough_handler(session->conn,
						session->passthrough_id);
		avctp_shutdown(session->conn);
	}

	g_free(session);
}

static size_t handle_vendordep_pdu(struct avctp *conn, uint8_t transaction,
					uint8_t *code, uint8_t *subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data)
{
	struct avrcp *session = user_data;
	const struct avrcp_control_handler *handler;
	struct avrcp_header *pdu = (void *) operands;
	uint32_t company_id = ntoh24(pdu->company_id);

	if (company_id != IEEEID_BTSIG) {
		*code = AVC_CTYPE_NOT_IMPLEMENTED;
		return 0;
	}

	DBG("AVRCP PDU 0x%02X, len 0x%04X", pdu->pdu_id,
						ntohs(pdu->params_len));

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

	*code = handler->func(session, transaction, &pdu->params_len,
					pdu->params, session->control_data);

	return AVRCP_HEADER_LENGTH + ntohs(pdu->params_len);

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

	/* Do not trigger handler on release */
	if (!pressed)
		return true;

	return handler->func(session);
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

	return session;
}

void avrcp_set_destroy_cb(struct avrcp *session, avrcp_destroy_cb_t cb,
							void *user_data)
{
	avctp_set_destroy_cb(session->conn, cb, user_data);
}

void avrcp_set_control_handlers(struct avrcp *session,
				const struct avrcp_control_handler *handlers,
				void *user_data)
{
	session->control_handlers = handlers;
	session->control_data = user_data;
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
