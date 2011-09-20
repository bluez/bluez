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

#define AVCTP_PSM 23

#define AVC_MTU 512
#define AVC_HEADER_LENGTH 3

/* ctype entries */
#define AVC_CTYPE_CONTROL		0x0
#define AVC_CTYPE_STATUS		0x1
#define AVC_CTYPE_NOTIFY		0x3
#define AVC_CTYPE_NOT_IMPLEMENTED	0x8
#define AVC_CTYPE_ACCEPTED		0x9
#define AVC_CTYPE_REJECTED		0xA
#define AVC_CTYPE_STABLE		0xC
#define AVC_CTYPE_CHANGED		0xD
#define AVC_CTYPE_INTERIM		0xF

/* opcodes */
#define AVC_OP_VENDORDEP		0x00
#define AVC_OP_UNITINFO			0x30
#define AVC_OP_SUBUNITINFO		0x31
#define AVC_OP_PASSTHROUGH		0x7c

/* subunits of interest */
#define AVC_SUBUNIT_PANEL		0x09

/* operands in passthrough commands */
#define VOL_UP_OP			0x41
#define VOL_DOWN_OP			0x42
#define MUTE_OP				0x43
#define PLAY_OP				0x44
#define STAVC_OP_OP			0x45
#define PAUSE_OP			0x46
#define RECORD_OP			0x47
#define REWIND_OP			0x48
#define FAST_FORWARD_OP			0x49
#define EJECT_OP			0x4a
#define FORWARD_OP			0x4b
#define BACKWARD_OP			0x4c

struct avctp;

typedef enum {
	AVCTP_STATE_DISCONNECTED = 0,
	AVCTP_STATE_CONNECTING,
	AVCTP_STATE_CONNECTED
} avctp_state_t;

typedef void (*avctp_state_cb) (struct audio_device *dev,
				avctp_state_t old_state,
				avctp_state_t new_state,
				void *user_data);

typedef size_t (*avctp_pdu_cb) (struct avctp *session, uint8_t transaction,
					uint8_t *code, uint8_t *subunit,
					uint8_t *operands, size_t operand_count,
					void *user_data);

unsigned int avctp_add_state_cb(avctp_state_cb cb, void *user_data);
gboolean avctp_remove_state_cb(unsigned int id);

int avctp_register(const bdaddr_t *src, gboolean master);
void avctp_unregister(const bdaddr_t *src);

struct avctp *avctp_connect(const bdaddr_t *src, const bdaddr_t *dst);
struct avctp *avctp_get(const bdaddr_t *src, const bdaddr_t *dst);
void avctp_disconnect(struct avctp *session);

unsigned int avctp_register_pdu_handler(uint8_t opcode, avctp_pdu_cb cb,
							void *user_data);
gboolean avctp_unregister_pdu_handler(unsigned int id);

int avctp_send_passthrough(struct avctp *session, uint8_t op);
int avctp_send_vendordep(struct avctp *session, uint8_t transaction,
				uint8_t code, uint8_t subunit,
				uint8_t *operands, size_t operand_count);
