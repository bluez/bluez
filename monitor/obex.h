// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2024  BlueZ project
 *
 *
 */

/* OBEX request opcodes (FINAL bit 0x80 is masked out before matching) */
#define OBEX_OP_CONNECT		0x00
#define OBEX_OP_DISCONNECT	0x01
#define OBEX_OP_PUT		0x02
#define OBEX_OP_GET		0x03
#define OBEX_OP_SETPATH	0x05
#define OBEX_OP_ACTION		0x06
#define OBEX_OP_SESSION	0x07
#define OBEX_OP_ABORT		0x7f

#define OBEX_FINAL_BIT		0x80

/* OBEX response codes */
#define OBEX_RSP_CONTINUE			0x10
#define OBEX_RSP_SUCCESS			0x20
#define OBEX_RSP_CREATED			0x21
#define OBEX_RSP_ACCEPTED			0x22
#define OBEX_RSP_NON_AUTHORITATIVE		0x23
#define OBEX_RSP_NO_CONTENT			0x24
#define OBEX_RSP_RESET_CONTENT			0x25
#define OBEX_RSP_PARTIAL_CONTENT		0x26
#define OBEX_RSP_MULTIPLE_CHOICES		0x30
#define OBEX_RSP_MOVED_PERMANENTLY		0x31
#define OBEX_RSP_MOVED_TEMPORARILY		0x32
#define OBEX_RSP_SEE_OTHER			0x33
#define OBEX_RSP_NOT_MODIFIED			0x34
#define OBEX_RSP_USE_PROXY			0x35
#define OBEX_RSP_BAD_REQUEST			0x40
#define OBEX_RSP_UNAUTHORIZED			0x41
#define OBEX_RSP_PAYMENT_REQUIRED		0x42
#define OBEX_RSP_FORBIDDEN			0x43
#define OBEX_RSP_NOT_FOUND			0x44
#define OBEX_RSP_METHOD_NOT_ALLOWED		0x45
#define OBEX_RSP_NOT_ACCEPTABLE		0x46
#define OBEX_RSP_PROXY_AUTH_REQUIRED		0x47
#define OBEX_RSP_REQUEST_TIME_OUT		0x48
#define OBEX_RSP_CONFLICT			0x49
#define OBEX_RSP_GONE				0x4a
#define OBEX_RSP_LENGTH_REQUIRED		0x4b
#define OBEX_RSP_PRECONDITION_FAILED		0x4c
#define OBEX_RSP_REQ_ENTITY_TOO_LARGE		0x4d
#define OBEX_RSP_REQ_URL_TOO_LARGE		0x4e
#define OBEX_RSP_UNSUPPORTED_MEDIA_TYPE	0x4f
#define OBEX_RSP_INTERNAL_SERVER_ERROR		0x50
#define OBEX_RSP_NOT_IMPLEMENTED		0x51
#define OBEX_RSP_BAD_GATEWAY			0x52
#define OBEX_RSP_SERVICE_UNAVAILABLE		0x53
#define OBEX_RSP_GATEWAY_TIMEOUT		0x54
#define OBEX_RSP_VERSION_NOT_SUPPORTED		0x55
#define OBEX_RSP_DATABASE_FULL			0x60
#define OBEX_RSP_DATABASE_LOCKED		0x61

/* OBEX header identifiers */
#define OBEX_HDR_COUNT		0xc0
#define OBEX_HDR_NAME		0x01
#define OBEX_HDR_TYPE		0x42
#define OBEX_HDR_LENGTH	0xc3
#define OBEX_HDR_TIME		0x44
#define OBEX_HDR_DESCRIPTION	0x05
#define OBEX_HDR_TARGET	0x46
#define OBEX_HDR_HTTP		0x47
#define OBEX_HDR_BODY		0x48
#define OBEX_HDR_BODY_END	0x49
#define OBEX_HDR_WHO		0x4a
#define OBEX_HDR_CONNECTION	0xcb
#define OBEX_HDR_APPARAM	0x4c
#define OBEX_HDR_AUTHCHAL	0x4d
#define OBEX_HDR_AUTHRESP	0x4e
#define OBEX_HDR_CREATOR	0xcf
#define OBEX_HDR_WANUUID	0x50
#define OBEX_HDR_OBJECTCLASS	0x51
#define OBEX_HDR_SESSIONPARAM	0x52
#define OBEX_HDR_SESSIONSEQ	0x93
#define OBEX_HDR_ACTION	0x94
#define OBEX_HDR_DESTNAME	0x15
#define OBEX_HDR_PERMISSIONS	0xd6
#define OBEX_HDR_SRM		0x97
#define OBEX_HDR_SRMP		0x98

/* BIP (Basic Imaging Profile) specific headers, see BIP spec section
 * 5.1. Only meaningful on a BIP channel, but the header IDs are not
 * reused by any other known profile so they can be decoded generically.
 */
#define OBEX_HDR_IMG_HANDLE	0x30
#define OBEX_HDR_IMG_DESC	0x71

/* Header ID encoding (top 2 bits of the header ID byte) */
#define OBEX_HDR_TYPE_MASK	0xc0
#define OBEX_HDR_TYPE_UNICODE	0x00
#define OBEX_HDR_TYPE_BYTES	0x40
#define OBEX_HDR_TYPE_UINT8	0x80
#define OBEX_HDR_TYPE_UINT32	0xc0

void obex_packet(const struct l2cap_frame *frame, uint16_t channel,
							uint16_t frag_len);

void obex_add_channel(uint16_t index, uint16_t handle, uint8_t channel,
							const char *profile);
bool obex_channel(uint16_t index, uint16_t handle, uint8_t channel,
							const char **profile);
void obex_remove_channel(uint16_t index, uint16_t handle, uint8_t channel);
void obex_remove_session(uint16_t index, uint16_t handle, uint16_t channel);
void obex_disconnect_handle(uint16_t index, uint16_t handle);

void obex_add_psm(uint16_t index, uint16_t handle, uint16_t psm);
bool obex_psm(uint16_t index, uint16_t handle, uint16_t psm);

void obex_sdp_scan(const struct l2cap_frame *frame, const uint8_t *data,
						uint32_t size, bool nested);
