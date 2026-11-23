// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright © 2025 Collabora Ltd.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"

#include "src/shared/util.h"
#include "bt.h"
#include "packet.h"
#include "display.h"
#include "l2cap.h"
#include "obex.h"

/* SDP Data Element types (see monitor/sdp.c type_table) */
#define SDP_DE_UINT		1
#define SDP_DE_UUID		3
#define SDP_DE_SEQ		6

/* SDP attribute IDs we care about */
#define SDP_ATTR_SVCLASS_ID_LIST	0x0001
#define SDP_ATTR_PROTO_DESC_LIST	0x0004
#define SDP_ATTR_ADD_PROTO_DESC_LISTS	0x000d
/* GOEP (OBEX) L2CAP PSM, shared by MAP/PBAP/OPP service records that
 * support an L2CAP transport alongside (or instead of) RFCOMM.
 */
#define SDP_ATTR_GOEP_L2CAP_PSM		0x0200

#define MAX_OBEX_CHAN 64
#define MAX_OBEX_REQ  32

struct obex_chan_data {
	uint16_t index;
	uint16_t handle;
	uint8_t channel;
	char profile[32];
};

static struct obex_chan_data obex_chan_list[MAX_OBEX_CHAN];

struct obex_req_data {
	uint16_t index;
	uint16_t handle;
	uint16_t channel;
	uint8_t opcode;
};

static struct obex_req_data obex_req_list[MAX_OBEX_REQ];

void obex_add_channel(uint16_t index, uint16_t handle, uint8_t channel,
							const char *profile)
{
	int i, n = -1;

	if (!channel)
		return;

	for (i = 0; i < MAX_OBEX_CHAN; i++) {
		if (!obex_chan_list[i].channel) {
			if (n < 0)
				n = i;
			continue;
		}

		if (obex_chan_list[i].index == index &&
				obex_chan_list[i].handle == handle &&
				obex_chan_list[i].channel == channel) {
			n = i;
			break;
		}
	}

	if (n < 0)
		return;

	obex_chan_list[n].index = index;
	obex_chan_list[n].handle = handle;
	obex_chan_list[n].channel = channel;

	if (profile)
		snprintf(obex_chan_list[n].profile,
				sizeof(obex_chan_list[n].profile),
							"%s", profile);
	else
		obex_chan_list[n].profile[0] = '\0';
}

bool obex_channel(uint16_t index, uint16_t handle, uint8_t channel,
							const char **profile)
{
	int i;

	if (!channel)
		return false;

	for (i = 0; i < MAX_OBEX_CHAN; i++) {
		if (!obex_chan_list[i].channel)
			continue;

		if (obex_chan_list[i].index == index &&
				obex_chan_list[i].handle == handle &&
				obex_chan_list[i].channel == channel) {
			if (profile)
				*profile = obex_chan_list[i].profile;
			return true;
		}
	}

	return false;
}

#define MAX_OBEX_PSM 16

/* Dynamic L2CAP PSMs advertised via the SDP GoepL2capPsm attribute
 * (0x0200), as used by GOEP-based profiles (MAP/PBAP/OPP) that support
 * an L2CAP transport for OBEX in addition to (or instead of) RFCOMM.
 */
struct obex_psm_data {
	uint16_t index;
	uint16_t handle;
	uint16_t psm;
};

static struct obex_psm_data obex_psm_list[MAX_OBEX_PSM];

void obex_add_psm(uint16_t index, uint16_t handle, uint16_t psm)
{
	int i, n = -1;

	if (!psm)
		return;

	for (i = 0; i < MAX_OBEX_PSM; i++) {
		if (!obex_psm_list[i].psm) {
			if (n < 0)
				n = i;
			continue;
		}

		if (obex_psm_list[i].index == index &&
				obex_psm_list[i].handle == handle &&
				obex_psm_list[i].psm == psm) {
			n = i;
			break;
		}
	}

	if (n < 0)
		return;

	obex_psm_list[n].index = index;
	obex_psm_list[n].handle = handle;
	obex_psm_list[n].psm = psm;
}

bool obex_psm(uint16_t index, uint16_t handle, uint16_t psm)
{
	int i;

	if (!psm)
		return false;

	for (i = 0; i < MAX_OBEX_PSM; i++) {
		if (!obex_psm_list[i].psm)
			continue;

		if (obex_psm_list[i].index == index &&
				obex_psm_list[i].handle == handle &&
				obex_psm_list[i].psm == psm)
			return true;
	}

	return false;
}

static void obex_clear_request(uint16_t index, uint16_t handle,
							uint16_t channel)
{
	int i;

	for (i = 0; i < MAX_OBEX_REQ; i++) {
		if (obex_req_list[i].index == index &&
				obex_req_list[i].handle == handle &&
				obex_req_list[i].channel == channel)
			memset(&obex_req_list[i], 0, sizeof(obex_req_list[i]));
	}
}

void obex_remove_channel(uint16_t index, uint16_t handle, uint8_t channel)
{
	int i;

	if (!channel)
		return;

	for (i = 0; i < MAX_OBEX_CHAN; i++) {
		if (obex_chan_list[i].index == index &&
				obex_chan_list[i].handle == handle &&
				obex_chan_list[i].channel == channel) {
			memset(&obex_chan_list[i], 0,
						sizeof(obex_chan_list[i]));
			break;
		}
	}

	obex_clear_request(index, handle, channel);
}

void obex_remove_session(uint16_t index, uint16_t handle, uint16_t channel)
{
	obex_clear_request(index, handle, channel);
}

void obex_disconnect_handle(uint16_t index, uint16_t handle)
{
	int i;

	for (i = 0; i < MAX_OBEX_CHAN; i++) {
		if (!obex_chan_list[i].channel)
			continue;

		if (obex_chan_list[i].index == index &&
				obex_chan_list[i].handle == handle)
			memset(&obex_chan_list[i], 0,
						sizeof(obex_chan_list[i]));
	}

	for (i = 0; i < MAX_OBEX_REQ; i++) {
		if (obex_req_list[i].index == index &&
				obex_req_list[i].handle == handle)
			memset(&obex_req_list[i], 0, sizeof(obex_req_list[i]));
	}

	for (i = 0; i < MAX_OBEX_PSM; i++) {
		if (!obex_psm_list[i].psm)
			continue;

		if (obex_psm_list[i].index == index &&
				obex_psm_list[i].handle == handle)
			memset(&obex_psm_list[i], 0,
						sizeof(obex_psm_list[i]));
	}
}

static void obex_set_last_request(uint16_t index, uint16_t handle,
					uint16_t channel, uint8_t opcode)
{
	int i, n = -1;

	for (i = 0; i < MAX_OBEX_REQ; i++) {
		if (obex_req_list[i].handle == 0x0000 && n < 0) {
			n = i;
			continue;
		}

		if (obex_req_list[i].index == index &&
				obex_req_list[i].handle == handle &&
				obex_req_list[i].channel == channel) {
			n = i;
			break;
		}
	}

	if (n < 0)
		return;

	obex_req_list[n].index = index;
	obex_req_list[n].handle = handle;
	obex_req_list[n].channel = channel;
	obex_req_list[n].opcode = opcode;
}

static bool obex_last_request_is(uint16_t index, uint16_t handle,
					uint16_t channel, uint8_t opcode)
{
	int i;

	for (i = 0; i < MAX_OBEX_REQ; i++) {
		if (obex_req_list[i].handle != handle ||
				obex_req_list[i].index != index ||
				obex_req_list[i].channel != channel)
			continue;

		return obex_req_list[i].opcode == opcode;
	}

	return false;
}

/*
 * Minimal SDP Data Element reader, mirroring monitor/sdp.c's
 * decode_data_elements() size/type decoding, but returning the decoded
 * element instead of printing it so callers can inspect the value.
 */
static uint32_t obex_de_next(const uint8_t *data, uint32_t size,
				uint8_t *type, const uint8_t **value,
				uint32_t *vsize)
{
	uint32_t extrabytes, datalen, elemlen;

	if (size < 1)
		return 0;

	*type = (data[0] & 0xf8) >> 3;

	switch (data[0] & 0x07) {
	case 0:
		extrabytes = 0;
		datalen = 1;
		break;
	case 1:
		extrabytes = 0;
		datalen = 2;
		break;
	case 2:
		extrabytes = 0;
		datalen = 4;
		break;
	case 3:
		extrabytes = 0;
		datalen = 8;
		break;
	case 4:
		extrabytes = 0;
		datalen = 16;
		break;
	case 5:
		extrabytes = 1;
		if (size < 2)
			return 0;
		datalen = data[1];
		break;
	case 6:
		extrabytes = 2;
		if (size < 3)
			return 0;
		datalen = get_be16(data + 1);
		break;
	case 7:
		extrabytes = 4;
		if (size < 5)
			return 0;
		datalen = get_be32(data + 1);
		break;
	default:
		return 0;
	}

	elemlen = 1 + extrabytes + datalen;

	if (elemlen > size)
		return 0;

	*value = data + 1 + extrabytes;
	*vsize = datalen;

	return elemlen;
}

static uint16_t obex_de_uuid16(const uint8_t *data, uint32_t size)
{
	switch (size) {
	case 2:
		return get_be16(data);
	case 4:
		/* 32-bit UUIDs based on the Bluetooth base UUID still encode
		 * the short value in the top 16 bits.
		 */
		return (uint16_t) (get_be32(data) >> 16);
	case 16:
		return get_be16(data + 2);
	default:
		return 0;
	}
}

/* Scan a single Protocol Descriptor List value (a sequence of protocol
 * entries, each of which is itself a sequence starting with a protocol
 * UUID) looking for an RFCOMM channel number alongside an OBEX marker.
 */
static void obex_scan_proto_list(uint16_t index, uint16_t handle,
				const uint8_t *data, uint32_t size,
				const char *profile)
{
	uint32_t pos = 0;
	uint8_t channel = 0;
	bool have_obex = false;

	while (pos < size) {
		uint8_t type;
		const uint8_t *entry;
		uint32_t entry_size;
		uint32_t elemlen = obex_de_next(data + pos, size - pos,
							&type, &entry,
							&entry_size);
		uint32_t epos;
		uint16_t uuid16 = 0;
		bool have_uuid = false;

		if (!elemlen)
			break;

		if (type != SDP_DE_SEQ)
			goto next;

		epos = 0;

		while (epos < entry_size) {
			uint8_t etype;
			const uint8_t *eval;
			uint32_t evsize;
			uint32_t eelemlen = obex_de_next(entry + epos,
							entry_size - epos,
							&etype, &eval,
							&evsize);

			if (!eelemlen)
				break;

			if (!have_uuid) {
				if (etype == SDP_DE_UUID) {
					uuid16 = obex_de_uuid16(eval, evsize);
					have_uuid = true;
				}
			} else if (uuid16 == 0x0003 && evsize >= 1) {
				/* RFCOMM channel parameter */
				channel = eval[0];
			}

			epos += eelemlen;
		}

		if (uuid16 == 0x0008)
			have_obex = true;

next:
		pos += elemlen;
	}

	if (have_obex && channel)
		obex_add_channel(index, handle, channel, profile);
}

/* Pull a short human-readable profile name out of a ServiceClassIDList
 * attribute value (first UUID in the list).
 */
static bool obex_scan_svclass(const uint8_t *data, uint32_t size,
							char *buf, size_t len)
{
	uint8_t type;
	const uint8_t *value;
	uint32_t vsize;
	uint16_t uuid16;

	if (!obex_de_next(data, size, &type, &value, &vsize))
		return false;

	if (type != SDP_DE_UUID)
		return false;

	uuid16 = obex_de_uuid16(value, vsize);
	if (!uuid16)
		return false;

	snprintf(buf, len, "%s", bt_uuid16_to_str(uuid16));

	return true;
}

static void obex_scan_attr_list(uint16_t index, uint16_t handle,
				const uint8_t *data, uint32_t size)
{
	uint32_t pos = 0;
	char profile[32] = { 0 };

	while (pos < size) {
		uint8_t type;
		const uint8_t *id_val;
		uint32_t id_size;
		uint32_t idlen = obex_de_next(data + pos, size - pos, &type,
							&id_val, &id_size);
		uint16_t attr_id;
		uint32_t vallen;
		const uint8_t *attr_val;
		uint32_t attr_size;

		if (!idlen || id_size < 2)
			break;

		attr_id = get_be16(id_val);
		pos += idlen;

		vallen = obex_de_next(data + pos, size - pos, &type,
						&attr_val, &attr_size);
		if (!vallen)
			break;

		switch (attr_id) {
		case SDP_ATTR_SVCLASS_ID_LIST:
			obex_scan_svclass(attr_val, attr_size, profile,
							sizeof(profile));
			break;
		case SDP_ATTR_PROTO_DESC_LIST:
			obex_scan_proto_list(index, handle, attr_val,
							attr_size, profile);
			break;
		case SDP_ATTR_ADD_PROTO_DESC_LISTS: {
			uint32_t apos = 0;

			while (apos < attr_size) {
				uint8_t atype;
				const uint8_t *aval;
				uint32_t avsize;
				uint32_t aelemlen = obex_de_next(
						attr_val + apos,
						attr_size - apos,
						&atype, &aval, &avsize);

				if (!aelemlen)
					break;

				if (atype == SDP_DE_SEQ)
					obex_scan_proto_list(index, handle,
								aval, avsize,
								profile);

				apos += aelemlen;
			}
			break;
		}
		case SDP_ATTR_GOEP_L2CAP_PSM:
			if (type == SDP_DE_UINT && attr_size == 2)
				obex_add_psm(index, handle,
						get_be16(attr_val));
			break;
		}

		pos += vallen;
	}
}

/*
 * The buffer handed to obex_sdp_scan() is still wrapped in the raw SDP
 * Data Element Sequence(s) used on the wire: a single outer Sequence
 * whose contents are either a flat attribute id/value list (one service
 * record, SDP_ServiceAttributeResponse) or, when "nested" is set, a
 * Sequence of such attribute lists, one per matched service record
 * (SDP_ServiceSearchAttributeResponse). Peel those wrapper(s) off before
 * handing each flat attribute list to obex_scan_attr_list(), mirroring
 * how monitor/sdp.c's print_attr_list()/print_attr_lists() unwrap the
 * same buffer for display.
 */
void obex_sdp_scan(const struct l2cap_frame *frame, const uint8_t *data,
						uint32_t size, bool nested)
{
	uint8_t type;
	const uint8_t *val;
	uint32_t vsize;
	uint32_t pos = 0;

	if (!obex_de_next(data, size, &type, &val, &vsize) ||
							type != SDP_DE_SEQ)
		return;

	if (!nested) {
		obex_scan_attr_list(frame->index, frame->handle, val, vsize);
		return;
	}

	while (pos < vsize) {
		uint8_t rtype;
		const uint8_t *rval;
		uint32_t rvsize;
		uint32_t relemlen = obex_de_next(val + pos, vsize - pos,
							&rtype, &rval, &rvsize);

		if (!relemlen)
			break;

		if (rtype == SDP_DE_SEQ)
			obex_scan_attr_list(frame->index, frame->handle,
							rval, rvsize);

		pos += relemlen;
	}
}

struct obex_opcode_data {
	uint8_t code;
	const char *str;
};

static const struct obex_opcode_data obex_req_table[] = {
	{ OBEX_OP_CONNECT,	"Connect"		},
	{ OBEX_OP_DISCONNECT,	"Disconnect"		},
	{ OBEX_OP_PUT,		"Put"			},
	{ OBEX_OP_GET,		"Get"			},
	{ OBEX_OP_SETPATH,	"Set Path"		},
	{ OBEX_OP_ACTION,	"Action"		},
	{ OBEX_OP_SESSION,	"Session"		},
	{ OBEX_OP_ABORT,	"Abort"			},
	{ }
};

static const struct obex_opcode_data obex_rsp_table[] = {
	{ OBEX_RSP_CONTINUE,			"Continue"		},
	{ OBEX_RSP_SUCCESS,			"OK, Success"		},
	{ OBEX_RSP_CREATED,			"Created"		},
	{ OBEX_RSP_ACCEPTED,			"Accepted"		},
	{ OBEX_RSP_NON_AUTHORITATIVE,		"Non-Authoritative"	},
	{ OBEX_RSP_NO_CONTENT,			"No Content"		},
	{ OBEX_RSP_RESET_CONTENT,		"Reset Content"		},
	{ OBEX_RSP_PARTIAL_CONTENT,		"Partial Content"	},
	{ OBEX_RSP_MULTIPLE_CHOICES,		"Multiple Choices"	},
	{ OBEX_RSP_MOVED_PERMANENTLY,		"Moved Permanently"	},
	{ OBEX_RSP_MOVED_TEMPORARILY,		"Moved Temporarily"	},
	{ OBEX_RSP_SEE_OTHER,			"See Other"		},
	{ OBEX_RSP_NOT_MODIFIED,		"Not Modified"		},
	{ OBEX_RSP_USE_PROXY,			"Use Proxy"		},
	{ OBEX_RSP_BAD_REQUEST,			"Bad Request"		},
	{ OBEX_RSP_UNAUTHORIZED,		"Unauthorized"		},
	{ OBEX_RSP_PAYMENT_REQUIRED,		"Payment Required"	},
	{ OBEX_RSP_FORBIDDEN,			"Forbidden"		},
	{ OBEX_RSP_NOT_FOUND,			"Not Found"		},
	{ OBEX_RSP_METHOD_NOT_ALLOWED,		"Method Not Allowed"	},
	{ OBEX_RSP_NOT_ACCEPTABLE,		"Not Acceptable"	},
	{ OBEX_RSP_PROXY_AUTH_REQUIRED,
					"Proxy Authentication Required" },
	{ OBEX_RSP_REQUEST_TIME_OUT,		"Request Time Out"	},
	{ OBEX_RSP_CONFLICT,			"Conflict"		},
	{ OBEX_RSP_GONE,			"Gone"			},
	{ OBEX_RSP_LENGTH_REQUIRED,		"Length Required"	},
	{ OBEX_RSP_PRECONDITION_FAILED,		"Precondition Failed"	},
	{ OBEX_RSP_REQ_ENTITY_TOO_LARGE,
					"Requested Entity Too Large"	},
	{ OBEX_RSP_REQ_URL_TOO_LARGE,		"Requested URL Too Large" },
	{ OBEX_RSP_UNSUPPORTED_MEDIA_TYPE,	"Unsupported Media Type" },
	{ OBEX_RSP_INTERNAL_SERVER_ERROR,	"Internal Server Error"	},
	{ OBEX_RSP_NOT_IMPLEMENTED,		"Not Implemented"	},
	{ OBEX_RSP_BAD_GATEWAY,			"Bad Gateway"		},
	{ OBEX_RSP_SERVICE_UNAVAILABLE,		"Service Unavailable"	},
	{ OBEX_RSP_GATEWAY_TIMEOUT,		"Gateway Timeout"	},
	{ OBEX_RSP_VERSION_NOT_SUPPORTED,	"HTTP Version Not Supported" },
	{ OBEX_RSP_DATABASE_FULL,		"Database Full"	},
	{ OBEX_RSP_DATABASE_LOCKED,		"Database Locked"	},
	{ }
};

static const char *obex_opcode_str(uint8_t code, bool *is_request)
{
	int i;

	for (i = 0; obex_req_table[i].str; i++) {
		if (obex_req_table[i].code == code) {
			*is_request = true;
			return obex_req_table[i].str;
		}
	}

	for (i = 0; obex_rsp_table[i].str; i++) {
		if (obex_rsp_table[i].code == code) {
			*is_request = false;
			return obex_rsp_table[i].str;
		}
	}

	return NULL;
}

static const struct {
	uint8_t id;
	const char *str;
} obex_hdr_table[] = {
	{ OBEX_HDR_COUNT,		"Count"			},
	{ OBEX_HDR_NAME,		"Name"			},
	{ OBEX_HDR_TYPE,		"Type"			},
	{ OBEX_HDR_LENGTH,		"Length"		},
	{ OBEX_HDR_TIME,		"Time"			},
	{ OBEX_HDR_DESCRIPTION,		"Description"		},
	{ OBEX_HDR_TARGET,		"Target"		},
	{ OBEX_HDR_HTTP,		"HTTP"			},
	{ OBEX_HDR_BODY,		"Body"			},
	{ OBEX_HDR_BODY_END,		"End of Body"		},
	{ OBEX_HDR_WHO,			"Who"			},
	{ OBEX_HDR_CONNECTION,		"Connection ID"		},
	{ OBEX_HDR_APPARAM,		"Application Parameters" },
	{ OBEX_HDR_AUTHCHAL,		"Authentication Challenge" },
	{ OBEX_HDR_AUTHRESP,		"Authentication Response" },
	{ OBEX_HDR_CREATOR,		"Creator ID"		},
	{ OBEX_HDR_WANUUID,		"WAN UUID"		},
	{ OBEX_HDR_OBJECTCLASS,		"Object Class"		},
	{ OBEX_HDR_SESSIONPARAM,	"Session Parameters"	},
	{ OBEX_HDR_SESSIONSEQ,		"Session Sequence Number" },
	{ OBEX_HDR_ACTION,		"Action ID"		},
	{ OBEX_HDR_DESTNAME,		"Destination Name"	},
	{ OBEX_HDR_PERMISSIONS,		"Permissions"		},
	{ OBEX_HDR_SRM,			"Single Response Mode"	},
	{ OBEX_HDR_SRMP,		"SRM Parameters"	},
	{ OBEX_HDR_IMG_HANDLE,		"Image Handle"		},
	{ OBEX_HDR_IMG_DESC,		"Image Descriptor"	},
	{ }
};

static const char *obex_hdr_str(uint8_t id)
{
	int i;

	for (i = 0; obex_hdr_table[i].str; i++) {
		if (obex_hdr_table[i].id == id)
			return obex_hdr_table[i].str;
	}

	return "Unknown";
}

/* Target/Who header values for well known OBEX based profiles. Values
 * taken from the obexd client implementations (obexd/client/pbap.c,
 * ftp.c, map.c, sync.c, bip.c), which carry the actual wire-format
 * UUIDs used in the CONNECT request/response Target and Who headers
 * (distinct from the 16-bit SDP service class UUIDs in lib/uuid.h).
 */
static const struct {
	const uint8_t uuid[16];
	uint8_t len;
	const char *str;
} obex_target_table[] = {
	{ { 0x79, 0x61, 0x35, 0xf0, 0xf0, 0xc5, 0x11, 0xd8,
	    0x09, 0x66, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66 }, 16,
					"Phonebook Access (PBAP)" },
	{ { 0xf9, 0xec, 0x7b, 0xc4, 0x95, 0x3c, 0x11, 0xd2,
	    0x98, 0x4e, 0x52, 0x54, 0x00, 0xdc, 0x9e, 0x09 }, 16,
					"File Transfer (FTP)" },
	{ { 0xbb, 0x58, 0x2b, 0x40, 0x42, 0x0c, 0x11, 0xdb,
	    0xb0, 0xde, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66 }, 16,
					"Message Access (MAP)" },
	{ { 0xbb, 0x58, 0x2b, 0x41, 0x42, 0x0c, 0x11, 0xdb,
	    0xb0, 0xde, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66 }, 16,
					"Message Notification (MNS)" },
	{ { 0x71, 0x63, 0xdd, 0x54, 0x4a, 0x7e, 0x11, 0xe2,
	    0xb4, 0x7c, 0x00, 0x50, 0xc2, 0x49, 0x00, 0x48 }, 16,
				"Basic Imaging (BIP, AVRCP Cover Art)" },
	{ { 'I', 'R', 'M', 'C', '-', 'S', 'Y', 'N', 'C' }, 9,
					"Synchronization (IrMC/SyncML)" },
	{ }
};

static const char *obex_target_str(const uint8_t *data, uint16_t len)
{
	int i;

	for (i = 0; obex_target_table[i].len; i++) {
		if (obex_target_table[i].len != len)
			continue;

		if (!memcmp(obex_target_table[i].uuid, data, len))
			return obex_target_table[i].str;
	}

	return NULL;
}

static void print_unicode_header(const char *label, const uint8_t *data,
						uint16_t len, uint8_t indent)
{
	char buf[256];
	size_t n = 0;
	uint16_t i;

	for (i = 0; i + 1 < len && n + 4 < sizeof(buf); i += 2) {
		uint16_t ch = get_be16(data + i);

		if (ch == 0x0000)
			break;

		if (ch < 0x80) {
			buf[n++] = (char) ch;
		} else if (ch < 0x800) {
			buf[n++] = 0xc0 | (ch >> 6);
			buf[n++] = 0x80 | (ch & 0x3f);
		} else {
			buf[n++] = 0xe0 | (ch >> 12);
			buf[n++] = 0x80 | ((ch >> 6) & 0x3f);
			buf[n++] = 0x80 | (ch & 0x3f);
		}
	}

	buf[n] = '\0';

	print_field("%*c%s: %s", indent, ' ', label, buf);
}

static void obex_print_apparam(const uint8_t *data, uint16_t size,
								uint8_t indent)
{
	uint16_t pos = 0;

	while (pos + 2 <= size) {
		uint8_t tag = data[pos];
		uint8_t len = data[pos + 1];

		if ((uint32_t) pos + 2 + len > size) {
			print_text(COLOR_ERROR, "invalid app parameter length");
			break;
		}

		print_field("%*cTag 0x%02x len %d", indent, ' ', tag, len);
		if (len)
			packet_hexdump(data + pos + 2, len);

		pos += 2 + len;
	}
}

static bool obex_print_headers(struct l2cap_frame *frame, uint8_t indent)
{
	while (frame->size > 0) {
		uint8_t hdr_id;
		const char *label;

		if (!l2cap_frame_get_u8(frame, &hdr_id))
			return false;

		label = obex_hdr_str(hdr_id);

		switch (hdr_id & OBEX_HDR_TYPE_MASK) {
		case OBEX_HDR_TYPE_UNICODE:
		case OBEX_HDR_TYPE_BYTES: {
			uint16_t hlen, vlen;
			const uint8_t *data;

			if (!l2cap_frame_get_be16(frame, &hlen))
				return false;

			if (hlen < 3 || hlen - 3 > frame->size) {
				print_text(COLOR_ERROR,
						"invalid header length");
				return false;
			}

			vlen = hlen - 3;
			data = frame->data;

			if ((hdr_id & OBEX_HDR_TYPE_MASK) ==
							OBEX_HDR_TYPE_UNICODE) {
				print_unicode_header(label, data, vlen,
									indent);
			} else if (hdr_id == OBEX_HDR_TARGET ||
					hdr_id == OBEX_HDR_WHO) {
				const char *profile =
					obex_target_str(data, vlen);

				if (profile) {
					print_field("%*c%s: %s", indent, ' ',
							label, profile);
				} else {
					print_field("%*c%s: [len %d]", indent,
							' ', label, vlen);
					if (vlen)
						packet_hexdump(data, vlen);
				}
			} else if (hdr_id == OBEX_HDR_TYPE ||
					hdr_id == OBEX_HDR_IMG_DESC) {
				print_field("%*c%s: %.*s", indent, ' ',
							label, vlen, data);
			} else {
				print_field("%*c%s: [len %d]", indent, ' ',
								label, vlen);

				if (hdr_id == OBEX_HDR_TIME)
					print_field("%*c%.*s", indent + 2, ' ',
								vlen, data);

				if (hdr_id == OBEX_HDR_APPARAM)
					obex_print_apparam(data, vlen,
								indent + 2);
				else if (vlen)
					packet_hexdump(data, vlen);
			}

			l2cap_frame_pull(frame, frame, vlen);
			break;
		}
		case OBEX_HDR_TYPE_UINT8: {
			uint8_t value;

			if (!l2cap_frame_get_u8(frame, &value))
				return false;

			print_field("%*c%s: %d (0x%02x)", indent, ' ', label,
							value, value);
			break;
		}
		case OBEX_HDR_TYPE_UINT32: {
			uint32_t value;

			if (!l2cap_frame_get_be32(frame, &value))
				return false;

			print_field("%*c%s: %u (0x%08x)", indent, ' ', label,
							value, value);
			break;
		}
		}
	}

	return true;
}

static bool obex_connect_fields(struct l2cap_frame *frame, uint8_t indent)
{
	uint8_t version, flags;
	uint16_t mtu;

	if (!l2cap_frame_get_u8(frame, &version) ||
			!l2cap_frame_get_u8(frame, &flags) ||
			!l2cap_frame_get_be16(frame, &mtu))
		return false;

	print_field("%*cVersion: %d.%d", indent, ' ', version >> 4,
							version & 0x0f);
	print_field("%*cFlags: 0x%02x", indent, ' ', flags);
	print_field("%*cMax Packet Length: %d", indent, ' ', mtu);

	return true;
}

static bool obex_setpath_fields(struct l2cap_frame *frame, uint8_t indent)
{
	uint8_t flags, constants;

	if (!l2cap_frame_get_u8(frame, &flags) ||
			!l2cap_frame_get_u8(frame, &constants))
		return false;

	print_field("%*cFlags: 0x%02x", indent, ' ', flags);
	print_field("%*cConstants: 0x%02x", indent, ' ', constants);

	return true;
}

void obex_packet(const struct l2cap_frame *frame, uint16_t channel)
{
	struct l2cap_frame obex_frame;
	struct l2cap_frame *f = &obex_frame;
	uint8_t opcode, code, indent = 1;
	uint16_t length, pdu_len;
	const char *opcode_str;
	const char *color;
	bool is_request = false;
	const uint8_t *trailer;
	uint16_t trailer_len;

	l2cap_frame_pull(f, frame, 0);

	if (f->size < 3)
		goto fail;

	if (!l2cap_frame_get_u8(f, &opcode) ||
			!l2cap_frame_get_be16(f, &length))
		goto fail;

	/* The 3-byte opcode+length field has just been consumed. Clamp
	 * parsing to the declared OBEX PDU boundary so trailing bytes
	 * (capture noise, malformed frames, concatenated payloads) are
	 * not decoded as if they belonged to this packet.
	 */
	if (length < 3)
		goto fail;

	pdu_len = length - 3;

	if (f->size < pdu_len)
		goto fail;

	trailer = (const uint8_t *) f->data + pdu_len;
	trailer_len = f->size - pdu_len;

	f->size = pdu_len;

	code = opcode & ~OBEX_FINAL_BIT;

	opcode_str = obex_opcode_str(code, &is_request);

	if (opcode_str)
		color = frame->in ? COLOR_MAGENTA : COLOR_BLUE;
	else {
		opcode_str = "Unknown";
		color = COLOR_WHITE_BG;
	}

	print_indent(6, color, "OBEX: ", opcode_str, COLOR_OFF,
			" (0x%2.2x) final %d len %d", code,
			(opcode & OBEX_FINAL_BIT) ? 1 : 0, length);

	if (is_request && code == OBEX_OP_CONNECT) {
		if (!obex_connect_fields(f, indent))
			goto fail;
	} else if (!is_request && obex_last_request_is(frame->index,
						frame->handle, channel,
						OBEX_OP_CONNECT)) {
		if (!obex_connect_fields(f, indent))
			goto fail;
	} else if (is_request && code == OBEX_OP_SETPATH) {
		if (!obex_setpath_fields(f, indent))
			goto fail;
	}

	if (!obex_print_headers(f, indent))
		goto fail;

	if (is_request)
		obex_set_last_request(frame->index, frame->handle, channel,
								code);

	if (trailer_len) {
		print_field("%*cTrailing data: [len %d]", indent, ' ',
							trailer_len);
		packet_hexdump(trailer, trailer_len);
	}

	return;

fail:
	print_text(COLOR_ERROR, "frame too short");
	packet_hexdump(frame->data, frame->size);
}
