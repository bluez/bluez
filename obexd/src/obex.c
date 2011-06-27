/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Nokia Corporation
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>

#include <glib.h>

#include <openobex/obex.h>

#include "log.h"
#include "obex.h"
#include "obex-priv.h"
#include "server.h"
#include "dbus.h"
#include "mimetype.h"
#include "service.h"
#include "transport.h"
#include "btio.h"

#ifndef OBEX_CMD_ACTION
#define OBEX_CMD_ACTION 0x06
#define OBEX_HDR_ACTION_ID 0x94
#define OBEX_HDR_DESTNAME 0x15
#define OBEX_HDR_PERMISSIONS 0xD6
#endif /* OBEX_CMD_ACTION */

/* Default MTU's */
#define DEFAULT_RX_MTU 32767
#define DEFAULT_TX_MTU 32767

/* Challenge request */
#define NONCE_TAG 0x00
#define OPTIONS_TAG 0x01 /* Optional */
#define REALM_TAG 0x02 /* Optional */

#define NONCE_LEN 16

/* Challenge response */
#define DIGEST_TAG 0x00
#define USER_ID_TAG 0x01 /* Optional */
#define DIGEST_NONCE_TAG 0x02 /* Optional */

/* Connection ID */
static uint32_t cid = 0x0000;

static GSList *sessions = NULL;

typedef struct {
	uint8_t  version;
	uint8_t  flags;
	uint16_t mtu;
} __attribute__ ((packed)) obex_connect_hdr_t;

struct auth_header {
	uint8_t tag;
	uint8_t len;
	uint8_t val[0];
} __attribute__ ((packed));

static struct {
	int evt;
	const char *name;
} obex_event[] = {
	/* Progress has been made */
	{ OBEX_EV_PROGRESS,	"PROGRESS"	},
	/* An incoming request is about to come */
	{ OBEX_EV_REQHINT,	"REQHINT"	},
	/* An incoming request has arrived */
	{ OBEX_EV_REQ,		"REQ"		},
	/* Request has finished */
	{ OBEX_EV_REQDONE,	"REQDONE"	},
	/* Link has been disconnected */
	{ OBEX_EV_LINKERR,	"LINKERR"	},
	/* Malformed data encountered */
	{ OBEX_EV_PARSEERR,	"PARSEERR"	},
	/* Connection accepted */
	{ OBEX_EV_ACCEPTHINT,	"ACCEPTHINT"	},
	/* Request was aborted */
	{ OBEX_EV_ABORT,	"ABORT"		},
	/* Need to feed more data when sending a stream */
	{ OBEX_EV_STREAMEMPTY,	"STREAMEMPTY"	},
	/* Time to pick up data when receiving a stream */
	{ OBEX_EV_STREAMAVAIL,	"STREAMAVAIL"	},
	/* Unexpected data, not fatal */
	{ OBEX_EV_UNEXPECTED,	"UNEXPECTED"	},
	/* First packet of an incoming request has been parsed */
	{ OBEX_EV_REQCHECK,	"REQCHECK"	},
	{ 0xFF,			NULL		},
};

/* Possible commands */
static struct {
	int cmd;
	const char *name;
} obex_command[] = {
	{ OBEX_CMD_CONNECT,	"CONNECT"	},
	{ OBEX_CMD_DISCONNECT,	"DISCONNECT"	},
	{ OBEX_CMD_PUT,		"PUT"		},
	{ OBEX_CMD_GET,		"GET"		},
	{ OBEX_CMD_SETPATH,	"SETPATH"	},
	{ OBEX_CMD_SESSION,	"SESSION"	},
	{ OBEX_CMD_ABORT,	"ABORT"		},
	{ OBEX_CMD_ACTION,	"ACTION"	},
	{ OBEX_FINAL,		"FINAL"		},
	{ 0xFF,			NULL		},
};

/* Possible Response */
static struct {
	int rsp;
	const char *name;
} obex_response[] = {
	{ OBEX_RSP_CONTINUE,			"CONTINUE"		},
	{ OBEX_RSP_SWITCH_PRO,			"SWITCH_PRO"		},
	{ OBEX_RSP_SUCCESS,			"SUCCESS"		},
	{ OBEX_RSP_CREATED,			"CREATED"		},
	{ OBEX_RSP_ACCEPTED,			"ACCEPTED"		},
	{ OBEX_RSP_NON_AUTHORITATIVE,		"NON_AUTHORITATIVE"	},
	{ OBEX_RSP_NO_CONTENT,			"NO_CONTENT"		},
	{ OBEX_RSP_RESET_CONTENT,		"RESET_CONTENT"		},
	{ OBEX_RSP_PARTIAL_CONTENT,		"PARTIAL_CONTENT"	},
	{ OBEX_RSP_MULTIPLE_CHOICES,		"MULTIPLE_CHOICES"	},
	{ OBEX_RSP_MOVED_PERMANENTLY,		"MOVED_PERMANENTLY"	},
	{ OBEX_RSP_MOVED_TEMPORARILY,		"MOVED_TEMPORARILY"	},
	{ OBEX_RSP_SEE_OTHER,			"SEE_OTHER"		},
	{ OBEX_RSP_NOT_MODIFIED,		"NOT_MODIFIED"		},
	{ OBEX_RSP_USE_PROXY,			"USE_PROXY"		},
	{ OBEX_RSP_BAD_REQUEST,			"BAD_REQUEST"		},
	{ OBEX_RSP_UNAUTHORIZED,		"UNAUTHORIZED"		},
	{ OBEX_RSP_PAYMENT_REQUIRED,		"PAYMENT_REQUIRED"	},
	{ OBEX_RSP_FORBIDDEN,			"FORBIDDEN"		},
	{ OBEX_RSP_NOT_FOUND,			"NOT_FOUND"		},
	{ OBEX_RSP_METHOD_NOT_ALLOWED,		"METHOD_NOT_ALLOWED"	},
	{ OBEX_RSP_NOT_ACCEPTABLE,		"NOT_ACCEPTABLE"	},
	{ OBEX_RSP_PROXY_AUTH_REQUIRED,		"PROXY_AUTH_REQUIRED"	},
	{ OBEX_RSP_REQUEST_TIME_OUT,		"REQUEST_TIME_OUT"	},
	{ OBEX_RSP_CONFLICT,			"CONFLICT"		},
	{ OBEX_RSP_GONE,			"GONE"			},
	{ OBEX_RSP_LENGTH_REQUIRED,		"LENGTH_REQUIRED"	},
	{ OBEX_RSP_PRECONDITION_FAILED,		"PRECONDITION_FAILED"	},
	{ OBEX_RSP_REQ_ENTITY_TOO_LARGE,	"REQ_ENTITY_TOO_LARGE"	},
	{ OBEX_RSP_REQ_URL_TOO_LARGE,		"REQ_URL_TOO_LARGE"	},
	{ OBEX_RSP_UNSUPPORTED_MEDIA_TYPE,	"UNSUPPORTED_MEDIA_TYPE"},
	{ OBEX_RSP_INTERNAL_SERVER_ERROR,	"INTERNAL_SERVER_ERROR"	},
	{ OBEX_RSP_NOT_IMPLEMENTED,		"NOT_IMPLEMENTED"	},
	{ OBEX_RSP_BAD_GATEWAY,			"BAD_GATEWAY"		},
	{ OBEX_RSP_SERVICE_UNAVAILABLE,		"SERVICE_UNAVAILABLE"	},
	{ OBEX_RSP_GATEWAY_TIMEOUT,		"GATEWAY_TIMEOUT"	},
	{ OBEX_RSP_VERSION_NOT_SUPPORTED,	"VERSION_NOT_SUPPORTED"	},
	{ OBEX_RSP_DATABASE_FULL,		"DATABASE_FULL"		},
	{ OBEX_RSP_DATABASE_LOCKED,		"DATABASE_LOCKED"	},
	{ 0xFF,					NULL			},
};

static void print_event(int evt, int cmd, int rsp)
{
	const char *evtstr = NULL, *cmdstr = NULL, *rspstr = NULL;
	int i;
	static int lastevt, lastcmd;

	if (evt < 0)
		evt = lastevt;
	else
		lastevt = evt;

	if (cmd < 0)
		cmd = lastcmd;
	else
		lastcmd = cmd;

	for (i = 0; obex_event[i].evt != 0xFF; i++) {
		if (obex_event[i].evt != evt)
			continue;
		evtstr = obex_event[i].name;
	}

	for (i = 0; obex_command[i].cmd != 0xFF; i++) {
		if (obex_command[i].cmd != cmd)
			continue;
		cmdstr = obex_command[i].name;
	}

	for (i = 0; obex_response[i].rsp != 0xFF; i++) {
		if (obex_response[i].rsp != rsp)
			continue;
		rspstr = obex_response[i].name;
	}

	obex_debug("%s(0x%x), %s(0x%x), %s(0x%x)", evtstr, evt, cmdstr, cmd,
								rspstr, rsp);
}

static void os_set_response(obex_object_t *obj, int err)
{
	uint8_t rsp;
	uint8_t lastrsp;

	switch (err) {
	case 0:
		rsp = OBEX_RSP_CONTINUE;
		lastrsp = OBEX_RSP_SUCCESS;
		break;
	case -EPERM:
	case -EACCES:
		rsp = OBEX_RSP_FORBIDDEN;
		lastrsp = OBEX_RSP_FORBIDDEN;
		break;
	case -ENOENT:
		rsp = OBEX_RSP_NOT_FOUND;
		lastrsp = OBEX_RSP_NOT_FOUND;
		break;
	case -EBADR:
		rsp = OBEX_RSP_BAD_REQUEST;
		lastrsp = OBEX_RSP_BAD_REQUEST;
		break;
	case -EFAULT:
		rsp = OBEX_RSP_SERVICE_UNAVAILABLE;
		lastrsp = OBEX_RSP_SERVICE_UNAVAILABLE;
		break;
	case -EINVAL:
		rsp = OBEX_RSP_NOT_IMPLEMENTED;
		lastrsp = OBEX_RSP_NOT_IMPLEMENTED;
		break;
	case -ENOTEMPTY:
	case -EEXIST:
		rsp = OBEX_RSP_PRECONDITION_FAILED;
		lastrsp = OBEX_RSP_PRECONDITION_FAILED;
		break;
	default:
		rsp = OBEX_RSP_INTERNAL_SERVER_ERROR;
		lastrsp = OBEX_RSP_INTERNAL_SERVER_ERROR;
	}

	print_event(-1, -1, rsp);

	OBEX_ObjectSetRsp(obj, rsp, lastrsp);
}

static void os_session_mark_aborted(struct obex_session *os)
{
	/* the session was already cancelled/aborted or size in unknown */
	if (os->aborted || os->size == OBJECT_SIZE_UNKNOWN)
		return;

	os->aborted = (os->size != os->offset);
}

static void os_reset_session(struct obex_session *os)
{
	os_session_mark_aborted(os);
	if (os->service && os->service->reset)
		os->service->reset(os, os->service_data);

	if (os->object) {
		os->driver->set_io_watch(os->object, NULL, NULL);
		os->driver->close(os->object);
		os->object = NULL;
		os->obj = NULL;
		if (os->aborted && os->cmd == OBEX_CMD_PUT && os->path &&
				os->driver->remove)
			os->driver->remove(os->path);
	}

	if (os->name) {
		g_free(os->name);
		os->name = NULL;
	}
	if (os->type) {
		g_free(os->type);
		os->type = NULL;
	}
	if (os->buf) {
		g_free(os->buf);
		os->buf = NULL;
	}
	if (os->path) {
		g_free(os->path);
		os->path = NULL;
	}

	os->driver = NULL;
	os->aborted = FALSE;
	os->pending = 0;
	os->offset = 0;
	os->size = OBJECT_SIZE_DELETE;
	os->headers_sent = FALSE;
	os->streaming = FALSE;
}

static void obex_session_free(struct obex_session *os)
{
	sessions = g_slist_remove(sessions, os);

	if (os->io)
		g_io_channel_unref(os->io);

	g_free(os);
}

/* From Imendio's GnomeVFS OBEX module (om-utils.c) */
static time_t parse_iso8610(const char *val, int size)
{
	time_t time, tz_offset = 0;
	struct tm tm;
	char *date;
	char tz;
	int nr;

	memset(&tm, 0, sizeof(tm));
	/* According to spec the time doesn't have to be null terminated */
	date = g_strndup(val, size);
	nr = sscanf(date, "%04u%02u%02uT%02u%02u%02u%c",
			&tm.tm_year, &tm.tm_mon, &tm.tm_mday,
			&tm.tm_hour, &tm.tm_min, &tm.tm_sec,
			&tz);
	g_free(date);
	if (nr < 6) {
		/* Invalid time format */
		return -1;
	}

	tm.tm_year -= 1900;	/* Year since 1900 */
	tm.tm_mon--;		/* Months since January, values 0-11 */
	tm.tm_isdst = -1;	/* Daylight savings information not avail */

#if defined(HAVE_TM_GMTOFF)
	tz_offset = tm.tm_gmtoff;
#elif defined(HAVE_TIMEZONE)
	tz_offset = -timezone;
	if (tm.tm_isdst > 0)
		tz_offset += 3600;
#endif

	time = mktime(&tm);
	if (nr == 7) {
		/*
		 * Date/Time was in localtime (to remote device)
		 * already. Since we don't know anything about the
		 * timezone on that one we won't try to apply UTC offset
		 */
		time += tz_offset;
	}

	return time;
}

static uint8_t *extract_nonce(const uint8_t *buffer, unsigned int hlen)
{
	struct auth_header *hdr;
	uint8_t *nonce = NULL;
	uint32_t len = 0;

	while (len < hlen) {
		hdr = (void *) buffer + len;

		switch (hdr->tag) {
		case NONCE_TAG:
			if (hdr->len != NONCE_LEN)
				return NULL;

			nonce = hdr->val;
			break;
		}

		len += hdr->len + sizeof(struct auth_header);
	}

	return nonce;
}

static uint8_t *challenge_response(const uint8_t *nonce)
{
	GChecksum *md5;
	uint8_t *result;
	size_t size;

	result = g_new0(uint8_t, NONCE_LEN);

	md5 = g_checksum_new(G_CHECKSUM_MD5);
	if (md5 == NULL)
		return result;

	g_checksum_update(md5, nonce, NONCE_LEN);
	g_checksum_update(md5, (uint8_t *) ":BlueZ", 6);

	size = NONCE_LEN;
	g_checksum_get_digest(md5, result, &size);

	g_checksum_free(md5);

	return result;
}

static void cmd_connect(struct obex_session *os,
			obex_t *obex, obex_object_t *obj)
{
	obex_connect_hdr_t *nonhdr;
	obex_headerdata_t hd;
	uint8_t *buffer;
	unsigned int hlen, newsize;
	uint16_t mtu;
	uint8_t hi;
	const uint8_t *target = NULL, *who = NULL, *nonce = NULL;
	unsigned int target_size = 0, who_size = 0;
	int err;

	if (OBEX_ObjectGetNonHdrData(obj, &buffer) != sizeof(*nonhdr)) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		DBG("Invalid OBEX CONNECT packet");
		return;
	}

	nonhdr = (obex_connect_hdr_t *) buffer;
	mtu = g_ntohs(nonhdr->mtu);
	DBG("Version: 0x%02x. Flags: 0x%02x  OBEX packet length: %d",
			nonhdr->version, nonhdr->flags, mtu);
	/* Leave space for headers */
	newsize = mtu - 200;

	os->tx_mtu = newsize;

	DBG("Resizing stream chunks to %d", newsize);

	/* connection id will be used to track the sessions, even for OPP */
	os->cid = ++cid;

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		switch (hi) {
		case OBEX_HDR_WHO:
			who = hd.bs;
			who_size = hlen;
			break;
		case OBEX_HDR_TARGET:
			target = hd.bs;
			target_size = hlen;
			break;
		case OBEX_HDR_AUTHCHAL:
			if (nonce) {
				DBG("Ignoring multiple challenge headers");
				break;
			}

			nonce = extract_nonce(hd.bs, hlen);
			DBG("AUTH CHALLENGE REQUEST");
			break;
		}
	}

	os->service = obex_service_driver_find(os->server->drivers,
						target, target_size,
						who, who_size);
	if (os->service == NULL) {
		error("Connect attempt to a non-supported target");
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);

		return;
	}

	DBG("Selected driver: %s", os->service->name);

	if (!os->service->connect) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return;
	}

	os->service_data = os->service->connect(os, &err);
	if (err == 0 && os->service->target) {
		hd.bs = os->service->target;
		OBEX_ObjectAddHeader(obex, obj,
				OBEX_HDR_WHO, hd, 16,
				OBEX_FL_FIT_ONE_PACKET);
		hd.bq4 = os->cid;
		OBEX_ObjectAddHeader(obex, obj,
				OBEX_HDR_CONNECTION, hd, 4,
				OBEX_FL_FIT_ONE_PACKET);
	}

	if (err == 0 && nonce) {
		uint8_t challenge[18];
		struct auth_header *hdr = (struct auth_header *) challenge;
		uint8_t *response = challenge_response(nonce);

		hdr->tag = DIGEST_TAG;
		hdr->len = NONCE_LEN;
		memcpy(hdr->val, response, NONCE_LEN);

		g_free(response);

		hd.bs = challenge;
		OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_AUTHRESP, hd, 18, 0);
	}

	os_set_response(obj, err);
}

static gboolean chk_cid(obex_t *obex, obex_object_t *obj, uint32_t cid)
{
	struct obex_session *os;
	obex_headerdata_t hd;
	unsigned int hlen;
	uint8_t hi;
	gboolean ret = FALSE;

	os = OBEX_GetUserData(obex);

	/* Object Push doesn't provide a connection id. */
	if (os->service->service == OBEX_OPP)
		return TRUE;

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		if (hi == OBEX_HDR_CONNECTION && hlen == 4) {
			ret = (hd.bq4 == cid ? TRUE : FALSE);
			break;
		}
	}

	OBEX_ObjectReParseHeaders(obex, obj);

	if (ret == FALSE)
		OBEX_ObjectSetRsp(obj, OBEX_RSP_SERVICE_UNAVAILABLE,
				OBEX_RSP_SERVICE_UNAVAILABLE);

	return ret;
}

static int obex_read_stream(struct obex_session *os, obex_t *obex,
						obex_object_t *obj)
{
	int size;
	ssize_t len = 0;
	const uint8_t *buffer;

	DBG("name=%s type=%s rx_mtu=%d file=%p",
		os->name ? os->name : "", os->type ? os->type : "",
		os->rx_mtu, os->object);

	if (os->aborted)
		return -EPERM;

	/* workaround: client didn't send the object lenght */
	if (os->size == OBJECT_SIZE_DELETE)
		os->size = OBJECT_SIZE_UNKNOWN;

	/* If there's something to write and we are able to write it */
	if (os->pending > 0 && os->driver)
		goto write;

	size = OBEX_ObjectReadStream(obex, obj, &buffer);
	if (size < 0) {
		error("Error on OBEX stream");
		return -EIO;
	}

	if (size > os->rx_mtu) {
		error("Received more data than RX_MAX");
		return -EIO;
	}

	os->buf = g_realloc(os->buf, os->pending + size);
	memcpy(os->buf + os->pending, buffer, size);
	os->pending += size;

	/* only write if both object and driver are valid */
	if (os->object == NULL || os->driver == NULL) {
		DBG("Stored %" PRIu64 " bytes into temporary buffer",
								os->pending);
		return 0;
	}

write:
	while (os->pending > 0) {
		ssize_t w;

		w = os->driver->write(os->object, os->buf + len,
					os->pending);
		if (w < 0) {
			if (w == -EINTR)
				continue;
			else {
				memmove(os->buf, os->buf + len, os->pending);
				return w;
			}
		}

		len += w;
		os->offset += w;
		os->pending -= w;
	}

	/* Flush on EOS */
	if (os->size != OBJECT_SIZE_UNKNOWN && os->size == os->offset &&
							os->driver->flush)
		return os->driver->flush(os->object) > 0 ? -EAGAIN : 0;

	return 0;
}

static int obex_write_stream(struct obex_session *os,
			obex_t *obex, obex_object_t *obj)
{
	obex_headerdata_t hd;
	ssize_t len;
	unsigned int flags;
	uint8_t hi;

	DBG("name=%s type=%s tx_mtu=%d file=%p",
		os->name ? os->name : "", os->type ? os->type : "",
		os->tx_mtu, os->object);

	if (os->aborted)
		return -EPERM;

	if (os->object == NULL)
		return -EIO;

	len = os->driver->read(os->object, os->buf, os->tx_mtu, &hi);
	if (len < 0) {
		error("read(): %s (%zd)", strerror(-len), -len);
		if (len == -EAGAIN)
			return len;

		g_free(os->buf);
		os->buf = NULL;

		if (len == -ENOSTR)
			return 0;

		return len;
	}

	if (!os->streaming) {
		hd.bs = NULL;
		OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_BODY, hd, 0,
						OBEX_FL_STREAM_START);
		os->streaming = TRUE;
	}

	hd.bs = os->buf;

	switch (hi) {
	case OBEX_HDR_BODY:
		flags = len ? OBEX_FL_STREAM_DATA : OBEX_FL_STREAM_DATAEND;
		break;
	case OBEX_HDR_APPARAM:
		flags =  0;
		break;
	default:
		error("read(): unkown header type %u", hi);
		return -EIO;
	}

	OBEX_ObjectAddHeader(obex, obj, hi, hd, len, flags);

	if (len == 0) {
		g_free(os->buf);
		os->buf = NULL;
	}

	return 0;
}

static int obex_write(struct obex_session *os, obex_t *obex, obex_object_t *obj)
{
	obex_headerdata_t hd;
	ssize_t len;
	uint8_t hi;

	DBG("name=%s type=%s tx_mtu=%d file=%p",
		os->name ? os->name : "", os->type ? os->type : "",
		os->tx_mtu, os->object);

	if (os->aborted)
		return -EPERM;

	if (os->object == NULL)
		return -EIO;

	if (os->headers_sent)
		return obex_write_stream(os, obex, obj);

	if (!os->driver->get_next_header)
		goto skip;

	while ((len = os->driver->get_next_header(os->object, os->buf,
					os->tx_mtu, &hi)) != 0) {
		if (len < 0) {
			error("get_next_header(): %s (%zd)", strerror(-len),
								-len);

			if (len == -EAGAIN)
				return len;

			g_free(os->buf);
			os->buf = NULL;

			return len;
		}

		hd.bs = os->buf;
		OBEX_ObjectAddHeader(obex, obj, hi, hd, len, 0);
	}

skip:
	os->headers_sent = TRUE;

	return obex_write_stream(os, obex, obj);
}

static gboolean handle_async_io(void *object, int flags, int err,
						void *user_data)
{
	struct obex_session *os = user_data;
	int ret = 0;

	if (err < 0) {
		ret = err;
		goto proceed;
	}

	if (flags & (G_IO_IN | G_IO_PRI))
		ret = obex_write(os, os->obex, os->obj);
	else if ((flags & G_IO_OUT) && os->pending > 0)
		ret = obex_read_stream(os, os->obex, os->obj);

proceed:
	if (ret == -EAGAIN) {
		return TRUE;
	} else if (ret < 0) {
		os_set_response(os->obj, ret);
		OBEX_CancelRequest(os->obex, TRUE);
	} else {
		OBEX_ResumeRequest(os->obex);
	}

	return FALSE;
}

static void cmd_get(struct obex_session *os, obex_t *obex, obex_object_t *obj)
{
	obex_headerdata_t hd;
	unsigned int hlen;
	uint8_t hi;
	int err;

	if (!os->service) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return;
	} else if (!os->service->get) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
				OBEX_RSP_NOT_IMPLEMENTED);
		return;
	}

	g_return_if_fail(chk_cid(obex, obj, os->cid));

	os->headers_sent = FALSE;
	os->streaming = FALSE;

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		switch (hi) {
		case OBEX_HDR_NAME:
			if (os->name) {
				DBG("Ignoring multiple name headers");
				break;
			}

			if (hlen == 0)
				continue;

			os->name = g_convert((const char *) hd.bs, hlen,
					"UTF8", "UTF16BE", NULL, NULL, NULL);
			DBG("OBEX_HDR_NAME: %s", os->name);
			break;
		case OBEX_HDR_TYPE:
			if (os->type) {
				DBG("Ignoring multiple type headers");
				break;
			}

			if (hlen == 0)
				continue;

			/* Ensure null termination */
			if (hd.bs[hlen - 1] != '\0')
				break;

			if (!g_utf8_validate((const char *) hd.bs, -1, NULL)) {
				DBG("Invalid type header: %s", hd.bs);
				break;
			}

			/* FIXME: x-obex/folder-listing - type is mandatory */

			os->type = g_strndup((const char *) hd.bs, hlen);
			DBG("OBEX_HDR_TYPE: %s", os->type);
			os->driver = obex_mime_type_driver_find(
						os->service->target,
						os->service->target_size,
						os->type,
						os->service->who,
						os->service->who_size);
			break;
		}
	}

	if (os->type == NULL)
		os->driver = obex_mime_type_driver_find(os->service->target,
							os->service->target_size,
							NULL,
							os->service->who,
							os->service->who_size);

	if (!os->driver) {
		error("No driver found");
		OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
					OBEX_RSP_NOT_IMPLEMENTED);
		return;
	}

	err = os->service->get(os, obj, os->service_data);

	if (err < 0)
		goto done;

	if (os->size != OBJECT_SIZE_UNKNOWN && os->size < UINT32_MAX) {
		hd.bq4 = os->size;
		OBEX_ObjectAddHeader(obex, obj,
				OBEX_HDR_LENGTH, hd, 4, 0);
	}

	/* Add body header */
	hd.bs = NULL;
	if (os->size == 0) {
		OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_BODY, hd, 0,
						OBEX_FL_FIT_ONE_PACKET);
		goto done;
	}

	/* Try to write to stream and suspend the stream immediately
	 * if no data available to send. */
	err = obex_write(os, obex, obj);
	if (err == -EAGAIN) {
		OBEX_SuspendRequest(obex, obj);
		os->obj = obj;
		os->driver->set_io_watch(os->object, handle_async_io, os);
		return;
	}

done:
	os_set_response(obj, err);
}

static void cmd_setpath(struct obex_session *os,
			obex_t *obex, obex_object_t *obj)
{
	obex_headerdata_t hd;
	uint32_t hlen;
	int err;
	uint8_t hi;

	if (!os->service) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return;
	} else if (!os->service->setpath) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
				OBEX_RSP_NOT_IMPLEMENTED);
		return;
	}

	g_return_if_fail(chk_cid(obex, obj, os->cid));

	if (os->name) {
		g_free(os->name);
		os->name = NULL;
	}

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		if (hi != OBEX_HDR_NAME)
			continue;

		if (os->name) {
			DBG("Ignoring multiple name headers");
			break;
		}

		/* This is because OBEX_UnicodeToChar() accesses the string
		 * even if its size is zero */
		if (hlen == 0) {
			os->name = g_strdup("");
			break;
		}

		os->name = g_convert((const char *) hd.bs, hlen,
				"UTF8", "UTF16BE", NULL, NULL, NULL);

		DBG("Set path name: %s", os->name);
		break;
	}

	err = os->service->setpath(os, obj, os->service_data);
	os_set_response(obj, err);
}

int obex_get_stream_start(struct obex_session *os, const char *filename)
{
	int err;
	void *object;
	size_t size = OBJECT_SIZE_UNKNOWN;

	object = os->driver->open(filename, O_RDONLY, 0, os->service_data,
								&size, &err);
	if (object == NULL) {
		error("open(%s): %s (%d)", filename, strerror(-err), -err);
		return err;
	}

	os->object = object;
	os->offset = 0;
	os->size = size;

	if (size > 0)
		os->buf = g_malloc0(os->tx_mtu);

	return 0;
}

int obex_put_stream_start(struct obex_session *os, const char *filename)
{
	int err;

	os->object = os->driver->open(filename, O_WRONLY | O_CREAT | O_TRUNC,
					0600, os->service_data,
					os->size != OBJECT_SIZE_UNKNOWN ?
					(size_t *) &os->size : NULL, &err);
	if (os->object == NULL) {
		error("open(%s): %s (%d)", filename, strerror(-err), -err);
		return -EPERM;
	}

	os->path = g_strdup(filename);

	if (!os->buf) {
		DBG("PUT request checked, no buffered data");
		return 0;
	}

	if (os->pending == 0)
		return 0;

	return obex_read_stream(os, os->obex, NULL);
}

static gboolean check_put(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;
	obex_headerdata_t hd;
	unsigned int hlen;
	uint8_t hi;
	int ret;

	os = OBEX_GetUserData(obex);

	if (os->type) {
		g_free(os->type);
		os->type = NULL;
	}

	if (os->name) {
		g_free(os->name);
		os->name = NULL;
	}

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		switch (hi) {
		case OBEX_HDR_NAME:
			if (os->name) {
				DBG("Ignoring multiple name headers");
				break;
			}

			if (hlen == 0)
				continue;

			os->name = g_convert((const char *) hd.bs, hlen,
					"UTF8", "UTF16BE", NULL, NULL, NULL);
			DBG("OBEX_HDR_NAME: %s", os->name);
			break;

		case OBEX_HDR_TYPE:
			if (os->type) {
				DBG("Ignoring multiple type headers");
				break;
			}

			if (hlen == 0)
				continue;

			/* Ensure null termination */
			if (hd.bs[hlen - 1] != '\0')
				break;

			if (!g_utf8_validate((const char *) hd.bs, -1, NULL)) {
				DBG("Invalid type header: %s", hd.bs);
				break;
			}

			os->type = g_strndup((const char *) hd.bs, hlen);
			DBG("OBEX_HDR_TYPE: %s", os->type);
			os->driver = obex_mime_type_driver_find(
						os->service->target,
						os->service->target_size,
						os->type,
						os->service->who,
						os->service->who_size);
			break;

		case OBEX_HDR_BODY:
			if (os->size < 0)
				os->size = OBJECT_SIZE_UNKNOWN;
			break;

		case OBEX_HDR_LENGTH:
			os->size = hd.bq4;
			DBG("OBEX_HDR_LENGTH: %" PRIu64, os->size);
			break;
		case OBEX_HDR_TIME:
			os->time = parse_iso8610((const char *) hd.bs, hlen);
			break;
		}
	}

	OBEX_ObjectReParseHeaders(obex, obj);

	if (os->type == NULL)
		os->driver = obex_mime_type_driver_find(os->service->target,
							os->service->target_size,
							NULL,
							os->service->who,
							os->service->who_size);

	if (!os->driver) {
		error("No driver found");
		OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
					OBEX_RSP_NOT_IMPLEMENTED);
		return FALSE;
	}

	if (!os->service->chkput)
		goto done;

	ret = os->service->chkput(os, os->service_data);
	switch (ret) {
	case 0:
		break;
	case -EPERM:
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return FALSE;
	case -EBADR:
		OBEX_ObjectSetRsp(obj, OBEX_RSP_BAD_REQUEST,
					OBEX_RSP_BAD_REQUEST);
		return FALSE;
	case -EAGAIN:
		OBEX_SuspendRequest(obex, obj);
		os->obj = obj;
		os->driver->set_io_watch(os->object, handle_async_io, os);
		return TRUE;
	default:
		DBG("Unhandled chkput error: %d", ret);
		OBEX_ObjectSetRsp(obj, OBEX_RSP_INTERNAL_SERVER_ERROR,
				OBEX_RSP_INTERNAL_SERVER_ERROR);
		return FALSE;

	}

	if (os->size == OBJECT_SIZE_DELETE || os->size == OBJECT_SIZE_UNKNOWN) {
		DBG("Got a PUT without a Length");
		goto done;
	}

done:
	os->checked = TRUE;

	return TRUE;
}

static void cmd_put(struct obex_session *os, obex_t *obex, obex_object_t *obj)
{
	int err;

	if (!os->service) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return;
	}

	g_return_if_fail(chk_cid(obex, obj, os->cid));

	if (!os->checked) {
		if (!check_put(obex, obj))
			return;
	}

	if (!os->service->put) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
				OBEX_RSP_NOT_IMPLEMENTED);
		return;
	}

	err = os->service->put(os, obj, os->service_data);
	if (err < 0) {
		os_set_response(obj, err);
		return;
	}

	/* Check if there is a body and it is not empty (size > 0), otherwise
	   openobex won't notify us with OBEX_EV_STREAMAVAIL and it gonna reply
	   right away */
	if (os->size != 0)
		return;

	/* Flush immediatly since there is nothing to write so the driver
	   has a chance to do something before we reply */
	if (os->object && os->driver && os->driver->flush &&
					os->driver->flush(os->object) > 0) {
		OBEX_SuspendRequest(obex, obj);
		os->obj = obj;
		os->driver->set_io_watch(os->object, handle_async_io, os);
	}
}

static void cmd_action(struct obex_session *os, obex_t *obex,
							obex_object_t *obj)
{
	obex_headerdata_t hd;
	unsigned int hlen;
	uint8_t hi;
	int err;

	if (!os->service) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return;
	} else if (!os->service->action) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
				OBEX_RSP_NOT_IMPLEMENTED);
		return;
	}

	g_return_if_fail(chk_cid(obex, obj, os->cid));

	if (os->name) {
		g_free(os->name);
		os->name = NULL;
	}

	if (os->destname) {
		g_free(os->destname);
		os->destname = NULL;
	}

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		switch (hi) {
		case OBEX_HDR_NAME:
			if (os->name) {
				DBG("Ignoring multiple name headers");
				break;
			}

			if (hlen == 0)
				continue;

			os->name = g_convert((const char *) hd.bs, hlen,
					"UTF8", "UTF16BE", NULL, NULL, NULL);
			DBG("OBEX_HDR_NAME: %s", os->name);
			break;

		case OBEX_HDR_DESTNAME:
			if (os->destname) {
				DBG("Ignoring multiple destination headers");
				break;
			}

			if (hlen == 0)
				continue;

			os->destname = g_convert((const char *) hd.bs, hlen,
					"UTF8", "UTF16BE", NULL, NULL, NULL);
			DBG("OBEX_HDR_DESTNAME: %s", os->destname);
			break;

		case OBEX_HDR_ACTION_ID:
			if (hlen == 0)
				continue;

			os->action_id = hd.bq1;

			DBG("OBEX_HDR_ACTIONID: %u", os->action_id);
			break;

		case OBEX_HDR_PERMISSIONS:
			if (hlen == 0)
				continue;

			DBG("OBEX_HDR_PERMISSIONS: %d", hd.bq4);
			break;
		}
	}

	os->driver = obex_mime_type_driver_find(os->service->target,
						os->service->target_size,
						NULL,
						os->service->who,
						os->service->who_size);

	if (!os->driver || !os->service->action) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
				OBEX_RSP_NOT_IMPLEMENTED);
		return;
	}

	err = os->service->action(os, obj, os->service_data);
	if (err < 0) {
		os_set_response(obj, err);
		return;
	}

	return;
}

static void obex_event_cb(obex_t *obex, obex_object_t *obj, int mode,
					int evt, int cmd, int rsp)
{
	struct obex_session *os;
	int err;

	print_event(evt, cmd, rsp);

	os = OBEX_GetUserData(obex);

	switch (evt) {
	case OBEX_EV_PROGRESS:
		if (os->service && os->service->progress)
			os->service->progress(os, os->service_data);
		break;
	case OBEX_EV_ABORT:
		os->aborted = TRUE;
		os_reset_session(os);
		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		break;
	case OBEX_EV_REQDONE:
		switch (cmd) {
		case OBEX_CMD_CONNECT:
			break;
		case OBEX_CMD_DISCONNECT:
			OBEX_TransportDisconnect(obex);
			break;
		case OBEX_CMD_PUT:
		case OBEX_CMD_GET:
		case OBEX_CMD_SETPATH:
		default:
			os_reset_session(os);
			break;
		}
		break;
	case OBEX_EV_REQHINT:
		os->cmd = cmd;
		switch (cmd) {
		case OBEX_CMD_PUT:
			os->checked = FALSE;
			OBEX_ObjectReadStream(obex, obj, NULL);
		case OBEX_CMD_GET:
		case OBEX_CMD_SETPATH:
		case OBEX_CMD_CONNECT:
		case OBEX_CMD_DISCONNECT:
		case OBEX_CMD_ACTION:
			OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
					OBEX_RSP_SUCCESS);
			break;
		default:
			OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
					OBEX_RSP_NOT_IMPLEMENTED);
			break;
		}
		break;
	case OBEX_EV_REQCHECK:
		switch (cmd) {
		case OBEX_CMD_PUT:
			if (os->service)
				check_put(obex, obj);
			break;
		default:
			break;
		}
		break;
	case OBEX_EV_REQ:
		switch (cmd) {
		case OBEX_CMD_DISCONNECT:
			break;
		case OBEX_CMD_CONNECT:
			cmd_connect(os, obex, obj);
			break;
		case OBEX_CMD_SETPATH:
			cmd_setpath(os, obex, obj);
			break;
		case OBEX_CMD_GET:
			cmd_get(os, obex, obj);
			break;
		case OBEX_CMD_PUT:
			cmd_put(os, obex, obj);
			break;
		case OBEX_CMD_ACTION:
			cmd_action(os, obex, obj);
			break;
		default:
			DBG("Unknown request: 0x%X", cmd);
			OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
						OBEX_RSP_NOT_IMPLEMENTED);
			break;
		}
		break;
	case OBEX_EV_STREAMAVAIL:
		err = obex_read_stream(os, obex, obj);
		if (err == -EAGAIN) {
			OBEX_SuspendRequest(obex, obj);
			os->obj = obj;
			os->driver->set_io_watch(os->object, handle_async_io,
									os);
		} else if (err < 0)
			os_set_response(obj, err);

		break;
	case OBEX_EV_STREAMEMPTY:
		err = obex_write_stream(os, obex, obj);
		if (err == -EAGAIN) {
			OBEX_SuspendRequest(obex, obj);
			os->obj = obj;
			os->driver->set_io_watch(os->object, handle_async_io,
									os);
		} else if (err < 0)
			os_set_response(obj, err);

		break;
	case OBEX_EV_LINKERR:
		break;
	case OBEX_EV_PARSEERR:
		break;
	case OBEX_EV_UNEXPECTED:
		break;

	default:
		DBG("Unknown evt %d", evt);
		break;
	}
}

static void obex_handle_destroy(void *user_data)
{
	struct obex_session *os;
	obex_t *obex = user_data;

	DBG("");

	os = OBEX_GetUserData(obex);

	os_reset_session(os);

	if (os->service && os->service->disconnect)
		os->service->disconnect(os, os->service_data);

	obex_session_free(os);

	OBEX_Cleanup(obex);
}

static gboolean obex_handle_input(GIOChannel *io,
				GIOCondition cond, void *user_data)
{
	obex_t *obex = user_data;

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		error("obex_handle_input: poll event %s%s%s",
				(cond & G_IO_HUP) ? "HUP " : "",
				(cond & G_IO_ERR) ? "ERR " : "",
				(cond & G_IO_NVAL) ? "NVAL " : "");
		return FALSE;
	}

	if (OBEX_HandleInput(obex, 1) < 0) {
		error("Handle input error");
		return FALSE;
	}

	return TRUE;
}

int obex_session_start(GIOChannel *io, uint16_t tx_mtu, uint16_t rx_mtu,
			struct obex_server *server)
{
	struct obex_session *os;
	obex_t *obex;
	int ret, fd;

	os = g_new0(struct obex_session, 1);

	os->service = obex_service_driver_find(server->drivers, NULL,
							0, NULL, 0);
	os->server = server;
	os->rx_mtu = rx_mtu != 0 ? rx_mtu : DEFAULT_RX_MTU;
	os->tx_mtu = tx_mtu != 0 ? tx_mtu : DEFAULT_TX_MTU;
	os->size = OBJECT_SIZE_DELETE;

	obex = OBEX_Init(OBEX_TRANS_FD, obex_event_cb, 0);
	if (!obex) {
		obex_session_free(os);
		return -EIO;
	}

	OBEX_SetUserData(obex, os);
	os->obex = obex;

	OBEX_SetTransportMTU(obex, os->rx_mtu, os->tx_mtu);

	fd = g_io_channel_unix_get_fd(io);

	ret = FdOBEX_TransportSetup(obex, fd, fd, 0);
	if (ret < 0) {
		obex_session_free(os);
		OBEX_Cleanup(obex);
		return ret;
	}

	g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			obex_handle_input, obex, obex_handle_destroy);
	os->io = g_io_channel_ref(io);

	sessions = g_slist_prepend(sessions, os);

	return 0;
}

const char *obex_get_name(struct obex_session *os)
{
	return os->name;
}

const char *obex_get_destname(struct obex_session *os)
{
	return os->destname;
}

void obex_set_name(struct obex_session *os, const char *name)
{
	g_free(os->name);
	os->name = g_strdup(name);
	DBG("Name changed: %s", os->name);
}

ssize_t obex_get_size(struct obex_session *os)
{
	return os->size;
}

const char *obex_get_type(struct obex_session *os)
{
	return os->type;
}

const char *obex_get_root_folder(struct obex_session *os)
{
	return os->server->folder;
}

uint16_t obex_get_service(struct obex_session *os)
{
	return os->service->service;
}

gboolean obex_get_symlinks(struct obex_session *os)
{
	return os->server->symlinks;
}

const char *obex_get_capability_path(struct obex_session *os)
{
	return os->server->capability;
}

gboolean obex_get_auto_accept(struct obex_session *os)
{
	return os->server->auto_accept;
}

int obex_remove(struct obex_session *os, const char *path)
{
	if (os->driver == NULL)
		return -EINVAL;

	return os->driver->remove(path);
}

int obex_copy(struct obex_session *os, const char *source,
						const char *destination)
{
	if (os->driver == NULL || os->driver->copy == NULL)
		return -EINVAL;

	DBG("%s %s", source, destination);

	return os->driver->copy(source, destination);
}

int obex_move(struct obex_session *os, const char *source,
						const char *destination)
{
	if (os->driver == NULL || os->driver->move == NULL)
		return -EINVAL;

	DBG("%s %s", source, destination);

	return os->driver->move(source, destination);
}

uint8_t obex_get_action_id(struct obex_session *os)
{
	return os->action_id;
}

/* TODO: find a way to do this for tty or fix syncevolution */
char *obex_get_id(struct obex_session *os)
{
	GError *gerr = NULL;
	char address[18];
	uint8_t channel;

	bt_io_get(os->io, BT_IO_RFCOMM, &gerr,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_CHANNEL, &channel,
			BT_IO_OPT_INVALID);
	if (gerr)
		return NULL;

	return g_strdup_printf("%s+%d", address, channel);
}

ssize_t obex_aparam_read(struct obex_session *os,
		obex_object_t *obj, const uint8_t **buffer)
{
	obex_headerdata_t hd;
	uint8_t hi;
	uint32_t hlen;

	OBEX_ObjectReParseHeaders(os->obex, obj);

	while (OBEX_ObjectGetNextHeader(os->obex, obj, &hi, &hd, &hlen)) {
		if (hi == OBEX_HDR_APPARAM) {
			*buffer = hd.bs;
			return hlen;
		}
	}

	return -EBADR;
}

int obex_aparam_write(struct obex_session *os,
		obex_object_t *obj, const uint8_t *data, unsigned int size)
{
	obex_headerdata_t hd;

	hd.bs = data;

	return OBEX_ObjectAddHeader(os->obex, obj,
			OBEX_HDR_APPARAM, hd, size, 0);
}

int memncmp0(const void *a, size_t na, const void *b, size_t nb)
{
	if (na != nb)
		return na - nb;

	if (a == NULL)
		return -(a != b);

	if (b == NULL)
		return a != b;

	return memcmp(a, b, na);
}
