/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Nokia Corporation
 *  Copyright (C) 2007-2008  Instituto Nokia de Tecnologia (INdT)
 *  Copyright (C) 2007-2009  Marcel Holtmann <marcel@holtmann.org>
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
#include <openobex/obex_const.h>

#include "logging.h"
#include "obex.h"
#include "dbus.h"
#include "mimetype.h"
#include "service.h"

/* Default MTU's */
#define DEFAULT_RX_MTU 32767
#define DEFAULT_TX_MTU 32767

/* Connection ID */
static guint32 cid = 0x0000;

static GSList *sessions = NULL;

typedef struct {
	guint8  version;
	guint8  flags;
	guint16 mtu;
} __attribute__ ((packed)) obex_connect_hdr_t;

static void os_reset_session(struct obex_session *os)
{
	if (os->object) {
		os->driver->close(os->object);
		os->object = NULL;
		if (os->aborted && os->cmd == OBEX_CMD_PUT && os->current_folder) {
			gchar *path;
			path = g_build_filename(os->current_folder, os->name, NULL);
			os->driver->remove(path);
			g_free(path);
		}
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
	os->driver = NULL;
	os->aborted = FALSE;
	os->offset = 0;
	os->size = OBJECT_SIZE_DELETE;
	os->finished = 0;
}

static void os_session_mark_aborted(struct obex_session *os)
{
	/* the session was alredy cancelled/aborted */
	if (os->aborted)
		return;

	os->aborted = os->size == OBJECT_SIZE_UNKNOWN ? FALSE :
							os->size != os->offset;
}

static void obex_session_free(struct obex_session *os)
{
	sessions = g_slist_remove(sessions, os);

	os_reset_session(os);

	if (os->current_folder)
		g_free(os->current_folder);

	if (os->io)
		g_io_channel_unref(os->io);

	g_free(os);
}

/* From Imendio's GnomeVFS OBEX module (om-utils.c) */
static time_t parse_iso8610(const gchar *val, int size)
{
	time_t time, tz_offset = 0;
	struct tm tm;
	gchar *date;
	gchar tz;
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

static void cmd_connect(struct obex_session *os,
			obex_t *obex, obex_object_t *obj)
{
	obex_connect_hdr_t *nonhdr;
	obex_headerdata_t hd;
	uint8_t *buffer;
	guint hlen, newsize;
	guint16 mtu;
	guint8 hi;

	if (OBEX_ObjectGetNonHdrData(obj, &buffer) != sizeof(*nonhdr)) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		debug("Invalid OBEX CONNECT packet");
		return;
	}

	nonhdr = (obex_connect_hdr_t *) buffer;
	mtu = g_ntohs(nonhdr->mtu);
	debug("Version: 0x%02x. Flags: 0x%02x  OBEX packet length: %d",
			nonhdr->version, nonhdr->flags, mtu);
	/* Leave space for headers */
	newsize = mtu - 200;

	os->tx_mtu = newsize;

	debug("Resizing stream chunks to %d", newsize);

	/* connection id will be used to track the sessions, even for OPP */
	os->cid = ++cid;

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		if (hi != OBEX_HDR_TARGET)
			continue;

		os->service = obex_service_driver_find(os->server->drivers,
								hd.bs, hlen);
		break;
	}

	if (os->service == NULL) {
		error("Connect attempt to a non-supported target");
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);

		return;
	}

	if (os->service->connect)
		os->service->connect(obex, obj);
}

static gboolean chk_cid(obex_t *obex, obex_object_t *obj, guint32 cid)
{
	struct obex_session *os;
	obex_headerdata_t hd;
	guint hlen;
	guint8 hi;
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

static void cmd_get(struct obex_session *os, obex_t *obex, obex_object_t *obj)
{
	obex_headerdata_t hd;
	guint hlen;
	guint8 hi;

	if (!os->service) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return;
	} else if (!os->service->get) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
				OBEX_RSP_NOT_IMPLEMENTED);
		return;
	}

	g_return_if_fail(chk_cid(obex, obj, os->cid));

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		switch (hi) {
		case OBEX_HDR_NAME:
			if (os->name) {
				debug("Ignoring multiple name headers");
				break;
			}

			if (hlen == 0)
				continue;

			os->name = g_convert((const gchar *) hd.bs, hlen,
					"UTF8", "UTF16BE", NULL, NULL, NULL);
			debug("OBEX_HDR_NAME: %s", os->name);
			break;
		case OBEX_HDR_TYPE:
			if (os->type) {
				debug("Ignoring multiple type headers");
				break;
			}

			if (hlen == 0)
				continue;

			/* Ensure null termination */
			if (hd.bs[hlen - 1] != '\0')
				break;

			if (!g_utf8_validate((const gchar *) hd.bs, -1, NULL)) {
				debug("Invalid type header: %s", hd.bs);
				break;
			}

			/* FIXME: x-obex/folder-listing - type is mandatory */

			os->type = g_strndup((const gchar *) hd.bs, hlen);
			debug("OBEX_HDR_TYPE: %s", os->type);
			os->driver = obex_mime_type_driver_find(os->service->target, os->type);
			break;
		}
	}

	if (!os->driver) {
		os->driver = obex_mime_type_driver_find(os->service->target, NULL);
		if (!os->driver) {
			error("No driver found");
			OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
					OBEX_RSP_NOT_IMPLEMENTED);
			return;
		}
	}

	os->service->get(obex, obj);
}

static void cmd_setpath(struct obex_session *os,
			obex_t *obex, obex_object_t *obj)
{
	obex_headerdata_t hd;
	guint32 hlen;
	guint8 hi;

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
			debug("Ignoring multiple name headers");
			break;
		}

		/* This is because OBEX_UnicodeToChar() accesses the string
		 * even if its size is zero */
		if (hlen == 0) {
			os->name = g_strdup("");
			break;
		}

		os->name = g_convert((const gchar *) hd.bs, hlen,
				"UTF8", "UTF16BE", NULL, NULL, NULL);

		debug("Set path name: %s", os->name);
		break;
	}

	os->service->setpath(obex, obj);
}

int os_prepare_get(struct obex_session *os, gchar *filename, size_t *size)
{
	gint err;
	gpointer object;

	object = os->driver->open(filename, O_RDONLY, 0, size);
	if (object == NULL) {
		err = -errno;
		error("open(%s): %s (%d)", filename, strerror(errno), errno);
		goto fail;
	}

	os->object = object;
	os->offset = 0;

	if (*size > 0)
		os->buf = g_malloc0(os->tx_mtu);

	return 0;

fail:
	if (object)
		os->driver->close(object);
	return err;
}

static gint obex_write_stream(struct obex_session *os,
			obex_t *obex, obex_object_t *obj)
{
	obex_headerdata_t hd;
	gint32 len;
	guint8 *ptr;

	debug("obex_write_stream: name=%s type=%s tx_mtu=%d file=%p",
		os->name ? os->name : "", os->type ? os->type : "",
		os->tx_mtu, os->object);

	if (os->aborted)
		return -EPERM;

	if (os->object == NULL) {
		if (os->buf == NULL && os->finished == FALSE)
			return -EIO;

		len = MIN(os->size - os->offset, os->tx_mtu);
		ptr = os->buf + os->offset;
		goto add_header;
	}

	len = os->driver->read(os->object, os->buf, os->tx_mtu);
	if (len < 0) {
		gint err = errno;
		error("read(): %s (%d)", strerror(err), err);
		g_free(os->buf);
		os->buf = NULL;
		return -err;
	}

	ptr = os->buf;

add_header:

	hd.bs = ptr;

	if (len == 0) {
		OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_BODY, hd, 0,
					OBEX_FL_STREAM_DATAEND);
		g_free(os->buf);
		os->buf = NULL;
		return len;
	}

	os->offset += len;

	OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_BODY, hd, len,
				OBEX_FL_STREAM_DATA);

	return len;
}

gint os_prepare_put(struct obex_session *os)
{
	gchar *path;
	gint len;

	path = g_build_filename(os->current_folder, os->name, NULL);

	os->object = os->driver->open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600,
					(size_t *) &os->size);
	if (os->object == NULL) {
		error("open(%s): %s (%d)", path, strerror(errno), errno);
		g_free(path);
		return -EPERM;
	}

	g_free(path);

	if (!os->buf) {
		debug("PUT request checked, no buffered data");
		return 0;
	}

	len = 0;
	while (len < os->offset) {
		gint w;

		w = os->driver->write(os->object, os->buf + len, os->offset - len);
		if (w < 0) {
			gint err = errno;
			error("write(%s): %s (%d)", path, strerror(errno),
									errno);
			if (err == EINTR)
				continue;
			else
				return -err;
		}

		len += w;
	}

	return 0;
}

static gint obex_read_stream(struct obex_session *os, obex_t *obex,
				obex_object_t *obj)
{
	gint size;
	gint32 len = 0;
	const guint8 *buffer;

	if (os->aborted)
		return -EPERM;

	/* workaround: client didn't send the object lenght */
	if (os->size == OBJECT_SIZE_DELETE)
		os->size = OBJECT_SIZE_UNKNOWN;

	size = OBEX_ObjectReadStream(obex, obj, &buffer);
	if (size < 0) {
		error("Error on OBEX stream");
		return -EIO;
	}

	if (size > os->rx_mtu) {
		error("Received more data than RX_MAX");
		return -EIO;
	}

	if (os->object == NULL && size > 0) {
		os->buf = g_realloc(os->buf, os->offset + size);
		memcpy(os->buf + os->offset, buffer, size);
		os->offset += size;

		debug("Stored %u bytes into temporary buffer", size);

		return 0;
	}

	while (len < size) {
		gint w;

		w = os->driver->write(os->object, buffer + len, size - len);
		if (w < 0) {
			gint err = errno;
			if (err == EINTR)
				continue;
			else
				return -err;
		}

		len += w;
	}

	os->offset += len;

	return 0;
}

static gboolean check_put(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;
	obex_headerdata_t hd;
	guint hlen;
	guint8 hi;
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
				debug("Ignoring multiple name headers");
				break;
			}

			if (hlen == 0)
				continue;

			os->name = g_convert((const gchar *) hd.bs, hlen,
					"UTF8", "UTF16BE", NULL, NULL, NULL);
			debug("OBEX_HDR_NAME: %s", os->name);
			break;

		case OBEX_HDR_TYPE:
			if (os->type) {
				debug("Ignoring multiple type headers");
				break;
			}

			if (hlen == 0)
				continue;

			/* Ensure null termination */
			if (hd.bs[hlen - 1] != '\0')
				break;

			if (!g_utf8_validate((const gchar *) hd.bs, -1, NULL)) {
				debug("Invalid type header: %s", hd.bs);
				break;
			}

			os->type = g_strndup((const gchar *) hd.bs, hlen);
			debug("OBEX_HDR_TYPE: %s", os->type);
			os->driver = obex_mime_type_driver_find(os->service->target, os->type);
			break;

		case OBEX_HDR_BODY:
			if (os->size < 0)
				os->size = OBJECT_SIZE_UNKNOWN;
			break;

		case OBEX_HDR_LENGTH:
			os->size = hd.bq4;
			debug("OBEX_HDR_LENGTH: %d", os->size);
			break;
		case OBEX_HDR_TIME:
			os->time = parse_iso8610((const gchar *) hd.bs, hlen);
			break;
		}
	}

	OBEX_ObjectReParseHeaders(obex, obj);

	if (!os->driver) {
		os->driver = obex_mime_type_driver_find(os->service->target, NULL);
		if (!os->driver) {
			error("No driver found");
			OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
					OBEX_RSP_NOT_IMPLEMENTED);
			return FALSE;
		}
	}

	if (!os->service || !os->service->chkput)
		goto done;

	ret = os->service->chkput(obex, obj);
	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		OBEX_ObjectSetRsp(obj, OBEX_RSP_BAD_REQUEST,
				OBEX_RSP_BAD_REQUEST);
		return FALSE;
	case -EPERM:
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return FALSE;
	default:
		debug("Unhandled chkput error: %d", ret);
		OBEX_ObjectSetRsp(obj, OBEX_RSP_INTERNAL_SERVER_ERROR,
				OBEX_RSP_INTERNAL_SERVER_ERROR);
		return FALSE;
	}

	if (os->size == OBJECT_SIZE_DELETE || os->size == OBJECT_SIZE_UNKNOWN) {
		debug("Got a PUT without a Length");
		goto done;
	}

done:
	os->checked = TRUE;

	return TRUE;
}

static void cmd_put(struct obex_session *os, obex_t *obex, obex_object_t *obj)
{
	if (!os->service) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return;
	} else if (!os->service->put) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
				OBEX_RSP_NOT_IMPLEMENTED);
		return;
	}

	g_return_if_fail(chk_cid(obex, obj, os->cid));

	if (!os->checked) {
		if (!check_put(obex, obj))
			return;
	}

	os->service->put(obex, obj);
}

static void obex_event(obex_t *obex, obex_object_t *obj, gint mode,
					gint evt, gint cmd, gint rsp)
{
	struct obex_session *os;

	obex_debug(evt, cmd, rsp);

	os = OBEX_GetUserData(obex);

	switch (evt) {
	case OBEX_EV_PROGRESS:
		if (os->service->progress)
			os->service->progress(obex, obj);
		break;
	case OBEX_EV_ABORT:
		os->aborted = TRUE;
		if (os->service->reset)
			os->service->reset(obex);
		os_reset_session(os);
		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		break;
	case OBEX_EV_REQDONE:
		switch (cmd) {
		case OBEX_CMD_DISCONNECT:
			OBEX_TransportDisconnect(obex);
			break;
		case OBEX_CMD_PUT:
		case OBEX_CMD_GET:
		case OBEX_CMD_SETPATH:
			os_session_mark_aborted(os);
			if (os->service->reset)
				os->service->reset(obex);
			os_reset_session(os);
			break;
		default:
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
			if (os->service && os->service->put)
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
		default:
			debug("Unknown request: 0x%X", cmd);
			OBEX_ObjectSetRsp(obj,
				OBEX_RSP_NOT_IMPLEMENTED, OBEX_RSP_NOT_IMPLEMENTED);
			break;
		}
		break;
	case OBEX_EV_STREAMAVAIL:
		switch (obex_read_stream(os, obex, obj)) {
		case 0:
			break;
		case -EPERM:
			OBEX_ObjectSetRsp(obj,
				OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
			break;
		default:
			OBEX_ObjectSetRsp(obj,
				OBEX_RSP_INTERNAL_SERVER_ERROR,
				OBEX_RSP_INTERNAL_SERVER_ERROR);
			break;
		}

		break;
	case OBEX_EV_STREAMEMPTY:
		obex_write_stream(os, obex, obj);
		break;
	case OBEX_EV_LINKERR:
		break;
	case OBEX_EV_PARSEERR:
		break;
	case OBEX_EV_UNEXPECTED:
		break;

	default:
		debug("Unknown evt %d", evt);
		break;
	}
}

void server_free(struct server *server)
{
	g_free(server->folder);
	g_free(server->capability);
	g_free(server->devnode);
	g_free(server);
}

static void obex_handle_destroy(gpointer user_data)
{
	struct obex_session *os;
	obex_t *obex = user_data;

	os = OBEX_GetUserData(obex);

	if (os->service && os->service->disconnect)
		os->service->disconnect(obex);

	obex_session_free(os);

	OBEX_Cleanup(obex);
}

static gboolean tty_reinit(gpointer data)
{
	struct server *server = data;
	GSList *l;
	guint services = 0;

	for (l = server->drivers; l; l = l->next) {
		struct obex_service_driver *driver = l->data;

		services |= driver->service;
	}

	tty_init(services, server->folder, server->capability,
			server->symlinks, server->devnode);

	server_free(server);

	return FALSE;
}

static gboolean obex_handle_input(GIOChannel *io,
				GIOCondition cond, gpointer user_data)
{
	obex_t *obex = user_data;
	struct obex_session *os = OBEX_GetUserData(obex);

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		error("obex_handle_input: poll event %s%s%s",
				(cond & G_IO_HUP) ? "HUP " : "",
				(cond & G_IO_ERR) ? "ERR " : "",
				(cond & G_IO_NVAL) ? "NVAL " : "");
		goto failed;
	}

	if (OBEX_HandleInput(obex, 1) < 0) {
		error("Handle input error");
		goto failed;
	}

	return TRUE;

failed:
	if (os->server->devnode) {
		if (cond & G_IO_NVAL)
			tty_closed();
		else
			g_idle_add(tty_reinit, os->server);
	}

	return FALSE;
}

gint obex_session_start(GIOChannel *io, struct server *server)
{
	struct obex_session *os;
	obex_t *obex;
	gint ret, fd;

	os = g_new0(struct obex_session, 1);

	os->service = obex_service_driver_find(server->drivers, NULL, 0);

	os->current_folder = g_strdup(server->folder);
	os->server = server;
	os->rx_mtu = server->rx_mtu ? server->rx_mtu : DEFAULT_RX_MTU;
	os->tx_mtu = server->tx_mtu ? server->tx_mtu : DEFAULT_TX_MTU;
	os->size = OBJECT_SIZE_DELETE;

	obex = OBEX_Init(OBEX_TRANS_FD, obex_event, 0);
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

gint obex_tty_session_stop(void)
{
	GSList *l;

	for (l = sessions; l != NULL; l = l->next) {
		struct obex_session *os = l->data;

		if (os->server->devnode && os->io)
			g_io_channel_shutdown(os->io, TRUE, NULL);
	}

	return 0;
}

struct obex_session *obex_get_session(gpointer object)
{
	GSList *l;

	for (l = sessions; l; l = l->next) {
		struct obex_session *os = l->data;

		if (os->object == object)
			return os;
	}

	return NULL;
}
