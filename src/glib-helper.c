/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include "btio.h"
#include "sdpd.h"
#include "glib-helper.h"

/* Number of seconds to keep a sdp_session_t in the cache */
#define CACHE_TIMEOUT 2

struct cached_sdp_session {
	bdaddr_t src;
	bdaddr_t dst;
	sdp_session_t *session;
	guint timer;
};

static GSList *cached_sdp_sessions = NULL;

static gboolean cached_session_expired(gpointer user_data)
{
	struct cached_sdp_session *cached = user_data;

	cached_sdp_sessions = g_slist_remove(cached_sdp_sessions, cached);

	sdp_close(cached->session);

	g_free(cached);

	return FALSE;
}

static sdp_session_t *get_sdp_session(const bdaddr_t *src, const bdaddr_t *dst)
{
	GSList *l;

	for (l = cached_sdp_sessions; l != NULL; l = l->next) {
		struct cached_sdp_session *c = l->data;
		sdp_session_t *session;

		if (bacmp(&c->src, src) || bacmp(&c->dst, dst))
			continue;

		g_source_remove(c->timer);

		session = c->session;

		cached_sdp_sessions = g_slist_remove(cached_sdp_sessions, c);
		g_free(c);

		return session;
	}

	return sdp_connect(src, dst, SDP_NON_BLOCKING);
}

static void cache_sdp_session(bdaddr_t *src, bdaddr_t *dst,
						sdp_session_t *session)
{
	struct cached_sdp_session *cached;

	cached = g_new0(struct cached_sdp_session, 1);

	bacpy(&cached->src, src);
	bacpy(&cached->dst, dst);

	cached->session = session;

	cached_sdp_sessions = g_slist_append(cached_sdp_sessions, cached);

	cached->timer = g_timeout_add_seconds(CACHE_TIMEOUT,
						cached_session_expired,
						cached);
}

struct search_context {
	bdaddr_t		src;
	bdaddr_t		dst;
	sdp_session_t		*session;
	bt_callback_t		cb;
	bt_destroy_t		destroy;
	gpointer		user_data;
	uuid_t			uuid;
	guint			io_id;
};

static GSList *context_list = NULL;

static void search_context_cleanup(struct search_context *ctxt)
{
	context_list = g_slist_remove(context_list, ctxt);

	if (ctxt->destroy)
		ctxt->destroy(ctxt->user_data);

	g_free(ctxt);
}

static void search_completed_cb(uint8_t type, uint16_t status,
			uint8_t *rsp, size_t size, void *user_data)
{
	struct search_context *ctxt = user_data;
	sdp_list_t *recs = NULL;
	int scanned, seqlen = 0, bytesleft = size;
	uint8_t dataType;
	int err = 0;

	if (status || type != SDP_SVC_SEARCH_ATTR_RSP) {
		err = -EPROTO;
		goto done;
	}

	scanned = sdp_extract_seqtype(rsp, bytesleft, &dataType, &seqlen);
	if (!scanned || !seqlen)
		goto done;

	rsp += scanned;
	bytesleft -= scanned;
	do {
		sdp_record_t *rec;
		int recsize;

		recsize = 0;
		rec = sdp_extract_pdu(rsp, bytesleft, &recsize);
		if (!rec)
			break;

		if (!recsize) {
			sdp_record_free(rec);
			break;
		}

		scanned += recsize;
		rsp += recsize;
		bytesleft -= recsize;

		recs = sdp_list_append(recs, rec);
	} while (scanned < (ssize_t) size && bytesleft > 0);

done:
	cache_sdp_session(&ctxt->src, &ctxt->dst, ctxt->session);

	if (ctxt->cb)
		ctxt->cb(recs, err, ctxt->user_data);

	if (recs)
		sdp_list_free(recs, (sdp_free_func_t) sdp_record_free);

	search_context_cleanup(ctxt);
}

static gboolean search_process_cb(GIOChannel *chan, GIOCondition cond,
							gpointer user_data)
{
	struct search_context *ctxt = user_data;
	int err = 0;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		err = EIO;
		goto failed;
	}

	if (sdp_process(ctxt->session) < 0)
		goto failed;

	return TRUE;

failed:
	if (err) {
		sdp_close(ctxt->session);
		ctxt->session = NULL;

		if (ctxt->cb)
			ctxt->cb(NULL, err, ctxt->user_data);

		search_context_cleanup(ctxt);
	}

	return FALSE;
}

static gboolean connect_watch(GIOChannel *chan, GIOCondition cond,
							gpointer user_data)
{
	struct search_context *ctxt = user_data;
	sdp_list_t *search, *attrids;
	uint32_t range = 0x0000ffff;
	socklen_t len;
	int sk, err = 0;

	sk = g_io_channel_unix_get_fd(chan);
	ctxt->io_id = 0;

	len = sizeof(err);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
		err = errno;
		goto failed;
	}

	if (err != 0)
		goto failed;

	if (sdp_set_notify(ctxt->session, search_completed_cb, ctxt) < 0) {
		err = EIO;
		goto failed;
	}

	search = sdp_list_append(NULL, &ctxt->uuid);
	attrids = sdp_list_append(NULL, &range);
	if (sdp_service_search_attr_async(ctxt->session,
				search, SDP_ATTR_REQ_RANGE, attrids) < 0) {
		sdp_list_free(attrids, NULL);
		sdp_list_free(search, NULL);
		err = EIO;
		goto failed;
	}

	sdp_list_free(attrids, NULL);
	sdp_list_free(search, NULL);

	/* Set callback responsible for update the internal SDP transaction */
	ctxt->io_id = g_io_add_watch(chan,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				search_process_cb, ctxt);
	return FALSE;

failed:
	sdp_close(ctxt->session);
	ctxt->session = NULL;

	if (ctxt->cb)
		ctxt->cb(NULL, -err, ctxt->user_data);

	search_context_cleanup(ctxt);

	return FALSE;
}

static int create_search_context(struct search_context **ctxt,
					const bdaddr_t *src,
					const bdaddr_t *dst,
					uuid_t *uuid)
{
	sdp_session_t *s;
	GIOChannel *chan;

	if (!ctxt)
		return -EINVAL;

	s = get_sdp_session(src, dst);
	if (!s)
		return -errno;

	*ctxt = g_try_malloc0(sizeof(struct search_context));
	if (!*ctxt) {
		sdp_close(s);
		return -ENOMEM;
	}

	bacpy(&(*ctxt)->src, src);
	bacpy(&(*ctxt)->dst, dst);
	(*ctxt)->session = s;
	(*ctxt)->uuid = *uuid;

	chan = g_io_channel_unix_new(sdp_get_socket(s));
	(*ctxt)->io_id = g_io_add_watch(chan,
				G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				connect_watch, *ctxt);
	g_io_channel_unref(chan);

	return 0;
}

int bt_search_service(const bdaddr_t *src, const bdaddr_t *dst,
			uuid_t *uuid, bt_callback_t cb, void *user_data,
			bt_destroy_t destroy)
{
	struct search_context *ctxt = NULL;
	int err;

	if (!cb)
		return -EINVAL;

	err = create_search_context(&ctxt, src, dst, uuid);
	if (err < 0)
		return err;

	ctxt->cb	= cb;
	ctxt->destroy	= destroy;
	ctxt->user_data	= user_data;

	context_list = g_slist_append(context_list, ctxt);

	return 0;
}

static gint find_by_bdaddr(gconstpointer data, gconstpointer user_data)
{
	const struct search_context *ctxt = data, *search = user_data;

	return (bacmp(&ctxt->dst, &search->dst) &&
					bacmp(&ctxt->src, &search->src));
}

int bt_cancel_discovery(const bdaddr_t *src, const bdaddr_t *dst)
{
	struct search_context match, *ctxt;
	GSList *l;

	memset(&match, 0, sizeof(match));
	bacpy(&match.src, src);
	bacpy(&match.dst, dst);

	/* Ongoing SDP Discovery */
	l = g_slist_find_custom(context_list, &match, find_by_bdaddr);
	if (l == NULL)
		return -ENOENT;

	ctxt = l->data;

	if (!ctxt->session)
		return -ENOTCONN;

	if (ctxt->io_id)
		g_source_remove(ctxt->io_id);

	if (ctxt->session)
		sdp_close(ctxt->session);

	search_context_cleanup(ctxt);

	return 0;
}

char *bt_uuid2string(uuid_t *uuid)
{
	gchar *str;
	uuid_t uuid128;
	unsigned int data0;
	unsigned short data1;
	unsigned short data2;
	unsigned short data3;
	unsigned int data4;
	unsigned short data5;

	if (!uuid)
		return NULL;

	switch (uuid->type) {
	case SDP_UUID16:
		sdp_uuid16_to_uuid128(&uuid128, uuid);
		break;
	case SDP_UUID32:
		sdp_uuid32_to_uuid128(&uuid128, uuid);
		break;
	case SDP_UUID128:
		memcpy(&uuid128, uuid, sizeof(uuid_t));
		break;
	default:
		/* Type of UUID unknown */
		return NULL;
	}

	memcpy(&data0, &uuid128.value.uuid128.data[0], 4);
	memcpy(&data1, &uuid128.value.uuid128.data[4], 2);
	memcpy(&data2, &uuid128.value.uuid128.data[6], 2);
	memcpy(&data3, &uuid128.value.uuid128.data[8], 2);
	memcpy(&data4, &uuid128.value.uuid128.data[10], 4);
	memcpy(&data5, &uuid128.value.uuid128.data[14], 2);

	str = g_try_malloc0(MAX_LEN_UUID_STR);
	if (!str)
		return NULL;

	sprintf(str, "%.8x-%.4x-%.4x-%.4x-%.8x%.4x",
			g_ntohl(data0), g_ntohs(data1),
			g_ntohs(data2), g_ntohs(data3),
			g_ntohl(data4), g_ntohs(data5));

	return str;
}

static struct {
	const char	*name;
	uint16_t	class;
} bt_services[] = {
	{ "vcp",	VIDEO_CONF_SVCLASS_ID		},
	{ "pbap",	PBAP_SVCLASS_ID			},
	{ "sap",	SAP_SVCLASS_ID			},
	{ "ftp",	OBEX_FILETRANS_SVCLASS_ID	},
	{ "bpp",	BASIC_PRINTING_SVCLASS_ID	},
	{ "bip",	IMAGING_SVCLASS_ID		},
	{ "synch",	IRMC_SYNC_SVCLASS_ID		},
	{ "dun",	DIALUP_NET_SVCLASS_ID		},
	{ "opp",	OBEX_OBJPUSH_SVCLASS_ID		},
	{ "fax",	FAX_SVCLASS_ID			},
	{ "spp",	SERIAL_PORT_SVCLASS_ID		},
	{ "hsp",	HEADSET_SVCLASS_ID		},
	{ "hfp",	HANDSFREE_SVCLASS_ID		},
	{ }
};

static uint16_t name2class(const char *pattern)
{
	int i;

	for (i = 0; bt_services[i].name; i++) {
		if (strcasecmp(bt_services[i].name, pattern) == 0)
			return bt_services[i].class;
	}

	return 0;
}

static inline gboolean is_uuid128(const char *string)
{
	return (strlen(string) == 36 &&
			string[8] == '-' &&
			string[13] == '-' &&
			string[18] == '-' &&
			string[23] == '-');
}

static int string2uuid16(uuid_t *uuid, const char *string)
{
	int length = strlen(string);
	char *endptr = NULL;
	uint16_t u16;

	if (length != 4 && length != 6)
		return -EINVAL;

	u16 = strtol(string, &endptr, 16);
	if (endptr && *endptr == '\0') {
		sdp_uuid16_create(uuid, u16);
		return 0;
	}

	return -EINVAL;
}

char *bt_name2string(const char *pattern)
{
	uuid_t uuid;
	uint16_t uuid16;
	int i;

	/* UUID 128 string format */
	if (is_uuid128(pattern))
		return g_strdup(pattern);

	/* Friendly service name format */
	uuid16 = name2class(pattern);
	if (uuid16)
		goto proceed;

	/* HEX format */
	uuid16 = strtol(pattern, NULL, 16);
	for (i = 0; bt_services[i].class; i++) {
		if (bt_services[i].class == uuid16)
			goto proceed;
	}

	return NULL;

proceed:
	sdp_uuid16_create(&uuid, uuid16);

	return bt_uuid2string(&uuid);
}

int bt_string2uuid(uuid_t *uuid, const char *string)
{
	uint32_t data0, data4;
	uint16_t data1, data2, data3, data5;

	if (is_uuid128(string) &&
			sscanf(string, "%08x-%04hx-%04hx-%04hx-%08x%04hx",
				&data0, &data1, &data2, &data3, &data4, &data5) == 6) {
		uint8_t val[16];

		data0 = g_htonl(data0);
		data1 = g_htons(data1);
		data2 = g_htons(data2);
		data3 = g_htons(data3);
		data4 = g_htonl(data4);
		data5 = g_htons(data5);

		memcpy(&val[0], &data0, 4);
		memcpy(&val[4], &data1, 2);
		memcpy(&val[6], &data2, 2);
		memcpy(&val[8], &data3, 2);
		memcpy(&val[10], &data4, 4);
		memcpy(&val[14], &data5, 2);

		sdp_uuid128_create(uuid, val);

		return 0;
	} else {
		uint16_t class = name2class(string);
		if (class) {
			sdp_uuid16_create(uuid, class);
			return 0;
		}

		return string2uuid16(uuid, string);
	}
}

gchar *bt_list2string(GSList *list)
{
	GSList *l;
	gchar *str, *tmp;

	if (!list)
		return NULL;

	str = g_strdup((const gchar *) list->data);

	for (l = list->next; l; l = l->next) {
		tmp = g_strconcat(str, " " , (const gchar *) l->data, NULL);
		g_free(str);
		str = tmp;
	}

	return str;
}

GSList *bt_string2list(const gchar *str)
{
	GSList *l = NULL;
	gchar **uuids;
	int i = 0;

	if (!str)
		return NULL;

	/* FIXME: eglib doesn't support g_strsplit */
	uuids = g_strsplit(str, " ", 0);
	if (!uuids)
		return NULL;

	while (uuids[i]) {
		l = g_slist_append(l, uuids[i]);
		i++;
	}

	g_free(uuids);

	return l;
}
