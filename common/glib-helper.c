/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sco.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

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

typedef int (*resolver_t) (int fd, char *src, char *dst);
typedef BtIOError (*connect_t) (BtIO *io, BtIOFunc func);
typedef BtIOError (*listen_t) (BtIO *io, BtIOFunc func);

struct hci_cmd_data {
	bt_hci_result_t		cb;
	uint16_t		handle;
	uint16_t		ocf;
	gpointer		caller_data;
};

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

int set_nonblocking(int fd)
{
	long arg;

	arg = fcntl(fd, F_GETFL);
	if (arg < 0)
		return -errno;

	/* Return if already nonblocking */
	if (arg & O_NONBLOCK)
		return 0;

	arg |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, arg) < 0)
		return -errno;

	return 0;
}

struct io_context {
	int			fd;
	GIOChannel		*io;
	BtIOFunc		func;
	bt_io_callback_t	cb;
	resolver_t		resolver;
	gpointer		user_data;
};

struct bt_io {
	char			src[18];
	char			dst[18];
	guint32			flags;
	guint8			channel;
	guint16			psm;
	guint16			mtu;
	BtIOTransport		type;
	connect_t		connect;
	listen_t		listen;
	struct io_context	*io_ctxt;
	int			refcount;
};

struct search_context {
	bdaddr_t		src;
	bdaddr_t		dst;
	sdp_session_t		*session;
	bt_callback_t		cb;
	bt_destroy_t		destroy;
	gpointer		user_data;
	uuid_t			uuid;
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
	} while (scanned < size && bytesleft > 0);

done:
	cache_sdp_session(&ctxt->src, &ctxt->dst, ctxt->session);

	if (ctxt->cb)
		ctxt->cb(recs, err, ctxt->user_data);

	if (recs)
		sdp_list_free(recs, (sdp_free_func_t) sdp_record_free);

	search_context_cleanup(ctxt);
}

static gboolean search_process_cb(GIOChannel *chan,
			GIOCondition cond, void *user_data)
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

		if (ctxt->cb)
			ctxt->cb(NULL, err, ctxt->user_data);

		search_context_cleanup(ctxt);
	}

	return FALSE;
}

static gboolean connect_watch(GIOChannel *chan, GIOCondition cond, gpointer user_data)
{
	struct search_context *ctxt = user_data;
	sdp_list_t *search, *attrids;
	uint32_t range = 0x0000ffff;
	socklen_t len;
	int sk, err = 0;

	sk = g_io_channel_unix_get_fd(chan);

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
	g_io_add_watch(chan, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			search_process_cb, ctxt);
	return FALSE;

failed:
	sdp_close(ctxt->session);

	if (ctxt->cb)
		ctxt->cb(NULL, -err, ctxt->user_data);

	search_context_cleanup(ctxt);

	return FALSE;
}

static int create_search_context(struct search_context **ctxt,
				const bdaddr_t *src, const bdaddr_t *dst,
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
	g_io_add_watch(chan, G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
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

int bt_discover_services(const bdaddr_t *src, const bdaddr_t *dst,
		bt_callback_t cb, void *user_data, bt_destroy_t destroy)
{
	uuid_t uuid;

	sdp_uuid16_create(&uuid, PUBLIC_BROWSE_GROUP);

	return bt_search_service(src, dst, &uuid, cb, user_data, destroy);
}

static int find_by_bdaddr(const void *data, const void *user_data)
{
	const struct search_context *ctxt = data, *search = user_data;

	return (bacmp(&ctxt->dst, &search->dst) &&
					bacmp(&ctxt->src, &search->src));
}

int bt_cancel_discovery(const bdaddr_t *src, const bdaddr_t *dst)
{
	struct search_context search, *ctxt;
	GSList *match;

	memset(&search, 0, sizeof(search));
	bacpy(&search.src, src);
	bacpy(&search.dst, dst);

	/* Ongoing SDP Discovery */
	match = g_slist_find_custom(context_list, &search, find_by_bdaddr);
	if (!match)
		return -ENODATA;

	ctxt = match->data;
	if (!ctxt->session)
		return -ENOTCONN;

	close(ctxt->session->sock);
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

uint16_t bt_name2class(const char *pattern)
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

char *bt_name2string(const char *pattern)
{
	uuid_t uuid;
	uint16_t uuid16;
	int i;

	/* UUID 128 string format */
	if (is_uuid128(pattern))
		return g_strdup(pattern);

	/* Friendly service name format */
	uuid16 = bt_name2class(pattern);
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
		uint16_t class = bt_name2class(string);
		if (class) {
			sdp_uuid16_create(uuid, class);
			return 0;
		}
	}

	return -1;
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

static inline int resolve_names(int fd, struct sockaddr *host,
			struct sockaddr *peer, socklen_t len)
{
	int err;
	socklen_t namelen;

	namelen = len;
	memset(host, 0, len);
	err = getsockname(fd, host, &namelen);
	if (err < 0)
		return err;

	namelen = len;
	memset(peer, 0, len);
	err = getpeername(fd, peer, &namelen);
	if (err < 0)
		return err;

	return 0;
}

static int rfcomm_resolver(int fd, char *src, char *dst)
{
	struct sockaddr_rc host, peer;
	socklen_t len;
	int err;

	len = sizeof(host);
	err = resolve_names(fd, (struct sockaddr *) &host,
			(struct sockaddr *) &peer, len);
	if (err < 0)
		return err;

	ba2str(&host.rc_bdaddr, src);
	ba2str(&peer.rc_bdaddr, dst);

	return 0;
}

static int l2cap_resolver(int fd, char *src, char *dst)
{
	struct sockaddr_l2 host, peer;
	socklen_t len;
	int err;

	len = sizeof(host);
	err = resolve_names(fd, (struct sockaddr *) &host,
			(struct sockaddr *) &peer, len);
	if (err < 0)
		return err;

	ba2str(&host.l2_bdaddr, src);
	ba2str(&peer.l2_bdaddr, dst);

	return 0;
}

static int sco_resolver(int fd, char *src, char *dst)
{
	struct sockaddr_sco host, peer;
	socklen_t len;
	int err;

	len = sizeof(host);
	err = resolve_names(fd, (struct sockaddr *) &host,
			(struct sockaddr *) &peer, len);
	if (err < 0)
		return err;

	ba2str(&host.sco_bdaddr, src);
	ba2str(&peer.sco_bdaddr, dst);

	return 0;
}

static gboolean listen_cb(GIOChannel *chan, GIOCondition cond,
		gpointer user_data)
{
	BtIO *io = user_data;
	struct io_context *io_ctxt = io->io_ctxt;
	int fd, err = 0;
	GIOChannel *gio;
	struct sockaddr addr;
	socklen_t len;
	bdaddr_t src, dst;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		g_io_channel_close(chan);
		g_io_channel_unref(chan);
		g_free(io_ctxt);
		return FALSE;
	}

	len = sizeof(addr);
	memset(&addr, 0, len);
	fd = accept(io_ctxt->fd, &addr, &len);
	if (fd < 0)
		goto drop;

	if (io_ctxt->resolver) {
		err = io_ctxt->resolver(fd, io->src, io->dst);
		if (err < 0) {
			close(fd);
			goto drop;
		}
	}

	gio = g_io_channel_unix_new(fd);
	if (!gio)
		err = -ENOMEM;

	if (io_ctxt->func)
		io_ctxt->func(io, err, gio, io_ctxt->user_data);
	if (io_ctxt->cb) {
		str2ba(io->src, &src);
		str2ba(io->dst, &dst);
		io_ctxt->cb(gio, err, &src, &dst, io_ctxt->user_data);
	}

	return TRUE;

drop:
	if (io_ctxt->func)
		io_ctxt->func(io, -errno, NULL, io_ctxt->user_data);
	if (io_ctxt->cb)
		io_ctxt->cb(NULL, err, NULL, NULL, io_ctxt->user_data);

	return TRUE;
}

static int transport_listen(BtIO *io)
{
	struct io_context *io_ctxt = io->io_ctxt;
	int err;

	err = listen(io_ctxt->fd, 5);
	if (err < 0)
		return -errno;

	io_ctxt->io = g_io_channel_unix_new(io_ctxt->fd);
	if (!io_ctxt->io)
		return -ENOMEM;

	g_io_add_watch(io_ctxt->io, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			(GIOFunc) listen_cb, io);

	return 0;
}

static gboolean connect_cb(GIOChannel *gio, GIOCondition cond,
				gpointer user_data)
{
	BtIO *io = user_data;
	struct io_context *io_ctxt = io->io_ctxt;
	int err = 0, ret;
	socklen_t len;
	bdaddr_t src, dst;

	if (cond & G_IO_NVAL)
		return FALSE;

	len = sizeof(ret);
	if (getsockopt(io_ctxt->fd, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		err = -errno;
		goto done;
	}

	if (ret != 0) {
		err = -ret;
		goto done;
	}

	if (io_ctxt->resolver) {
		err = io_ctxt->resolver(io_ctxt->fd, io->src, io->dst);
		if (err < 0)
			goto done;
	}

	io_ctxt->io = NULL;

done:
	if (io_ctxt->func)
		io_ctxt->func(io, err, gio, io_ctxt->user_data);
	if (io_ctxt->cb) {
		str2ba(io->src, &src);
		str2ba(io->dst, &dst);
		io_ctxt->cb(gio, err, &src, &dst, io_ctxt->user_data);
	}
	if (io_ctxt->io) {
		g_io_channel_close(io_ctxt->io);
		g_io_channel_unref(io_ctxt->io);
	}
	g_free(io_ctxt);

	return FALSE;
}

static int transport_connect(BtIO *io, struct sockaddr *addr,
		socklen_t addrlen)
{
	struct io_context *io_ctxt = io->io_ctxt;
	int err;

	io_ctxt->io = g_io_channel_unix_new(io_ctxt->fd);
	if (!io_ctxt->io)
		return -ENOMEM;

	err = g_io_channel_set_flags(io_ctxt->io, G_IO_FLAG_NONBLOCK, NULL);
	if (err != G_IO_STATUS_NORMAL)
		return -EPERM;

	err = connect(io_ctxt->fd, addr, addrlen);
	if (err < 0 && !(errno == EAGAIN || errno == EINPROGRESS))
		return -errno;

	g_io_add_watch(io_ctxt->io, G_IO_OUT | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			(GIOFunc) connect_cb, io);

	return 0;
}

static int sco_bind(struct io_context *io_ctxt, const char *address,
			uint16_t mtu, struct sockaddr_sco *addr)
{
	int err;
	struct sco_options sco_opt;

	io_ctxt->fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (io_ctxt->fd < 0)
		return -errno;

	memset(addr, 0, sizeof(*addr));
	addr->sco_family = AF_BLUETOOTH;
	str2ba(address, &addr->sco_bdaddr);

	err = bind(io_ctxt->fd, (struct sockaddr *) addr, sizeof(*addr));
	if (err < 0) {
		close(io_ctxt->fd);
		return -errno;
	}

	if (mtu) {
		socklen_t olen = sizeof(sco_opt);
		memset(&sco_opt, 0, olen);
		getsockopt(io_ctxt->fd, SOL_SCO, SCO_OPTIONS, &sco_opt, &olen);
		sco_opt.mtu = mtu;
		setsockopt(io_ctxt->fd, SOL_SCO, SCO_OPTIONS, &sco_opt,
				sizeof(sco_opt));
	}

	return 0;
}

static BtIOError sco_connect(BtIO *io, BtIOFunc func)
{
	struct io_context *io_ctxt = io->io_ctxt;
	struct sockaddr_sco addr;
	int err;

	io_ctxt->func = func;

	err = sco_bind(io_ctxt, io->src, 0, &addr);
	if (err < 0)
		return BT_IO_FAILED;

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	str2ba(io->dst, &addr.sco_bdaddr);

	err = transport_connect(io, (struct sockaddr *) &addr,
				sizeof(addr));
	if (err < 0) {
		close(io_ctxt->fd);
		return BT_IO_FAILED;
	}

	return BT_IO_SUCCESS;
}

static int l2cap_bind(struct io_context *io_ctxt, const char *address,
			uint16_t psm, uint16_t mtu, uint32_t flags,
			struct sockaddr_l2 *addr)
{
	int err;
	struct l2cap_options l2o;

	io_ctxt->fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (io_ctxt->fd < 0)
		return -errno;

	memset(addr, 0, sizeof(*addr));
	addr->l2_family = AF_BLUETOOTH;
	str2ba(address, &addr->l2_bdaddr);
	addr->l2_psm = htobs(psm);

	err = bind(io_ctxt->fd, (struct sockaddr *) addr, sizeof(*addr));
	if (err < 0) {
		close(io_ctxt->fd);
		return -errno;
	}

	if (mtu) {
		socklen_t olen = sizeof(l2o);
		memset(&l2o, 0, olen);
		getsockopt(io_ctxt->fd, SOL_L2CAP, L2CAP_OPTIONS, &l2o, &olen);
		l2o.imtu = l2o.omtu = mtu;
		setsockopt(io_ctxt->fd, SOL_L2CAP, L2CAP_OPTIONS, &l2o, sizeof(l2o));
	}

	if (flags) {
		int opt = flags;
		err = setsockopt(io_ctxt->fd, SOL_L2CAP, L2CAP_LM, &opt,
				sizeof(opt));
		if (err < 0) {
			close(io_ctxt->fd);
			return -errno;
		}
	}

	return 0;
}

static BtIOError l2cap_listen(BtIO *io, BtIOFunc func)
{
	struct io_context *io_ctxt = io->io_ctxt;
	struct sockaddr_l2 addr;
	BtIOError err;

	io_ctxt->func = func;

	err = l2cap_bind(io_ctxt, io->src, io->psm, io->mtu, io->flags, &addr);
	if (err < 0)
		return err;

	err = transport_listen(io);
	if (err < 0) {
		close(io_ctxt->fd);
		return err;
	}

	return BT_IO_SUCCESS;
}

static BtIOError l2cap_connect(BtIO *io, BtIOFunc func)
{
	struct io_context *io_ctxt = io->io_ctxt;
	struct sockaddr_l2 l2a;
	BtIOError err;

	io_ctxt->func = func;

	err = l2cap_bind(io_ctxt, io->src, 0, io->mtu, 0, &l2a);
	if (err < 0)
		return err;

	memset(&l2a, 0, sizeof(l2a));
	l2a.l2_family = AF_BLUETOOTH;
	str2ba(io->dst, &l2a.l2_bdaddr);
	l2a.l2_psm = htobs(io->psm);

	err = transport_connect(io, (struct sockaddr *) &l2a,
				sizeof(l2a));
	if (err < 0) {
		close(io_ctxt->fd);
		return err;
	}

	return BT_IO_SUCCESS;
}

static BtIOError rfcomm_bind(struct io_context *io_ctxt, const char *address,
				uint8_t channel, uint32_t flags,
				struct sockaddr_rc *addr)
{
	BtIOError err;

	io_ctxt->fd = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (io_ctxt->fd < 0)
		return BT_IO_FAILED;


	memset(addr, 0, sizeof(*addr));
	addr->rc_family = AF_BLUETOOTH;
	str2ba(address, &addr->rc_bdaddr);
	addr->rc_channel = channel;

	err = bind(io_ctxt->fd, (struct sockaddr *) addr, sizeof(*addr));
	if (err < 0) {
		close(io_ctxt->fd);
		return BT_IO_FAILED;
	}

	if (flags) {
		int opt = flags;
		err = setsockopt(io_ctxt->fd, SOL_RFCOMM, RFCOMM_LM, &opt,
				sizeof(opt));
		if (err < 0) {
			close(io_ctxt->fd);
			return BT_IO_FAILED;
		}
	}

	return BT_IO_SUCCESS;
}

static BtIOError rfcomm_listen(BtIO *io, BtIOFunc func)
{
	struct io_context *io_ctxt = io->io_ctxt;
	struct sockaddr_rc addr;
	socklen_t sa_len;
	BtIOError err;

	io_ctxt->func = func;

	err = rfcomm_bind(io_ctxt, io->src, io->channel, io->flags, &addr);
	if (err < 0)
		return err;

	err = transport_listen(io);
	if (err < 0) {
		close(io_ctxt->fd);
		return err;
	}

	sa_len = sizeof(struct sockaddr_rc);
	memset(&addr, 0, sizeof(addr));
	if (getsockname(io_ctxt->fd, (struct sockaddr *) &addr, &sa_len) < 0) {
		err = -errno;
		close(io_ctxt->fd);
		return err;
	}

	io->channel = addr.rc_channel;

	return BT_IO_SUCCESS;
}

static BtIOError rfcomm_connect(BtIO *io, BtIOFunc func)
{
	struct io_context *io_ctxt = io->io_ctxt;
	struct sockaddr_rc addr;
	BtIOError err;

	io_ctxt->func = func;

	err = rfcomm_bind(io_ctxt, io->src, 0, 0, &addr);
	if (err < 0)
		return err;

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	str2ba(io->dst, &addr.rc_bdaddr);
	addr.rc_channel = io->channel;

	err = transport_connect(io, (struct sockaddr *) &addr,
				sizeof(addr));
	if (err < 0) {
		close(io_ctxt->fd);
		return err;
	}

	return BT_IO_SUCCESS;
}

static BtIOError sco_listen(BtIO *io, BtIOFunc func)
{
	struct io_context *io_ctxt = io->io_ctxt;
	struct sockaddr_sco addr;
	BtIOError err;

	io_ctxt->func = func;

	err = sco_bind(io_ctxt, io->src, io->mtu, &addr);
	if (err < 0)
		return err;

	err = transport_listen(io);
	if (err < 0) {
		close(io_ctxt->fd);
		return err;
	}

	return BT_IO_SUCCESS;
}

static gboolean hci_event_watch(GIOChannel *io,
			GIOCondition cond, gpointer user_data)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *body;
	struct hci_cmd_data *cmd = user_data;
	evt_cmd_status *evt_status;
	evt_auth_complete *evt_auth;
	evt_encrypt_change *evt_enc;
	hci_event_hdr *hdr;
	set_conn_encrypt_cp cp;
	int dd;
	uint16_t ocf;
	uint8_t status = HCI_OE_POWER_OFF;

	if (cond & G_IO_NVAL) {
		cmd->cb(status, cmd->caller_data);
		return FALSE;
	}

	if (cond & (G_IO_ERR | G_IO_HUP))
		goto failed;

	dd = g_io_channel_unix_get_fd(io);

	if (read(dd, buf, sizeof(buf)) < 0)
		goto failed;

	hdr = (hci_event_hdr *) (buf + 1);
	body = buf + (1 + HCI_EVENT_HDR_SIZE);

	switch (hdr->evt) {
	case EVT_CMD_STATUS:
		evt_status = (evt_cmd_status *) body;
		ocf = cmd_opcode_ocf(evt_status->opcode);
		if (ocf != cmd->ocf)
			return TRUE;
		switch (ocf) {
		case OCF_AUTH_REQUESTED:
		case OCF_SET_CONN_ENCRYPT:
			if (evt_status->status != 0) {
				/* Baseband rejected command */
				status = evt_status->status;
				goto failed;
			}
			break;
		default:
			return TRUE;
		}
		/* Wait for the next event */
		return TRUE;
	case EVT_AUTH_COMPLETE:
		evt_auth = (evt_auth_complete *) body;
		if (evt_auth->handle != cmd->handle) {
			/* Skipping */
			return TRUE;
		}

		if (evt_auth->status != 0x00) {
			status = evt_auth->status;
			/* Abort encryption */
			goto failed;
		}

		memset(&cp, 0, sizeof(cp));
		cp.handle  = cmd->handle;
		cp.encrypt = 1;

		cmd->ocf = OCF_SET_CONN_ENCRYPT;

		if (hci_send_cmd(dd, OGF_LINK_CTL, OCF_SET_CONN_ENCRYPT,
					SET_CONN_ENCRYPT_CP_SIZE, &cp) < 0) {
			status = HCI_COMMAND_DISALLOWED;
			goto failed;
		}
		/* Wait for encrypt change event */
		return TRUE;
	case EVT_ENCRYPT_CHANGE:
		evt_enc = (evt_encrypt_change *) body;
		if (evt_enc->handle != cmd->handle)
			return TRUE;

		/* Procedure finished: reporting status */
		status = evt_enc->status;
		break;
	default:
		/* Skipping */
		return TRUE;
	}

failed:
	cmd->cb(status, cmd->caller_data);
	g_io_channel_close(io);

	return FALSE;
}

int bt_acl_encrypt(const bdaddr_t *src, const bdaddr_t *dst,
			bt_hci_result_t cb, gpointer user_data)
{
	GIOChannel *io;
	struct hci_cmd_data *cmd;
	struct hci_conn_info_req *cr;
	auth_requested_cp cp;
	struct hci_filter nf;
	int dd, dev_id, err;
	char src_addr[18];
	uint32_t link_mode;
	uint16_t handle;

	ba2str(src, src_addr);
	dev_id = hci_devid(src_addr);
	if (dev_id < 0)
		return -errno;

	dd = hci_open_dev(dev_id);
	if (dd < 0)
		return -errno;

	cr = g_malloc0(sizeof(*cr) + sizeof(struct hci_conn_info));
	cr->type = ACL_LINK;
	bacpy(&cr->bdaddr, dst);

	err = ioctl(dd, HCIGETCONNINFO, cr);
	link_mode = cr->conn_info->link_mode;
	handle = cr->conn_info->handle;
	g_free(cr);

	if (err < 0) {
		err = errno;
		goto failed;
	}

	if (link_mode & HCI_LM_ENCRYPT) {
		/* Already encrypted */
		err = EALREADY;
		goto failed;
	}

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(handle);

	if (hci_send_cmd(dd, OGF_LINK_CTL, OCF_AUTH_REQUESTED,
				AUTH_REQUESTED_CP_SIZE, &cp) < 0) {
		err = errno;
		goto failed;
	}

	cmd = g_new0(struct hci_cmd_data, 1);
	cmd->handle = handle;
	cmd->ocf = OCF_AUTH_REQUESTED;
	cmd->cb	= cb;
	cmd->caller_data = user_data;

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_CMD_STATUS, &nf);
	hci_filter_set_event(EVT_AUTH_COMPLETE, &nf);
	hci_filter_set_event(EVT_ENCRYPT_CHANGE, &nf);

	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		err = errno;
		goto failed;
	}

	io = g_io_channel_unix_new(dd);
	g_io_channel_set_close_on_unref(io, FALSE);
	g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
			G_IO_HUP | G_IO_ERR | G_IO_NVAL | G_IO_IN,
			hci_event_watch, cmd, g_free);
	g_io_channel_unref(io);

	return 0;

failed:
	close(dd);

	return -err;
}

static int create_io_context(struct io_context **io_ctxt, BtIOFunc func,
			gpointer cb, gpointer resolver, gpointer user_data)
{
	*io_ctxt = g_try_malloc0(sizeof(struct search_context));
	if (!*io_ctxt)
		return -ENOMEM;

	(*io_ctxt)->cb = cb;
	(*io_ctxt)->func = func;
	(*io_ctxt)->resolver = resolver;
	(*io_ctxt)->user_data = user_data;

	return 0;
}

static void io_context_cleanup(struct io_context *io_ctxt)
{
	if (io_ctxt->io) {
		g_io_channel_close(io_ctxt->io);
		g_io_channel_unref(io_ctxt->io);
	}
	g_free(io_ctxt);
}

GIOChannel *rfcomm_listen_internal(const bdaddr_t *src, uint8_t *channel,
			uint32_t flags, bt_io_callback_t cb, void *user_data)
{
	BtIO *io;
	BtIOError err;

	io = bt_io_create(BT_IO_RFCOMM, user_data, NULL);
	if (!io)
		return NULL;

	ba2str(src, io->src);
	io->channel = *channel;
	io->flags = flags;
	io->io_ctxt->cb = cb;
	err = bt_io_listen(io, NULL, NULL);
	if (err != BT_IO_SUCCESS) {
		bt_io_unref(io);
		return NULL;
	}

	*channel = io->channel;

	return io->io_ctxt->io;
}

GIOChannel *bt_rfcomm_listen_allocate(const bdaddr_t *src, uint8_t *channel,
			uint32_t flags, bt_io_callback_t cb, void *user_data)
{
	if (!channel)
		return NULL;

	*channel = 0;

	return rfcomm_listen_internal(src, channel, flags, cb, user_data);
}

GIOChannel *bt_rfcomm_listen(const bdaddr_t *src, uint8_t channel,
			uint32_t flags, bt_io_callback_t cb, void *user_data)
{
	if (channel < 1 || channel > 30)
		return NULL;

	return rfcomm_listen_internal(src, &channel, flags, cb, user_data);

}

int bt_rfcomm_connect(const bdaddr_t *src, const bdaddr_t *dst,
			uint8_t channel, bt_io_callback_t cb, void *user_data)
{
	BtIO *io;
	BtIOError err;

	io = bt_io_create(BT_IO_RFCOMM, user_data, NULL);
	if (!io)
		return -1;

	ba2str(src, io->src);
	ba2str(dst, io->dst);
	io->channel = channel;
	io->io_ctxt->cb = cb;
	err = bt_io_connect(io, NULL, NULL);
	if (err != BT_IO_SUCCESS) {
		bt_io_unref(io);
		return -1;
	}

	return 0;
}

GIOChannel *bt_l2cap_listen(const bdaddr_t *src, uint16_t psm, uint16_t mtu,
			uint32_t flags, bt_io_callback_t cb, void *user_data)
{
	BtIO *io;
	BtIOError err;

	io = bt_io_create(BT_IO_L2CAP, user_data, NULL);
	if (!io)
		return NULL;

	ba2str(src, io->src);
	io->psm = psm;
	io->mtu = mtu;
	io->flags = flags;
	io->io_ctxt->cb = cb;
	err = bt_io_listen(io, NULL, NULL);
	if (err != BT_IO_SUCCESS) {
		bt_io_unref(io);
		return NULL;
	}

	return io->io_ctxt->io;
}

int bt_l2cap_connect(const bdaddr_t *src, const bdaddr_t *dst,
			uint16_t psm, uint16_t mtu, bt_io_callback_t cb,
			void *user_data)
{
	BtIO *io;
	BtIOError err;

	io = bt_io_create(BT_IO_L2CAP, user_data, NULL);
	if (!io)
		return -1;

	ba2str(src, io->src);
	ba2str(dst, io->dst);
	io->psm = psm;
	io->mtu = mtu;
	io->io_ctxt->cb = cb;
	err = bt_io_connect(io, NULL, NULL);
	if (err != BT_IO_SUCCESS) {
		bt_io_unref(io);
		return -1;
	}

	return 0;
}

GIOChannel *bt_sco_listen(const bdaddr_t *src, uint16_t mtu,
				bt_io_callback_t cb, void *user_data)
{
	BtIO *io;
	BtIOError err;

	io = bt_io_create(BT_IO_SCO, user_data, NULL);
	if (!io)
		return NULL;

	ba2str(src, io->src);
	io->io_ctxt->cb = cb;
	err = bt_io_listen(io, NULL, NULL);
	if (err != BT_IO_SUCCESS) {
		bt_io_unref(io);
		return NULL;
	}

	return io->io_ctxt->io;
}


int bt_sco_connect(const bdaddr_t *src, const bdaddr_t *dst,
			bt_io_callback_t cb, void *user_data)
{
	BtIO *io;
	BtIOError err;

	io = bt_io_create(BT_IO_SCO, user_data, NULL);
	if (!io)
		return -1;

	ba2str(src, io->src);
	ba2str(dst, io->dst);
	io->io_ctxt->cb = cb;
	err = bt_io_connect(io, NULL, NULL);
	if (err != BT_IO_SUCCESS) {
		bt_io_unref(io);
		return -1;
	}

	return 0;
}

/* Experiemental bt_io API */

BtIO *bt_io_create(BtIOTransport type, gpointer user_data, GDestroyNotify notify)
{
	BtIO *io;
	int err;

	io = g_new0(BtIO, 1);
	if (!io)
		return NULL;

	io->refcount = 1;

	switch (type) {
	case BT_IO_L2CAP:
		err = create_io_context(&io->io_ctxt, NULL, NULL,
				l2cap_resolver, user_data);
		io->connect = l2cap_connect;
		io->listen = l2cap_listen;
		break;
	case BT_IO_RFCOMM:
		err = create_io_context(&io->io_ctxt, NULL, NULL,
				rfcomm_resolver, user_data);
		io->connect = rfcomm_connect;
		io->listen = rfcomm_listen;
		break;
	case BT_IO_SCO:
		err = create_io_context(&io->io_ctxt, NULL, NULL,
				sco_resolver, user_data);
		io->connect = sco_connect;
		io->listen = sco_listen;
		break;
	default:
		return NULL;
	}

	if (err < 0) {
		bt_io_unref(io);
		return NULL;
	}

	return io;
}

BtIO *bt_io_ref(BtIO *io)
{
	io->refcount++;

	return io;
}

void bt_io_unref(BtIO *io)
{
	io->refcount--;

	if (io->refcount)
		return;

	io_context_cleanup(io->io_ctxt);
	g_free(io);
}

gboolean bt_io_set_source(BtIO *io, const char *address)
{
	if (strlen(address) != sizeof(io->src))
		return FALSE;

	memcpy(io->src, address, sizeof(io->src));

	return TRUE;
}

const char *bt_io_get_source(BtIO *io)
{
	return io->src;
}

gboolean bt_io_set_destination(BtIO *io, const char *address)
{
	if (strlen(address) != sizeof(io->dst))
		return FALSE;

	memcpy(io->dst, address, sizeof(io->dst));

	return TRUE;
}

const char *bt_io_get_destination(BtIO *io)
{
	return io->dst;
}

gboolean bt_io_set_flags(BtIO *io, guint32 flags)
{
	io->flags = flags;

	return TRUE;
}

guint32 bt_io_get_flags(BtIO *io)
{
	return io->flags;
}

gboolean bt_io_set_channel(BtIO *io, guint8 channel)
{
	if (io->type != BT_IO_RFCOMM)
		return FALSE;

	io->channel = channel;

	return TRUE;
}

guint8 bt_io_get_channel(BtIO *io)
{
	return io->channel;
}

gboolean bt_io_set_psm(BtIO *io, guint16 psm)
{
	if (io->type != BT_IO_L2CAP)
		return FALSE;

	io->psm = psm;

	return TRUE;
}

guint16 bt_io_get_psm(BtIO *io)
{
	return io->psm;
}

gboolean bt_io_set_mtu(BtIO *io, guint16 mtu)
{
	io->mtu = mtu;

	return TRUE;
}

guint16 bt_io_get_mtu(BtIO *io)
{
	return io->mtu;
}

BtIOError bt_io_connect(BtIO *io, const char *uuid, BtIOFunc func)
{
	if (!io->connect)
		return BT_IO_FAILED;

	return io->connect(io, func);
}

BtIOError bt_io_listen(BtIO *io, const char *uuid, BtIOFunc func)
{
	if (!io->listen)
		return BT_IO_FAILED;

	return io->listen(io, func);
}

BtIOError bt_io_shutdown(BtIO *io)
{
	io_context_cleanup(io->io_ctxt);

	return BT_IO_SUCCESS;
}
