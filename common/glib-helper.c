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

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sco.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include "glib-helper.h"

typedef int (*resolver_t) (int fd, bdaddr_t *src, bdaddr_t *dst);

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
	bt_io_callback_t	cb;
	resolver_t		resolver;
	gpointer		user_data;
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

static void search_context_cleanup(struct search_context *ctxt)
{
	if (ctxt->destroy)
		ctxt->destroy(ctxt->user_data);
	g_free(ctxt);
}

static void search_completed_cb(uint8_t type, uint16_t status,
			uint8_t *rsp, size_t size, void *user_data)
{
	struct search_context *ctxt = user_data;
	sdp_list_t *recs = NULL;
	int scanned, seqlen = 0;
	uint8_t dataType;
	int err = 0;

	if (status || type != SDP_SVC_SEARCH_ATTR_RSP) {
		err = -EPROTO;
		goto done;
	}

	scanned = sdp_extract_seqtype(rsp, &dataType, &seqlen);
	if (!scanned || !seqlen)
		goto done;

	rsp += scanned;
	do {
		sdp_record_t *rec;
		int recsize;

		recsize = 0;
		rec = sdp_extract_pdu(rsp, &recsize);
		if (!rec)
			break;

		if (!recsize) {
			sdp_record_free(rec);
			break;
		}

		scanned += recsize;
		rsp += recsize;

		recs = sdp_list_append(recs, rec);
	} while (scanned < size);

done:
	sdp_close(ctxt->session);
	if (ctxt->cb)
		ctxt->cb(recs, err, ctxt->user_data);
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

	s = sdp_connect(src, dst, SDP_NON_BLOCKING);
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
	struct search_context *ctxt;
	int err;

	if (!cb)
		return -EINVAL;

	err = create_search_context(&ctxt, src, dst, uuid);
	if (err < 0)
		return err;

	ctxt->cb	= cb;
	ctxt->destroy	= destroy;
	ctxt->user_data	= user_data;

	return 0;
}

int bt_discover_services(const bdaddr_t *src, const bdaddr_t *dst,
		bt_callback_t cb, void *user_data, bt_destroy_t destroy)
{
	uuid_t uuid;

	sdp_uuid16_create(&uuid, PUBLIC_BROWSE_GROUP);

	return bt_search_service(src, dst, &uuid, cb, user_data, destroy);
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
			ntohl(data0), ntohs(data1),
			ntohs(data2), ntohs(data3),
			ntohl(data4), ntohs(data5));

	return str;
}

int bt_string2uuid(uuid_t *uuid, const char *string)
{
	uint16_t data1, data2, data3, data5;
	uint32_t data0, data4;

	if (strlen(string) == 36 &&
			string[8] == '-' &&
			string[13] == '-' &&
			string[18] == '-' &&
			string[23] == '-' &&
			sscanf(string, "%08x-%04hx-%04hx-%04hx-%08x%04hx",
				&data0, &data1, &data2, &data3, &data4, &data5) == 6) {
		uint8_t val[16];

		data0 = htonl(data0);
		data1 = htons(data1);
		data2 = htons(data2);
		data3 = htons(data3);
		data4 = htonl(data4);
		data5 = htons(data5);

		memcpy(&val[0], &data0, 4);
		memcpy(&val[4], &data1, 2);
		memcpy(&val[6], &data2, 2);
		memcpy(&val[8], &data3, 2);
		memcpy(&val[10], &data4, 4);
		memcpy(&val[14], &data5, 2);

		sdp_uuid128_create(uuid, val);

		return 0;
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

	/* FIXME: eglib doesn't support g_strconcat */
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

static int rfcomm_resolver(int fd, bdaddr_t *src, bdaddr_t *dst)
{
	struct sockaddr_rc host, peer;
	socklen_t len;
	int err;

	len = sizeof(host);
	err = resolve_names(fd, (struct sockaddr *) &host,
			(struct sockaddr *) &peer, len);
	if (err < 0)
		return err;

	bacpy(src, &host.rc_bdaddr);
	bacpy(dst, &peer.rc_bdaddr);

	return 0;
}

static int l2cap_resolver(int fd, bdaddr_t *src, bdaddr_t *dst)
{
	struct sockaddr_l2 host, peer;
	socklen_t len;
	int err;

	len = sizeof(host);
	err = resolve_names(fd, (struct sockaddr *) &host,
			(struct sockaddr *) &peer, len);
	if (err < 0)
		return err;

	bacpy(src, &host.l2_bdaddr);
	bacpy(dst, &peer.l2_bdaddr);

	return 0;
}

static int sco_resolver(int fd, bdaddr_t *src, bdaddr_t *dst)
{
	struct sockaddr_sco host, peer;
	socklen_t len;
	int err;

	len = sizeof(host);
	err = resolve_names(fd, (struct sockaddr *) &host,
			(struct sockaddr *) &peer, len);
	if (err < 0)
		return err;

	bacpy(src, &host.sco_bdaddr);
	bacpy(dst, &peer.sco_bdaddr);

	return 0;
}

static gboolean listen_cb(GIOChannel *chan, GIOCondition cond,
				struct io_context *io_ctxt)
{
	int fd, err = 0;
	GIOChannel *io;
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
		err = io_ctxt->resolver(fd, &src, &dst);
		if (err < 0) {
			close(fd);
			goto drop;
		}
	}

	io = g_io_channel_unix_new(fd);
	if (!io)
		err = -ENOMEM;

	if (io_ctxt->cb)
		io_ctxt->cb(io, err, &src, &dst, io_ctxt->user_data);

	return TRUE;

drop:
	if (io_ctxt->cb)
		io_ctxt->cb(NULL, -errno, NULL, NULL, io_ctxt->user_data);

	return TRUE;
}

static int transport_listen(struct io_context *io_ctxt)
{
	int err;

	err = listen(io_ctxt->fd, 1);
	if (err < 0)
		return -errno;

	io_ctxt->io = g_io_channel_unix_new(io_ctxt->fd);
	if (!io_ctxt->io)
		return -ENOMEM;

	g_io_add_watch(io_ctxt->io, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			(GIOFunc) listen_cb, io_ctxt);

	return 0;
}

static gboolean connect_cb(GIOChannel *io, GIOCondition cond,
				struct io_context *io_ctxt)
{
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
		err = io_ctxt->resolver(io_ctxt->fd, &src, &dst);
		if (err < 0)
			goto done;
	}

	io_ctxt->io = NULL;

done:
	if (io_ctxt->cb)
		io_ctxt->cb(io, err, &src, &dst, io_ctxt->user_data);
	if (io_ctxt->io) {
		g_io_channel_close(io_ctxt->io);
		g_io_channel_unref(io_ctxt->io);
	}
	g_free(io_ctxt);

	return FALSE;
}

static int transport_connect(struct io_context *io_ctxt, struct sockaddr *addr,
				socklen_t addrlen)
{
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
			(GIOFunc) connect_cb, io_ctxt);

	return 0;
}

static int sco_connect(struct io_context *io_ctxt, const bdaddr_t *src,
				const bdaddr_t *dst)
{
	struct sockaddr_sco addr;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, src);

	err = bind(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		close(sk);
		return -errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, dst);

	err = transport_connect(io_ctxt, (struct sockaddr *) &addr,
				sizeof(addr));
	if (err < 0) {
		close(sk);
		return err;
	}

	return 0;
}

static int l2cap_bind(struct io_context *io_ctxt, const bdaddr_t *src,
			uint16_t psm, uint16_t mtu, uint32_t flags,
			struct sockaddr_l2 *addr)
{
	int err;
	struct l2cap_options l2o;

	io_ctxt->fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (io_ctxt->fd < 0)
		return -errno;

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

	memset(addr, 0, sizeof(*addr));
	addr->l2_family = AF_BLUETOOTH;
	bacpy(&addr->l2_bdaddr, src);
	addr->l2_psm = htobs(psm);

	err = bind(io_ctxt->fd, (struct sockaddr *) addr, sizeof(*addr));
	if (err < 0) {
		close(io_ctxt->fd);
		return -errno;
	}

	return 0;
}

static int l2cap_listen(struct io_context *io_ctxt, const bdaddr_t *src,
			uint16_t psm, uint16_t mtu, uint32_t flags)
{
	struct sockaddr_l2 addr;
	int err;

	err = l2cap_bind(io_ctxt, src, psm, mtu, flags, &addr);
	if (err < 0)
		return err;

	err = transport_listen(io_ctxt);
	if (err < 0) {
		close(io_ctxt->fd);
		return err;
	}

	return 0;
}

static int l2cap_connect(struct io_context *io_ctxt, const bdaddr_t *src,
				const bdaddr_t *dst, uint16_t psm,
				uint16_t mtu)
{
	struct sockaddr_l2 l2a;
	int err;

	err = l2cap_bind(io_ctxt, src, 0, mtu, 0, &l2a);
	if (err < 0)
		return err;

	memset(&l2a, 0, sizeof(l2a));
	l2a.l2_family = AF_BLUETOOTH;
	bacpy(&l2a.l2_bdaddr, dst);
	l2a.l2_psm = htobs(psm);

	err = transport_connect(io_ctxt, (struct sockaddr *) &l2a,
				sizeof(l2a));
	if (err < 0) {
		close(io_ctxt->fd);
		return err;
	}

	return 0;
}

static int rfcomm_bind(struct io_context *io_ctxt, const bdaddr_t *src,
				uint8_t channel, uint32_t flags,
				struct sockaddr_rc *addr)
{
	int err;

	io_ctxt->fd = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (io_ctxt->fd < 0)
		return -errno;

	if (flags) {
		int opt = flags;
		err = setsockopt(io_ctxt->fd, SOL_RFCOMM, RFCOMM_LM, &opt,
				sizeof(opt));
		if (err < 0) {
			close(io_ctxt->fd);
			return -errno;
		}
	}

	memset(addr, 0, sizeof(*addr));
	addr->rc_family = AF_BLUETOOTH;
	bacpy(&addr->rc_bdaddr, src);
	addr->rc_channel = channel;

	err = bind(io_ctxt->fd, (struct sockaddr *) addr, sizeof(*addr));
	if (err < 0) {
		close(io_ctxt->fd);
		return -errno;
	}

	return 0;
}

static int rfcomm_listen(struct io_context *io_ctxt, const bdaddr_t *src,
				uint8_t *channel, uint32_t flags)
{
	struct sockaddr_rc addr;
	socklen_t sa_len;
	int err;

	err = rfcomm_bind(io_ctxt, src, *channel, flags, &addr);
	if (err < 0)
		return err;

	err = transport_listen(io_ctxt);
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

	*channel = addr.rc_channel;

	return 0;
}

static int rfcomm_connect(struct io_context *io_ctxt, const bdaddr_t *src,
				const bdaddr_t *dst, uint8_t channel)
{
	struct sockaddr_rc addr;
	int err;

	err = rfcomm_bind(io_ctxt, src, 0, 0, &addr);
	if (err < 0)
		return err;

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, dst);
	addr.rc_channel = channel;

	err = transport_connect(io_ctxt, (struct sockaddr *) &addr,
				sizeof(addr));
	if (err < 0) {
		close(io_ctxt->fd);
		return err;
	}

	return 0;
}

static int create_io_context(struct io_context **io_ctxt, gpointer cb,
			gpointer resolver, gpointer user_data)
{
	*io_ctxt = g_try_malloc0(sizeof(struct search_context));
	if (!*io_ctxt)
		return -ENOMEM;

	(*io_ctxt)->cb = cb;
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
	struct io_context *io_ctxt;
	int err;

	err = create_io_context(&io_ctxt, cb, rfcomm_resolver, user_data);
	if (err < 0)
		return NULL;

	err = rfcomm_listen(io_ctxt, src, channel, flags);
	if (err < 0) {
		io_context_cleanup(io_ctxt);
		return NULL;
	}

	return io_ctxt->io;
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
	struct io_context *io_ctxt;
	int err;

	err = create_io_context(&io_ctxt, cb, rfcomm_resolver, user_data);
	if (err < 0)
		return err;

	err = rfcomm_connect(io_ctxt, src, dst, channel);
	if (err < 0) {
		io_context_cleanup(io_ctxt);
		return err;
	}

	return 0;
}

GIOChannel *bt_l2cap_listen(const bdaddr_t *src, uint16_t psm, uint16_t mtu,
			uint32_t flags, bt_io_callback_t cb, void *user_data)
{
	struct io_context *io_ctxt;
	int err;

	err = create_io_context(&io_ctxt, cb, l2cap_resolver, user_data);
	if (err < 0)
		return NULL;

	err = l2cap_listen(io_ctxt, src, psm, mtu, flags);
	if (err < 0) {
		io_context_cleanup(io_ctxt);
		return NULL;
	}

	return io_ctxt->io;
}

int bt_l2cap_connect(const bdaddr_t *src, const bdaddr_t *dst,
			uint16_t psm, uint16_t mtu, bt_io_callback_t cb,
			void *user_data)
{
	struct io_context *io_ctxt;
	int err;

	err = create_io_context(&io_ctxt, cb, l2cap_resolver, user_data);
	if (err < 0)
		return err;

	err = l2cap_connect(io_ctxt, src, dst, psm, mtu);
	if (err < 0) {
		io_context_cleanup(io_ctxt);
		return err;
	}

	return 0;
}

int bt_sco_connect(const bdaddr_t *src, const bdaddr_t *dst,
			bt_io_callback_t cb, void *user_data)
{
	struct io_context *io_ctxt;
	int err;

	err = create_io_context(&io_ctxt, cb, sco_resolver, user_data);
	if (err < 0)
		return err;

	err = sco_connect(io_ctxt, src, dst);
	if (err < 0) {
		io_context_cleanup(io_ctxt);
		return err;
	}

	return 0;
}
