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

struct io_context {
	GIOChannel		*io;
	bt_io_callback_t	cb;
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

static gboolean connect_cb(GIOChannel *io, GIOCondition cond,
				struct io_context *io_ctxt)
{
	int sk, err = 0, ret;
	socklen_t len;

	if (cond & G_IO_NVAL)
		return FALSE;

	sk = g_io_channel_unix_get_fd(io);

	len = sizeof(ret);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		err = -errno;
		goto done;
	}

	if (ret != 0) {
		err = -ret;
		goto done;
	}

	io_ctxt->io = NULL;

done:
	if (io_ctxt->cb)
		io_ctxt->cb(io, err, io_ctxt->user_data);
	if (io_ctxt->io) {
		g_io_channel_close(io_ctxt->io);
		g_io_channel_unref(io_ctxt->io);
	}
	g_free(io_ctxt);

	return FALSE;
}

static int transport_connect(struct io_context *io_ctxt, int fd,
				struct sockaddr *addr, socklen_t addrlen)
{
	int err;

	io_ctxt->io = g_io_channel_unix_new(fd);
	if (!io_ctxt->io)
		return -ENOMEM;

	err = g_io_channel_set_flags(io_ctxt->io, G_IO_FLAG_NONBLOCK, NULL);
	if (err != G_IO_STATUS_NORMAL)
		return -EPERM;

	err = connect(fd, addr, addrlen);
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

	err = transport_connect(io_ctxt, sk, (struct sockaddr *) &addr,
				sizeof(addr));
	if (err < 0) {
		close(sk);
		return err;
	}

	return 0;
}

static int l2cap_connect(struct io_context *io_ctxt, const bdaddr_t *src,
				const bdaddr_t *dst, uint16_t psm)
{
	struct sockaddr_l2 l2a;
	int sk, err;

	sk = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0)
		return -errno;

	memset(&l2a, 0, sizeof(l2a));
	l2a.l2_family = AF_BLUETOOTH;
	bacpy(&l2a.l2_bdaddr, src);

	err = bind(sk, (struct sockaddr *) &l2a, sizeof(l2a));
	if (err < 0) {
		close(sk);
		return -errno;
	}

	memset(&l2a, 0, sizeof(l2a));
	l2a.l2_family = AF_BLUETOOTH;
	bacpy(&l2a.l2_bdaddr, dst);
	l2a.l2_psm = htobs(psm);

	err = transport_connect(io_ctxt, sk, (struct sockaddr *) &l2a,
				sizeof(l2a));
	if (err < 0) {
		close(sk);
		return err;
	}

	return 0;
}

static int rfcomm_connect(struct io_context *io_ctxt, const bdaddr_t *src,
				const bdaddr_t *dst, uint8_t channel)
{
	struct sockaddr_rc addr;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, src);

	err = bind(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		close(sk);
		return -errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, dst);
	addr.rc_channel = channel;

	err = transport_connect(io_ctxt, sk, (struct sockaddr *) &addr,
				sizeof(addr));
	if (err < 0) {
		close(sk);
		return err;
	}

	return 0;
}

static int create_io_context(struct io_context **io_ctxt, bt_io_callback_t cb,
				void *user_data)
{
	*io_ctxt = g_try_malloc0(sizeof(struct search_context));
	if (!*io_ctxt)
		return -ENOMEM;

	(*io_ctxt)->cb = cb;
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

int bt_rfcomm_connect(const bdaddr_t *src, const bdaddr_t *dst,
			uint8_t channel, bt_io_callback_t cb, void *user_data)
{
	struct io_context *io_ctxt;
	int err;

	err = create_io_context(&io_ctxt, cb, user_data);
	if (err < 0)
		return err;

	err = rfcomm_connect(io_ctxt, src, dst, channel);
	if (err < 0) {
		io_context_cleanup(io_ctxt);
		return err;
	}

	return 0;
}

int bt_l2cap_connect(const bdaddr_t *src, const bdaddr_t *dst,
			uint16_t psm, bt_io_callback_t cb, void *user_data)
{
	struct io_context *io_ctxt;
	int err;

	err = create_io_context(&io_ctxt, cb, user_data);
	if (err < 0)
		return err;

	err = l2cap_connect(io_ctxt, src, dst, psm);
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

	err = create_io_context(&io_ctxt, cb, user_data);
	if (err < 0)
		return err;

	err = sco_connect(io_ctxt, src, dst);
	if (err < 0) {
		io_context_cleanup(io_ctxt);
		return err;
	}

	return 0;
}
