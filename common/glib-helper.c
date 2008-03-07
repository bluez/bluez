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
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include "glib-helper.h"

struct search_context {
	bdaddr_t		src;
	bdaddr_t		dst;
	sdp_session_t		*session;
	bt_callback_t		cb;
	bt_destroy_t		destroy;
	gpointer		user_data;
};

static void search_context_cleanup(struct search_context *ctxt)
{
	if (ctxt->destroy)
		ctxt->destroy(ctxt->user_data);
	sdp_close(ctxt->session);
	g_free(ctxt);
}

static void search_completed_cb(uint8_t type, uint16_t status,
			uint8_t *rsp, size_t size, void *user_data)
{
	struct search_context *ctxt = user_data;
	sdp_list_t *recs = NULL;

	/* FIXME: Extract the records */

	ctxt->cb(ctxt->user_data, recs, 0);

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
		ctxt->cb(ctxt->user_data, NULL, -err);
		search_context_cleanup(ctxt);
	}

	return FALSE;
}

static gboolean connect_watch(GIOChannel *chan, GIOCondition cond, gpointer user_data)
{
	struct search_context *ctxt = user_data;
	sdp_list_t *search, *attrids;
	uint32_t range = 0x0000ffff;
	uuid_t uuid;
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

	sdp_uuid16_create(&uuid, PUBLIC_BROWSE_GROUP);
	search = sdp_list_append(NULL, &uuid);
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
	ctxt->cb(ctxt->user_data, NULL, -err);
	search_context_cleanup(ctxt);

	return FALSE;
}

int bt_discover_services(const bdaddr_t *src, const bdaddr_t *dst,
		bt_callback_t cb, void *user_data, bt_destroy_t destroy)
{
	struct search_context *ctxt;
	sdp_session_t *s;
	GIOChannel *chan;

	if (!cb)
		return -EINVAL;

	s = sdp_connect(src, dst, SDP_NON_BLOCKING);
	if (!s)
		return -errno;

	ctxt = g_try_malloc0(sizeof(struct search_context));
	if (!ctxt) {
		sdp_close(s);
		return -ENOMEM;
	}

	bacpy(&ctxt->src, src);
	bacpy(&ctxt->dst, dst);
	ctxt->session	= s;
	ctxt->cb	= cb;
	ctxt->destroy	= destroy;
	ctxt->user_data	= user_data;

	chan = g_io_channel_unix_new(sdp_get_socket(s));
	g_io_add_watch(chan, G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			connect_watch, ctxt);
	g_io_channel_unref(chan);

	return 0;
}
