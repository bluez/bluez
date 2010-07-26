/*
 *
 *  MCAP for BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010 GSyC/LibreSoft, Universidad Rey Juan Carlos.
 *
 *  Authors:
 *  Santiago Carot-Nemesio <sancane at gmail.com>
 *  Jose Antonio Santos-Cadenas <santoscadenas at gmail.com>
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

#include "log.h"
#include "error.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <errno.h>

#include "btio.h"
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include "mcap.h"
#include "mcap_lib.h"
#include "mcap_internal.h"

#define MCAP_ERROR g_quark_from_static_string("mcap-error-quark")


static void default_mdl_connected_cb(struct mcap_mdl *mdl, gpointer data)
{
	DBG("MCAP Unmanaged mdl connection");
}

static void default_mdl_closed_cb(struct mcap_mdl *mdl, gpointer data)
{
	DBG("MCAP Unmanaged mdl closed");
}

static void default_mdl_deleted_cb(struct mcap_mdl *mdl, gpointer data)
{
	DBG("MCAP Unmanaged mdl deleted");
}

static void default_mdl_aborted_cb(struct mcap_mdl *mdl, gpointer data)
{
	DBG("MCAP Unmanaged mdl aborted");
}

static uint8_t default_mdl_conn_req_cb(struct mcap_mcl *mcl,
						uint8_t mdepid, uint16_t mdlid,
						uint8_t *conf, gpointer data)
{
	DBG("MCAP mdl remote connection aborted");
	/* Due to this callback isn't managed this request won't be supported */
	return MCAP_REQUEST_NOT_SUPPORTED;
}

static uint8_t default_mdl_reconn_req_cb(struct mcap_mdl *mdl,
						gpointer data)
{
	DBG("MCAP mdl remote reconnection aborted");
	/* Due to this callback isn't managed this request won't be supported */
	return MCAP_REQUEST_NOT_SUPPORTED;
}

static void set_default_cb(struct mcap_mcl *mcl)
{
	if (!mcl->cb)
		mcl->cb = g_new0(struct mcap_mdl_cb, 1);

	mcl->cb->mdl_connected = default_mdl_connected_cb;
	mcl->cb->mdl_closed = default_mdl_closed_cb;
	mcl->cb->mdl_deleted = default_mdl_deleted_cb;
	mcl->cb->mdl_aborted = default_mdl_aborted_cb;
	mcl->cb->mdl_conn_req = default_mdl_conn_req_cb;
	mcl->cb->mdl_reconn_req = default_mdl_reconn_req_cb;
}

static struct mcap_mcl *find_mcl(GSList *list, const bdaddr_t *addr)
{
	GSList *l;
	struct mcap_mcl *mcl;

	for (l = list; l; l = l->next) {
		mcl = l->data;

		if (!bacmp(&mcl->addr, addr))
			return mcl;
	}

	return NULL;
}

static void mcap_mcl_shutdown(struct mcap_mcl *mcl)
{
	/* TODO: implement mcap_mcl_shutdown */
}

static void mcap_mcl_release(struct mcap_mcl *mcl)
{
	/* TODO: implement mcap_mcl_release */
}

static void mcap_mcl_check_del(struct mcap_mcl *mcl)
{
	if (mcl->ctrl & MCAP_CTRL_CACHED)
		mcap_mcl_shutdown(mcl);
	else
		mcap_mcl_unref(mcl);
}

static void mcap_uncache_mcl(struct mcap_mcl *mcl)
{
	if (!(mcl->ctrl & MCAP_CTRL_CACHED))
		return;

	DBG("Got MCL from cache");

	mcl->ms->cached = g_slist_remove(mcl->ms->cached, mcl);
	mcl->ms->mcls = g_slist_prepend(mcl->ms->mcls, mcl);
	mcl->ctrl &= ~MCAP_CTRL_CACHED;
	mcl->ctrl &= ~MCAP_CTRL_FREE;
}

struct mcap_mcl *mcap_mcl_ref(struct mcap_mcl *mcl)
{
	mcl->ref++;

	DBG("mcap_mcl_ref(%p): ref=%d", mcl, mcl->ref);

	return mcl;
}

void mcap_mcl_unref(struct mcap_mcl *mcl)
{
	mcl->ref--;

	DBG("mcap_mcl_unref(%p): ref=%d", mcl, mcl->ref);

	if ((mcl->ctrl & MCAP_CTRL_CACHED) && (mcl->ref < 2)) {
		/* Free space in cache memory due any other profile has a local
		 * copy of current MCL stored in cache */
		DBG("Remove from cache (%p): ref=%d", mcl, mcl->ref);
		mcl->ms->cached = g_slist_remove(mcl->ms->cached, mcl);
		mcap_mcl_release(mcl);
		return;
	}

	if (mcl->ref > 0)
		return;

	mcap_mcl_release(mcl);
}

static gboolean mcl_control_cb(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	/* TODO: Create mcl_control_cb */
	return FALSE;
}
static void confirm_dc_event_cb(GIOChannel *chan, gpointer user_data)
{
	/* TODO: implement confirm_dc_event_cb */
}

static void connect_mcl_event_cb(GIOChannel *chan, GError *err,
							gpointer user_data)
{
	struct mcap_mcl *mcl = user_data;
	gboolean reconn;

	if (err) {
		mcap_mcl_check_del(mcl);
		return;
	}

	mcl->state = MCL_CONNECTED;
	mcl->role = MCL_ACCEPTOR;
	mcl->req = MCL_AVAILABLE;
	mcl->cc = g_io_channel_ref(chan);
	mcl->ctrl |= MCAP_CTRL_STD_OP;

	reconn = (mcl->ctrl & MCAP_CTRL_CACHED);
	if (reconn)
		mcap_uncache_mcl(mcl);
	else
		mcl->ms->mcls = g_slist_prepend(mcl->ms->mcls, mcl);

	mcl->wid = g_io_add_watch(mcl->cc,
			G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			(GIOFunc) mcl_control_cb, mcl);

	/* Callback to report new MCL */
	if (reconn)
		mcl->ms->mcl_reconnected_cb(mcl, mcl->ms->user_data);
	else
		mcl->ms->mcl_connected_cb(mcl, mcl->ms->user_data);

	if (mcl->ref == 1) {
		mcl->ms->mcls = g_slist_remove(mcl->ms->mcls, mcl);
		mcap_mcl_unref(mcl);
	}
}

static void confirm_mcl_event_cb(GIOChannel *chan, gpointer user_data)
{
	struct mcap_instance *ms = user_data;
	struct mcap_mcl *mcl;
	bdaddr_t dst;
	char address[18], srcstr[18];
	GError *err = NULL;

	bt_io_get(chan, BT_IO_L2CAP, &err,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	ba2str(&ms->src, srcstr);
	mcl = find_mcl(ms->mcls, &dst);
	if (mcl) {
		error("Control channel already created with %s on adapter %s",
				address, srcstr);
		goto drop;
	}

	mcl = find_mcl(ms->cached, &dst);
	if (!mcl) {
		mcl = g_new0(struct mcap_mcl, 1);
		mcl->ms = ms;
		bacpy(&mcl->addr, &dst);
		set_default_cb(mcl);
		mcl->next_mdl = (rand() % MCAP_MDLID_FINAL) + 1;
		mcl = mcap_mcl_ref(mcl);
	}

	if (!bt_io_accept(chan, connect_mcl_event_cb, mcl, NULL, &err)) {
		error("mcap accept error: %s", err->message);
		if (!(mcl->ctrl & MCAP_CTRL_CACHED))
			mcap_mcl_unref(mcl);
		g_error_free(err);
		goto drop;
	}

	return;
drop:
	g_io_channel_shutdown(chan, TRUE, NULL);
}

struct mcap_instance *mcap_create_instance(bdaddr_t *src,
					BtIOSecLevel sec,
					uint16_t ccpsm,
					uint16_t dcpsm,
					mcap_mcl_event_cb mcl_connected,
					mcap_mcl_event_cb mcl_reconnected,
					mcap_mcl_event_cb mcl_disconnected,
					mcap_mcl_event_cb mcl_uncached,
					gpointer user_data,
					GError **gerr)
{
	struct mcap_instance *ms;

	if (sec < BT_IO_SEC_MEDIUM) {
		g_set_error(gerr, MCAP_ERROR, MCAP_ERROR_INVALID_ARGS,
				"Security level can't be minor of %d",
				BT_IO_SEC_MEDIUM);
		return NULL;
	}

	if (!(mcl_connected && mcl_reconnected &&
			mcl_disconnected && mcl_uncached)) {
		g_set_error(gerr, MCAP_ERROR, MCAP_ERROR_INVALID_ARGS,
				"The callbacks can't be null");
		return NULL;
	}

	ms = g_new0(struct mcap_instance, 1);

	bacpy(&ms->src, src);

	ms->sec = sec;
	ms->mcl_connected_cb = mcl_connected;
	ms->mcl_reconnected_cb = mcl_reconnected;
	ms->mcl_disconnected_cb = mcl_disconnected;
	ms->mcl_uncached_cb = mcl_uncached;
	ms->user_data = user_data;

	/* Listen incoming connections in control channel */
	ms->ccio = bt_io_listen(BT_IO_L2CAP, NULL, confirm_mcl_event_cb, ms,
				NULL, gerr,
				BT_IO_OPT_SOURCE_BDADDR, &ms->src,
				BT_IO_OPT_PSM, ccpsm,
				BT_IO_OPT_MTU, MCAP_CC_MTU,
				BT_IO_OPT_SEC_LEVEL, sec,
				BT_IO_OPT_INVALID);
	if (!ms->ccio) {
		error("%s", (*gerr)->message);
		g_free(ms);
		return NULL;
	}

	/* Listen incoming connections in data channels */
	ms->dcio = bt_io_listen(BT_IO_L2CAP, NULL, confirm_dc_event_cb, ms,
				NULL, gerr,
				BT_IO_OPT_SOURCE_BDADDR, &ms->src,
				BT_IO_OPT_PSM, dcpsm,
				BT_IO_OPT_MTU, MCAP_DC_MTU,
				BT_IO_OPT_SEC_LEVEL, sec,
				BT_IO_OPT_INVALID);
	if (!ms->dcio) {
		g_io_channel_shutdown(ms->ccio, TRUE, NULL);
		g_io_channel_unref(ms->ccio);
		ms->ccio = NULL;
		error("%s", (*gerr)->message);
		g_free(ms);
		return NULL;
	}
	/* Initialize random seed to generate mdlids for this instance */
	srand(time(NULL));
	return ms;
}

void mcap_release_instance(struct mcap_instance *mi)
{
	GSList *l;

	if (!mi)
		return;

	if (mi->ccio) {
		g_io_channel_shutdown(mi->ccio, TRUE, NULL);
		g_io_channel_unref(mi->ccio);
		mi->ccio = NULL;
	}

	if (mi->dcio) {
		g_io_channel_shutdown(mi->dcio, TRUE, NULL);
		g_io_channel_unref(mi->dcio);
		mi->dcio = NULL;
	}

	for (l = mi->mcls; l; l = l->next) {
		mcap_mcl_shutdown(l->data);
		mcap_mcl_unref(l->data);
	}
	g_slist_free(mi->mcls);
	mi->mcls = NULL;

	for (l = mi->cached; l; l = l->next)
		mcap_mcl_unref(l->data);
	g_slist_free(mi->cached);
	mi->cached = NULL;

	g_free(mi);
}

uint16_t mcap_get_ctrl_psm(struct mcap_instance *mi, GError **err)
{
	uint16_t lpsm;

	if (!(mi && mi->ccio)) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_INVALID_ARGS,
			"Invalid MCAP instance");
		return 0;
	}

	bt_io_get(mi->ccio, BT_IO_L2CAP, err,
			BT_IO_OPT_PSM, &lpsm,
			BT_IO_OPT_INVALID);
	if (*err)
		return 0;
	return lpsm;
}

uint16_t mcap_get_data_psm(struct mcap_instance *mi, GError **err)
{
	uint16_t lpsm;

	if (!(mi && mi->dcio)) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_INVALID_ARGS,
			"Invalid MCAP instance");
		return 0;
	}

	bt_io_get(mi->dcio, BT_IO_L2CAP, err,
			BT_IO_OPT_PSM, &lpsm,
			BT_IO_OPT_INVALID);
	if (*err)
		return 0;
	return lpsm;
}
