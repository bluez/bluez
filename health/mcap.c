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


static void mcap_mcl_shutdown(struct mcap_mcl *mcl)
{
	/* TODO: implement mcap_mcl_shutdown */
}

void mcap_mcl_unref(struct mcap_mcl *mcl)
{
	/* TODO: implement mcap_mcl_unref */
}

static void confirm_dc_event_cb(GIOChannel *chan, gpointer user_data)
{
	/* TODO: implement confirm_dc_event_cb */
}

static void confirm_mcl_event_cb(GIOChannel *chan, gpointer user_data)
{
	/* TODO: implement confirm_mcl_event_cb */
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
