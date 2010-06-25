/*
 *
 *  MCAP for BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010 GSyC/LibreSoft, Universidad Rey Juan Carlos.
 *  Copyright (C) 2010 Signove
 *
 *  Authors:
 *  Santiago Carot-Nemesio <sancane at gmail.com>
 *  Jose Antonio Santos-Cadenas <santoscadenas at gmail.com>
 *  Elvis Pfützenreuter <epx at signove.com>
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

#include "btio.h"
#include <stdint.h>
#include <netinet/in.h>
#include <time.h>

#include "config.h"
#include "log.h"

#include <bluetooth/bluetooth.h>
#include "mcap.h"
#include "mcap_lib.h"
#include "mcap_internal.h"

struct mcap_csp {
	uint64_t		base_tmstamp;	/* CSP base timestamp */
	struct timespec		base_time;	/* CSP base time when timestamp set */
	guint			local_caps;	/* CSP-Master: have got remote caps */
	guint			remote_caps;	/* CSP-Slave: remote master got caps */
	guint			rem_req_acc;	/* CSP-Slave: accuracy required by master */
	guint			ind_expected;	/* CSP-Master: indication expected */
	MCAPCtrl		csp_req;	/* CSP-Master: Request control flag */
	guint			ind_timer;	/* CSP-Slave: indication timer */
	guint			set_timer;	/* CSP-Slave: delayed set timer */
	void			*set_data;	/* CSP-Slave: delayed set data */
	gint			dev_id;		/* CSP-Slave: device ID */
	gint			dev_hci_fd;	/* CSP-Slave fd to read BT clock */
	void			*csp_priv_data;	/* CSP-Master: In-flight request data */
};

static int send_unsupported_cap_req(struct mcap_mcl *mcl)
{
	mcap_md_sync_cap_rsp *cmd;
	int sock, sent;

	cmd = g_new0(mcap_md_sync_cap_rsp, 1);
	cmd->op = MCAP_MD_SYNC_CAP_RSP;
	cmd->rc = MCAP_REQUEST_NOT_SUPPORTED;

	sock = g_io_channel_unix_get_fd(mcl->cc);
	sent = mcap_send_data(sock, cmd, sizeof(*cmd));
	g_free(cmd);

	return sent;
}

static int send_unsupported_set_req(struct mcap_mcl *mcl)
{
	mcap_md_sync_set_rsp *cmd;
	int sock, sent;

	cmd = g_new0(mcap_md_sync_set_rsp, 1);
	cmd->op = MCAP_MD_SYNC_SET_RSP;
	cmd->rc = MCAP_REQUEST_NOT_SUPPORTED;

	sock = g_io_channel_unix_get_fd(mcl->cc);
	sent = mcap_send_data(sock, cmd, sizeof(*cmd));
	g_free(cmd);

	return sent;
}

void proc_sync_cmd(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	switch (cmd[0]) {
	case MCAP_MD_SYNC_CAP_REQ:
		DBG("TODO: received MCAP_MD_SYNC_CAP_REQ: %d",
							MCAP_MD_SYNC_CAP_REQ);
		/* Not implemented yet. Reply with unsupported request */
		send_unsupported_cap_req(mcl);
		break;
	case MCAP_MD_SYNC_CAP_RSP:
		DBG("TODO: received MCAP_MD_SYNC_CAP_RSP: %d",
							MCAP_MD_SYNC_CAP_RSP);
		break;
	case MCAP_MD_SYNC_SET_REQ:
		DBG("TODO: received MCAP_MD_SYNC_SET_REQ: %d",
							MCAP_MD_SYNC_SET_REQ);
		/* Not implemented yet. Reply with unsupported request */
		send_unsupported_set_req(mcl);
		break;
	case MCAP_MD_SYNC_SET_RSP:
		DBG("TODO: received MCAP_MD_SYNC_SET_RSP: %d",
							MCAP_MD_SYNC_SET_RSP);
		break;
	case MCAP_MD_SYNC_INFO_IND:
		DBG("TODO: received MCAP_MD_SYNC_INFO_IND :%d",
							MCAP_MD_SYNC_INFO_IND);
		break;
	}
}

static void reset_tmstamp(struct mcap_csp *csp, struct timespec *base_time,
				uint64_t new_tmstamp)
{
	csp->base_tmstamp = new_tmstamp;
	if (base_time)
		csp->base_time = *base_time;
	else
		clock_gettime(CLOCK_MONOTONIC, &csp->base_time);
}

void mcap_sync_init(struct mcap_mcl *mcl)
{
	mcl->csp = g_new0(struct mcap_csp, 1);

	mcl->csp->rem_req_acc = 10000; /* safe divisor */
	mcl->csp->set_data = NULL;
	mcl->csp->dev_id = -1;
	mcl->csp->dev_hci_fd = -1;
	mcl->csp->csp_priv_data = NULL;

	reset_tmstamp(mcl->csp, NULL, 0);
}
