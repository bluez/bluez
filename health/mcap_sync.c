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

#include "config.h"
#include "log.h"

#include <bluetooth/bluetooth.h>
#include "mcap.h"
#include "mcap_lib.h"
#include "mcap_internal.h"

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
