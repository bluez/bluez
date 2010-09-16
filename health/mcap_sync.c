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

#include "btio.h"
#include <stdint.h>
#include <netinet/in.h>

#include "log.h"

#include <bluetooth/bluetooth.h>
#include "mcap.h"
#include "mcap_lib.h"
#include "mcap_internal.h"

typedef struct {
	uint8_t         op;
	uint8_t         rc;
} __attribute__ ((packed)) mcap_md_sync_error_rsp;

static int mcap_sync_send_cmd(struct mcap_mcl *mcl, uint8_t oc, uint8_t rc)
{
	mcap_md_sync_error_rsp *cmd;
	int sock, sent;

	if (mcl->cc == NULL)
		return -1;

	sock = g_io_channel_unix_get_fd(mcl->cc);

	cmd = g_malloc(sizeof(mcap_md_sync_error_rsp));
	cmd->op = oc;
	cmd->rc = rc;

	sent = mcap_send_data(sock, cmd, sizeof(mcap_md_sync_error_rsp));
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
		mcap_sync_send_cmd(mcl, MCAP_MD_SYNC_CAP_RSP,
						MCAP_REQUEST_NOT_SUPPORTED);
		break;
	case MCAP_MD_SYNC_CAP_RSP:
		DBG("TODO: received MCAP_MD_SYNC_CAP_RSP: %d",
							MCAP_MD_SYNC_CAP_RSP);
		break;
	case MCAP_MD_SYNC_SET_REQ:
		DBG("TODO: received MCAP_MD_SYNC_SET_REQ: %d",
							MCAP_MD_SYNC_SET_REQ);
		/* Not implemented yet. Reply with unsupported request */
		mcap_sync_send_cmd(mcl, MCAP_MD_SYNC_SET_RSP,
						MCAP_REQUEST_NOT_SUPPORTED);
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
