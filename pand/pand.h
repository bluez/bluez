/*
  pand - Bluetooth PAN daemon for BlueZ
  Copyright (C) 2002 Maxim Krasnyansky <maxk@qualcomm.com>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License, version 2, as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
*/

/*
 * $Id$
 */

/* PAN scripts & commands */
#define PAND_CONFIG_DIR  "/etc/bluetooth/pan"
#define PAND_DEVUP_CMD   "dev-up"

/* BNEP functions */
int bnep_init(void);
int bnep_cleanup(void);

int bnep_str2svc(char *svc, uint16_t *uuid);
char *bnep_svc2str(uint16_t uuid);

int bnep_show_connections(void);
int bnep_kill_connection(uint8_t *dst);
int bnep_kill_all_connections(void);

int bnep_accept_connection(int sk, uint16_t role, char *dev);
int bnep_create_connection(int sk, uint16_t role, uint16_t svc, char *dev);

/* SDP functions */
int  bnep_sdp_register(uint16_t role);
void bnep_sdp_unregister(void);
int  bnep_sdp_search(bdaddr_t *src, bdaddr_t *dst, uint16_t service);
