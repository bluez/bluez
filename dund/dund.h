/*
  dund - Bluetooth LAN/DUN daemon for BlueZ
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

/* DUN scripts & commands */
#define DUN_CONFIG_DIR      "/etc/bluetooth/dun"

#define DUN_DEFAULT_CHANNEL 1

#define DUN_MAX_PPP_OPTS    40

/* DUN functions */
int dun_init(void);
int dun_cleanup(void);

int dun_show_connections(void);
int dun_kill_connection(uint8_t *dst);
int dun_kill_all_connections(void);

int dun_open_connection(int sk, char *pppd, char **pppd_opts, int wait);

/* SDP functions */
int  dun_sdp_register(uint8_t channel);
void dun_sdp_unregister(void);
int  dun_sdp_search(bdaddr_t *src, bdaddr_t *dst, int *channel);

