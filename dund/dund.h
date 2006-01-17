/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2006  Marcel Holtmann <marcel@holtmann.org>
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

/* DUN scripts & commands */
#define DUN_CONFIG_DIR	"/etc/bluetooth/dun"

#define DUN_DEFAULT_CHANNEL	1

#define DUN_MAX_PPP_OPTS	40

/* DUN types */
#define LANACCESS	0
#define MROUTER		1
#define ACTIVESYNC	2
#define DIALUP		3

/* DUN functions */
int dun_init(void);
int dun_cleanup(void);

int dun_show_connections(void);
int dun_kill_connection(uint8_t *dst);
int dun_kill_all_connections(void);

int dun_open_connection(int sk, char *pppd, char **pppd_opts, int wait);

/* SDP functions */
int  dun_sdp_register(bdaddr_t *device, uint8_t channel, int type);
void dun_sdp_unregister(void);
int  dun_sdp_search(bdaddr_t *src, bdaddr_t *dst, int *channel, int type);
