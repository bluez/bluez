/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2005  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */

/* DUN scripts & commands */
#define DUN_CONFIG_DIR	"/etc/bluetooth/dun"

#define DUN_DEFAULT_CHANNEL	1

#define DUN_MAX_PPP_OPTS	40

/* DUN types */
#define LANACCESS	0
#define MROUTER		1
#define ACTIVESYNC	2

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
