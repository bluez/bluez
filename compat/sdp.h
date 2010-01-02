/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2010  Marcel Holtmann <marcel@holtmann.org>
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

#define LANACCESS	0
#define MROUTER		1
#define ACTIVESYNC	2
#define DIALUP		3

int get_stored_device_info(const bdaddr_t *src, const bdaddr_t *dst, struct hidp_connadd_req *req);
int get_sdp_device_info(const bdaddr_t *src, const bdaddr_t *dst, struct hidp_connadd_req *req);
int get_alternate_device_info(const bdaddr_t *src, const bdaddr_t *dst, uint16_t *uuid, uint8_t *channel, char *name, size_t len);

int bnep_sdp_search(bdaddr_t *src, bdaddr_t *dst, uint16_t service);
int bnep_sdp_register(bdaddr_t *device, uint16_t role);
void bnep_sdp_unregister(void);

int dun_sdp_search(bdaddr_t *src, bdaddr_t *dst, int *channel, int type);
int dun_sdp_register(bdaddr_t *device, uint8_t channel, int type);
void dun_sdp_unregister(void);
