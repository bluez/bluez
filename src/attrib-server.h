/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
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

int attrib_server_init(void);
void attrib_server_exit(void);

uint16_t attrib_db_find_avail(uint16_t nitems);
struct attribute *attrib_db_add(uint16_t handle, bt_uuid_t *uuid, int read_reqs,
				int write_reqs, const uint8_t *value, int len);
int attrib_db_update(uint16_t handle, bt_uuid_t *uuid, const uint8_t *value,
					int len, struct attribute **attr);
int attrib_db_del(uint16_t handle);
int attrib_gap_set(uint16_t uuid, const uint8_t *value, int len);
uint32_t attrib_create_sdp(uint16_t handle, const char *name);
void attrib_free_sdp(uint32_t sdp_handle);
