/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
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

int bnep_init(void);
int bnep_cleanup(void);

int bnep_str2svc(char *svc, uint16_t *uuid);
char *bnep_svc2str(uint16_t uuid);

int bnep_show_connections(void);
int bnep_kill_connection(uint8_t *dst);
int bnep_kill_all_connections(void);

int bnep_accept_connection(int sk, uint16_t role, char *dev);
int bnep_create_connection(int sk, uint16_t role, uint16_t svc, char *dev);
