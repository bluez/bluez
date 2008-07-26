/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

int port_delete(bdaddr_t *src, bdaddr_t *dst, int16_t id);
int port_store(bdaddr_t *src, bdaddr_t *dst, int16_t id,
			uint8_t ch, const char *svcname);
int proxy_delete(bdaddr_t *src, const char *tty);
int proxy_store(bdaddr_t *src, const char *uuid, const char *tty,
		const char *name, uint8_t ch, int opts, struct termios *ti);
int read_device_name(bdaddr_t *src, bdaddr_t *dst, char **name);
