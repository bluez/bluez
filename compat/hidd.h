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

#define L2CAP_PSM_HIDP_CTRL 0x11
#define L2CAP_PSM_HIDP_INTR 0x13

int epox_presenter(const bdaddr_t *src, const bdaddr_t *dst, uint8_t channel);
int headset_presenter(const bdaddr_t *src, const bdaddr_t *dst, uint8_t channel);
int jthree_keyboard(const bdaddr_t *src, const bdaddr_t *dst, uint8_t channel);
int celluon_keyboard(const bdaddr_t *src, const bdaddr_t *dst, uint8_t channel);
