/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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

#include <stdint.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>

#include "att.h"

int att_read_by_grp_type_encode(uint16_t start, uint16_t end, uuid_t *uuid,
							uint8_t *pdu, int len)
{
	return 0;
}

int att_find_by_type_encode(uint16_t start, uint16_t end, uuid_t *uuid,
							uint8_t *pdu, int len)
{
	return 0;
}
