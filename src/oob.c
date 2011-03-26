/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  ST-Ericsson SA
 *
 *  Author: Szymon Janc <szymon.janc@tieto.com> for ST-Ericsson
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

#include "adapter.h"
#include "oob.h"

static oob_read_cb_t local_oob_read_cb = NULL;

void oob_register_cb(oob_read_cb_t cb)
{
	local_oob_read_cb = cb;
}

void oob_read_local_data_complete(struct btd_adapter *adapter, uint8_t *hash,
							uint8_t *randomizer)
{
	if (local_oob_read_cb)
		local_oob_read_cb(adapter, hash, randomizer);
}
