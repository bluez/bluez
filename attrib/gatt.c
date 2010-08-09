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

#include <stdint.h>
#include <glib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "att.h"
#include "gattrib.h"
#include "gatt.h"

guint gatt_discover_primary(GAttrib *attrib, uint16_t start,
		uint16_t end, GAttribResultFunc func, gpointer user_data)
{
	uint8_t pdu[ATT_MTU];
	uuid_t uuid;
	guint16 plen;

	sdp_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);

	plen = enc_read_by_grp_req(start, end, &uuid, pdu, sizeof(pdu));
	if (plen == 0)
		return 0;

	return g_attrib_send(attrib, ATT_OP_READ_BY_GROUP_REQ,
					pdu, plen, func, user_data, NULL);
}

guint gatt_discover_char(GAttrib *attrib, uint16_t start, uint16_t end,
				GAttribResultFunc func, gpointer user_data)
{
	uint8_t pdu[ATT_MTU];
	uuid_t uuid;
	guint16 plen;

	sdp_uuid16_create(&uuid, GATT_CHARAC_UUID);

	plen = enc_read_by_type_req(start, end, &uuid, pdu, sizeof(pdu));
	if (plen == 0)
		return 0;

	return g_attrib_send(attrib, ATT_OP_READ_BY_TYPE_REQ,
					pdu, plen, func, user_data, NULL);
}

guint gatt_read_char(GAttrib *attrib, uint16_t handle, GAttribResultFunc func,
							gpointer user_data)
{
	uint8_t pdu[ATT_MTU];
	guint16 plen;

	plen = enc_read_req(handle, pdu, sizeof(pdu));
	return g_attrib_send(attrib, ATT_OP_READ_REQ, pdu, plen, func,
							user_data, NULL);
}

guint gatt_find_info(GAttrib *attrib, uint16_t start, uint16_t end,
				GAttribResultFunc func, gpointer user_data)
{
	uint8_t pdu[ATT_MTU];
	guint16 plen;

	plen = enc_find_info_req(start, end, pdu, sizeof(pdu));
	if (plen == 0)
		return 0;

	return g_attrib_send(attrib, ATT_OP_FIND_INFO_REQ, pdu, plen, func,
							user_data, NULL);
}
