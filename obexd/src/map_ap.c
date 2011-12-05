/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2010-2011  Nokia Corporation
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "map_ap.h"

map_ap_t *map_ap_new(void)
{
	return NULL;
}

void map_ap_free(map_ap_t *ap)
{
}

map_ap_t *map_ap_decode(const uint8_t *buffer, size_t length)
{
	return NULL;
}

uint8_t *map_ap_encode(map_ap_t *ap, size_t *length)
{
	*length = 0;

	return NULL;
}

gboolean map_ap_get_u8(map_ap_t *ap, enum map_ap_tag tag, uint8_t *val)
{
	return FALSE;
}

gboolean map_ap_get_u16(map_ap_t *ap, enum map_ap_tag tag, uint16_t *val)
{
	return FALSE;
}

gboolean map_ap_get_u32(map_ap_t *ap, enum map_ap_tag tag, uint32_t *val)
{
	return FALSE;
}

const char *map_ap_get_string(map_ap_t *ap, enum map_ap_tag tag)
{
	return NULL;
}

gboolean map_ap_set_u8(map_ap_t *ap, enum map_ap_tag tag, uint8_t val)
{
	return FALSE;
}

gboolean map_ap_set_u16(map_ap_t *ap, enum map_ap_tag tag, uint16_t val)
{
	return FALSE;
}

gboolean map_ap_set_u32(map_ap_t *ap, enum map_ap_tag tag, uint32_t val)
{
	return FALSE;
}

gboolean map_ap_set_string(map_ap_t *ap, enum map_ap_tag tag, const char *val)
{
	return FALSE;
}
