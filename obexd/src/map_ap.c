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

enum ap_type {
	APT_UINT8,
	APT_UINT16,
	APT_UINT32,
	APT_STR
};

/* NOTE: ap_defs array has to be kept in sync with map_ap_tag. */
static const struct ap_def {
	const char *name;
	enum ap_type type;
} ap_defs[] = {
	{ "MAXLISTCOUNT",		APT_UINT16 },
	{ "STARTOFFSET",		APT_UINT16 },
	{ "FILTERMESSAGETYPE",		APT_UINT8  },
	{ "FILTERPERIODBEGIN",		APT_STR    },
	{ "FILTERPERIODEND",		APT_STR    },
	{ "FILTERREADSTATUS",		APT_UINT8  },
	{ "FILTERRECIPIENT",		APT_STR    },
	{ "FILTERORIGINATOR",		APT_STR    },
	{ "FILTERPRIORITY",		APT_UINT8  },
	{ "ATTACHMENT",			APT_UINT8  },
	{ "TRANSPARENT",		APT_UINT8  },
	{ "RETRY",			APT_UINT8  },
	{ "NEWMESSAGE",			APT_UINT8  },
	{ "NOTIFICATIONSTATUS",		APT_UINT8  },
	{ "MASINSTANCEID",		APT_UINT8  },
	{ "PARAMETERMASK",		APT_UINT32 },
	{ "FOLDERLISTINGSIZE",		APT_UINT16 },
	{ "MESSAGESLISTINGSIZE",	APT_UINT16 },
	{ "SUBJECTLENGTH",		APT_UINT8  },
	{ "CHARSET",			APT_UINT8  },
	{ "FRACTIONREQUEST",		APT_UINT8  },
	{ "FRACTIONDELIVER",		APT_UINT8  },
	{ "STATUSINDICATOR",		APT_UINT8  },
	{ "STATUSVALUE",		APT_UINT8  },
	{ "MSETIME",			APT_STR    },
};

struct ap_entry {
	enum map_ap_tag tag;
	union {
		uint32_t u32;
		uint16_t u16;
		uint8_t u8;
		char *str;
	} val;
};

static int find_ap_def_offset(uint8_t tag)
{
	if (tag == 0 || tag > G_N_ELEMENTS(ap_defs))
		return -1;

	return tag - 1;
}

static void ap_entry_free(gpointer val)
{
	struct ap_entry *entry = val;
	int offset;

	offset = find_ap_def_offset(entry->tag);

	if (offset >= 0 && ap_defs[offset].type == APT_STR)
		g_free(entry->val.str);

	g_free(entry);
}

map_ap_t *map_ap_new(void)
{
	return g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
								ap_entry_free);
}

void map_ap_free(map_ap_t *ap)
{
	if (!ap)
		return;

	g_hash_table_destroy(ap);
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
