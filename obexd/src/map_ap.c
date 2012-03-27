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

#include <string.h>

#include "log.h"

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

/* This comes from OBEX specs */
struct obex_ap_header {
	uint8_t tag;
	uint8_t len;
	uint8_t val[0];
} __attribute__ ((packed));

static int find_ap_def_offset(uint8_t tag)
{
	if (tag == 0 || tag > G_N_ELEMENTS(ap_defs))
		return -1;

	return tag - 1;
}

static void ap_entry_dump(gpointer tag, gpointer val, gpointer user_data)
{
	struct ap_entry *entry = val;
	int offset;

	offset = find_ap_def_offset(GPOINTER_TO_INT(tag));

	switch (ap_defs[offset].type) {
	case APT_UINT8:
		DBG("%-30s %08x", ap_defs[offset].name, entry->val.u8);
		break;
	case APT_UINT16:
		DBG("%-30s %08x", ap_defs[offset].name, entry->val.u16);
		break;
	case APT_UINT32:
		DBG("%-30s %08x", ap_defs[offset].name, entry->val.u32);
		break;
	case APT_STR:
		DBG("%-30s %s", ap_defs[offset].name, entry->val.str);
		break;
	}
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

static void ap_decode_u8(map_ap_t *ap, const struct obex_ap_header *hdr)
{
	if (hdr->len != 1) {
		DBG("Value of tag %u is %u byte(s) long instead of expected "
				"1 byte - skipped!", hdr->tag, hdr->len);
		return;
	}

	map_ap_set_u8(ap, hdr->tag, hdr->val[0]);
}

static void ap_decode_u16(map_ap_t *ap, const struct obex_ap_header *hdr)
{
	uint16_t val;

	if (hdr->len != 2) {
		DBG("Value of tag %u is %u byte(s) long instead of expected "
				"2 bytes - skipped!", hdr->tag, hdr->len);
		return;
	}

	memcpy(&val, hdr->val, sizeof(val));
	map_ap_set_u16(ap, hdr->tag, GUINT16_FROM_BE(val));
}

static void ap_decode_u32(map_ap_t *ap, const struct obex_ap_header *hdr)
{
	uint32_t val;

	if (hdr->len != 4) {
		DBG("Value of tag %u is %u byte(s) long instead of expected "
				"4 bytes - skipped!", hdr->tag, hdr->len);
		return;
	}

	memcpy(&val, hdr->val, sizeof(val));
	map_ap_set_u32(ap, hdr->tag, GUINT32_FROM_BE(val));
}

static void ap_decode_str(map_ap_t *ap, const struct obex_ap_header *hdr)
{
	char *val = g_malloc0(hdr->len + 1);

	memcpy(val, hdr->val, hdr->len);
	map_ap_set_string(ap, hdr->tag, val);

	g_free(val);
}

map_ap_t *map_ap_decode(const uint8_t *buffer, size_t length)
{
	map_ap_t *ap;
	struct obex_ap_header *hdr;
	uint32_t done;
	int offset;

	ap = map_ap_new();
	if (!ap)
		return NULL;

	for (done = 0;  done < length; done += hdr->len + sizeof(*hdr)) {
		hdr = (struct obex_ap_header *)(buffer + done);

		offset = find_ap_def_offset(hdr->tag);

		if (offset < 0) {
			DBG("Unknown tag %u (length %u) - skipped.",
							hdr->tag, hdr->len);
			continue;
		}

		switch (ap_defs[offset].type) {
		case APT_UINT8:
			ap_decode_u8(ap, hdr);
			break;
		case APT_UINT16:
			ap_decode_u16(ap, hdr);
			break;
		case APT_UINT32:
			ap_decode_u32(ap, hdr);
			break;
		case APT_STR:
			ap_decode_str(ap, hdr);
			break;
		}
	}

	g_hash_table_foreach(ap, ap_entry_dump, NULL);

	return ap;
}

static void ap_encode_u8(GByteArray *buf, struct ap_entry *entry)
{
	struct obex_ap_header *hdr;

	hdr = (struct obex_ap_header *) buf->data + buf->len;
	g_byte_array_set_size(buf, buf->len + sizeof(*hdr) + 1);

	hdr->tag = entry->tag;
	hdr->len = 1;
	hdr->val[0] = entry->val.u8;
}

static void ap_encode_u16(GByteArray *buf, struct ap_entry *entry)
{
	struct obex_ap_header *hdr;
	uint16_t val;

	hdr = (struct obex_ap_header *) buf->data + buf->len;

	g_byte_array_set_size(buf, buf->len + sizeof(*hdr) + 2);

	hdr->tag = entry->tag;
	hdr->len = 2;

	val = GUINT16_TO_BE(entry->val.u16);
	memcpy(hdr->val, &val, sizeof(val));
}

static void ap_encode_u32(GByteArray *buf, struct ap_entry *entry)
{
	uint32_t val;
	struct obex_ap_header *hdr;

	hdr = (struct obex_ap_header *) buf->data + buf->len;
	g_byte_array_set_size(buf, buf->len + sizeof(*hdr) + 4);

	hdr->tag = entry->tag;
	hdr->len = 4;

	val = GUINT32_TO_BE(entry->val.u16);
	memcpy(hdr->val, &val, sizeof(val));
}

static void ap_encode_str(GByteArray *buf, struct ap_entry *entry)
{
	size_t len;
	struct obex_ap_header *hdr;

	hdr = (struct obex_ap_header *) buf->data + buf->len;
	len = strlen(entry->val.str);
	g_byte_array_set_size(buf, buf->len + sizeof(*hdr) + len);

	hdr->tag = entry->tag;
	hdr->len = len;

	memcpy(hdr->val, entry->val.str, len);
}

uint8_t *map_ap_encode(map_ap_t *ap, size_t *length)
{
	GByteArray *buf;
	GHashTableIter iter;
	gpointer key, value;
	struct ap_entry *entry;
	int offset;

	buf = g_byte_array_new();
	g_hash_table_iter_init(&iter, ap);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		entry = (struct ap_entry *) value;
		offset = find_ap_def_offset(entry->tag);

		switch (ap_defs[offset].type) {
		case APT_UINT8:
			ap_encode_u8(buf, entry);
			break;
		case APT_UINT16:
			ap_encode_u16(buf, entry);
			break;
		case APT_UINT32:
			ap_encode_u32(buf, entry);
			break;
		case APT_STR:
			ap_encode_str(buf, entry);
			break;
		}
	}

	*length = buf->len;

	return g_byte_array_free(buf, FALSE);
}

gboolean map_ap_get_u8(map_ap_t *ap, enum map_ap_tag tag, uint8_t *val)
{
	struct ap_entry *entry;
	int offset = find_ap_def_offset(tag);

	if (offset < 0 || ap_defs[offset].type != APT_UINT8)
		return FALSE;

	entry = g_hash_table_lookup(ap, GINT_TO_POINTER(tag));
	if (entry == NULL)
		return FALSE;

	*val = entry->val.u8;

	return TRUE;
}

gboolean map_ap_get_u16(map_ap_t *ap, enum map_ap_tag tag, uint16_t *val)
{
	struct ap_entry *entry;
	int offset = find_ap_def_offset(tag);

	if (offset < 0 || ap_defs[offset].type != APT_UINT16)
		return FALSE;

	entry = g_hash_table_lookup(ap, GINT_TO_POINTER(tag));
	if (entry == NULL)
		return FALSE;

	*val = entry->val.u16;

	return TRUE;
}

gboolean map_ap_get_u32(map_ap_t *ap, enum map_ap_tag tag, uint32_t *val)
{
	struct ap_entry *entry;
	int offset = find_ap_def_offset(tag);

	if (offset < 0 || ap_defs[offset].type != APT_UINT32)
		return FALSE;

	entry = g_hash_table_lookup(ap, GINT_TO_POINTER(tag));
	if (entry == NULL)
		return FALSE;

	*val = entry->val.u32;

	return TRUE;
}

const char *map_ap_get_string(map_ap_t *ap, enum map_ap_tag tag)
{
	struct ap_entry *entry;
	int offset = find_ap_def_offset(tag);

	if (offset < 0 || ap_defs[offset].type != APT_STR)
		return NULL;

	entry = g_hash_table_lookup(ap, GINT_TO_POINTER(tag));
	if (entry == NULL)
		return NULL;

	return entry->val.str;
}

gboolean map_ap_set_u8(map_ap_t *ap, enum map_ap_tag tag, uint8_t val)
{
	struct ap_entry *entry;
	int offset = find_ap_def_offset(tag);

	if (offset < 0 || ap_defs[offset].type != APT_UINT8)
		return FALSE;

	entry = g_new0(struct ap_entry, 1);
	entry->tag = tag;
	entry->val.u8 = val;

	g_hash_table_insert(ap, GINT_TO_POINTER(tag), entry);

	return TRUE;
}

gboolean map_ap_set_u16(map_ap_t *ap, enum map_ap_tag tag, uint16_t val)
{
	struct ap_entry *entry;
	int offset = find_ap_def_offset(tag);

	if (offset < 0 || ap_defs[offset].type != APT_UINT16)
		return FALSE;

	entry = g_new0(struct ap_entry, 1);
	entry->tag = tag;
	entry->val.u16 = val;

	g_hash_table_insert(ap, GINT_TO_POINTER(tag), entry);

	return TRUE;
}

gboolean map_ap_set_u32(map_ap_t *ap, enum map_ap_tag tag, uint32_t val)
{
	struct ap_entry *entry;
	int offset = find_ap_def_offset(tag);

	if (offset < 0 || ap_defs[offset].type != APT_UINT32)
		return FALSE;

	entry = g_new0(struct ap_entry, 1);
	entry->tag = tag;
	entry->val.u32 = val;

	g_hash_table_insert(ap, GINT_TO_POINTER(tag), entry);

	return TRUE;
}

gboolean map_ap_set_string(map_ap_t *ap, enum map_ap_tag tag, const char *val)
{
	struct ap_entry *entry;
	int offset = find_ap_def_offset(tag);

	if (offset < 0 || ap_defs[offset].type != APT_STR)
		return FALSE;

	entry = g_new0(struct ap_entry, 1);
	entry->tag = tag;
	entry->val.str = g_strdup(val);

	g_hash_table_insert(ap, GINT_TO_POINTER(tag), entry);

	return TRUE;
}
