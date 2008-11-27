/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include <glib.h>
#include <bluetooth/bluetooth.h>

#include "logging.h"
#include "obex.h"

#define PHONEBOOK_TYPE "x-bt/phonebook"

#define ORDER_TAG		0x01
#define SEARCHVALUE_TAG		0x02
#define SEARCHATTRIB_TAG	0x03
#define MAXLISTCOUNT_TAG	0x04
#define LISTSTARTOFFSET_TAG	0x05
#define FILTER_TAG		0x06
#define FORMAT_TAG		0X07
#define PHONEBOOKSIZE_TAG	0X08
#define NEWMISSEDCALLS_TAG	0X09

/* The following length is in the unit of byte */
#define ORDER_LEN		1
#define SEARCHATTRIB_LEN	1
#define MAXLISTCOUNT_LEN	2
#define LISTSTARTOFFSET_LEN	2
#define FILTER_LEN		8
#define FORMAT_LEN		1
#define PHONEBOOKSIZE_LEN	2
#define NEWMISSEDCALLS_LEN	1

typedef struct {
	uint8_t		tag;
	uint8_t		len;
	uint8_t		val[0];
} __attribute__ ((packed)) apparam_hdr;

#define get_be64(val)	GUINT64_FROM_BE(bt_get_unaligned((guint64 *) val))
#define get_be16(val)	GUINT16_FROM_BE(bt_get_unaligned((guint16 *) val))

static GSList *session_list = NULL;

static int pbap_pullphonebook(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *session;
	obex_headerdata_t hd;
	guint8 hi, *p, newmissedcalls, format;
	guint16 maxlistcount, liststartoffset, phonebooksize;
	guint32 hlen, offset;
	guint64 filter;
	apparam_hdr *hdr;

	session = OBEX_GetUserData(obex);

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		if (hi != OBEX_HDR_APPARAM)
			continue;

		if (hlen <= sizeof(apparam_hdr)) {
			error("PBAP pullphonebook app parameters header"
					" is too short: %d", hlen);
			return -1;
		}

		p = (guint8 *) hd.bs;
		hdr = (apparam_hdr *) hd.bs;
		offset = 0;
		while (offset < hlen) {
			switch (hdr->tag) {
			case FILTER_TAG:
				if (hdr->len == FILTER_LEN)
					filter = get_be64(hdr->val);
				else
					goto fail;
				break;
			case FORMAT_TAG:
				if (hdr->len == FORMAT_LEN)
					format = hdr->val[0];
				else
					goto fail;
				break;
			case MAXLISTCOUNT_TAG:
				if (hdr->len == MAXLISTCOUNT_LEN)
					maxlistcount = get_be16(hdr->val);
				else
					goto fail;
				break;
			case LISTSTARTOFFSET_TAG:
				if (hdr->len == LISTSTARTOFFSET_LEN)
					liststartoffset = get_be16(hdr->val);
				else
					goto fail;
				break;
			default:
fail:				error("Unexpected PBAP pullphonebook app"
					" parameter, tag %d, len %d",
					hdr->tag, hdr->len);
				return -1;
			}

			p += sizeof(apparam_hdr) + hdr->len;
			offset += sizeof(apparam_hdr) + hdr->len;
			hdr = (apparam_hdr *) p;
		}

		/* Ignore multiple app param headers */
		break;
	}

	return phonebook_pullphonebook(session->pbctx, session->name, filter,
				format, maxlistcount, liststartoffset,
				&phonebooksize, &newmissedcalls);
}

void pbap_get(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *session;
	obex_headerdata_t hv;
	int err;

	session = OBEX_GetUserData(obex);
	if (session == NULL)
		return;

	if (session->type == NULL || session->name == NULL)
		goto fail;

	OBEX_ObjectReParseHeaders(obex, obj);

	if (g_str_equal(session->type, PHONEBOOK_TYPE) == TRUE)
		err = pbap_pullphonebook(obex, obj);
	else
		goto fail;

	if (err < 0)
		goto fail;

	OBEX_SuspendRequest(obex, obj);
	session->size = 0;

	/* Add body header */
	hv.bs = NULL;
	OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_BODY,
					hv, 0, OBEX_FL_STREAM_START);

	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);

	return;

fail:
	OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
}

gboolean pbap_phonebook_context_create(struct obex_session *session)
{
	struct phonebook_context *context;
	struct phonebook_driver *driver;

	driver = phonebook_get_driver(NULL);
	if (driver == NULL)
		return FALSE;

	context = phonebook_create(driver);
	if (context == NULL)
		return FALSE;

	session->pbctx = context;

	session_list = g_slist_append(session_list, session);

	return TRUE;
}

void pbap_phonebook_context_destroy(struct obex_session *session)
{
	struct phonebook_context *context;

	context = session->pbctx;
	phonebook_unref(context);

	session_list = g_slist_remove(session_list, session);
}

struct obex_session *pbap_get_session(struct phonebook_context *context)
{
	GSList *current;

	for (current = session_list; current != NULL; current = current->next) {
		struct obex_session *session = current->data;
		if (session->pbctx == context)
			return session;
	}

	return NULL;
}
