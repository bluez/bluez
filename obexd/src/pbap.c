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

#include <glib.h>
#include <bluetooth/bluetooth.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

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

#define MCH		"telecom/mch.vcf"
#define SIM1_MCH	"SIM1/telecom/mch.vcf"

struct apparam_hdr {
	uint8_t		tag;
	uint8_t		len;
	uint8_t		val[0];
} __attribute__ ((packed));
#define APPARAM_HDR_SIZE 2

#define get_be64(val)	GUINT64_FROM_BE(bt_get_unaligned((guint64 *) val))
#define get_be16(val)	GUINT16_FROM_BE(bt_get_unaligned((guint16 *) val))

#define put_be16(val, ptr) bt_put_unaligned(GUINT16_TO_BE(val), (guint16 *) ptr)

static GSList *session_list = NULL;

static int pbap_pullphonebook(obex_t *obex, obex_object_t *obj,
							gboolean *addbody)
{
	struct obex_session *session = OBEX_GetUserData(obex);
	obex_headerdata_t hd;
	guint8 hi, format, newmissedcalls = 0, rspsize = 0;
	guint16 maxlistcount, liststartoffset, phonebooksize = 0;
	guint32 hlen;
	guint64 filter;
	gboolean addmissedcalls = FALSE;
	int err;

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		void *ptr = (void *) hd.bs;
		uint32_t len = hlen;

		if (hi != OBEX_HDR_APPARAM)
			continue;

		if (hlen < APPARAM_HDR_SIZE) {
			error("PBAP pullphonebook app parameters header"
						" is too short: %d", hlen);
			return -1;
		}

		while (len > APPARAM_HDR_SIZE) {
			struct apparam_hdr *hdr = ptr;

			if (hdr->len > len - APPARAM_HDR_SIZE) {
				error("Unexpected PBAP pullphonebook app"
						" length, tag %d, len %d",
							hdr->tag, hdr->len);
				return -1;
			}

			switch (hdr->tag) {
			case FILTER_TAG:
				if (hdr->len == FILTER_LEN)
					filter = get_be64(hdr->val);
				break;
			case FORMAT_TAG:
				if (hdr->len == FORMAT_LEN)
					format = hdr->val[0];
				break;
			case MAXLISTCOUNT_TAG:
				if (hdr->len == MAXLISTCOUNT_LEN)
					maxlistcount = get_be16(hdr->val);
				break;
			case LISTSTARTOFFSET_TAG:
				if (hdr->len == LISTSTARTOFFSET_LEN)
					liststartoffset = get_be16(hdr->val);
				break;
			default:
				error("Unexpected PBAP pullphonebook app"
						" parameter, tag %d, len %d",
							hdr->tag, hdr->len);
				return -1;
			}

			ptr += APPARAM_HDR_SIZE + hdr->len;
			len -= APPARAM_HDR_SIZE + hdr->len;
		}

		/* Ignore multiple app param headers */
		break;
	}

	err = phonebook_pullphonebook(session->pbctx, session->name, filter,
				format, maxlistcount, liststartoffset,
				&phonebooksize, &newmissedcalls);
	if (err < 0)
		return err;

	/* Add app parameter header, that is sent back to PBAP client */
	if (maxlistcount == 0) {
		rspsize += APPARAM_HDR_SIZE + PHONEBOOKSIZE_LEN;
		*addbody = FALSE;
	}

	if (g_str_equal(session->name, SIM1_MCH) == TRUE ||
				g_str_equal(session->name, MCH) == TRUE) {
		rspsize += APPARAM_HDR_SIZE + NEWMISSEDCALLS_LEN;
		addmissedcalls = TRUE;
	}

	if (rspsize > 0) {
		void *buf, *ptr;

		buf = g_try_malloc0(rspsize);
		if (buf == NULL)
			return -1;

		ptr = buf;

		if (maxlistcount == 0) {
			struct apparam_hdr *hdr = ptr;

			hdr->tag = PHONEBOOKSIZE_TAG;
			hdr->len = PHONEBOOKSIZE_LEN;
			put_be16(phonebooksize, hdr->val);

			ptr += APPARAM_HDR_SIZE + PHONEBOOKSIZE_LEN;
		}

		if (addmissedcalls == TRUE) {
			struct apparam_hdr *hdr = ptr;

			hdr->tag = NEWMISSEDCALLS_TAG;
			hdr->len = NEWMISSEDCALLS_LEN;
			hdr->val[0] = newmissedcalls;

			ptr += APPARAM_HDR_SIZE + NEWMISSEDCALLS_LEN;
		}

		hd.bs = buf;
		OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_APPARAM,
							hd, rspsize, 0);

		g_free(buf);
	}

	return 0;
}

void pbap_get(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *session = OBEX_GetUserData(obex);
	obex_headerdata_t hd;
	gboolean addbody = TRUE;
	int err;

	if (session == NULL)
		return;

	if (session->type == NULL || session->name == NULL)
		goto fail;

	OBEX_ObjectReParseHeaders(obex, obj);

	if (g_str_equal(session->type, PHONEBOOK_TYPE) == TRUE)
		err = pbap_pullphonebook(obex, obj, &addbody);
	else
		goto fail;

	if (err < 0)
		goto fail;

	if (addbody == TRUE) {
		OBEX_SuspendRequest(obex, obj);
		session->size = 0;

		/* Add body header */
		hd.bs = NULL;
		OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_BODY,
						hd, 0, OBEX_FL_STREAM_START);
	}

	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);

	return;

fail:
	OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
}

static gboolean pbap_is_valid_folder(struct obex_session *session)
{
	if (session->current_folder == NULL) {
		if (g_str_equal(session->name, "telecom") == TRUE ||
			g_str_equal(session->name, "SIM1") == TRUE)
			return TRUE;
	} else if (g_str_equal(session->current_folder, "SIM1") == TRUE) {
		if (g_str_equal(session->name, "telecom") == TRUE)
			return TRUE;
	} else if (g_str_equal(session->current_folder, "telecom") == TRUE ||
		g_str_equal(session->current_folder, "SIM1/telecom") == TRUE) {
		if (g_str_equal(session->name, "pb") == TRUE ||
				g_str_equal(session->name, "ich") == TRUE ||
				g_str_equal(session->name, "och") == TRUE ||
				g_str_equal(session->name, "mch") == TRUE ||
				g_str_equal(session->name, "cch") == TRUE)
			return TRUE;
	}

	return FALSE;
}

void pbap_setpath(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *session = OBEX_GetUserData(obex);
	guint8 *nonhdr;
	gchar *fullname;

	if (OBEX_ObjectGetNonHdrData(obj, &nonhdr) != 2) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
				OBEX_RSP_PRECONDITION_FAILED);
		error("Set path failed: flag and constants not found!");
		return;
	}

	/* Check "Backup" flag */
	if ((nonhdr[0] & 0x01) == 0x01) {
		debug("Set to parent path");

		if (session->current_folder == NULL) {
			/* we are already in top level folder */
			OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN,
					OBEX_RSP_FORBIDDEN);
			return;
		}

		fullname = g_path_get_dirname(session->current_folder);
		g_free(session->current_folder);

		if (strlen(fullname) == 1 && *fullname == '.')
			session->current_folder = NULL;
		else
			session->current_folder = g_strdup(fullname);

		g_free(fullname);

		debug("Set to parent path: %s", session->current_folder);

		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		return;
	}

	if (!session->name) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_BAD_REQUEST);
		error("Set path failed: name missing!");
		return;
	}

	if (strlen(session->name) == 0) {
		debug("Set to root");

		g_free(session->current_folder);
		session->current_folder = NULL;

		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		return;
	}

	/* Check and set to name path */
	if (strstr(session->name, "/")) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		error("Set path failed: name incorrect!");
		return;
	}

	if (pbap_is_valid_folder(session) == FALSE) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_FOUND, OBEX_RSP_NOT_FOUND);
		return;
	}

	fullname = g_build_filename(session->current_folder, session->name, NULL);

	debug("Fullname: %s", fullname);

	g_free(session->current_folder);
	session->current_folder = fullname;
	OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
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
