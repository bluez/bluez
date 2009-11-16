/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2009  Intel Corporation
 *  Copyright (C) 2007-2009  Marcel Holtmann <marcel@holtmann.org>
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
#include <errno.h>
#include <glib.h>
#include <bluetooth/bluetooth.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "plugin.h"
#include "logging.h"
#include "obex.h"
#include "service.h"
#include "phonebook.h"
#include "telephony.h"
#include "dbus.h"

#define PHONEBOOK_TYPE		"x-bt/phonebook"
#define VCARDLISTING_TYPE	"x-bt/vcard-listing"
#define VCARDENTRY_TYPE		"x-bt/vcard"

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

#define DEFAULT_COUNT 65535

#define APPARAM_HDR_SIZE 2

#define get_be64(val)	GUINT64_FROM_BE(bt_get_unaligned((guint64 *) val))
#define get_be16(val)	GUINT16_FROM_BE(bt_get_unaligned((guint16 *) val))

#define put_be16(val, ptr) bt_put_unaligned(GUINT16_TO_BE(val), (guint16 *) ptr)

#define PBAP_CHANNEL	15

#define PBAP_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>	\
<record>									\
  <attribute id=\"0x0001\">							\
    <sequence>									\
      <uuid value=\"0x112f\"/>							\
    </sequence>									\
  </attribute>									\
										\
  <attribute id=\"0x0004\">							\
    <sequence>									\
      <sequence>								\
        <uuid value=\"0x0100\"/>						\
      </sequence>								\
      <sequence>								\
        <uuid value=\"0x0003\"/>						\
        <uint8 value=\"%u\" name=\"channel\"/>					\
      </sequence>								\
      <sequence>								\
        <uuid value=\"0x0008\"/>						\
      </sequence>								\
    </sequence>									\
  </attribute>									\
										\
  <attribute id=\"0x0009\">							\
    <sequence>									\
      <sequence>								\
        <uuid value=\"0x1130\"/>						\
        <uint16 value=\"0x0100\" name=\"version\"/>				\
      </sequence>								\
    </sequence>									\
  </attribute>									\
										\
  <attribute id=\"0x0100\">							\
    <text value=\"%s\" name=\"name\"/>						\
  </attribute>									\
										\
  <attribute id=\"0x0314\">							\
    <uint8 value=\"0x01\"/>							\
  </attribute>									\
</record>"

struct apparam_hdr {
	uint8_t		tag;
	uint8_t		len;
	uint8_t		val[0];
} __attribute__ ((packed));

static const guint8 PBAP_TARGET[TARGET_SIZE] = {
			0x79, 0x61, 0x35, 0xF0,  0xF0, 0xC5, 0x11, 0xD8,
			0x09, 0x66, 0x08, 0x00,  0x20, 0x0C, 0x9A, 0x66  };

static int pbap_parse_apparam_header(obex_t *obex, obex_object_t *obj,
						struct apparam_field *apparam)
{
	obex_headerdata_t hd;
	guint8 hi;
	guint32 hlen;

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		void *ptr = (void *) hd.bs;
		uint32_t len = hlen;

		if (hi != OBEX_HDR_APPARAM)
			continue;

		if (hlen < APPARAM_HDR_SIZE) {
			g_free(apparam->searchval);
			error("PBAP pullphonebook app parameters header"
						" is too short: %d", hlen);
			return -1;
		}

		while (len > APPARAM_HDR_SIZE) {
			struct apparam_hdr *hdr = ptr;

			if (hdr->len > len - APPARAM_HDR_SIZE) {
				g_free(apparam->searchval);
				error("Unexpected PBAP pullphonebook app"
						" length, tag %d, len %d",
							hdr->tag, hdr->len);
				return -1;
			}

			switch (hdr->tag) {
			case ORDER_TAG:
				if (hdr->len == ORDER_LEN)
					apparam->order = hdr->val[0];
				break;
			case SEARCHATTRIB_TAG:
				if (hdr->len == SEARCHATTRIB_LEN)
					apparam->searchattrib = hdr->val[0];
				break;
			case SEARCHVALUE_TAG:
				apparam->searchval = g_try_malloc(hdr->len + 1);
				if (apparam->searchval != NULL) {
					memcpy(apparam->searchval, hdr->val,
								hdr->len);
					apparam->searchval[hdr->len] = '\0';
				}
				break;
			case FILTER_TAG:
				if (hdr->len == FILTER_LEN) {
					guint64 val;
					memcpy(&val, hdr->val, sizeof(val));
					apparam->filter = get_be64(&val);
				}
				break;
			case FORMAT_TAG:
				if (hdr->len == FORMAT_LEN)
					apparam->format = hdr->val[0];
				break;
			case MAXLISTCOUNT_TAG:
				if (hdr->len == MAXLISTCOUNT_LEN) {
					guint16 val;
					memcpy(&val, hdr->val, sizeof(val));
					apparam->maxlistcount = get_be16(&val);
				}
				break;
			case LISTSTARTOFFSET_TAG:
				if (hdr->len == LISTSTARTOFFSET_LEN) {
					guint16 val;
					memcpy(&val, hdr->val, sizeof(val));
					apparam->liststartoffset = get_be16(&val);
				}
				break;
			default:
				g_free(apparam->searchval);
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

	return 0;
}

/* Add app parameter header, that is sent back to PBAP client */
static int pbap_add_result_apparam_header(obex_t *obex, obex_object_t *obj,
				guint16 maxlistcount, gchar *path_name,
				guint16 phonebooksize,
				guint8 newmissedcalls, gboolean *addbody)
{
	guint8 rspsize = 0;
	gboolean addmissedcalls = FALSE;
	obex_headerdata_t hd;

	if (maxlistcount == 0) {
		rspsize += APPARAM_HDR_SIZE + PHONEBOOKSIZE_LEN;
		*addbody = FALSE;
	}

	if (g_str_equal(path_name, SIM1_MCH) == TRUE ||
				g_str_equal(path_name, MCH) == TRUE) {
		rspsize += APPARAM_HDR_SIZE + NEWMISSEDCALLS_LEN;
		addmissedcalls = TRUE;
	}

	if (rspsize > 0) {
		void *buf, *ptr;

		buf = g_try_malloc0(rspsize);
		if (buf == NULL)
			return -ENOMEM;

		ptr = buf;

		if (maxlistcount == 0) {
			struct apparam_hdr *hdr = ptr;
			guint16 val = GUINT16_TO_BE(phonebooksize);

			hdr->tag = PHONEBOOKSIZE_TAG;
			hdr->len = PHONEBOOKSIZE_LEN;
			memcpy(hdr->val, &val, sizeof(val));

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

static int pbap_pullphonebook(obex_t *obex, obex_object_t *obj,
							gboolean *addbody)
{
	struct obex_session *session = OBEX_GetUserData(obex);
	struct apparam_field params;
	guint8 newmissedcalls = 0;
	guint16 phonebooksize = 0;
	int err;

	memset(&params, 0, sizeof(struct apparam_field));

	err = pbap_parse_apparam_header(obex, obj, &params);
	if (err < 0)
		return err;

	if (params.maxlistcount == 0) {
		phonebooksize = DEFAULT_COUNT;
		goto done;
	}

	err = phonebook_pullphonebook(obex, obj, params);
	if (err < 0)
		return err;

done:
	return pbap_add_result_apparam_header(obex, obj, params.maxlistcount,
						session->name, phonebooksize,
						newmissedcalls, addbody);
}

static int pbap_pullvcardlisting(obex_t *obex, obex_object_t *obj,
							gboolean *addbody)
{
	struct obex_session *session = OBEX_GetUserData(obex);
	gchar *fullname;
	struct apparam_field params;
	guint8 newmissedcalls = 0;
	guint16 phonebooksize = 0;
	int err;

	memset(&params, 0, sizeof(struct apparam_field));

	err = pbap_parse_apparam_header(obex, obj, &params);
	if (err < 0)
		return err;

	if (params.maxlistcount == 0) {
		phonebooksize = DEFAULT_COUNT;
		goto proceed;
	}

	/* libebook does not support sound attribute */
	if (params.searchattrib >= 2) {
		DBG("libebook does not support sound attribute");
		goto done;
	}

	err = phonebook_pullvcardlisting(obex, obj, params);
	if (err < 0)
		goto done;

proceed:

	fullname = g_build_filename(session->current_folder, session->name,
								NULL);
	if (fullname != NULL)
		fullname = g_strconcat(fullname, ".vcf", NULL);

	err = pbap_add_result_apparam_header(obex, obj, params.maxlistcount,
						fullname, phonebooksize,
						newmissedcalls, addbody);
	g_free(fullname);

done:
	g_free(params.searchval);
	return err;
}

static int pbap_pullvcardentry(obex_t *obex, obex_object_t *obj)
{
	struct apparam_field params;
	int err;

	memset(&params, 0, sizeof(struct apparam_field));
	err = pbap_parse_apparam_header(obex, obj, &params);
	if (err < 0)
		return err;

	err = phonebook_pullvcardentry(obex, obj, params);

	g_free(params.searchval);
	return err;
}

static void pbap_connect(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os = OBEX_GetUserData(obex);
	obex_headerdata_t hd;

	register_session(os->cid, os);
	emit_session_created(os->cid);

	/* Append received UUID in WHO header */
	hd.bs = PBAP_TARGET;
	OBEX_ObjectAddHeader(obex, obj,
			OBEX_HDR_WHO, hd, sizeof(PBAP_TARGET),
			OBEX_FL_FIT_ONE_PACKET);
	hd.bq4 = os->cid;
	OBEX_ObjectAddHeader(obex, obj,
			OBEX_HDR_CONNECTION, hd, 4,
			OBEX_FL_FIT_ONE_PACKET);

	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
}

static void pbap_get(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *session = OBEX_GetUserData(obex);
	obex_headerdata_t hd;
	gboolean addbody = TRUE;
	int err;

	if (session == NULL)
		return;

	if (session->type == NULL)
		goto fail;

	if (g_str_equal(session->type, VCARDLISTING_TYPE) == FALSE
						&& session->name == NULL)
		goto fail;

	OBEX_ObjectReParseHeaders(obex, obj);

	if (g_str_equal(session->type, PHONEBOOK_TYPE) == TRUE)
		err = pbap_pullphonebook(obex, obj, &addbody);
	else if (g_str_equal(session->type, VCARDLISTING_TYPE) == TRUE)
		err = pbap_pullvcardlisting(obex, obj, &addbody);
	else if (g_str_equal(session->type, VCARDENTRY_TYPE) == TRUE)
		err = pbap_pullvcardentry(obex, obj);
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

static void pbap_setpath(obex_t *obex, obex_object_t *obj)
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

	if (session->current_folder == NULL)
		fullname = g_build_filename("", session->name, NULL);
	else
		fullname = g_build_filename(session->current_folder, session->name, NULL);

	debug("Fullname: %s", fullname);

	g_free(session->current_folder);
	session->current_folder = fullname;
	OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
}

static void pbap_disconnect(obex_t *obex)
{
	struct obex_session *os = OBEX_GetUserData(obex);

	emit_session_removed(os->cid);
	unregister_session(os->cid);
}

struct obex_service_driver pbap = {
	.name = "Phonebook Access server",
	.service = OBEX_PBAP,
	.channel = PBAP_CHANNEL,
	.record = PBAP_RECORD,
	.target = PBAP_TARGET,
	.target_size = TARGET_SIZE,
	.connect = pbap_connect,
	.get = pbap_get,
	.setpath = pbap_setpath,
	.disconnect = pbap_disconnect
};

static int pbap_init(void)
{
	return obex_service_driver_register(&pbap);
}

static void pbap_exit(void)
{
	obex_service_driver_unregister(&pbap);
}

OBEX_PLUGIN_DEFINE(pbap, pbap_init, pbap_exit)
