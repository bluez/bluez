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

#include "logging.h"
#include "obex.h"

#define PHONEBOOK_TYPE "x-bt/phonebook"

static GSList *session_list = NULL;

void pbap_get(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *session;
	obex_headerdata_t hv;
	int ret;

	session = OBEX_GetUserData(obex);
	if (session == NULL)
		return;

	if (session->type == NULL)
		goto fail;

	if (g_str_equal(session->type, PHONEBOOK_TYPE) == FALSE)
		goto fail;

	ret = phonebook_pullphonebook(session->pbctx);

	if (!ret) {
		OBEX_SuspendRequest(obex, obj);
		session->size = 0;
	}
	else
		goto fail;

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
