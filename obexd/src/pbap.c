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

#include "phonebook.h"
#include "logging.h"
#include "obex.h"

#define PHONEBOOK_TYPE "x-bt/phonebook"

static void test_phonebook(void)
{
	struct phonebook_context *context;
	struct phonebook_driver *driver;

	driver = phonebook_get_driver(NULL);
	if (driver == NULL)
		return;

	context = phonebook_create(driver);
	if (context == NULL)
		return;

	phonebook_pullphonebook(context);

	phonebook_unref(context);
}

void pbap_get(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;
	obex_headerdata_t hv;
	guint32 size;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return;

	if (os->type == NULL)
		goto fail;

	if (g_str_equal(os->type, PHONEBOOK_TYPE) == FALSE)
		goto fail;

	test_phonebook();
	size = 0;

	hv.bq4 = size;
	OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_LENGTH, hv, 4, 0);

	/* Add body header */
	hv.bs = NULL;
	if (size == 0)
		OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_BODY,
						hv, 0, OBEX_FL_FIT_ONE_PACKET);
	else
		OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_BODY,
						hv, 0, OBEX_FL_STREAM_START);

	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);

	return;

fail:
	OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
}
