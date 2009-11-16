/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Nokia Corporation
 *  Copyright (C) 2007-2008  Instituto Nokia de Tecnologia (INdT)
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

#include <errno.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include <glib.h>

#include "plugin.h"
#include "service.h"
#include "logging.h"
#include "obex.h"
#include "dbus.h"

#define VCARD_TYPE "text/x-vcard"
#define VCARD_FILE CONFIGDIR "/vcard.vcf"

#define OPP_CHANNEL	9
#define OPP_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>	\
<record>									\
  <attribute id=\"0x0001\">							\
    <sequence>									\
      <uuid value=\"0x1105\"/>							\
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
        <uuid value=\"0x1105\"/>						\
        <uint16 value=\"0x0100\" name=\"version\"/>				\
      </sequence>								\
    </sequence>									\
  </attribute>									\
										\
  <attribute id=\"0x0100\">							\
    <text value=\"%s\" name=\"name\"/>						\
  </attribute>									\
										\
  <attribute id=\"0x0303\">							\
    <sequence>									\
      <uint8 value=\"0x01\"/>							\
      <uint8 value=\"0x01\"/>							\
      <uint8 value=\"0x02\"/>							\
      <uint8 value=\"0x03\"/>							\
      <uint8 value=\"0x04\"/>							\
      <uint8 value=\"0x05\"/>							\
      <uint8 value=\"0x06\"/>							\
      <uint8 value=\"0xff\"/>							\
    </sequence>									\
  </attribute>									\
</record>"

static void opp_connect(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os = OBEX_GetUserData(obex);

	register_transfer(os->cid, os);
	/* OPP doesn't contains target or connection id. */
	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
}

static void opp_progress(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os = OBEX_GetUserData(obex);

	emit_transfer_progress(os->cid, os->size, os->offset);
}

static gint opp_chkput(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;
	gchar *new_folder, *new_name;
	gint32 time;
	gint ret;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return -EINVAL;

	if (!os->name)
		return -EINVAL;

	if (os->size == OBJECT_SIZE_DELETE)
		return -EINVAL;

	if (os->server->auto_accept)
		goto skip_auth;

	time = 0;
	ret = request_authorization(os->cid, OBEX_GetFD(obex),
					os->name ? os->name : "",
					os->type ? os->type : "",
					os->size, time, &new_folder,
					&new_name);

	if (ret < 0)
		return -EPERM;

	if (new_folder) {
		g_free(os->current_folder);
		os->current_folder = new_folder;
	}

	if (new_name) {
		g_free(os->name);
		os->name = new_name;
	}

skip_auth:
	emit_transfer_started(os->cid);
	return os_prepare_put(os);
}

static void opp_put(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return;

	if (os->current_folder == NULL) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return;
	}

	if (os->name == NULL) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_BAD_REQUEST, OBEX_RSP_BAD_REQUEST);
		return;
	}

	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
}

static void opp_get(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;
	obex_headerdata_t hv;
	size_t size;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return;

	if (os->name)
		goto fail;

	if (os->type == NULL)
		goto fail;

	if (g_str_equal(os->type, VCARD_TYPE)) {
		if (os_prepare_get(os, VCARD_FILE, &size) < 0)
			goto fail;
	} else
		goto fail;


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

static void opp_disconnect(obex_t *obex)
{
	struct obex_session *os = OBEX_GetUserData(obex);

	/* Got an error during a transfer. */
	if (os->object)
		emit_transfer_completed(os->cid, os->offset == os->size);

	unregister_transfer(os->cid);
}

static void opp_reset(obex_t *obex)
{
	struct obex_session *os = OBEX_GetUserData(obex);

	emit_transfer_completed(os->cid, !os->aborted);
}

struct obex_service_driver driver = {
	.name = "Object Push server",
	.service = OBEX_OPP,
	.channel = OPP_CHANNEL,
	.record = OPP_RECORD,
	.connect = opp_connect,
	.progress = opp_progress,
	.disconnect = opp_disconnect,
	.get = opp_get,
	.put = opp_put,
	.chkput = opp_chkput,
	.reset = opp_reset
};

static int opp_init(void)
{
	return obex_service_driver_register(&driver);
}

static void opp_exit(void)
{
	obex_service_driver_unregister(&driver);
}

OBEX_PLUGIN_DEFINE(opp, opp_init, opp_exit)
