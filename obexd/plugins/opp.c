/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Nokia Corporation
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include "obex.h"
#include "service.h"
#include "logging.h"
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

static int opp_connect(struct OBEX_session *os)
{
	manager_register_transfer(os);

	return 0;
}

static void opp_progress(struct OBEX_session *os)
{
	manager_emit_transfer_progress(os);
}

static gint opp_chkput(struct OBEX_session *os)
{
	gchar *new_folder, *new_name;
	gint32 time;
	gint ret;

	if (obex_get_size(os) == OBJECT_SIZE_DELETE)
		return -EINVAL;

	if (obex_get_auto_accept(os))
		goto skip_auth;

	time = 0;
	ret = manager_request_authorization(os, time, &new_folder, &new_name);
	if (ret < 0)
		return -EPERM;

	if (new_folder) {
		obex_set_folder(os, new_folder);
		g_free(new_folder);
	}

	if (new_name) {
		obex_set_name(os, new_name);
		g_free(new_name);
	}

skip_auth:
	manager_emit_transfer_started(os);
	return obex_prepare_put(os);
}

static int opp_put(struct OBEX_session *os)
{
	const char *name = obex_get_name(os);
	const char *folder = obex_get_folder(os);

	if (folder == NULL)
		return -EPERM;

	if (name == NULL)
		return -EBADR;

	return 0;
}

static int opp_get(struct OBEX_session *os, obex_object_t *obj)
{
	const char *type;

	if (obex_get_name(os) == NULL)
		return -EPERM;

	type = obex_get_type(os);

	if (type == NULL)
		return -EPERM;

	if (g_str_equal(type, VCARD_TYPE)) {
		if (obex_stream_start(os, VCARD_FILE) < 0)
			return -ENOENT;

	} else
		return -EPERM;

	return 0;
}

static void opp_disconnect(struct OBEX_session *os)
{
	manager_unregister_transfer(os);
}

static void opp_reset(struct OBEX_session *os)
{
	manager_emit_transfer_completed(os);
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
