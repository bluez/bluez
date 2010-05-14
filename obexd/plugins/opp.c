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
#include <string.h>

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

static gpointer opp_connect(struct obex_session *os, int *err)
{
	manager_register_transfer(os);

	if (err)
		*err = 0;

	return NULL;
}

static void opp_progress(struct obex_session *os, gpointer user_data)
{
	manager_emit_transfer_progress(os);
}

static gint opp_chkput(struct obex_session *os, gpointer user_data)
{
	gchar *folder, *name;
	gchar *path;
	gint32 time;
	gint ret;

	if (obex_get_size(os) == OBJECT_SIZE_DELETE)
		return -EINVAL;

	if (obex_get_auto_accept(os)) {
		folder = g_strdup(obex_get_root_folder(os));
		name = g_strdup(obex_get_name(os));
		goto skip_auth;
	}

	time = 0;
	ret = manager_request_authorization(os, time, &folder, &name);
	if (ret < 0)
		return -EPERM;

	if (folder == NULL)
		folder = g_strdup(obex_get_root_folder(os));

	if (name == NULL)
		name = g_strdup(obex_get_name(os));

skip_auth:
	if (name == NULL || strlen(name) == 0)
		return -EBADR;

	path = g_build_filename(folder, name, NULL);

	manager_emit_transfer_started(os);

	ret = obex_put_stream_start(os, path);

	g_free(path);
	g_free(folder);
	g_free(name);

	return ret;
}

static int opp_put(struct obex_session *os, gpointer user_data)
{
	const char *name = obex_get_name(os);
	const char *folder = obex_get_root_folder(os);

	if (folder == NULL)
		return -EPERM;

	if (name == NULL)
		return -EBADR;

	return 0;
}

static int opp_get(struct obex_session *os, obex_object_t *obj,
			gboolean *stream, gpointer user_data)
{
	const char *type;

	if (obex_get_name(os))
		return -EPERM;

	type = obex_get_type(os);

	if (type == NULL)
		return -EPERM;

	if (g_str_equal(type, VCARD_TYPE)) {
		if (obex_get_stream_start(os, VCARD_FILE) < 0)
			return -ENOENT;

	} else
		return -EPERM;

	if (stream)
		*stream = TRUE;

	return 0;
}

static void opp_disconnect(struct obex_session *os, gpointer user_data)
{
	manager_unregister_transfer(os);
}

static void opp_reset(struct obex_session *os, gpointer user_data)
{
	manager_emit_transfer_completed(os);
}

static struct obex_service_driver driver = {
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
