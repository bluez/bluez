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

#include <errno.h>
#include <glib.h>
#include <openobex/obex.h>

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "service.h"
#include "mimetype.h"
#include "dbus.h"

#include "messages.h"

/* Channel number according to bluez doc/assigned-numbers.txt */
#define MAS_CHANNEL	16

#define MAS_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>		\
<record>								\
  <attribute id=\"0x0001\">						\
    <sequence>								\
      <uuid value=\"0x1132\"/>						\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0004\">						\
    <sequence>								\
      <sequence>							\
        <uuid value=\"0x0100\"/>					\
      </sequence>							\
      <sequence>							\
        <uuid value=\"0x0003\"/>					\
        <uint8 value=\"%u\" name=\"channel\"/>				\
      </sequence>							\
      <sequence>							\
        <uuid value=\"0x0008\"/>					\
      </sequence>							\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0009\">						\
    <sequence>								\
      <sequence>							\
        <uuid value=\"0x1134\"/>					\
        <uint16 value=\"0x0100\" name=\"version\"/>			\
      </sequence>							\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0100\">						\
    <text value=\"%s\" name=\"name\"/>					\
  </attribute>								\
									\
  <attribute id=\"0x0315\">						\
    <uint8 value=\"0x00\"/>						\
  </attribute>								\
									\
  <attribute id=\"0x0316\">						\
    <uint8 value=\"0x0F\"/>						\
  </attribute>								\
</record>"

struct mas_session {
	struct mas_request *request;
};

static const uint8_t MAS_TARGET[TARGET_SIZE] = {
			0xbb, 0x58, 0x2b, 0x40, 0x42, 0x0c, 0x11, 0xdb,
			0xb0, 0xde, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66  };

static void mas_clean(struct mas_session *mas)
{
	g_free(mas);
}

static void *mas_connect(struct obex_session *os, int *err)
{
	struct mas_session *mas;

	DBG("");

	*err = 0;

	mas = g_new0(struct mas_session, 1);

	manager_register_session(os);

	return mas;
}

static void mas_disconnect(struct obex_session *os, void *user_data)
{
	struct mas_session *mas = user_data;

	DBG("");

	manager_unregister_session(os);

	mas_clean(mas);
}

static int mas_get(struct obex_session *os, obex_object_t *obj,
					gboolean *stream, void *user_data)
{
	struct mas_session *mas = user_data;
	const char *type = obex_get_type(os);
	const char *name = obex_get_name(os);
	int ret;

	DBG("GET: name %s type %s mas %p",
			name, type, mas);

	if (type == NULL)
		return -EBADR;

	*stream = FALSE;

	ret = obex_get_stream_start(os, name);
	if (ret < 0)
		goto failed;

	return 0;

failed:
	return ret;
}

static int mas_put(struct obex_session *os, obex_object_t *obj, void *user_data)
{
	struct mas_session *mas = user_data;
	const char *type = obex_get_type(os);
	const char *name = obex_get_name(os);
	int ret;

	DBG("PUT: name %s type %s mas %p", name, type, mas);

	if (type == NULL)
		return -EBADR;

	ret = obex_put_stream_start(os, name);
	if (ret < 0)
		goto failed;

	return 0;

failed:
	return ret;
}

static int mas_setpath(struct obex_session *os, obex_object_t *obj,
		void *user_data)
{
	const char *name;
	uint8_t *nonhdr;

	if (OBEX_ObjectGetNonHdrData(obj, &nonhdr) != 2) {
		error("Set path failed: flag and constants not found!");
		return -EBADR;
	}

	name = obex_get_name(os);

	DBG("SETPATH: name %s nonhdr 0x%x%x", name, nonhdr[0], nonhdr[1]);

	if ((nonhdr[0] & 0x02) != 0x02) {
		DBG("Error: requested directory creation");
		return -EBADR;
	}

	return 0;
}

static void *any_open(const char *name, int oflag, mode_t mode,
				void *driver_data, size_t *size, int *err)
{
	struct mas_session *mas = driver_data;

	DBG("");

	*err = 0;

	return mas;
}

static ssize_t any_write(void *object, const void *buf, size_t count)
{
	DBG("");

	return count;
}

static ssize_t any_read(void *obj, void *buf, size_t count,
				uint8_t *hi, unsigned int *flags)
{
	DBG("");

	*hi = OBEX_HDR_BODY;
	*flags = 0;

	return 0;
}

static int any_close(void *obj)
{
	DBG("");

	return 0;
}

static struct obex_service_driver mas = {
	.name = "Message Access server",
	.service = OBEX_MAS,
	.channel = MAS_CHANNEL,
	.record = MAS_RECORD,
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.connect = mas_connect,
	.get = mas_get,
	.put = mas_put,
	.setpath = mas_setpath,
	.disconnect = mas_disconnect,
};

static struct obex_mime_type_driver mime_map = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = NULL,
	.open = any_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static int mas_init(void)
{
	int err;

	err = messages_init();
	if (err < 0)
		return err;

	err = obex_mime_type_driver_register(&mime_map);
	if (err < 0)
		goto failed_mime;

	err = obex_service_driver_register(&mas);
	if (err < 0)
		goto failed_mas_reg;

	return 0;

failed_mas_reg:
	obex_mime_type_driver_unregister(&mime_map);

failed_mime:
	messages_exit();

	return err;
}

static void mas_exit(void)
{
	obex_service_driver_unregister(&mas);
	obex_mime_type_driver_unregister(&mime_map);
	messages_exit();
}

OBEX_PLUGIN_DEFINE(mas, mas_init, mas_exit)
