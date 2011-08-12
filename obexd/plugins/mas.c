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
#include <fcntl.h>

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "service.h"
#include "mimetype.h"
#include "filesystem.h"
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

#define XML_DECL "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"

/* Building blocks for x-obex/folder-listing */
#define FL_DTD "<!DOCTYPE folder-listing SYSTEM \"obex-folder-listing.dtd\">"
#define FL_BODY_BEGIN "<folder-listing version=\"1.0\">"
#define FL_BODY_EMPTY "<folder-listing version=\"1.0\"/>"
#define FL_PARENT_FOLDER_ELEMENT "<parent-folder/>"
#define FL_FOLDER_ELEMENT "<folder name=\"%s\"/>"
#define FL_BODY_END "</folder-listing>"

struct mas_session {
	struct mas_request *request;
	void *backend_data;
	gboolean finished;
	gboolean nth_call;
	GString *buffer;
};

static const uint8_t MAS_TARGET[TARGET_SIZE] = {
			0xbb, 0x58, 0x2b, 0x40, 0x42, 0x0c, 0x11, 0xdb,
			0xb0, 0xde, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66  };

static void reset_request(struct mas_session *mas)
{
	if (mas->buffer) {
		g_string_free(mas->buffer, TRUE);
		mas->buffer = NULL;
	}

	mas->nth_call = FALSE;
	mas->finished = FALSE;
}

static void mas_clean(struct mas_session *mas)
{
	reset_request(mas);
	g_free(mas);
}

static void *mas_connect(struct obex_session *os, int *err)
{
	struct mas_session *mas;

	DBG("");

	mas = g_new0(struct mas_session, 1);

	*err = messages_connect(&mas->backend_data);
	if (*err < 0)
		goto failed;

	manager_register_session(os);

	return mas;

failed:
	g_free(mas);

	return NULL;
}

static void mas_disconnect(struct obex_session *os, void *user_data)
{
	struct mas_session *mas = user_data;

	DBG("");

	manager_unregister_session(os);
	messages_disconnect(mas->backend_data);

	mas_clean(mas);
}

static int mas_get(struct obex_session *os, obex_object_t *obj, void *user_data)
{
	struct mas_session *mas = user_data;
	const char *type = obex_get_type(os);
	const char *name = obex_get_name(os);
	int ret;

	DBG("GET: name %s type %s mas %p",
			name, type, mas);

	if (type == NULL)
		return -EBADR;

	ret = obex_get_stream_start(os, name);
	if (ret < 0)
		goto failed;

	return 0;

failed:
	reset_request(mas);

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
	reset_request(mas);

	return ret;
}

/* FIXME: Preserve whitespaces */
static void g_string_append_escaped_printf(GString *string, const gchar *format,
		...)
{
	va_list ap;
	char *escaped;

	va_start(ap, format);
	escaped = g_markup_vprintf_escaped(format, ap);
	g_string_append(string, escaped);
	g_free(escaped);
	va_end(ap);
}

static void get_folder_listing_cb(void *session, int err, uint16_t size,
					const char *name, void *user_data)
{
	struct mas_session *mas = user_data;

	if (err < 0 && err != -EAGAIN) {
		obex_object_set_io_flags(mas, G_IO_ERR, err);
		return;
	}

	if (!mas->nth_call) {
		g_string_append(mas->buffer, XML_DECL);
		g_string_append(mas->buffer, FL_DTD);
		if (!name) {
			g_string_append(mas->buffer, FL_BODY_EMPTY);
			mas->finished = TRUE;
			goto proceed;
		}
		g_string_append(mas->buffer, FL_BODY_BEGIN);
		mas->nth_call = TRUE;
	}

	if (!name) {
		g_string_append(mas->buffer, FL_BODY_END);
		mas->finished = TRUE;
		goto proceed;
	}

	if (g_strcmp0(name, "..") == 0)
		g_string_append(mas->buffer, FL_PARENT_FOLDER_ELEMENT);
	else
		g_string_append_escaped_printf(mas->buffer, FL_FOLDER_ELEMENT,
									name);

proceed:
	if (err != -EAGAIN)
		obex_object_set_io_flags(mas, G_IO_IN, err);
}

static int mas_setpath(struct obex_session *os, obex_object_t *obj,
		void *user_data)
{
	const char *name;
	uint8_t *nonhdr;
	struct mas_session *mas = user_data;

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

	return messages_set_folder(mas->backend_data, name, nonhdr[0] & 0x01);
}

static void *folder_listing_open(const char *name, int oflag, mode_t mode,
				void *driver_data, size_t *size, int *err)
{
	struct mas_session *mas = driver_data;

	if (oflag != O_RDONLY) {
		*err = -EBADR;
		return NULL;
	}

	DBG("name = %s", name);

	/* 1024 is the default when there was no MaxListCount sent */
	*err = messages_get_folder_listing(mas->backend_data, name, 1024, 0,
			get_folder_listing_cb, mas);

	mas->buffer = g_string_new("");

	if (*err < 0)
		return NULL;
	else
		return mas;
}

static void *any_open(const char *name, int oflag, mode_t mode,
				void *driver_data, size_t *size, int *err)
{
	DBG("");

	*err = -EINVAL;

	return NULL;
}

static ssize_t any_write(void *object, const void *buf, size_t count)
{
	DBG("");

	return count;
}

static ssize_t any_read(void *obj, void *buf, size_t count)
{
	struct mas_session *mas = obj;
	ssize_t len;

	DBG("");

	len = string_read(mas->buffer, buf, count);

	if (len == 0 && !mas->finished)
		return -EAGAIN;

	return len;
}

static int any_close(void *obj)
{
	struct mas_session *mas = obj;

	DBG("");

	if (!mas->finished)
		messages_abort(mas->backend_data);

	reset_request(mas);

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

static struct obex_mime_type_driver mime_message = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/message",
	.open = any_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver mime_folder_listing = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-obex/folder-listing",
	.open = folder_listing_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver mime_msg_listing = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/MAP-msg-listing",
	.open = any_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver mime_notification_registration = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/MAP-NotificationRegistration",
	.open = any_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver mime_message_status = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/messageStatus",
	.open = any_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver mime_message_update = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/MAP-messageUpdate",
	.open = any_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver *map_drivers[] = {
	&mime_map,
	&mime_message,
	&mime_folder_listing,
	&mime_msg_listing,
	&mime_notification_registration,
	&mime_message_status,
	&mime_message_update,
	NULL
};

static int mas_init(void)
{
	int err;
	int i;

	err = messages_init();
	if (err < 0)
		return err;

	for (i = 0; map_drivers[i] != NULL; ++i) {
		err = obex_mime_type_driver_register(map_drivers[i]);
		if (err < 0)
			goto failed;
	}

	err = obex_service_driver_register(&mas);
	if (err < 0)
		goto failed;

	return 0;

failed:
	for (--i; i >= 0; --i)
		obex_mime_type_driver_unregister(map_drivers[i]);

	messages_exit();

	return err;
}

static void mas_exit(void)
{
	int i;

	obex_service_driver_unregister(&mas);

	for (i = 0; map_drivers[i] != NULL; ++i)
		obex_mime_type_driver_unregister(map_drivers[i]);

	messages_exit();
}

OBEX_PLUGIN_DEFINE(mas, mas_init, mas_exit)
