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

#include <string.h>
#include <errno.h>
#include <glib.h>
#include <fcntl.h>
#include <inttypes.h>

#include <gobex/gobex.h>

#include "obexd.h"
#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "service.h"
#include "mimetype.h"
#include "filesystem.h"
#include "manager.h"
#include "map_ap.h"

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

#define ML_BODY_BEGIN "<MAP-msg-listing version=\"1.0\">"
#define ML_BODY_END "</MAP-msg-listing>"

struct mas_session {
	struct mas_request *request;
	void *backend_data;
	gboolean finished;
	gboolean nth_call;
	GString *buffer;
	map_ap_t *inparams;
	map_ap_t *outparams;
	gboolean ap_sent;
};

static const uint8_t MAS_TARGET[TARGET_SIZE] = {
			0xbb, 0x58, 0x2b, 0x40, 0x42, 0x0c, 0x11, 0xdb,
			0xb0, 0xde, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66  };

static int get_params(struct obex_session *os, struct mas_session *mas)
{
	const uint8_t *buffer;
	ssize_t size;

	size = obex_get_apparam(os, &buffer);
	if (size < 0)
		size = 0;

	mas->inparams = map_ap_decode(buffer, size);
	if (mas->inparams == NULL) {
		DBG("Error when parsing parameters!");
		return -EBADR;
	}

	mas->outparams = map_ap_new();

	return 0;
}

static void reset_request(struct mas_session *mas)
{
	if (mas->buffer) {
		g_string_free(mas->buffer, TRUE);
		mas->buffer = NULL;
	}

	map_ap_free(mas->inparams);
	mas->inparams = NULL;
	map_ap_free(mas->outparams);
	mas->outparams = NULL;

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

static int mas_get(struct obex_session *os, void *user_data)
{
	struct mas_session *mas = user_data;
	const char *type = obex_get_type(os);
	const char *name = obex_get_name(os);
	int ret;

	DBG("GET: name %s type %s mas %p",
			name, type, mas);

	if (type == NULL)
		return -EBADR;

	ret = get_params(os, mas);
	if (ret < 0)
		goto failed;

	ret = obex_get_stream_start(os, name);
	if (ret < 0)
		goto failed;

	return 0;

failed:
	reset_request(mas);

	return ret;
}

static int mas_put(struct obex_session *os, void *user_data)
{
	struct mas_session *mas = user_data;
	const char *type = obex_get_type(os);
	const char *name = obex_get_name(os);
	int ret;

	DBG("PUT: name %s type %s mas %p", name, type, mas);

	if (type == NULL)
		return -EBADR;

	ret = get_params(os, mas);
	if (ret < 0)
		goto failed;

	ret = obex_put_stream_start(os, name);
	if (ret < 0)
		goto failed;

	return 0;

failed:
	reset_request(mas);

	return ret;
}

/* FIXME: Preserve whitespaces */
static void g_string_append_escaped_printf(GString *string,
						const gchar *format, ...)
{
	va_list ap;
	char *escaped;

	va_start(ap, format);
	escaped = g_markup_vprintf_escaped(format, ap);
	g_string_append(string, escaped);
	g_free(escaped);
	va_end(ap);
}

static const char *yesorno(gboolean a)
{
	if (a)
		return "yes";

	return "no";
}

static void get_messages_listing_cb(void *session, int err, uint16_t size,
					gboolean newmsg,
					const struct messages_message *entry,
					void *user_data)
{
	struct mas_session *mas = user_data;
	uint16_t max = 1024;

	if (err < 0 && err != -EAGAIN) {
		obex_object_set_io_flags(mas, G_IO_ERR, err);
		return;
	}

	map_ap_get_u16(mas->inparams, MAP_AP_MAXLISTCOUNT, &max);

	if (max == 0) {
		if (!entry)
			mas->finished = TRUE;

		goto proceed;
	}

	if (!mas->nth_call) {
		g_string_append(mas->buffer, ML_BODY_BEGIN);
		mas->nth_call = TRUE;
	}

	if (!entry) {
		g_string_append(mas->buffer, ML_BODY_END);
		mas->finished = TRUE;

		goto proceed;
	}

	g_string_append(mas->buffer, "<msg");

	g_string_append_escaped_printf(mas->buffer, " handle=\"%s\"",
								entry->handle);

	if (entry->mask & PMASK_SUBJECT)
		g_string_append_escaped_printf(mas->buffer, " subject=\"%s\"",
				entry->subject);

	if (entry->mask & PMASK_DATETIME)
		g_string_append_escaped_printf(mas->buffer, " datetime=\"%s\"",
				entry->datetime);

	if (entry->mask & PMASK_SENDER_NAME)
		g_string_append_escaped_printf(mas->buffer,
						" sender_name=\"%s\"",
						entry->sender_name);

	if (entry->mask & PMASK_SENDER_ADDRESSING)
		g_string_append_escaped_printf(mas->buffer,
						" sender_addressing=\"%s\"",
						entry->sender_addressing);

	if (entry->mask & PMASK_REPLYTO_ADDRESSING)
		g_string_append_escaped_printf(mas->buffer,
						" replyto_addressing=\"%s\"",
						entry->replyto_addressing);

	if (entry->mask & PMASK_RECIPIENT_NAME)
		g_string_append_escaped_printf(mas->buffer,
						" recipient_name=\"%s\"",
						entry->recipient_name);

	if (entry->mask & PMASK_RECIPIENT_ADDRESSING)
		g_string_append_escaped_printf(mas->buffer,
						" recipient_addressing=\"%s\"",
						entry->recipient_addressing);

	if (entry->mask & PMASK_TYPE)
		g_string_append_escaped_printf(mas->buffer, " type=\"%s\"",
				entry->type);

	if (entry->mask & PMASK_RECEPTION_STATUS)
		g_string_append_escaped_printf(mas->buffer,
						" reception_status=\"%s\"",
						entry->reception_status);

	if (entry->mask & PMASK_SIZE)
		g_string_append_escaped_printf(mas->buffer, " size=\"%s\"",
				entry->size);

	if (entry->mask & PMASK_ATTACHMENT_SIZE)
		g_string_append_escaped_printf(mas->buffer,
						" attachment_size=\"%s\"",
						entry->attachment_size);

	if (entry->mask & PMASK_TEXT)
		g_string_append_escaped_printf(mas->buffer, " text=\"%s\"",
				yesorno(entry->text));

	if (entry->mask & PMASK_READ)
		g_string_append_escaped_printf(mas->buffer, " read=\"%s\"",
				yesorno(entry->read));

	if (entry->mask & PMASK_SENT)
		g_string_append_escaped_printf(mas->buffer, " sent=\"%s\"",
				yesorno(entry->sent));

	if (entry->mask & PMASK_PROTECTED)
		g_string_append_escaped_printf(mas->buffer, " protected=\"%s\"",
				yesorno(entry->protect));

	if (entry->mask & PMASK_PRIORITY)
		g_string_append_escaped_printf(mas->buffer, " priority=\"%s\"",
				yesorno(entry->priority));

	g_string_append(mas->buffer, "/>\n");

proceed:
	if (!entry) {
		map_ap_set_u16(mas->outparams, MAP_AP_MESSAGESLISTINGSIZE,
							size);
		map_ap_set_u8(mas->outparams, MAP_AP_NEWMESSAGE,
							newmsg ? 1 : 0);
	}

	if (err != -EAGAIN)
		obex_object_set_io_flags(mas, G_IO_IN, 0);
}

static void get_message_cb(void *session, int err, gboolean fmore,
					const char *chunk, void *user_data)
{
	struct mas_session *mas = user_data;

	DBG("");

	if (err < 0 && err != -EAGAIN) {
		obex_object_set_io_flags(mas, G_IO_ERR, err);
		return;
	}

	if (!chunk) {
		mas->finished = TRUE;
		goto proceed;
	}

	g_string_append(mas->buffer, chunk);

proceed:
	if (err != -EAGAIN)
		obex_object_set_io_flags(mas, G_IO_IN, 0);
}

static void get_folder_listing_cb(void *session, int err, uint16_t size,
					const char *name, void *user_data)
{
	struct mas_session *mas = user_data;
	uint16_t max = 1024;

	if (err < 0 && err != -EAGAIN) {
		obex_object_set_io_flags(mas, G_IO_ERR, err);
		return;
	}

	map_ap_get_u16(mas->inparams, MAP_AP_MAXLISTCOUNT, &max);

	if (max == 0) {
		if (err != -EAGAIN)
			map_ap_set_u16(mas->outparams,
					MAP_AP_FOLDERLISTINGSIZE, size);

		if (!name)
			mas->finished = TRUE;

		goto proceed;
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

static void update_inbox_cb(void *session, int err, void *user_data)
{
	struct mas_session *mas = user_data;

	DBG("");

	mas->finished = TRUE;

	if (err < 0)
		obex_object_set_io_flags(mas, G_IO_ERR, err);
	else
		obex_object_set_io_flags(mas, G_IO_OUT, 0);
}

static int mas_setpath(struct obex_session *os, void *user_data)
{
	const char *name;
	const uint8_t *nonhdr;
	struct mas_session *mas = user_data;

	if (obex_get_non_header_data(os, &nonhdr) != 2) {
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
	/* 1024 is the default when there was no MaxListCount sent */
	uint16_t max = 1024;
	uint16_t offset = 0;

	if (oflag != O_RDONLY) {
		*err = -EBADR;
		return NULL;
	}

	DBG("name = %s", name);

	map_ap_get_u16(mas->inparams, MAP_AP_MAXLISTCOUNT, &max);
	map_ap_get_u16(mas->inparams, MAP_AP_STARTOFFSET, &offset);

	*err = messages_get_folder_listing(mas->backend_data, name, max,
					offset, get_folder_listing_cb, mas);

	mas->buffer = g_string_new("");

	if (*err < 0)
		return NULL;
	else
		return mas;
}

static void *msg_listing_open(const char *name, int oflag, mode_t mode,
				void *driver_data, size_t *size, int *err)
{
	struct mas_session *mas = driver_data;
	struct messages_filter filter = { 0, };
	/* 1024 is the default when there was no MaxListCount sent */
	uint16_t max = 1024;
	uint16_t offset = 0;

	DBG("");

	if (oflag != O_RDONLY) {
		*err = -EBADR;
		return NULL;
	}

	map_ap_get_u16(mas->inparams, MAP_AP_MAXLISTCOUNT, &max);
	map_ap_get_u16(mas->inparams, MAP_AP_STARTOFFSET, &offset);

	map_ap_get_u32(mas->inparams, MAP_AP_PARAMETERMASK,
						&filter.parameter_mask);
	map_ap_get_u8(mas->inparams, MAP_AP_FILTERMESSAGETYPE,
						&filter.type);
	filter.period_begin = map_ap_get_string(mas->inparams,
						MAP_AP_FILTERPERIODBEGIN);
	filter.period_end = map_ap_get_string(mas->inparams,
						MAP_AP_FILTERPERIODEND);
	map_ap_get_u8(mas->inparams, MAP_AP_FILTERREADSTATUS,
						&filter.read_status);
	filter.recipient = map_ap_get_string(mas->inparams,
						MAP_AP_FILTERRECIPIENT);
	filter.originator = map_ap_get_string(mas->inparams,
						MAP_AP_FILTERORIGINATOR);
	map_ap_get_u8(mas->inparams, MAP_AP_FILTERPRIORITY,
						&filter.priority);

	*err = messages_get_messages_listing(mas->backend_data, name, max,
			offset, &filter,
			get_messages_listing_cb, mas);

	mas->buffer = g_string_new("");

	if (*err < 0)
		return NULL;
	else
		return mas;
}

static void *message_open(const char *name, int oflag, mode_t mode,
				void *driver_data, size_t *size, int *err)
{
	struct mas_session *mas = driver_data;

	DBG("");

	if (oflag != O_RDONLY) {
		DBG("Message pushing unsupported");
		*err = -ENOSYS;

		return NULL;
	}

	*err = messages_get_message(mas->backend_data, name, 0,
			get_message_cb, mas);

	mas->buffer = g_string_new("");

	if (*err < 0)
		return NULL;
	else
		return mas;
}

static void *message_update_open(const char *name, int oflag, mode_t mode,
					void *driver_data, size_t *size,
					int *err)
{
	struct mas_session *mas = driver_data;

	DBG("");

	if (oflag != O_WRONLY) {
		*err = -EBADR;
		return NULL;
	}

	*err = messages_update_inbox(mas->backend_data, update_inbox_cb, mas);
	if (*err < 0)
		return NULL;
	else
		return mas;
}

static ssize_t any_get_next_header(void *object, void *buf, size_t mtu,
								uint8_t *hi)
{
	struct mas_session *mas = object;
	size_t len;
	uint8_t *apbuf;

	DBG("");

	if (mas->buffer->len == 0 && !mas->finished)
		return -EAGAIN;

	*hi = G_OBEX_HDR_APPARAM;

	if (mas->ap_sent)
		return 0;

	mas->ap_sent = TRUE;
	apbuf = map_ap_encode(mas->outparams, &len);

	if (len > mtu) {
		DBG("MTU is to small to fit application parameters header!");
		g_free(apbuf);

		return -EIO;
	}

	memcpy(buf, apbuf, len);

	return len;
}

static void *any_open(const char *name, int oflag, mode_t mode,
				void *driver_data, size_t *size, int *err)
{
	DBG("");

	*err = -ENOSYS;

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
	.secure = TRUE,
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
	.open = message_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver mime_folder_listing = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-obex/folder-listing",
	.get_next_header = any_get_next_header,
	.open = folder_listing_open,
	.close = any_close,
	.read = any_read,
	.write = any_write,
};

static struct obex_mime_type_driver mime_msg_listing = {
	.target = MAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/MAP-msg-listing",
	.open = msg_listing_open,
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
	.open = message_update_open,
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
