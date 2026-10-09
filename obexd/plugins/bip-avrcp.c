// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  OBEX Server - AVRCP Cover Art responder
 *
 *  Copyright (C) 2026  Jan-Michael Brummer <jan.brummer@tabos.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "gdbus/gdbus.h"

#include "obexd/src/obexd.h"
#include "obexd/src/plugin.h"
#include "obexd/src/obex.h"
#include "obexd/src/service.h"
#include "obexd/src/mimetype.h"
#include "obexd/src/log.h"
#include "obexd/src/manager.h"

/* AVRCP 1.6 section 5.14.2.1 */
#define COVER_ART_TARGET ((const uint8_t *) \
	"\x71\x63\xDD\x54\x4A\x7E\x11\xE2\xB4\x7C\x00\x50\xC2\x49\x00\x48")
#define COVER_ART_TARGET_SIZE 16

#define COVER_ART_MAX_SIZE (1024 * 1024)

#define MPRIS_PREFIX "org.mpris.MediaPlayer2."
#define MPRIS_PLAYER_INTERFACE "org.mpris.MediaPlayer2.Player"

struct cover_art_object {
	int fd;
	char *contents;		/* Properties document, NULL for images */
	size_t size;
	size_t offset;
};

/*
 * The image handle is derived from the art URL, the same way bluetoothd
 * derives the value it reports in AVRCP attribute 0x08. Keep in sync with
 * profiles/audio/media.c.
 */
static void cover_art_handle(const char *url, char *handle, size_t len)
{
	snprintf(handle, len, "%07u", g_str_hash(url) % 10000000);
}

static char *mpris_get_art_url(DBusConnection *conn, const char *name)
{
	DBusMessage *msg, *reply;
	DBusMessageIter iter, variant, dict;
	const char *iface = MPRIS_PLAYER_INTERFACE;
	const char *prop = "Metadata";
	char *url = NULL;

	msg = dbus_message_new_method_call(name, "/org/mpris/MediaPlayer2",
					"org.freedesktop.DBus.Properties",
					"Get");
	if (msg == NULL)
		return NULL;

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &iface,
					DBUS_TYPE_STRING, &prop,
					DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, NULL);
	dbus_message_unref(msg);

	if (reply == NULL)
		return NULL;

	if (!dbus_message_iter_init(reply, &iter) ||
			dbus_message_iter_get_arg_type(&iter) !=
							DBUS_TYPE_VARIANT)
		goto done;

	dbus_message_iter_recurse(&iter, &variant);

	if (dbus_message_iter_get_arg_type(&variant) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&variant, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key, *str;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) !=
							DBUS_TYPE_VARIANT)
			break;

		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "mpris:artUrl") &&
				dbus_message_iter_get_arg_type(&value) ==
							DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&value, &str);
			url = g_strdup(str);
			break;
		}

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);

	return url;
}

/*
 * Controllers fetch lazily and commonly ask for the previous track's
 * handle after a track change, when the player no longer advertises that
 * art URL. Remember the last few resolved handles so those requests can
 * still be answered.
 */
#define COVER_ART_CACHE_SIZE 4

struct cover_art_entry {
	char handle[8];
	char *filename;
};

static GQueue cover_art_cache = G_QUEUE_INIT;

static void cover_art_cache_add(const char *handle, const char *filename)
{
	struct cover_art_entry *entry;
	GList *l;

	for (l = cover_art_cache.head; l != NULL; l = g_list_next(l)) {
		entry = l->data;

		if (!g_str_equal(entry->handle, handle))
			continue;

		g_queue_unlink(&cover_art_cache, l);
		g_queue_push_head_link(&cover_art_cache, l);
		return;
	}

	if (g_queue_get_length(&cover_art_cache) >= COVER_ART_CACHE_SIZE) {
		entry = g_queue_pop_tail(&cover_art_cache);
		g_free(entry->filename);
		g_free(entry);
	}

	entry = g_new0(struct cover_art_entry, 1);
	strncpy(entry->handle, handle, sizeof(entry->handle) - 1);
	entry->filename = g_strdup(filename);

	g_queue_push_head(&cover_art_cache, entry);
}

static char *cover_art_cache_lookup(const char *handle)
{
	GList *l;

	for (l = cover_art_cache.head; l != NULL; l = g_list_next(l)) {
		struct cover_art_entry *entry = l->data;

		if (g_str_equal(entry->handle, handle))
			return g_strdup(entry->filename);
	}

	return NULL;
}

static void cover_art_cache_clear(void)
{
	struct cover_art_entry *entry;

	while ((entry = g_queue_pop_head(&cover_art_cache)) != NULL) {
		g_free(entry->filename);
		g_free(entry);
	}
}

/*
 * Find the file a handle refers to by asking every MPRIS player on the bus
 * for its current art URL and hashing it. Players are few and the lookup
 * only happens when a controller actually fetches an image.
 */
static char *cover_art_lookup(const char *handle)
{
	DBusConnection *conn = obex_get_dbus_connection();
	DBusMessage *msg, *reply;
	DBusMessageIter iter, array;
	char *filename = NULL;

	if (handle == NULL)
		return NULL;

	filename = cover_art_cache_lookup(handle);
	if (filename != NULL)
		return filename;

	if (conn == NULL)
		return NULL;

	msg = dbus_message_new_method_call("org.freedesktop.DBus",
					"/org/freedesktop/DBus",
					"org.freedesktop.DBus", "ListNames");
	if (msg == NULL)
		return NULL;

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, NULL);
	dbus_message_unref(msg);

	if (reply == NULL)
		return NULL;

	if (!dbus_message_iter_init(reply, &iter) ||
			dbus_message_iter_get_arg_type(&iter) !=
							DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRING) {
		const char *name;
		char *url;
		char h[8];

		dbus_message_iter_get_basic(&array, &name);
		dbus_message_iter_next(&array);

		if (!g_str_has_prefix(name, MPRIS_PREFIX))
			continue;

		url = mpris_get_art_url(conn, name);
		if (url == NULL)
			continue;

		cover_art_handle(url, h, sizeof(h));

		if (g_str_equal(h, handle)) {
			filename = g_filename_from_uri(url, NULL, NULL);

			if (filename != NULL)
				cover_art_cache_add(handle, filename);
		}

		g_free(url);

		if (filename != NULL)
			break;
	}

done:
	dbus_message_unref(reply);

	return filename;
}

static void *cover_art_open_image(const char *name, int oflag, mode_t mode,
					void *context, size_t *size, int *err)
{
	struct cover_art_object *obj;
	struct stat st;
	char *filename;
	int fd;

	if (oflag != O_RDONLY) {
		if (err)
			*err = -EPERM;
		return NULL;
	}

	filename = cover_art_lookup(name);
	if (filename == NULL) {
		DBG("no image for handle %s", name ? name : "(none)");
		if (err)
			*err = -ENOENT;
		return NULL;
	}

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	g_free(filename);

	if (fd < 0) {
		if (err)
			*err = -errno;
		return NULL;
	}

	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
					st.st_size > COVER_ART_MAX_SIZE) {
		close(fd);
		if (err)
			*err = -EINVAL;
		return NULL;
	}

	obj = g_new0(struct cover_art_object, 1);
	obj->fd = fd;
	obj->size = st.st_size;

	if (size)
		*size = obj->size;

	if (err)
		*err = 0;

	return obj;
}

/*
 * Parse the JPEG start-of-frame marker for the image dimensions, which the
 * image-properties document has to carry.
 */
static gboolean jpeg_dimensions(int fd, unsigned int *width,
						unsigned int *height)
{
	uint8_t buf[4];
	off_t pos = 2;

	if (lseek(fd, 0, SEEK_SET) < 0)
		return FALSE;

	if (read(fd, buf, 2) != 2 || buf[0] != 0xff || buf[1] != 0xd8)
		return FALSE;

	while (lseek(fd, pos, SEEK_SET) >= 0 && read(fd, buf, 4) == 4) {
		uint16_t len = (buf[2] << 8) | buf[3];

		if (buf[0] != 0xff)
			return FALSE;

		/* SOF0..SOF3, SOF5..SOF7, SOF9..SOF11, SOF13..SOF15 */
		if (buf[1] >= 0xc0 && buf[1] <= 0xcf &&
				buf[1] != 0xc4 && buf[1] != 0xc8 &&
				buf[1] != 0xcc) {
			uint8_t sof[5];

			if (read(fd, sof, 5) != 5)
				return FALSE;

			*height = (sof[1] << 8) | sof[2];
			*width = (sof[3] << 8) | sof[4];

			return TRUE;
		}

		if (len < 2)
			return FALSE;

		pos += 2 + len;
	}

	return FALSE;
}

static void *cover_art_open_properties(const char *name, int oflag,
					mode_t mode, void *context,
					size_t *size, int *err)
{
	struct cover_art_object *obj;
	unsigned int width = 0, height = 0;
	GString *props;

	obj = cover_art_open_image(name, oflag, mode, context, NULL, err);
	if (obj == NULL)
		return NULL;

	if (!jpeg_dimensions(obj->fd, &width, &height)) {
		close(obj->fd);
		g_free(obj);
		if (err)
			*err = -EINVAL;
		return NULL;
	}

	props = g_string_new("<image-properties version=\"1.0\" handle=\"");
	g_string_append_printf(props, "%s\">\n", name);
	g_string_append_printf(props,
		"<native encoding=\"JPEG\" pixel=\"%ux%u\" size=\"%zu\"/>\n",
		width, height, obj->size);
	g_string_append(props, "</image-properties>\n");

	close(obj->fd);
	obj->fd = -1;
	obj->size = props->len;
	obj->contents = g_string_free(props, FALSE);

	if (size)
		*size = obj->size;

	return obj;
}

static ssize_t cover_art_read(void *object, void *buf, size_t count)
{
	struct cover_art_object *obj = object;
	ssize_t len;

	if (obj->contents != NULL) {
		len = MIN(count, obj->size - obj->offset);
		memcpy(buf, obj->contents + obj->offset, len);
		obj->offset += len;

		return len;
	}

	len = read(obj->fd, buf, count);
	if (len < 0)
		return -errno;

	return len;
}

static int cover_art_close(void *object)
{
	struct cover_art_object *obj = object;

	if (obj->fd >= 0)
		close(obj->fd);

	g_free(obj->contents);
	g_free(obj);

	return 0;
}

static void *cover_art_connect(struct obex_session *os, int *err)
{
	DBG("");

	manager_register_session(os);

	if (err)
		*err = 0;

	return NULL;
}

static void cover_art_disconnect(struct obex_session *os, void *user_data)
{
	DBG("");

	manager_unregister_session(os);
}

static int cover_art_get(struct obex_session *os, void *user_data)
{
	const char *type = obex_get_type(os);
	const char *handle = obex_get_img_handle(os);

	DBG("type %s handle %s", type ? type : "(none)",
					handle ? handle : "(none)");

	if (type == NULL || handle == NULL)
		return -EBADR;

	return obex_get_stream_start(os, handle);
}

static const struct obex_service_driver cover_art = {
	.name = "AVRCP Cover Art server",
	.service = OBEX_BIP,
	.target = COVER_ART_TARGET,
	.target_size = COVER_ART_TARGET_SIZE,
	.connect = cover_art_connect,
	.get = cover_art_get,
	.disconnect = cover_art_disconnect,
};

static const struct obex_mime_type_driver properties = {
	.target = COVER_ART_TARGET,
	.target_size = COVER_ART_TARGET_SIZE,
	.mimetype = "x-bt/img-properties",
	.open = cover_art_open_properties,
	.close = cover_art_close,
	.read = cover_art_read,
};

/*
 * The linked thumbnail is served in the image's native encoding rather
 * than the 200x200 JPEG the specification describes: scaling would mean
 * decoding images inside obexd. Controllers seen so far accept it.
 */
static const struct obex_mime_type_driver thumbnail = {
	.target = COVER_ART_TARGET,
	.target_size = COVER_ART_TARGET_SIZE,
	.mimetype = "x-bt/img-thm",
	.open = cover_art_open_image,
	.close = cover_art_close,
	.read = cover_art_read,
};

static const struct obex_mime_type_driver image = {
	.target = COVER_ART_TARGET,
	.target_size = COVER_ART_TARGET_SIZE,
	.mimetype = "x-bt/img-img",
	.open = cover_art_open_image,
	.close = cover_art_close,
	.read = cover_art_read,
};

static int bip_avrcp_init(void)
{
	int err;

	err = obex_mime_type_driver_register(&properties);
	if (err < 0)
		return err;

	err = obex_mime_type_driver_register(&thumbnail);
	if (err < 0)
		goto failed_thumbnail;

	err = obex_mime_type_driver_register(&image);
	if (err < 0)
		goto failed_image;

	err = obex_service_driver_register(&cover_art);
	if (err < 0)
		goto failed_service;

	return 0;

failed_service:
	obex_mime_type_driver_unregister(&image);
failed_image:
	obex_mime_type_driver_unregister(&thumbnail);
failed_thumbnail:
	obex_mime_type_driver_unregister(&properties);

	return err;
}

static void bip_avrcp_exit(void)
{
	cover_art_cache_clear();

	obex_service_driver_unregister(&cover_art);
	obex_mime_type_driver_unregister(&image);
	obex_mime_type_driver_unregister(&thumbnail);
	obex_mime_type_driver_unregister(&properties);
}

OBEX_PLUGIN_DEFINE(bip_avrcp, bip_avrcp_init, bip_avrcp_exit)
