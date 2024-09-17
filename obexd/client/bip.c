/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2024  Collabora Ltd.
 *
 *
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "gdbus/gdbus.h"
#include "gobex/gobex.h"

#include "obexd/src/log.h"
#include "transfer.h"
#include "session.h"
#include "driver.h"
#include "bip-common.h"
#include "bip.h"

#define OBEX_BIP_AVRCP_UUID \
	"\x71\x63\xDD\x54\x4A\x7E\x11\xE2\xB4\x7C\x00\x50\xC2\x49\x00\x48"
#define OBEX_BIP_AVRCP_UUID_LEN 16

#define IMAGE_INTERFACE "org.bluez.obex.Image1"
#define ERROR_INTERFACE "org.bluez.obex.Error"
#define IMAGE_UUID "0000111A-0000-1000-8000-00805f9b34fb"

#define IMG_HANDLE_TAG  0x30
#define IMG_DESC_TAG    0x71

#define EOL_CHARS "\n"
#define IMG_DESC_BEGIN "<image-descriptor version=\"1.0\">" EOL_CHARS
#define IMG_BEGIN "<image encoding=\"%s\" pixel=\"%s\""
#define IMG_TRANSFORM " transformation=\"%s\""
#define IMG_END "/>" EOL_CHARS
#define IMG_DESC_END "</image-descriptor>" EOL_CHARS

static DBusConnection *conn;

struct bip_avrcp_data {
	struct obc_session *session;
};

static void image_properties_complete_cb(struct obc_session *session,
						struct obc_transfer *transfer,
						GError *err, void *user_data)
{
	DBusMessage *message = user_data;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	char *contents = NULL;
	size_t size;
	int perr;
	struct prop_object *prop = NULL;

	if (err != NULL) {
		reply = g_dbus_create_error(message,
					ERROR_INTERFACE ".Failed",
					"%s", err->message);
		goto done;
	}

	perr = obc_transfer_get_contents(transfer, &contents, &size);
	if (perr < 0) {
		reply = g_dbus_create_error(message,
						ERROR_INTERFACE ".Failed",
						"Error reading contents: %s",
						strerror(-perr));
		goto done;
	}

	prop = parse_properties(contents, size, &perr);
	if (prop == NULL) {
		reply = g_dbus_create_error(message,
						ERROR_INTERFACE ".Failed",
						"Error parsing contents: %s",
						strerror(-perr));
		goto done;
	}

	if (!verify_properties(prop)) {
		reply = g_dbus_create_error(message,
						ERROR_INTERFACE ".Failed",
						"Error verifying contents");
		goto done;
	}

	reply = dbus_message_new_method_return(message);
	dbus_message_iter_init_append(reply, &iter);
	append_properties(&iter, prop);

done:
	g_dbus_send_message(conn, reply);
	g_free(contents);
	dbus_message_unref(message);
}

static DBusMessage *get_image_properties(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct bip_avrcp_data *bip_avrcp = user_data;
	const char *handle = NULL;
	struct obc_transfer *transfer;
	GObexHeader *header;
	DBusMessage *reply = NULL;
	GError *err = NULL;

	DBG("");

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &handle,
				DBUS_TYPE_INVALID) == FALSE) {
		reply = g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);
		return reply;
	}

	transfer = obc_transfer_get("x-bt/img-properties", NULL, NULL, &err);
	if (transfer == NULL)
		goto fail;

	header = g_obex_header_new_unicode(IMG_HANDLE_TAG, handle);
	obc_transfer_add_header(transfer, header);

	if (!obc_session_queue(bip_avrcp->session, transfer,
			image_properties_complete_cb, message, &err))
		goto fail;

	dbus_message_ref(message);

	return NULL;

fail:
	reply = g_dbus_create_error(message, ERROR_INTERFACE ".Failed", "%s",
								err->message);
	g_error_free(err);
	return reply;
}

static DBusMessage *get_thumbnail(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct bip_avrcp_data *bip_avrcp = user_data;
	const char *handle = NULL, *image_path = NULL;
	struct obc_transfer *transfer;
	GObexHeader *header;
	DBusMessage *reply = NULL;
	GError *err = NULL;

	DBG("");

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &image_path,
				DBUS_TYPE_STRING, &handle,
				DBUS_TYPE_INVALID) == FALSE) {
		reply = g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);
		return reply;
	}

	transfer = obc_transfer_get("x-bt/img-thm", NULL, image_path, &err);
	if (transfer == NULL)
		goto fail;

	header = g_obex_header_new_unicode(IMG_HANDLE_TAG, handle);
	obc_transfer_add_header(transfer, header);

	if (!obc_session_queue(bip_avrcp->session, transfer, NULL, NULL, &err))
		goto fail;

	return obc_transfer_create_dbus_reply(transfer, message);

fail:
	reply = g_dbus_create_error(message, ERROR_INTERFACE ".Failed", "%s",
								err->message);
	g_error_free(err);
	return reply;
}

static gboolean parse_get_image_dict(DBusMessage *msg, char **path,
					char **handle, char **pixel,
					char **encoding, uint64_t *maxsize,
							char **transform)
{
	DBusMessageIter iter, array;

	DBG("");

	*path = NULL;
	*handle = NULL;
	*pixel = NULL;
	*encoding = NULL;
	*transform = NULL;

	dbus_message_iter_init(msg, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		goto failed;
	dbus_message_iter_get_basic(&iter, path);
	*path = g_strdup(*path);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		goto failed;
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, handle);
	*handle = g_strdup(*handle);
	dbus_message_iter_next(&iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		goto failed;

	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key, *val;

		dbus_message_iter_recurse(&array, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return FALSE;
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);
		switch (dbus_message_iter_get_arg_type(&value)) {
		case DBUS_TYPE_STRING:
			dbus_message_iter_get_basic(&value, &val);
			if (g_str_equal(key, "pixel")) {
				if (!parse_pixel_range(val, NULL, NULL, NULL))
					goto failed;
				*pixel = g_strdup(val);
			} else if (g_str_equal(key, "encoding")) {
				if (!verify_encoding(val))
					goto failed;
				*encoding = g_strdup(val);
				if (*encoding == NULL)
					goto failed;
			} else if (g_str_equal(key, "transformation")) {
				*transform = parse_transform(val);
				if (*transform == NULL)
					goto failed;
			}
			break;
		case DBUS_TYPE_UINT64:
			if (g_str_equal(key, "maxsize") == TRUE) {
				dbus_message_iter_get_basic(&value, maxsize);
				if (*maxsize == 0)
					goto failed;
			}
			break;
		}
		dbus_message_iter_next(&array);
	}

	if (*pixel == NULL)
		*pixel = strdup("");
	if (*encoding == NULL)
		*encoding = strdup("");

	DBG("pixel: '%s' encoding: '%s' maxsize: '%lu' transform: '%s'",
			*pixel, *encoding, *maxsize, *transform
	);

	return TRUE;
failed:
	g_free(*path);
	g_free(*handle);
	g_free(*pixel);
	g_free(*encoding);
	g_free(*transform);
	return FALSE;
}

static DBusMessage *get_image(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct bip_avrcp_data *bip_avrcp = user_data;
	char *handle = NULL, *image_path = NULL, *transform = NULL,
		*encoding = NULL, *pixel = NULL;
	uint64_t maxsize;
	struct obc_transfer *transfer;
	GObexHeader *header;
	DBusMessage *reply = NULL;
	GString *descriptor = NULL;
	GError *err = NULL;

	DBG("");

	if (!parse_get_image_dict(message, &image_path, &handle, &pixel,
					&encoding, &maxsize, &transform))
		return g_dbus_create_error(message,
				ERROR_INTERFACE ".InvalidArguments", NULL);

	transfer = obc_transfer_get("x-bt/img-img", NULL, image_path, &err);
	if (transfer == NULL) {
		reply = g_dbus_create_error(message, ERROR_INTERFACE ".Failed",
						"%s",
						err->message);
		g_error_free(err);
		goto fail;
	}

	header = g_obex_header_new_unicode(IMG_HANDLE_TAG, handle);
	obc_transfer_add_header(transfer, header);

	descriptor = g_string_new(IMG_DESC_BEGIN);
	g_string_append_printf(descriptor, IMG_BEGIN, encoding, pixel);
	if (transform != NULL)
		g_string_append_printf(descriptor, IMG_TRANSFORM, transform);
	g_string_append(descriptor, IMG_END);
	descriptor = g_string_append(descriptor, IMG_DESC_END);
	header = g_obex_header_new_bytes(IMG_DESC_TAG, descriptor->str,
						descriptor->len);
	obc_transfer_add_header(transfer, header);
	g_string_free(descriptor, TRUE);

	if (!obc_session_queue(bip_avrcp->session, transfer, NULL, NULL,
								&err)) {
		reply = g_dbus_create_error(message, ERROR_INTERFACE ".Failed",
						"%s",
						err->message);
		g_error_free(err);
		goto fail;
	}

	reply = obc_transfer_create_dbus_reply(transfer, message);

fail:
	g_free(handle);
	g_free(image_path);
	g_free(transform);
	g_free(encoding);
	g_free(pixel);
	return reply;
}

static const GDBusMethodTable bip_avrcp_methods[] = {
	{ GDBUS_ASYNC_METHOD("Properties",
		GDBUS_ARGS({ "handle", "s"}),
		GDBUS_ARGS({ "properties", "aa{sv}" }),
		get_image_properties) },
	{ GDBUS_ASYNC_METHOD("Get",
		GDBUS_ARGS({ "file", "s" }, { "handle", "s"},
				{"properties", "a{sv}"}),
		GDBUS_ARGS({ "transfer", "o" }, { "properties", "a{sv}" }),
		get_image) },
	{ GDBUS_ASYNC_METHOD("GetThumbnail",
		GDBUS_ARGS({ "file", "s" }, { "handle", "s"}),
		GDBUS_ARGS({ "transfer", "o" }, { "properties", "a{sv}" }),
		get_thumbnail) },
	{ }
};

static void bip_avrcp_free(void *data)
{
	struct bip_avrcp_data *bip_avrcp = data;

	obc_session_unref(bip_avrcp->session);
	g_free(bip_avrcp);
}

static int bip_avrcp_probe(struct obc_session *session)
{
	struct bip_avrcp_data *bip_avrcp;
	const char *path;

	path = obc_session_get_path(session);

	DBG("%s", path);

	bip_avrcp = g_try_new0(struct bip_avrcp_data, 1);
	if (!bip_avrcp)
		return -ENOMEM;

	bip_avrcp->session = obc_session_ref(session);

	if (!g_dbus_register_interface(conn, path, IMAGE_INTERFACE,
					bip_avrcp_methods,
					NULL, NULL,
					bip_avrcp, bip_avrcp_free)) {
		bip_avrcp_free(bip_avrcp);
		return -ENOMEM;
	}

	return 0;
}

static void bip_avrcp_remove(struct obc_session *session)
{
	const char *path = obc_session_get_path(session);

	DBG("%s", path);

	g_dbus_unregister_interface(conn, path, IMAGE_INTERFACE);
}

static struct obc_driver bip_avrcp = {
	.service = "BIP-AVRCP",
	.uuid = IMAGE_UUID,
	.target = OBEX_BIP_AVRCP_UUID,
	.target_len = OBEX_BIP_AVRCP_UUID_LEN,
	.probe = bip_avrcp_probe,
	.remove = bip_avrcp_remove
};

int bip_init(void)
{
	int err;

	DBG("");

	conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (!conn)
		return -EIO;

	err = obc_driver_register(&bip_avrcp);
	if (err < 0)
		goto failed;

	return 0;

failed:
	dbus_connection_unref(conn);
	conn = NULL;
	return err;
}

void bip_exit(void)
{
	DBG("");

	dbus_connection_unref(conn);
	conn = NULL;

	obc_driver_unregister(&bip_avrcp);
}
