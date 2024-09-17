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

static const GDBusMethodTable bip_avrcp_methods[] = {
	{ GDBUS_ASYNC_METHOD("Properties",
		GDBUS_ARGS({ "handle", "s"}),
		GDBUS_ARGS({ "properties", "aa{sv}" }),
		get_image_properties) },
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
