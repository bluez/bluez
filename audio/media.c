/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
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
#include <gdbus.h>

#include "../src/adapter.h"
#include "../src/dbus-common.h"

#include "log.h"
#include "error.h"
#include "device.h"
#include "avdtp.h"
#include "media.h"
#include "transport.h"
#include "a2dp.h"
#include "headset.h"
#include "manager.h"

#ifndef DBUS_TYPE_UNIX_FD
#define DBUS_TYPE_UNIX_FD -1
#endif

#define MEDIA_INTERFACE "org.bluez.Media"
#define MEDIA_ENDPOINT_INTERFACE "org.bluez.MediaEndpoint"

#define REQUEST_TIMEOUT (3 * 1000)		/* 3 seconds */

struct media_adapter {
	bdaddr_t		src;		/* Adapter address */
	char			*path;		/* Adapter path */
	DBusConnection		*conn;		/* Adapter connection */
	GSList			*endpoints;	/* Endpoints list */
};

struct endpoint_request {
	DBusMessage		*msg;
	DBusPendingCall		*call;
	media_endpoint_cb_t	cb;
	void			*user_data;
};

struct media_endpoint {
	struct a2dp_sep		*sep;
	char			*sender;	/* Endpoint DBus bus id */
	char			*path;		/* Endpoint object path */
	char			*uuid;		/* Endpoint property UUID */
	uint8_t			codec;		/* Endpoint codec */
	uint8_t			*capabilities;	/* Endpoint property capabilities */
	size_t			size;		/* Endpoint capabilities size */
	guint			hs_watch;
	guint			watch;
	struct endpoint_request *request;
	struct media_transport	*transport;
	struct media_adapter	*adapter;
};

static GSList *adapters = NULL;

static void endpoint_request_free(struct endpoint_request *request)
{
	if (request->call)
		dbus_pending_call_unref(request->call);

	dbus_message_unref(request->msg);
	g_free(request);
}

static void media_endpoint_cancel(struct media_endpoint *endpoint)
{
	struct endpoint_request *request = endpoint->request;

	if (request->call)
		dbus_pending_call_cancel(request->call);

	endpoint_request_free(request);
	endpoint->request = NULL;
}

static void media_endpoint_remove(struct media_endpoint *endpoint)
{
	struct media_adapter *adapter = endpoint->adapter;

	if (g_slist_find(adapter->endpoints, endpoint) == NULL)
		return;

	info("Endpoint unregistered: sender=%s path=%s", endpoint->sender,
			endpoint->path);

	adapter->endpoints = g_slist_remove(adapter->endpoints, endpoint);

	if (endpoint->sep)
		a2dp_remove_sep(endpoint->sep);

	if (endpoint->hs_watch)
		headset_remove_state_cb(endpoint->hs_watch);

	if (endpoint->request)
		media_endpoint_cancel(endpoint);

	if (endpoint->transport)
		media_transport_destroy(endpoint->transport);

	g_dbus_remove_watch(adapter->conn, endpoint->watch);
	g_free(endpoint->capabilities);
	g_free(endpoint->sender);
	g_free(endpoint->path);
	g_free(endpoint->uuid);
	g_free(endpoint);
}

static void media_endpoint_exit(DBusConnection *connection, void *user_data)
{
	struct media_endpoint *endpoint = user_data;

	endpoint->watch = 0;
	media_endpoint_remove(endpoint);
}

static void headset_setconf_cb(struct media_endpoint *endpoint, void *ret,
						int size, void *user_data)
{
	struct audio_device *dev = user_data;

	if (ret != NULL)
		return;

	headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
}

static void headset_state_changed(struct audio_device *dev,
					headset_state_t old_state,
					headset_state_t new_state,
					void *user_data)
{
	struct media_endpoint *endpoint = user_data;

	DBG("");

	switch (new_state) {
	case HEADSET_STATE_DISCONNECTED:
		media_endpoint_clear_configuration(endpoint);
		break;
	case HEADSET_STATE_CONNECTING:
		media_endpoint_set_configuration(endpoint, dev, NULL, 0,
						headset_setconf_cb, dev);
		break;
	case HEADSET_STATE_CONNECTED:
		break;
	case HEADSET_STATE_PLAY_IN_PROGRESS:
		break;
	case HEADSET_STATE_PLAYING:
		break;
	}
}

static struct media_endpoint *media_endpoint_create(struct media_adapter *adapter,
						const char *sender,
						const char *path,
						const char *uuid,
						gboolean delay_reporting,
						uint8_t codec,
						uint8_t *capabilities,
						int size,
						int *err)
{
	struct media_endpoint *endpoint;

	endpoint = g_new0(struct media_endpoint, 1);
	endpoint->sender = g_strdup(sender);
	endpoint->path = g_strdup(path);
	endpoint->uuid = g_strdup(uuid);
	endpoint->codec = codec;

	if (size > 0) {
		endpoint->capabilities = g_new(uint8_t, size);
		memcpy(endpoint->capabilities, capabilities, size);
		endpoint->size = size;
	}

	endpoint->adapter = adapter;

	if (strcasecmp(uuid, A2DP_SOURCE_UUID) == 0) {
		endpoint->sep = a2dp_add_sep(&adapter->src,
					AVDTP_SEP_TYPE_SOURCE, codec,
					delay_reporting, endpoint, err);
		if (endpoint->sep == NULL)
			goto failed;
	} else if (strcasecmp(uuid, A2DP_SINK_UUID) == 0) {
		endpoint->sep = a2dp_add_sep(&adapter->src,
						AVDTP_SEP_TYPE_SINK, codec,
						delay_reporting, endpoint, err);
		if (endpoint->sep == NULL)
			goto failed;
	} else if (strcasecmp(uuid, HFP_AG_UUID) == 0 ||
					g_strcmp0(uuid, HSP_AG_UUID) == 0) {
		struct audio_device *dev;

		endpoint->hs_watch = headset_add_state_cb(headset_state_changed,
								endpoint);
		dev = manager_find_device(NULL, &adapter->src, BDADDR_ANY,
						AUDIO_HEADSET_INTERFACE, TRUE);
		if (dev)
			media_endpoint_set_configuration(endpoint, dev, NULL,
							0, headset_setconf_cb,
							dev);
	} else {
		if (err)
			*err = -EINVAL;
		goto failed;
	}

	endpoint->watch = g_dbus_add_disconnect_watch(adapter->conn, sender,
						media_endpoint_exit, endpoint,
						NULL);

	adapter->endpoints = g_slist_append(adapter->endpoints, endpoint);
	info("Endpoint registered: sender=%s path=%s", sender, path);

	if (err)
		*err = 0;
	return endpoint;

failed:
	g_free(endpoint);
	return NULL;
}

static struct media_endpoint *media_adapter_find_endpoint(
						struct media_adapter *adapter,
						const char *sender,
						const char *path,
						const char *uuid)
{
	GSList *l;

	for (l = adapter->endpoints; l; l = l->next) {
		struct media_endpoint *endpoint = l->data;

		if (sender && g_strcmp0(endpoint->sender, sender) != 0)
			continue;

		if (path && g_strcmp0(endpoint->path, path) != 0)
			continue;

		if (uuid && g_strcmp0(endpoint->uuid, uuid) != 0)
			continue;

		return endpoint;
	}

	return NULL;
}

const char *media_endpoint_get_sender(struct media_endpoint *endpoint)
{
	return endpoint->sender;
}

static int parse_properties(DBusMessageIter *props, const char **uuid,
				gboolean *delay_reporting, uint8_t *codec,
				uint8_t **capabilities, int *size)
{
	gboolean has_uuid = FALSE;
	gboolean has_codec = FALSE;

	while (dbus_message_iter_get_arg_type(props) == DBUS_TYPE_DICT_ENTRY) {
		const char *key;
		DBusMessageIter value, entry;
		int var;

		dbus_message_iter_recurse(props, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		var = dbus_message_iter_get_arg_type(&value);
		if (strcasecmp(key, "UUID") == 0) {
			if (var != DBUS_TYPE_STRING)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, uuid);
			has_uuid = TRUE;
		} else if (strcasecmp(key, "Codec") == 0) {
			if (var != DBUS_TYPE_BYTE)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, codec);
			has_codec = TRUE;
		} else if (strcasecmp(key, "DelayReporting") == 0) {
			if (var != DBUS_TYPE_BOOLEAN)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, delay_reporting);
		} else if (strcasecmp(key, "Capabilities") == 0) {
			DBusMessageIter array;

			if (var != DBUS_TYPE_ARRAY)
				return -EINVAL;

			dbus_message_iter_recurse(&value, &array);
			dbus_message_iter_get_fixed_array(&array, capabilities,
							size);
		}

		dbus_message_iter_next(props);
	}

	return (has_uuid && has_codec) ? 0 : -EINVAL;
}

static DBusMessage *register_endpoint(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct media_adapter *adapter = data;
	DBusMessageIter args, props;
	const char *sender, *path, *uuid;
	gboolean delay_reporting = FALSE;
	uint8_t codec;
	uint8_t *capabilities;
	int size = 0;
	int err;

	sender = dbus_message_get_sender(msg);

	dbus_message_iter_init(msg, &args);

	dbus_message_iter_get_basic(&args, &path);
	dbus_message_iter_next(&args);

	if (media_adapter_find_endpoint(adapter, sender, path, NULL) != NULL)
		return btd_error_already_exists(msg);

	dbus_message_iter_recurse(&args, &props);
	if (dbus_message_iter_get_arg_type(&props) != DBUS_TYPE_DICT_ENTRY)
		return btd_error_invalid_args(msg);

	if (parse_properties(&props, &uuid, &delay_reporting, &codec,
						&capabilities, &size) < 0)
		return btd_error_invalid_args(msg);

	if (media_endpoint_create(adapter, sender, path, uuid, delay_reporting,
				codec, capabilities, size, &err) == FALSE) {
		if (err == -EPROTONOSUPPORT)
			return btd_error_not_supported(msg);
		else
			return btd_error_invalid_args(msg);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *unregister_endpoint(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct media_adapter *adapter = data;
	struct media_endpoint *endpoint;
	const char *sender, *path;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID))
		return NULL;

	sender = dbus_message_get_sender(msg);

	endpoint = media_adapter_find_endpoint(adapter, sender, path, NULL);
	if (endpoint == NULL)
		return btd_error_does_not_exist(msg);

	media_endpoint_remove(endpoint);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable media_methods[] = {
	{ "RegisterEndpoint",	"oa{sv}",	"",	register_endpoint },
	{ "UnregisterEndpoint",	"o",		"",	unregister_endpoint },
	{ },
};

static void path_free(void *data)
{
	struct media_adapter *adapter = data;

	g_slist_foreach(adapter->endpoints, (GFunc) media_endpoint_release,
									NULL);
	g_slist_free(adapter->endpoints);

	dbus_connection_unref(adapter->conn);

	adapters = g_slist_remove(adapters, adapter);

	g_free(adapter->path);
	g_free(adapter);
}

int media_register(DBusConnection *conn, const char *path, const bdaddr_t *src)
{
	struct media_adapter *adapter;

	if (DBUS_TYPE_UNIX_FD < 0)
		return -EPERM;

	adapter = g_new0(struct media_adapter, 1);
	adapter->conn = dbus_connection_ref(conn);
	bacpy(&adapter->src, src);
	adapter->path = g_strdup(path);

	if (!g_dbus_register_interface(conn, path, MEDIA_INTERFACE,
					media_methods, NULL, NULL,
					adapter, path_free)) {
		error("D-Bus failed to register %s path", path);
		path_free(adapter);
		return -1;
	}

	adapters = g_slist_append(adapters, adapter);

	return 0;
}

void media_unregister(const char *path)
{
	GSList *l;

	for (l = adapters; l; l = l->next) {
		struct media_adapter *adapter = l->data;

		if (g_strcmp0(path, adapter->path) == 0) {
			g_dbus_unregister_interface(adapter->conn, path,
							MEDIA_INTERFACE);
			return;
		}
	}
}

size_t media_endpoint_get_capabilities(struct media_endpoint *endpoint,
					uint8_t **capabilities)
{
	*capabilities = endpoint->capabilities;
	return endpoint->size;
}

static void endpoint_reply(DBusPendingCall *call, void *user_data)
{
	struct media_endpoint *endpoint = user_data;
	struct endpoint_request *request = endpoint->request;
	DBusMessage *reply;
	DBusError err;
	gboolean value;
	void *ret = NULL;
	int size = -1;

	/* steal_reply will always return non-NULL since the callback
	 * is only called after a reply has been received */
	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("Endpoint replied with an error: %s",
				err.name);

		/* Clear endpoint configuration in case of NO_REPLY error */
		if (dbus_error_has_name(&err, DBUS_ERROR_NO_REPLY)) {
			if (request->cb)
				request->cb(endpoint, NULL, size,
							request->user_data);
			media_endpoint_clear_configuration(endpoint);
			dbus_message_unref(reply);
			dbus_error_free(&err);
			return;
		}

		dbus_error_free(&err);
		goto done;
	}

	dbus_error_init(&err);
	if (dbus_message_is_method_call(request->msg, MEDIA_ENDPOINT_INTERFACE,
				"SelectConfiguration")) {
		DBusMessageIter args, array;
		uint8_t *configuration;

		dbus_message_iter_init(reply, &args);

		dbus_message_iter_recurse(&args, &array);

		dbus_message_iter_get_fixed_array(&array, &configuration, &size);

		ret = configuration;
		goto done;
	} else  if (!dbus_message_get_args(reply, &err, DBUS_TYPE_INVALID)) {
		error("Wrong reply signature: %s", err.message);
		dbus_error_free(&err);
		goto done;
	}

	size = 1;
	value = TRUE;
	ret = &value;

done:
	dbus_message_unref(reply);

	if (request->cb)
		request->cb(endpoint, ret, size, request->user_data);

	endpoint_request_free(request);
	endpoint->request = NULL;
}

static gboolean media_endpoint_async_call(DBusConnection *conn,
					DBusMessage *msg,
					struct media_endpoint *endpoint,
					media_endpoint_cb_t cb,
					void *user_data)
{
	struct endpoint_request *request;

	if (endpoint->request)
		return FALSE;

	request = g_new0(struct endpoint_request, 1);

	/* Timeout should be less than avdtp request timeout (4 seconds) */
	if (dbus_connection_send_with_reply(conn, msg, &request->call,
						REQUEST_TIMEOUT) == FALSE) {
		error("D-Bus send failed");
		g_free(request);
		return FALSE;
	}

	dbus_pending_call_set_notify(request->call, endpoint_reply, endpoint, NULL);

	request->msg = msg;
	request->cb = cb;
	request->user_data = user_data;
	endpoint->request = request;

	DBG("Calling %s: name = %s path = %s", dbus_message_get_member(msg),
			dbus_message_get_destination(msg),
			dbus_message_get_path(msg));

	return TRUE;
}

gboolean media_endpoint_set_configuration(struct media_endpoint *endpoint,
					struct audio_device *device,
					uint8_t *configuration, size_t size,
					media_endpoint_cb_t cb,
					void *user_data)
{
	DBusConnection *conn;
	DBusMessage *msg;
	const char *path;
	DBusMessageIter iter;

	if (endpoint->transport != NULL || endpoint->request != NULL)
		return FALSE;

	conn = endpoint->adapter->conn;

	endpoint->transport = media_transport_create(conn, endpoint, device,
						configuration, size);
	if (endpoint->transport == NULL)
		return FALSE;

	msg = dbus_message_new_method_call(endpoint->sender, endpoint->path,
						MEDIA_ENDPOINT_INTERFACE,
						"SetConfiguration");
	if (msg == NULL) {
		error("Couldn't allocate D-Bus message");
		return FALSE;
	}

	dbus_message_iter_init_append(msg, &iter);

	path = media_transport_get_path(endpoint->transport);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &path);

	transport_get_properties(endpoint->transport, &iter);

	return media_endpoint_async_call(conn, msg, endpoint, cb, user_data);
}

gboolean media_endpoint_select_configuration(struct media_endpoint *endpoint,
						uint8_t *capabilities,
						size_t length,
						media_endpoint_cb_t cb,
						void *user_data)
{
	DBusConnection *conn;
	DBusMessage *msg;

	if (endpoint->request != NULL)
		return FALSE;

	conn = endpoint->adapter->conn;

	msg = dbus_message_new_method_call(endpoint->sender, endpoint->path,
						MEDIA_ENDPOINT_INTERFACE,
						"SelectConfiguration");
	if (msg == NULL) {
		error("Couldn't allocate D-Bus message");
		return FALSE;
	}

	dbus_message_append_args(msg, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
					&capabilities, length,
					DBUS_TYPE_INVALID);

	return media_endpoint_async_call(conn, msg, endpoint, cb, user_data);
}

void media_endpoint_clear_configuration(struct media_endpoint *endpoint)
{
	DBusConnection *conn;
	DBusMessage *msg;
	const char *path;

	if (endpoint->transport == NULL)
		return;

	if (endpoint->request)
		media_endpoint_cancel(endpoint);

	conn = endpoint->adapter->conn;

	msg = dbus_message_new_method_call(endpoint->sender, endpoint->path,
						MEDIA_ENDPOINT_INTERFACE,
						"ClearConfiguration");
	if (msg == NULL) {
		error("Couldn't allocate D-Bus message");
		goto done;
	}

	path = media_transport_get_path(endpoint->transport);
	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);
	g_dbus_send_message(conn, msg);
done:
	media_transport_destroy(endpoint->transport);
	endpoint->transport = NULL;
}

void media_endpoint_release(struct media_endpoint *endpoint)
{
	DBusMessage *msg;

	DBG("sender=%s path=%s", endpoint->sender, endpoint->path);

	/* already exit */
	if (endpoint->watch == 0)
		return;

	msg = dbus_message_new_method_call(endpoint->sender, endpoint->path,
						MEDIA_ENDPOINT_INTERFACE,
						"Release");
	if (msg == NULL) {
		error("Couldn't allocate D-Bus message");
		return;
	}

	g_dbus_send_message(endpoint->adapter->conn, msg);

	media_endpoint_remove(endpoint);
}

struct a2dp_sep *media_endpoint_get_sep(struct media_endpoint *endpoint)
{
	return endpoint->sep;
}

const char *media_endpoint_get_uuid(struct media_endpoint *endpoint)
{
	return endpoint->uuid;
}

uint8_t media_endpoint_get_codec(struct media_endpoint *endpoint)
{
	return endpoint->codec;
}

struct media_transport *media_endpoint_get_transport(
					struct media_endpoint *endpoint)
{
	return endpoint->transport;
}
