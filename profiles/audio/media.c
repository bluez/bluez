// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2011  BMW Car IT GmbH. All rights reserved.
 *  Copyright 2023 NXP
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>

#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/uuid.h"
#include "lib/mgmt.h"

#include "gdbus/gdbus.h"

#include "src/plugin.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/dbus-common.h"
#include "src/profile.h"
#include "src/service.h"

#include "src/uuid-helper.h"
#include "src/log.h"
#include "src/error.h"
#include "src/gatt-database.h"
#include "src/shared/asha.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/bap.h"
#include "src/shared/bap-debug.h"

#include "avdtp.h"
#include "media.h"
#include "transport.h"
#include "a2dp.h"

#ifdef HAVE_AVRCP
#include "avrcp.h"
#endif

#define MEDIA_INTERFACE "org.bluez.Media1"
#define MEDIA_ENDPOINT_INTERFACE "org.bluez.MediaEndpoint1"
#define MEDIA_PLAYER_INTERFACE "org.mpris.MediaPlayer2.Player"

#define REQUEST_TIMEOUT (3 * 1000)		/* 3 seconds */

struct media_app {
	struct media_adapter	*adapter;
	GDBusClient		*client;
	DBusMessage		*reg;
	char			*sender;	/* Application bus id */
	char			*path;		/* Application object path */
	struct queue		*proxies;	/* Application proxies */
	struct queue		*endpoints;	/* Application endpoints */
#ifdef HAVE_AVRCP
	struct queue		*players;	/* Application players */
#endif
	int			err;
};

struct media_adapter {
	struct btd_adapter	*btd_adapter;
	struct queue		*apps;		/* Application list */
	GSList			*endpoints;	/* Endpoints list */
#ifdef HAVE_AVRCP
	GSList			*players;	/* Players list */
#endif
	int			so_timestamping;
};

struct endpoint_request {
	struct media_endpoint	*endpoint;
	struct media_transport	*transport;
	DBusMessage		*msg;
	DBusPendingCall		*call;
	media_endpoint_cb_t	cb;
	GDestroyNotify		destroy;
	void			*user_data;
};

struct media_endpoint {
	struct a2dp_sep		*sep;
	struct bt_bap_pac	*pac;
	struct bt_asha_device	*asha;
	char			*sender;	/* Endpoint DBus bus id */
	char			*path;		/* Endpoint object path */
	char			*uuid;		/* Endpoint property UUID */
	uint8_t			codec;		/* Endpoint codec */
	uint16_t                cid;            /* Endpoint company ID */
	uint16_t                vid;            /* Endpoint vendor codec ID */
	bool			delay_reporting;/* Endpoint delay_reporting */
	struct bt_bap_pac_qos	qos;		/* Endpoint qos */
	uint8_t			*capabilities;	/* Endpoint property capabilities */
	size_t			size;		/* Endpoint capabilities size */
	uint8_t                 *metadata;      /* Endpoint property metadata */
	size_t                  metadata_size;  /* Endpoint metadata size */
	guint			hs_watch;
	guint			ag_watch;
	guint			watch;
	GSList			*requests;
	struct media_adapter	*adapter;
	GSList			*transports;
};

struct media_player {
	struct media_adapter	*adapter;
	struct avrcp_player	*player;
	char			*sender;	/* Player DBus bus id */
	char			*path;		/* Player object path */
	GHashTable		*settings;	/* Player settings */
	GHashTable		*track;		/* Player current track */
	guint			watch;
	guint			properties_watch;
	guint			seek_watch;
	char			*status;
	uint32_t		position;
	uint32_t		duration;
	int8_t			volume;
	GTimer			*timer;
	bool			play;
	bool			pause;
	bool			next;
	bool			previous;
	bool			control;
	char			*name;
};

static GSList *adapters = NULL;

static void endpoint_request_free(struct endpoint_request *request)
{
	if (request->call)
		dbus_pending_call_unref(request->call);

	if (request->destroy)
		request->destroy(request->user_data);

	dbus_message_unref(request->msg);
	g_free(request);
}

static void media_endpoint_cancel(struct endpoint_request *request)
{
	struct media_endpoint *endpoint = request->endpoint;

	DBG("Canceling %s: name = %s path = %s",
			dbus_message_get_member(request->msg),
			dbus_message_get_destination(request->msg),
			dbus_message_get_path(request->msg));

	if (request->call)
		dbus_pending_call_cancel(request->call);

	endpoint->requests = g_slist_remove(endpoint->requests, request);

	if (request->cb)
		request->cb(endpoint, NULL, -1, request->user_data);

	endpoint_request_free(request);
}

static void media_endpoint_cancel_all(struct media_endpoint *endpoint)
{
	while (endpoint->requests != NULL)
		media_endpoint_cancel(endpoint->requests->data);
}

static void media_endpoint_destroy(struct media_endpoint *endpoint)
{
	DBG("sender=%s path=%s", endpoint->sender, endpoint->path);

	media_endpoint_cancel_all(endpoint);

	g_slist_free_full(endpoint->transports,
				(GDestroyNotify) media_transport_destroy);
	endpoint->transports = NULL;

	if (endpoint->pac) {
		bt_bap_remove_pac(endpoint->pac);
		endpoint->pac = NULL;
	}

	g_dbus_remove_watch(btd_get_dbus_connection(), endpoint->watch);
	g_free(endpoint->capabilities);
	g_free(endpoint->metadata);
	g_free(endpoint->sender);
	g_free(endpoint->path);
	g_free(endpoint->uuid);
	g_free(endpoint);
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

		if (uuid && strcasecmp(endpoint->uuid, uuid) != 0)
			continue;

		return endpoint;
	}

	return NULL;
}

static void media_endpoint_remove(void *data)
{
	struct media_endpoint *endpoint = data;
	struct media_adapter *adapter = endpoint->adapter;

	if (endpoint->sep) {
		a2dp_remove_sep(endpoint->sep);
		return;
	}

	info("Endpoint unregistered: sender=%s path=%s", endpoint->sender,
			endpoint->path);

	adapter->endpoints = g_slist_remove(adapter->endpoints, endpoint);

	if (media_adapter_find_endpoint(adapter, NULL, NULL,
						endpoint->uuid) == NULL)
		btd_profile_remove_custom_prop(endpoint->uuid,
							"MediaEndpoints");

	media_endpoint_destroy(endpoint);
}

static void media_endpoint_exit(DBusConnection *connection, void *user_data)
{
	struct media_endpoint *endpoint = user_data;

	endpoint->watch = 0;
	media_endpoint_remove(endpoint);
}

static struct media_adapter *find_adapter(struct btd_device *device)
{
	GSList *l;

	for (l = adapters; l; l = l->next) {
		struct media_adapter *adapter = l->data;

		if (adapter->btd_adapter == device_get_adapter(device))
			return adapter;
	}

	return NULL;
}

static void endpoint_remove_transport(struct media_endpoint *endpoint,
					struct media_transport *transport)
{
	if (!endpoint || !transport)
		return;

	endpoint->transports = g_slist_remove(endpoint->transports, transport);
	media_transport_destroy(transport);
}

static void clear_configuration(struct media_endpoint *endpoint,
					struct media_transport *transport)
{
	DBusMessage *msg;
	const char *path;

	msg = dbus_message_new_method_call(endpoint->sender, endpoint->path,
						MEDIA_ENDPOINT_INTERFACE,
						"ClearConfiguration");
	if (msg == NULL) {
		error("Couldn't allocate D-Bus message");
		goto done;
	}

	path = media_transport_get_path(transport);
	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);
	g_dbus_send_message(btd_get_dbus_connection(), msg);
done:
	endpoint_remove_transport(endpoint, transport);
}

static void clear_endpoint(struct media_endpoint *endpoint)
{
	media_endpoint_cancel_all(endpoint);

	while (endpoint->transports != NULL)
		clear_configuration(endpoint, endpoint->transports->data);
}

static void endpoint_reply(DBusPendingCall *call, void *user_data)
{
	struct endpoint_request *request = user_data;
	struct media_endpoint *endpoint = request->endpoint;
	DBusMessage *reply;
	DBusMessageIter args, props;
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
			clear_endpoint(endpoint);
			dbus_message_unref(reply);
			dbus_error_free(&err);
			return;
		}

		if (dbus_message_is_method_call(request->msg,
					MEDIA_ENDPOINT_INTERFACE,
					"SetConfiguration"))
			endpoint_remove_transport(endpoint, request->transport);

		dbus_error_free(&err);
		goto done;
	}

	if (dbus_message_is_method_call(request->msg, MEDIA_ENDPOINT_INTERFACE,
						"SelectConfiguration")) {
		DBusMessageIter args, array;
		uint8_t *configuration;

		dbus_message_iter_init(reply, &args);

		dbus_message_iter_recurse(&args, &array);

		dbus_message_iter_get_fixed_array(&array, &configuration, &size);

		ret = configuration;
		goto done;
	} else if (dbus_message_is_method_call(request->msg,
						MEDIA_ENDPOINT_INTERFACE,
						"SelectProperties")) {
		dbus_message_iter_init(reply, &args);
		dbus_message_iter_recurse(&args, &props);
		ret = &props;
		goto done;
	} else if (!dbus_message_get_args(reply, &err, DBUS_TYPE_INVALID)) {
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

	endpoint->requests = g_slist_remove(endpoint->requests, request);
	endpoint_request_free(request);
}

static gboolean media_endpoint_async_call(DBusMessage *msg,
					struct media_endpoint *endpoint,
					struct media_transport *transport,
					media_endpoint_cb_t cb,
					void *user_data,
					GDestroyNotify destroy)
{
	struct endpoint_request *request;

	request = g_new0(struct endpoint_request, 1);

	/* Timeout should be less than avdtp request timeout (4 seconds) */
	if (g_dbus_send_message_with_reply(btd_get_dbus_connection(),
						msg, &request->call,
						REQUEST_TIMEOUT) == FALSE) {
		error("D-Bus send failed");
		g_free(request);
		return FALSE;
	}

	dbus_pending_call_set_notify(request->call, endpoint_reply, request,
									NULL);

	request->endpoint = endpoint;
	request->transport = transport;
	request->msg = msg;
	request->cb = cb;
	request->destroy = destroy;
	request->user_data = user_data;

	endpoint->requests = g_slist_append(endpoint->requests, request);

	DBG("Calling %s: name = %s path = %s", dbus_message_get_member(msg),
			dbus_message_get_destination(msg),
			dbus_message_get_path(msg));

	return TRUE;
}

static gboolean select_configuration(struct media_endpoint *endpoint,
						uint8_t *capabilities,
						size_t length,
						media_endpoint_cb_t cb,
						void *user_data,
						GDestroyNotify destroy)
{
	DBusMessage *msg;

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

	return media_endpoint_async_call(msg, endpoint, NULL,
						cb, user_data, destroy);
}

static int transport_device_cmp(gconstpointer data, gconstpointer user_data)
{
	struct media_transport *transport = (struct media_transport *) data;
	const struct btd_device *device = user_data;
	const struct btd_device *dev = media_transport_get_dev(transport);

	if (device == dev)
		return 0;

	return -1;
}

static struct media_transport *find_device_transport(
					struct media_endpoint *endpoint,
					struct btd_device *device)
{
	GSList *match;

	match = g_slist_find_custom(endpoint->transports, device,
							transport_device_cmp);
	if (match == NULL)
		return NULL;

	return match->data;
}

struct a2dp_config_data {
	struct a2dp_setup *setup;
	a2dp_endpoint_config_t cb;
};

int8_t media_player_get_device_volume(struct btd_device *device)
{
#ifdef HAVE_AVRCP
	struct avrcp_player *target_player;
	struct media_adapter *adapter;
	GSList *l;

	if (!device)
		return -1;

	target_player = avrcp_get_target_player_by_device(device);
	if (!target_player)
		goto done;

	adapter = find_adapter(device);
	if (!adapter)
		goto done;

	for (l = adapter->players; l; l = l->next) {
		struct media_player *mp = l->data;

		if (mp->player == target_player)
			return mp->volume;
	}

done:
#endif /* HAVE_AVRCP */
	/* If media_player doesn't exists use device_volume */
	return btd_device_get_volume(device);
}

static gboolean set_configuration(struct media_endpoint *endpoint,
					uint8_t *configuration, size_t size,
					media_endpoint_cb_t cb,
					void *user_data,
					GDestroyNotify destroy)
{
	struct a2dp_config_data *data = user_data;
	struct btd_device *device = a2dp_setup_get_device(data->setup);
	DBusConnection *conn = btd_get_dbus_connection();
	DBusMessage *msg;
	const char *path;
	DBusMessageIter iter;
	struct media_transport *transport;
	int8_t init_volume;

	transport = find_device_transport(endpoint, device);

	if (transport != NULL)
		return FALSE;

	transport = media_transport_create(device,
					a2dp_setup_remote_path(data->setup),
					configuration, size, endpoint, NULL);
	if (transport == NULL)
		return FALSE;

	init_volume = media_player_get_device_volume(device);
	media_transport_update_volume(transport, init_volume);

	msg = dbus_message_new_method_call(endpoint->sender, endpoint->path,
						MEDIA_ENDPOINT_INTERFACE,
						"SetConfiguration");
	if (msg == NULL) {
		error("Couldn't allocate D-Bus message");
		media_transport_destroy(transport);
		return FALSE;
	}

	endpoint->transports = g_slist_append(endpoint->transports, transport);

	dbus_message_iter_init_append(msg, &iter);

	path = media_transport_get_path(transport);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &path);

	g_dbus_get_properties(conn, path, "org.bluez.MediaTransport1", &iter);

	return media_endpoint_async_call(msg, endpoint, transport,
						cb, user_data, destroy);
}

static void release_endpoint(struct media_endpoint *endpoint)
{
	DBusMessage *msg;

	DBG("sender=%s path=%s", endpoint->sender, endpoint->path);

	/* already exit */
	if (endpoint->watch == 0)
		goto done;

	clear_endpoint(endpoint);

	msg = dbus_message_new_method_call(endpoint->sender, endpoint->path,
						MEDIA_ENDPOINT_INTERFACE,
						"Release");
	if (msg == NULL) {
		error("Couldn't allocate D-Bus message");
		return;
	}

	g_dbus_send_message(btd_get_dbus_connection(), msg);

done:
	media_endpoint_remove(endpoint);
}

static const char *get_name(struct a2dp_sep *sep, void *user_data)
{
	struct media_endpoint *endpoint = user_data;

	return endpoint->sender;
}

static const char *get_path(struct a2dp_sep *sep, void *user_data)
{
	struct media_endpoint *endpoint = user_data;

	return endpoint->path;
}

static size_t get_capabilities(struct a2dp_sep *sep, uint8_t **capabilities,
							void *user_data)
{
	struct media_endpoint *endpoint = user_data;

	*capabilities = endpoint->capabilities;
	return endpoint->size;
}

struct a2dp_select_data {
	struct a2dp_setup *setup;
	a2dp_endpoint_select_t cb;
};

static void select_cb(struct media_endpoint *endpoint, void *ret, int size,
							void *user_data)
{
	struct a2dp_select_data *data = user_data;

	data->cb(data->setup, ret, size);
}

static int select_config(struct a2dp_sep *sep, uint8_t *capabilities,
				size_t length, struct a2dp_setup *setup,
				a2dp_endpoint_select_t cb, void *user_data)
{
	struct media_endpoint *endpoint = user_data;
	struct a2dp_select_data *data;

	data = g_new0(struct a2dp_select_data, 1);
	data->setup = setup;
	data->cb = cb;

	if (select_configuration(endpoint, capabilities, length,
					select_cb, data, g_free) == TRUE)
		return 0;

	g_free(data);
	return -ENOMEM;
}

static void config_cb(struct media_endpoint *endpoint, void *ret, int size,
							void *user_data)
{
	struct a2dp_config_data *data = user_data;
	gboolean *ret_value = ret;

	data->cb(data->setup, ret_value ? *ret_value : FALSE);
}

static int set_config(struct a2dp_sep *sep, uint8_t *configuration,
				size_t length,
				struct a2dp_setup *setup,
				a2dp_endpoint_config_t cb,
				void *user_data)
{
	struct media_endpoint *endpoint = user_data;
	struct a2dp_config_data *data;

	data = g_new0(struct a2dp_config_data, 1);
	data->setup = setup;
	data->cb = cb;

	if (set_configuration(endpoint, configuration, length, config_cb, data,
							g_free) == TRUE)
		return 0;

	g_free(data);
	return -ENOMEM;
}

static void clear_config(struct a2dp_sep *sep, struct btd_device *device,
				void *user_data)
{
	struct media_endpoint *endpoint = user_data;
	struct media_transport *transport;

	if (!device) {
		clear_endpoint(endpoint);
		return;
	}

	transport = find_device_transport(endpoint, device);
	if (!transport)
		return;

	clear_configuration(endpoint, transport);
}

static void set_delay(struct a2dp_sep *sep, uint16_t delay, void *user_data)
{
	struct media_endpoint *endpoint = user_data;

	if (endpoint->transports == NULL)
		return;

	media_transport_update_delay(endpoint->transports->data, delay);
}

static struct a2dp_endpoint a2dp_endpoint = {
	.get_name = get_name,
	.get_path = get_path,
	.get_capabilities = get_capabilities,
	.select_configuration = select_config,
	.set_configuration = set_config,
	.clear_configuration = clear_config,
	.set_delay = set_delay
};

static void a2dp_destroy_endpoint(void *user_data)
{
	struct media_endpoint *endpoint = user_data;

	endpoint->sep = NULL;
	release_endpoint(endpoint);
}

static bool endpoint_init_a2dp_source(struct media_endpoint *endpoint, int *err)
{
	endpoint->sep = a2dp_add_sep(endpoint->adapter->btd_adapter,
					AVDTP_SEP_TYPE_SOURCE, endpoint->codec,
					endpoint->delay_reporting,
					&a2dp_endpoint, endpoint,
					a2dp_destroy_endpoint, err);
	if (endpoint->sep == NULL)
		return false;

	return true;
}

static bool endpoint_init_a2dp_sink(struct media_endpoint *endpoint, int *err)
{
	endpoint->sep = a2dp_add_sep(endpoint->adapter->btd_adapter,
					AVDTP_SEP_TYPE_SINK, endpoint->codec,
					endpoint->delay_reporting,
					&a2dp_endpoint, endpoint,
					a2dp_destroy_endpoint, err);
	if (endpoint->sep == NULL)
		return false;

	return true;
}

struct pac_select_data {
	struct bt_bap_pac *pac;
	bt_bap_pac_select_t cb;
	void *user_data;
};

static int parse_array(DBusMessageIter *iter, struct iovec *iov)
{
	DBusMessageIter array;

	if (!iov)
		return 0;

	dbus_message_iter_recurse(iter, &array);
	dbus_message_iter_get_fixed_array(&array, &iov->iov_base,
						(int *)&iov->iov_len);
	return 0;
}

static int parse_ucast_qos(DBusMessageIter *iter, struct bt_bap_qos *qos)
{
	DBusMessageIter array;
	const char *key;
	struct bt_bap_io_qos io_qos;

	dbus_message_iter_recurse(iter, &array);

	memset(&io_qos, 0, sizeof(io_qos));
	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter value, entry;
		int var;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		var = dbus_message_iter_get_arg_type(&value);

		if (!strcasecmp(key, "CIG")) {
			if (var != DBUS_TYPE_BYTE)
				goto fail;

			dbus_message_iter_get_basic(&value, &qos->ucast.cig_id);
		} else if (!strcasecmp(key, "CIS")) {
			if (var != DBUS_TYPE_BYTE)
				goto fail;

			dbus_message_iter_get_basic(&value, &qos->ucast.cis_id);
		} else if (!strcasecmp(key, "Interval")) {
			if (var != DBUS_TYPE_UINT32)
				goto fail;

			dbus_message_iter_get_basic(&value, &io_qos.interval);
		} else if (!strcasecmp(key, "Framing")) {
			if (var != DBUS_TYPE_BYTE)
				goto fail;

			dbus_message_iter_get_basic(&value,
							&qos->ucast.framing);
		} else if (!strcasecmp(key, "PHY")) {
			if (var != DBUS_TYPE_BYTE)
				goto fail;

			dbus_message_iter_get_basic(&value, &io_qos.phy);
		} else if (!strcasecmp(key, "SDU")) {
			if (var != DBUS_TYPE_UINT16)
				goto fail;

			dbus_message_iter_get_basic(&value, &io_qos.sdu);
		} else if (!strcasecmp(key, "Retransmissions")) {
			if (var != DBUS_TYPE_BYTE)
				goto fail;

			dbus_message_iter_get_basic(&value, &io_qos.rtn);
		} else if (!strcasecmp(key, "Latency")) {
			if (var != DBUS_TYPE_UINT16)
				goto fail;

			dbus_message_iter_get_basic(&value, &io_qos.latency);
		} else if (!strcasecmp(key, "PresentationDelay")) {
			if (var != DBUS_TYPE_UINT32)
				goto fail;

			dbus_message_iter_get_basic(&value, &qos->ucast.delay);
		} else if (!strcasecmp(key, "TargetLatency")) {
			if (var != DBUS_TYPE_BYTE)
				goto fail;

			dbus_message_iter_get_basic(&value,
						&qos->ucast.target_latency);
		}

		dbus_message_iter_next(&array);
	}

	memcpy(&qos->ucast.io_qos, &io_qos, sizeof(io_qos));

	return 0;

fail:
	DBG("Failed parsing %s", key);

	return -EINVAL;
}

static int parse_select_properties(DBusMessageIter *props, struct iovec *caps,
					struct iovec *metadata,
					struct bt_bap_qos *qos)
{
	const char *key;

	while (dbus_message_iter_get_arg_type(props) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter value, entry;
		int var;

		dbus_message_iter_recurse(props, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		var = dbus_message_iter_get_arg_type(&value);

		if (!strcasecmp(key, "Capabilities")) {
			if (var != DBUS_TYPE_ARRAY)
				goto fail;

			if (parse_array(&value, caps))
				goto fail;
		} else if (!strcasecmp(key, "Metadata")) {
			if (var != DBUS_TYPE_ARRAY)
				goto fail;

			if (parse_array(&value, metadata))
				goto fail;
		} else if (!strcasecmp(key, "QoS")) {
			if (var != DBUS_TYPE_ARRAY)
				goto fail;

			if (parse_ucast_qos(&value, qos))
				goto fail;
		}

		dbus_message_iter_next(props);
	}

	return 0;

fail:
	DBG("Failed parsing %s", key);

	return -EINVAL;
}

static void pac_select_cb(struct media_endpoint *endpoint, void *ret, int size,
							void *user_data)
{
	struct pac_select_data *data = user_data;
	DBusMessageIter *iter = ret;
	int err;
	struct iovec caps, meta;
	struct bt_bap_qos qos;

	if (!ret) {
		err = -EPERM;
		goto done;
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_DICT_ENTRY) {
		DBG("Unexpected argument type: %c != %c",
			    dbus_message_iter_get_arg_type(iter),
			    DBUS_TYPE_DICT_ENTRY);
		err = -EINVAL;
		goto done;
	}

	memset(&qos, 0, sizeof(qos));

	/* Mark CIG and CIS to be auto assigned */
	qos.ucast.cig_id = BT_ISO_QOS_CIG_UNSET;
	qos.ucast.cis_id = BT_ISO_QOS_CIS_UNSET;

	memset(&caps, 0, sizeof(caps));
	memset(&meta, 0, sizeof(meta));

	err = parse_select_properties(iter, &caps, &meta, &qos);
	if (err < 0)
		DBG("Unable to parse properties");

done:
	data->cb(data->pac, err, &caps, &meta, &qos, data->user_data);
}

static int pac_select(struct bt_bap_pac *lpac, struct bt_bap_pac *rpac,
			uint32_t location, struct bt_bap_pac_qos *qos,
			bt_bap_pac_select_t cb, void *cb_data, void *user_data)
{
	struct media_endpoint *endpoint = user_data;
	struct iovec *caps;
	struct iovec *metadata;
	const char *endpoint_path;
	struct pac_select_data *data;
	DBusMessage *msg;
	DBusMessageIter iter, dict;
	const char *key = "Capabilities";
	uint32_t loc;

	bt_bap_pac_get_codec(rpac, NULL, &caps, &metadata);
	if (!caps)
		return -EINVAL;

	msg = dbus_message_new_method_call(endpoint->sender, endpoint->path,
						MEDIA_ENDPOINT_INTERFACE,
						"SelectProperties");
	if (msg == NULL) {
		error("Couldn't allocate D-Bus message");
		return -ENOMEM;
	}

	data = new0(struct pac_select_data, 1);
	data->pac = lpac;
	data->cb = cb;
	data->user_data = cb_data;

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

	endpoint_path = bt_bap_pac_get_user_data(rpac);
	if (endpoint_path)
		g_dbus_dict_append_entry(&dict, "Endpoint",
					DBUS_TYPE_OBJECT_PATH, &endpoint_path);

	g_dbus_dict_append_basic_array(&dict, DBUS_TYPE_STRING, &key,
					DBUS_TYPE_BYTE, &caps->iov_base,
					caps->iov_len);

	loc = bt_bap_pac_get_locations(rpac);
	if (loc)
		g_dbus_dict_append_entry(&dict, "Locations", DBUS_TYPE_UINT32,
									&loc);

	if (location)
		g_dbus_dict_append_entry(&dict, "ChannelAllocation",
					DBUS_TYPE_UINT32, &location);

	if (metadata) {
		key = "Metadata";
		g_dbus_dict_append_basic_array(&dict, DBUS_TYPE_STRING, &key,
						DBUS_TYPE_BYTE,
						&metadata->iov_base,
						metadata->iov_len);
	}

	if (qos && qos->phy) {
		DBusMessageIter entry, variant, qos_dict;

		key = "QoS";
		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
							"a{sv}", &variant);
		dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
							"{sv}", &qos_dict);

		g_dbus_dict_append_entry(&qos_dict, "Framing", DBUS_TYPE_BYTE,
							&qos->framing);

		g_dbus_dict_append_entry(&qos_dict, "PHY", DBUS_TYPE_BYTE,
							&qos->phy);

		g_dbus_dict_append_entry(&qos_dict, "Retransmissions",
					DBUS_TYPE_BYTE, &qos->rtn);

		g_dbus_dict_append_entry(&qos_dict, "MaximumLatency",
					DBUS_TYPE_UINT16, &qos->latency);

		g_dbus_dict_append_entry(&qos_dict, "MinimumDelay",
					DBUS_TYPE_UINT32, &qos->pd_min);

		g_dbus_dict_append_entry(&qos_dict, "MaximumDelay",
					DBUS_TYPE_UINT32, &qos->pd_max);

		g_dbus_dict_append_entry(&qos_dict, "PreferredMinimumDelay",
					DBUS_TYPE_UINT32, &qos->ppd_min);

		g_dbus_dict_append_entry(&qos_dict, "PreferredMaximumDelay",
					DBUS_TYPE_UINT32, &qos->ppd_max);

		dbus_message_iter_close_container(&variant, &qos_dict);
		dbus_message_iter_close_container(&entry, &variant);
		dbus_message_iter_close_container(&dict, &entry);
	}

	dbus_message_iter_close_container(&iter, &dict);

	return media_endpoint_async_call(msg, endpoint, NULL, pac_select_cb,
								data, free);
}

static void pac_cancel_select(struct bt_bap_pac *lpac, bt_bap_pac_select_t cb,
						void *cb_data, void *user_data)
{
	struct media_endpoint *endpoint = user_data;
	GSList *l = endpoint->requests;

	while (l) {
		struct endpoint_request *req = l->data;
		struct pac_select_data *data;

		if (req->cb != pac_select_cb) {
			l = g_slist_next(l);
			continue;
		}

		data = req->user_data;
		if (data->pac != lpac || data->cb != cb ||
						data->user_data != cb_data) {
			l = g_slist_next(l);
			continue;
		}

		media_endpoint_cancel(req);
		l = endpoint->requests;
	}
}

struct pac_config_data {
	struct bt_bap_stream *stream;
	bt_bap_pac_config_t cb;
	void *user_data;
};

static int transport_cmp(gconstpointer data, gconstpointer user_data)
{
	const struct media_transport *transport = data;

	if (media_transport_get_stream((void *)transport) == user_data)
		return 0;

	return -1;
}

static struct media_transport *find_transport(struct media_endpoint *endpoint,
						void *stream)
{
	GSList *match;

	match = g_slist_find_custom(endpoint->transports, stream,
								transport_cmp);
	if (match == NULL)
		return NULL;

	return match->data;
}

static void pac_config_cb(struct media_endpoint *endpoint, void *ret, int size,
							void *user_data)
{
	struct pac_config_data *data = user_data;
	gboolean *ret_value = ret;
	struct media_transport *transport;

	/* If transport was cleared, configuration was cancelled */
	transport = find_transport(endpoint, data->stream);
	if (!transport)
		return;

	data->cb(data->stream, ret_value ? 0 : -EINVAL);
}

static struct media_transport *pac_ucast_config(struct bt_bap_stream *stream,
						struct iovec *cfg,
						struct media_endpoint *endpoint)
{
	struct bt_bap *bap = bt_bap_stream_get_session(stream);
	struct btd_service *service = bt_bap_get_user_data(bap);
	struct btd_device *device;
	const char *path;

	if (service)
		device = btd_service_get_device(service);
	else {
		struct bt_att *att = bt_bap_get_att(bap);
		int fd = bt_att_get_fd(att);

		device = btd_adapter_find_device_by_fd(fd);
	}

	if (!device) {
		error("Unable to find device");
		return NULL;
	}

	path = bt_bap_stream_get_user_data(stream);

	return media_transport_create(device, path, cfg->iov_base, cfg->iov_len,
					endpoint, stream);
}

static struct media_transport *pac_bcast_config(struct bt_bap_stream *stream,
						struct iovec *cfg,
						struct media_endpoint *endpoint)
{
	struct bt_bap *bap = bt_bap_stream_get_session(stream);
	struct btd_adapter *adapter = endpoint->adapter->btd_adapter;
	struct btd_device *device;
	const char *path;

	if (!adapter)
		return NULL;

	if (!strcmp(endpoint->uuid, BCAA_SERVICE_UUID))
		device = NULL;
	else
		device = btd_service_get_device(bt_bap_get_user_data(bap));

	path = bt_bap_stream_get_user_data(stream);

	return media_transport_create(device, path, cfg->iov_base, cfg->iov_len,
					endpoint, stream);
}

static int pac_config(struct bt_bap_stream *stream, struct iovec *cfg,
			struct bt_bap_qos *qos, bt_bap_pac_config_t cb,
			void *user_data)
{
	struct media_endpoint *endpoint = user_data;
	DBusConnection *conn = btd_get_dbus_connection();
	struct pac_config_data *data;
	struct media_transport *transport;
	DBusMessage *msg;
	DBusMessageIter iter;
	const char *path;

	DBG("endpoint %p stream %p", endpoint, stream);

	transport = find_transport(endpoint, stream);
	if (!transport) {
		switch (bt_bap_stream_get_type(stream)) {
		case BT_BAP_STREAM_TYPE_UCAST:
			transport = pac_ucast_config(stream, cfg, endpoint);
			break;
		case BT_BAP_STREAM_TYPE_BCAST:
			transport = pac_bcast_config(stream, cfg, endpoint);
			break;
		}

		if (!transport)
			return -EINVAL;

		endpoint->transports = g_slist_append(endpoint->transports,
								transport);
	}

	msg = dbus_message_new_method_call(endpoint->sender, endpoint->path,
						MEDIA_ENDPOINT_INTERFACE,
						"SetConfiguration");
	if (msg == NULL) {
		error("Couldn't allocate D-Bus message");
		endpoint_remove_transport(endpoint, transport);
		return FALSE;
	}

	data = new0(struct pac_config_data, 1);
	data->stream = stream;
	data->cb = cb;
	data->user_data = user_data;

	dbus_message_iter_init_append(msg, &iter);

	path = media_transport_get_path(transport);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &path);

	g_dbus_get_properties(conn, path, "org.bluez.MediaTransport1", &iter);

	return media_endpoint_async_call(msg, endpoint, transport,
					pac_config_cb, data, free);
}

static void pac_clear(struct bt_bap_stream *stream, void *user_data)
{
	struct media_endpoint *endpoint = user_data;
	struct media_transport *transport;

	DBG("endpoint %p stream %p", endpoint, stream);

	transport = find_transport(endpoint, stream);
	if (transport)
		clear_configuration(endpoint, transport);
}

static struct bt_bap_pac_ops pac_ops = {
	.select = pac_select,
	.cancel_select = pac_cancel_select,
	.config = pac_config,
	.clear = pac_clear,
};

static void bap_debug(const char *str, void *user_data)
{
	DBG("%s", str);
}

static bool endpoint_init_pac(struct media_endpoint *endpoint, uint8_t type,
								int *err)
{
	struct btd_gatt_database *database;
	struct gatt_db *db;
	struct iovec data;
	struct iovec *metadata = NULL;
	char *name;

	if (!(g_dbus_get_flags() & G_DBUS_FLAG_ENABLE_EXPERIMENTAL)) {
		DBG("D-Bus experimental not enabled");
		*err = -ENOTSUP;
		return false;
	}

	database = btd_adapter_get_database(endpoint->adapter->btd_adapter);
	if (!database) {
		error("Adapter database not found");
		return false;
	}

	if (!bt_bap_debug_caps(endpoint->capabilities, endpoint->size,
				bap_debug, NULL)) {
		error("Unable to parse endpoint capabilities");
		return false;
	}

	if (!bt_bap_debug_metadata(endpoint->metadata, endpoint->metadata_size,
					bap_debug, NULL)) {
		error("Unable to parse endpoint metadata");
		return false;
	}

	db = btd_gatt_database_get_db(database);

	data.iov_base = endpoint->capabilities;
	data.iov_len = endpoint->size;

	if (asprintf(&name, "%s:%s", endpoint->sender, endpoint->path) < 0) {
		error("Could not allocate name for pac %s:%s",
				endpoint->sender, endpoint->path);
		free(name);
		return false;
	}

	/* TODO: Add support for metadata */
	if (endpoint->metadata_size) {
		metadata = g_new0(struct iovec, 1);
		metadata->iov_base = endpoint->metadata;
		metadata->iov_len = endpoint->metadata_size;
	}

	endpoint->pac = bt_bap_add_vendor_pac(db, name, type, endpoint->codec,
				endpoint->cid, endpoint->vid, &endpoint->qos,
				&data, metadata);
	if (!endpoint->pac) {
		error("Unable to create PAC");
		free(name);
		free(metadata);
		return false;
	}

	bt_bap_pac_set_ops(endpoint->pac, &pac_ops, endpoint);

	DBG("PAC %s registered", name);

	free(name);
	free(metadata);

	return true;
}

static bool endpoint_init_pac_sink(struct media_endpoint *endpoint, int *err)
{
	return endpoint_init_pac(endpoint, BT_BAP_SINK, err);
}

static bool endpoint_init_pac_source(struct media_endpoint *endpoint, int *err)
{
	return endpoint_init_pac(endpoint, BT_BAP_SOURCE, err);
}

static bool endpoint_init_broadcast_source(struct media_endpoint *endpoint,
						int *err)
{
	return endpoint_init_pac(endpoint, BT_BAP_BCAST_SOURCE, err);
}

static bool endpoint_init_broadcast_sink(struct media_endpoint *endpoint,
						int *err)
{
	return endpoint_init_pac(endpoint, BT_BAP_BCAST_SINK, err);
}

static bool endpoint_init_asha(struct media_endpoint *endpoint,
						int *err)
{
	return true;
}

static bool endpoint_properties_exists(const char *uuid,
						struct btd_device *dev,
						void *user_data)
{
	struct media_adapter *adapter;

	adapter = find_adapter(dev);
	if (adapter == NULL)
		return false;

	if (media_adapter_find_endpoint(adapter, NULL, NULL, uuid) == NULL)
		return false;

	return true;
}

static void append_endpoint(struct media_endpoint *endpoint,
						DBusMessageIter *dict)
{
	DBusMessageIter entry, var, props;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
						&endpoint->sender);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "a{sv}",
								&var);

	dbus_message_iter_open_container(&var, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&props);

	dict_append_entry(&props, "Path", DBUS_TYPE_OBJECT_PATH,
							&endpoint->path);
	dict_append_entry(&props, "Codec", DBUS_TYPE_BYTE, &endpoint->codec);
	dict_append_array(&props, "Capabilities", DBUS_TYPE_BYTE,
				&endpoint->capabilities, endpoint->size);

	dbus_message_iter_close_container(&var, &props);
	dbus_message_iter_close_container(&entry, &var);
	dbus_message_iter_close_container(dict, &entry);
}

static bool endpoint_properties_get(const char *uuid,
						struct btd_device *dev,
						DBusMessageIter *iter,
						void *user_data)
{
	struct media_adapter *adapter;
	DBusMessageIter dict;
	GSList *l;

	adapter = find_adapter(dev);
	if (adapter == NULL)
		return false;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	for (l = adapter->endpoints; l; l = l->next) {
		struct media_endpoint *endpoint = l->data;

		if (strcasecmp(endpoint->uuid, uuid) != 0)
			continue;

		append_endpoint(endpoint, &dict);
	}

	dbus_message_iter_close_container(iter, &dict);

	return true;
}

static bool a2dp_endpoint_supported(struct btd_adapter *adapter)
{
	if (!btd_adapter_has_settings(adapter, MGMT_SETTING_BREDR))
		return false;

	return true;
}

static bool experimental_endpoint_supported(struct btd_adapter *adapter)
{
	if (!btd_adapter_has_exp_feature(adapter, EXP_FEAT_ISO_SOCKET))
		return false;

	if (!btd_adapter_has_settings(adapter, MGMT_SETTING_CIS_CENTRAL |
					MGMT_SETTING_CIS_PERIPHERAL))
		return false;

	return g_dbus_get_flags() & G_DBUS_FLAG_ENABLE_EXPERIMENTAL;
}

static bool experimental_broadcaster_ep_supported(struct btd_adapter *adapter)
{
	if (!btd_adapter_has_exp_feature(adapter, EXP_FEAT_ISO_SOCKET))
		return false;

	if (!btd_adapter_has_settings(adapter, MGMT_SETTING_ISO_BROADCASTER))
		return false;

	return g_dbus_get_flags() & G_DBUS_FLAG_ENABLE_EXPERIMENTAL;
}

static bool experimental_bcast_sink_ep_supported(struct btd_adapter *adapter)
{
	if (!btd_adapter_has_exp_feature(adapter, EXP_FEAT_ISO_SOCKET))
		return false;

	if (!btd_adapter_has_settings(adapter, MGMT_SETTING_ISO_SYNC_RECEIVER))
		return false;

	return g_dbus_get_flags() & G_DBUS_FLAG_ENABLE_EXPERIMENTAL;
}

static bool experimental_asha_supported(struct btd_adapter *adapter)
{
	return g_dbus_get_flags() & G_DBUS_FLAG_ENABLE_EXPERIMENTAL;
}

static const struct media_endpoint_init {
	const char *uuid;
	bool (*func)(struct media_endpoint *endpoint, int *err);
	bool (*supported)(struct btd_adapter *adapter);
} init_table[] = {
	{ A2DP_SOURCE_UUID, endpoint_init_a2dp_source,
				a2dp_endpoint_supported },
	{ A2DP_SINK_UUID, endpoint_init_a2dp_sink,
				a2dp_endpoint_supported },
	{ PAC_SINK_UUID, endpoint_init_pac_sink,
				experimental_endpoint_supported },
	{ PAC_SOURCE_UUID, endpoint_init_pac_source,
				experimental_endpoint_supported },
	{ BCAA_SERVICE_UUID, endpoint_init_broadcast_source,
			experimental_broadcaster_ep_supported },
	{ BAA_SERVICE_UUID, endpoint_init_broadcast_sink,
			experimental_bcast_sink_ep_supported },
	{ ASHA_PROFILE_UUID, endpoint_init_asha,
			experimental_asha_supported },
};

static struct media_endpoint *
media_endpoint_create(struct media_adapter *adapter,
						const char *sender,
						const char *path,
						const char *uuid,
						gboolean delay_reporting,
						uint8_t codec,
						uint16_t cid,
						uint16_t vid,
						struct bt_bap_pac_qos *qos,
						uint8_t *capabilities,
						int size,
						uint8_t *metadata,
						int metadata_size,
						int *err)
{
	struct media_endpoint *endpoint;
	const struct media_endpoint_init *init;
	size_t i;
	bool succeeded = false;

	endpoint = g_new0(struct media_endpoint, 1);
	endpoint->sender = g_strdup(sender);
	endpoint->path = g_strdup(path);
	endpoint->uuid = g_strdup(uuid);
	endpoint->codec = codec;
	endpoint->cid = cid;
	endpoint->vid = vid;
	endpoint->delay_reporting = delay_reporting;

	if (qos)
		endpoint->qos = *qos;

	if (size > 0) {
		endpoint->capabilities = g_new(uint8_t, size);
		memcpy(endpoint->capabilities, capabilities, size);
		endpoint->size = size;
	}

	if (metadata_size > 0) {
		endpoint->metadata = g_new(uint8_t, metadata_size);
		memcpy(endpoint->metadata, metadata, metadata_size);
		endpoint->metadata_size = metadata_size;
	}

	endpoint->adapter = adapter;

	for (i = 0; i < ARRAY_SIZE(init_table); i++) {
		init = &init_table[i];

		if (!init->supported(adapter->btd_adapter))
			continue;

		if (!strcasecmp(init->uuid, uuid)) {
			succeeded = init->func(endpoint, err);
			break;
		}
	}

	if (!succeeded) {
		error("Unable initialize endpoint for UUID %s", uuid);
		media_endpoint_destroy(endpoint);
		return NULL;
	}

	endpoint->watch = g_dbus_add_disconnect_watch(btd_get_dbus_connection(),
						sender, media_endpoint_exit,
						endpoint, NULL);

	if (media_adapter_find_endpoint(adapter, NULL, NULL, uuid) == NULL) {
		btd_profile_add_custom_prop(uuid, "a{sv}", "MediaEndpoints",
						endpoint_properties_exists,
						endpoint_properties_get,
						NULL);
	}

	adapter->endpoints = g_slist_append(adapter->endpoints, endpoint);
	info("Endpoint registered: sender=%s path=%s", sender, path);

	if (err)
		*err = 0;
	return endpoint;
}

struct vendor {
	uint16_t cid;
	uint16_t vid;
} __packed;

static int parse_properties(DBusMessageIter *props, const char **uuid,
				gboolean *delay_reporting, uint8_t *codec,
				uint16_t *cid, uint16_t *vid,
				struct bt_bap_pac_qos *qos,
				uint8_t **capabilities, int *size,
				uint8_t **metadata, int *metadata_size)
{
	gboolean has_uuid = FALSE;
	gboolean has_codec = FALSE;
	struct vendor vendor;

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
		} else if (strcasecmp(key, "Vendor") == 0) {
			if (var != DBUS_TYPE_UINT32)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, &vendor);
			*cid = vendor.cid;
			*vid = vendor.vid;
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
		} else if (strcasecmp(key, "Metadata") == 0) {
			DBusMessageIter array;

			if (var != DBUS_TYPE_ARRAY)
				return -EINVAL;

			dbus_message_iter_recurse(&value, &array);
			dbus_message_iter_get_fixed_array(&array, metadata,
							metadata_size);
		} else if (strcasecmp(key, "Framing") == 0) {
			if (var != DBUS_TYPE_BYTE)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, &qos->framing);
		} else if (strcasecmp(key, "PHY") == 0) {
			if (var != DBUS_TYPE_BYTE)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, &qos->phy);
		} else if (strcasecmp(key, "Retransmissions") == 0) {
			if (var != DBUS_TYPE_BYTE)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, &qos->rtn);
		} else if (strcasecmp(key, "MinimumDelay") == 0) {
			if (var != DBUS_TYPE_UINT16)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, &qos->pd_min);
		} else if (strcasecmp(key, "MaximumDelay") == 0) {
			if (var != DBUS_TYPE_UINT16)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, &qos->pd_max);
		} else if (strcasecmp(key, "PreferredMinimumDelay") == 0) {
			if (var != DBUS_TYPE_UINT16)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, &qos->ppd_min);
		} else if (strcasecmp(key, "PreferredMaximumDelay") == 0) {
			if (var != DBUS_TYPE_UINT16)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, &qos->ppd_max);
		} else if (strcasecmp(key, "Locations") == 0) {
			if (var != DBUS_TYPE_UINT32)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, &qos->location);
		} else if (strcasecmp(key, "Context") == 0) {
			if (var != DBUS_TYPE_UINT16)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, &qos->context);
		} else if (strcasecmp(key, "SupportedContext") == 0) {
			if (var != DBUS_TYPE_UINT16)
				return -EINVAL;
			dbus_message_iter_get_basic(&value,
						    &qos->supported_context);
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
	uint8_t codec = 0;
	uint16_t cid = 0;
	uint16_t vid = 0;
	struct bt_bap_pac_qos qos = {};
	uint8_t *capabilities = NULL;
	uint8_t *metadata = NULL;
	int size = 0;
	int metadata_size = 0;
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

	if (parse_properties(&props, &uuid, &delay_reporting, &codec, &cid,
			&vid, &qos, &capabilities, &size, &metadata,
			&metadata_size) < 0)
		return btd_error_invalid_args(msg);

	if (media_endpoint_create(adapter, sender, path, uuid, delay_reporting,
					codec, cid, vid, &qos, capabilities,
					size, metadata, metadata_size,
					&err) == NULL) {
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
		return btd_error_invalid_args(msg);

	sender = dbus_message_get_sender(msg);

	endpoint = media_adapter_find_endpoint(adapter, sender, path, NULL);
	if (endpoint == NULL)
		return btd_error_does_not_exist(msg);

	media_endpoint_remove(endpoint);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

#ifdef HAVE_AVRCP
static struct media_player *media_adapter_find_player(
						struct media_adapter *adapter,
						const char *sender,
						const char *path)
{
	GSList *l;

	for (l = adapter->players; l; l = l->next) {
		struct media_player *mp = l->data;

		if (sender && g_strcmp0(mp->sender, sender) != 0)
			continue;

		if (path && g_strcmp0(mp->path, path) != 0)
			continue;

		return mp;
	}

	return NULL;
}

static void release_player(struct media_player *mp)
{
	DBusMessage *msg;

	DBG("sender=%s path=%s", mp->sender, mp->path);

	msg = dbus_message_new_method_call(mp->sender, mp->path,
						MEDIA_PLAYER_INTERFACE,
						"Release");
	if (msg == NULL) {
		error("Couldn't allocate D-Bus message");
		return;
	}

	g_dbus_send_message(btd_get_dbus_connection(), msg);
}

static void media_player_free(gpointer data)
{
	DBusConnection *conn = btd_get_dbus_connection();
	struct media_player *mp = data;
	struct media_adapter *adapter = mp->adapter;

	if (mp->player) {
		adapter->players = g_slist_remove(adapter->players, mp);
		release_player(mp);
	}

	g_dbus_remove_watch(conn, mp->watch);
	g_dbus_remove_watch(conn, mp->properties_watch);
	g_dbus_remove_watch(conn, mp->seek_watch);

	if (mp->track)
		g_hash_table_unref(mp->track);

	if (mp->settings)
		g_hash_table_unref(mp->settings);

	g_timer_destroy(mp->timer);
	g_free(mp->sender);
	g_free(mp->path);
	g_free(mp->status);
	g_free(mp->name);
	g_free(mp);
}

static void media_player_destroy(struct media_player *mp)
{
	struct media_adapter *adapter = mp->adapter;

	DBG("sender=%s path=%s", mp->sender, mp->path);

	if (mp->player) {
		struct avrcp_player *player = mp->player;
		mp->player = NULL;
		adapter->players = g_slist_remove(adapter->players, mp);
		avrcp_unregister_player(player);
		return;
	}

	media_player_free(mp);
}

static void media_player_remove(void *data)
{
	struct media_player *mp = data;

	info("Player unregistered: sender=%s path=%s", mp->sender, mp->path);

	media_player_destroy(mp);
}

static GList *media_player_list_settings(void *user_data)
{
	struct media_player *mp = user_data;

	DBG("");

	if (mp->settings == NULL)
		return NULL;

	return g_hash_table_get_keys(mp->settings);
}

static const char *media_player_get_setting(const char *key, void *user_data)
{
	struct media_player *mp = user_data;

	DBG("%s", key);

	return g_hash_table_lookup(mp->settings, key);
}

static const char *media_player_get_player_name(void *user_data)
{
	struct media_player *mp = user_data;

	if (!mp->name)
		return "Player";

	return mp->name;
}

static void set_shuffle_setting(DBusMessageIter *iter, const char *value)
{
	const char *key = "Shuffle";
	dbus_bool_t val;
	DBusMessageIter var;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
						DBUS_TYPE_BOOLEAN_AS_STRING,
						&var);
	val = strcasecmp(value, "off") != 0;
	dbus_message_iter_append_basic(&var, DBUS_TYPE_BOOLEAN, &val);
	dbus_message_iter_close_container(iter, &var);
}

static const char *repeat_to_loop_status(const char *value)
{
	if (strcasecmp(value, "off") == 0)
		return "None";
	else if (strcasecmp(value, "singletrack") == 0)
		return "Track";
	else if (strcasecmp(value, "alltracks") == 0)
		return "Playlist";
	else if (strcasecmp(value, "group") == 0)
		return "Playlist";

	return NULL;
}

static void set_repeat_setting(DBusMessageIter *iter, const char *value)
{
	const char *key = "LoopStatus";
	const char *val;
	DBusMessageIter var;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
						DBUS_TYPE_STRING_AS_STRING,
						&var);
	val = repeat_to_loop_status(value);
	dbus_message_iter_append_basic(&var, DBUS_TYPE_STRING, &val);
	dbus_message_iter_close_container(iter, &var);
}

static int media_player_set_setting(const char *key, const char *value,
				    void *user_data)
{
	struct media_player *mp = user_data;
	const char *iface = MEDIA_PLAYER_INTERFACE;
	DBusMessage *msg;
	DBusMessageIter iter;
	const char *curval;

	DBG("%s = %s", key, value);

	curval = g_hash_table_lookup(mp->settings, key);
	if (!curval)
		return -EINVAL;

	if (strcasecmp(curval, value) == 0)
		return 0;

	msg = dbus_message_new_method_call(mp->sender, mp->path,
					DBUS_INTERFACE_PROPERTIES, "Set");
	if (msg == NULL) {
		error("Couldn't allocate D-Bus message");
		return -ENOMEM;
	}

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &iface);

	if (strcasecmp(key, "Shuffle") == 0)
		set_shuffle_setting(&iter, value);
	else if (strcasecmp(key, "Repeat") == 0)
		set_repeat_setting(&iter, value);

	g_dbus_send_message(btd_get_dbus_connection(), msg);

	return 0;
}

static GList *media_player_list_metadata(void *user_data)
{
	struct media_player *mp = user_data;

	DBG("");

	if (mp->track == NULL)
		return NULL;

	return g_hash_table_get_keys(mp->track);
}

static uint64_t media_player_get_uid(void *user_data)
{
	struct media_player *mp = user_data;

	DBG("%p", mp->track);

	if (mp->track == NULL)
		return UINT64_MAX;

	return 0;
}

static const char *media_player_get_metadata(const char *key, void *user_data)
{
	struct media_player *mp = user_data;

	DBG("%s", key);

	if (mp->track == NULL)
		return NULL;

	return g_hash_table_lookup(mp->track, key);
}

static const char *media_player_get_status(void *user_data)
{
	struct media_player *mp = user_data;

	return mp->status;
}

static uint32_t media_player_get_position(void *user_data)
{
	struct media_player *mp = user_data;
	double timedelta;
	uint32_t sec, msec;

	if (mp->status == NULL || strcasecmp(mp->status, "Playing") != 0)
		return mp->position;

	timedelta = g_timer_elapsed(mp->timer, NULL);

	sec = (uint32_t) timedelta;
	msec = (uint32_t) ((timedelta - sec) * 1000);

	return mp->position + sec * 1000 + msec;
}

static uint32_t media_player_get_duration(void *user_data)
{
	struct media_player *mp = user_data;

	return mp->duration;
}

static void media_player_set_volume(int8_t volume, struct btd_device *dev,
				    void *user_data)
{
	struct media_player *mp = user_data;

	if (mp->volume == volume)
		return;

	mp->volume = volume;
}

static bool media_player_send(struct media_player *mp, const char *name)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(mp->sender, mp->path,
					MEDIA_PLAYER_INTERFACE, name);
	if (msg == NULL) {
		error("Couldn't allocate D-Bus message");
		return false;
	}

	g_dbus_send_message(btd_get_dbus_connection(), msg);

	return true;
}

static bool media_player_play(void *user_data)
{
	struct media_player *mp = user_data;

	DBG("");

	if (!mp->play || !mp->control)
		return false;

	return media_player_send(mp, "Play");
}

static bool media_player_stop(void *user_data)
{
	struct media_player *mp = user_data;

	DBG("");

	if (!mp->control)
		return false;

	return media_player_send(mp, "Stop");
}

static bool media_player_pause(void *user_data)
{
	struct media_player *mp = user_data;

	DBG("");

	if (!mp->pause || !mp->control)
		return false;

	return media_player_send(mp, "Pause");
}

static bool media_player_next(void *user_data)
{
	struct media_player *mp = user_data;

	DBG("");

	if (!mp->next || !mp->control)
		return false;

	return media_player_send(mp, "Next");
}

static bool media_player_previous(void *user_data)
{
	struct media_player *mp = user_data;

	DBG("");

	if (!mp->previous || !mp->control)
		return false;

	return media_player_send(mp, "Previous");
}

static struct avrcp_player_cb player_cb = {
	.list_settings = media_player_list_settings,
	.get_setting = media_player_get_setting,
	.set_setting = media_player_set_setting,
	.list_metadata = media_player_list_metadata,
	.get_uid = media_player_get_uid,
	.get_metadata = media_player_get_metadata,
	.get_position = media_player_get_position,
	.get_duration = media_player_get_duration,
	.get_status = media_player_get_status,
	.get_name = media_player_get_player_name,
	.set_volume = media_player_set_volume,
	.play = media_player_play,
	.stop = media_player_stop,
	.pause = media_player_pause,
	.next = media_player_next,
	.previous = media_player_previous,
};

static void media_player_exit(DBusConnection *connection, void *user_data)
{
	struct media_player *mp = user_data;

	mp->watch = 0;
	media_player_remove(mp);
}

static gboolean set_status(struct media_player *mp, DBusMessageIter *iter)
{
	const char *value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING)
		return FALSE;

	dbus_message_iter_get_basic(iter, &value);
	DBG("Status=%s", value);

	if (g_strcmp0(mp->status, value) == 0)
		return TRUE;

	mp->position = media_player_get_position(mp);
	g_timer_start(mp->timer);

	g_free(mp->status);
	mp->status = g_strdup(value);

	avrcp_player_event(mp->player, AVRCP_EVENT_STATUS_CHANGED, mp->status);

	return TRUE;
}

static gboolean set_position(struct media_player *mp, DBusMessageIter *iter)
{
	uint64_t value;
	const char *status;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_INT64)
		return FALSE;

	dbus_message_iter_get_basic(iter, &value);

	value /= 1000;

	if (value > media_player_get_position(mp))
		status = "forward-seek";
	else
		status = "reverse-seek";

	mp->position = value;
	g_timer_start(mp->timer);

	DBG("Position=%u", mp->position);

	if (!mp->position) {
		avrcp_player_event(mp->player,
					AVRCP_EVENT_TRACK_REACHED_START, NULL);
		return TRUE;
	}

	/*
	 * If position is the maximum value allowed or greater than track's
	 * duration, we send a track-reached-end event.
	 */
	if (mp->position == UINT32_MAX || mp->position >= mp->duration) {
		avrcp_player_event(mp->player, AVRCP_EVENT_TRACK_REACHED_END,
									NULL);
		return TRUE;
	}

	/* Send a status change to force resync the position */
	avrcp_player_event(mp->player, AVRCP_EVENT_STATUS_CHANGED, status);

	return TRUE;
}

static void set_metadata(struct media_player *mp, const char *key,
							const char *value)
{
	DBG("%s=%s", key, value);
	g_hash_table_replace(mp->track, g_strdup(key), g_strdup(value));
}

static gboolean parse_string_metadata(struct media_player *mp, const char *key,
							DBusMessageIter *iter)
{
	const char *value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING)
		return FALSE;

	dbus_message_iter_get_basic(iter, &value);

	set_metadata(mp, key, value);

	return TRUE;
}

static gboolean parse_array_metadata(struct media_player *mp, const char *key,
							DBusMessageIter *iter)
{
	DBusMessageIter array;
	const char *value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return FALSE;

	dbus_message_iter_recurse(iter, &array);

	if (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_INVALID)
		return TRUE;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_STRING)
		return FALSE;

	dbus_message_iter_get_basic(&array, &value);

	set_metadata(mp, key, value);

	return TRUE;
}

static gboolean parse_int64_metadata(struct media_player *mp, const char *key,
							DBusMessageIter *iter)
{
	uint64_t value;
	char valstr[20];
	int type;

	type = dbus_message_iter_get_arg_type(iter);
	if (type == DBUS_TYPE_UINT64)
		warn("expected DBUS_TYPE_INT64 got DBUS_TYPE_UINT64");
	else if (type != DBUS_TYPE_INT64)
		return FALSE;

	dbus_message_iter_get_basic(iter, &value);

	if (strcasecmp(key, "Duration") == 0) {
		value /= 1000;
		mp->duration = value;
	}

	snprintf(valstr, 20, "%" PRIu64, value);

	set_metadata(mp, key, valstr);

	return TRUE;
}

static gboolean parse_int32_metadata(struct media_player *mp, const char *key,
							DBusMessageIter *iter)
{
	uint32_t value;
	char valstr[20];
	int type;

	type = dbus_message_iter_get_arg_type(iter);
	if (type == DBUS_TYPE_UINT32)
		warn("expected DBUS_TYPE_INT32 got DBUS_TYPE_UINT32");
	else if (type != DBUS_TYPE_INT32)
		return FALSE;

	dbus_message_iter_get_basic(iter, &value);

	snprintf(valstr, 20, "%u", value);

	set_metadata(mp, key, valstr);

	return TRUE;
}

static gboolean parse_player_metadata(struct media_player *mp,
							DBusMessageIter *iter)
{
	DBusMessageIter dict;
	DBusMessageIter var;
	int ctype;
	gboolean title = FALSE;
	uint64_t uid;

	ctype = dbus_message_iter_get_arg_type(iter);
	if (ctype != DBUS_TYPE_ARRAY)
		return FALSE;

	dbus_message_iter_recurse(iter, &dict);

	if (mp->track != NULL)
		g_hash_table_unref(mp->track);

	mp->track = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
								g_free);

	while ((ctype = dbus_message_iter_get_arg_type(&dict)) !=
							DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char *key;

		if (ctype != DBUS_TYPE_DICT_ENTRY)
			return FALSE;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return FALSE;

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			return FALSE;

		dbus_message_iter_recurse(&entry, &var);

		if (strcasecmp(key, "xesam:title") == 0) {
			if (!parse_string_metadata(mp, "Title", &var))
				return FALSE;
			title = TRUE;
		} else if (strcasecmp(key, "xesam:artist") == 0) {
			if (!parse_array_metadata(mp, "Artist", &var))
				return FALSE;
		} else if (strcasecmp(key, "xesam:album") == 0) {
			if (!parse_string_metadata(mp, "Album", &var))
				return FALSE;
		} else if (strcasecmp(key, "xesam:genre") == 0) {
			if (!parse_array_metadata(mp, "Genre", &var))
				return FALSE;
		} else if (strcasecmp(key, "mpris:length") == 0) {
			if (!parse_int64_metadata(mp, "Duration", &var))
				return FALSE;
		} else if (strcasecmp(key, "xesam:trackNumber") == 0) {
			if (!parse_int32_metadata(mp, "TrackNumber", &var))
				return FALSE;
		} else
			DBG("%s not supported, ignoring", key);

		dbus_message_iter_next(&dict);
	}

	if (title == FALSE)
		g_hash_table_insert(mp->track, g_strdup("Title"),
								g_strdup(""));

	mp->position = 0;
	g_timer_start(mp->timer);
	uid = media_player_get_uid(mp);

	avrcp_player_event(mp->player, AVRCP_EVENT_TRACK_CHANGED, &uid);
	avrcp_player_event(mp->player, AVRCP_EVENT_TRACK_REACHED_START, NULL);

	return TRUE;
}

static gboolean set_property(struct media_player *mp, const char *key,
							const char *value)
{
	const char *curval;

	curval = g_hash_table_lookup(mp->settings, key);
	if (g_strcmp0(curval, value) == 0)
		return TRUE;

	DBG("%s=%s", key, value);

	g_hash_table_replace(mp->settings, g_strdup(key), g_strdup(value));

	avrcp_player_event(mp->player, AVRCP_EVENT_SETTINGS_CHANGED, key);

	return TRUE;
}

static gboolean set_shuffle(struct media_player *mp, DBusMessageIter *iter)
{
	dbus_bool_t value;
	const char *strvalue;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_BOOLEAN)
		return FALSE;

	dbus_message_iter_get_basic(iter, &value);

	strvalue = value ? "alltracks" : "off";

	return set_property(mp, "Shuffle", strvalue);
}

static const char *loop_status_to_repeat(const char *value)
{
	if (strcasecmp(value, "None") == 0)
		return "off";
	else if (strcasecmp(value, "Track") == 0)
		return "singletrack";
	else if (strcasecmp(value, "Playlist") == 0)
		return "alltracks";

	return NULL;
}

static gboolean set_repeat(struct media_player *mp, DBusMessageIter *iter)
{
	const char *value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING)
		return FALSE;

	dbus_message_iter_get_basic(iter, &value);

	value = loop_status_to_repeat(value);
	if (value == NULL)
		return FALSE;

	return set_property(mp, "Repeat", value);
}

static gboolean set_flag(struct media_player *mp, DBusMessageIter *iter,
								bool *var)
{
	dbus_bool_t value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_BOOLEAN)
		return FALSE;

	dbus_message_iter_get_basic(iter, &value);

	*var = value;

	return TRUE;
}

static gboolean set_name(struct media_player *mp, DBusMessageIter *iter)
{
	const char *value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING)
		return FALSE;

	dbus_message_iter_get_basic(iter, &value);

	if (g_strcmp0(mp->name, value) == 0)
		return TRUE;

	g_free(mp->name);

	mp->name = g_strdup(value);

	return TRUE;
}

static gboolean set_player_property(struct media_player *mp, const char *key,
							DBusMessageIter *entry)
{
	DBusMessageIter var;

	if (dbus_message_iter_get_arg_type(entry) != DBUS_TYPE_VARIANT)
		return FALSE;

	dbus_message_iter_recurse(entry, &var);

	if (strcasecmp(key, "PlaybackStatus") == 0)
		return set_status(mp, &var);

	if (strcasecmp(key, "Position") == 0)
		return set_position(mp, &var);

	if (strcasecmp(key, "Metadata") == 0)
		return parse_player_metadata(mp, &var);

	if (strcasecmp(key, "Shuffle") == 0)
		return set_shuffle(mp, &var);

	if (strcasecmp(key, "LoopStatus") == 0)
		return set_repeat(mp, &var);

	if (strcasecmp(key, "CanPlay") == 0)
		return set_flag(mp, &var, &mp->play);

	if (strcasecmp(key, "CanPause") == 0)
		return set_flag(mp, &var, &mp->pause);

	if (strcasecmp(key, "CanGoNext") == 0)
		return set_flag(mp, &var, &mp->next);

	if (strcasecmp(key, "CanGoPrevious") == 0)
		return set_flag(mp, &var, &mp->previous);

	if (strcasecmp(key, "CanControl") == 0)
		return set_flag(mp, &var, &mp->control);

	if (strcasecmp(key, "Identity") == 0)
		return set_name(mp, &var);

	DBG("%s not supported, ignoring", key);

	return TRUE;
}

static gboolean parse_player_properties(struct media_player *mp,
							DBusMessageIter *iter)
{
	DBusMessageIter dict;
	int ctype;

	ctype = dbus_message_iter_get_arg_type(iter);
	if (ctype != DBUS_TYPE_ARRAY)
		return FALSE;

	dbus_message_iter_recurse(iter, &dict);

	while ((ctype = dbus_message_iter_get_arg_type(&dict)) !=
							DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char *key;

		if (ctype != DBUS_TYPE_DICT_ENTRY)
			return FALSE;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return FALSE;

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (set_player_property(mp, key, &entry) == FALSE)
			return FALSE;

		dbus_message_iter_next(&dict);
	}

	return TRUE;
}

static gboolean properties_changed(DBusConnection *connection, DBusMessage *msg,
							void *user_data)
{
	struct media_player *mp = user_data;
	DBusMessageIter iter;

	DBG("sender=%s path=%s", mp->sender, mp->path);

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_next(&iter);

	parse_player_properties(mp, &iter);

	return TRUE;
}

static gboolean position_changed(DBusConnection *connection, DBusMessage *msg,
							void *user_data)
{
	struct media_player *mp = user_data;
	DBusMessageIter iter;

	DBG("sender=%s path=%s", mp->sender, mp->path);

	dbus_message_iter_init(msg, &iter);

	set_position(mp, &iter);

	return TRUE;
}

static struct media_player *media_player_create(struct media_adapter *adapter,
						const char *sender,
						const char *path,
						int *err)
{
	DBusConnection *conn = btd_get_dbus_connection();
	struct media_player *mp;

	mp = g_new0(struct media_player, 1);
	mp->adapter = adapter;
	mp->sender = g_strdup(sender);
	mp->path = g_strdup(path);
	mp->timer = g_timer_new();
	mp->volume = -1;

	mp->watch = g_dbus_add_disconnect_watch(conn, sender,
						media_player_exit, mp,
						NULL);
	mp->properties_watch = g_dbus_add_properties_watch(conn, sender,
						path, MEDIA_PLAYER_INTERFACE,
						properties_changed,
						mp, NULL);
	mp->seek_watch = g_dbus_add_signal_watch(conn, sender,
						path, MEDIA_PLAYER_INTERFACE,
						"Seeked", position_changed,
						mp, NULL);
	mp->player = avrcp_register_player(adapter->btd_adapter, &player_cb,
							mp, media_player_free);
	if (!mp->player) {
		if (err)
			*err = -EPROTONOSUPPORT;
		media_player_destroy(mp);
		return NULL;
	}

	mp->settings = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
								g_free);

	adapter->players = g_slist_append(adapter->players, mp);

	info("Player registered: sender=%s path=%s", sender, path);

	if (err)
		*err = 0;

	return mp;
}
#endif /* HAVE_AVRCP */

static DBusMessage *register_player(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
#ifdef HAVE_AVRCP
	struct media_adapter *adapter = data;
	struct media_player *mp;
	DBusMessageIter args;
	const char *sender, *path;
	int err;

	sender = dbus_message_get_sender(msg);

	dbus_message_iter_init(msg, &args);

	dbus_message_iter_get_basic(&args, &path);
	dbus_message_iter_next(&args);

	if (media_adapter_find_player(adapter, sender, path) != NULL)
		return btd_error_already_exists(msg);

	mp = media_player_create(adapter, sender, path, &err);
	if (mp == NULL) {
		if (err == -EPROTONOSUPPORT)
			return btd_error_not_supported(msg);
		else
			return btd_error_invalid_args(msg);
	}

	if (parse_player_properties(mp, &args) == FALSE) {
		media_player_destroy(mp);
		return btd_error_invalid_args(msg);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
#else
	return btd_error_not_supported(msg);
#endif
}

static DBusMessage *unregister_player(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
#ifdef HAVE_AVRCP
	struct media_adapter *adapter = data;
	struct media_player *player;
	const char *sender, *path;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	sender = dbus_message_get_sender(msg);

	player = media_adapter_find_player(adapter, sender, path);
	if (player == NULL)
		return btd_error_does_not_exist(msg);

	media_player_remove(player);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
#else
	return btd_error_not_supported(msg);
#endif
}

static void app_free(void *data)
{
	struct media_app *app = data;

	queue_destroy(app->proxies, NULL);
	queue_destroy(app->endpoints, media_endpoint_remove);
#ifdef HAVE_AVRCP
	queue_destroy(app->players, media_player_remove);
#endif

	if (app->client) {
		g_dbus_client_set_disconnect_watch(app->client, NULL, NULL);
		g_dbus_client_set_proxy_handlers(app->client, NULL, NULL,
								NULL, NULL);
		g_dbus_client_set_ready_watch(app->client, NULL, NULL);
		g_dbus_client_unref(app->client);
	}

	if (app->reg)
		dbus_message_unref(app->reg);

	g_free(app->sender);
	g_free(app->path);

	free(app);
}

static void client_disconnect_cb(DBusConnection *conn, void *user_data)
{
	struct media_app *app = user_data;
	struct media_adapter *adapter = app->adapter;

	DBG("Client disconnected");

	if (queue_remove(adapter->apps, app))
		app_free(app);
}

static void app_register_endpoint(void *data, void *user_data)
{
	struct media_app *app = user_data;
	GDBusProxy *proxy = data;
	const char *iface = g_dbus_proxy_get_interface(proxy);
	const char *path = g_dbus_proxy_get_path(proxy);
	const char *uuid;
	gboolean delay_reporting = FALSE;
	uint8_t codec;
	struct vendor vendor;
	struct bt_bap_pac_qos qos;
	uint8_t *capabilities = NULL;
	int size = 0;
	uint8_t *metadata = NULL;
	int metadata_size = 0;
	DBusMessageIter iter, array;
	struct media_endpoint *endpoint;

	if (app->err)
		return;

	if (strcmp(iface, MEDIA_ENDPOINT_INTERFACE))
		return;

	/* Parse properties */
	if (!g_dbus_proxy_get_property(proxy, "UUID", &iter))
		goto fail;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		goto fail;

	dbus_message_iter_get_basic(&iter, &uuid);

	if (!g_dbus_proxy_get_property(proxy, "Codec", &iter))
		goto fail;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BYTE)
		goto fail;

	dbus_message_iter_get_basic(&iter, &codec);

	memset(&vendor, 0, sizeof(vendor));

	if (g_dbus_proxy_get_property(proxy, "Vendor", &iter)) {
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
			goto fail;

		dbus_message_iter_get_basic(&iter, &vendor);
	}

	/* DelayReporting and Capabilities are considered optional */
	if (g_dbus_proxy_get_property(proxy, "DelayReporting", &iter))	{
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BOOLEAN)
			goto fail;

		dbus_message_iter_get_basic(&iter, &delay_reporting);
	}

	if (g_dbus_proxy_get_property(proxy, "Capabilities", &iter)) {
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
			goto fail;

		dbus_message_iter_recurse(&iter, &array);
		dbus_message_iter_get_fixed_array(&array, &capabilities, &size);
	}

	if (g_dbus_proxy_get_property(proxy, "Metadata", &iter)) {
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
			goto fail;

		dbus_message_iter_recurse(&iter, &array);
		dbus_message_iter_get_fixed_array(&array, &metadata,
						&metadata_size);
	}

	/* Parse QoS preferences */
	memset(&qos, 0, sizeof(qos));
	if (g_dbus_proxy_get_property(proxy, "Framing", &iter)) {
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BYTE)
			goto fail;

		dbus_message_iter_get_basic(&iter, &qos.framing);
	}

	if (g_dbus_proxy_get_property(proxy, "PHY", &iter)) {
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BYTE)
			goto fail;

		dbus_message_iter_get_basic(&iter, &qos.phy);
	}

	if (g_dbus_proxy_get_property(proxy, "MaximumLatency", &iter)) {
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT16)
			goto fail;

		dbus_message_iter_get_basic(&iter, &qos.latency);
	}

	if (g_dbus_proxy_get_property(proxy, "MinimumDelay", &iter)) {
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
			goto fail;

		dbus_message_iter_get_basic(&iter, &qos.pd_min);
	}

	if (g_dbus_proxy_get_property(proxy, "MaximumDelay", &iter)) {
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
			goto fail;

		dbus_message_iter_get_basic(&iter, &qos.pd_max);
	}

	if (g_dbus_proxy_get_property(proxy, "PreferredMinimumDelay", &iter)) {
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
			goto fail;

		dbus_message_iter_get_basic(&iter, &qos.ppd_min);
	}

	if (g_dbus_proxy_get_property(proxy, "PreferredMaximumDelay", &iter)) {
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
			goto fail;

		dbus_message_iter_get_basic(&iter, &qos.ppd_min);
	}

	if (g_dbus_proxy_get_property(proxy, "Locations", &iter)) {
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
			goto fail;

		dbus_message_iter_get_basic(&iter, &qos.location);
	}

	if (g_dbus_proxy_get_property(proxy, "Context", &iter)) {
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT16)
			goto fail;

		dbus_message_iter_get_basic(&iter, &qos.context);
	}

	if (g_dbus_proxy_get_property(proxy, "SupportedContext", &iter)) {
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT16)
			goto fail;

		dbus_message_iter_get_basic(&iter, &qos.supported_context);
	}

	endpoint = media_endpoint_create(app->adapter, app->sender, path, uuid,
						delay_reporting, codec,
						vendor.cid, vendor.vid, &qos,
						capabilities, size,
						metadata, metadata_size,
						&app->err);
	if (!endpoint) {
		error("Unable to register endpoint %s:%s: %s", app->sender,
						path, strerror(-app->err));
		return;
	}

	queue_push_tail(app->endpoints, endpoint);

	return;

fail:
	app->err = -EINVAL;
}

static void app_register_player(void *data, void *user_data)
{
#ifdef HAVE_AVRCP
	struct media_app *app = user_data;
	GDBusProxy *proxy = data;
	const char *iface = g_dbus_proxy_get_interface(proxy);
	const char *path = g_dbus_proxy_get_path(proxy);
	struct media_player *player;
	DBusMessageIter iter;

	if (app->err)
		return;

	if (strcmp(iface, MEDIA_PLAYER_INTERFACE))
		return;

	player = media_player_create(app->adapter, app->sender, path,
							&app->err);
	if (!player)
		return;

	if (g_dbus_proxy_get_property(proxy, "PlaybackStatus", &iter)) {
		if (!set_status(player, &iter))
			goto fail;
	}

	if (g_dbus_proxy_get_property(proxy, "Position", &iter)) {
		if (!set_position(player, &iter))
			goto fail;
	}

	if (g_dbus_proxy_get_property(proxy, "Metadata", &iter)) {
		if (!parse_player_metadata(player, &iter))
			goto fail;
	}

	if (g_dbus_proxy_get_property(proxy, "Shuffle", &iter)) {
		if (!set_shuffle(player, &iter))
			goto fail;
	}

	if (g_dbus_proxy_get_property(proxy, "LoopStatus", &iter)) {
		if (!set_repeat(player, &iter))
			goto fail;
	}

	if (g_dbus_proxy_get_property(proxy, "CanPlay", &iter)) {
		if (!set_flag(player, &iter, &player->play))
			goto fail;
	}

	if (g_dbus_proxy_get_property(proxy, "CanPause", &iter)) {
		if (!set_flag(player, &iter, &player->pause))
			goto fail;
	}

	if (g_dbus_proxy_get_property(proxy, "CanGoNext", &iter)) {
		if (!set_flag(player, &iter, &player->next))
			goto fail;
	}

	if (g_dbus_proxy_get_property(proxy, "CanGoPrevious", &iter)) {
		if (!set_flag(player, &iter, &player->previous))
			goto fail;
	}

	if (g_dbus_proxy_get_property(proxy, "CanControl", &iter)) {
		if (!set_flag(player, &iter, &player->control))
			goto fail;
	}

	if (g_dbus_proxy_get_property(proxy, "Identity", &iter)) {
		if (!set_name(player, &iter))
			goto fail;
	}

	queue_push_tail(app->players, player);

	return;
fail:
	app->err = -EINVAL;
	error("Unable to register player %s:%s: %s", app->sender, path,
							strerror(-app->err));
	media_player_destroy(player);
#endif /* HAVE_AVRCP */
}

static void remove_app(void *data)
{
	struct media_app *app = data;

	/*
	 * Set callback to NULL to avoid potential race condition
	 * when calling remove_app and GDBusClient unref.
	 */
	g_dbus_client_set_disconnect_watch(app->client, NULL, NULL);

	/*
	 * Set proxy handlers to NULL, so that this gets called only once when
	 * the first proxy that belongs to this service gets removed.
	 */
	g_dbus_client_set_proxy_handlers(app->client, NULL, NULL, NULL, NULL);


	queue_remove(app->adapter->apps, app);

	app_free(app);
}

static void client_ready_cb(GDBusClient *client, void *user_data)
{
	struct media_app *app = user_data;
	DBusMessage *reply;
	bool fail = false;

	/*
	 * Process received objects
	 */
	if (queue_isempty(app->proxies)) {
		error("No object received");
		fail = true;
		reply = btd_error_failed(app->reg, "No object received");
		goto reply;
	}

	if (app->err) {
		if (app->err == -EPROTONOSUPPORT)
			reply = btd_error_not_supported(app->reg);
		else
			reply = btd_error_invalid_args(app->reg);
		goto reply;
	}

#ifdef HAVE_AVRCP
	if ((queue_isempty(app->endpoints) && queue_isempty(app->players))) {
#else
	if (queue_isempty(app->endpoints)) {
#endif
		error("No valid external Media objects found");
		fail = true;
		reply = btd_error_failed(app->reg,
					"No valid media object found");
		goto reply;
	}

	DBG("Media application registered: %s:%s", app->sender, app->path);

	reply = dbus_message_new_method_return(app->reg);

reply:
	g_dbus_send_message(btd_get_dbus_connection(), reply);
	dbus_message_unref(app->reg);
	app->reg = NULL;

	if (fail)
		remove_app(app);
}

static void proxy_added_cb(GDBusProxy *proxy, void *user_data)
{
	struct media_app *app = user_data;
	const char *iface, *path;

	if (app->err)
		return;

	queue_push_tail(app->proxies, proxy);

	iface = g_dbus_proxy_get_interface(proxy);
	path = g_dbus_proxy_get_path(proxy);

	DBG("Proxy added: %s, iface: %s", path, iface);

	app_register_endpoint(proxy, app);
	app_register_player(proxy, app);

}

static bool match_endpoint_by_path(const void *a, const void *b)
{
	const struct media_endpoint *endpoint = a;
	const char *path = b;

	return !strcmp(endpoint->path, path);
}

#ifdef HAVE_AVRCP
static bool match_player_by_path(const void *a, const void *b)
{
	const struct media_player *player = a;
	const char *path = b;

	return !strcmp(player->path, path);
}
#endif

static void proxy_removed_cb(GDBusProxy *proxy, void *user_data)
{
	struct media_app *app = user_data;
	struct media_endpoint *endpoint;
	const char *iface, *path;

	iface = g_dbus_proxy_get_interface(proxy);
	path = g_dbus_proxy_get_path(proxy);

	if (!strcmp(iface, MEDIA_ENDPOINT_INTERFACE)) {
		endpoint = queue_remove_if(app->endpoints,
						match_endpoint_by_path,
						(void *) path);
		if (!endpoint)
			return;

		if (!g_slist_find(app->adapter->endpoints, endpoint))
			return;

		DBG("Proxy removed - removing endpoint: %s", endpoint->path);

		media_endpoint_remove(endpoint);
#ifdef HAVE_AVRCP
	} else if (!strcmp(iface, MEDIA_PLAYER_INTERFACE)) {
		struct media_player *player;

		player = queue_remove_if(app->players, match_player_by_path,
						(void *) path);
		if (!player)
			return;

		if (!g_slist_find(app->adapter->players, player))
			return;

		DBG("Proxy removed - removing player: %s", player->path);

		media_player_remove(player);
#endif
	}
}

static struct media_app *create_app(DBusConnection *conn, DBusMessage *msg,
							const char *path)
{
	struct media_app *app;
	const char *sender = dbus_message_get_sender(msg);

	if (!path || !g_str_has_prefix(path, "/"))
		return NULL;

	app = new0(struct media_app, 1);

	app->client = g_dbus_client_new_full(conn, sender, path, path);
	if (!app->client)
		goto fail;

	app->sender = g_strdup(sender);
	if (!app->sender)
		goto fail;

	app->path = g_strdup(path);
	if (!app->path)
		goto fail;

	app->proxies = queue_new();
	app->endpoints = queue_new();
#ifdef HAVE_AVRCP
	app->players = queue_new();
#endif
	app->reg = dbus_message_ref(msg);

	g_dbus_client_set_disconnect_watch(app->client, client_disconnect_cb,
									app);
	g_dbus_client_set_proxy_handlers(app->client, proxy_added_cb,
					proxy_removed_cb, NULL, app);
	g_dbus_client_set_ready_watch(app->client, client_ready_cb, app);

	return app;

fail:
	app_free(app);
	return NULL;
}

struct match_data {
	const char *path;
	const char *sender;
};

static bool match_app(const void *a, const void *b)
{
	const struct media_app *app = a;
	const struct match_data *data = b;

	return g_strcmp0(app->path, data->path) == 0 &&
				g_strcmp0(app->sender, data->sender) == 0;
}

static DBusMessage *register_app(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct media_adapter *adapter = user_data;
	const char *sender = dbus_message_get_sender(msg);
	DBusMessageIter args;
	const char *path;
	struct media_app *app;
	struct match_data match_data;

	if (!dbus_message_iter_init(msg, &args))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&args, &path);

	match_data.path = path;
	match_data.sender = sender;

	if (queue_find(adapter->apps, match_app, &match_data))
		return btd_error_already_exists(msg);

	dbus_message_iter_next(&args);
	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		return btd_error_invalid_args(msg);

	app = create_app(conn, msg, path);
	if (!app)
		return btd_error_failed(msg, "Failed to register application");

	DBG("Registering application: %s:%s", sender, path);

	app->adapter = adapter;
	queue_push_tail(adapter->apps, app);

	return NULL;
}

static DBusMessage *unregister_app(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct media_adapter *adapter = user_data;
	const char *sender = dbus_message_get_sender(msg);
	const char *path;
	DBusMessageIter args;
	struct media_app *app;
	struct match_data match_data;

	if (!dbus_message_iter_init(msg, &args))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&args, &path);

	match_data.path = path;
	match_data.sender = sender;

	app = queue_remove_if(adapter->apps, match_app, &match_data);
	if (!app)
		return btd_error_does_not_exist(msg);

	app_free(app);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable media_methods[] = {
	{ GDBUS_METHOD("RegisterEndpoint",
		GDBUS_ARGS({ "endpoint", "o" }, { "properties", "a{sv}" }),
		NULL, register_endpoint) },
	{ GDBUS_METHOD("UnregisterEndpoint",
		GDBUS_ARGS({ "endpoint", "o" }), NULL, unregister_endpoint) },
	{ GDBUS_METHOD("RegisterPlayer",
		GDBUS_ARGS({ "player", "o" }, { "properties", "a{sv}" }),
		NULL, register_player) },
	{ GDBUS_METHOD("UnregisterPlayer",
		GDBUS_ARGS({ "player", "o" }), NULL, unregister_player) },
	{ GDBUS_ASYNC_METHOD("RegisterApplication",
					GDBUS_ARGS({ "application", "o" },
						{ "options", "a{sv}" }),
					NULL, register_app) },
	{ GDBUS_ASYNC_METHOD("UnregisterApplication",
					GDBUS_ARGS({ "application", "o" }),
					NULL, unregister_app) },
	{ },
};

static gboolean supported_uuids(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_adapter *adapter = data;
	DBusMessageIter entry;
	size_t i;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &entry);

	for (i = 0; i < ARRAY_SIZE(init_table); i++) {
		const struct media_endpoint_init *init = &init_table[i];

		if (init->supported(adapter->btd_adapter))
			dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
							&init->uuid);
	}

	dbus_message_iter_close_container(iter, &entry);

	return TRUE;
}

static bool probe_tx_timestamping(struct media_adapter *adapter)
{
	struct ifreq ifr = {};
	struct ethtool_ts_info cmd = {};
	int sk = -1;

	/* TX timestamping requires support from BlueZ in order to not mistake
	 * errqueue for socket errors in media stream sockets. This is always
	 * enabled (io_glib_add_err_watch), so need only check kernel side here.
	 */

	if (adapter->so_timestamping != -1)
		goto done;

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "hci%u",
				btd_adapter_get_index(adapter->btd_adapter));
	ifr.ifr_data = (void *)&cmd;
	cmd.cmd = ETHTOOL_GET_TS_INFO;

	/* Check kernel reports some support for TX timestamping for L2CAP. If
	 * yes then kernel version is new enough to have TX timestamping
	 * available for other socket types too.
	 */
	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0)
		goto error;
	if (ioctl(sk, SIOCETHTOOL, &ifr))
		goto error;
	close(sk);

	adapter->so_timestamping = cmd.so_timestamping;

done:
	return adapter->so_timestamping & SOF_TIMESTAMPING_TX_SOFTWARE;

error:
	if (sk >= 0)
		close(sk);
	adapter->so_timestamping = 0;
	return false;
}

static const struct {
	const char *name;
	bool (*probe)(struct media_adapter *adapter);
} features[] = {
	{ "tx-timestamping", probe_tx_timestamping },
};

static gboolean supported_features(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_adapter *adapter = data;
	DBusMessageIter entry;
	size_t i;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &entry);

	for (i = 0; i < ARRAY_SIZE(features); ++i)
		if (features[i].probe(adapter))
			dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
							&features[i].name);

	dbus_message_iter_close_container(iter, &entry);

	return TRUE;
}

static const GDBusPropertyTable media_properties[] = {
	{ "SupportedUUIDs", "as", supported_uuids },
	{ "SupportedFeatures", "as", supported_features },
	{ }
};

static void path_free(void *data)
{
	struct media_adapter *adapter = data;
	GSList *l;

	queue_destroy(adapter->apps, app_free);

	for (l = adapter->endpoints; l;) {
		struct media_endpoint *endpoint	= l->data;

		l = g_slist_next(l);

		release_endpoint(endpoint);
	}

#ifdef HAVE_AVRCP
	for (l = adapter->players; l;) {
		struct media_player *mp = l->data;

		l = g_slist_next(l);

		media_player_destroy(mp);
	}
#endif

	adapters = g_slist_remove(adapters, adapter);

	btd_adapter_unref(adapter->btd_adapter);
	g_free(adapter);
}

int media_register(struct btd_adapter *btd_adapter)
{
	struct media_adapter *adapter;

	adapter = g_new0(struct media_adapter, 1);
	adapter->btd_adapter = btd_adapter_ref(btd_adapter);
	adapter->apps = queue_new();
	adapter->so_timestamping = -1;

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
					adapter_get_path(btd_adapter),
					MEDIA_INTERFACE,
					media_methods, NULL, media_properties,
					adapter, path_free)) {
		error("D-Bus failed to register %s path",
						adapter_get_path(btd_adapter));
		path_free(adapter);
		return -1;
	}

	adapters = g_slist_append(adapters, adapter);

	return 0;
}

void media_unregister(struct btd_adapter *btd_adapter)
{
	GSList *l;

	for (l = adapters; l; l = l->next) {
		struct media_adapter *adapter = l->data;

		if (adapter->btd_adapter == btd_adapter) {
			g_dbus_unregister_interface(btd_get_dbus_connection(),
						adapter_get_path(btd_adapter),
						MEDIA_INTERFACE);
			return;
		}
	}
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

struct btd_adapter *media_endpoint_get_btd_adapter(
					struct media_endpoint *endpoint)
{
	return endpoint->adapter->btd_adapter;
}

bool media_endpoint_is_broadcast(struct media_endpoint *endpoint)
{
	if (!strcmp(endpoint->uuid, BCAA_SERVICE_UUID)
		|| !strcmp(endpoint->uuid, BAA_SERVICE_UUID))
		return true;

	return false;
}

const struct media_endpoint *media_endpoint_get_asha(void)
{
	/*
	 * Because ASHA does not require the application to register an
	 * endpoint, we need a minimal media_endpoint for transport creation to
	 * work, so let's create one
	 */
	static struct media_endpoint asha_endpoint =  {
		.uuid = ASHA_PROFILE_UUID,
		.codec = 0x2, /* Currently on G.722 is defined by the spec */
	};

	return &asha_endpoint;
}
