// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

#include <glib.h>

#include "gdbus/gdbus.h"

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/sdp.h"
#include "lib/uuid.h"

#include "src/dbus-common.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gatt-server.h"
#include "src/shared/bap.h"

#include "btio/btio.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/gatt-database.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/log.h"
#include "src/error.h"

#define PACS_UUID_STR "00001850-0000-1000-8000-00805f9b34fb"
#define MEDIA_ENDPOINT_INTERFACE "org.bluez.MediaEndpoint1"

struct bap_ep {
	char *path;
	struct bap_data *data;
	struct bt_bap_pac *lpac;
	struct bt_bap_pac *rpac;
	struct bt_bap_stream *stream;
	GIOChannel *io;
	unsigned int io_id;
	bool recreate;
	struct iovec *caps;
	struct iovec *metadata;
	struct bt_bap_qos qos;
	unsigned int id;
	DBusMessage *msg;
};

struct bap_data {
	struct btd_device *device;
	struct btd_service *service;
	struct bt_bap *bap;
	unsigned int ready_id;
	unsigned int state_id;
	unsigned int pac_id;
	struct queue *srcs;
	struct queue *snks;
	struct queue *streams;
	GIOChannel *listen_io;
};

static struct queue *sessions;

static void bap_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static void ep_unregister(void *data)
{
	struct bap_ep *ep = data;

	DBG("ep %p path %s", ep, ep->path);

	g_dbus_unregister_interface(btd_get_dbus_connection(), ep->path,
						MEDIA_ENDPOINT_INTERFACE);
}

static void bap_data_free(struct bap_data *data)
{
	if (data->listen_io) {
		g_io_channel_shutdown(data->listen_io, TRUE, NULL);
		g_io_channel_unref(data->listen_io);
	}

	if (data->service) {
		btd_service_set_user_data(data->service, NULL);
		bt_bap_set_user_data(data->bap, NULL);
	}

	queue_destroy(data->snks, ep_unregister);
	queue_destroy(data->srcs, ep_unregister);
	queue_destroy(data->streams, NULL);
	bt_bap_ready_unregister(data->bap, data->ready_id);
	bt_bap_state_unregister(data->bap, data->state_id);
	bt_bap_pac_unregister(data->pac_id);
	bt_bap_unref(data->bap);
	free(data);
}

static void bap_data_remove(struct bap_data *data)
{
	DBG("data %p", data);

	if (!queue_remove(sessions, data))
		return;

	bap_data_free(data);

	if (queue_isempty(sessions)) {
		queue_destroy(sessions, NULL);
		sessions = NULL;
	}
}

static void bap_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bap_data *data;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	data = btd_service_get_user_data(service);
	if (!data) {
		error("BAP service not handled by profile");
		return;
	}

	bap_data_remove(data);
}

static gboolean get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bap_ep *ep = data;
	const char *uuid;

	if (queue_find(ep->data->snks, NULL, ep))
		uuid = PAC_SINK_UUID;
	else
		uuid = PAC_SOURCE_UUID;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &uuid);

	return TRUE;
}

static gboolean get_codec(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bap_ep *ep = data;
	uint8_t codec;

	bt_bap_pac_get_codec(ep->rpac, &codec, NULL, NULL);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &codec);

	return TRUE;
}

static gboolean get_capabilities(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bap_ep *ep = data;
	DBusMessageIter array;
	struct iovec *d;

	bt_bap_pac_get_codec(ep->rpac, NULL, &d, NULL);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&d->iov_base, d->iov_len);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean get_device(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct bap_ep *ep = data;
	const char *path;

	path = device_get_path(ep->data->device);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);

	return TRUE;
}

static const GDBusPropertyTable ep_properties[] = {
	{ "UUID", "s", get_uuid, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Codec", "y", get_codec, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Capabilities", "ay", get_capabilities, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Device", "o", get_device, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};

static int parse_array(DBusMessageIter *iter, struct iovec **iov)
{
	DBusMessageIter array;

	if (!iov)
		return 0;

	if (!(*iov))
		*iov = new0(struct iovec, 1);

	dbus_message_iter_recurse(iter, &array);
	dbus_message_iter_get_fixed_array(&array, &(*iov)->iov_base,
						(int *)&(*iov)->iov_len);
	return 0;
}

static int parse_properties(DBusMessageIter *props, struct iovec **caps,
				struct iovec **metadata, struct bt_bap_qos *qos)
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
		} else if (!strcasecmp(key, "CIG")) {
			if (var != DBUS_TYPE_BYTE)
				goto fail;

			dbus_message_iter_get_basic(&value, &qos->cig_id);
		} else if (!strcasecmp(key, "CIS")) {
			if (var != DBUS_TYPE_BYTE)
				goto fail;

			dbus_message_iter_get_basic(&value, &qos->cis_id);
		} else if (!strcasecmp(key, "Interval")) {
			if (var != DBUS_TYPE_UINT32)
				goto fail;

			dbus_message_iter_get_basic(&value, &qos->interval);
		} else if (!strcasecmp(key, "Framing")) {
			dbus_bool_t val;

			if (var != DBUS_TYPE_BOOLEAN)
				goto fail;

			dbus_message_iter_get_basic(&value, &val);

			qos->framing = val;
		} else if (!strcasecmp(key, "PHY")) {
			const char *str;

			if (var != DBUS_TYPE_STRING)
				goto fail;

			dbus_message_iter_get_basic(&value, &str);

			if (!strcasecmp(str, "1M"))
				qos->phy = 0x01;
			else if (!strcasecmp(str, "2M"))
				qos->phy = 0x02;
			else
				goto fail;
		} else if (!strcasecmp(key, "SDU")) {
			if (var != DBUS_TYPE_UINT16)
				goto fail;

			dbus_message_iter_get_basic(&value, &qos->sdu);
		} else if (!strcasecmp(key, "Retransmissions")) {
			if (var != DBUS_TYPE_BYTE)
				goto fail;

			dbus_message_iter_get_basic(&value, &qos->rtn);
		} else if (!strcasecmp(key, "Latency")) {
			if (var != DBUS_TYPE_UINT16)
				goto fail;

			dbus_message_iter_get_basic(&value, &qos->latency);
		} else if (!strcasecmp(key, "Delay")) {
			if (var != DBUS_TYPE_UINT32)
				goto fail;

			dbus_message_iter_get_basic(&value, &qos->delay);
		} else if (!strcasecmp(key, "TargetLatency")) {
			if (var != DBUS_TYPE_BYTE)
				goto fail;

			dbus_message_iter_get_basic(&value,
							&qos->target_latency);
		}

		dbus_message_iter_next(props);
	}

	return 0;

fail:
	DBG("Failed parsing %s", key);

	if (*caps) {
		free(*caps);
		*caps = NULL;
	}

	return -EINVAL;
}

static void qos_cb(struct bt_bap_stream *stream, uint8_t code, uint8_t reason,
					void *user_data)
{
	struct bap_ep *ep = user_data;
	DBusMessage *reply;

	DBG("stream %p code 0x%02x reason 0x%02x", stream, code, reason);

	if (!ep->msg)
		return;

	if (!code)
		reply = dbus_message_new_method_return(ep->msg);
	else
		reply = btd_error_failed(ep->msg, "Unable to configure");

	g_dbus_send_message(btd_get_dbus_connection(), reply);

	dbus_message_unref(ep->msg);
	ep->msg = NULL;
}

static void config_cb(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	struct bap_ep *ep = user_data;
	DBusMessage *reply;

	DBG("stream %p code 0x%02x reason 0x%02x", stream, code, reason);

	ep->id = 0;

	if (!code)
		return;

	if (!ep->msg)
		return;

	reply = btd_error_failed(ep->msg, "Unable to configure");
	g_dbus_send_message(btd_get_dbus_connection(), reply);

	dbus_message_unref(ep->msg);
	ep->msg = NULL;
}

static void bap_io_close(struct bap_ep *ep)
{
	int fd;

	if (ep->io_id) {
		g_source_remove(ep->io_id);
		ep->io_id = 0;
	}

	if (!ep->io)
		return;


	DBG("ep %p", ep);

	fd = g_io_channel_unix_get_fd(ep->io);
	close(fd);

	g_io_channel_unref(ep->io);
	ep->io = NULL;
}

static DBusMessage *set_configuration(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct bap_ep *ep = data;
	const char *path;
	DBusMessageIter args, props;

	if (ep->msg)
		return btd_error_busy(msg);

	dbus_message_iter_init(msg, &args);

	dbus_message_iter_get_basic(&args, &path);
	dbus_message_iter_next(&args);

	dbus_message_iter_recurse(&args, &props);
	if (dbus_message_iter_get_arg_type(&props) != DBUS_TYPE_DICT_ENTRY)
		return btd_error_invalid_args(msg);

	/* Disconnect IO if connecting since QoS is going to be reconfigured */
	if (bt_bap_stream_io_is_connecting(ep->stream, NULL)) {
		bap_io_close(ep);
		bt_bap_stream_io_connecting(ep->stream, -1);
	}

	/* Mark CIG and CIS to be auto assigned */
	ep->qos.cig_id = BT_ISO_QOS_CIG_UNSET;
	ep->qos.cis_id = BT_ISO_QOS_CIS_UNSET;

	if (parse_properties(&props, &ep->caps, &ep->metadata, &ep->qos) < 0) {
		DBG("Unable to parse properties");
		return btd_error_invalid_args(msg);
	}

	/* TODO: Check if stream capabilities match add support for Latency
	 * and PHY.
	 */
	if (ep->stream)
		ep->id = bt_bap_stream_config(ep->stream, &ep->qos, ep->caps,
						config_cb, ep);
	else
		ep->stream = bt_bap_config(ep->data->bap, ep->lpac, ep->rpac,
						&ep->qos, ep->caps,
						config_cb, ep);

	if (!ep->stream) {
		DBG("Unable to config stream");
		free(ep->caps);
		ep->caps = NULL;
		return btd_error_invalid_args(msg);
	}

	bt_bap_stream_set_user_data(ep->stream, ep->path);
	ep->msg = dbus_message_ref(msg);

	return NULL;
}

static const GDBusMethodTable ep_methods[] = {
	{ GDBUS_EXPERIMENTAL_ASYNC_METHOD("SetConfiguration",
					GDBUS_ARGS({ "endpoint", "o" },
						{ "properties", "a{sv}" } ),
					NULL, set_configuration) },
	{ },
};

static void ep_free(void *data)
{
	struct bap_ep *ep = data;

	if (ep->id)
		bt_bap_stream_cancel(ep->stream, ep->id);

	bap_io_close(ep);

	free(ep->caps);
	free(ep->path);
	free(ep);
}

static struct bap_ep *ep_register(struct btd_service *service,
					struct bt_bap_pac *lpac,
					struct bt_bap_pac *rpac)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bap_data *data = btd_service_get_user_data(service);
	struct bap_ep *ep;
	struct queue *queue;
	int i, err;
	const char *suffix;

	switch (bt_bap_pac_get_type(rpac)) {
	case BT_BAP_SINK:
		queue = data->snks;
		i = queue_length(data->snks);
		suffix = "sink";
		break;
	case BT_BAP_SOURCE:
		queue = data->srcs;
		i = queue_length(data->srcs);
		suffix = "source";
		break;
	default:
		return NULL;
	}

	ep = new0(struct bap_ep, 1);
	ep->data = data;
	ep->lpac = lpac;
	ep->rpac = rpac;

	err = asprintf(&ep->path, "%s/pac_%s%d", device_get_path(device),
		       suffix, i);
	if (err < 0) {
		error("Could not allocate path for remote pac %s/pac%d",
				device_get_path(device), i);
		free(ep);
		return NULL;
	}

	if (g_dbus_register_interface(btd_get_dbus_connection(),
				ep->path, MEDIA_ENDPOINT_INTERFACE,
				ep_methods, NULL, ep_properties,
				ep, ep_free) == FALSE) {
		error("Could not register remote ep %s", ep->path);
		ep_free(ep);
		return NULL;
	}

	bt_bap_pac_set_user_data(rpac, ep->path);

	DBG("ep %p lpac %p rpac %p path %s", ep, ep->lpac, ep->rpac, ep->path);

	queue_push_tail(queue, ep);

	return ep;
}

static void select_cb(struct bt_bap_pac *pac, int err, struct iovec *caps,
				struct iovec *metadata, struct bt_bap_qos *qos,
				void *user_data)
{
	struct bap_ep *ep = user_data;

	if (err) {
		error("err %d", err);
		return;
	}

	ep->caps = caps;
	ep->metadata = metadata;
	ep->qos = *qos;

	/* TODO: Check if stream capabilities match add support for Latency
	 * and PHY.
	 */
	if (ep->stream)
		ep->id = bt_bap_stream_config(ep->stream, &ep->qos, ep->caps,
						config_cb, ep);
	else
		ep->stream = bt_bap_config(ep->data->bap, ep->lpac, ep->rpac,
						&ep->qos, ep->caps,
						config_cb, ep);

	if (!ep->stream) {
		DBG("Unable to config stream");
		free(ep->caps);
		ep->caps = NULL;
	}

	bt_bap_stream_set_user_data(ep->stream, ep->path);
}

static bool pac_found(struct bt_bap_pac *lpac, struct bt_bap_pac *rpac,
							void *user_data)
{
	struct btd_service *service = user_data;
	struct bap_ep *ep;

	DBG("lpac %p rpac %p", lpac, rpac);

	ep = ep_register(service, lpac, rpac);
	if (!ep) {
		error("Unable to register endpoint for pac %p", rpac);
		return true;
	}

	/* TODO: Cache LRU? */
	if (btd_service_is_initiator(service))
		bt_bap_select(lpac, rpac, select_cb, ep);

	return true;
}

static void bap_ready(struct bt_bap *bap, void *user_data)
{
	struct btd_service *service = user_data;

	DBG("bap %p", bap);

	bt_bap_foreach_pac(bap, BT_BAP_SOURCE, pac_found, service);
	bt_bap_foreach_pac(bap, BT_BAP_SINK, pac_found, service);
}

static bool match_ep_by_stream(const void *data, const void *user_data)
{
	const struct bap_ep *ep = data;
	const struct bt_bap_stream *stream = user_data;

	return ep->stream == stream;
}

static struct bap_ep *bap_find_ep_by_stream(struct bap_data *data,
					struct bt_bap_stream *stream)
{
	struct bap_ep *ep;

	ep = queue_find(data->snks, match_ep_by_stream, stream);
	if (ep)
		return ep;

	return queue_find(data->srcs, match_ep_by_stream, stream);
}

static void iso_connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct bt_bap_stream *stream = user_data;
	int fd;

	if (err) {
		error("%s", err->message);
		bt_bap_stream_set_io(stream, -1);
		return;
	}

	DBG("ISO connected");

	fd = g_io_channel_unix_get_fd(chan);

	if (bt_bap_stream_set_io(stream, fd)) {
		g_io_channel_set_close_on_unref(chan, FALSE);
		return;
	}

	error("Unable to set IO");
	bt_bap_stream_set_io(stream, -1);
}

static void bap_iso_qos(struct bt_bap_qos *qos, struct bt_iso_io_qos *io)
{
	if (!qos)
		return;

	io->interval = qos->interval;
	io->latency = qos->latency;
	io->sdu = qos->sdu;
	io->phy = qos->phy;
	io->rtn = qos->rtn;
}

static bool match_stream_qos(const void *data, const void *user_data)
{
	const struct bt_bap_stream *stream = data;
	const struct bt_iso_qos *iso_qos = user_data;
	struct bt_bap_qos *qos;

	qos = bt_bap_stream_get_qos((void *)stream);

	if (iso_qos->cig != qos->cig_id)
		return false;

	return iso_qos->cis == qos->cis_id;
}

static void iso_confirm_cb(GIOChannel *io, void *user_data)
{
	struct bap_data *data = user_data;
	struct bt_bap_stream *stream;
	struct bt_iso_qos qos;
	char address[18];
	GError *err = NULL;

	bt_io_get(io, &err,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_QOS, &qos,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	DBG("ISO: incoming connect from %s (CIG 0x%02x CIS 0x%02x)",
					address, qos.cig, qos.cis);

	stream = queue_remove_if(data->streams, match_stream_qos, &qos);
	if (!stream) {
		error("No matching stream found");
		goto drop;
	}

	if (!bt_io_accept(io, iso_connect_cb, stream, NULL, &err)) {
		error("bt_io_accept: %s", err->message);
		g_error_free(err);
		goto drop;
	}

	return;

drop:
	g_io_channel_shutdown(io, TRUE, NULL);
}

static void bap_accept_io(struct bap_data *data, struct bt_bap_stream *stream,
							int fd, int defer)
{
	char c;
	struct pollfd pfd;
	socklen_t len;

	if (fd < 0 || defer)
		return;

	/* Check if socket has DEFER_SETUP set */
	len = sizeof(defer);
	if (getsockopt(fd, SOL_BLUETOOTH, BT_DEFER_SETUP, &defer, &len) < 0)
		/* Ignore errors since the fd may be connected already */
		return;

	if (!defer)
		return;

	DBG("stream %p fd %d defer %s", stream, fd, defer ? "true" : "false");

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLOUT;

	if (poll(&pfd, 1, 0) < 0) {
		error("poll: %s (%d)", strerror(errno), errno);
		goto fail;
	}

	if (!(pfd.revents & POLLOUT)) {
		if (read(fd, &c, 1) < 0) {
			error("read: %s (%d)", strerror(errno), errno);
			goto fail;
		}
	}

	return;

fail:
	close(fd);
}

static void bap_create_io(struct bap_data *data, struct bap_ep *ep,
				struct bt_bap_stream *stream, int defer);

static gboolean bap_io_recreate(void *user_data)
{
	struct bap_ep *ep = user_data;

	DBG("ep %p", ep);

	ep->io_id = 0;

	bap_create_io(ep->data, ep, ep->stream, true);

	return FALSE;
}

static gboolean bap_io_disconnected(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct bap_ep *ep = user_data;

	DBG("ep %p recreate %s", ep, ep->recreate ? "true" : "false");

	ep->io_id = 0;

	bap_io_close(ep);

	/* Check if connecting recreate IO */
	if (ep->recreate) {
		ep->recreate = false;
		ep->io_id = g_idle_add(bap_io_recreate, ep);
	}

	return FALSE;
}

static void bap_connect_io_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct bap_ep *ep = user_data;

	if (!ep->stream)
		return;

	iso_connect_cb(chan, err, ep->stream);
}

static void bap_connect_io(struct bap_data *data, struct bap_ep *ep,
				struct bt_bap_stream *stream,
				struct bt_iso_qos *qos, int defer)
{
	struct btd_adapter *adapter = device_get_adapter(data->device);
	GIOChannel *io;
	GError *err = NULL;
	int fd;

	/* If IO already set skip creating it again */
	if (bt_bap_stream_get_io(stream))
		return;

	if (bt_bap_stream_io_is_connecting(stream, &fd)) {
		bap_accept_io(data, stream, fd, defer);
		return;
	}

	/* If IO channel still up wait for it to be disconnected and then
	 * recreate.
	 */
	if (ep->io) {
		ep->recreate = true;
		return;
	}

	if (ep->io_id) {
		g_source_remove(ep->io_id);
		ep->io_id = 0;
	}

	DBG("ep %p stream %p defer %s", ep, stream, defer ? "true" : "false");

	io = bt_io_connect(bap_connect_io_cb, ep, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR,
				btd_adapter_get_address(adapter),
				BT_IO_OPT_DEST_BDADDR,
				device_get_address(ep->data->device),
				BT_IO_OPT_DEST_TYPE,
				device_get_le_address_type(ep->data->device),
				BT_IO_OPT_MODE, BT_IO_MODE_ISO,
				BT_IO_OPT_QOS, qos,
				BT_IO_OPT_DEFER_TIMEOUT, defer,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("%s", err->message);
		g_error_free(err);
		return;
	}

	ep->io_id = g_io_add_watch(io, G_IO_HUP | G_IO_ERR | G_IO_NVAL,
						bap_io_disconnected, ep);

	ep->io = io;

	bt_bap_stream_io_connecting(stream, g_io_channel_unix_get_fd(io));
}

static void bap_listen_io(struct bap_data *data, struct bt_bap_stream *stream,
						struct bt_iso_qos *qos)
{
	struct btd_adapter *adapter = device_get_adapter(data->device);
	GIOChannel *io;
	GError *err = NULL;

	DBG("stream %p", stream);

	/* If IO already set skip creating it again */
	if (bt_bap_stream_get_io(stream) || data->listen_io)
		return;

	io = bt_io_listen(NULL, iso_confirm_cb, data, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR,
				btd_adapter_get_address(adapter),
				BT_IO_OPT_DEST_BDADDR,
				device_get_address(data->device),
				BT_IO_OPT_DEST_TYPE,
				device_get_le_address_type(data->device),
				BT_IO_OPT_MODE, BT_IO_MODE_ISO,
				BT_IO_OPT_QOS, qos,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("%s", err->message);
		g_error_free(err);
		return;
	}

	data->listen_io = io;
}

static void bap_create_io(struct bap_data *data, struct bap_ep *ep,
				struct bt_bap_stream *stream, int defer)
{
	struct bt_bap_qos *qos[2] = {};
	struct bt_iso_qos iso_qos;

	DBG("ep %p stream %p defer %s", ep, stream, defer ? "true" : "false");

	if (!data->streams)
		data->streams = queue_new();

	if (!queue_find(data->streams, NULL, stream))
		queue_push_tail(data->streams, stream);

	if (!bt_bap_stream_io_get_qos(stream, &qos[0], &qos[1])) {
		error("bt_bap_stream_get_qos_links: failed");
		return;
	}

	memset(&iso_qos, 0, sizeof(iso_qos));
	iso_qos.cig = qos[0] ? qos[0]->cig_id : qos[1]->cig_id;
	iso_qos.cis = qos[0] ? qos[0]->cis_id : qos[1]->cis_id;

	bap_iso_qos(qos[0], &iso_qos.in);
	bap_iso_qos(qos[1], &iso_qos.out);

	if (ep)
		bap_connect_io(data, ep, stream, &iso_qos, defer);
	else
		bap_listen_io(data, stream, &iso_qos);
}

static void bap_state(struct bt_bap_stream *stream, uint8_t old_state,
				uint8_t new_state, void *user_data)
{
	struct bap_data *data = user_data;
	struct bap_ep *ep;

	DBG("stream %p: %s(%u) -> %s(%u)", stream,
			bt_bap_stream_statestr(old_state), old_state,
			bt_bap_stream_statestr(new_state), new_state);

	if (new_state == old_state)
		return;

	ep = bap_find_ep_by_stream(data, stream);

	switch (new_state) {
	case BT_BAP_STREAM_STATE_IDLE:
		/* Release stream if idle */
		if (ep)
			bap_io_close(ep);
		else
			queue_remove(data->streams, stream);
		break;
	case BT_BAP_STREAM_STATE_CONFIG:
		if (ep && !ep->id) {
			bap_create_io(data, ep, stream, true);
			if (!ep->io) {
				error("Unable to create io");
				bt_bap_stream_release(stream, NULL, NULL);
				return;
			}


			/* Wait QoS response to respond */
			ep->id = bt_bap_stream_qos(stream, &ep->qos, qos_cb,
									ep);
			if (!ep->id) {
				error("Failed to Configure QoS");
				bt_bap_stream_release(stream, NULL, NULL);
			}
		}
		break;
	case BT_BAP_STREAM_STATE_QOS:
		bap_create_io(data, ep, stream, true);
		break;
	case BT_BAP_STREAM_STATE_ENABLING:
		if (ep)
			bap_create_io(data, ep, stream, false);
		break;
	}
}

static void pac_added(struct bt_bap_pac *pac, void *user_data)
{
	struct btd_service *service = user_data;
	struct bap_data *data;

	DBG("pac %p", pac);

	if (btd_service_get_state(service) != BTD_SERVICE_STATE_CONNECTED)
		return;

	data = btd_service_get_user_data(service);

	bt_bap_foreach_pac(data->bap, BT_BAP_SOURCE, pac_found, service);
	bt_bap_foreach_pac(data->bap, BT_BAP_SINK, pac_found, service);
}

static bool ep_match_rpac(const void *data, const void *match_data)
{
	const struct bap_ep *ep = data;
	const struct bt_bap_pac *pac = match_data;

	return ep->rpac == pac;
}

static void pac_removed(struct bt_bap_pac *pac, void *user_data)
{
	struct btd_service *service = user_data;
	struct bap_data *data;
	struct queue *queue;
	struct bap_ep *ep;

	DBG("pac %p", pac);

	if (btd_service_get_state(service) != BTD_SERVICE_STATE_CONNECTED)
		return;

	data = btd_service_get_user_data(service);

	switch (bt_bap_pac_get_type(pac)) {
	case BT_BAP_SINK:
		queue = data->srcs;
		break;
	case BT_BAP_SOURCE:
		queue = data->snks;
		break;
	default:
		return;
	}

	ep = queue_remove_if(queue, ep_match_rpac, pac);
	if (!ep)
		return;

	ep_unregister(ep);
}

static struct bap_data *bap_data_new(struct btd_device *device)
{
	struct bap_data *data;

	data = new0(struct bap_data, 1);
	data->device = device;
	data->srcs = queue_new();
	data->snks = queue_new();

	return data;
}

static void bap_data_add(struct bap_data *data)
{
	DBG("data %p", data);

	if (queue_find(sessions, NULL, data)) {
		error("data %p already added", data);
		return;
	}

	bt_bap_set_debug(data->bap, bap_debug, NULL, NULL);

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, data);

	if (data->service)
		btd_service_set_user_data(data->service, data);
}

static bool match_data(const void *data, const void *match_data)
{
	const struct bap_data *bdata = data;
	const struct bt_bap *bap = match_data;

	return bdata->bap == bap;
}

static void bap_connecting(struct bt_bap_stream *stream, bool state, int fd,
							void *user_data)
{
	struct bap_data *data = user_data;
	struct bap_ep *ep;
	GIOChannel *io;

	if (!state)
		return;

	ep = bap_find_ep_by_stream(data, stream);
	if (!ep)
		return;

	ep->recreate = false;

	if (!ep->io) {
		io = g_io_channel_unix_new(fd);
		ep->io = io;
	} else
		io = ep->io;

	g_io_channel_set_close_on_unref(io, FALSE);

	/* Attempt to get CIG/CIS if they have not been set */
	if (ep->qos.cig_id == BT_ISO_QOS_CIG_UNSET ||
				ep->qos.cis_id == BT_ISO_QOS_CIS_UNSET) {
		struct bt_iso_qos qos;
		GError *err = NULL;

		if (!bt_io_get(io, &err, BT_IO_OPT_QOS, &qos,
					BT_IO_OPT_INVALID)) {
			error("%s", err->message);
			g_error_free(err);
			g_io_channel_unref(io);
			return;
		}

		ep->qos.cig_id = qos.cig;
		ep->qos.cis_id = qos.cis;
	}

	DBG("stream %p fd %d: CIG 0x%02x CIS 0x%02x", stream, fd,
					ep->qos.cig_id, ep->qos.cis_id);
}

static void bap_attached(struct bt_bap *bap, void *user_data)
{
	struct bap_data *data;
	struct bt_att *att;
	struct btd_device *device;

	DBG("%p", bap);

	data = queue_find(sessions, match_data, bap);
	if (data)
		return;

	att = bt_bap_get_att(bap);
	if (!att)
		return;

	device = btd_adapter_find_device_by_fd(bt_att_get_fd(att));
	if (!device) {
		error("Unable to find device");
		return;
	}

	data = bap_data_new(device);
	data->bap = bap;

	bap_data_add(data);

	data->state_id = bt_bap_state_register(data->bap, bap_state,
						bap_connecting, data, NULL);
}

static void bap_detached(struct bt_bap *bap, void *user_data)
{
	struct bap_data *data;

	DBG("%p", bap);

	data = queue_find(sessions, match_data, bap);
	if (!data) {
		error("Unable to find bap session");
		return;
	}

	/* If there is a service it means there is PACS thus we can keep
	 * instance allocated.
	 */
	if (data->service)
		return;

	bap_data_remove(data);
}

static int bap_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct btd_adapter *adapter = device_get_adapter(device);
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct bap_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	if (!btd_adapter_has_exp_feature(adapter, EXP_FEAT_ISO_SOCKET)) {
		error("BAP requires ISO Socket which is not enabled");
		return -ENOTSUP;
	}

	/* Ignore, if we were probed for this device already */
	if (data) {
		error("Profile probed twice for the same device!");
		return -EINVAL;
	}

	data = bap_data_new(device);
	data->service = service;

	data->bap = bt_bap_new(btd_gatt_database_get_db(database),
					btd_device_get_gatt_db(device));
	if (!data->bap) {
		error("Unable to create BAP instance");
		free(data);
		return -EINVAL;
	}

	bap_data_add(data);

	data->ready_id = bt_bap_ready_register(data->bap, bap_ready, service,
								NULL);
	data->state_id = bt_bap_state_register(data->bap, bap_state,
						bap_connecting, data, NULL);
	data->pac_id = bt_bap_pac_register(pac_added, pac_removed, service,
								NULL);

	bt_bap_set_user_data(data->bap, service);

	return 0;
}

static int bap_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct bap_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	if (!data) {
		error("BAP service not handled by profile");
		return -EINVAL;
	}

	if (!bt_bap_attach(data->bap, client)) {
		error("BAP unable to attach");
		return -EINVAL;
	}

	btd_service_connecting_complete(service, 0);

	return 0;
}

static bool ep_remove(const void *data, const void *match_data)
{
	ep_unregister((void *)data);

	return true;
}

static int bap_disconnect(struct btd_service *service)
{
	struct bap_data *data = btd_service_get_user_data(service);

	queue_remove_all(data->snks, ep_remove, NULL, NULL);
	queue_remove_all(data->srcs, ep_remove, NULL, NULL);

	bt_bap_detach(data->bap);

	btd_service_disconnecting_complete(service, 0);

	return 0;
}

static struct btd_profile bap_profile = {
	.name		= "bap",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.remote_uuid	= PACS_UUID_STR,
	.device_probe	= bap_probe,
	.device_remove	= bap_remove,
	.accept		= bap_accept,
	.disconnect	= bap_disconnect,
};

static unsigned int bap_id = 0;

static int bap_init(void)
{
	if (!(g_dbus_get_flags() & G_DBUS_FLAG_ENABLE_EXPERIMENTAL)) {
		warn("D-Bus experimental not enabled");
		return -ENOTSUP;
	}

	btd_profile_register(&bap_profile);
	bap_id = bt_bap_register(bap_attached, bap_detached, NULL);

	return 0;
}

static void bap_exit(void)
{
	if (g_dbus_get_flags() & G_DBUS_FLAG_ENABLE_EXPERIMENTAL) {
		btd_profile_unregister(&bap_profile);
		bt_bap_unregister(bap_id);
	}
}

BLUETOOTH_PLUGIN_DEFINE(bap, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							bap_init, bap_exit)
