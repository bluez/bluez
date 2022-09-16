// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <errno.h>

#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/uuid.h"

#include "gdbus/gdbus.h"
#include "btio/btio.h"

#include "src/adapter.h"
#include "src/device.h"
#include "src/dbus-common.h"

#include "src/log.h"
#include "src/error.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/bap.h"
#include "src/shared/io.h"

#include "avdtp.h"
#include "media.h"
#include "transport.h"
#include "a2dp.h"
#include "sink.h"
#include "source.h"
#include "avrcp.h"

#define MEDIA_TRANSPORT_INTERFACE "org.bluez.MediaTransport1"

typedef enum {
	TRANSPORT_STATE_IDLE,		/* Not acquired and suspended */
	TRANSPORT_STATE_PENDING,	/* Playing but not acquired */
	TRANSPORT_STATE_REQUESTING,	/* Acquire in progress */
	TRANSPORT_STATE_ACTIVE,		/* Acquired and playing */
	TRANSPORT_STATE_SUSPENDING,     /* Release in progress */
} transport_state_t;

static char *str_state[] = {
	"TRANSPORT_STATE_IDLE",
	"TRANSPORT_STATE_PENDING",
	"TRANSPORT_STATE_REQUESTING",
	"TRANSPORT_STATE_ACTIVE",
	"TRANSPORT_STATE_SUSPENDING",
};

struct media_request {
	DBusMessage		*msg;
	guint			id;
};

struct media_owner {
	struct media_transport	*transport;
	struct media_request	*pending;
	char			*name;
	guint			watch;
};

struct a2dp_transport {
	struct avdtp		*session;
	uint16_t		delay;
	int8_t			volume;
};

struct bap_transport {
	struct bt_bap_stream	*stream;
	unsigned int		state_id;
	bool			linked;
	uint32_t		interval;
	uint8_t			framing;
	uint8_t			phy;
	uint16_t		sdu;
	uint8_t			rtn;
	uint16_t		latency;
	uint32_t		delay;
};

struct media_transport {
	char			*path;		/* Transport object path */
	struct btd_device	*device;	/* Transport device */
	const char		*remote_endpoint; /* Transport remote SEP */
	struct media_endpoint	*endpoint;	/* Transport endpoint */
	struct media_owner	*owner;		/* Transport owner */
	uint8_t			*configuration; /* Transport configuration */
	int			size;		/* Transport configuration size */
	int			fd;		/* Transport file descriptor */
	uint16_t		imtu;		/* Transport input mtu */
	uint16_t		omtu;		/* Transport output mtu */
	transport_state_t	state;
	guint			hs_watch;
	guint			source_watch;
	guint			sink_watch;
	guint			(*resume) (struct media_transport *transport,
					struct media_owner *owner);
	guint			(*suspend) (struct media_transport *transport,
					struct media_owner *owner);
	void			(*cancel) (struct media_transport *transport,
								guint id);
	void			(*set_state) (struct media_transport *transport,
						transport_state_t state);
	GDestroyNotify		destroy;
	void			*data;
};

static GSList *transports = NULL;

static const char *state2str(transport_state_t state)
{
	switch (state) {
	case TRANSPORT_STATE_IDLE:
	case TRANSPORT_STATE_REQUESTING:
		return "idle";
	case TRANSPORT_STATE_PENDING:
		return "pending";
	case TRANSPORT_STATE_ACTIVE:
	case TRANSPORT_STATE_SUSPENDING:
		return "active";
	}

	return NULL;
}

static gboolean state_in_use(transport_state_t state)
{
	switch (state) {
	case TRANSPORT_STATE_IDLE:
	case TRANSPORT_STATE_PENDING:
		return FALSE;
	case TRANSPORT_STATE_REQUESTING:
	case TRANSPORT_STATE_ACTIVE:
	case TRANSPORT_STATE_SUSPENDING:
		return TRUE;
	}

	return FALSE;
}

static struct media_transport *
find_transport_by_bap_stream(const struct bt_bap_stream *stream)
{
	GSList *l;

	for (l = transports; l; l = g_slist_next(l)) {
		struct media_transport *transport = l->data;
		const char *uuid = media_endpoint_get_uuid(transport->endpoint);
		struct bap_transport *bap;

		if (strcasecmp(uuid, PAC_SINK_UUID) &&
				strcasecmp(uuid, PAC_SOURCE_UUID))
			continue;

		bap = transport->data;

		if (bap->stream == stream)
			return transport;
	}

	return NULL;
}

static void transport_set_state(struct media_transport *transport,
							transport_state_t state)
{
	transport_state_t old_state = transport->state;
	const char *str;

	if (old_state == state)
		return;

	transport->state = state;

	DBG("State changed %s: %s -> %s", transport->path, str_state[old_state],
							str_state[state]);

	str = state2str(state);

	if (g_strcmp0(str, state2str(old_state)) != 0)
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
						transport->path,
						MEDIA_TRANSPORT_INTERFACE,
						"State");

	/* Update transport specific data */
	if (transport->set_state)
		transport->set_state(transport, state);
}

void media_transport_destroy(struct media_transport *transport)
{
	char *path;

	if (transport->sink_watch)
		sink_remove_state_cb(transport->sink_watch);

	if (transport->source_watch)
		source_remove_state_cb(transport->source_watch);

	path = g_strdup(transport->path);
	g_dbus_unregister_interface(btd_get_dbus_connection(), path,
						MEDIA_TRANSPORT_INTERFACE);

	g_free(path);
}

static struct media_request *media_request_create(DBusMessage *msg, guint id)
{
	struct media_request *req;

	req = g_new0(struct media_request, 1);
	req->msg = dbus_message_ref(msg);
	req->id = id;

	DBG("Request created: method=%s id=%u", dbus_message_get_member(msg),
									id);

	return req;
}

static void media_request_reply(struct media_request *req, int err)
{
	DBusMessage *reply;

	DBG("Request %s Reply %s", dbus_message_get_member(req->msg),
							strerror(err));

	if (!err)
		reply = g_dbus_create_reply(req->msg, DBUS_TYPE_INVALID);
	else
		reply = g_dbus_create_error(req->msg,
						ERROR_INTERFACE ".Failed",
						"%s", strerror(err));

	g_dbus_send_message(btd_get_dbus_connection(), reply);
}

static void media_owner_remove(struct media_owner *owner)
{
	struct media_transport *transport = owner->transport;
	struct media_request *req = owner->pending;

	if (!req)
		return;

	DBG("Owner %s Request %s", owner->name,
					dbus_message_get_member(req->msg));

	if (req->id)
		transport->cancel(transport, req->id);

	owner->pending = NULL;
	if (req->msg)
		dbus_message_unref(req->msg);

	g_free(req);
}

static void media_owner_free(struct media_owner *owner)
{
	DBG("Owner %s", owner->name);

	media_owner_remove(owner);

	g_free(owner->name);
	g_free(owner);
}

static void linked_transport_remove_owner(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	struct media_owner *owner = user_data;
	struct media_transport *transport;

	transport = find_transport_by_bap_stream(stream);
	if (!transport) {
		error("Unable to find transport");
		return;
	}

	DBG("Transport %s Owner %s", transport->path, owner->name);
	transport->owner = NULL;
}

static void media_transport_remove_owner(struct media_transport *transport)
{
	struct media_owner *owner = transport->owner;
	struct bap_transport *bap = transport->data;

	if (!transport->owner)
		return;

	DBG("Transport %s Owner %s", transport->path, owner->name);

	/* Reply if owner has a pending request */
	if (owner->pending)
		media_request_reply(owner->pending, EIO);

	transport->owner = NULL;
	if (bap->linked)
		queue_foreach(bt_bap_stream_io_get_links(bap->stream),
				linked_transport_remove_owner, owner);

	if (owner->watch)
		g_dbus_remove_watch(btd_get_dbus_connection(), owner->watch);

	media_owner_free(owner);

	if (state_in_use(transport->state))
		transport->suspend(transport, NULL);
}

static gboolean media_transport_set_fd(struct media_transport *transport,
					int fd, uint16_t imtu, uint16_t omtu)
{
	if (transport->fd == fd)
		return TRUE;

	transport->fd = fd;
	transport->imtu = imtu;
	transport->omtu = omtu;

	info("%s: fd(%d) ready", transport->path, fd);

	return TRUE;
}

static void a2dp_resume_complete(struct avdtp *session, int err,
							void *user_data)
{
	struct media_owner *owner = user_data;
	struct media_request *req = owner->pending;
	struct media_transport *transport = owner->transport;
	struct a2dp_sep *sep = media_endpoint_get_sep(transport->endpoint);
	struct avdtp_stream *stream;
	int fd;
	uint16_t imtu, omtu;
	gboolean ret;

	req->id = 0;

	if (err)
		goto fail;

	stream = a2dp_sep_get_stream(sep);
	if (stream == NULL)
		goto fail;

	ret = avdtp_stream_get_transport(stream, &fd, &imtu, &omtu, NULL);
	if (ret == FALSE)
		goto fail;

	media_transport_set_fd(transport, fd, imtu, omtu);

	ret = g_dbus_send_reply(btd_get_dbus_connection(), req->msg,
						DBUS_TYPE_UNIX_FD, &fd,
						DBUS_TYPE_UINT16, &imtu,
						DBUS_TYPE_UINT16, &omtu,
						DBUS_TYPE_INVALID);
	if (ret == FALSE)
		goto fail;

	media_owner_remove(owner);

	transport_set_state(transport, TRANSPORT_STATE_ACTIVE);

	return;

fail:
	media_transport_remove_owner(transport);
}

static guint resume_a2dp(struct media_transport *transport,
				struct media_owner *owner)
{
	struct a2dp_transport *a2dp = transport->data;
	struct media_endpoint *endpoint = transport->endpoint;
	struct a2dp_sep *sep = media_endpoint_get_sep(endpoint);
	guint id;

	if (a2dp->session == NULL) {
		a2dp->session = a2dp_avdtp_get(transport->device);
		if (a2dp->session == NULL)
			return 0;
	}

	if (state_in_use(transport->state))
		return a2dp_resume(a2dp->session, sep, a2dp_resume_complete,
									owner);

	if (a2dp_sep_lock(sep, a2dp->session) == FALSE)
		return 0;

	id = a2dp_resume(a2dp->session, sep, a2dp_resume_complete, owner);

	if (id == 0) {
		a2dp_sep_unlock(sep, a2dp->session);
		return 0;
	}

	if (transport->state == TRANSPORT_STATE_IDLE)
		transport_set_state(transport, TRANSPORT_STATE_REQUESTING);

	return id;
}

static void a2dp_suspend_complete(struct avdtp *session, int err,
							void *user_data)
{
	struct media_owner *owner = user_data;
	struct media_transport *transport = owner->transport;
	struct a2dp_transport *a2dp = transport->data;
	struct a2dp_sep *sep = media_endpoint_get_sep(transport->endpoint);

	/* Release always succeeds */
	if (owner->pending) {
		owner->pending->id = 0;
		media_request_reply(owner->pending, 0);
		media_owner_remove(owner);
	}

	a2dp_sep_unlock(sep, a2dp->session);
	transport_set_state(transport, TRANSPORT_STATE_IDLE);
	media_transport_remove_owner(transport);
}

static guint suspend_a2dp(struct media_transport *transport,
						struct media_owner *owner)
{
	struct a2dp_transport *a2dp = transport->data;
	struct media_endpoint *endpoint = transport->endpoint;
	struct a2dp_sep *sep = media_endpoint_get_sep(endpoint);

	if (owner != NULL)
		return a2dp_suspend(a2dp->session, sep, a2dp_suspend_complete,
									owner);

	transport_set_state(transport, TRANSPORT_STATE_IDLE);
	a2dp_sep_unlock(sep, a2dp->session);

	return 0;
}

static void cancel_a2dp(struct media_transport *transport, guint id)
{
	a2dp_cancel(id);
}

static void media_owner_exit(DBusConnection *connection, void *user_data)
{
	struct media_owner *owner = user_data;

	owner->watch = 0;

	media_owner_remove(owner);

	media_transport_remove_owner(owner->transport);
}

static void linked_transport_set_owner(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	struct media_owner *owner = user_data;
	struct media_transport *transport;

	transport = find_transport_by_bap_stream(stream);
	if (!transport) {
		error("Unable to find transport");
		return;
	}

	DBG("Transport %s Owner %s", transport->path, owner->name);
	transport->owner = owner;
}

static void media_transport_set_owner(struct media_transport *transport,
					struct media_owner *owner)
{
	struct bap_transport *bap = transport->data;

	DBG("Transport %s Owner %s", transport->path, owner->name);
	transport->owner = owner;

	if (bap->linked)
		queue_foreach(bt_bap_stream_io_get_links(bap->stream),
				linked_transport_set_owner, owner);

	owner->transport = transport;
	owner->watch = g_dbus_add_disconnect_watch(btd_get_dbus_connection(),
							owner->name,
							media_owner_exit,
							owner, NULL);
}

static struct media_owner *media_owner_create(DBusMessage *msg)
{
	struct media_owner *owner;

	owner = g_new0(struct media_owner, 1);
	owner->name = g_strdup(dbus_message_get_sender(msg));

	DBG("Owner created: sender=%s", owner->name);

	return owner;
}

static void media_owner_add(struct media_owner *owner,
						struct media_request *req)
{
	DBG("Owner %s Request %s", owner->name,
					dbus_message_get_member(req->msg));

	owner->pending = req;
}

static DBusMessage *acquire(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct media_transport *transport = data;
	struct media_owner *owner;
	struct media_request *req;
	guint id;

	if (transport->owner != NULL)
		return btd_error_not_authorized(msg);

	if (transport->state >= TRANSPORT_STATE_REQUESTING)
		return btd_error_not_authorized(msg);

	owner = media_owner_create(msg);
	id = transport->resume(transport, owner);
	if (id == 0) {
		media_owner_free(owner);
		return btd_error_not_authorized(msg);
	}

	req = media_request_create(msg, id);
	media_owner_add(owner, req);
	media_transport_set_owner(transport, owner);

	return NULL;
}

static DBusMessage *try_acquire(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct media_transport *transport = data;
	struct media_owner *owner;
	struct media_request *req;
	guint id;

	if (transport->owner != NULL)
		return btd_error_not_authorized(msg);

	if (transport->state >= TRANSPORT_STATE_REQUESTING)
		return btd_error_not_authorized(msg);

	if (transport->state != TRANSPORT_STATE_PENDING)
		return btd_error_not_available(msg);

	owner = media_owner_create(msg);
	id = transport->resume(transport, owner);
	if (id == 0) {
		media_owner_free(owner);
		return btd_error_not_authorized(msg);
	}

	req = media_request_create(msg, id);
	media_owner_add(owner, req);
	media_transport_set_owner(transport, owner);

	return NULL;
}

static DBusMessage *release(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct media_transport *transport = data;
	struct media_owner *owner = transport->owner;
	const char *sender;
	struct media_request *req;
	guint id;

	sender = dbus_message_get_sender(msg);

	if (owner == NULL || g_strcmp0(owner->name, sender) != 0)
		return btd_error_not_authorized(msg);

	if (owner->pending) {
		const char *member;

		member = dbus_message_get_member(owner->pending->msg);
		/* Cancel Acquire request if that exist */
		if (g_str_equal(member, "Acquire"))
			media_owner_remove(owner);
		else
			return btd_error_in_progress(msg);
	}

	transport_set_state(transport, TRANSPORT_STATE_SUSPENDING);

	id = transport->suspend(transport, owner);
	if (id == 0) {
		media_transport_remove_owner(transport);
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	}

	req = media_request_create(msg, id);
	media_owner_add(owner, req);

	return NULL;
}

static gboolean get_device(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	const char *path = device_get_path(transport->device);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);

	return TRUE;
}

static gboolean get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	const char *uuid = media_endpoint_get_uuid(transport->endpoint);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &uuid);

	return TRUE;
}

static gboolean get_codec(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	uint8_t codec = media_endpoint_get_codec(transport->endpoint);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &codec);

	return TRUE;
}

static gboolean get_configuration(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&transport->configuration,
						transport->size);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean get_state(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	const char *state = state2str(transport->state);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &state);

	return TRUE;
}

static gboolean delay_reporting_exists(const GDBusPropertyTable *property,
							void *data)
{
	struct media_transport *transport = data;
	struct a2dp_transport *a2dp = transport->data;

	return a2dp->delay != 0;
}

static gboolean get_delay_reporting(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct a2dp_transport *a2dp = transport->data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &a2dp->delay);

	return TRUE;
}

static gboolean volume_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_transport *transport = data;
	struct a2dp_transport *a2dp = transport->data;

	return a2dp->volume >= 0;
}

static gboolean get_volume(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct a2dp_transport *a2dp = transport->data;
	uint16_t volume = (uint16_t)a2dp->volume;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &volume);

	return TRUE;
}

static void set_volume(const GDBusPropertyTable *property,
			DBusMessageIter *iter, GDBusPendingPropertySet id,
			void *data)
{
	struct media_transport *transport = data;
	struct a2dp_transport *a2dp = transport->data;
	uint16_t arg;
	int8_t volume;
	bool notify;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_UINT16)
		goto error;

	dbus_message_iter_get_basic(iter, &arg);
	if (arg > INT8_MAX)
		goto error;

	g_dbus_pending_property_success(id);

	volume = (int8_t)arg;
	if (a2dp->volume == volume)
		return;

	notify = transport->source_watch ? true : false;
	if (notify) {
		a2dp->volume = volume;
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
						transport->path,
						MEDIA_TRANSPORT_INTERFACE,
						"Volume");
	}

	avrcp_set_volume(transport->device, volume, notify);
	return;

error:
	g_dbus_pending_property_error(id, ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
}

static gboolean endpoint_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_transport *transport = data;

	return transport->remote_endpoint != NULL;
}

static gboolean get_endpoint(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
					&transport->remote_endpoint);

	return TRUE;
}

static const GDBusMethodTable transport_methods[] = {
	{ GDBUS_ASYNC_METHOD("Acquire",
			NULL,
			GDBUS_ARGS({ "fd", "h" }, { "mtu_r", "q" },
							{ "mtu_w", "q" }),
			acquire) },
	{ GDBUS_ASYNC_METHOD("TryAcquire",
			NULL,
			GDBUS_ARGS({ "fd", "h" }, { "mtu_r", "q" },
							{ "mtu_w", "q" }),
			try_acquire) },
	{ GDBUS_ASYNC_METHOD("Release", NULL, NULL, release) },
	{ },
};

static const GDBusPropertyTable a2dp_properties[] = {
	{ "Device", "o", get_device },
	{ "UUID", "s", get_uuid },
	{ "Codec", "y", get_codec },
	{ "Configuration", "ay", get_configuration },
	{ "State", "s", get_state },
	{ "Delay", "q", get_delay_reporting, NULL, delay_reporting_exists },
	{ "Volume", "q", get_volume, set_volume, volume_exists },
	{ "Endpoint", "o", get_endpoint, NULL, endpoint_exists,
				G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};

static gboolean get_interval(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &bap->interval);

	return TRUE;
}

static gboolean get_framing(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;
	dbus_bool_t val = bap->framing;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &val);

	return TRUE;
}

static gboolean get_sdu(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &bap->sdu);

	return TRUE;
}

static gboolean get_retransmissions(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &bap->rtn);

	return TRUE;
}

static gboolean get_latency(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &bap->latency);

	return TRUE;
}

static gboolean get_delay(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &bap->delay);

	return TRUE;
}

static gboolean get_location(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;
	uint32_t location = bt_bap_stream_get_location(bap->stream);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &location);

	return TRUE;
}

static gboolean get_metadata(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;
	struct iovec *meta = bt_bap_stream_get_metadata(bap->stream);
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	if (meta)
		dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
							&meta->iov_base,
							meta->iov_len);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean links_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;

	return bap->linked;
}

static void append_links(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	DBusMessageIter *array = user_data;
	struct media_transport *transport;

	transport = find_transport_by_bap_stream(stream);
	if (!transport) {
		error("Unable to find transport");
		return;
	}

	dbus_message_iter_append_basic(array, DBUS_TYPE_OBJECT_PATH,
					&transport->path);
}

static gboolean get_links(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;
	struct queue *links = bt_bap_stream_io_get_links(bap->stream);
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_OBJECT_PATH_AS_STRING,
					&array);

	queue_foreach(links, append_links, &array);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static const GDBusPropertyTable bap_properties[] = {
	{ "Device", "o", get_device },
	{ "UUID", "s", get_uuid },
	{ "Codec", "y", get_codec },
	{ "Configuration", "ay", get_configuration },
	{ "State", "s", get_state },
	{ "Interval", "u", get_interval },
	{ "Framing", "b", get_framing },
	{ "SDU", "q", get_sdu },
	{ "Retransmissions", "y", get_retransmissions },
	{ "Latency", "q", get_latency },
	{ "Delay", "u", get_delay },
	{ "Endpoint", "o", get_endpoint, NULL, endpoint_exists },
	{ "Location", "u", get_location },
	{ "Metadata", "ay", get_metadata },
	{ "Links", "ao", get_links, NULL, links_exists },
	{ }
};

static void destroy_a2dp(void *data)
{
	struct a2dp_transport *a2dp = data;

	if (a2dp->session)
		avdtp_unref(a2dp->session);

	g_free(a2dp);
}

static void media_transport_free(void *data)
{
	struct media_transport *transport = data;

	transports = g_slist_remove(transports, transport);

	if (transport->owner)
		media_transport_remove_owner(transport);

	if (transport->destroy != NULL)
		transport->destroy(transport->data);

	g_free(transport->configuration);
	g_free(transport->path);
	g_free(transport);
}

static void transport_update_playing(struct media_transport *transport,
							gboolean playing)
{
	DBG("%s State=%s Playing=%d", transport->path,
					str_state[transport->state], playing);

	if (playing == FALSE) {
		if (transport->state == TRANSPORT_STATE_PENDING)
			transport_set_state(transport, TRANSPORT_STATE_IDLE);
		else if (transport->state == TRANSPORT_STATE_ACTIVE) {
			/* Remove owner */
			if (transport->owner != NULL)
				media_transport_remove_owner(transport);
		}
	} else if (transport->state == TRANSPORT_STATE_IDLE)
		transport_set_state(transport, TRANSPORT_STATE_PENDING);
}

static void sink_state_changed(struct btd_service *service,
						sink_state_t old_state,
						sink_state_t new_state,
						void *user_data)
{
	struct media_transport *transport = user_data;

	if (new_state == SINK_STATE_PLAYING)
		transport_update_playing(transport, TRUE);
	else
		transport_update_playing(transport, FALSE);
}

static void source_state_changed(struct btd_service *service,
						source_state_t old_state,
						source_state_t new_state,
						void *user_data)
{
	struct media_transport *transport = user_data;

	if (new_state == SOURCE_STATE_PLAYING)
		transport_update_playing(transport, TRUE);
	else
		transport_update_playing(transport, FALSE);
}

static int media_transport_init_source(struct media_transport *transport)
{
	struct btd_service *service;
	struct a2dp_transport *a2dp;

	service = btd_device_get_service(transport->device, A2DP_SINK_UUID);
	if (service == NULL)
		return -EINVAL;

	a2dp = g_new0(struct a2dp_transport, 1);

	transport->resume = resume_a2dp;
	transport->suspend = suspend_a2dp;
	transport->cancel = cancel_a2dp;
	transport->data = a2dp;
	transport->destroy = destroy_a2dp;

	a2dp->volume = -1;
	transport->sink_watch = sink_add_state_cb(service, sink_state_changed,
								transport);

	return 0;
}

static int media_transport_init_sink(struct media_transport *transport)
{
	struct btd_service *service;
	struct a2dp_transport *a2dp;

	service = btd_device_get_service(transport->device, A2DP_SOURCE_UUID);
	if (service == NULL)
		return -EINVAL;

	a2dp = g_new0(struct a2dp_transport, 1);

	transport->resume = resume_a2dp;
	transport->suspend = suspend_a2dp;
	transport->cancel = cancel_a2dp;
	transport->data = a2dp;
	transport->destroy = destroy_a2dp;

	a2dp->volume = 127;
	transport->source_watch = source_add_state_cb(service,
							source_state_changed,
							transport);

	return 0;
}

static void bap_enable_complete(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	struct media_owner *owner = user_data;

	if (code)
		media_transport_remove_owner(owner->transport);
}

static gboolean resume_complete(void *data)
{
	struct media_transport *transport = data;
	struct media_owner *owner = transport->owner;

	if (!owner)
		return FALSE;

	if (transport->fd < 0) {
		media_transport_remove_owner(transport);
		return FALSE;
	}

	if (owner->pending) {
		gboolean ret;

		ret = g_dbus_send_reply(btd_get_dbus_connection(),
					owner->pending->msg,
					DBUS_TYPE_UNIX_FD, &transport->fd,
					DBUS_TYPE_UINT16, &transport->imtu,
					DBUS_TYPE_UINT16, &transport->omtu,
						DBUS_TYPE_INVALID);
		if (!ret) {
			media_transport_remove_owner(transport);
			return FALSE;
		}
	}

	media_owner_remove(owner);

	transport_set_state(transport, TRANSPORT_STATE_ACTIVE);

	return FALSE;
}

static void bap_update_links(const struct media_transport *transport);

static bool match_link_transport(const void *data, const void *user_data)
{
	const struct bt_bap_stream *stream = data;
	const struct media_transport *transport;

	transport = find_transport_by_bap_stream(stream);
	if (!transport)
		return false;

	bap_update_links(transport);

	return true;
}

static void bap_update_links(const struct media_transport *transport)
{
	struct bap_transport *bap = transport->data;
	struct queue *links = bt_bap_stream_io_get_links(bap->stream);

	if (bap->linked == !queue_isempty(links))
		return;

	bap->linked = !queue_isempty(links);

	/* Check if the links transport has been create yet */
	if (bap->linked && !queue_find(links, match_link_transport, NULL)) {
		bap->linked = false;
		return;
	}

	g_dbus_emit_property_changed(btd_get_dbus_connection(), transport->path,
						MEDIA_TRANSPORT_INTERFACE,
						"Links");

	DBG("stream %p linked %s", bap->stream, bap->linked ? "true" : "false");
}

static guint resume_bap(struct media_transport *transport,
				struct media_owner *owner)
{
	struct bap_transport *bap = transport->data;
	guint id;

	if (!bap->stream)
		return 0;

	bap_update_links(transport);

	switch (bt_bap_stream_get_state(bap->stream)) {
	case BT_BAP_STREAM_STATE_ENABLING:
		bap_enable_complete(bap->stream, 0x00, 0x00, owner);
		if (owner->pending)
			return owner->pending->id;
		return 0;
	case BT_BAP_STREAM_STATE_STREAMING:
		return g_idle_add(resume_complete, transport);
	}

	id = bt_bap_stream_enable(bap->stream, bap->linked, NULL,
					bap_enable_complete, owner);
	if (!id)
		return 0;

	if (transport->state == TRANSPORT_STATE_IDLE)
		transport_set_state(transport, TRANSPORT_STATE_REQUESTING);

	return id;
}

static void bap_stop_complete(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	struct media_owner *owner = user_data;
	struct media_request *req = owner->pending;
	struct media_transport *transport = owner->transport;

	/* Release always succeeds */
	if (req) {
		req->id = 0;
		media_request_reply(req, 0);
		media_owner_remove(owner);
	}

	transport_set_state(transport, TRANSPORT_STATE_IDLE);
	media_transport_remove_owner(transport);
}

static void bap_disable_complete(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	bap_stop_complete(stream, code, reason, user_data);
}

static guint suspend_bap(struct media_transport *transport,
				struct media_owner *owner)
{
	struct bap_transport *bap = transport->data;
	bt_bap_stream_func_t func = NULL;

	if (!bap->stream)
		return 0;

	if (owner)
		func = bap_disable_complete;
	else
		transport_set_state(transport, TRANSPORT_STATE_IDLE);

	bap_update_links(transport);

	return bt_bap_stream_disable(bap->stream, bap->linked, func, owner);
}

static void cancel_bap(struct media_transport *transport, guint id)
{
	struct bap_transport *bap = transport->data;

	if (!bap->stream)
		return;

	bt_bap_stream_cancel(bap->stream, id);
}

static void link_set_state(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	transport_state_t state = PTR_TO_UINT(user_data);
	struct media_transport *transport;

	transport = find_transport_by_bap_stream(stream);
	if (!transport) {
		error("Unable to find transport");
		return;
	}

	transport_set_state(transport, state);
}

static void set_state_bap(struct media_transport *transport,
					transport_state_t state)
{
	struct bap_transport *bap = transport->data;

	if (!bap->linked)
		return;

	/* Update links */
	queue_foreach(bt_bap_stream_io_get_links(bap->stream), link_set_state,
							UINT_TO_PTR(state));
}

static void bap_state_changed(struct bt_bap_stream *stream, uint8_t old_state,
				uint8_t new_state, void *user_data)
{
	struct media_transport *transport = user_data;
	struct bap_transport *bap = transport->data;
	struct media_owner *owner = transport->owner;
	struct io *io;
	GIOChannel *chan;
	GError *err = NULL;
	int fd;
	uint16_t imtu, omtu;

	if (bap->stream != stream)
		return;

	DBG("stream %p: %s(%u) -> %s(%u)", stream,
			bt_bap_stream_statestr(old_state), old_state,
			bt_bap_stream_statestr(new_state), new_state);

	switch (new_state) {
	case BT_BAP_STREAM_STATE_IDLE:
	case BT_BAP_STREAM_STATE_CONFIG:
	case BT_BAP_STREAM_STATE_QOS:
		/* If a request is pending wait it to complete */
		if (owner && owner->pending)
			return;
		bap_update_links(transport);
		transport_update_playing(transport, FALSE);
		return;
	case BT_BAP_STREAM_STATE_DISABLING:
		return;
	case BT_BAP_STREAM_STATE_ENABLING:
		if (!bt_bap_stream_get_io(stream))
			return;
		break;
	case BT_BAP_STREAM_STATE_STREAMING:
		break;
	}

	io = bt_bap_stream_get_io(stream);
	if (!io) {
		error("Unable to get stream IO");
		/* TODO: Fail if IO has not been established */
		goto done;
	}

	fd = io_get_fd(io);
	if (fd < 0) {
		error("Unable to get IO fd");
		goto done;
	}

	chan = g_io_channel_unix_new(fd);

	if (!bt_io_get(chan, &err, BT_IO_OPT_OMTU, &omtu,
					BT_IO_OPT_IMTU, &imtu,
					BT_IO_OPT_INVALID)) {
		error("%s", err->message);
		goto done;
	}

	g_io_channel_unref(chan);

	media_transport_set_fd(transport, fd, imtu, omtu);
	transport_update_playing(transport, TRUE);

done:
	resume_complete(transport);
}

static void bap_connecting(struct bt_bap_stream *stream, bool state, int fd,
							void *user_data)
{
	struct media_transport *transport = user_data;
	struct bap_transport *bap = transport->data;

	if (bap->stream != stream)
		return;

	bap_update_links(transport);
}

static void free_bap(void *data)
{
	struct bap_transport *bap = data;

	bt_bap_state_unregister(bt_bap_stream_get_session(bap->stream),
							bap->state_id);
	free(bap);
}

static int media_transport_init_bap(struct media_transport *transport,
							void *stream)
{
	struct bt_bap_qos *qos;
	struct bap_transport *bap;

	qos = bt_bap_stream_get_qos(stream);

	bap = new0(struct bap_transport, 1);
	bap->stream = stream;
	bap->interval = qos->interval;
	bap->framing = qos->framing;
	bap->phy = qos->phy;
	bap->rtn = qos->rtn;
	bap->latency = qos->latency;
	bap->delay = qos->delay;
	bap->state_id = bt_bap_state_register(bt_bap_stream_get_session(stream),
						bap_state_changed,
						bap_connecting,
						transport, NULL);

	transport->data = bap;
	transport->resume = resume_bap;
	transport->suspend = suspend_bap;
	transport->cancel = cancel_bap;
	transport->set_state = set_state_bap;
	transport->destroy = free_bap;

	return 0;
}

struct media_transport *media_transport_create(struct btd_device *device,
						const char *remote_endpoint,
						uint8_t *configuration,
						size_t size, void *data,
						void *stream)
{
	struct media_endpoint *endpoint = data;
	struct media_transport *transport;
	const char *uuid;
	static int fd = 0;
	const GDBusPropertyTable *properties;

	transport = g_new0(struct media_transport, 1);
	transport->device = device;
	transport->endpoint = endpoint;
	transport->configuration = g_new(uint8_t, size);
	memcpy(transport->configuration, configuration, size);
	transport->size = size;
	transport->remote_endpoint = remote_endpoint;
	transport->path = g_strdup_printf("%s/fd%d",
				remote_endpoint ? remote_endpoint :
				device_get_path(device), fd++);
	transport->fd = -1;

	uuid = media_endpoint_get_uuid(endpoint);
	if (strcasecmp(uuid, A2DP_SOURCE_UUID) == 0) {
		if (media_transport_init_source(transport) < 0)
			goto fail;
		properties = a2dp_properties;
	} else if (strcasecmp(uuid, A2DP_SINK_UUID) == 0) {
		if (media_transport_init_sink(transport) < 0)
			goto fail;
		properties = a2dp_properties;
	} else if (!strcasecmp(uuid, PAC_SINK_UUID) ||
				!strcasecmp(uuid, PAC_SOURCE_UUID)) {
		if (media_transport_init_bap(transport, stream) < 0)
			goto fail;
		properties = bap_properties;
	} else
		goto fail;

	if (g_dbus_register_interface(btd_get_dbus_connection(),
				transport->path, MEDIA_TRANSPORT_INTERFACE,
				transport_methods, NULL, properties,
				transport, media_transport_free) == FALSE) {
		error("Could not register transport %s", transport->path);
		goto fail;
	}

	transports = g_slist_append(transports, transport);

	return transport;

fail:
	media_transport_free(transport);
	return NULL;
}

const char *media_transport_get_path(struct media_transport *transport)
{
	return transport->path;
}

void media_transport_update_delay(struct media_transport *transport,
							uint16_t delay)
{
	struct a2dp_transport *a2dp = transport->data;

	/* Check if delay really changed */
	if (a2dp->delay == delay)
		return;

	a2dp->delay = delay;

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
					transport->path,
					MEDIA_TRANSPORT_INTERFACE, "Delay");
}

struct btd_device *media_transport_get_dev(struct media_transport *transport)
{
	return transport->device;
}

int8_t media_transport_get_volume(struct media_transport *transport)
{
	struct a2dp_transport *a2dp = transport->data;
	return a2dp->volume;
}

void media_transport_update_volume(struct media_transport *transport,
								int8_t volume)
{
	struct a2dp_transport *a2dp = transport->data;

	if (volume < 0)
		return;

	/* Check if volume really changed */
	if (a2dp->volume == volume)
		return;

	a2dp->volume = volume;

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
					transport->path,
					MEDIA_TRANSPORT_INTERFACE, "Volume");
}

int8_t media_transport_get_device_volume(struct btd_device *dev)
{
	GSList *l;

	if (dev == NULL)
		return -1;

	/* Attempt to locate the transport to get its volume */
	for (l = transports; l; l = l->next) {
		struct media_transport *transport = l->data;
		if (transport->device != dev)
			continue;

		/* Volume is A2DP only */
		if (media_endpoint_get_sep(transport->endpoint))
			return media_transport_get_volume(transport);
	}

	/* If transport volume doesn't exists use device_volume */
	return btd_device_get_volume(dev);
}

void media_transport_update_device_volume(struct btd_device *dev,
								int8_t volume)
{
	GSList *l;

	if (dev == NULL || volume < 0)
		return;

	/* Attempt to locate the transport to set its volume */
	for (l = transports; l; l = l->next) {
		struct media_transport *transport = l->data;
		if (transport->device != dev)
			continue;

		/* Volume is A2DP only */
		if (media_endpoint_get_sep(transport->endpoint)) {
			media_transport_update_volume(transport, volume);
			return;
		}
	}

	/* If transport volume doesn't exists add to device_volume */
	btd_device_set_volume(dev, volume);
}
