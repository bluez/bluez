// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright 2023-2025 NXP
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <errno.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/sdp.h"
#include "bluetooth/uuid.h"

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
#include "src/shared/bass.h"
#include "src/shared/io.h"

#ifdef HAVE_A2DP
#include "avdtp.h"
#include "a2dp.h"
#include "sink.h"
#include "source.h"
#ifdef HAVE_AVRCP
#include "avrcp.h"
#endif
#endif

#ifdef HAVE_ASHA
#include "asha.h"
#endif

#include "media.h"
#include "transport.h"
#include "vcp.h"

#define MEDIA_TRANSPORT_INTERFACE "org.bluez.MediaTransport1"

typedef enum {
	TRANSPORT_STATE_IDLE,		/* Not acquired and suspended */
	TRANSPORT_STATE_PENDING,	/* Playing but not acquired */
	/* Playing but not acquired, applicable only for transports
	 * created by a broadcast sink
	 */
	TRANSPORT_STATE_BROADCASTING,
	TRANSPORT_STATE_REQUESTING,	/* Acquire in progress */
	TRANSPORT_STATE_ACTIVE,		/* Acquired and playing */
	TRANSPORT_STATE_SUSPENDING,     /* Release in progress */
} transport_state_t;

static const char *str_state[] = {
	"TRANSPORT_STATE_IDLE",
	"TRANSPORT_STATE_PENDING",
	"TRANSPORT_STATE_BROADCASTING",
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
	guint			watch;
	guint			resume_id;
	gboolean		cancel_resume;
	guint			cancel_id;
};

struct bap_transport {
	struct bt_bap_stream	*stream;
	unsigned int		state_id;
	bool			linked;
	struct bt_bap_qos	qos;
	guint			resume_id;
	struct iovec		*meta;
	guint			chan_id;
};

struct media_transport_ops {
	const char *uuid;
	const GDBusPropertyTable *properties;
	void (*set_owner)(struct media_transport *transport,
				struct media_owner *owner);
	void (*remove_owner)(struct media_transport *transport,
				struct media_owner *owner);
	void *(*init)(struct media_transport *transport, void *stream);
	guint (*resume)(struct media_transport *transport,
				struct media_owner *owner);
	guint (*suspend)(struct media_transport *transport,
				struct media_owner *owner);
	void (*cancel)(struct media_transport *transport, guint id);
	void (*set_state)(struct media_transport *transport,
				transport_state_t state);
	void *(*get_stream)(struct media_transport *transport);
	int (*get_volume)(struct media_transport *transport);
	int (*set_volume)(struct media_transport *transport, int level);
	int (*set_delay)(struct media_transport *transport, uint16_t delay);
	void (*update_links)(const struct media_transport *transport);
	GDestroyNotify destroy;
};

struct media_transport {
	char			*path;		/* Transport object path */
	struct btd_device	*device;	/* Transport device */
	struct btd_adapter	*adapter;	/* Transport adapter bcast*/
	char			*remote_endpoint; /* Transport remote SEP */
	struct media_endpoint	*endpoint;	/* Transport endpoint */
	struct media_owner	*owner;		/* Transport owner */
	uint8_t			*configuration; /* Transport configuration */
	int			size;		/* Transport configuration size */
	int			fd;		/* Transport file descriptor */
	uint16_t		imtu;		/* Transport input mtu */
	uint16_t		omtu;		/* Transport output mtu */
	transport_state_t	state;
	const struct media_transport_ops *ops;
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
	case TRANSPORT_STATE_BROADCASTING:
		return "broadcasting";
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
	case TRANSPORT_STATE_BROADCASTING:
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
				strcasecmp(uuid, PAC_SOURCE_UUID) &&
				strcasecmp(uuid, BAA_SERVICE_UUID))
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
	if (transport->ops && transport->ops->set_state)
		transport->ops->set_state(transport, state);
}

void media_transport_destroy(struct media_transport *transport)
{
	char *path;

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

	if (req->id && transport->ops && transport->ops->cancel)
		transport->ops->cancel(transport, req->id);

	owner->pending = NULL;
	if (req->msg)
		dbus_message_unref(req->msg);

	g_free(req);
}

static void media_owner_free(struct media_owner *owner)
{
	struct media_transport *transport = owner->transport;

	DBG("Owner %s", owner->name);

	media_owner_remove(owner);

	if (transport)
		transport->owner = NULL;

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

static guint media_transport_suspend(struct media_transport *transport,
					struct media_owner *owner)
{
	if (!state_in_use(transport->state))
		return 0;

	DBG("Transport %s Owner %s", transport->path, owner ? owner->name : "");

	if (transport->ops && transport->ops->suspend)
		return transport->ops->suspend(transport, owner);

	return 0;
}

static void transport_bap_remove_owner(struct media_transport *transport,
					struct media_owner *owner)
{
	struct bap_transport *bap = transport->data;

	if (bap && bap->linked)
		queue_foreach(bt_bap_stream_io_get_links(bap->stream),
				linked_transport_remove_owner, owner);
}

static void media_transport_remove_owner(struct media_transport *transport)
{
	struct media_owner *owner = transport->owner;

	if (!transport->owner)
		return;

	DBG("Transport %s Owner %s", transport->path, owner->name);

	/* Reply if owner has a pending request */
	if (owner->pending)
		media_request_reply(owner->pending, EIO);

	transport->owner = NULL;

	if (transport->ops && transport->ops->remove_owner)
		transport->ops->remove_owner(transport, owner);

	if (owner->watch)
		g_dbus_remove_watch(btd_get_dbus_connection(), owner->watch);

	media_owner_free(owner);

	media_transport_suspend(transport, NULL);
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

#ifdef HAVE_A2DP
static void *transport_a2dp_get_stream(struct media_transport *transport)
{
	struct a2dp_transport *a2dp = transport->data;
	struct a2dp_sep *sep = media_endpoint_get_sep(transport->endpoint);

	if (!sep)
		return NULL;

	return a2dp_sep_get_stream(sep, a2dp->session);
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

static guint transport_a2dp_suspend(struct media_transport *transport,
						struct media_owner *owner)
{
	struct a2dp_transport *a2dp = transport->data;
	struct media_endpoint *endpoint = transport->endpoint;
	struct a2dp_sep *sep = media_endpoint_get_sep(endpoint);

	if (owner != NULL) {
		if (a2dp->resume_id) {
			a2dp->cancel_resume = TRUE;
			return a2dp->resume_id;
		}

		return a2dp_suspend(a2dp->session, sep, a2dp_suspend_complete,
									owner);
	}

	transport_set_state(transport, TRANSPORT_STATE_IDLE);
	a2dp_sep_unlock(sep, a2dp->session);

	return 0;
}

static gboolean a2dp_cancel_resume_cb(void *user_data)
{
	struct media_owner *owner = user_data;
	struct media_transport *transport = owner->transport;
	struct a2dp_transport *a2dp = transport->data;
	guint id;

	a2dp->cancel_id = 0;

	if (!owner->pending)
		goto fail;

	owner->pending->id = 0;

	/* The suspend fails e.g. if stream was closed/aborted. This happens if
	 * SetConfiguration() was called while we were waiting for the START to
	 * complete.
	 *
	 * We bail out from the Release() with error in that case.
	 */
	id = transport_a2dp_suspend(transport, owner);
	if (id)
		owner->pending->id = id;
	else
		goto fail;

	return FALSE;

fail:
	media_transport_remove_owner(transport);
	return FALSE;
}

static void a2dp_resume_complete(struct avdtp *session, int err,
							void *user_data)
{
	struct media_owner *owner = user_data;
	struct media_request *req = owner->pending;
	struct media_transport *transport = owner->transport;
	struct a2dp_transport *a2dp = transport->data;
	struct avdtp_stream *stream;
	int fd;
	uint16_t imtu, omtu;
	gboolean ret;

	a2dp->resume_id = 0;

	if (!req)
		goto fail;

	req->id = 0;

	if (err)
		goto fail;

	if (a2dp->cancel_resume) {
		DBG("cancel resume");
		a2dp->cancel_id = g_idle_add(a2dp_cancel_resume_cb, owner);
		return;
	}

	stream = transport_a2dp_get_stream(transport);
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

static guint transport_a2dp_resume(struct media_transport *transport,
				struct media_owner *owner)
{
	struct a2dp_transport *a2dp = transport->data;
	struct media_endpoint *endpoint = transport->endpoint;
	struct a2dp_sep *sep = media_endpoint_get_sep(endpoint);
	guint id;

	if (a2dp->resume_id || a2dp->cancel_id)
		return 0;

	if (a2dp->session == NULL) {
		a2dp->session = a2dp_avdtp_get(transport->device);
		if (a2dp->session == NULL)
			return 0;
	}

	if (state_in_use(transport->state)) {
		id = a2dp_resume(a2dp->session, sep, a2dp_resume_complete,
									owner);
		goto done;
	}

	if (a2dp_sep_lock(sep, a2dp->session) == FALSE)
		return 0;

	id = a2dp_resume(a2dp->session, sep, a2dp_resume_complete, owner);

	if (id == 0) {
		a2dp_sep_unlock(sep, a2dp->session);
		return 0;
	}

	if (transport->state == TRANSPORT_STATE_IDLE)
		transport_set_state(transport, TRANSPORT_STATE_REQUESTING);

done:
	a2dp->resume_id = id;
	a2dp->cancel_resume = FALSE;
	return id;
}

static void transport_a2dp_cancel(struct media_transport *transport, guint id)
{
	struct a2dp_transport *a2dp = transport->data;

	/* a2dp_cancel() results to ABORT->IDLE->disconnect. For START we
	 * instead wait the operation out.
	 */
	if (id == a2dp->resume_id) {
		a2dp->cancel_resume = TRUE;
		return;
	}

	a2dp_cancel(id);
}

static void transport_a2dp_remove_owner(struct media_transport *transport,
					struct media_owner *owner)
{
	struct a2dp_transport *a2dp = transport->data;

	/* Cancel any pending operations for the owner */

	if (a2dp->cancel_id) {
		g_source_remove(a2dp->cancel_id);
		a2dp->cancel_id = 0;
	}

	if (a2dp->resume_id) {
		a2dp_cancel(a2dp->resume_id);
		a2dp->resume_id = 0;
	}

	a2dp->cancel_resume = FALSE;
}

static int transport_a2dp_get_volume(struct media_transport *transport)
{
	struct a2dp_transport *a2dp = transport->data;
	return a2dp->volume;
}

#ifdef HAVE_AVRCP
static int transport_a2dp_src_set_volume(struct media_transport *transport,
					int level)
{
	struct a2dp_transport *a2dp = transport->data;

	if (level < 0 || level > 127)
		return -EINVAL;

	if (a2dp->volume == level)
		return 0;

	return avrcp_set_volume(transport->device, level, false);
}

static int transport_a2dp_snk_set_volume(struct media_transport *transport,
					int level)
{
	struct a2dp_transport *a2dp = transport->data;
	bool notify;

	if (level < 0 || level > 127)
		return -EINVAL;

	if (a2dp->volume == level)
		return 0;

	notify = a2dp->watch ? true : false;
	if (notify) {
		a2dp->volume = level;
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
						transport->path,
						MEDIA_TRANSPORT_INTERFACE,
						"Volume");
	}

	return avrcp_set_volume(transport->device, level, notify);
}
#endif

static int transport_a2dp_snk_set_delay(struct media_transport *transport,
					uint16_t delay)
{
	struct a2dp_transport *a2dp = transport->data;
	struct avdtp_stream *stream;

	if (a2dp->delay == delay)
		return 0;

	if (a2dp->session == NULL) {
		a2dp->session = a2dp_avdtp_get(transport->device);
		if (a2dp->session == NULL)
			return -EIO;
	}

	stream = media_transport_get_stream(transport);
	if (stream == NULL)
		return -EIO;

	if (a2dp->watch) {
		a2dp->delay = delay;
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
						transport->path,
						MEDIA_TRANSPORT_INTERFACE,
						"Delay");
	}

	return avdtp_delay_report(a2dp->session, stream, delay);
}
#endif /* HAVE_A2DP */

static void media_owner_exit(DBusConnection *connection, void *user_data)
{
	struct media_owner *owner = user_data;

	DBG("Owner %s", owner->name);

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

static void transport_bap_set_owner(struct media_transport *transport,
					struct media_owner *owner)
{
	struct bap_transport *bap = transport->data;

	if (bap && bap->linked)
		queue_foreach(bt_bap_stream_io_get_links(bap->stream),
				linked_transport_set_owner, owner);
}

static void media_transport_set_owner(struct media_transport *transport,
					struct media_owner *owner)
{
	DBG("Transport %s Owner %s", transport->path, owner->name);
	transport->owner = owner;

	if (transport->ops && transport->ops->set_owner)
		transport->ops->set_owner(transport, owner);

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

static void *transport_bap_get_stream(struct media_transport *transport)
{
	struct bap_transport *bap = transport->data;

	return bap->stream;
}

static guint media_transport_resume(struct media_transport *transport,
					struct media_owner *owner)
{
	DBG("Transport %s Owner %s", transport->path, owner ? owner->name : "");

	if (transport->ops && transport->ops->resume)
		return transport->ops->resume(transport, owner);

	return 0;
}

static DBusMessage *acquire(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct media_transport *transport = data;
	struct media_owner *owner;
	struct media_request *req = NULL;
	guint id;

	if (transport->owner != NULL)
		return btd_error_not_authorized(msg);

	if (transport->state >= TRANSPORT_STATE_REQUESTING)
		return btd_error_not_authorized(msg);

	owner = media_owner_create(msg);

	if (!strcmp(media_endpoint_get_uuid(transport->endpoint),
						BAA_SERVICE_UUID)
		|| !strcmp(media_endpoint_get_uuid(transport->endpoint),
						BCAA_SERVICE_UUID)) {
		req = media_request_create(msg, 0x00);
		media_owner_add(owner, req);
		media_transport_set_owner(transport, owner);
	}

	id = media_transport_resume(transport, owner);
	if (id == 0) {
		media_owner_free(owner);
		return btd_error_not_authorized(msg);
	}

	if (!req) {
		req = media_request_create(msg, id);
		media_owner_add(owner, req);
		media_transport_set_owner(transport, owner);
	}

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

	if ((transport->state != TRANSPORT_STATE_PENDING) &&
		(transport->state != TRANSPORT_STATE_BROADCASTING))
		return btd_error_not_available(msg);

	owner = media_owner_create(msg);
	id = media_transport_resume(transport, owner);
	if (id == 0) {
		media_owner_free(owner);
		return btd_error_not_authorized(msg);
	}

	req = media_request_create(msg, id);
	media_owner_add(owner, req);
	media_transport_set_owner(transport, owner);

	return NULL;
}

static void bap_stop_complete(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	struct media_owner *owner = user_data;
	struct media_request *req;
	struct media_transport *transport;

	if (!owner)
		return;

	req = owner->pending;

	/* Release always succeeds */
	if (req) {
		req->id = 0;
		media_request_reply(req, 0);
		media_owner_remove(owner);
	}

	transport = owner->transport;

	if (transport) {
		transport_set_state(transport, TRANSPORT_STATE_IDLE);
		media_transport_remove_owner(transport);
	}
}

static void bap_disable_complete(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	bap_stop_complete(stream, code, reason, user_data);
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

	DBG("Owner %s", owner->name);

	if (owner->pending) {
		const char *member;

		member = dbus_message_get_member(owner->pending->msg);
		/* Cancel Acquire request if that exist */
		if (g_str_equal(member, "Acquire")) {
			media_request_reply(owner->pending, ECANCELED);
			media_owner_remove(owner);
		} else {
			return btd_error_in_progress(msg);
		}
	}

	transport_set_state(transport, TRANSPORT_STATE_SUSPENDING);

	id = media_transport_suspend(transport, owner);
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
	const char *path;

	if (transport->device)
		path = device_get_path(transport->device);
	else
		path = adapter_get_path(transport->adapter);

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

#ifdef HAVE_A2DP
static gboolean delay_reporting_exists(const GDBusPropertyTable *property,
							void *data)
{
	struct media_transport *transport = data;
	struct media_endpoint *endpoint = transport->endpoint;
	struct avdtp_stream *stream;

	/* Local A2DP sink decides itself if it has delay reporting */
	if (!strcmp(media_endpoint_get_uuid(endpoint), A2DP_SINK_UUID))
		return media_endpoint_get_delay_reporting(endpoint);

	stream = media_transport_get_stream(transport);
	if (stream == NULL)
		return FALSE;

	return avdtp_stream_has_delay_reporting(stream);
}

static gboolean get_delay_report(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct a2dp_transport *a2dp = transport->data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &a2dp->delay);

	return TRUE;
}

static int media_transport_set_delay(struct media_transport *transport,
					uint16_t delay)
{
	DBG("Transport %s delay %d", transport->path, delay);

	if (transport->ops && transport->ops->set_delay)
		return transport->ops->set_delay(transport, delay);

	return 0;
}

static void set_delay_report(const GDBusPropertyTable *property,
				DBusMessageIter *iter,
				GDBusPendingPropertySet id,
				void *data)
{
	struct media_transport *transport = data;
	struct media_owner *owner = transport->owner;
	const char *sender;
	uint16_t arg;
	int err;

	if (owner != NULL) {
		/* If the transport is acquired, do not allow to modify
		 * the delay anyone but the owner.
		 */
		sender = g_dbus_pending_property_get_sender(id);
		if (g_strcmp0(owner->name, sender) != 0) {
			g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".NotAuthorized",
					"Operation Not Authorized");
			return;
		}
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_UINT16) {
		g_dbus_pending_property_error(id,
				ERROR_INTERFACE ".InvalidArguments",
				"Expected UINT16");
		return;
	}

	dbus_message_iter_get_basic(iter, &arg);

	err = media_transport_set_delay(transport, arg);
	if (err) {
		error("Unable to set delay: %s (%d)", strerror(-err), err);
		g_dbus_pending_property_error(id,
						ERROR_INTERFACE ".Failed",
						"Internal error %s (%d)",
						strerror(-err), err);
		return;
	}

	g_dbus_pending_property_success(id);
}
#endif /* HAVE_A2DP */

static gboolean volume_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_transport *transport = data;
	int volume;

	if (media_transport_get_volume(transport, &volume))
		return FALSE;

	return volume >= 0;
}

int media_transport_get_volume(struct media_transport *transport, int *volume)
{
	if (transport->ops && transport->ops->get_volume) {
		*volume = transport->ops->get_volume(transport);
		return 0;
	}

	return -EINVAL;
}

static gboolean get_volume(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	int level;
	uint16_t volume;

	if (media_transport_get_volume(transport, &level))
		return FALSE;

	volume = level;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &volume);

	return TRUE;
}

static int media_transport_set_volume(struct media_transport *transport,
					int level)
{
	DBG("Transport %s level %d", transport->path, level);

	if (transport->ops && transport->ops->set_volume)
		return transport->ops->set_volume(transport, level);

	return 0;
}

static void set_volume(const GDBusPropertyTable *property,
			DBusMessageIter *iter, GDBusPendingPropertySet id,
			void *data)
{
	struct media_transport *transport = data;
	uint16_t arg;
	int err;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_UINT16) {
		g_dbus_pending_property_error(id,
				ERROR_INTERFACE ".InvalidArguments",
				"Expected UINT16");
		return;
	}

	dbus_message_iter_get_basic(iter, &arg);
	err = media_transport_set_volume(transport, arg);
	if (err == -EINVAL) {
		g_dbus_pending_property_error(id,
				ERROR_INTERFACE ".InvalidArguments",
				"Invalid volume value");
		return;
	} else if (err) {
		error("Unable to set volume: %s (%d)", strerror(-err), err);
		g_dbus_pending_property_error(id,
						ERROR_INTERFACE ".Failed",
						"Internal error %s (%d)",
						strerror(-err), err);
		return;
	}

	g_dbus_pending_property_success(id);
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

static DBusMessage *select_transport(DBusConnection *conn, DBusMessage *msg,
					void *data);

static DBusMessage *unselect_transport(DBusConnection *conn, DBusMessage *msg,
					void *data);

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
	{ GDBUS_ASYNC_METHOD("Select",
			NULL, NULL, select_transport) },
	{ GDBUS_ASYNC_METHOD("Unselect",
			NULL, NULL, unselect_transport) },
	{ },
};

#ifdef HAVE_A2DP
static const GDBusPropertyTable transport_a2dp_properties[] = {
	{ "Device", "o", get_device },
	{ "UUID", "s", get_uuid },
	{ "Codec", "y", get_codec },
	{ "Configuration", "ay", get_configuration },
	{ "State", "s", get_state },
	{ "Delay", "q", get_delay_report, set_delay_report,
				delay_reporting_exists },
	{ "Volume", "q", get_volume, set_volume, volume_exists },
	{ "Endpoint", "o", get_endpoint, NULL, endpoint_exists,
				G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};
#endif /* HAVE_A2DP */

static void append_io_qos(DBusMessageIter *dict, struct bt_bap_io_qos *qos)
{
	dict_append_entry(dict, "Interval", DBUS_TYPE_UINT32, &qos->interval);
	dict_append_entry(dict, "Latency", DBUS_TYPE_UINT16, &qos->latency);
	dict_append_entry(dict, "SDU", DBUS_TYPE_UINT16, &qos->sdu);
	dict_append_entry(dict, "PHY", DBUS_TYPE_BYTE, &qos->phy);
	dict_append_entry(dict, "Retransmissions", DBUS_TYPE_BYTE, &qos->rtn);
}

static gboolean get_ucast_qos(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;
	DBusMessageIter dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	dict_append_entry(&dict, "CIG", DBUS_TYPE_BYTE,
					&bap->qos.ucast.cig_id);
	dict_append_entry(&dict, "CIS", DBUS_TYPE_BYTE,
					&bap->qos.ucast.cis_id);
	dict_append_entry(&dict, "Framing", DBUS_TYPE_BYTE,
					&bap->qos.ucast.framing);
	dict_append_entry(&dict, "PresentationDelay", DBUS_TYPE_UINT32,
					&bap->qos.ucast.delay);

	append_io_qos(&dict, &bap->qos.ucast.io_qos);

	dbus_message_iter_close_container(iter, &dict);

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

static void bap_metadata_complete(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	GDBusPendingPropertySet id = PTR_TO_UINT(user_data);

	if (code)
		g_dbus_pending_property_error(id,
				ERROR_INTERFACE ".Failed",
				"Unable to set metadata");
	else
		g_dbus_pending_property_success(id);
}

static void set_metadata(const GDBusPropertyTable *property,
			DBusMessageIter *iter, GDBusPendingPropertySet id,
			void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;
	DBusMessageIter array;
	struct iovec iov;
	int ret;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY) {
		g_dbus_pending_property_error(id,
				ERROR_INTERFACE ".InvalidArguments",
				"Expected ARRAY");
		return;
	}

	dbus_message_iter_recurse(iter, &array);
	dbus_message_iter_get_fixed_array(&array, &iov.iov_base,
					(int *)&iov.iov_len);

	ret = bt_bap_stream_metadata(bap->stream, &iov, bap_metadata_complete,
				     UINT_TO_PTR(id));
	if (!ret)
		g_dbus_pending_property_error(id,
				ERROR_INTERFACE ".InvalidArguments",
				"Invalid metadata");
}

static gboolean links_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;

	return bap->linked;
}

static void append_link(void *data, void *user_data)
{
	struct bt_bap_stream *stream = data;
	DBusMessageIter *array = user_data;
	struct media_transport *transport;

	if (!stream)
		return;

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

	queue_foreach(links, append_link, &array);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static struct media_transport *find_transport_by_path(const char *path)
{
	GSList *l;

	for (l = transports; l; l = g_slist_next(l)) {
		struct media_transport *transport = l->data;

		if (g_str_equal(path, transport->path))
			return transport;
	}

	return NULL;
}

static void set_links(const GDBusPropertyTable *property,
				DBusMessageIter *iter,
				GDBusPendingPropertySet id, void *user_data)
{
	struct media_transport *transport = user_data;
	struct bap_transport *bap = transport->data;
	DBusMessageIter array;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY) {
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
		return;
	}

	dbus_message_iter_recurse(iter, &array);

	while (dbus_message_iter_get_arg_type(&array) ==
						DBUS_TYPE_OBJECT_PATH) {
		struct media_transport *link;
		struct bap_transport *bap_link;
		const char *path;

		dbus_message_iter_get_basic(&array, &path);

		link = find_transport_by_path(path);
		if (!link) {
			g_dbus_pending_property_error(id,
				ERROR_INTERFACE ".InvalidArguments",
				"Invalid arguments in method call");
			return;
		}

		bap_link = link->data;

		/* Link stream */
		bt_bap_stream_io_link(bap->stream, bap_link->stream);

		dbus_message_iter_next(&array);
	}

	g_dbus_pending_property_success(id);
}

static gboolean qos_ucast_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;

	return bap->qos.ucast.io_qos.phy != 0x00;
}

static const GDBusPropertyTable transport_bap_uc_properties[] = {
	{ "Device", "o", get_device },
	{ "UUID", "s", get_uuid },
	{ "Codec", "y", get_codec },
	{ "Configuration", "ay", get_configuration },
	{ "State", "s", get_state },
	{ "QoS", "a{sv}", get_ucast_qos, NULL, qos_ucast_exists },
	{ "Endpoint", "o", get_endpoint, NULL, endpoint_exists },
	{ "Location", "u", get_location },
	{ "Metadata", "ay", get_metadata, set_metadata },
	{ "Links", "ao", get_links, NULL, links_exists },
	{ "Volume", "q", get_volume, set_volume, volume_exists },
	{ }
};

static gboolean get_bcast_qos(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;
	DBusMessageIter dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	dict_append_entry(&dict, "BIG", DBUS_TYPE_BYTE,
					&bap->qos.bcast.big);
	dict_append_entry(&dict, "BIS", DBUS_TYPE_BYTE,
					&bap->qos.bcast.bis);
	dict_append_entry(&dict, "SyncFactor", DBUS_TYPE_BYTE,
					&bap->qos.bcast.sync_factor);
	dict_append_entry(&dict, "Packing", DBUS_TYPE_BYTE,
					&bap->qos.bcast.packing);
	dict_append_entry(&dict, "Framing", DBUS_TYPE_BYTE,
					&bap->qos.bcast.framing);
	dict_append_entry(&dict, "Encryption", DBUS_TYPE_BYTE,
					&bap->qos.bcast.encryption);
	if (bap->qos.bcast.bcode)
		dict_append_array(&dict, "BCode", DBUS_TYPE_BYTE,
					&bap->qos.bcast.bcode->iov_base,
					bap->qos.bcast.bcode->iov_len);
	dict_append_entry(&dict, "Options", DBUS_TYPE_BYTE,
					&bap->qos.bcast.options);
	dict_append_entry(&dict, "Skip", DBUS_TYPE_UINT16,
					&bap->qos.bcast.skip);
	dict_append_entry(&dict, "SyncTimeout", DBUS_TYPE_UINT16,
					&bap->qos.bcast.sync_timeout);
	dict_append_entry(&dict, "SyncType", DBUS_TYPE_BYTE,
					&bap->qos.bcast.sync_cte_type);
	dict_append_entry(&dict, "MSE", DBUS_TYPE_BYTE,
					&bap->qos.bcast.mse);
	dict_append_entry(&dict, "Timeout", DBUS_TYPE_UINT16,
					&bap->qos.bcast.timeout);

	append_io_qos(&dict, &bap->qos.bcast.io_qos);

	dbus_message_iter_close_container(iter, &dict);

	return TRUE;
}

static gboolean qos_bcast_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;

	return bap->qos.bcast.io_qos.phy != 0x00;
}

static void bcast_qos_set(void *user_data, int err)
{
	GDBusPendingPropertySet id = GPOINTER_TO_UINT(user_data);

	if (!err)
		g_dbus_pending_property_success(id);
	else
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".Failed",
					"Failed to set Broadcast Code");
}

static void set_bcast_qos(const GDBusPropertyTable *property,
			DBusMessageIter *dict, GDBusPendingPropertySet id,
			void *data)
{
	DBusMessageIter array, entry, value;
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;
	struct bt_bap_qos *bap_qos = bt_bap_stream_get_qos(bap->stream);
	char *key;

	dbus_message_iter_recurse(dict, &array);

	dbus_message_iter_recurse(&array, &entry);
	dbus_message_iter_get_basic(&entry, &key);

	dbus_message_iter_next(&entry);
	dbus_message_iter_recurse(&entry, &value);

	if (!strcasecmp(key, "BCode")) {
		uint8_t *val;
		int len;
		DBusMessageIter array;
		uint8_t empty_bcode[BT_BASS_BCAST_CODE_SIZE] = {0};

		dbus_message_iter_recurse(&value, &array);
		dbus_message_iter_get_fixed_array(&array, &val, &len);

		if (len > BT_BASS_BCAST_CODE_SIZE) {
			g_dbus_pending_property_error(id,
				ERROR_INTERFACE ".InvalidArguments",
				"Invalid arguments in method call");
			return;
		}

		if (!memcmp(val, empty_bcode, len)) {
			/* If the user did not provide a Broadcast Code
			 * for the encrypted stream, request the code from
			 * Broadcast Assistants, if any are available.
			 */
			bt_bap_req_bcode(bap->stream, bcast_qos_set,
						GUINT_TO_POINTER(id));
			return;
		}

		bap_qos->bcast.bcode = util_iov_new(val, len);
	}

	bt_bap_stream_qos(bap->stream, bap_qos, NULL, NULL);
	g_dbus_pending_property_success(id);
}

static const GDBusPropertyTable transport_bap_bc_properties[] = {
	{ "Device", "o", get_device },
	{ "UUID", "s", get_uuid },
	{ "Codec", "y", get_codec },
	{ "Configuration", "ay", get_configuration },
	{ "State", "s", get_state },
	{ "QoS", "a{sv}", get_bcast_qos, set_bcast_qos, qos_bcast_exists },
	{ "Endpoint", "o", get_endpoint, NULL, endpoint_exists },
	{ "Location", "u", get_location },
	{ "Metadata", "ay", get_metadata },
	{ "Links", "ao", get_links, set_links, NULL },
	{ }
};

#ifdef HAVE_ASHA
static gboolean get_asha_delay(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct bt_asha_device *asha_dev = transport->data;
	uint16_t delay;

	// Delay property is in 1/10ths of ms, while ASHA RenderDelay is in ms
	delay = bt_asha_device_get_render_delay(asha_dev) * 10;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &delay);

	return TRUE;
}

static const GDBusPropertyTable transport_asha_properties[] = {
	{ "Device", "o", get_device },
	{ "Endpoint", "o", get_endpoint, NULL, endpoint_exists },
	{ "UUID", "s", get_uuid },
	{ "Codec", "y", get_codec },
	{ "State", "s", get_state },
	{ "Delay", "q", get_asha_delay },
	{ "Volume", "q", get_volume, set_volume, volume_exists },
	{ }
};
#endif /* HAVE_ASHA */

#ifdef HAVE_A2DP
static void transport_a2dp_destroy(void *data)
{
	struct a2dp_transport *a2dp = data;

	if (a2dp->session)
		avdtp_unref(a2dp->session);

	free(a2dp);
}

static void transport_a2dp_src_destroy(void *data)
{
	struct a2dp_transport *a2dp = data;

	if (a2dp->watch)
		sink_remove_state_cb(a2dp->watch);

	transport_a2dp_destroy(data);
}

static void transport_a2dp_snk_destroy(void *data)
{
	struct a2dp_transport *a2dp = data;

	if (a2dp->watch)
		source_remove_state_cb(a2dp->watch);

	transport_a2dp_destroy(data);
}
#endif /* HAVE_A2DP */

static void media_transport_free(void *data)
{
	struct media_transport *transport = data;

	transports = g_slist_remove(transports, transport);

	if (transport->owner)
		media_transport_remove_owner(transport);

	if (transport->ops && transport->ops->destroy)
		transport->ops->destroy(transport->data);

	g_free(transport->remote_endpoint);
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
		if (!strcmp(media_endpoint_get_uuid(transport->endpoint),
						BAA_SERVICE_UUID)) {
			if ((transport->state ==
				TRANSPORT_STATE_BROADCASTING) ||
				(transport->state == TRANSPORT_STATE_ACTIVE))
				transport_set_state(transport,
						TRANSPORT_STATE_IDLE);
		} else {
			if (transport->state == TRANSPORT_STATE_PENDING)
				transport_set_state(transport,
						TRANSPORT_STATE_IDLE);
			else if (transport->state == TRANSPORT_STATE_ACTIVE) {
				/* Remove owner */
				if (transport->owner != NULL)
					media_transport_remove_owner(transport);
			}
		}
	} else if (transport->state == TRANSPORT_STATE_IDLE) {
		if (!strcmp(media_endpoint_get_uuid(transport->endpoint),
						BAA_SERVICE_UUID))
			transport_set_state(transport,
						TRANSPORT_STATE_BROADCASTING);
		else
			transport_set_state(transport, TRANSPORT_STATE_PENDING);
	}
}

static DBusMessage *select_transport(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct media_transport *transport = data;

	if (transport->owner != NULL)
		return btd_error_not_authorized(msg);

	if (transport->state >= TRANSPORT_STATE_REQUESTING)
		return btd_error_not_authorized(msg);

	if (!strcmp(media_endpoint_get_uuid(transport->endpoint),
						BAA_SERVICE_UUID)) {
		transport_update_playing(transport, TRUE);
	}

	return dbus_message_new_method_return(msg);
}

static DBusMessage *unselect_transport(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct media_transport *transport = data;

	if (!strcmp(media_endpoint_get_uuid(transport->endpoint),
						BAA_SERVICE_UUID)) {
		transport_update_playing(transport, FALSE);
	}

	return dbus_message_new_method_return(msg);
}

#ifdef HAVE_A2DP
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

static void *transport_a2dp_src_init(struct media_transport *transport,
					void *stream)
{
	struct btd_service *service;
	struct a2dp_transport *a2dp;

	service = btd_device_get_service(transport->device, A2DP_SINK_UUID);
	if (!service)
		return NULL;

	a2dp = new0(struct a2dp_transport, 1);
	a2dp->volume = -1;
	a2dp->watch = sink_add_state_cb(service, sink_state_changed, transport);

	return a2dp;
}

static void *transport_a2dp_snk_init(struct media_transport *transport,
					void *stream)
{
	struct btd_service *service;
	struct a2dp_transport *a2dp;

	service = btd_device_get_service(transport->device, A2DP_SOURCE_UUID);
	if (!service)
		return NULL;

	a2dp = new0(struct a2dp_transport, 1);
	a2dp->volume = 127;
	a2dp->watch = source_add_state_cb(service, source_state_changed,
						transport);

	return a2dp;
}
#endif /* HAVE_A2DP */

static void bap_enable_complete(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data)
{
	struct media_owner *owner = user_data;

	if (code)
		media_transport_remove_owner(owner->transport);
}

static void bap_resume_complete(struct media_transport *transport)
{
	struct bap_transport *bap = transport->data;
	struct media_owner *owner = transport->owner;

	DBG("stream %p owner %p resume complete", bap->stream, owner);

	if (bap->resume_id) {
		g_source_remove(bap->resume_id);
		bap->resume_id = 0;
	}

	if (!owner)
		return;

	if (owner->pending)
		owner->pending->id = 0;

	if (transport->fd < 0) {
		media_transport_remove_owner(transport);
		return;
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
			return;
		}
	}

	media_owner_remove(owner);

	transport_set_state(transport, TRANSPORT_STATE_ACTIVE);
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

static void transport_bap_update_links_uc(
	const struct media_transport *transport)
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

static void transport_bap_update_links_bc(
	const struct media_transport *transport)
{
	struct bap_transport *bap = transport->data;
	struct queue *links = bt_bap_stream_io_get_links(bap->stream);

	if (!queue_isempty(links))
		bap->linked = true;
	else
		bap->linked = false;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), transport->path,
						MEDIA_TRANSPORT_INTERFACE,
						"Links");

	DBG("stream %p linked %s", bap->stream, bap->linked ? "true" : "false");
}

static void bap_update_links(const struct media_transport *transport)
{
	if (transport->ops && transport->ops->update_links)
		transport->ops->update_links(transport);
}

static void bap_update_qos(const struct media_transport *transport)
{
	struct bap_transport *bap = transport->data;
	struct bt_bap_qos *qos;

	qos = bt_bap_stream_get_qos(bap->stream);

	if (!memcmp(qos, &bap->qos, sizeof(struct bt_bap_qos)))
		return;

	bap->qos = *qos;

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
			transport->path, MEDIA_TRANSPORT_INTERFACE,
			"QoS");
}

static gboolean bap_resume_complete_cb(void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;

	bap->resume_id = 0;
	bap_resume_complete(transport);
	return FALSE;
}

static gboolean bap_resume_wait_cb(void *data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;
	struct media_owner *owner = transport->owner;

	/* bap_state_changed will call completion callback when ready */
	DBG("stream %p owner %p resume wait", bap->stream, owner);

	bap->resume_id = 0;
	if (owner && owner->pending)
		owner->pending->id = 0;

	return FALSE;
}

static void bap_update_bcast_qos(const struct media_transport *transport)
{
	struct bap_transport *bap = transport->data;
	struct bt_bap_qos *qos;

	qos = bt_bap_stream_get_qos(bap->stream);

	if (!memcmp(qos, &bap->qos, sizeof(struct bt_bap_qos)))
		return;

	bap->qos = *qos;

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
			transport->path, MEDIA_TRANSPORT_INTERFACE,
			"QoS");
	g_dbus_emit_property_changed(btd_get_dbus_connection(),
			transport->path, MEDIA_TRANSPORT_INTERFACE,
			"Codec");
	g_dbus_emit_property_changed(btd_get_dbus_connection(),
			transport->path, MEDIA_TRANSPORT_INTERFACE,
			"Configuration");
}

static guint transport_bap_resume(struct media_transport *transport,
				struct media_owner *owner)
{
	struct bap_transport *bap = transport->data;
	guint id;

	if (!bap->stream)
		return 0;
	if (bap->resume_id)
		return 0;

	bap_update_links(transport);

	switch (bt_bap_stream_get_state(bap->stream)) {
	case BT_BAP_STREAM_STATE_ENABLING:
		bap_enable_complete(bap->stream, 0x00, 0x00, owner);
		bap->resume_id = g_idle_add(bap_resume_wait_cb, transport);
		return bap->resume_id;
	case BT_BAP_STREAM_STATE_STREAMING:
		bap->resume_id = g_idle_add(bap_resume_complete_cb, transport);
		return bap->resume_id;
	}

	id = bt_bap_stream_enable(bap->stream, bap->linked, NULL,
					bap_enable_complete, owner);
	if (!id)
		return 0;

	if (transport->state == TRANSPORT_STATE_IDLE)
		transport_set_state(transport, TRANSPORT_STATE_REQUESTING);

	return id;
}

static void update_links(void *data, void *user_data)
{
	struct bt_bap_stream *link = data;
	struct media_transport *transport;

	transport = find_transport_by_bap_stream(link);
	if (!transport) {
		error("Unable to find transport");
		return;
	}

	bap_update_links(transport);
}

static void transport_unlink(void *data, void *user_data)
{
	struct bt_bap_stream *link = data;
	struct bt_bap_stream *stream = user_data;
	struct media_transport *transport;

	transport = find_transport_by_bap_stream(link);
	if (!transport) {
		error("Unable to find transport");
		return;
	}

	bt_bap_stream_io_unlink(link, stream);

	bap_update_links(transport);

	/* Emit property changed for all remaining links */
	queue_foreach(bt_bap_stream_io_get_links(link), update_links, NULL);
}

static guint transport_bap_suspend(struct media_transport *transport,
				struct media_owner *owner)
{
	struct bap_transport *bap = transport->data;
	struct queue *links = bt_bap_stream_io_get_links(bap->stream);
	bt_bap_stream_func_t func = NULL;
	guint id;

	if (!bap->stream)
		return 0;

	if (owner)
		func = bap_disable_complete;
	else
		transport_set_state(transport, TRANSPORT_STATE_IDLE);

	if (bt_bap_stream_get_type(bap->stream) == BT_BAP_STREAM_TYPE_BCAST)
		/* Unlink stream from all its links */
		queue_foreach(links, transport_unlink, bap->stream);

	bap_update_links(transport);

	id = bt_bap_stream_disable(bap->stream, bap->linked, func, owner);

	if (bt_bap_stream_get_type(bap->stream) == BT_BAP_STREAM_TYPE_BCAST) {
		if (transport->owner == owner)
			bap_disable_complete(bap->stream, 0x00, 0x00, owner);
		return 0;
	}

	return id;
}

static void bap_clear_chan(struct bap_transport *bap)
{
	if (bap->chan_id) {
		g_source_remove(bap->chan_id);
		bap->chan_id = 0;
	}
}

static void transport_bap_cancel(struct media_transport *transport, guint id)
{
	struct bap_transport *bap = transport->data;

	bap_clear_chan(bap);

	if (id == bap->resume_id && bap->resume_id) {
		g_source_remove(bap->resume_id);
		bap->resume_id = 0;
		return;
	}

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

static void transport_bap_set_state(struct media_transport *transport,
					transport_state_t state)
{
	struct bap_transport *bap = transport->data;

	if (!bap->linked)
		return;

	/* Update links */
	queue_foreach(bt_bap_stream_io_get_links(bap->stream), link_set_state,
							UINT_TO_PTR(state));
}

static void bap_metadata_changed(struct media_transport *transport)
{
	struct bap_transport *bap = transport->data;
	struct iovec *meta;

	/* Update metadata if it has changed */
	meta = bt_bap_stream_get_metadata(bap->stream);

	DBG("stream %p: metadata %p old %p", bap->stream, meta, bap->meta);

	if (util_iov_memcmp(meta, bap->meta)) {
		util_iov_free(bap->meta, 1);
		bap->meta = util_iov_dup(meta, 1);
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
						transport->path,
						MEDIA_TRANSPORT_INTERFACE,
						"Metadata");
	}
}

static gboolean bap_transport_fd_ready(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	struct media_transport *transport = data;
	struct bap_transport *bap = transport->data;
	int fd;
	uint16_t imtu, omtu;
	GError *err = NULL;

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		error("Transport connection failed");
		goto done;
	}

	if (!bt_io_get(chan, &err, BT_IO_OPT_OMTU, &omtu,
					BT_IO_OPT_IMTU, &imtu,
					BT_IO_OPT_INVALID)) {
		error("%s", err->message);
		goto done;
	}

	fd = g_io_channel_unix_get_fd(chan);
	media_transport_set_fd(transport, fd, imtu, omtu);
	transport_update_playing(transport, TRUE);

done:
	bap->chan_id = 0;
	bap_resume_complete(transport);

	return FALSE;
}

static void bap_state_changed(struct bt_bap_stream *stream, uint8_t old_state,
				uint8_t new_state, void *user_data)
{
	struct media_transport *transport = user_data;
	struct bap_transport *bap = transport->data;
	struct media_owner *owner = transport->owner;
	struct io *io;
	GIOChannel *chan;
	int fd;

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
		if (!media_endpoint_is_broadcast(transport->endpoint))
			bap_update_qos(transport);
		else if (bt_bap_stream_io_dir(stream) != BT_BAP_BCAST_SOURCE)
			bap_update_bcast_qos(transport);
		transport_update_playing(transport, FALSE);
		return;
	case BT_BAP_STREAM_STATE_DISABLING:
		return;
	case BT_BAP_STREAM_STATE_ENABLING:
		if (!bt_bap_stream_get_io(stream))
			return;

		bap_metadata_changed(transport);
		break;
	case BT_BAP_STREAM_STATE_STREAMING:
		if ((bt_bap_stream_io_dir(stream) == BT_BAP_BCAST_SOURCE) ||
			(bt_bap_stream_io_dir(stream) == BT_BAP_BCAST_SINK))
			bap_update_bcast_qos(transport);

		bap_metadata_changed(transport);
		break;
	case BT_BAP_STREAM_STATE_RELEASING:
		if (bt_bap_stream_io_dir(stream) == BT_BAP_BCAST_SINK)
			return;
		transport_update_playing(transport, FALSE);
		goto done;
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

	/* Wait for FD to become ready */
	bap_clear_chan(bap);

	chan = g_io_channel_unix_new(fd);
	bap->chan_id = g_io_add_watch(chan,
				G_IO_OUT | G_IO_IN |
				G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				bap_transport_fd_ready, transport);
	g_io_channel_unref(chan);
	if (bap->chan_id)
		return;

done:
	bap_clear_chan(bap);
	bap_resume_complete(transport);
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

static int transport_bap_get_volume(struct media_transport *transport)
{
#ifdef HAVE_VCP
	return bt_audio_vcp_get_volume(transport->device);
#else
	return -ENODEV;
#endif /* HAVE_VCP */
}

static int transport_bap_set_volume(struct media_transport *transport,
								int volume)
{
#ifdef HAVE_VCP
	if (volume < 0 || volume > 255)
		return -EINVAL;

	return bt_audio_vcp_set_volume(transport->device, volume) ? 0 : -EIO;
#else
	return -ENODEV;
#endif /* HAVE_VCP */
}

static void transport_bap_destroy(void *data)
{
	struct bap_transport *bap = data;

	bap_clear_chan(bap);

	util_iov_free(bap->meta, 1);
	bt_bap_state_unregister(bt_bap_stream_get_session(bap->stream),
							bap->state_id);
	free(bap);
}

static void *transport_bap_init(struct media_transport *transport, void *stream)
{
	struct bt_bap_qos *qos;
	struct bap_transport *bap;

	qos = bt_bap_stream_get_qos(stream);

	bap = new0(struct bap_transport, 1);
	bap->stream = stream;
	bap->qos = *qos;
	bap->state_id = bt_bap_state_register(bt_bap_stream_get_session(stream),
						bap_state_changed,
						bap_connecting,
						transport, NULL);

	return bap;
}

#ifdef HAVE_ASHA
static void asha_transport_sync_state(struct media_transport *transport,
						struct bt_asha_device *asha_dev)
{
	switch (bt_asha_device_get_state(asha_dev)) {
	case ASHA_STOPPED:
		transport_set_state(transport, TRANSPORT_STATE_IDLE);
		break;
	case ASHA_STARTING:
		transport_set_state(transport, TRANSPORT_STATE_REQUESTING);
		break;
	case ASHA_STARTED:
		transport_set_state(transport, TRANSPORT_STATE_ACTIVE);
		break;
	}
}

static void asha_transport_state_cb(int status, void *user_data)
{
	struct media_owner *owner = user_data;
	struct media_transport *transport = owner->transport;
	struct bt_asha_device *asha_dev;
	enum bt_asha_state_t state;

	if (!transport) {
		DBG("Lost owner while connecting, bailing");
		return;
	}

	asha_dev = transport->data;
	state = bt_asha_device_get_state(asha_dev);

	if (state == ASHA_STARTED) {
		int fd;
		uint16_t imtu, omtu;
		gboolean ret;

		fd = bt_asha_device_get_fd(asha_dev);
		imtu = bt_asha_device_get_imtu(asha_dev);
		omtu = bt_asha_device_get_omtu(asha_dev);

		media_transport_set_fd(transport, fd, imtu, omtu);

		owner->pending->id = 0;
		ret = g_dbus_send_reply(btd_get_dbus_connection(),
				owner->pending->msg,
				DBUS_TYPE_UNIX_FD, &fd,
				DBUS_TYPE_UINT16, &imtu,
				DBUS_TYPE_UINT16, &omtu,
				DBUS_TYPE_INVALID);
		if (!ret) {
			media_transport_remove_owner(transport);
			return;
		}

		media_owner_remove(owner);
	} else if (state == ASHA_STOPPED) {
		if (owner->pending) {
			owner->pending->id = 0;
			media_request_reply(owner->pending, 0);
			media_owner_remove(owner);
		}

		media_transport_remove_owner(transport);
	}

	asha_transport_sync_state(transport, asha_dev);
}

static gboolean asha_transport_suspend_cb(void *user_data)
{
	asha_transport_state_cb(-1, user_data);

	return FALSE;
}

static guint transport_asha_resume(struct media_transport *transport,
						struct media_owner *owner)
{
	struct bt_asha_device *asha_dev = transport->data;
	guint ret;

	ret = bt_asha_device_start(asha_dev, asha_transport_state_cb, owner);
	asha_transport_sync_state(transport, asha_dev);

	return ret > 0 ? ret : 0;
}

static guint transport_asha_suspend(struct media_transport *transport,
						struct media_owner *owner)
{
	struct bt_asha_device *asha_dev = transport->data;
	guint ret = 0;

	if (owner) {
		ret = bt_asha_device_stop(asha_dev);
		asha_transport_sync_state(transport, asha_dev);
		g_idle_add(asha_transport_suspend_cb, owner);
	} else {
		ret = bt_asha_device_stop(asha_dev);
		/* We won't have a callback to set the final state */
		transport_set_state(transport, TRANSPORT_STATE_IDLE);
	}

	return ret;
}

static void transport_asha_cancel(struct media_transport *transport, guint id)
{
	struct bt_asha_device *asha_dev = transport->data;
	enum bt_asha_state_t state = bt_asha_device_get_state(asha_dev);

	if (id != bt_asha_device_device_get_resume_id(asha_dev)) {
		/* Not current, ignore */
		DBG("Ignoring cancel request for id %d", id);
		return;
	}

	if (state == ASHA_STARTING || state == ASHA_STARTED) {
		DBG("Cancel requested, stopping");
		bt_asha_device_stop(asha_dev);
		/* We won't have a callback to set the final state */
		transport_set_state(transport, TRANSPORT_STATE_IDLE);
	}
}

static int transport_asha_get_volume(struct media_transport *transport)
{
	struct bt_asha_device *asha_dev = transport->data;
	int8_t volume;
	int scaled_volume;

	volume = bt_asha_device_get_volume(asha_dev);

	/* Convert -128-0 to 0-127 */
	scaled_volume = ((((int) volume) + 128) * 127) / 128;

	return scaled_volume;
}

static int transport_asha_set_volume(struct media_transport *transport,
							int volume)
{
	struct bt_asha_device *asha_dev = transport->data;
	int scaled_volume;

	if (volume < 0 || volume > 127)
		return -EINVAL;

	/* Convert 0-127 to -128-0 */
	scaled_volume = ((((int) volume) * 128) / 127) - 128;

	return bt_asha_device_set_volume(asha_dev, scaled_volume) ? 0 : -EIO;
}

static void *transport_asha_init(struct media_transport *transport, void *data)
{
	/* We just store the struct asha_device on the transport */
	return data;
}
#endif /* HAVE_ASHA */

#define TRANSPORT_OPS(_uuid, _props, _set_owner, _remove_owner, _init, \
		      _resume, _suspend, _cancel, _set_state, _get_stream, \
		      _get_volume, _set_volume, _set_delay, _update_links, \
		      _destroy) \
{ \
	.uuid = _uuid, \
	.properties = _props, \
	.set_owner = _set_owner, \
	.remove_owner = _remove_owner, \
	.init = _init, \
	.resume = _resume, \
	.suspend = _suspend, \
	.cancel = _cancel, \
	.set_state = _set_state, \
	.get_stream = _get_stream, \
	.get_volume = _get_volume, \
	.set_volume = _set_volume, \
	.set_delay = _set_delay, \
	.update_links = _update_links, \
	.destroy = _destroy \
}

#define A2DP_OPS(_uuid, _init, _set_volume, _set_delay, _destroy) \
	TRANSPORT_OPS(_uuid, transport_a2dp_properties, NULL, \
			transport_a2dp_remove_owner, _init,	      \
			transport_a2dp_resume, transport_a2dp_suspend, \
			transport_a2dp_cancel, NULL, \
			transport_a2dp_get_stream, transport_a2dp_get_volume, \
			_set_volume, _set_delay, NULL, _destroy)

#define BAP_OPS(_uuid, _props, _set_owner, _remove_owner, _update_links, \
		_set_state) \
	TRANSPORT_OPS(_uuid, _props, _set_owner, _remove_owner,\
			transport_bap_init, \
			transport_bap_resume, transport_bap_suspend, \
			transport_bap_cancel, _set_state, \
			transport_bap_get_stream, transport_bap_get_volume, \
			transport_bap_set_volume, NULL, \
			_update_links, transport_bap_destroy)

#define BAP_UC_OPS(_uuid) \
	BAP_OPS(_uuid, transport_bap_uc_properties, \
			transport_bap_set_owner, transport_bap_remove_owner, \
			transport_bap_update_links_uc, transport_bap_set_state)

#define BAP_BC_OPS(_uuid) \
	BAP_OPS(_uuid, transport_bap_bc_properties, NULL, NULL, \
			transport_bap_update_links_bc, NULL)

#define ASHA_OPS(_uuid) \
	TRANSPORT_OPS(_uuid, transport_asha_properties, NULL, NULL, \
			transport_asha_init, \
			transport_asha_resume, transport_asha_suspend, \
			transport_asha_cancel, NULL, NULL, \
			transport_asha_get_volume, transport_asha_set_volume, \
			NULL, NULL, NULL)

static const struct media_transport_ops transport_ops[] = {
#ifdef HAVE_A2DP
	A2DP_OPS(A2DP_SOURCE_UUID, transport_a2dp_src_init,
#ifdef HAVE_AVRCP
			transport_a2dp_src_set_volume,
#else
			NULL,
#endif
			NULL,
			transport_a2dp_src_destroy),
	A2DP_OPS(A2DP_SINK_UUID, transport_a2dp_snk_init,
#ifdef HAVE_AVRCP
			transport_a2dp_snk_set_volume,
#else
			NULL,
#endif
			transport_a2dp_snk_set_delay,
			transport_a2dp_snk_destroy),
#endif /* HAVE_A2DP */
	BAP_UC_OPS(PAC_SOURCE_UUID),
	BAP_UC_OPS(PAC_SINK_UUID),
	BAP_BC_OPS(BCAA_SERVICE_UUID),
	BAP_BC_OPS(BAA_SERVICE_UUID),
#ifdef HAVE_ASHA
	ASHA_OPS(ASHA_PROFILE_UUID),
#endif /* HAVE_ASHA */
};

static const struct media_transport_ops *
media_transport_find_ops(const char *uuid)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(transport_ops); i++) {
		const struct media_transport_ops *ops = &transport_ops[i];

		if (!strcasecmp(uuid, ops->uuid))
			return ops;
	}

	return NULL;
}

struct media_transport *media_transport_create(struct btd_device *device,
						const char *remote_endpoint,
						uint8_t *configuration,
						size_t size, void *data,
						void *stream)
{
	struct media_endpoint *endpoint = data;
	struct media_transport *transport;
	const struct media_transport_ops *ops;
	int fd;

	transport = g_new0(struct media_transport, 1);
	if (device)
		transport->device = device;
	else
		transport->adapter = media_endpoint_get_btd_adapter(endpoint);

	transport->endpoint = endpoint;
	transport->configuration = util_memdup(configuration, size);
	transport->size = size;
	transport->remote_endpoint = g_strdup(remote_endpoint);

	for (fd = g_slist_length(transports); fd < UINT8_MAX; fd++) {
		char *path;

		if (device)
			path = g_strdup_printf("%s/fd%d",
					remote_endpoint ? remote_endpoint :
					device_get_path(device),
					fd);
		else
			path = g_strdup_printf("%s/fd%d",
					remote_endpoint ? remote_endpoint :
					adapter_get_path(transport->adapter),
					fd);

		/* Check if transport already exists */
		if (!find_transport_by_path(path)) {
			transport->path = path;
			break;
		}

		g_free(path);
	}

	if (!transport->path) {
		error("Unable to allocate transport path");
		goto fail;
	}

	transport->fd = -1;

	ops = media_transport_find_ops(media_endpoint_get_uuid(endpoint));
	if (!ops)
		goto fail;

	transport->ops = ops;

	if (ops->init) {
		transport->data = ops->init(transport, stream);
		if (!transport->data)
			goto fail;
	}

	if (g_dbus_register_interface(btd_get_dbus_connection(),
				transport->path, MEDIA_TRANSPORT_INTERFACE,
				transport_methods, NULL, ops->properties,
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

void *media_transport_get_stream(struct media_transport *transport)
{
	if (transport->ops && transport->ops->get_stream)
		return transport->ops->get_stream(transport);

	return NULL;
}

void media_transport_update_delay(struct media_transport *transport,
							uint16_t delay)
{
#ifdef HAVE_A2DP
	struct a2dp_transport *a2dp = transport->data;

	/* Check if delay really changed */
	if (a2dp->delay == delay)
		return;

	if (a2dp->session == NULL)
		a2dp->session = a2dp_avdtp_get(transport->device);

	a2dp->delay = delay;

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
					transport->path,
					MEDIA_TRANSPORT_INTERFACE, "Delay");
#endif /* HAVE_A2DP */
}

struct btd_device *media_transport_get_dev(struct media_transport *transport)
{
	return transport->device;
}

void media_transport_update_volume(struct media_transport *transport,
								int volume)
{
	if (volume < 0)
		return;

#ifdef HAVE_A2DP
	if (media_endpoint_get_sep(transport->endpoint)) {
		struct a2dp_transport *a2dp = transport->data;

		if (volume > 127)
			return;

		/* Check if volume really changed */
		if (a2dp->volume == volume)
			return;

		a2dp->volume = volume;
	}
#endif
	g_dbus_emit_property_changed(btd_get_dbus_connection(),
					transport->path,
					MEDIA_TRANSPORT_INTERFACE, "Volume");
}

int media_transport_get_device_volume(struct btd_device *dev)
{
	GSList *l;

	if (dev == NULL)
		return -1;

#ifdef HAVE_A2DP
	/* Attempt to locate the transport to get its volume */
	for (l = transports; l; l = l->next) {
		struct media_transport *transport = l->data;
		if (transport->device != dev)
			continue;

		/* Volume is A2DP only */
		if (media_endpoint_get_sep(transport->endpoint)) {
			int volume;

			if (!media_transport_get_volume(transport, &volume))
				return volume;

			return -1;
		}
	}
#endif

	/* If transport volume doesn't exists use device_volume */
	return btd_device_get_volume(dev);
}

void media_transport_update_device_volume(struct btd_device *dev,
								int volume)
{
	GSList *l;

	if (dev == NULL || volume < 0)
		return;

#ifdef HAVE_A2DP
	/* Attempt to locate the transport to set its volume */
	for (l = transports; l; l = l->next) {
		struct media_transport *transport = l->data;
		const char *uuid = media_endpoint_get_uuid(transport->endpoint);
		if (transport->device != dev)
			continue;

		/* Volume is A2DP and BAP only */
		if (media_endpoint_get_sep(transport->endpoint) ||
				strcasecmp(uuid, PAC_SINK_UUID) ||
				strcasecmp(uuid, PAC_SOURCE_UUID) ||
				strcasecmp(uuid, BAA_SERVICE_UUID)) {
			media_transport_update_volume(transport, volume);
			break;
		}
	}
#endif

	btd_device_set_volume(dev, volume);
}

const char *media_transport_stream_path(void *stream)
{
	GSList *l;

	if (!stream)
		return NULL;

	for (l = transports; l; l = l->next) {
		struct media_transport *transport = l->data;

		if (media_transport_get_stream(transport) == stream)
			return transport->path;
	}

	return NULL;
}
