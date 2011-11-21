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
#include "gateway.h"

#ifndef DBUS_TYPE_UNIX_FD
#define DBUS_TYPE_UNIX_FD -1
#endif

#define MEDIA_TRANSPORT_INTERFACE "org.bluez.MediaTransport"

struct media_request {
	DBusMessage		*msg;
	guint			id;
};

struct media_owner {
	struct media_transport	*transport;
	struct media_request	*pending;
	char			*name;
	char			*accesstype;
	guint			watch;
};

struct media_transport {
	DBusConnection		*conn;
	char			*path;		/* Transport object path */
	struct audio_device	*device;	/* Transport device */
	struct avdtp		*session;	/* Signalling session (a2dp only) */
	struct media_endpoint	*endpoint;	/* Transport endpoint */
	GSList			*owners;	/* Transport owners */
	uint8_t			*configuration; /* Transport configuration */
	int			size;		/* Transport configuration size */
	int			fd;		/* Transport file descriptor */
	uint16_t		imtu;		/* Transport input mtu */
	uint16_t		omtu;		/* Transport output mtu */
	uint16_t		delay;		/* Transport delay (a2dp only) */
	unsigned int		nrec_id;	/* Transport nrec watch (headset only) */
	gboolean		read_lock;
	gboolean		write_lock;
	gboolean		in_use;
	guint			(*resume) (struct media_transport *transport,
					struct media_owner *owner);
	guint			(*suspend) (struct media_transport *transport,
					struct media_owner *owner);
	void			(*cancel) (struct media_transport *transport,
								guint id);
	void			(*get_properties) (
					struct media_transport *transport,
					DBusMessageIter *dict);
	int			(*set_property) (
					struct media_transport *transport,
					const char *property,
					DBusMessageIter *value);
};

void media_transport_destroy(struct media_transport *transport)
{
	char *path;

	path = g_strdup(transport->path);
	g_dbus_unregister_interface(transport->conn, path,
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

static void media_request_reply(struct media_request *req,
						DBusConnection *conn, int err)
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

	g_dbus_send_message(conn, reply);
}

static gboolean media_transport_release(struct media_transport *transport,
					const char *accesstype)
{
	if (g_strstr_len(accesstype, -1, "r") != NULL) {
		transport->read_lock = FALSE;
		DBG("Transport %s: read lock released", transport->path);
	}

	if (g_strstr_len(accesstype, -1, "w") != NULL) {
		transport->write_lock = FALSE;
		DBG("Transport %s: write lock released", transport->path);
	}

	return TRUE;
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
	g_free(owner->accesstype);
	g_free(owner);
}

static void media_transport_remove(struct media_transport *transport,
						struct media_owner *owner)
{
	DBG("Transport %s Owner %s", transport->path, owner->name);

	media_transport_release(transport, owner->accesstype);

	/* Reply if owner has a pending request */
	if (owner->pending)
		media_request_reply(owner->pending, transport->conn, EIO);

	transport->owners = g_slist_remove(transport->owners, owner);

	if (owner->watch)
		g_dbus_remove_watch(transport->conn, owner->watch);

	media_owner_free(owner);

	/* Suspend if there is no longer any owner */
	if (transport->owners == NULL && transport->in_use)
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

static void a2dp_resume_complete(struct avdtp *session,
				struct avdtp_error *err, void *user_data)
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

	if (g_strstr_len(owner->accesstype, -1, "r") == NULL)
		imtu = 0;

	if (g_strstr_len(owner->accesstype, -1, "w") == NULL)
		omtu = 0;

	ret = g_dbus_send_reply(transport->conn, req->msg,
						DBUS_TYPE_UNIX_FD, &fd,
						DBUS_TYPE_UINT16, &imtu,
						DBUS_TYPE_UINT16, &omtu,
						DBUS_TYPE_INVALID);
	if (ret == FALSE)
		goto fail;

	media_owner_remove(owner);

	return;

fail:
	media_transport_remove(transport, owner);
}

static guint resume_a2dp(struct media_transport *transport,
				struct media_owner *owner)
{
	struct media_endpoint *endpoint = transport->endpoint;
	struct audio_device *device = transport->device;
	struct a2dp_sep *sep = media_endpoint_get_sep(endpoint);

	if (transport->session == NULL) {
		transport->session = avdtp_get(&device->src, &device->dst);
		if (transport->session == NULL)
			return 0;
	}

	if (transport->in_use == TRUE)
		goto done;

	transport->in_use = a2dp_sep_lock(sep, transport->session);
	if (transport->in_use == FALSE)
		return 0;

done:
	return a2dp_resume(transport->session, sep, a2dp_resume_complete,
				owner);
}

static void a2dp_suspend_complete(struct avdtp *session,
				struct avdtp_error *err, void *user_data)
{
	struct media_owner *owner = user_data;
	struct media_transport *transport = owner->transport;
	struct a2dp_sep *sep = media_endpoint_get_sep(transport->endpoint);

	/* Release always succeeds */
	if (owner->pending) {
		owner->pending->id = 0;
		media_request_reply(owner->pending, transport->conn, 0);
		media_owner_remove(owner);
	}

	a2dp_sep_unlock(sep, transport->session);
	transport->in_use = FALSE;
	media_transport_remove(transport, owner);
}

static guint suspend_a2dp(struct media_transport *transport,
						struct media_owner *owner)
{
	struct media_endpoint *endpoint = transport->endpoint;
	struct a2dp_sep *sep = media_endpoint_get_sep(endpoint);

	if (!owner) {
		a2dp_sep_unlock(sep, transport->session);
		transport->in_use = FALSE;
		return 0;
	}

	return a2dp_suspend(transport->session, sep, a2dp_suspend_complete,
				owner);
}

static void cancel_a2dp(struct media_transport *transport, guint id)
{
	a2dp_cancel(transport->device, id);
}

static void headset_resume_complete(struct audio_device *dev, void *user_data)
{
	struct media_owner *owner = user_data;
	struct media_request *req = owner->pending;
	struct media_transport *transport = owner->transport;
	int fd;
	uint16_t imtu, omtu;
	gboolean ret;

	req->id = 0;

	if (dev == NULL)
		goto fail;

	fd = headset_get_sco_fd(dev);
	if (fd < 0)
		goto fail;

	imtu = 48;
	omtu = 48;

	media_transport_set_fd(transport, fd, imtu, omtu);

	if (g_strstr_len(owner->accesstype, -1, "r") == NULL)
		imtu = 0;

	if (g_strstr_len(owner->accesstype, -1, "w") == NULL)
		omtu = 0;

	ret = g_dbus_send_reply(transport->conn, req->msg,
						DBUS_TYPE_UNIX_FD, &fd,
						DBUS_TYPE_UINT16, &imtu,
						DBUS_TYPE_UINT16, &omtu,
						DBUS_TYPE_INVALID);
	if (ret == FALSE)
		goto fail;

	media_owner_remove(owner);

	return;

fail:
	media_transport_remove(transport, owner);
}

static guint resume_headset(struct media_transport *transport,
				struct media_owner *owner)
{
	struct audio_device *device = transport->device;

	if (transport->in_use == TRUE)
		goto done;

	transport->in_use = headset_lock(device, HEADSET_LOCK_READ |
						HEADSET_LOCK_WRITE);
	if (transport->in_use == FALSE)
		return 0;

done:
	return headset_request_stream(device, headset_resume_complete,
					owner);
}

static void headset_suspend_complete(struct audio_device *dev, void *user_data)
{
	struct media_owner *owner = user_data;
	struct media_transport *transport = owner->transport;

	/* Release always succeeds */
	if (owner->pending) {
		owner->pending->id = 0;
		media_request_reply(owner->pending, transport->conn, 0);
		media_owner_remove(owner);
	}

	headset_unlock(dev, HEADSET_LOCK_READ | HEADSET_LOCK_WRITE);
	transport->in_use = FALSE;
	media_transport_remove(transport, owner);
}

static guint suspend_headset(struct media_transport *transport,
						struct media_owner *owner)
{
	struct audio_device *device = transport->device;

	if (!owner) {
		headset_unlock(device, HEADSET_LOCK_READ | HEADSET_LOCK_WRITE);
		transport->in_use = FALSE;
		return 0;
	}

	return headset_suspend_stream(device, headset_suspend_complete, owner);
}

static void cancel_headset(struct media_transport *transport, guint id)
{
	headset_cancel_stream(transport->device, id);
}

static void gateway_resume_complete(struct audio_device *dev, GError *err,
							void *user_data)
{
	struct media_owner *owner = user_data;
	struct media_request *req = owner->pending;
	struct media_transport *transport = owner->transport;
	int fd;
	uint16_t imtu, omtu;
	gboolean ret;

	req->id = 0;

	if (dev == NULL)
		goto fail;

	if (err) {
		error("Failed to resume gateway: error %s", err->message);
		goto fail;
	}

	fd = gateway_get_sco_fd(dev);
	if (fd < 0)
		goto fail;

	imtu = 48;
	omtu = 48;

	media_transport_set_fd(transport, fd, imtu, omtu);

	if (g_strstr_len(owner->accesstype, -1, "r") == NULL)
		imtu = 0;

	if (g_strstr_len(owner->accesstype, -1, "w") == NULL)
		omtu = 0;

	ret = g_dbus_send_reply(transport->conn, req->msg,
						DBUS_TYPE_UNIX_FD, &fd,
						DBUS_TYPE_UINT16, &imtu,
						DBUS_TYPE_UINT16, &omtu,
						DBUS_TYPE_INVALID);
	if (ret == FALSE)
		goto fail;

	media_owner_remove(owner);

	return;

fail:
	media_transport_remove(transport, owner);
}

static guint resume_gateway(struct media_transport *transport,
				struct media_owner *owner)
{
	struct audio_device *device = transport->device;

	if (transport->in_use == TRUE)
		goto done;

	transport->in_use = gateway_lock(device, GATEWAY_LOCK_READ |
						GATEWAY_LOCK_WRITE);
	if (transport->in_use == FALSE)
		return 0;

done:
	return gateway_request_stream(device, gateway_resume_complete,
					owner);
}

static gboolean gateway_suspend_complete(gpointer user_data)
{
	struct media_owner *owner = user_data;
	struct media_transport *transport = owner->transport;

	/* Release always succeeds */
	if (owner->pending) {
		owner->pending->id = 0;
		media_request_reply(owner->pending, transport->conn, 0);
		media_owner_remove(owner);
	}

	transport->in_use = FALSE;
	media_transport_remove(transport, owner);
	return FALSE;
}

static guint suspend_gateway(struct media_transport *transport,
						struct media_owner *owner)
{
	struct audio_device *device = transport->device;
	static int id = 1;

	if (!owner) {
		gateway_unlock(device, GATEWAY_LOCK_READ | GATEWAY_LOCK_WRITE);
		transport->in_use = FALSE;
		return 0;
	}

	gateway_suspend_stream(device);
	gateway_unlock(device, GATEWAY_LOCK_READ | GATEWAY_LOCK_WRITE);
	g_idle_add(gateway_suspend_complete, owner);
	return id++;
}

static void cancel_gateway(struct media_transport *transport, guint id)
{
	gateway_cancel_stream(transport->device, id);
}

static void media_owner_exit(DBusConnection *connection, void *user_data)
{
	struct media_owner *owner = user_data;

	owner->watch = 0;

	media_owner_remove(owner);

	media_transport_remove(owner->transport, owner);
}

static gboolean media_transport_acquire(struct media_transport *transport,
							const char *accesstype)
{
	gboolean read_lock = FALSE, write_lock = FALSE;

	if (g_strstr_len(accesstype, -1, "r") != NULL) {
		if (transport->read_lock == TRUE)
			return FALSE;
		read_lock = TRUE;
	}

	if (g_strstr_len(accesstype, -1, "w") != NULL) {
		if (transport->write_lock == TRUE)
			return FALSE;
		write_lock = TRUE;
	}

	/* Check invalid accesstype */
	if (read_lock == FALSE && write_lock == FALSE)
		return FALSE;

	if (read_lock) {
		transport->read_lock = read_lock;
		DBG("Transport %s: read lock acquired", transport->path);
	}

	if (write_lock) {
		transport->write_lock = write_lock;
		DBG("Transport %s: write lock acquired", transport->path);
	}


	return TRUE;
}

static void media_transport_add(struct media_transport *transport,
					struct media_owner *owner)
{
	DBG("Transport %s Owner %s", transport->path, owner->name);
	transport->owners = g_slist_append(transport->owners, owner);
	owner->transport = transport;
}

static struct media_owner *media_owner_create(DBusConnection *conn,
						DBusMessage *msg,
						const char *accesstype)
{
	struct media_owner *owner;

	owner = g_new0(struct media_owner, 1);
	owner->name = g_strdup(dbus_message_get_sender(msg));
	owner->accesstype = g_strdup(accesstype);
	owner->watch = g_dbus_add_disconnect_watch(conn, owner->name,
							media_owner_exit,
							owner, NULL);

	DBG("Owner created: sender=%s accesstype=%s", owner->name,
			accesstype);

	return owner;
}

static void media_owner_add(struct media_owner *owner,
						struct media_request *req)
{
	DBG("Owner %s Request %s", owner->name,
					dbus_message_get_member(req->msg));

	owner->pending = req;
}

static struct media_owner *media_transport_find_owner(
					struct media_transport *transport,
					const char *name)
{
	GSList *l;

	for (l = transport->owners; l; l = l->next) {
		struct media_owner *owner = l->data;

		if (g_strcmp0(owner->name, name) == 0)
			return owner;
	}

	return NULL;
}

static DBusMessage *acquire(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct media_transport *transport = data;
	struct media_owner *owner;
	struct media_request *req;
	const char *accesstype, *sender;
	guint id;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &accesstype,
				DBUS_TYPE_INVALID))
		return NULL;

	sender = dbus_message_get_sender(msg);

	owner = media_transport_find_owner(transport, sender);
	if (owner != NULL)
		return btd_error_not_authorized(msg);

	if (media_transport_acquire(transport, accesstype) == FALSE)
		return btd_error_not_authorized(msg);

	owner = media_owner_create(conn, msg, accesstype);
	id = transport->resume(transport, owner);
	if (id == 0) {
		media_transport_release(transport, accesstype);
		media_owner_free(owner);
		return btd_error_not_authorized(msg);
	}

	req = media_request_create(msg, id);
	media_owner_add(owner, req);
	media_transport_add(transport, owner);

	return NULL;
}

static DBusMessage *release(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct media_transport *transport = data;
	struct media_owner *owner;
	const char *accesstype, *sender;
	struct media_request *req;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &accesstype,
				DBUS_TYPE_INVALID))
		return NULL;

	sender = dbus_message_get_sender(msg);

	owner = media_transport_find_owner(transport, sender);
	if (owner == NULL)
		return btd_error_not_authorized(msg);

	if (g_strcmp0(owner->accesstype, accesstype) == 0) {
		guint id;

		/* Not the last owner, no need to suspend */
		if (g_slist_length(transport->owners) != 1) {
			media_transport_remove(transport, owner);
			return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
		}

		if (owner->pending) {
			const char *member;

			member = dbus_message_get_member(owner->pending->msg);
			/* Cancel Acquire request if that exist */
			if (g_str_equal(member, "Acquire"))
				media_owner_remove(owner);
			else
				return btd_error_in_progress(msg);
		}

		id = transport->suspend(transport, owner);
		if (id == 0) {
			media_transport_remove(transport, owner);
			return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
		}

		req = media_request_create(msg, id);
		media_owner_add(owner, req);

		return NULL;
	} else if (g_strstr_len(owner->accesstype, -1, accesstype) != NULL) {
		media_transport_release(transport, accesstype);
		g_strdelimit(owner->accesstype, accesstype, ' ');
	} else
		return btd_error_not_authorized(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static int set_property_a2dp(struct media_transport *transport,
						const char *property,
						DBusMessageIter *value)
{
	if (g_strcmp0(property, "Delay") == 0) {
		if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_UINT16)
			return -EINVAL;
		dbus_message_iter_get_basic(value, &transport->delay);

		/* FIXME: send new delay */
		return 0;
	}

	return -EINVAL;
}

static int set_property_headset(struct media_transport *transport,
						const char *property,
						DBusMessageIter *value)
{
	if (g_strcmp0(property, "NREC") == 0) {
		gboolean nrec;

		if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_BOOLEAN)
			return -EINVAL;
		dbus_message_iter_get_basic(value, &nrec);

		/* FIXME: set new nrec */
		return 0;
	} else if (g_strcmp0(property, "InbandRingtone") == 0) {
		gboolean inband;

		if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_BOOLEAN)
			return -EINVAL;
		dbus_message_iter_get_basic(value, &inband);

		/* FIXME: set new inband */
		return 0;
	}

	return -EINVAL;
}

static int set_property_gateway(struct media_transport *transport,
						const char *property,
						DBusMessageIter *value)
{
	return -EINVAL;
}

static DBusMessage *set_property(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct media_transport *transport = data;
	DBusMessageIter iter;
	DBusMessageIter value;
	const char *property, *sender;
	GSList *l;
	int err;

	if (!dbus_message_iter_init(msg, &iter))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return btd_error_invalid_args(msg);
	dbus_message_iter_recurse(&iter, &value);

	sender = dbus_message_get_sender(msg);
	err = -EINVAL;

	/* Check if sender has acquired the transport */
	for (l = transport->owners; l; l = l->next) {
		struct media_owner *owner = l->data;

		if (g_strcmp0(owner->name, sender) == 0) {
			err = transport->set_property(transport, property,
								&value);
			break;
		}
	}

	if (err < 0) {
		if (err == -EINVAL)
			return btd_error_invalid_args(msg);
		return btd_error_failed(msg, strerror(-err));
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void get_properties_a2dp(struct media_transport *transport,
						DBusMessageIter *dict)
{
	dict_append_entry(dict, "Delay", DBUS_TYPE_UINT16, &transport->delay);
}

static void get_properties_headset(struct media_transport *transport,
						DBusMessageIter *dict)
{
	gboolean nrec, inband;
	const char *routing;

	nrec = headset_get_nrec(transport->device);
	dict_append_entry(dict, "NREC", DBUS_TYPE_BOOLEAN, &nrec);

	inband = headset_get_inband(transport->device);
	dict_append_entry(dict, "InbandRingtone", DBUS_TYPE_BOOLEAN, &inband);

	routing = headset_get_sco_hci(transport->device) ? "HCI" : "PCM";
	dict_append_entry(dict, "Routing", DBUS_TYPE_STRING, &routing);
}

static void get_properties_gateway(struct media_transport *transport,
						DBusMessageIter *dict)
{
	/* None */
}

void transport_get_properties(struct media_transport *transport,
							DBusMessageIter *iter)
{
	DBusMessageIter dict;
	const char *uuid;
	uint8_t codec;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Device */
	dict_append_entry(&dict, "Device", DBUS_TYPE_OBJECT_PATH,
						&transport->device->path);

	uuid = media_endpoint_get_uuid(transport->endpoint);
	dict_append_entry(&dict, "UUID", DBUS_TYPE_STRING, &uuid);

	codec = media_endpoint_get_codec(transport->endpoint);
	dict_append_entry(&dict, "Codec", DBUS_TYPE_BYTE, &codec);

	dict_append_array(&dict, "Configuration", DBUS_TYPE_BYTE,
				&transport->configuration, transport->size);

	if (transport->get_properties)
		transport->get_properties(transport, &dict);

	dbus_message_iter_close_container(iter, &dict);
}

static DBusMessage *get_properties(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct media_transport *transport = data;
	DBusMessage *reply;
	DBusMessageIter iter;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	transport_get_properties(transport, &iter);

	return reply;
}

static GDBusMethodTable transport_methods[] = {
	{ "GetProperties",	"",	"a{sv}",	get_properties },
	{ "Acquire",		"s",	"h",		acquire,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "Release",		"s",	"",		release,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "SetProperty",	"sv",	"",		set_property },
	{ },
};

static GDBusSignalTable transport_signals[] = {
	{ "PropertyChanged",	"sv"	},
	{ }
};

static void media_transport_free(void *data)
{
	struct media_transport *transport = data;
	GSList *l = transport->owners;

	while (l) {
		struct media_owner *owner = l->data;
		l = l->next;
		media_transport_remove(transport, owner);
	}

	g_slist_free(transport->owners);

	if (transport->session)
		avdtp_unref(transport->session);

	if (transport->nrec_id)
		headset_remove_nrec_cb(transport->device, transport->nrec_id);

	if (transport->conn)
		dbus_connection_unref(transport->conn);

	g_free(transport->configuration);
	g_free(transport->path);
	g_free(transport);
}

static void headset_nrec_changed(struct audio_device *dev, gboolean nrec,
							void *user_data)
{
	struct media_transport *transport = user_data;

	DBG("");

	emit_property_changed(transport->conn, transport->path,
				MEDIA_TRANSPORT_INTERFACE, "NREC",
				DBUS_TYPE_BOOLEAN, &nrec);
}

struct media_transport *media_transport_create(DBusConnection *conn,
						struct media_endpoint *endpoint,
						struct audio_device *device,
						uint8_t *configuration,
						size_t size)
{
	struct media_transport *transport;
	const char *uuid;
	static int fd = 0;

	transport = g_new0(struct media_transport, 1);
	transport->conn = dbus_connection_ref(conn);
	transport->device = device;
	transport->endpoint = endpoint;
	transport->configuration = g_new(uint8_t, size);
	memcpy(transport->configuration, configuration, size);
	transport->size = size;
	transport->path = g_strdup_printf("%s/fd%d", device->path, fd++);
	transport->fd = -1;

	uuid = media_endpoint_get_uuid(endpoint);
	if (strcasecmp(uuid, A2DP_SOURCE_UUID) == 0 ||
			strcasecmp(uuid, A2DP_SINK_UUID) == 0) {
		transport->resume = resume_a2dp;
		transport->suspend = suspend_a2dp;
		transport->cancel = cancel_a2dp;
		transport->get_properties = get_properties_a2dp;
		transport->set_property = set_property_a2dp;
	} else if (strcasecmp(uuid, HFP_AG_UUID) == 0 ||
			strcasecmp(uuid, HSP_AG_UUID) == 0) {
		transport->resume = resume_headset;
		transport->suspend = suspend_headset;
		transport->cancel = cancel_headset;
		transport->get_properties = get_properties_headset;
		transport->set_property = set_property_headset;
		transport->nrec_id = headset_add_nrec_cb(device,
							headset_nrec_changed,
							transport);
	} else if (strcasecmp(uuid, HFP_HS_UUID) == 0 ||
			strcasecmp(uuid, HSP_HS_UUID) == 0) {
		transport->resume = resume_gateway;
		transport->suspend = suspend_gateway;
		transport->cancel = cancel_gateway;
		transport->get_properties = get_properties_gateway;
		transport->set_property = set_property_gateway;
	} else
		goto fail;

	if (g_dbus_register_interface(transport->conn, transport->path,
				MEDIA_TRANSPORT_INTERFACE,
				transport_methods, transport_signals, NULL,
				transport, media_transport_free) == FALSE) {
		error("Could not register transport %s", transport->path);
		goto fail;
	}

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
	/* Check if delay really changed */
	if (transport->delay == delay)
		return;

	transport->delay = delay;

	emit_property_changed(transport->conn, transport->path,
				MEDIA_TRANSPORT_INTERFACE, "Delay",
				DBUS_TYPE_UINT16, &transport->delay);
}

struct audio_device *media_transport_get_dev(struct media_transport *transport)
{
	return transport->device;
}
