/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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

#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/uuid.h>

#include "btio.h"
#include "log.h"
#include "error.h"
#include "dbus-common.h"
#include "adapter.h"
#include "manager.h"
#include "device.h"
#include "profile.h"

struct pending_connect {
	struct btd_device *dev;
	btd_profile_cb cb;
};

struct ext_profile {
	struct btd_profile p;

	char *name;
	char *owner;
	char *uuid;
	char *path;
	char *role;

	char **remote_uuids;

	guint id;

	BtIOSecLevel sec_level;
	bool authorize;

	uint16_t psm;
	uint8_t chan;

	GSList *servers;
	GSList *conns;

	GSList *connects;
};

struct ext_io {
	struct ext_profile *ext;
	int proto;
	GIOChannel *io;
	guint io_id;
	struct btd_adapter *adapter;

	guint auth_id;
	DBusPendingCall *new_conn;
};

static GSList *profiles = NULL;
static GSList *ext_profiles = NULL;

void btd_profile_foreach(void (*func)(struct btd_profile *p, void *data),
								void *data)
{
	GSList *l, *next;

	for (l = profiles; l != NULL; l = next) {
		struct btd_profile *profile = l->data;

		next = g_slist_next(l);

		func(profile, data);
	}

	for (l = ext_profiles; l != NULL; l = next) {
		struct ext_profile *profile = l->data;

		next = g_slist_next(l);

		func(&profile->p, data);
	}
}

int btd_profile_register(struct btd_profile *profile)
{
	profiles = g_slist_append(profiles, profile);
	return 0;
}

void btd_profile_unregister(struct btd_profile *profile)
{
	profiles = g_slist_remove(profiles, profile);
}

static struct ext_profile *find_ext_profile(const char *owner,
						const char *path)
{
	GSList *l;

	for (l = ext_profiles; l != NULL; l = g_slist_next(l)) {
		struct ext_profile *ext = l->data;

		if (!g_str_equal(ext->owner, owner))
			continue;

		if (g_str_equal(ext->path, path))
			return ext;
	}

	return NULL;
}

static void ext_cancel(struct ext_profile *ext)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(ext->owner, ext->path,
						"org.bluez.Profile", "Cancel");
	if (msg)
		g_dbus_send_message(btd_get_dbus_connection(), msg);
}

static void ext_io_destroy(gpointer p)
{
	struct ext_io *ext_io = p;
	struct ext_profile *ext = ext_io->ext;

	if (ext_io->io_id > 0)
		g_source_remove(ext_io->io_id);

	g_io_channel_shutdown(ext_io->io, FALSE, NULL);
	g_io_channel_unref(ext_io->io);

	if (ext_io->auth_id != 0)
		btd_cancel_authorization(ext_io->auth_id);

	if (ext_io->new_conn) {
		dbus_pending_call_cancel(ext_io->new_conn);
		dbus_pending_call_unref(ext_io->new_conn);
		ext_cancel(ext);
	}

	if (ext_io->adapter)
		btd_adapter_unref(ext_io->adapter);

	g_free(ext_io);
}

static gboolean ext_io_disconnected(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct ext_io *conn = user_data;
	struct ext_profile *ext = conn->ext;
	GError *gerr = NULL;
	char addr[18];

	if (cond & G_IO_NVAL)
		return FALSE;

	bt_io_get(io, &gerr, BT_IO_OPT_DEST, addr, BT_IO_OPT_INVALID);
	if (gerr != NULL) {
		error("Unable to get io data for %s: %s",
						ext->name, gerr->message);
		g_error_free(gerr);
		goto drop;
	}

	DBG("%s disconnected from %s", ext->name, addr);
drop:
	ext->conns = g_slist_remove(ext->conns, conn);
	ext_io_destroy(conn);
	return FALSE;
}

static void new_conn_reply(DBusPendingCall *call, void *user_data)
{
	struct ext_io *conn = user_data;
	struct ext_profile *ext = conn->ext;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError err;

	dbus_error_init(&err);
	dbus_set_error_from_message(&err, reply);

	dbus_message_unref(reply);

	dbus_pending_call_unref(conn->new_conn);
	conn->new_conn = NULL;

	if (!dbus_error_is_set(&err))
		return;

	error("%s replied with an error: %s, %s", ext->name,
						err.name, err.message);

	if (dbus_error_has_name(&err, DBUS_ERROR_NO_REPLY))
		ext_cancel(ext);

	dbus_error_free(&err);

	ext->conns = g_slist_remove(ext->conns, conn);
	ext_io_destroy(conn);
}

static bool send_new_connection(struct ext_profile *ext, struct ext_io *conn,
							struct btd_device *dev)
{
	DBusMessage *msg;
	const char *path;
	int fd;

	msg = dbus_message_new_method_call(ext->owner, ext->path,
							"org.bluez.Profile",
							"NewConnection");
	if (!msg) {
		error("Unable to create NewConnection call for %s", ext->name);
		return false;
	}

	path = device_get_path(dev);
	fd = g_io_channel_unix_get_fd(conn->io);

	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &path,
					DBUS_TYPE_UNIX_FD, &fd,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(btd_get_dbus_connection(),
						msg, &conn->new_conn, -1)) {
		error("%s: sending NewConnection failed", ext->name);
		dbus_message_unref(msg);
		return false;
	}

	dbus_message_unref(msg);

	dbus_pending_call_set_notify(conn->new_conn, new_conn_reply, conn,
									NULL);

	return true;
}

static struct btd_device *get_btd_dev(bdaddr_t *src, const char *addr)
{
	struct btd_adapter *adapter;

	adapter = manager_find_adapter(src);
	if (!adapter)
		return NULL;

	return adapter_get_device(adapter, addr);
}

static void ext_connect(GIOChannel *io, GError *err, gpointer user_data)
{
	struct ext_io *conn = user_data;
	struct ext_profile *ext = conn->ext;
	struct btd_device *device;
	bdaddr_t src;
	char addr[18];

	if (!bt_io_get(io, NULL,
				BT_IO_OPT_SOURCE_BDADDR, &src,
				BT_IO_OPT_DEST, addr,
				BT_IO_OPT_INVALID)) {
		error("Unable to get connect data for %s", ext->name);
		goto drop;
	}

	if (err != NULL) {
		error("%s failed to connect to %s: %s", ext->name, addr,
								err->message);
		goto drop;
	}

	DBG("%s connected to %s", ext->name, addr);

	device = get_btd_dev(&src, addr);
	if (!device) {
		error("%s: Unable to get dev object for %s", ext->name, addr);
		goto drop;
	}

	if (send_new_connection(ext, conn, device))
		return;

drop:
	ext->conns = g_slist_remove(ext->conns, conn);
	ext_io_destroy(conn);
}

static void ext_auth(DBusError *err, void *user_data)
{
	struct ext_io *conn = user_data;
	struct ext_profile *ext = conn->ext;
	GError *gerr = NULL;
	char addr[18];

	conn->auth_id = 0;

	bt_io_get(conn->io, &gerr, BT_IO_OPT_DEST, addr, BT_IO_OPT_INVALID);
	if (gerr != NULL) {
		error("Unable to get connect data for %s: %s",
						ext->name, err->message);
		g_error_free(gerr);
		goto drop;
	}

	if (err && dbus_error_is_set(err)) {
		error("%s rejected %s: %s", ext->name, addr, err->message);
		goto drop;
	}

	if (!bt_io_accept(conn->io, ext_connect, conn, NULL, &gerr)) {
		error("bt_io_accept: %s", gerr->message);
		g_error_free(gerr);
		goto drop;
	}

	DBG("%s authorized to connect to %s", addr, ext->name);

	return;

drop:
	ext->conns = g_slist_remove(ext->conns, conn);
	ext_io_destroy(conn);
}

static struct ext_io *create_conn(struct ext_io *server, GIOChannel *io)
{
	struct ext_io *conn;
	GIOCondition cond;

	conn = g_new0(struct ext_io, 1);
	conn->io = g_io_channel_ref(io);
	conn->proto = server->proto;
	conn->ext = server->ext;

	cond = G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	conn->io_id = g_io_add_watch(io, cond, ext_io_disconnected, conn);

	return conn;
}

static void ext_confirm(GIOChannel *io, gpointer user_data)
{
	struct ext_io *server = user_data;
	struct ext_profile *ext = server->ext;
	struct ext_io *conn;
	GError *gerr = NULL;
	bdaddr_t src, dst;
	char addr[18];

	bt_io_get(io, &gerr,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_DEST, addr,
			BT_IO_OPT_INVALID);
	if (gerr != NULL) {
		error("%s failed to get connect data: %s", ext->name,
								gerr->message);
		g_error_free(gerr);
		return;
	}

	DBG("incoming connect from %s", addr);

	conn = create_conn(server, io);

	conn->auth_id = btd_request_authorization(&src, &dst, ext->uuid,
								ext_auth, conn);
	if (conn->auth_id == 0) {
		error("%s authorization failure", ext->name);
		ext_io_destroy(conn);
		return;
	}

	ext->conns = g_slist_append(ext->conns, conn);

	DBG("%s authorizing connection from %s", ext->name, addr);
}

static void ext_direct_connect(GIOChannel *io, GError *err, gpointer user_data)
{
	struct ext_io *server = user_data;
	struct ext_profile *ext = server->ext;
	struct ext_io *conn;

	conn = create_conn(server, io);
	ext->conns = g_slist_append(ext->conns, conn);

	ext_connect(io, err, conn);
}

static int ext_start_servers(struct ext_profile *ext,
						struct btd_adapter *adapter)
{
	struct ext_io *server;
	BtIOConfirm confirm;
	BtIOConnect connect;
	GError *err = NULL;
	GIOChannel *io;
	bdaddr_t src;

	adapter_get_address(adapter, &src);

	if (ext->authorize) {
		confirm = ext_confirm;
		connect = NULL;
	} else {
		confirm = NULL;
		connect = ext_direct_connect;
	}

	if (ext->psm) {
		server = g_new0(struct ext_io, 1);
		server->ext = ext;

		io = bt_io_listen(connect, confirm, server, NULL, &err,
					BT_IO_OPT_SOURCE_BDADDR, &src,
					BT_IO_OPT_PSM, ext->psm,
					BT_IO_OPT_SEC_LEVEL, ext->sec_level,
					BT_IO_OPT_INVALID);
		if (err != NULL) {
			error("L2CAP server failed for %s: %s",
						ext->name, err->message);
			g_free(server);
			g_clear_error(&err);
		} else {
			server->io = io;
			server->proto = BTPROTO_L2CAP;
			server->adapter = btd_adapter_ref(adapter);
			ext->servers = g_slist_append(ext->servers, server);
			DBG("%s listening on PSM %u", ext->name, ext->psm);
		}
	}

	if (ext->chan) {
		server = g_new0(struct ext_io, 1);
		server->ext = ext;

		io = bt_io_listen(connect, confirm, server, NULL, &err,
					BT_IO_OPT_SOURCE_BDADDR, &src,
					BT_IO_OPT_CHANNEL, ext->chan,
					BT_IO_OPT_SEC_LEVEL, ext->sec_level,
					BT_IO_OPT_INVALID);
		if (err != NULL) {
			error("RFCOMM server failed for %s: %s",
						ext->name, err->message);
			g_free(server);
			g_clear_error(&err);
		} else {
			server->io = io;
			server->proto = BTPROTO_RFCOMM;
			server->adapter = btd_adapter_ref(adapter);
			ext->servers = g_slist_append(ext->servers, server);
			DBG("%s listening on chan %u", ext->name, ext->chan);
		}
	}

	return 0;
}

static struct ext_profile *find_ext(struct btd_profile *p)
{
	GSList *l;

	l = g_slist_find(ext_profiles, p);
	if (!l)
		return NULL;

	return l->data;
}

static int ext_adapter_probe(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	struct ext_profile *ext;

	ext = find_ext(p);
	if (!ext)
		return -ENOENT;

	DBG("\"%s\" probed", ext->name);

	return ext_start_servers(ext, adapter);
}

static void ext_adapter_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	struct ext_profile *ext;
	GSList *l, *next;

	ext = find_ext(p);
	if (!ext)
		return;

	DBG("\"%s\" removed", ext->name);

	for (l = ext->servers; l != NULL; l = next) {
		struct ext_io *server = l->data;

		next = g_slist_next(l);

		if (server->adapter != adapter)
			continue;

		ext->servers = g_slist_remove(ext->servers, server);
		ext_io_destroy(server);
	}
}

static int ext_device_probe(struct btd_profile *p, struct btd_device *dev,
								GSList *uuids)
{
	struct ext_profile *ext;

	ext = find_ext(p);
	if (!ext)
		return -ENOENT;

	DBG("%s probed with %u UUIDs", ext->name, g_slist_length(uuids));

	return 0;
}

static void pending_conn_free(gpointer data)
{
	struct pending_connect *conn = data;

	btd_device_unref(conn->dev);
	g_free(conn);
}

static void remove_connect(struct ext_profile *ext, struct btd_device *dev)
{
	GSList *l, *next;

	for (l = ext->connects; l != NULL; l = next) {
		struct pending_connect *conn = l->data;

		next = g_slist_next(l);

		if (conn->dev != dev)
			continue;

		ext->connects = g_slist_remove(ext->connects, conn);
		pending_conn_free(conn);
	}
}

static void ext_device_remove(struct btd_profile *p, struct btd_device *dev)
{
	struct ext_profile *ext;

	ext = find_ext(p);
	if (!ext)
		return;

	DBG("%s", ext->name);

	remove_connect(ext, dev);
}

static int connect_ext(struct ext_profile *ext, struct btd_device *dev)
{
	return -ENOSYS;
}

static int ext_connect_dev(struct btd_device *dev, struct btd_profile *profile,
							btd_profile_cb cb)
{
	struct ext_profile *ext;
	struct pending_connect *conn;
	int err;

	ext = find_ext(profile);
	if (!ext)
		return -ENOENT;

	err = connect_ext(ext, dev);
	if (err < 0)
		return err;

	conn = g_new0(struct pending_connect, 1);
	conn->dev = btd_device_ref(dev);
	conn->cb = cb;

	ext->connects = g_slist_append(ext->connects, conn);

	return 0;
}

static int ext_disconnect_dev(struct btd_device *dev,
						struct btd_profile *profile,
						btd_profile_cb cb)
{
	struct ext_profile *ext;

	ext = find_ext(profile);
	if (!ext)
		return -ENOENT;

	remove_connect(ext, dev);

	return 0;
}

static void ext_get_defaults(struct ext_profile *ext)
{
	if (ext->psm || ext->chan)
		return;

	if (strcasecmp(ext->uuid, "spp") == 0) {
		if (g_strcmp0(ext->role, "client") == 0)
			return;

		ext->chan = 3;
	}
}

static int parse_ext_opt(struct ext_profile *ext, const char *key,
							DBusMessageIter *value)
{
	int type = dbus_message_iter_get_arg_type(value);
	const char *str;

	if (strcasecmp(key, "Name") == 0) {
		if (type != DBUS_TYPE_STRING)
			return -EINVAL;
		dbus_message_iter_get_basic(value, &str);
		g_free(ext->name);
		ext->name = g_strdup(str);
	} else if (strcasecmp(key, "AutoConnect") == 0) {
		if (type != DBUS_TYPE_BOOLEAN)
			return -EINVAL;
		dbus_message_iter_get_basic(value, &ext->p.auto_connect);
	} else if (strcasecmp(key, "PSM") == 0) {
		if (type != DBUS_TYPE_UINT16)
			return -EINVAL;
		dbus_message_iter_get_basic(value, &ext->psm);
	} else if (strcasecmp(key, "Channel") == 0) {
		uint16_t ch;

		if (type != DBUS_TYPE_UINT16)
			return -EINVAL;

		dbus_message_iter_get_basic(value, &ch);
		ext->chan = ch;
	} else if (strcasecmp(key, "RequireAuthentication") == 0) {
		dbus_bool_t b;

		if (type != DBUS_TYPE_BOOLEAN)
			return -EINVAL;

		dbus_message_iter_get_basic(value, &b);
		if (b)
			ext->sec_level = BT_IO_SEC_MEDIUM;
		else
			ext->sec_level = BT_IO_SEC_LOW;
	} else if (strcasecmp(key, "RequireAuthorization") == 0) {
		if (type != DBUS_TYPE_BOOLEAN)
			return -EINVAL;
		dbus_message_iter_get_basic(value, &ext->authorize);
	} else if (strcasecmp(key, "Role") == 0) {
		if (type != DBUS_TYPE_STRING)
			return -EINVAL;
		dbus_message_iter_get_basic(value, &str);
		g_free(ext->role);
		ext->role = g_strdup(str);
	}

	return 0;
}

static struct ext_profile *create_ext(const char *owner, const char *path,
					const char *uuid,
					DBusMessageIter *opts)
{
	struct btd_profile *p;
	struct ext_profile *ext;

	ext = g_new0(struct ext_profile, 1);

	ext->owner = g_strdup(owner);
	ext->path = g_strdup(path);
	ext->uuid = g_strdup(uuid);
	ext->remote_uuids = g_new0(char *, 1);

	ext->sec_level = BT_IO_SEC_LOW;

	while (dbus_message_iter_get_arg_type(opts) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter value, entry;
		const char *key;

		dbus_message_iter_recurse(opts, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (parse_ext_opt(ext, key, &value) < 0)
			error("Invalid value for profile option %s", key);

		dbus_message_iter_next(opts);
	}

	if (!ext->name)
		ext->name = g_strdup_printf("%s%s/%s", owner, path, uuid);

	ext_get_defaults(ext);

	p = &ext->p;

	p->name = ext->name;
	p->adapter_probe = ext_adapter_probe;
	p->adapter_remove = ext_adapter_remove;

	/* Typecast can't really be avoided here:
	 * http://c-faq.com/ansi/constmismatch.html */
	p->remote_uuids = (const char **) ext->remote_uuids;

	p->device_probe = ext_device_probe;
	p->device_remove = ext_device_remove;
	p->connect = ext_connect_dev;
	p->disconnect = ext_disconnect_dev;

	DBG("Created \"%s\"", ext->name);

	ext_profiles = g_slist_append(ext_profiles, ext);

	manager_foreach_adapter(adapter_add_profile, &ext->p);

	return ext;
}

static void remove_ext(struct ext_profile *ext)
{
	manager_foreach_adapter(adapter_remove_profile, &ext->p);

	ext_profiles = g_slist_remove(ext_profiles, ext);

	DBG("Removed \"%s\"", ext->name);

	g_slist_free_full(ext->servers, ext_io_destroy);
	g_slist_free_full(ext->conns, ext_io_destroy);
	g_slist_free_full(ext->connects, pending_conn_free);

	g_strfreev(ext->remote_uuids);

	g_free(ext->name);
	g_free(ext->owner);
	g_free(ext->uuid);
	g_free(ext->role);
	g_free(ext->path);

	g_free(ext);
}

static void ext_exited(DBusConnection *conn, void *user_data)
{
	struct ext_profile *ext = user_data;

	DBG("\"%s\" exited", ext->name);

	remove_ext(ext);
}

DBusMessage *btd_profile_reg_ext(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	const char *path, *sender, *uuid;
	DBusMessageIter args, opts;
	struct ext_profile *ext;

	sender = dbus_message_get_sender(msg);

	dbus_message_iter_init(msg, &args);

	dbus_message_iter_get_basic(&args, &path);
	dbus_message_iter_next(&args);

	ext = find_ext_profile(sender, path);
	if (ext)
		return btd_error_already_exists(msg);

	dbus_message_iter_get_basic(&args, &uuid);
	dbus_message_iter_next(&args);

	dbus_message_iter_recurse(&args, &opts);
	if (dbus_message_iter_get_arg_type(&opts) != DBUS_TYPE_DICT_ENTRY)
		return btd_error_invalid_args(msg);

	ext = create_ext(sender, path, uuid, &opts);
	if (!ext)
		return btd_error_invalid_args(msg);

	ext->id = g_dbus_add_disconnect_watch(conn, sender, ext_exited, ext,
									NULL);

	return dbus_message_new_method_return(msg);
}

DBusMessage *btd_profile_unreg_ext(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	const char *path, *sender;
	struct ext_profile *ext;

	sender = dbus_message_get_sender(msg);

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	ext = find_ext_profile(sender, path);
	if (!ext)
		return btd_error_does_not_exist(msg);

	g_dbus_remove_watch(conn, ext->id);
	remove_ext(ext);

	return dbus_message_new_method_return(msg);
}

void btd_profile_cleanup(void)
{
	while (ext_profiles) {
		struct ext_profile *ext = ext_profiles->data;
		DBusConnection *conn = btd_get_dbus_connection();
		DBusMessage *msg;

		DBG("Releasing \"%s\"", ext->name);

		g_slist_free_full(ext->conns, ext_io_destroy);
		ext->conns = NULL;

		msg = dbus_message_new_method_call(ext->owner, ext->path,
							"org.bluez.Profile",
							"Release");
		if (msg)
			g_dbus_send_message(conn, msg);

		g_dbus_remove_watch(conn, ext->id);
		remove_ext(ext);

	}
}
