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
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "btio.h"
#include "sdpd.h"
#include "log.h"
#include "error.h"
#include "glib-helper.h"
#include "dbus-common.h"
#include "sdp-client.h"
#include "sdp-xml.h"
#include "adapter.h"
#include "manager.h"
#include "device.h"
#include "profile.h"

#define SPP_DEFAULT_CHANNEL	3

struct ext_profile {
	struct btd_profile p;

	char *name;
	char *owner;
	char *uuid;
	char *path;
	char *role;
	char *record;

	char **remote_uuids;

	guint id;

	BtIOSecLevel sec_level;
	bool authorize;

	bool enable_client;
	bool enable_server;

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
	struct btd_device *device;

	bool resolving;
	btd_profile_cb cb;
	uint16_t rec_handle;

	guint auth_id;
	DBusPendingCall *new_conn;
};

struct btd_profile_custom_property {
	char *uuid;
	char *type;
	char *name;
	btd_profile_prop_exists exists;
	btd_profile_prop_get get;
	void *user_data;
};

static GSList *custom_props = NULL;

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
						"org.bluez.Profile1", "Cancel");
	if (msg)
		g_dbus_send_message(btd_get_dbus_connection(), msg);
}

static void ext_io_destroy(gpointer p)
{
	struct ext_io *ext_io = p;
	struct ext_profile *ext = ext_io->ext;

	if (ext_io->io_id > 0)
		g_source_remove(ext_io->io_id);

	if (ext_io->io) {
		g_io_channel_shutdown(ext_io->io, FALSE, NULL);
		g_io_channel_unref(ext_io->io);
	}

	if (ext_io->auth_id != 0)
		btd_cancel_authorization(ext_io->auth_id);

	if (ext_io->new_conn) {
		dbus_pending_call_cancel(ext_io->new_conn);
		dbus_pending_call_unref(ext_io->new_conn);
		ext_cancel(ext);
	}

	if (ext_io->resolving)
		bt_cancel_discovery(adapter_get_address(ext_io->adapter),
					device_get_address(ext_io->device));

	if (ext_io->rec_handle)
		remove_record_from_server(ext_io->rec_handle);

	if (ext_io->adapter)
		btd_adapter_unref(ext_io->adapter);

	if (ext_io->device)
		btd_device_unref(ext_io->device);

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

	if (!dbus_error_is_set(&err)) {
		if (conn->cb) {
			conn->cb(&ext->p, conn->device, 0);
			conn->cb = NULL;
		}
		return;
	}

	error("%s replied with an error: %s, %s", ext->name,
						err.name, err.message);

	if (conn->cb) {
		conn->cb(&ext->p, conn->device, -ECONNREFUSED);
		conn->cb = NULL;
	}

	if (dbus_error_has_name(&err, DBUS_ERROR_NO_REPLY))
		ext_cancel(ext);

	dbus_error_free(&err);

	ext->conns = g_slist_remove(ext->conns, conn);
	ext_io_destroy(conn);
}

struct prop_append_data {
	DBusMessageIter *dict;
	struct ext_io *io;
};

static void append_prop(gpointer a, gpointer b)
{
	struct btd_profile_custom_property *p = a;
	struct prop_append_data *data = b;
	DBusMessageIter entry, value, *dict = data->dict;
	struct btd_device *dev = data->io->device;

	if (p->exists && !p->exists(p->uuid, dev, p->user_data))
		return;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
								&entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &p->name);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, p->type,
								&value);

	p->get(p->uuid, dev, &value, p->user_data);

	dbus_message_iter_close_container(&entry, &value);
	dbus_message_iter_close_container(dict, &entry);
}

static bool send_new_connection(struct ext_profile *ext, struct ext_io *conn,
							struct btd_device *dev)
{
	DBusMessage *msg;
	DBusMessageIter iter, dict;
	struct prop_append_data data = { &dict, conn };
	const char *path;
	int fd;

	msg = dbus_message_new_method_call(ext->owner, ext->path,
							"org.bluez.Profile1",
							"NewConnection");
	if (!msg) {
		error("Unable to create NewConnection call for %s", ext->name);
		return false;
	}

	dbus_message_iter_init_append(msg, &iter);

	path = device_get_path(dev);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &path);

	fd = g_io_channel_unix_get_fd(conn->io);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UNIX_FD, &fd);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

	g_slist_foreach(custom_props, append_prop, &data);

	dbus_message_iter_close_container(&iter, &dict);

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

	if (conn->io_id == 0) {
		GIOCondition cond = G_IO_HUP | G_IO_ERR | G_IO_NVAL;
		conn->io_id = g_io_add_watch(io, cond, ext_io_disconnected,
									conn);
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

static sdp_record_t *ext_get_record(struct ext_profile *ext)
{
	return NULL;
}

static uint16_t ext_register_record(struct ext_profile *ext,
							const bdaddr_t *src)
{
	sdp_record_t *rec;

	if (ext->record)
		rec = sdp_xml_parse_record(ext->record, strlen(ext->record));
	else
		rec = ext_get_record(ext);

	if (!rec)
		return 0;

	if (add_record_to_server(src, rec) < 0) {
		error("Failed to register service record");
		sdp_record_free(rec);
		return 0;
	}

	return rec->handle;
}

static int ext_start_servers(struct ext_profile *ext,
						struct btd_adapter *adapter)
{
	struct ext_io *server;
	BtIOConfirm confirm;
	BtIOConnect connect;
	GError *err = NULL;
	uint16_t handle;
	GIOChannel *io;

	handle = ext_register_record(ext, adapter_get_address(adapter));

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
		server->rec_handle = handle;

		io = bt_io_listen(connect, confirm, server, NULL, &err,
					BT_IO_OPT_SOURCE_BDADDR,
					adapter_get_address(adapter),
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
		server->rec_handle = handle;

		io = bt_io_listen(connect, confirm, server, NULL, &err,
					BT_IO_OPT_SOURCE_BDADDR,
					adapter_get_address(adapter),
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

static void remove_connect(struct ext_profile *ext, struct btd_device *dev)
{
	GSList *l, *next;

	for (l = ext->conns; l != NULL; l = next) {
		struct ext_io *conn = l->data;

		next = g_slist_next(l);

		if (!conn->cb)
			continue;

		if (conn->device != dev)
			continue;

		ext->conns = g_slist_remove(ext->conns, conn);
		ext_io_destroy(conn);
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

static int connect_io(struct ext_io *conn, const bdaddr_t *src,
							const bdaddr_t *dst)
{
	struct ext_profile *ext = conn->ext;
	GError *gerr = NULL;
	GIOChannel *io;

	if (ext->psm) {
		conn->proto = BTPROTO_L2CAP;
		io = bt_io_connect(ext_connect, conn, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, src,
					BT_IO_OPT_DEST_BDADDR, dst,
					BT_IO_OPT_SEC_LEVEL, ext->sec_level,
					BT_IO_OPT_PSM, ext->psm,
					BT_IO_OPT_INVALID);
	} else {
		conn->proto = BTPROTO_RFCOMM;
		io = bt_io_connect(ext_connect, conn, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, src,
					BT_IO_OPT_DEST_BDADDR, dst,
					BT_IO_OPT_SEC_LEVEL, ext->sec_level,
					BT_IO_OPT_CHANNEL, ext->chan,
					BT_IO_OPT_INVALID);
	}

	if (gerr != NULL) {
		error("Unable to connect %s: %s", ext->name, gerr->message);
		g_error_free(gerr);
		return -EIO;
	}

	conn->io = io;

	return 0;
}

static uint16_t get_goep_l2cap_psm(sdp_record_t *rec)
{
	sdp_data_t *data;

	data = sdp_data_get(rec, SDP_ATTR_GOEP_L2CAP_PSM);
	if (!data)
		return 0;

	if (data->dtd != SDP_UINT16)
		return 0;

	/* PSM must be odd and lsb of upper byte must be 0 */
	if ((data->val.uint16 & 0x0101) != 0x0001)
		return 0;

	return data->val.uint16;
}

static void record_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct ext_io *conn = user_data;
	struct ext_profile *ext = conn->ext;
	sdp_list_t *r;

	conn->resolving = false;

	if (err < 0) {
		error("Unable to get %s SDP record: %s", ext->name,
							strerror(-err));
		goto failed;
	}

	if (!recs || !recs->data) {
		error("No SDP records found for %s", ext->name);
		goto failed;
	}

	for (r = recs; r != NULL; r = r->next) {
		sdp_record_t *rec = r->data;
		sdp_list_t *protos;
		int port;

		if (sdp_get_access_protos(rec, &protos) < 0) {
			error("Unable to get proto list from %s record",
								ext->name);
			goto failed;
		}

		port = sdp_get_proto_port(protos, L2CAP_UUID);
		if (port > 0)
			ext->psm = port;

		port = sdp_get_proto_port(protos, RFCOMM_UUID);
		if (port > 0)
			ext->chan = port;

		if (ext->psm == 0 && sdp_get_proto_desc(protos, OBEX_UUID))
			ext->psm = get_goep_l2cap_psm(rec);

		sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free,
									NULL);
		sdp_list_free(protos, NULL);

		if (ext->chan || ext->psm)
			break;
	}

	if (!ext->chan && !ext->psm) {
		error("Failed to find L2CAP PSM or RFCOMM channel for %s",
								ext->name);
		goto failed;
	}

	err = connect_io(conn, adapter_get_address(conn->adapter),
					device_get_address(conn->device));
	if (err < 0) {
		error("Connecting %s failed: %s", ext->name, strerror(-err));
		goto failed;
	}

	return;

failed:
	conn->cb(&ext->p, conn->device, err);
	ext->conns = g_slist_remove(ext->conns, conn);
	ext_io_destroy(conn);
}

static int resolve_service(struct ext_io *conn, const bdaddr_t *src,
							const bdaddr_t *dst)
{
	struct ext_profile *ext = conn->ext;
	uuid_t uuid;
	int err;

	bt_string2uuid(&uuid, ext->remote_uuids[0]);

	err = bt_search_service(src, dst, &uuid, record_cb, conn, NULL);
	if (err == 0)
		conn->resolving = true;

	return err;
}

static int ext_connect_dev(struct btd_device *dev, struct btd_profile *profile,
							btd_profile_cb cb)
{
	struct btd_adapter *adapter;
	struct ext_io *conn;
	struct ext_profile *ext;
	int err;

	ext = find_ext(profile);
	if (!ext)
		return -ENOENT;

	adapter = device_get_adapter(dev);

	conn = g_new0(struct ext_io, 1);
	conn->ext = ext;

	if (ext->psm || ext->chan)
		err = connect_io(conn, adapter_get_address(adapter),
						device_get_address(dev));
	else
		err = resolve_service(conn, adapter_get_address(adapter),
						device_get_address(dev));

	if (err < 0)
		goto failed;

	conn->adapter = btd_adapter_ref(adapter);
	conn->device = btd_device_ref(dev);
	conn->cb = cb;

	ext->conns = g_slist_append(ext->conns, conn);

	return 0;

failed:
	g_free(conn);
	return err;
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
	if (ext->enable_client && !ext->remote_uuids[0]) {
		g_strfreev(ext->remote_uuids);
		ext->remote_uuids = g_new0(char *, 2);
		ext->remote_uuids[0] = g_strdup(ext->uuid);
	}

	if (strcasecmp(ext->uuid, SPP_UUID) == 0) {
		if (ext->enable_server && !ext->chan)
			ext->chan = SPP_DEFAULT_CHANNEL;
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

		if (g_str_equal(ext->role, "client")) {
			ext->enable_server = false;
			ext->enable_client = true;
		} else if (g_str_equal(ext->role, "server")) {
			ext->enable_server = true;
			ext->enable_client = false;
		}
	} else if (strcasecmp(key, "ServiceRecord") == 0) {
		if (type != DBUS_TYPE_STRING)
			return -EINVAL;
		dbus_message_iter_get_basic(value, &str);
		g_free(ext->record);
		ext->record = g_strdup(str);
		ext->enable_server = true;
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

	ext->uuid = bt_name2string(uuid);

	ext->remote_uuids = g_new0(char *, 1);

	ext->sec_level = BT_IO_SEC_LOW;
	ext->enable_client = true;
	ext->enable_server = true;

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

	/* Typecast can't really be avoided here:
	 * http://c-faq.com/ansi/constmismatch.html */
	p->remote_uuids = (const char **) ext->remote_uuids;

	if (ext->enable_server) {
		p->adapter_probe = ext_adapter_probe;
		p->adapter_remove = ext_adapter_remove;
	}

	if (ext->enable_client) {
		p->device_probe = ext_device_probe;
		p->device_remove = ext_device_remove;
		p->connect = ext_connect_dev;
		p->disconnect = ext_disconnect_dev;
	}

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

	g_strfreev(ext->remote_uuids);

	g_free(ext->name);
	g_free(ext->owner);
	g_free(ext->uuid);
	g_free(ext->role);
	g_free(ext->path);
	g_free(ext->record);

	g_free(ext);
}

static void ext_exited(DBusConnection *conn, void *user_data)
{
	struct ext_profile *ext = user_data;

	DBG("\"%s\" exited", ext->name);

	remove_ext(ext);
}

static DBusMessage *register_profile(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
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

static DBusMessage *unregister_profile(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
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

static const GDBusMethodTable methods[] = {
	{ GDBUS_METHOD("RegisterProfile",
			GDBUS_ARGS({ "profile", "o"}, { "UUID", "s" },
						{ "options", "a{sv}" }),
			NULL, register_profile) },
	{ GDBUS_METHOD("UnregisterProfile", GDBUS_ARGS({ "profile", "o" }),
			NULL, unregister_profile) },
	{ }
};

void btd_profile_add_custom_prop(const char *uuid, const char *type,
					const char *name,
					btd_profile_prop_exists exists,
					btd_profile_prop_get get,
					void *user_data)
{
	struct btd_profile_custom_property *prop;

	prop = g_new0(struct btd_profile_custom_property, 1);

	prop->uuid = g_strdup(uuid);
	prop->type = g_strdup(type);
	prop->name = g_strdup(name);
	prop->exists = exists;
	prop->get = get;
	prop->user_data = user_data;

	custom_props = g_slist_append(custom_props, prop);
}

static void free_property(gpointer data)
{
	struct btd_profile_custom_property *p = data;

	g_free(p->uuid);
	g_free(p->type);
	g_free(p->name);

	g_free(p);
}

void btd_profile_init(void)
{
	g_dbus_register_interface(btd_get_dbus_connection(),
				"/org/bluez", "org.bluez.ProfileManager1",
				methods, NULL, NULL, NULL, NULL);
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
							"org.bluez.Profile1",
							"Release");
		if (msg)
			g_dbus_send_message(conn, msg);

		g_dbus_remove_watch(conn, ext->id);
		remove_ext(ext);

	}

	g_slist_free_full(custom_props, free_property);
	custom_props = NULL;

	g_dbus_unregister_interface(btd_get_dbus_connection(),
				"/org/bluez", "org.bluez.ProfileManager1");

}
