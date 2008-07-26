/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <ctype.h>
#include <dirent.h>

#include <sys/stat.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/bnep.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <gdbus.h>

#include "logging.h"
#include "textfile.h"
#include "glib-helper.h"

#define NETWORK_MANAGER_INTERFACE "org.bluez.network.Manager"

#include "error.h"
#include "bridge.h"
#include "manager.h"
#include "common.h"

#define MAX_NAME_SIZE	256

struct pending_reply {
	DBusConnection	*conn;
	DBusMessage	*msg;
	bdaddr_t	src;		/* Source address */
	bdaddr_t	dst;		/* Destination address */
	char		*addr;		/* Destination address */
	char		*path;		/* D-Bus object path */
	char		*adapter_path;	/* Default adapter path */
	uint16_t	id;		/* Role */
};

static struct network_conf *conf = NULL;/* Network service configuration */
static GSList *server_paths	= NULL;	/* Network registered servers paths */
static GSList *connection_paths	= NULL;	/* Network registered connections paths */
static int default_index = -1;		/* Network default connection path index */
static int net_uid = 0;			/* Network objects identifier */

static DBusConnection *connection = NULL;

static void pending_reply_free(struct pending_reply *pr)
{
	if (pr->addr)
		g_free(pr->addr);
	if (pr->path)
		g_free(pr->path);
	if (pr->adapter_path)
		g_free(pr->adapter_path);
	if (pr->msg)
		dbus_message_unref(pr->msg);
	if (pr->conn)
		dbus_connection_unref(pr->conn);
}

static inline DBusMessage *does_not_exist(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".AlreadyExists",
							"No such connection");
}

static inline DBusMessage *already_exists(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".AlreadyExists",
						"Connection already exists");
}

static inline DBusMessage *not_supported(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotSupported",
							"Not supported");
}

static inline DBusMessage *connection_is_busy(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
						"Connection is Busy");
}

static inline DBusMessage *adapter_not_available(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
						"Adapter not available");
}

static void create_path(DBusConnection *conn, DBusMessage *msg,
				const char *path, const char *sname)
{
	/* emit signal when it is a new path */
	if (sname) {
		g_dbus_emit_signal(conn, NETWORK_PATH,
						NETWORK_MANAGER_INTERFACE,
						sname, DBUS_TYPE_STRING, &path,
						DBUS_TYPE_INVALID);
	}

	g_dbus_send_reply(conn, msg, DBUS_TYPE_STRING, &path,
						DBUS_TYPE_INVALID);
}

static DBusMessage *list_paths(DBusConnection *conn, DBusMessage *msg,
					GSList *list)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array_iter;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	for (; list; list = list->next) {
		dbus_message_iter_append_basic(&array_iter,
						DBUS_TYPE_STRING,
						&list->data);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return reply;
}

static const char *last_connection_used(DBusConnection *conn)
{
	const char *path = NULL;
	GSList *l;
	int i;

	for (i = g_slist_length (connection_paths) -1; i > -1; i--) {
		path = g_slist_nth_data (connection_paths, i);
		if (connection_is_connected(path))
			break;
	}

	/* No connection connected fallback to last connection */
	if (i == -1) {
		l = g_slist_last(connection_paths);
		path = l->data;
	}

	return path;
}

static DBusMessage *remove_path(DBusConnection *conn,
					DBusMessage *msg, GSList **list,
					const char *sname)
{
	const char *path;
	GSList *l;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &path,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	l = g_slist_find_custom(*list, path, (GCompareFunc) strcmp);
	if (!l)
		return does_not_exist(msg);

	/* Remove references from the storage */
	if (*list == connection_paths) {
		if (connection_has_pending(path))
			return connection_is_busy(msg);

		connection_remove_stored(path);
		/* Reset default connection */
		if (l == g_slist_nth(*list, default_index)) {
			const char *dpath;

			dpath = last_connection_used(conn);
			connection_store(dpath, TRUE);
		}
	}

	g_free(l->data);
	*list = g_slist_remove(*list, l->data);

	g_dbus_emit_signal(conn, NETWORK_PATH,
					NETWORK_MANAGER_INTERFACE,
					sname, DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID);

	g_dbus_unregister_interface(conn, path, NETWORK_CONNECTION_INTERFACE);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void records_cb(sdp_list_t *recs, int err, gpointer data)
{
	struct pending_reply *pr = data;
	int len;
	sdp_data_t *d;
	sdp_record_t *rec = NULL;
	char name[MAX_NAME_SIZE], *desc = NULL;

	if (err < 0) {
		error_connection_attempt_failed(pr->conn, pr->msg, -err);
		goto fail;
	}

	if (!recs || !recs->data) {
		error_not_supported(pr->conn, pr->msg);
		error("Invalid PAN service record");
		goto fail;
	}

	rec = recs->data;

	/* Concat remote name and service name */
	memset(name, 0, MAX_NAME_SIZE);
	if (read_remote_name(&pr->src, &pr->dst, name, MAX_NAME_SIZE) < 0)
		len = 0;
	else
		len = strlen(name);

	d = sdp_data_get(rec, SDP_ATTR_SVCNAME_PRIMARY);
	if (d) {
		snprintf(name + len, MAX_NAME_SIZE - len,
			len ? " (%.*s)" : "%.*s", d->unitSize, d->val.str);
	}

	/* Extract service description from record */
	d = sdp_data_get(rec, SDP_ATTR_SVCDESC_PRIMARY);
	if (d) {
		desc = g_new0(char, d->unitSize);
		snprintf(desc, d->unitSize, "%.*s",
				d->unitSize, d->val.str);
	}

	sdp_list_free(recs, (sdp_free_func_t) sdp_record_free);

	if (connection_register(pr->path, &pr->src, &pr->dst, pr->id, name,
				desc) < 0) {
		error_failed(pr->conn, pr->msg, "D-Bus path registration failed");
		goto fail;
	}

	connection_store(pr->path, FALSE);
	connection_paths = g_slist_append(connection_paths, g_strdup(pr->path));

	create_path(pr->conn, pr->msg, pr->path, "ConnectionCreated");

fail:
	g_free(desc);
	pending_reply_free(pr);
}

static DBusMessage *list_servers(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return list_paths(conn, msg, server_paths);
}

static DBusMessage *find_server(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *pattern;
	const char *path;
	GSList *list;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pattern,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	for (list = server_paths; list; list = list->next) {
		path = (const char *) list->data;
		if (server_find_data(path, pattern) == 0)
			break;
	}

	if (list == NULL)
		return does_not_exist(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_STRING, &path,
							DBUS_TYPE_INVALID);
}

static DBusMessage *list_connections(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return list_paths(conn, msg, connection_paths);
}

static GSList *find_connection_pattern(DBusConnection *conn,
						const char *pattern)
{
	const char *path;
	GSList *list;

	if (pattern == NULL)
		return NULL;

	for (list = connection_paths; list; list = list->next) {
		path = (const char *) list->data;
		if (connection_find_data(path, pattern) == 0)
			break;
	}

	return list;
}

static DBusMessage *find_connection(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *pattern;
	const char *path;
	GSList *list;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pattern,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	list = find_connection_pattern(conn, pattern);
	if (list == NULL)
		return does_not_exist(msg);

	path = list->data;

	return g_dbus_create_reply(msg, DBUS_TYPE_STRING, &path,
							DBUS_TYPE_INVALID);
}

static DBusMessage *create_connection(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct pending_reply *pr;
	const char *addr;
	const char *str;
	bdaddr_t src;
	uint16_t id;
	int dev_id, err;
	char key[32];
	GSList *l;
	uuid_t uuid;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &addr,
			DBUS_TYPE_STRING, &str, DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	id = bnep_service_id(str);
	if (id != BNEP_SVC_GN && id != BNEP_SVC_NAP && id != BNEP_SVC_PANU)
		return not_supported(msg);

	snprintf(key, 32, "%s#%s", addr, bnep_name(id));

	/* Checks if the connection was already been made */
	for (l = connection_paths; l; l = l->next) {
		if (connection_find_data(l->data, key) == 0)
			return already_exists(msg);
	}

	bacpy(&src, BDADDR_ANY);
	dev_id = hci_get_route(&src);
	if (dev_id < 0 || hci_devba(dev_id, &src) < 0)
		return adapter_not_available(msg);

	pr = g_new0(struct pending_reply, 1);

	/* FIXME just to maintain compatibility */
	pr->adapter_path = g_strdup_printf("/org/bluez/hci%d", dev_id);
	if (!pr->adapter_path) {
		pending_reply_free (pr);
		return adapter_not_available(msg);
	}

	pr->conn = dbus_connection_ref(conn);
	pr->msg = dbus_message_ref(msg);
	bacpy(&pr->src, &src);
	str2ba(addr, &pr->dst);
	pr->addr = g_strdup(addr);
	pr->id = id;
	pr->path = g_new0(char, MAX_PATH_LENGTH);
	snprintf(pr->path, MAX_PATH_LENGTH,
				NETWORK_PATH "/connection%d", net_uid++);

	sdp_uuid16_create(&uuid, pr->id);
	err = bt_search_service(&pr->src, &pr->dst, &uuid, records_cb, pr,
				NULL);
	if (err < 0) {
		pending_reply_free(pr);
		return not_supported(msg);
	}

	return NULL;
}

static DBusMessage *remove_connection(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return remove_path(conn, msg, &connection_paths, "ConnectionRemoved");
}

static DBusMessage *last_connection(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *path;

	if (connection_paths == NULL ||
				g_slist_length(connection_paths) == 0)
		return does_not_exist(msg);

	path = last_connection_used(conn);

	return g_dbus_create_reply(msg, DBUS_TYPE_STRING, &path,
							DBUS_TYPE_INVALID);
}

static DBusMessage *default_connection(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *path;

	if (connection_paths == NULL ||
				g_slist_length (connection_paths) == 0)
		return does_not_exist(msg);

	path = g_slist_nth_data (connection_paths, default_index);

	if (path == NULL) {
		path = last_connection_used(conn);
		connection_store(path, TRUE);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_STRING, &path,
							DBUS_TYPE_INVALID);
}

static DBusMessage *change_default_connection(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *path;
	const char *pattern;
	GSList *list;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pattern,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	if (connection_paths == NULL ||
				g_slist_length(connection_paths) == 0)
		return does_not_exist(msg);

	list = g_slist_find_custom(connection_paths, pattern,
						(GCompareFunc) strcmp);

	/* Find object path via pattern */
	if (list == NULL) {
		list = find_connection_pattern(conn, pattern);
		if (list == NULL)
			return does_not_exist(msg);

		path = list->data;
	} else
		path = list->data;

	default_index = g_slist_position(connection_paths, list);
	connection_store(path, TRUE);

	g_dbus_emit_signal(connection, NETWORK_PATH,
					NETWORK_MANAGER_INTERFACE,
					"DefaultConnectionChanged",
					DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID);

	return g_dbus_create_reply(msg, DBUS_TYPE_STRING, &path,
							DBUS_TYPE_INVALID);
}

static void manager_unregister(void *data)
{
	info("Unregistered manager path");

	if (server_paths) {
		g_slist_foreach(server_paths, (GFunc) g_free, NULL);
		g_slist_free(server_paths);
		server_paths = NULL;
	}

	if (connection_paths) {
		g_slist_foreach(connection_paths, (GFunc) g_free, NULL);
		g_slist_free(connection_paths);
		connection_paths = NULL;
	}

	bnep_kill_all_connections();
}

static void parse_stored_connection(char *key, char *value, void *data)
{
	bdaddr_t dst, *src = data;
	char path[MAX_PATH_LENGTH];
	char addr[18];
	const char *ptr;
	char *name;
	int len, id;

	/* Format: XX:XX:XX:XX:XX:XX#{NAP, GN} name:description */

	/* Parsing the key: address#role */
	ptr = strchr(key, '#');

	/* Empty address or invalid len */
	if (!ptr || ((ptr - key) != 17))
		return;

	memset(addr, 0, 18);
	strncpy(addr, key, 17);
	str2ba(addr, &dst);

	/* Empty role */
	if (++ptr == NULL)
		return;

	if (strcasecmp("nap", ptr) == 0)
		id = BNEP_SVC_NAP;
	else if (strcasecmp("gn", ptr) == 0)
		id = BNEP_SVC_GN;
	else if (strcasecmp("panu", ptr) == 0)
		id = BNEP_SVC_PANU;
	else
		return;

	snprintf(path, MAX_PATH_LENGTH,
				NETWORK_PATH "/connection%d", net_uid++);

	/* Parsing the value: name and description */
	ptr = strchr(value, ':');

	/* Empty name */
	if (!ptr)
		return;

	len = ptr-value;
	name = g_malloc0(len + 1);
	strncpy(name, value, len);

	/* Empty description */
	if (++ptr == NULL) {
		g_free(name);
		return;
	}

	if (connection_register(path, src, &dst, id, name, ptr) == 0) {
		char *rpath = g_strdup(path);
		connection_paths = g_slist_append(connection_paths, rpath);
	}

	g_free(name);
}

static void register_connections_stored(const char *adapter)
{
	char filename[PATH_MAX + 1];
	char *pattern;
	struct stat st;
	GSList *list;
	bdaddr_t src;
	bdaddr_t default_src;
	int dev_id;

	create_name(filename, PATH_MAX, STORAGEDIR, adapter, "network");

	str2ba(adapter, &src);

	if (stat(filename, &st) < 0)
		return;

	if (!(st.st_mode & __S_IFREG))
		return;

	textfile_foreach(filename, parse_stored_connection, &src);

	/* Check default connection for current default adapter */
	bacpy(&default_src, BDADDR_ANY);
	dev_id = hci_get_route(&default_src);
	if (dev_id < 0 || hci_devba(dev_id, &default_src) < 0)
		return;

	if (bacmp(&default_src, &src) != 0)
		return;

	pattern = textfile_get(filename, "default");
	if (!pattern)
		return;

	list = find_connection_pattern(connection, pattern);
	if (!list)
		return;
	default_index = g_slist_position(connection_paths, list);
}

static void register_server(uint16_t id)
{
	char path[MAX_PATH_LENGTH];
	bdaddr_t src;
	int dev_id;

	if (!conf->server_enabled)
		return;

	snprintf(path, MAX_PATH_LENGTH, NETWORK_PATH "/%s", bnep_name(id));

	if (g_slist_find_custom(server_paths, path,
				(GCompareFunc) strcmp))
		return;

	bacpy(&src, BDADDR_ANY);
	dev_id = hci_get_route(&src);
	if (dev_id < 0 || hci_devba(dev_id, &src))
		return;

	if (server_register(path, &src, id) < 0)
		return;

	server_store(path);

	server_paths = g_slist_append(server_paths, g_strdup(path));
}

static void register_servers_stored(const char *adapter, const char *profile)
{
	char filename[PATH_MAX + 1];
	char path[MAX_PATH_LENGTH];
	uint16_t id;
	struct stat s;
	bdaddr_t src;

	if (strcmp(profile, "nap") == 0)
		id = BNEP_SVC_NAP;
	else if (strcmp(profile, "gn") == 0)
		id = BNEP_SVC_GN;
	else
		id = BNEP_SVC_PANU;

	create_name(filename, PATH_MAX, STORAGEDIR, adapter, profile);

	str2ba(adapter, &src);

	if (stat (filename, &s) == 0 && (s.st_mode & __S_IFREG)) {
		snprintf(path, MAX_PATH_LENGTH, NETWORK_PATH "/%s", profile);
		if (server_register_from_file(path, &src, id, filename) == 0) {
			server_paths = g_slist_append(server_paths,
						g_strdup(path));
		}
	}
}

static void register_stored(void)
{
	char dirname[PATH_MAX + 1];
	struct dirent *de;
	DIR *dir;

	snprintf(dirname, PATH_MAX, "%s", STORAGEDIR);

	dir = opendir(dirname);
	if (!dir)
		return;

	while ((de = readdir(dir)) != NULL) {
		if (!isdigit(de->d_name[0]))
			continue;

		/* Connection objects */
		if (conf->connection_enabled)
			register_connections_stored(de->d_name);

		/* Server objects */
		if (conf->server_enabled) {
			/* NAP objects */
			register_servers_stored(de->d_name, "nap");

			/* GN objects */
			register_servers_stored(de->d_name, "gn");

			/* PANU objects */
			register_servers_stored(de->d_name, "panu");
		}
	}

	closedir(dir);
}

static GDBusMethodTable connection_methods[] = {
	{ "ListConnections",	"",	"as",	list_connections	},
	{ "FindConnection",	"s",	"s",	find_connection		},
	{ "CreateConnection",	"ss",	"s",	create_connection,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "RemoveConnection",	"s",	"",	remove_connection	},
	{ "LastConnection",	"",	"s",	last_connection		},
	{ "DefaultConnection",	"",	"s",	default_connection	},
	{ "ChangeDefaultConnection", "s", "s", change_default_connection },
	{ }
};

static GDBusSignalTable connection_signals[] = {
	{ "ConnectionCreated",		"s"	},
	{ "ConnectionRemoved",		"s"	},
	{ "DefaultConnectionChanged",	"s"	},
	{ }
};

static GDBusMethodTable server_methods[] = {
	{ "ListServers",	"",	"as",	list_servers	},
	{ "FindServer",		"s",	"s",	find_server	},
	{ }
};

static GDBusMethodTable manager_methods[] = {
	{ "ListServers",	"",	"as",	list_servers	},
	{ "FindServer",		"s",	"s",	find_server	},
	{ "ListConnections",	"",	"as",	list_connections	},
	{ "FindConnection",	"s",	"s",	find_connection		},
	{ "CreateConnection",	"ss",	"s",	create_connection,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "RemoveConnection",	"s",	"",	remove_connection	},
	{ "LastConnection",	"",	"s",	last_connection		},
	{ "DefaultConnection",	"",	"s",	default_connection	},
	{ "ChangeDefaultConnection", "s", "s", change_default_connection },
	{ }
};

int network_manager_init(DBusConnection *conn, struct network_conf *service_conf)
{
	GDBusMethodTable *methods = NULL;
	GDBusSignalTable *signals = NULL;

	conf = service_conf;

	if (conf->server_enabled && conf->connection_enabled) {
		methods = manager_methods;
		signals = connection_signals;
	} else if (conf->connection_enabled) {
		methods = connection_methods;
		signals = connection_signals;
	} else if (conf->server_enabled)
		methods = server_methods;
	else {
		error ("All interfaces were disabled");
		return -1;
	}

	if (bnep_init(conf->panu_script, conf->gn_script, conf->nap_script)) {
		error("Can't init bnep module");
		return -1;
	}

	/*
	 * There is one socket to handle the incomming connections. NAP,
	 * GN and PANU servers share the same PSM. The initial BNEP message
	 * (setup connection request) contains the destination service
	 * field that defines which service the source is connecting to.
	 */
	if (conf->server_enabled) {
		if (bridge_init(conf->gn_iface, conf->nap_iface) < 0) {
			error("Can't init bridge module");
			return -1;
		}

		if (server_init(conn, conf->iface_prefix, conf->security) < 0)
			return -1;
	}

	if (conf->connection_enabled) {
		if (connection_init(conn, conf->iface_prefix) < 0)
			return -1;
	}

	if (g_dbus_register_interface(conn, NETWORK_PATH,
					NETWORK_MANAGER_INTERFACE,
					methods, signals, NULL,
					NULL, manager_unregister) == FALSE) {
		error("Failed to register %s interface to %s",
				NETWORK_MANAGER_INTERFACE, NETWORK_PATH);
		return -1;
	}

	connection = dbus_connection_ref(conn);

	info("Registered manager path:%s", NETWORK_PATH);

	register_stored();

	/* Register PANU, GN and NAP servers if they don't exist */
	register_server(BNEP_SVC_PANU);
	register_server(BNEP_SVC_GN);
	register_server(BNEP_SVC_NAP);

	return 0;
}

void network_manager_exit(void)
{
	if (conf->server_enabled)
		server_exit();

	if (conf->connection_enabled)
		connection_exit();

	g_dbus_unregister_interface(connection, NETWORK_PATH,
						NETWORK_MANAGER_INTERFACE);

	dbus_connection_unref(connection);
	connection = NULL;

	bnep_cleanup();
	bridge_cleanup();
}

static inline int create_filename(char *buf, size_t size,
					bdaddr_t *bdaddr, const char *name)
{
	char addr[18];

	ba2str(bdaddr, addr);

	return create_name(buf, size, STORAGEDIR, addr, name);
}
