/*
 *
 *  D-Bus helper library
 *
 *  Copyright (C) 2004-2011  Marcel Holtmann <marcel@holtmann.org>
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

#include <glib.h>
#include <dbus/dbus.h>

#include "gdbus.h"

#define METHOD_CALL_TIMEOUT (300 * 1000)

struct GDBusClient {
	gint ref_count;
	DBusConnection *dbus_conn;
	char *service_name;
	char *unique_name;
	char *base_path;
	GPtrArray *match_rules;
	DBusPendingCall *pending_call;
	GDBusWatchFunction connect_func;
	void *connect_data;
	GDBusWatchFunction disconn_func;
	void *disconn_data;
	GDBusMessageFunction signal_func;
	void *signal_data;
	GDBusProxyFunction proxy_added;
	GDBusProxyFunction proxy_removed;
	GDBusPropertyFunction property_changed;
	void *user_data;
	GList *proxy_list;
};

struct GDBusProxy {
	gint ref_count;
	GDBusClient *client;
	char *obj_path;
	char *interface;
	GHashTable *prop_list;
	char *match_rule;
};

struct prop_entry {
	char *name;
	int type;
	DBusMessage *msg;
};

static void modify_match_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply) == TRUE)
		dbus_error_free(&error);

	dbus_message_unref(reply);
}

static gboolean modify_match(DBusConnection *conn, const char *member,
							const char *rule)
{
	DBusMessage *msg;
	DBusPendingCall *call;

	msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
					DBUS_INTERFACE_DBUS, member);
	if (msg == NULL)
		return FALSE;

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &rule,
						DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(conn, msg, &call, -1) == FALSE) {
		dbus_message_unref(msg);
		return FALSE;
	}

	dbus_pending_call_set_notify(call, modify_match_reply, NULL, NULL);
	dbus_pending_call_unref(call);

	dbus_message_unref(msg);

	return TRUE;
}

static void iter_append_iter(DBusMessageIter *base, DBusMessageIter *iter)
{
	int type;

	type = dbus_message_iter_get_arg_type(iter);

	if (dbus_type_is_basic(type)) {
		const void *value;

		dbus_message_iter_get_basic(iter, &value);
		dbus_message_iter_append_basic(base, type, &value);
	} else if (dbus_type_is_container(type)) {
		DBusMessageIter iter_sub, base_sub;
		char *sig;

		dbus_message_iter_recurse(iter, &iter_sub);

		switch (type) {
		case DBUS_TYPE_ARRAY:
		case DBUS_TYPE_VARIANT:
			sig = dbus_message_iter_get_signature(&iter_sub);
			break;
		default:
			sig = NULL;
			break;
		}

		dbus_message_iter_open_container(base, type, sig, &base_sub);

		if (sig != NULL)
			dbus_free(sig);

		while (dbus_message_iter_get_arg_type(&iter_sub) !=
							DBUS_TYPE_INVALID) {
			iter_append_iter(&base_sub, &iter_sub);
			dbus_message_iter_next(&iter_sub);
		}

		dbus_message_iter_close_container(base, &base_sub);
	}
}

static void prop_entry_update(struct prop_entry *prop, DBusMessageIter *iter)
{
	DBusMessage *msg;
	DBusMessageIter base;

	msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
	if (msg == NULL)
		return;

	dbus_message_iter_init_append(msg, &base);
	iter_append_iter(&base, iter);

	if (prop->msg != NULL)
		dbus_message_unref(prop->msg);

	prop->msg = dbus_message_copy(msg);
	dbus_message_unref(msg);
}

static struct prop_entry *prop_entry_new(const char *name,
						DBusMessageIter *iter)
{
	struct prop_entry *prop;

	prop = g_try_new0(struct prop_entry, 1);
	if (prop == NULL)
		return NULL;

	prop->name = g_strdup(name);
	prop->type = dbus_message_iter_get_arg_type(iter);

	prop_entry_update(prop, iter);

	return prop;
}

static void prop_entry_free(gpointer data)
{
	struct prop_entry *prop = data;

	if (prop->msg != NULL)
		dbus_message_unref(prop->msg);

	g_free(prop->name);

	g_free(prop);
}

static GDBusProxy *proxy_lookup(GDBusClient *client, const char *path,
						const char *interface)
{
	GList *list;

	for (list = g_list_first(client->proxy_list); list;
						list = g_list_next(list)) {
		GDBusProxy *proxy = list->data;

		if (g_str_equal(proxy->interface, interface) == TRUE &&
				g_str_equal(proxy->obj_path, path) == TRUE)
			return proxy;
        }

	return NULL;
}

static GDBusProxy *proxy_new(GDBusClient *client, const char *path,
						const char *interface)
{
	GDBusProxy *proxy;

	proxy = g_try_new0(GDBusProxy, 1);
	if (proxy == NULL)
		return NULL;

	proxy->client = client;
	proxy->obj_path = g_strdup(path);
	proxy->interface = g_strdup(interface);

	proxy->prop_list = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, prop_entry_free);

	proxy->match_rule = g_strdup_printf("type='signal',"
				"sender='%s',path='%s',interface='%s',"
				"member='PropertiesChanged',arg0='%s'",
				client->service_name, proxy->obj_path,
				DBUS_INTERFACE_PROPERTIES, proxy->interface);

	modify_match(client->dbus_conn, "AddMatch", proxy->match_rule);

	return g_dbus_proxy_ref(proxy);
}

static void proxy_free(gpointer data)
{
	GDBusProxy *proxy = data;

	if (proxy->client) {
		GDBusClient *client = proxy->client;

		if (client->proxy_removed)
			client->proxy_removed(proxy, client->user_data);

		modify_match(client->dbus_conn, "RemoveMatch",
							proxy->match_rule);

		g_free(proxy->match_rule);
		proxy->match_rule = NULL;

		g_hash_table_remove_all(proxy->prop_list);

		proxy->client = NULL;
	}

	g_dbus_proxy_unref(proxy);
}

static void proxy_remove(GDBusClient *client, const char *path,
						const char *interface)
{
	GList *list;

	for (list = g_list_first(client->proxy_list); list;
						list = g_list_next(list)) {
		GDBusProxy *proxy = list->data;

		if (g_str_equal(proxy->interface, interface) == TRUE &&
				g_str_equal(proxy->obj_path, path) == TRUE) {
			client->proxy_list =
				g_list_delete_link(client->proxy_list, list);
			proxy_free(proxy);
			break;
		}
	}
}

GDBusProxy *g_dbus_proxy_ref(GDBusProxy *proxy)
{
	if (proxy == NULL)
		return NULL;

	g_atomic_int_inc(&proxy->ref_count);

	return proxy;
}

void g_dbus_proxy_unref(GDBusProxy *proxy)
{
	if (proxy == NULL)
		return;

	if (g_atomic_int_dec_and_test(&proxy->ref_count) == FALSE)
		return;

	g_hash_table_destroy(proxy->prop_list);

	g_free(proxy->obj_path);
	g_free(proxy->interface);

	g_free(proxy);
}

const char *g_dbus_proxy_get_path(GDBusProxy *proxy)
{
	if (proxy == NULL)
		return NULL;

	return proxy->obj_path;
}

const char *g_dbus_proxy_get_interface(GDBusProxy *proxy)
{
	if (proxy == NULL)
		return NULL;

	return proxy->interface;
}

gboolean g_dbus_proxy_get_property(GDBusProxy *proxy, const char *name,
                                                        DBusMessageIter *iter)
{
	struct prop_entry *prop;

	if (proxy == NULL || name == NULL)
		return FALSE;

	prop = g_hash_table_lookup(proxy->prop_list, name);
	if (prop == NULL)
		return FALSE;

	if (prop->msg == NULL)
		return FALSE;

	if (dbus_message_iter_init(prop->msg, iter) == FALSE)
		return FALSE;

	return TRUE;
}

struct set_property_data {
	GDBusResultFunction function;
	void *user_data;
	GDBusDestroyFunction destroy;
};

static void set_property_reply(DBusPendingCall *call, void *user_data)
{
	struct set_property_data *data = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError error;

	dbus_error_init(&error);

	dbus_set_error_from_message(&error, reply);

	if (data->function)
		data->function(&error, data->user_data);

	if (data->destroy)
		data->destroy(data->user_data);

	dbus_error_free(&error);

	dbus_message_unref(reply);
}

gboolean g_dbus_proxy_set_property_basic(GDBusProxy *proxy,
				const char *name, int type, const void *value,
				GDBusResultFunction function, void *user_data,
				GDBusDestroyFunction destroy)
{
	struct set_property_data *data;
	GDBusClient *client;
	DBusMessage *msg;
	DBusMessageIter iter, variant;
	DBusPendingCall *call;
	char type_as_str[2];

	if (proxy == NULL || name == NULL || value == NULL)
		return FALSE;

	if (dbus_type_is_basic(type) == FALSE)
		return FALSE;

	client = proxy->client;
	if (client == NULL)
		return FALSE;

	data = g_try_new0(struct set_property_data, 1);
	if (data == NULL)
		return FALSE;

	data->function = function;
	data->user_data = user_data;
	data->destroy = destroy;

	msg = dbus_message_new_method_call(client->service_name,
			proxy->obj_path, DBUS_INTERFACE_PROPERTIES, "Set");
	if (msg == NULL) {
		g_free(data);
		return FALSE;
	}

	type_as_str[0] = (char) type;
	type_as_str[1] = '\0';

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING,
							&proxy->interface);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &name);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
						type_as_str, &variant);
	dbus_message_iter_append_basic(&variant, type, value);
	dbus_message_iter_close_container(&iter, &variant);

	if (dbus_connection_send_with_reply(client->dbus_conn, msg,
							&call, -1) == FALSE) {
		dbus_message_unref(msg);
		g_free(data);
		return FALSE;
	}

	dbus_pending_call_set_notify(call, set_property_reply, data, g_free);
	dbus_pending_call_unref(call);

	dbus_message_unref(msg);

	return TRUE;
}

struct method_call_data {
	GDBusReturnFunction function;
	void *user_data;
	GDBusDestroyFunction destroy;
};

static void method_call_reply(DBusPendingCall *call, void *user_data)
{
	struct method_call_data *data = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);

	if (data->function)
		data->function(reply, data->user_data);

	if (data->destroy)
		data->destroy(data->user_data);

	dbus_message_unref(reply);
}

gboolean g_dbus_proxy_method_call(GDBusProxy *proxy, const char *method,
				GDBusSetupFunction setup,
				GDBusReturnFunction function, void *user_data,
				GDBusDestroyFunction destroy)
{
	struct method_call_data *data;
	GDBusClient *client;
	DBusMessage *msg;
	DBusPendingCall *call;

	if (proxy == NULL || method == NULL)
		return FALSE;

	client = proxy->client;
	if (client == NULL)
		return FALSE;

	data = g_try_new0(struct method_call_data, 1);
	if (data == NULL)
		return FALSE;

	data->function = function;
	data->user_data = user_data;
	data->destroy = destroy;

	msg = dbus_message_new_method_call(client->service_name,
				proxy->obj_path, proxy->interface, method);
	if (msg == NULL) {
		g_free(data);
		return FALSE;
	}

	if (setup) {
		DBusMessageIter iter;

		dbus_message_iter_init_append(msg, &iter);
		setup(&iter, data->user_data);
	}

	if (dbus_connection_send_with_reply(client->dbus_conn, msg,
					&call, METHOD_CALL_TIMEOUT) == FALSE) {
		dbus_message_unref(msg);
		g_free(data);
		return FALSE;
	}

	dbus_pending_call_set_notify(call, method_call_reply, data, g_free);
	dbus_pending_call_unref(call);

	dbus_message_unref(msg);

	return TRUE;
}

static void add_property(GDBusProxy *proxy, const char *name,
						DBusMessageIter *iter)
{
	DBusMessageIter value;
	struct prop_entry *prop;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_VARIANT)
		return;

	dbus_message_iter_recurse(iter, &value);

	prop = g_hash_table_lookup(proxy->prop_list, name);
	if (prop != NULL) {
		GDBusClient *client = proxy->client;

		prop_entry_update(prop, &value);

		if (client == NULL)
			return;

		if (client->property_changed)
			client->property_changed(proxy, name, &value,
							client->user_data);
		return;
	}

	prop = prop_entry_new(name, &value);
	if (prop == NULL)
		return;

	g_hash_table_replace(proxy->prop_list, prop->name, prop);
}

static void update_properties(GDBusProxy *proxy, DBusMessageIter *iter)
{
	DBusMessageIter dict;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;
		const char *name;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&entry, &name);
		dbus_message_iter_next(&entry);

		add_property(proxy, name, &entry);

		dbus_message_iter_next(&dict);
	}
}

static void properties_changed(GDBusClient *client, const char *path,
							DBusMessage *msg)
{
	GDBusProxy *proxy = NULL;
	DBusMessageIter iter, entry;
	const char *interface;
	GList *list;

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return;

	dbus_message_iter_get_basic(&iter, &interface);
	dbus_message_iter_next(&iter);

	for (list = g_list_first(client->proxy_list); list;
						list = g_list_next(list)) {
		GDBusProxy *data = list->data;

		if (g_str_equal(data->interface, interface) == TRUE &&
				g_str_equal(data->obj_path, path) == TRUE) {
			proxy = data;
			break;
		}
	}

	if (proxy == NULL)
		return;

	update_properties(proxy, &iter);

	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(&iter, &entry);

	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
		const char *name;

		dbus_message_iter_get_basic(&entry, &name);

		g_hash_table_remove(proxy->prop_list, name);

		if (client->property_changed)
			client->property_changed(proxy, name, NULL,
							client->user_data);

		dbus_message_iter_next(&entry);
	}
}

static void parse_properties(GDBusClient *client, const char *path,
				const char *interface, DBusMessageIter *iter)
{
	GDBusProxy *proxy;

	if (g_str_equal(interface, DBUS_INTERFACE_INTROSPECTABLE) == TRUE)
		return;

	if (g_str_equal(interface, DBUS_INTERFACE_PROPERTIES) == TRUE)
		return;

	proxy = proxy_lookup(client, path, interface);
	if (proxy) {
		update_properties(proxy, iter);
		return;
	}

	proxy = proxy_new(client, path, interface);
	if (proxy == NULL)
		return;

	update_properties(proxy, iter);

	if (client->proxy_added)
		client->proxy_added(proxy, client->user_data);

	client->proxy_list = g_list_append(client->proxy_list, proxy);
}

static void parse_interfaces(GDBusClient *client, const char *path,
						DBusMessageIter *iter)
{
	DBusMessageIter dict;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;
		const char *interface;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&entry, &interface);
		dbus_message_iter_next(&entry);

		parse_properties(client, path, interface, &entry);

		dbus_message_iter_next(&dict);
	}
}

static void interfaces_added(GDBusClient *client, DBusMessage *msg)
{
	DBusMessageIter iter;
	const char *path;

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return;

	dbus_message_iter_get_basic(&iter, &path);
	dbus_message_iter_next(&iter);

	g_dbus_client_ref(client);

	parse_interfaces(client, path, &iter);

	g_dbus_client_unref(client);
}

static void interfaces_removed(GDBusClient *client, DBusMessage *msg)
{
	DBusMessageIter iter, entry;
	const char *path;

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return;

	dbus_message_iter_get_basic(&iter, &path);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(&iter, &entry);

	g_dbus_client_ref(client);

	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
		const char *interface;

		dbus_message_iter_get_basic(&entry, &interface);
		proxy_remove(client, path, interface);
		dbus_message_iter_next(&entry);
	}

	g_dbus_client_unref(client);
}

static void parse_managed_objects(GDBusClient *client, DBusMessage *msg)
{
	DBusMessageIter iter, dict;

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;
		const char *path;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) !=
							DBUS_TYPE_OBJECT_PATH)
			break;

		dbus_message_iter_get_basic(&entry, &path);
		dbus_message_iter_next(&entry);

		parse_interfaces(client, path, &entry);

		dbus_message_iter_next(&dict);
	}
}

static void get_managed_objects_reply(DBusPendingCall *call, void *user_data)
{
	GDBusClient *client = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply) == TRUE) {
		dbus_error_free(&error);
		goto done;
	}

	parse_managed_objects(client, reply);

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(client->pending_call);
	client->pending_call = NULL;

	g_dbus_client_unref(client);
}

static void get_managed_objects(GDBusClient *client)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call("org.bluez", "/",
					DBUS_INTERFACE_DBUS ".ObjectManager",
							"GetManagedObjects");
	if (msg == NULL)
		return;

	dbus_message_append_args(msg, DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(client->dbus_conn, msg,
					&client->pending_call, -1) == FALSE) {
		dbus_message_unref(msg);
		return;
	}

	g_dbus_client_ref(client);

	dbus_pending_call_set_notify(client->pending_call,
				get_managed_objects_reply, client, NULL);

	dbus_message_unref(msg);
}

static void get_name_owner_reply(DBusPendingCall *call, void *user_data)
{
	GDBusClient *client = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError error;
	const char *name;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply) == TRUE) {
		dbus_error_free(&error);
		goto done;
	}

	if (dbus_message_get_args(reply, NULL, DBUS_TYPE_STRING, &name,
						DBUS_TYPE_INVALID) == FALSE)
		goto done;

	g_free(client->unique_name);
	client->unique_name = g_strdup(name);

	g_dbus_client_ref(client);

	if (client->connect_func)
		client->connect_func(client->dbus_conn, client->connect_data);

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(client->pending_call);
	client->pending_call = NULL;

	get_managed_objects(client);

	g_dbus_client_unref(client);
}

static void get_name_owner(GDBusClient *client, const char *name)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
					DBUS_INTERFACE_DBUS, "GetNameOwner");
	if (msg == NULL)
		return;

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &name,
						DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(client->dbus_conn, msg,
					&client->pending_call, -1) == FALSE) {
		dbus_message_unref(msg);
		return;
	}

	dbus_pending_call_set_notify(client->pending_call,
					get_name_owner_reply, client, NULL);

	dbus_message_unref(msg);
}

static DBusHandlerResult message_filter(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	GDBusClient *client = user_data;
	const char *sender;

	if (dbus_message_get_type(message) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	sender = dbus_message_get_sender(message);

	if (g_str_equal(sender, DBUS_SERVICE_DBUS) == TRUE) {
		const char *interface, *member;
		const char *name, *old, *new;

		interface = dbus_message_get_interface(message);

		if (g_str_equal(interface, DBUS_INTERFACE_DBUS) == FALSE)
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

		member = dbus_message_get_member(message);

		if (g_str_equal(member, "NameOwnerChanged") == FALSE)
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

		if (dbus_message_get_args(message, NULL,
						DBUS_TYPE_STRING, &name,
						DBUS_TYPE_STRING, &old,
						DBUS_TYPE_STRING, &new,
						DBUS_TYPE_INVALID) == FALSE)
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

		if (g_str_equal(name, client->service_name) == FALSE)
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

		if (*new == '\0') {
			if (client->disconn_func)
				client->disconn_func(client->dbus_conn,
							client->disconn_data);

			g_free(client->unique_name);
			client->unique_name = NULL;
		} else if (*old == '\0') {
			g_free(client->unique_name);
			client->unique_name = g_strdup(new);

			if (client->connect_func)
				client->connect_func(client->dbus_conn,
							client->connect_data);

			get_managed_objects(client);
		}

		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (client->unique_name == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (g_str_equal(sender, client->unique_name) == TRUE) {
		const char *path, *interface, *member;

		path = dbus_message_get_path(message);
		interface = dbus_message_get_interface(message);
		member = dbus_message_get_member(message);

		if (g_str_equal(path, "/") == TRUE) {
			if (g_str_equal(interface, DBUS_INTERFACE_DBUS
						".ObjectManager") == FALSE)
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

			if (g_str_equal(member, "InterfacesAdded") == TRUE) {
				interfaces_added(client, message);
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}

			if (g_str_equal(member, "InterfacesRemoved") == TRUE) {
				interfaces_removed(client, message);
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}

			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		if (g_str_has_prefix(path, client->base_path) == FALSE)
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

		if (g_str_equal(interface, DBUS_INTERFACE_PROPERTIES) == TRUE) {
			if (g_str_equal(member, "PropertiesChanged") == TRUE)
				properties_changed(client, path, message);

			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		if (client->signal_func)
			client->signal_func(client->dbus_conn,
					message, client->signal_data);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

GDBusClient *g_dbus_client_new(DBusConnection *connection,
					const char *service, const char *path)
{
	GDBusClient *client;
	unsigned int i;

	if (connection == NULL)
		return NULL;

	client = g_try_new0(GDBusClient, 1);
	if (client == NULL)
		return NULL;

	if (dbus_connection_add_filter(connection, message_filter,
						client, NULL) == FALSE) {
		g_free(client);
		return NULL;
	}

	client->dbus_conn = dbus_connection_ref(connection);
	client->service_name = g_strdup(service);
	client->base_path = g_strdup(path);

	get_name_owner(client, client->service_name);

	client->match_rules = g_ptr_array_new_full(4, g_free);

	g_ptr_array_add(client->match_rules, g_strdup_printf("type='signal',"
				"sender='%s',path='%s',interface='%s',"
				"member='NameOwnerChanged',arg0='%s'",
				DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
				DBUS_INTERFACE_DBUS, client->service_name));
	g_ptr_array_add(client->match_rules, g_strdup_printf("type='signal',"
				"sender='%s',"
				"path='/',interface='%s.ObjectManager',"
				"member='InterfacesAdded'",
				client->service_name, DBUS_INTERFACE_DBUS));
	g_ptr_array_add(client->match_rules, g_strdup_printf("type='signal',"
				"sender='%s',"
				"path='/',interface='%s.ObjectManager',"
				"member='InterfacesRemoved'",
				client->service_name, DBUS_INTERFACE_DBUS));
	g_ptr_array_add(client->match_rules, g_strdup_printf("type='signal',"
				"sender='%s',path_namespace='%s'",
				client->service_name, client->base_path));

	for (i = 0; i < client->match_rules->len; i++) {
		modify_match(client->dbus_conn, "AddMatch",
				g_ptr_array_index(client->match_rules, i));
	}

	return g_dbus_client_ref(client);
}

GDBusClient *g_dbus_client_ref(GDBusClient *client)
{
	if (client == NULL)
		return NULL;

	g_atomic_int_inc(&client->ref_count);

	return client;
}

void g_dbus_client_unref(GDBusClient *client)
{
	unsigned int i;

	if (client == NULL)
		return;

	if (g_atomic_int_dec_and_test(&client->ref_count) == FALSE)
		return;

	if (client->pending_call != NULL) {
		dbus_pending_call_cancel(client->pending_call);
		dbus_pending_call_unref(client->pending_call);
	}

	for (i = 0; i < client->match_rules->len; i++) {
		modify_match(client->dbus_conn, "RemoveMatch",
				g_ptr_array_index(client->match_rules, i));
	}

	g_ptr_array_free(client->match_rules, TRUE);

	dbus_connection_remove_filter(client->dbus_conn,
						message_filter, client);

	g_list_free_full(client->proxy_list, proxy_free);

	if (client->disconn_func)
		client->disconn_func(client->dbus_conn, client->disconn_data);

	dbus_connection_unref(client->dbus_conn);

	g_free(client->service_name);
	g_free(client->unique_name);
	g_free(client->base_path);

	g_free(client);
}

gboolean g_dbus_client_set_connect_watch(GDBusClient *client,
				GDBusWatchFunction function, void *user_data)
{
	if (client == NULL)
		return FALSE;

	client->connect_func = function;
	client->connect_data = user_data;

	return TRUE;
}

gboolean g_dbus_client_set_disconnect_watch(GDBusClient *client,
				GDBusWatchFunction function, void *user_data)
{
	if (client == NULL)
		return FALSE;

	client->disconn_func = function;
	client->disconn_data = user_data;

	return TRUE;
}

gboolean g_dbus_client_set_signal_watch(GDBusClient *client,
				GDBusMessageFunction function, void *user_data)
{
	if (client == NULL)
		return FALSE;

	client->signal_func = function;
	client->signal_data = user_data;

	return TRUE;
}

gboolean g_dbus_client_set_proxy_handlers(GDBusClient *client,
					GDBusProxyFunction proxy_added,
					GDBusProxyFunction proxy_removed,
					GDBusPropertyFunction property_changed,
					void *user_data)
{
	if (client == NULL)
		return FALSE;

	client->proxy_added = proxy_added;
	client->proxy_removed = proxy_removed;
	client->property_changed = property_changed;
	client->user_data = user_data;

	return TRUE;
}
