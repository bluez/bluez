/*
 *
 *  D-Bus helper library
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdio.h>
#include <string.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "gdbus.h"

#define info(fmt...)
#define error(fmt...)
#define debug(fmt...)

struct generic_data {
	unsigned int refcount;
	GSList *interfaces;
	char *introspect;
};

struct interface_data {
	char *name;
	const GDBusMethodTable *methods;
	const GDBusSignalTable *signals;
	const GDBusPropertyTable *properties;
	void *user_data;
	GDBusDestroyFunction destroy;
};

static void print_arguments(GString *gstr, const char *sig,
						const char *direction)
{
	int i;

	for (i = 0; sig[i]; i++) {
		char type[32];
		int struct_level, dict_level;
		unsigned int len;
		gboolean complete;

		complete = FALSE;
		struct_level = dict_level = 0;
		memset(type, 0, sizeof(type));

		/* Gather enough data to have a single complete type */
		for (len = 0; len < (sizeof(type) - 1) && sig[i]; len++, i++) {
			switch (sig[i]){
			case '(':
				struct_level++;
				break;
			case ')':
				struct_level--;
				if (struct_level <= 0 && dict_level <= 0)
					complete = TRUE;
				break;
			case '{':
				dict_level++;
				break;
			case '}':
				dict_level--;
				if (struct_level <= 0 && dict_level <= 0)
					complete = TRUE;
				break;
			case 'a':
				break;
			default:
				if (struct_level <= 0 && dict_level <= 0)
					complete = TRUE;
				break;
			}

			type[len] = sig[i];

			if (complete)
				break;
		}


		if (direction)
			g_string_append_printf(gstr,
					"\t\t\t<arg type=\"%s\" direction=\"%s\"/>\n",
					type, direction);
		else
			g_string_append_printf(gstr,
					"\t\t\t<arg type=\"%s\"/>\n",
					type);
	}
}

static void generate_interface_xml(GString *gstr, struct interface_data *iface)
{
	const GDBusMethodTable *method;
	const GDBusSignalTable *signal;

	for (method = iface->methods; method && method->name; method++) {
		if (!strlen(method->signature) && !strlen(method->reply))
			g_string_append_printf(gstr, "\t\t<method name=\"%s\"/>\n",
								method->name);
		else {
			g_string_append_printf(gstr, "\t\t<method name=\"%s\">\n",
								method->name);
			print_arguments(gstr, method->signature, "in");
			print_arguments(gstr, method->reply, "out");
			g_string_append_printf(gstr, "\t\t</method>\n");
		}
	}

	for (signal = iface->signals; signal && signal->name; signal++) {
		if (!strlen(signal->signature))
			g_string_append_printf(gstr, "\t\t<signal name=\"%s\"/>\n",
								signal->name);
		else {
			g_string_append_printf(gstr, "\t\t<signal name=\"%s\">\n",
								signal->name);
			print_arguments(gstr, signal->signature, NULL);
			g_string_append_printf(gstr, "\t\t</signal>\n");
		}
	}
}

static void generate_introspection_xml(DBusConnection *conn,
				struct generic_data *data, const char *path)
{
	GSList *list;
	GString *gstr;
	char **children;
	int i;

	g_free(data->introspect);

	gstr = g_string_new(DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE);

	g_string_append_printf(gstr, "<node name=\"%s\">\n", path);

	for (list = data->interfaces; list; list = list->next) {
		struct interface_data *iface = list->data;

		g_string_append_printf(gstr, "\t<interface name=\"%s\">\n",
								iface->name);

		generate_interface_xml(gstr, iface);

		g_string_append_printf(gstr, "\t</interface>\n");
	}

	if (!dbus_connection_list_registered(conn, path, &children))
		goto done;

	for (i = 0; children[i]; i++)
		g_string_append_printf(gstr, "\t<node name=\"%s\"/>\n",
								children[i]);

	dbus_free_string_array(children);

done:
	g_string_append_printf(gstr, "</node>\n");

	data->introspect = g_string_free(gstr, FALSE);
}

static DBusMessage *introspect(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	DBusMessage *reply;

	if (!dbus_message_has_signature(message, DBUS_TYPE_INVALID_AS_STRING)) {
		error("Unexpected signature to introspect call");
		return NULL;
	}

	if (!data->introspect)
		generate_introspection_xml(connection, data,
						dbus_message_get_path(message));

	reply = dbus_message_new_method_return(message);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &data->introspect,
					DBUS_TYPE_INVALID);

	return reply;
}

static void generic_unregister(DBusConnection *connection, void *user_data)
{
	struct generic_data *data = user_data;

	g_free(data->introspect);
	g_free(data);
}

static struct interface_data *find_interface(GSList *interfaces,
						const char *name)
{
	GSList *list;

	if (!name)
		return NULL;

	for (list = interfaces; list; list = list->next) {
		struct interface_data *iface = list->data;
		if (!strcmp(name, iface->name))
			return iface;
	}

	return NULL;
}

static DBusHandlerResult generic_message(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	struct interface_data *iface;
	const GDBusMethodTable *method;
	const char *interface;

	interface = dbus_message_get_interface(message);

	iface = find_interface(data->interfaces, interface);
	if (!iface)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	for (method = iface->methods; method &&
			method->name && method->function; method++) {
		DBusMessage *reply;

		if (dbus_message_is_method_call(message, iface->name,
							method->name) == FALSE)
			continue;

		if (dbus_message_has_signature(message,
						method->signature) == FALSE)
			continue;

		reply = method->function(connection, message, iface->user_data);

		if (method->flags & G_DBUS_METHOD_FLAG_NOREPLY) {
			if (reply != NULL)
				dbus_message_unref(reply);
			return DBUS_HANDLER_RESULT_HANDLED;
		}

		if (method->flags & G_DBUS_METHOD_FLAG_ASYNC) {
			if (reply == NULL)
				return DBUS_HANDLER_RESULT_HANDLED;
		}

		if (reply == NULL)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		dbus_connection_send(connection, reply, NULL);
		dbus_message_unref(reply);

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusObjectPathVTable generic_table = {
	.unregister_function	= generic_unregister,
	.message_function	= generic_message,
};

static void invalidate_parent_data(DBusConnection *conn, const char *child_path)
{
	struct generic_data *data = NULL;
	char *parent_path, *slash;

	parent_path = g_strdup(child_path);
	slash = strrchr(parent_path, '/');
	if (!slash)
		goto done;

	if (slash == parent_path && parent_path[1] != '\0')
		parent_path[1] = '\0';
	else
		*slash = '\0';

	if (!strlen(parent_path))
		goto done;

	if (!dbus_connection_get_object_path_data(conn, parent_path,
							(void *) &data)) {
		invalidate_parent_data(conn, parent_path);
		goto done;
	}

	if (!data)
		goto done;

	g_free(data->introspect);
	data->introspect = NULL;

done:
	g_free(parent_path);
}

static GDBusMethodTable introspect_methods[] = {
	{ "Introspect",	"",	"s", introspect	},
	{ }
};

static void add_interface(struct generic_data *data, const char *name,
				const GDBusMethodTable *methods,
				const GDBusSignalTable *signals,
				const GDBusPropertyTable *properties,
				void *user_data,
				GDBusDestroyFunction destroy)
{
	struct interface_data *iface;

	iface = g_new0(struct interface_data, 1);
	iface->name = g_strdup(name);
	iface->methods = methods;
	iface->signals = signals;
	iface->properties = properties;
	iface->user_data = user_data;
	iface->destroy = destroy;

	data->interfaces = g_slist_append(data->interfaces, iface);
}

static struct generic_data *object_path_ref(DBusConnection *connection,
							const char *path)
{
	struct generic_data *data;

	if (dbus_connection_get_object_path_data(connection, path,
						(void *) &data) == TRUE) {
		if (data != NULL) {
			data->refcount++;
			return data;
		}
	}

	data = g_new0(struct generic_data, 1);

	data->introspect = g_strdup(DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE "<node></node>");

	data->refcount = 1;

	if (!dbus_connection_register_object_path(connection, path,
						&generic_table, data)) {
		g_free(data->introspect);
		g_free(data);
		return NULL;
	}

	invalidate_parent_data(connection, path);

	add_interface(data, DBUS_INTERFACE_INTROSPECTABLE,
			introspect_methods, NULL, NULL, data, NULL);

	return data;
}

static gboolean remove_interface(struct generic_data *data, const char *name)
{
	struct interface_data *iface;

	iface = find_interface(data->interfaces, name);
	if (!iface)
		return FALSE;

	data->interfaces = g_slist_remove(data->interfaces, iface);

	if (iface->destroy)
		iface->destroy(iface->user_data);

	g_free(iface->name);
	g_free(iface);

	return TRUE;
}

static void object_path_unref(DBusConnection *connection, const char *path)
{
	struct generic_data *data = NULL;

	if (dbus_connection_get_object_path_data(connection, path,
						(void *) &data) == FALSE)
		return;

	if (data == NULL)
		return;

	data->refcount--;

	if (data->refcount > 0)
		return;

	remove_interface(data, DBUS_INTERFACE_INTROSPECTABLE);

	invalidate_parent_data(connection, path);

	dbus_connection_unregister_object_path(connection, path);
}

static gboolean check_signal(DBusConnection *conn, const char *path,
				const char *interface, const char *name,
				const char **args)
{
	struct generic_data *data = NULL;
	struct interface_data *iface;
	const GDBusSignalTable *signal;

	*args = NULL;
	if (!dbus_connection_get_object_path_data(conn, path,
					(void *) &data) || !data) {
		error("dbus_connection_emit_signal: path %s isn't registered",
				path);
		return FALSE;
	}

	iface = find_interface(data->interfaces, interface);
	if (!iface) {
		error("dbus_connection_emit_signal: %s does not implement %s",
				path, interface);
		return FALSE;
	}

	for (signal = iface->signals; signal && signal->name; signal++) {
		if (!strcmp(signal->name, name)) {
			*args = signal->signature;
			break;
		}
	}

	if (!*args) {
		error("No signal named %s on interface %s", name, interface);
		return FALSE;
	}

	return TRUE;
}

static dbus_bool_t emit_signal_valist(DBusConnection *conn,
						const char *path,
						const char *interface,
						const char *name,
						int first,
						va_list var_args)
{
	DBusMessage *signal;
	dbus_bool_t ret;
	const char *signature, *args;

	if (!check_signal(conn, path, interface, name, &args))
		return FALSE;

	signal = dbus_message_new_signal(path, interface, name);
	if (!signal) {
		error("Unable to allocate new %s.%s signal", interface,  name);
		return FALSE;
	}

	ret = dbus_message_append_args_valist(signal, first, var_args);
	if (!ret)
		goto fail;

	signature = dbus_message_get_signature(signal);
	if (strcmp(args, signature) != 0) {
		error("%s.%s: expected signature'%s' but got '%s'",
				interface, name, args, signature);
		ret = FALSE;
		goto fail;
	}

	ret = dbus_connection_send(conn, signal, NULL);

fail:
	dbus_message_unref(signal);

	return ret;
}

gboolean g_dbus_register_interface(DBusConnection *connection,
					const char *path, const char *name,
					const GDBusMethodTable *methods,
					const GDBusSignalTable *signals,
					const GDBusPropertyTable *properties,
					void *user_data,
					GDBusDestroyFunction destroy)
{
	struct generic_data *data;

	data = object_path_ref(connection, path);
	if (data == NULL)
		return FALSE;

	if (find_interface(data->interfaces, name)) {
		object_path_unref(connection, path);
		return FALSE;
	}

	add_interface(data, name, methods, signals,
			properties, user_data, destroy);

	g_free(data->introspect);
	data->introspect = NULL;

	return TRUE;
}

gboolean g_dbus_unregister_interface(DBusConnection *connection,
					const char *path, const char *name)
{
	struct generic_data *data = NULL;

	if (!path)
		return FALSE;

	if (dbus_connection_get_object_path_data(connection, path,
						(void *) &data) == FALSE)
		return FALSE;

	if (data == NULL)
		return FALSE;

	if (remove_interface(data, name) == FALSE)
		return FALSE;

	g_free(data->introspect);
	data->introspect = NULL;

	object_path_unref(connection, path);

	return TRUE;
}

DBusMessage *g_dbus_create_error_valist(DBusMessage *message, const char *name,
					const char *format, va_list args)
{
	char str[1024];

	vsnprintf(str, sizeof(str), format, args);

	return dbus_message_new_error(message, name, str);
}

DBusMessage *g_dbus_create_error(DBusMessage *message, const char *name,
						const char *format, ...)
{
	va_list args;
	DBusMessage *reply;

	va_start(args, format);

	reply = g_dbus_create_error_valist(message, name, format, args);

	va_end(args);

	return reply;
}

DBusMessage *g_dbus_create_reply_valist(DBusMessage *message,
						int type, va_list args)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	if (dbus_message_append_args_valist(reply, type, args) == FALSE) {
		dbus_message_unref(reply);
		return NULL;
	}

	return reply;
}

DBusMessage *g_dbus_create_reply(DBusMessage *message, int type, ...)
{
	va_list args;
	DBusMessage *reply;

	va_start(args, type);

	reply = g_dbus_create_reply_valist(message, type, args);

	va_end(args);

	return reply;
}

gboolean g_dbus_send_message(DBusConnection *connection, DBusMessage *message)
{
	dbus_bool_t result;

	if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_METHOD_CALL)
		dbus_message_set_no_reply(message, TRUE);

	result = dbus_connection_send(connection, message, NULL);

	dbus_message_unref(message);

	return result;
}

gboolean g_dbus_send_reply_valist(DBusConnection *connection,
				DBusMessage *message, int type, va_list args)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return FALSE;

	if (dbus_message_append_args_valist(reply, type, args) == FALSE) {
		dbus_message_unref(reply);
		return FALSE;
	}

	return g_dbus_send_message(connection, reply);
}

gboolean g_dbus_send_reply(DBusConnection *connection,
				DBusMessage *message, int type, ...)
{
	va_list args;
	gboolean result;

	va_start(args, type);

	result = g_dbus_send_reply_valist(connection, message, type, args);

	va_end(args);

	return result;
}

gboolean g_dbus_emit_signal(DBusConnection *connection,
				const char *path, const char *interface,
				const char *name, int type, ...)
{
	va_list args;
	gboolean result;

	va_start(args, type);

	result = emit_signal_valist(connection, path, interface,
							name, type, args);

	va_end(args);

	return result;
}

gboolean g_dbus_emit_signal_valist(DBusConnection *connection,
				const char *path, const char *interface,
				const char *name, int type, va_list args)
{
	return emit_signal_valist(connection, path, interface,
							name, type, args);
}
