/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <wordexp.h>

#include <inttypes.h>
#include <ctype.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include "bluetooth/bluetooth.h"

#include <readline/readline.h>
#include <readline/history.h>
#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/uuid.h"
#include "src/shared/util.h"
#include "gdbus/gdbus.h"
#include "monitor/uuid.h"
#include "client/display.h"
#include "mesh/mesh-net.h"
#include "mesh/gatt.h"
#include "mesh/crypto.h"
#include "mesh/node.h"
#include "mesh/net.h"
#include "mesh/keys.h"
#include "mesh/prov.h"
#include "mesh/util.h"
#include "mesh/agent.h"
#include "mesh/prov-db.h"
#include "mesh/config-model.h"
#include "mesh/onoff-model.h"

/* String display constants */
#define COLORED_NEW	COLOR_GREEN "NEW" COLOR_OFF
#define COLORED_CHG	COLOR_YELLOW "CHG" COLOR_OFF
#define COLORED_DEL	COLOR_RED "DEL" COLOR_OFF

#define PROMPT_ON	COLOR_BLUE "[meshctl]" COLOR_OFF "# "
#define PROMPT_OFF	"Waiting to connect to bluetoothd..."

#define MESH_PROV_DATA_IN_UUID_STR	"00002adb-0000-1000-8000-00805f9b34fb"
#define MESH_PROV_DATA_OUT_UUID_STR	"00002adc-0000-1000-8000-00805f9b34fb"
#define MESH_PROXY_DATA_IN_UUID_STR	"00002add-0000-1000-8000-00805f9b34fb"
#define MESH_PROXY_DATA_OUT_UUID_STR	"00002ade-0000-1000-8000-00805f9b34fb"

static GMainLoop *main_loop;
static DBusConnection *dbus_conn;

struct adapter {
GDBusProxy *proxy;
	GList *mesh_devices;
};

struct mesh_device {
	GDBusProxy *proxy;
	uint8_t dev_uuid[16];
	gboolean hide;
};

GList *service_list;
GList *char_list;

static GList *ctrl_list;
static struct adapter *default_ctrl;

static char *mesh_prov_db_filename;
static char *mesh_local_config_filename;

static bool discovering = false;
static bool discover_mesh;
static uint16_t prov_net_key_index = NET_IDX_PRIMARY;

static guint input = 0;

#define CONN_TYPE_NETWORK	0x00
#define CONN_TYPE_IDENTITY	0x01
#define CONN_TYPE_PROVISION	0x02
#define CONN_TYPE_INVALID	0xff

#define NET_IDX_INVALID		0xffff

struct {
	GDBusProxy *device;
	GDBusProxy *service;
	GDBusProxy *data_in;
	GDBusProxy *data_out;
	bool session_open;
	uint16_t unicast;
	uint16_t net_idx;
	uint8_t dev_uuid[16];
	uint8_t type;
} connection;

static bool service_is_mesh(GDBusProxy *proxy, const char *target_uuid)
{
	DBusMessageIter iter;
	const char *uuid;

	if (g_dbus_proxy_get_property(proxy, "UUID", &iter) == FALSE)
		return false;

	dbus_message_iter_get_basic(&iter, &uuid);

	if (target_uuid)
		return (!bt_uuid_strcmp(uuid, target_uuid));
	else if (bt_uuid_strcmp(uuid, MESH_PROV_SVC_UUID) ||
				bt_uuid_strcmp(uuid, MESH_PROXY_SVC_UUID))
		return true;
	else
		return false;
}

static bool char_is_mesh(GDBusProxy *proxy, const char *target_uuid)
{
	DBusMessageIter iter;
	const char *uuid;

	if (g_dbus_proxy_get_property(proxy, "UUID", &iter) == FALSE)
		return false;

	dbus_message_iter_get_basic(&iter, &uuid);

	if (target_uuid)
		return (!bt_uuid_strcmp(uuid, target_uuid));

	if (!bt_uuid_strcmp(uuid, MESH_PROV_DATA_IN_UUID_STR))
		return true;

	if (!bt_uuid_strcmp(uuid, MESH_PROV_DATA_OUT_UUID_STR))
		return true;

	if (!bt_uuid_strcmp(uuid, MESH_PROXY_DATA_IN_UUID_STR))
		return true;

	if (!bt_uuid_strcmp(uuid, MESH_PROXY_DATA_OUT_UUID_STR))
		return true;

	return false;
}

static gboolean check_default_ctrl(void)
{
	if (!default_ctrl) {
		rl_printf("No default controller available\n");
		return FALSE;
	}

	return TRUE;
}

static void proxy_leak(gpointer data)
{
	rl_printf("Leaking proxy %p\n", data);
}

static gboolean input_handler(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	if (condition & G_IO_IN) {
		rl_callback_read_char();
		return TRUE;
	}

	if (condition & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		g_main_loop_quit(main_loop);
		return FALSE;
	}

	return TRUE;
}

static guint setup_standard_input(void)
{
	GIOChannel *channel;
	guint source;

	channel = g_io_channel_unix_new(fileno(stdin));

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				input_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

static void connect_handler(DBusConnection *connection, void *user_data)
{
	rl_set_prompt(PROMPT_ON);
	rl_printf("\r");
	rl_on_new_line();
	rl_redisplay();
}

static void disconnect_handler(DBusConnection *connection, void *user_data)
{
	if (input > 0) {
		g_source_remove(input);
		input = 0;
	}

	rl_set_prompt(PROMPT_OFF);
	rl_printf("\r");
	rl_on_new_line();
	rl_redisplay();

	g_list_free_full(ctrl_list, proxy_leak);
	ctrl_list = NULL;

	default_ctrl = NULL;
}

static void print_adapter(GDBusProxy *proxy, const char *description)
{
	DBusMessageIter iter;
	const char *address, *name;

	if (g_dbus_proxy_get_property(proxy, "Address", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &address);

	if (g_dbus_proxy_get_property(proxy, "Alias", &iter) == TRUE)
		dbus_message_iter_get_basic(&iter, &name);
	else
		name = "<unknown>";

	rl_printf("%s%s%sController %s %s %s\n",
				description ? "[" : "",
				description ? : "",
				description ? "] " : "",
				address, name,
				default_ctrl &&
				default_ctrl->proxy == proxy ?
				"[default]" : "");

}

static void print_device(GDBusProxy *proxy, const char *description)
{
	DBusMessageIter iter;
	const char *address, *name;

	if (g_dbus_proxy_get_property(proxy, "Address", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &address);

	if (g_dbus_proxy_get_property(proxy, "Alias", &iter) == TRUE)
		dbus_message_iter_get_basic(&iter, &name);
	else
		name = "<unknown>";

	rl_printf("%s%s%sDevice %s %s\n",
				description ? "[" : "",
				description ? : "",
				description ? "] " : "",
				address, name);
}

static void print_iter(const char *label, const char *name,
						DBusMessageIter *iter)
{
	dbus_bool_t valbool;
	dbus_uint32_t valu32;
	dbus_uint16_t valu16;
	dbus_int16_t vals16;
	unsigned char byte;
	const char *valstr;
	DBusMessageIter subiter;
	char *entry;

	if (iter == NULL) {
		rl_printf("%s%s is nil\n", label, name);
		return;
	}

	switch (dbus_message_iter_get_arg_type(iter)) {
	case DBUS_TYPE_INVALID:
		rl_printf("%s%s is invalid\n", label, name);
		break;
	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		dbus_message_iter_get_basic(iter, &valstr);
		rl_printf("%s%s: %s\n", label, name, valstr);
		break;
	case DBUS_TYPE_BOOLEAN:
		dbus_message_iter_get_basic(iter, &valbool);
		rl_printf("%s%s: %s\n", label, name,
					valbool == TRUE ? "yes" : "no");
		break;
	case DBUS_TYPE_UINT32:
		dbus_message_iter_get_basic(iter, &valu32);
		rl_printf("%s%s: 0x%06x\n", label, name, valu32);
		break;
	case DBUS_TYPE_UINT16:
		dbus_message_iter_get_basic(iter, &valu16);
		rl_printf("%s%s: 0x%04x\n", label, name, valu16);
		break;
	case DBUS_TYPE_INT16:
		dbus_message_iter_get_basic(iter, &vals16);
		rl_printf("%s%s: %d\n", label, name, vals16);
		break;
	case DBUS_TYPE_BYTE:
		dbus_message_iter_get_basic(iter, &byte);
		rl_printf("%s%s: 0x%02x\n", label, name, byte);
		break;
	case DBUS_TYPE_VARIANT:
		dbus_message_iter_recurse(iter, &subiter);
		print_iter(label, name, &subiter);
		break;
	case DBUS_TYPE_ARRAY:
		dbus_message_iter_recurse(iter, &subiter);
		while (dbus_message_iter_get_arg_type(&subiter) !=
							DBUS_TYPE_INVALID) {
			print_iter(label, name, &subiter);
			dbus_message_iter_next(&subiter);
		}
		break;
	case DBUS_TYPE_DICT_ENTRY:
		dbus_message_iter_recurse(iter, &subiter);
		entry = g_strconcat(name, "Key", NULL);
		print_iter(label, entry, &subiter);
		g_free(entry);

		entry = g_strconcat(name, " Value", NULL);
		dbus_message_iter_next(&subiter);
		print_iter(label, entry, &subiter);
		g_free(entry);
		break;
	default:
		rl_printf("%s%s has unsupported type\n", label, name);
		break;
	}
}

static void print_property(GDBusProxy *proxy, const char *name)
{
	DBusMessageIter iter;

	if (g_dbus_proxy_get_property(proxy, name, &iter) == FALSE)
		return;

	print_iter("\t", name, &iter);
}

static void forget_mesh_devices()
{
	g_list_free_full(default_ctrl->mesh_devices, g_free);
	default_ctrl->mesh_devices = NULL;
}

static struct mesh_device *find_device_by_uuid(GList *source, uint8_t uuid[16])
{
	GList *list;

	for (list = g_list_first(source); list; list = g_list_next(list)) {
		struct mesh_device *dev = list->data;

		if (!memcmp(dev->dev_uuid, uuid, 16))
			return dev;
	}

	return NULL;
}

static void print_prov_service(struct prov_svc_data *prov_data)
{
	const char *prefix = "\t\t";
	char txt_uuid[16 * 2 + 1];
	int i;

	rl_printf("%sMesh Provisioning Service (%s)\n", prefix,
							MESH_PROV_SVC_UUID);
	for (i = 0; i < 16; ++i) {
		sprintf(txt_uuid + (i * 2), "%2.2x", prov_data->dev_uuid[i]);
	}

	rl_printf("%s\tDevice UUID: %s\n", prefix, txt_uuid);
	rl_printf("%s\tOOB: %4.4x\n", prefix, prov_data->oob);

}

static bool parse_prov_service_data(const char *uuid, uint8_t *data, int len,
								void *data_out)
{
	struct prov_svc_data *prov_data = data_out;
	int i;

	if (len < 18)
		return false;

	for (i = 0; i < 16; ++i) {
		prov_data->dev_uuid[i] = data[i];
	}

	prov_data->oob = get_be16(&data[16]);

	return true;
}

static bool parse_mesh_service_data(const char *uuid, uint8_t *data, int len,
								void *data_out)
{
	const char *prefix = "\t\t";

	if (!(len == 9 && data[0] == 0x00) && !(len == 17 && data[0] == 0x01)) {
		rl_printf("Unexpected mesh proxy service data length %d\n",
									len);
		return false;
	}

	if (data[0] != connection.type)
		return false;

	if (data[0] == CONN_TYPE_IDENTITY) {
		uint8_t *key;

		if (IS_UNASSIGNED(connection.unicast)) {
			/* This would be a bug */
			rl_printf("Error: Searching identity with "
							"unicast 0000\n");
			return false;
		}

		key = keys_net_key_get(prov_net_key_index, true);
		if (!key)
			return false;

		if (!mesh_crypto_identity_check(key, connection.unicast,
					       &data[1]))
			return false;

		if (discovering) {
			rl_printf("\n%sMesh Proxy Service (%s)\n", prefix,
									uuid);
			rl_printf("%sIdentity for node %4.4x\n", prefix,
							connection.unicast);
		}

	} else if (data[0] == CONN_TYPE_NETWORK) {
		uint16_t net_idx = net_validate_proxy_beacon(data + 1);

		if (net_idx == NET_IDX_INVALID || net_idx != connection.net_idx)
			return false;

		if (discovering) {
			rl_printf("\n%sMesh Proxy Service (%s)\n", prefix,
									uuid);
			rl_printf("%sNetwork Beacon for net index %4.4x\n",
							prefix, net_idx);
		}
	}

	return true;
}

static bool parse_service_data(GDBusProxy *proxy, const char *target_uuid,
					void *data_out)
{
	DBusMessageIter iter, entries;
	bool mesh_prov = false;
	bool mesh_proxy = false;

	if (target_uuid) {
		mesh_prov = !strcmp(target_uuid, MESH_PROV_SVC_UUID);
		mesh_proxy = !strcmp(target_uuid, MESH_PROXY_SVC_UUID);
	}

	if (!g_dbus_proxy_get_property(proxy, "ServiceData", &iter))
		return false;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return false;

	dbus_message_iter_recurse(&iter, &entries);

	while (dbus_message_iter_get_arg_type(&entries)
						== DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter value, entry, array;
		const char *uuid_str;
		bt_uuid_t uuid;
		uint8_t *service_data;
		int len;

		dbus_message_iter_recurse(&entries, &entry);
		dbus_message_iter_get_basic(&entry, &uuid_str);

		if (bt_string_to_uuid(&uuid, uuid_str) < 0)
			goto fail;

		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			goto fail;

		dbus_message_iter_recurse(&entry, &value);

		if (dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_ARRAY)
			goto fail;

		dbus_message_iter_recurse(&value, &array);

		if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_BYTE)
			goto fail;

		dbus_message_iter_get_fixed_array(&array, &service_data, &len);

		if (mesh_prov && !strcmp(uuid_str, MESH_PROV_SVC_UUID)) {
			return parse_prov_service_data(uuid_str, service_data,
								len, data_out);
		} else if (mesh_proxy &&
				!strcmp(uuid_str, MESH_PROXY_SVC_UUID)) {
			return parse_mesh_service_data(uuid_str, service_data,
								len, data_out);
		}

		dbus_message_iter_next(&entries);
	}

	if (!target_uuid)
		return true;
fail:
	return false;
}

static void print_uuids(GDBusProxy *proxy)
{
	DBusMessageIter iter, value;

	if (g_dbus_proxy_get_property(proxy, "UUIDs", &iter) == FALSE)
		return;

	dbus_message_iter_recurse(&iter, &value);

	while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_STRING) {
		const char *uuid, *text;

		dbus_message_iter_get_basic(&value, &uuid);

		text = uuidstr_to_str(uuid);
		if (text) {
			char str[26];
			unsigned int n;

			str[sizeof(str) - 1] = '\0';

			n = snprintf(str, sizeof(str), "%s", text);
			if (n > sizeof(str) - 1) {
				str[sizeof(str) - 2] = '.';
				str[sizeof(str) - 3] = '.';
				if (str[sizeof(str) - 4] == ' ')
					str[sizeof(str) - 4] = '.';

				n = sizeof(str) - 1;
			}

			rl_printf("\tUUID: %s%*c(%s)\n",
						str, 26 - n, ' ', uuid);
		} else
			rl_printf("\tUUID: %*c(%s)\n", 26, ' ', uuid);

		dbus_message_iter_next(&value);
	}
}

static gboolean device_is_child(GDBusProxy *device, GDBusProxy *master)
{
	DBusMessageIter iter;
	const char *adapter, *path;

	if (!master)
		return FALSE;

	if (g_dbus_proxy_get_property(device, "Adapter", &iter) == FALSE)
		return FALSE;

	dbus_message_iter_get_basic(&iter, &adapter);
	path = g_dbus_proxy_get_path(master);

	if (!strcmp(path, adapter))
		return TRUE;

	return FALSE;
}

static struct adapter *find_parent(GDBusProxy *device)
{
	GList *list;

	for (list = g_list_first(ctrl_list); list; list = g_list_next(list)) {
		struct adapter *adapter = list->data;

		if (device_is_child(device, adapter->proxy) == TRUE)
			return adapter;
	}
	return NULL;
}

static void set_connected_device(GDBusProxy *proxy)
{
	char *desc = NULL;
	DBusMessageIter iter;
	char buf[10];
	bool mesh;

	connection.device = proxy;

	if (proxy == NULL) {
		memset(&connection, 0, sizeof(connection));
		connection.type = CONN_TYPE_INVALID;
		goto done;
	}

	if (connection.type == CONN_TYPE_IDENTITY) {
		mesh = true;
		snprintf(buf, 10, "Node-%4.4x", connection.unicast);
	} else if (connection.type == CONN_TYPE_NETWORK) {
		mesh = true;
		snprintf(buf, 9, "Net-%4.4x", connection.net_idx);
	} else {
		mesh = false;
	}

	if (!g_dbus_proxy_get_property(proxy, "Alias", &iter) && !mesh)
			goto done;

	dbus_message_iter_get_basic(&iter, &desc);
	desc = g_strdup_printf(COLOR_BLUE "[%s%s%s]" COLOR_OFF "# ", desc,
			       (desc && mesh) ? "-" : "",
				mesh ? buf : "");

done:
	rl_set_prompt(desc ? desc : PROMPT_ON);
	rl_printf("\r");
	rl_on_new_line();
	g_free(desc);

	/* If disconnected, return to main menu */
	if (proxy == NULL)
		cmd_menu_main(true);
}

static void connect_reply(DBusMessage *message, void *user_data)
{
	GDBusProxy *proxy = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		rl_printf("Failed to connect: %s\n", error.name);
		dbus_error_free(&error);
		set_connected_device(NULL);
		return;
	}

	rl_printf("Connection successful\n");

	set_connected_device(proxy);
}

static void update_device_info(GDBusProxy *proxy)
{
	struct adapter *adapter = find_parent(proxy);
	DBusMessageIter iter;
	struct prov_svc_data prov_data;

	if (!adapter) {
		/* TODO: Error */
		return;
	}

	if (adapter != default_ctrl)
		return;

	if (!g_dbus_proxy_get_property(proxy, "Address", &iter))
		return;

	if (parse_service_data(proxy, MESH_PROV_SVC_UUID, &prov_data)) {
		struct mesh_device *dev;

		dev = find_device_by_uuid(adapter->mesh_devices,
							prov_data.dev_uuid);

		/* Display provisioning service once per discovery session */
		if (discovering && (!dev || !dev->hide))
						print_prov_service(&prov_data);

		if (dev) {
			dev->proxy = proxy;
			dev->hide = discovering;
			return;
		}

		dev = g_malloc0(sizeof(struct mesh_device));
		if (!dev)
			return;

		dev->proxy = proxy;
		dev->hide = discovering;

		memcpy(dev->dev_uuid, prov_data.dev_uuid, 16);

		adapter->mesh_devices = g_list_append(adapter->mesh_devices,
							dev);
		print_device(proxy, COLORED_NEW);

		node_create_new(&prov_data);

	} else if (parse_service_data(proxy, MESH_PROXY_SVC_UUID, NULL) &&
								discover_mesh) {
		bool res;

		g_dbus_proxy_method_call(default_ctrl->proxy, "StopDiscovery",
						NULL, NULL, NULL, NULL);
		discover_mesh = false;

		forget_mesh_devices();

		res = g_dbus_proxy_method_call(proxy, "Connect", NULL,
						connect_reply, proxy, NULL);

		if (!res)
			rl_printf("Failed to connect to mesh\n");

		else
			rl_printf("Trying to connect to mesh\n");

	}
}

static void adapter_added(GDBusProxy *proxy)
{
	struct adapter *adapter = g_malloc0(sizeof(struct adapter));

	adapter->proxy = proxy;
	ctrl_list = g_list_append(ctrl_list, adapter);

	if (!default_ctrl)
		default_ctrl = adapter;

	print_adapter(proxy, COLORED_NEW);
}

static void data_out_notify(GDBusProxy *proxy, bool enable,
				GDBusReturnFunction cb)
{
	struct mesh_node *node;

	node = node_find_by_uuid(connection.dev_uuid);

	if (!mesh_gatt_notify(proxy, enable, cb, node))
		rl_printf("Failed to %s notification on %s\n", enable ?
				"start" : "stop", g_dbus_proxy_get_path(proxy));
	else
		rl_printf("%s notification on %s\n", enable ?
			  "Start" : "Stop", g_dbus_proxy_get_path(proxy));
}

struct disconnect_data {
	GDBusReturnFunction cb;
	void *data;
};

static void disconnect(GDBusReturnFunction cb, void *user_data)
{
	GDBusProxy *proxy;
	DBusMessageIter iter;
	const char *addr;

	proxy = connection.device;
	if (!proxy)
		return;

	if (g_dbus_proxy_method_call(proxy, "Disconnect", NULL, cb, user_data,
							NULL) == FALSE) {
		rl_printf("Failed to disconnect\n");
		return;
	}

	if (g_dbus_proxy_get_property(proxy, "Address", &iter) == TRUE)
			dbus_message_iter_get_basic(&iter, &addr);

	rl_printf("Attempting to disconnect from %s\n", addr);
}

static void disc_notify_cb(DBusMessage *message, void *user_data)
{
	struct disconnect_data *disc_data = user_data;

	disconnect(disc_data->cb, disc_data->data);

	g_free(user_data);
}

static void disconnect_device(GDBusReturnFunction cb, void *user_data)
{
	DBusMessageIter iter;

	net_session_close(connection.data_in);

	/* Stop notificiation on prov_out or proxy out characteristics */
	if (connection.data_out) {
		if (g_dbus_proxy_get_property(connection.data_out, "Notifying",
							&iter) == TRUE) {
			struct disconnect_data *disc_data;
			disc_data = g_malloc(sizeof(struct disconnect_data));
			disc_data->cb = cb;
			disc_data->data = user_data;

			if (mesh_gatt_notify(connection.data_out, false,
						disc_notify_cb, disc_data))
				return;
		}
	}

	disconnect(cb, user_data);
}

static void mesh_prov_done(void *user_data, int status);

static void notify_prov_out_cb(DBusMessage *message, void *user_data)
{
	struct mesh_node *node = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		rl_printf("Failed to start notify: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	rl_printf("Notify for Mesh Provisioning Out Data started\n");

	if (connection.type != CONN_TYPE_PROVISION) {
		rl_printf("Error: wrong connection type %d (expected %d)\n",
			connection.type, CONN_TYPE_PROVISION);
		return;
	}

	if (!connection.data_in) {
		rl_printf("Error: don't have mesh provisioning data in\n");
		return;
	}

	if (!node) {
		rl_printf("Error: provisioning node not present\n");
		return;
	}

	if(!prov_open(node, connection.data_in, prov_net_key_index,
			mesh_prov_done, node))
	{
		rl_printf("Failed to start provisioning\n");
		node_free(node);
		disconnect_device(NULL, NULL);
	} else
		rl_printf("Initiated provisioning\n");

}

static void session_open_cb (int status)
{
	if (status) {
		rl_printf("Failed to open Mesh session\n");
		disconnect_device(NULL, NULL);
		return;
	}

	rl_printf("Mesh session is open\n");

	/* Get composition data for a newly provisioned node */
	if (connection.type == CONN_TYPE_IDENTITY)
		config_client_get_composition(connection.unicast);
}

static void notify_proxy_out_cb(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		rl_printf("Failed to start notify: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	rl_printf("Notify for Mesh Proxy Out Data started\n");

	if (connection.type != CONN_TYPE_IDENTITY &&
			connection.type != CONN_TYPE_NETWORK) {
		rl_printf("Error: wrong connection type %d "
				"(expected %d or %d)\n", connection.type,
				CONN_TYPE_IDENTITY, CONN_TYPE_NETWORK);
		return;
	}

	if (!connection.data_in) {
		rl_printf("Error: don't have mesh proxy data in\n");
		return;
	}

	rl_printf("Trying to open mesh session\n");
	net_session_open(connection.data_in, true, session_open_cb);
	connection.session_open = true;
}

static GDBusProxy *get_characteristic(GDBusProxy *device, const char *char_uuid)
{
	GList *l;
	GDBusProxy *service;
	const char *svc_uuid;

	if (connection.type == CONN_TYPE_PROVISION) {
		svc_uuid = MESH_PROV_SVC_UUID;
	} else {
		svc_uuid = MESH_PROXY_SVC_UUID;
	}
	for (l = service_list; l; l = l->next) {
		if (mesh_gatt_is_child(l->data, device, "Device") &&
					service_is_mesh(l->data, svc_uuid))
			break;
	}

	if (l)
		service = l->data;
	else {
		rl_printf("Mesh service not found\n");
		return	NULL;
	}

	for (l = char_list; l; l = l->next) {
		if (mesh_gatt_is_child(l->data, service, "Service") &&
					char_is_mesh(l->data, char_uuid)) {
			rl_printf("Found matching char: path %s, uuid %s\n",
				g_dbus_proxy_get_path(l->data), char_uuid);
			return l->data;
		}
	}
	return NULL;
}

static void mesh_session_setup(GDBusProxy *proxy)
{
	if (connection.type == CONN_TYPE_PROVISION) {
		connection.data_in = get_characteristic(proxy,
						MESH_PROV_DATA_IN_UUID_STR);
		if (!connection.data_in)
			goto fail;

		connection.data_out = get_characteristic(proxy,
						MESH_PROV_DATA_OUT_UUID_STR);
		if (!connection.data_out)
			goto fail;

		data_out_notify(connection.data_out, true, notify_prov_out_cb);

	} else if (connection.type != CONN_TYPE_INVALID){

		connection.data_in = get_characteristic(proxy,
						MESH_PROXY_DATA_IN_UUID_STR);
		if (!connection.data_in)
			goto fail;

		connection.data_out = get_characteristic(proxy,
						MESH_PROXY_DATA_OUT_UUID_STR);
		if (!connection.data_out)
			goto fail;

		data_out_notify(connection.data_out, true, notify_proxy_out_cb);
	}

	return;

fail:

	rl_printf("Services resolved, mesh characteristics not found\n");
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.Device1")) {
		update_device_info(proxy);

	} else if (!strcmp(interface, "org.bluez.Adapter1")) {

		adapter_added(proxy);

	} else if (!strcmp(interface, "org.bluez.GattService1") &&
						service_is_mesh(proxy, NULL)) {

		rl_printf("Service added %s\n", g_dbus_proxy_get_path(proxy));
		service_list = g_list_append(service_list, proxy);

	} else if (!strcmp(interface, "org.bluez.GattCharacteristic1") &&
						char_is_mesh(proxy, NULL)) {

		rl_printf("Char added %s:\n", g_dbus_proxy_get_path(proxy));

		char_list = g_list_append(char_list, proxy);
	}
}

static void start_discovery_reply(DBusMessage *message, void *user_data)
{
	dbus_bool_t enable = GPOINTER_TO_UINT(user_data);
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		rl_printf("Failed to %s discovery: %s\n",
				enable == TRUE ? "start" : "stop", error.name);
		dbus_error_free(&error);
		return;
	}

	rl_printf("Discovery %s\n", enable == TRUE ? "started" : "stopped");
}

static struct mesh_device *find_device_by_proxy(GList *source,
							GDBusProxy *proxy)
{
	GList *list;

	for (list = g_list_first(source); list; list = g_list_next(list)) {
		struct mesh_device *dev = list->data;
		GDBusProxy *proxy = dev->proxy;

		if (dev->proxy == proxy)
			return dev;
	}

	return NULL;
}

static void device_removed(GDBusProxy *proxy)
{
	struct adapter *adapter = find_parent(proxy);
	struct mesh_device *dev;

	if (!adapter) {
		/* TODO: Error */
		return;
	}

	dev = find_device_by_proxy(adapter->mesh_devices, proxy);
	if (dev)
		adapter->mesh_devices = g_list_remove(adapter->mesh_devices,
									dev);

	print_device(proxy, COLORED_DEL);

	if (connection.device == proxy)
		set_connected_device(NULL);

}

static void adapter_removed(GDBusProxy *proxy)
{
	GList *ll;
	for (ll = g_list_first(ctrl_list); ll; ll = g_list_next(ll)) {
		struct adapter *adapter = ll->data;

		if (adapter->proxy == proxy) {
			print_adapter(proxy, COLORED_DEL);

			if (default_ctrl && default_ctrl->proxy == proxy) {
				default_ctrl = NULL;
				set_connected_device(NULL);
			}

			ctrl_list = g_list_remove_link(ctrl_list, ll);

			g_list_free_full(adapter->mesh_devices, g_free);
			g_free(adapter);
			g_list_free(ll);
			return;
		}
	}
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.Device1")) {
		device_removed(proxy);
	} else if (!strcmp(interface, "org.bluez.Adapter1")) {
		adapter_removed(proxy);
	} else if (!strcmp(interface, "org.bluez.GattService1")) {
		if (proxy == connection.service) {
			if (service_is_mesh(proxy, MESH_PROXY_SVC_UUID)) {
				data_out_notify(connection.data_out,
								false, NULL);
				net_session_close(connection.data_in);
			}
			connection.service = NULL;
			connection.data_in = NULL;
			connection.data_out = NULL;
		}

		service_list = g_list_remove(service_list, proxy);

	} else if (!strcmp(interface, "org.bluez.GattCharacteristic1")) {
		char_list = g_list_remove(char_list, proxy);
	}
}

static int get_characteristic_value(DBusMessageIter *value, uint8_t *buf)
{
	DBusMessageIter array;
	uint8_t *data;
	int len;

	if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_ARRAY)
		return 0;

	dbus_message_iter_recurse(value, &array);

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_BYTE)
		return 0;

	dbus_message_iter_get_fixed_array(&array, &data, &len);
	memcpy(buf, data, len);

	return len;
}

static bool process_mesh_characteristic(GDBusProxy *proxy)
{
	DBusMessageIter iter;
	const char *uuid;
	uint8_t *res;
	uint8_t buf[256];
	bool is_prov;

	if (g_dbus_proxy_get_property(proxy, "UUID", &iter) == FALSE)
		return false;

	dbus_message_iter_get_basic(&iter, &uuid);

	if (g_dbus_proxy_get_property(proxy, "Value", &iter) == FALSE)
		return false;

	is_prov = !bt_uuid_strcmp(uuid, MESH_PROV_DATA_OUT_UUID_STR);

	if (is_prov || !bt_uuid_strcmp(uuid, MESH_PROXY_DATA_OUT_UUID_STR))
	{
		struct mesh_node *node;
		uint16_t len;

		len = get_characteristic_value(&iter, buf);

		if (!len || len > 69)
			return false;

		res = buf;
		len = mesh_gatt_sar(&res, len);

		if (!len)
			return false;

		if (is_prov) {
			node = node_find_by_uuid(connection.dev_uuid);

			if (!node) {
				rl_printf("Node not found?\n");
				return false;
			}

			return prov_data_ready(node, res, len);
		}

		return net_data_ready(res, len);
	}

	return false;
}


static void property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.Device1")) {

		if (default_ctrl && device_is_child(proxy,
					default_ctrl->proxy) == TRUE) {

			if (strcmp(name, "Connected") == 0) {
				dbus_bool_t connected;
				dbus_message_iter_get_basic(iter, &connected);

				if (connected && connection.device == NULL)
					set_connected_device(proxy);
				else if (!connected &&
						connection.device == proxy)
					set_connected_device(NULL);
			} else if ((strcmp(name, "Alias") == 0) &&
						connection.device == proxy) {
				/* Re-generate prompt */
				set_connected_device(proxy);
			} else if (!strcmp(name, "ServiceData")) {
				update_device_info(proxy);
			} else if (!strcmp(name, "ServicesResolved")) {
				gboolean resolved;

				dbus_message_iter_get_basic(iter, &resolved);

				rl_printf("Services resolved %s\n", resolved ?
								"yes" : "no");

				if (resolved)
					mesh_session_setup(connection.device);
			}

		}
	} else if (!strcmp(interface, "org.bluez.Adapter1")) {
		DBusMessageIter addr_iter;
		char *str;

		rl_printf("Adapter property changed \n");
		if (g_dbus_proxy_get_property(proxy, "Address",
						&addr_iter) == TRUE) {
			const char *address;

			dbus_message_iter_get_basic(&addr_iter, &address);
			str = g_strdup_printf("[" COLORED_CHG
						"] Controller %s ", address);
		} else
			str = g_strdup("");

		if (strcmp(name, "Discovering") == 0) {
			int temp;

			dbus_message_iter_get_basic(iter, &temp);
			discovering = !!temp;
		}

		print_iter(str, name, iter);
		g_free(str);
	} else if (!strcmp(interface, "org.bluez.GattService1")) {
		rl_printf("Service property changed %s\n",
						g_dbus_proxy_get_path(proxy));
	} else if (!strcmp(interface, "org.bluez.GattCharacteristic1")) {
		rl_printf("Characteristic property changed %s\n",
						g_dbus_proxy_get_path(proxy));

		if ((strcmp(name, "Value") == 0) &&
				((connection.type == CONN_TYPE_PROVISION) ||
						connection.session_open))
			process_mesh_characteristic(proxy);
	}
}

static void message_handler(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	rl_printf("[SIGNAL] %s.%s\n", dbus_message_get_interface(message),
					dbus_message_get_member(message));
}

static struct adapter *find_ctrl_by_address(GList *source, const char *address)
{
	GList *list;

	for (list = g_list_first(source); list; list = g_list_next(list)) {
		struct adapter *adapter = list->data;
		DBusMessageIter iter;
		const char *str;

		if (g_dbus_proxy_get_property(adapter->proxy,
					"Address", &iter) == FALSE)
			continue;

		dbus_message_iter_get_basic(&iter, &str);

		if (!strcmp(str, address))
			return adapter;
	}

	return NULL;
}

static gboolean parse_argument_on_off(const char *arg, dbus_bool_t *value)
{
	if (!arg || !strlen(arg)) {
		rl_printf("Missing on/off argument\n");
		return FALSE;
	}

	if (!strcmp(arg, "on") || !strcmp(arg, "yes")) {
		*value = TRUE;
		return TRUE;
	}

	if (!strcmp(arg, "off") || !strcmp(arg, "no")) {
		*value = FALSE;
		return TRUE;
	}

	rl_printf("Invalid argument %s\n", arg);
	return FALSE;
}

static void cmd_list(const char *arg)
{
	GList *list;

	for (list = g_list_first(ctrl_list); list; list = g_list_next(list)) {
		struct adapter *adapter = list->data;
		print_adapter(adapter->proxy, NULL);
	}
}

static void cmd_show(const char *arg)
{
	struct adapter *adapter;
	GDBusProxy *proxy;
	DBusMessageIter iter;
	const char *address;


	if (!arg || !strlen(arg)) {
		if (check_default_ctrl() == FALSE)
			return;

		proxy = default_ctrl->proxy;
	} else {
		adapter = find_ctrl_by_address(ctrl_list, arg);
		if (!adapter) {
			rl_printf("Controller %s not available\n", arg);
			return;
		}
		proxy = adapter->proxy;
	}

	if (g_dbus_proxy_get_property(proxy, "Address", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &address);
	rl_printf("Controller %s\n", address);

	print_property(proxy, "Name");
	print_property(proxy, "Alias");
	print_property(proxy, "Class");
	print_property(proxy, "Powered");
	print_property(proxy, "Discoverable");
	print_uuids(proxy);
	print_property(proxy, "Modalias");
	print_property(proxy, "Discovering");
}

static void cmd_select(const char *arg)
{
	struct adapter *adapter;

	if (!arg || !strlen(arg)) {
		rl_printf("Missing controller address argument\n");
		return;
	}

	adapter = find_ctrl_by_address(ctrl_list, arg);
	if (!adapter) {
		rl_printf("Controller %s not available\n", arg);
		return;
	}

	if (default_ctrl && default_ctrl->proxy == adapter->proxy)
		return;

	forget_mesh_devices();

	default_ctrl = adapter;
	print_adapter(adapter->proxy, NULL);
}

static void generic_callback(const DBusError *error, void *user_data)
{
	char *str = user_data;

	if (dbus_error_is_set(error))
		rl_printf("Failed to set %s: %s\n", str, error->name);
	else
		rl_printf("Changing %s succeeded\n", str);
}

static void cmd_power(const char *arg)
{
	dbus_bool_t powered;
	char *str;

	if (parse_argument_on_off(arg, &powered) == FALSE)
		return;

	if (check_default_ctrl() == FALSE)
		return;

	str = g_strdup_printf("power %s", powered == TRUE ? "on" : "off");

	if (g_dbus_proxy_set_property_basic(default_ctrl->proxy, "Powered",
					DBUS_TYPE_BOOLEAN, &powered,
					generic_callback, str, g_free) == TRUE)
		return;

	g_free(str);
}

static void cmd_scan(const char *arg)
{
	dbus_bool_t enable;
	const char *method;

	if (parse_argument_on_off(arg, &enable) == FALSE)
		return;

	if (check_default_ctrl() == FALSE)
		return;

	if (enable == TRUE) {
		method = "StartDiscovery";
	} else {
		method = "StopDiscovery";
	}

	if (g_dbus_proxy_method_call(default_ctrl->proxy, method,
				NULL, start_discovery_reply,
				GUINT_TO_POINTER(enable), NULL) == FALSE) {
		rl_printf("Failed to %s discovery\n",
					enable == TRUE ? "start" : "stop");
		return;
	}
}

static void append_variant(DBusMessageIter *iter, int type, void *val)
{
	DBusMessageIter value;
	char sig[2] = { type, '\0' };

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, sig, &value);

	dbus_message_iter_append_basic(&value, type, val);

	dbus_message_iter_close_container(iter, &value);
}

static void append_array_variant(DBusMessageIter *iter, int type, void *val,
							int n_elements)
{
	DBusMessageIter variant, array;
	char type_sig[2] = { type, '\0' };
	char array_sig[3] = { DBUS_TYPE_ARRAY, type, '\0' };

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
						array_sig, &variant);

	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						type_sig, &array);

	if (dbus_type_is_fixed(type) == TRUE) {
		dbus_message_iter_append_fixed_array(&array, type, val,
							n_elements);
	} else if (type == DBUS_TYPE_STRING || type == DBUS_TYPE_OBJECT_PATH) {
		const char ***str_array = val;
		int i;

		for (i = 0; i < n_elements; i++)
			dbus_message_iter_append_basic(&array, type,
							&((*str_array)[i]));
	}

	dbus_message_iter_close_container(&variant, &array);

	dbus_message_iter_close_container(iter, &variant);
}

static void dict_append_entry(DBusMessageIter *dict, const char *key,
							int type, void *val)
{
	DBusMessageIter entry;

	if (type == DBUS_TYPE_STRING) {
		const char *str = *((const char **) val);

		if (str == NULL)
			return;
	}

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	append_variant(&entry, type, val);

	dbus_message_iter_close_container(dict, &entry);
}

static void dict_append_basic_array(DBusMessageIter *dict, int key_type,
					const void *key, int type, void *val,
					int n_elements)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
						NULL, &entry);

	dbus_message_iter_append_basic(&entry, key_type, key);

	append_array_variant(&entry, type, val, n_elements);

	dbus_message_iter_close_container(dict, &entry);
}

static void dict_append_array(DBusMessageIter *dict, const char *key, int type,
						void *val, int n_elements)
{
	dict_append_basic_array(dict, DBUS_TYPE_STRING, &key, type, val,
								n_elements);
}

#define	DISTANCE_VAL_INVALID	0x7FFF

struct set_discovery_filter_args {
	char *transport;
	dbus_uint16_t rssi;
	dbus_int16_t pathloss;
	char **uuids;
	size_t uuids_len;
	dbus_bool_t duplicate;
};

static void set_discovery_filter_setup(DBusMessageIter *iter, void *user_data)
{
	struct set_discovery_filter_args *args = user_data;
	DBusMessageIter dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dict_append_array(&dict, "UUIDs", DBUS_TYPE_STRING, &args->uuids,
							args->uuids_len);

	if (args->pathloss != DISTANCE_VAL_INVALID)
		dict_append_entry(&dict, "Pathloss", DBUS_TYPE_UINT16,
						&args->pathloss);

	if (args->rssi != DISTANCE_VAL_INVALID)
		dict_append_entry(&dict, "RSSI", DBUS_TYPE_INT16, &args->rssi);

	if (args->transport != NULL)
		dict_append_entry(&dict, "Transport", DBUS_TYPE_STRING,
						&args->transport);
	if (args->duplicate)
		dict_append_entry(&dict, "DuplicateData", DBUS_TYPE_BOOLEAN,
						&args->duplicate);

	dbus_message_iter_close_container(iter, &dict);
}


static void set_discovery_filter_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);
	if (dbus_set_error_from_message(&error, message) == TRUE) {
		rl_printf("SetDiscoveryFilter failed: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	rl_printf("SetDiscoveryFilter success\n");
}

static gint filtered_scan_rssi = DISTANCE_VAL_INVALID;
static gint filtered_scan_pathloss = DISTANCE_VAL_INVALID;
static char **filtered_scan_uuids;
static size_t filtered_scan_uuids_len;
static char *filtered_scan_transport = "le";

static void set_scan_filter_commit(void)
{
	struct set_discovery_filter_args args;

	args.pathloss = filtered_scan_pathloss;
	args.rssi = filtered_scan_rssi;
	args.transport = filtered_scan_transport;
	args.uuids = filtered_scan_uuids;
	args.uuids_len = filtered_scan_uuids_len;
	args.duplicate = TRUE;

	if (check_default_ctrl() == FALSE)
		return;

	if (g_dbus_proxy_method_call(default_ctrl->proxy, "SetDiscoveryFilter",
		set_discovery_filter_setup, set_discovery_filter_reply,
		&args, NULL) == FALSE) {
		rl_printf("Failed to set discovery filter\n");
		return;
	}
}

static void set_scan_filter_uuids(const char *arg)
{
	g_strfreev(filtered_scan_uuids);
	filtered_scan_uuids = NULL;
	filtered_scan_uuids_len = 0;

	if (!arg || !strlen(arg))
		goto commit;

	rl_printf("set_scan_filter_uuids %s\n", arg);
	filtered_scan_uuids = g_strsplit(arg, " ", -1);
	if (!filtered_scan_uuids) {
		rl_printf("Failed to parse input\n");
		return;
	}

	filtered_scan_uuids_len = g_strv_length(filtered_scan_uuids);

commit:
	set_scan_filter_commit();
}

static void cmd_scan_unprovisioned_devices(const char *arg)
{
	dbus_bool_t enable;

	if (parse_argument_on_off(arg, &enable) == FALSE)
		return;

	if (enable == TRUE) {
		discover_mesh = false;
		set_scan_filter_uuids(MESH_PROV_SVC_UUID);
	}
	cmd_scan(arg);
}

static void cmd_info(const char *arg)
{
	GDBusProxy *proxy;
	DBusMessageIter iter;
	const char *address;

	proxy = connection.device;
	if (!proxy)
		return;

	if (g_dbus_proxy_get_property(proxy, "Address", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &address);
	rl_printf("Device %s\n", address);

	print_property(proxy, "Name");
	print_property(proxy, "Alias");
	print_property(proxy, "Class");
	print_property(proxy, "Appearance");
	print_property(proxy, "Icon");
	print_property(proxy, "Trusted");
	print_property(proxy, "Blocked");
	print_property(proxy, "Connected");
	print_uuids(proxy);
	print_property(proxy, "Modalias");
	print_property(proxy, "ManufacturerData");
	print_property(proxy, "ServiceData");
	print_property(proxy, "RSSI");
	print_property(proxy, "TxPower");
}

static const char *security2str(uint8_t level)
{
	switch (level) {
	case 0:
		return "low";
	case 1:
		return "medium";
	case 2:
		return "high";
	default:
		return "invalid";
	}
}

static void cmd_security(const char *arg)
{
	uint8_t level;
	char *end;

	if (!arg || arg[0] == '\0') {
		level = prov_get_sec_level();
		goto done;
	}

	level = strtol(arg, &end, 10);
	if (end == arg || !prov_set_sec_level(level)) {
		rl_printf("Invalid security level %s\n", arg);
		return;
	}

done:
	rl_printf("Provision Security Level set to %u (%s)\n", level,
						security2str(level));
}

static void cmd_connect(const char *arg)
{
	if (check_default_ctrl() == FALSE)
		return;

	memset(&connection, 0, sizeof(connection));

	if (!arg || !strlen(arg)) {
		connection.net_idx = NET_IDX_PRIMARY;
	} else {
		char *end;
		connection.net_idx = strtol(arg, &end, 16);
		if (end == arg) {
			connection.net_idx = NET_IDX_INVALID;
			rl_printf("Invalid network index %s\n", arg);
			return;
		}
	}

	if (discovering)
		g_dbus_proxy_method_call(default_ctrl->proxy, "StopDiscovery",
						NULL, NULL, NULL, NULL);

	set_scan_filter_uuids(MESH_PROXY_SVC_UUID);
	discover_mesh = true;

	connection.type = CONN_TYPE_NETWORK;


	rl_printf("Looking for mesh network with net index %4.4x\n",
							connection.net_idx);

	if (g_dbus_proxy_method_call(default_ctrl->proxy,
			"StartDiscovery", NULL, start_discovery_reply,
				GUINT_TO_POINTER(TRUE), NULL) == FALSE)
		rl_printf("Failed to start mesh proxy discovery\n");

	g_dbus_proxy_method_call(default_ctrl->proxy, "StartDiscovery",
						NULL, NULL, NULL, NULL);

}

static void prov_disconn_reply(DBusMessage *message, void *user_data)
{
	struct mesh_node *node = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		rl_printf("Failed to disconnect: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	set_connected_device(NULL);

	set_scan_filter_uuids(MESH_PROXY_SVC_UUID);
	discover_mesh = true;

	connection.type = CONN_TYPE_IDENTITY;
	connection.data_in = NULL;
	connection.data_out = NULL;
	connection.unicast = node_get_primary(node);

	if (g_dbus_proxy_method_call(default_ctrl->proxy,
			"StartDiscovery", NULL, start_discovery_reply,
				GUINT_TO_POINTER(TRUE), NULL) == FALSE)
		rl_printf("Failed to start mesh proxy discovery\n");

}

static void disconn_reply(DBusMessage *message, void *user_data)
{
	GDBusProxy *proxy = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		rl_printf("Failed to disconnect: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	rl_printf("Successfully disconnected\n");

	if (proxy != connection.device)
		return;

	set_connected_device(NULL);
}

static void cmd_disconn(const char *arg)
{
	if (connection.type == CONN_TYPE_PROVISION) {
		struct mesh_node *node = node_find_by_uuid(connection.dev_uuid);
		if (node)
			node_free(node);
	}

	disconnect_device(disconn_reply, connection.device);
}

static void mesh_prov_done(void *user_data, int status)
{
	struct mesh_node *node = user_data;

	if (status){
		rl_printf("Provisioning failed\n");
		node_free(node);
		disconnect_device(NULL, NULL);
		return;
	}

	rl_printf("Provision success. Assigned Primary Unicast %4.4x\n",
						node_get_primary(node));

	if (!prov_db_add_new_node(node))
		rl_printf("Failed to add node to provisioning DB\n");

	disconnect_device(prov_disconn_reply, node);
}

static void cmd_start_prov(const char *arg)
{
	GDBusProxy *proxy;
	struct mesh_device *dev;
	struct mesh_node *node;
	int len;

	if (!arg) {
		rl_printf("Mesh Device UUID is required\n");
		return;
	}

	len = strlen(arg);
	if ( len > 32 || len % 2) {
		rl_printf("Incorrect UUID size %d\n", len);
	}

	disconnect_device(NULL, NULL);

	memset(connection.dev_uuid, 0, 16);
	str2hex(arg, len, connection.dev_uuid, len/2);

	node = node_find_by_uuid(connection.dev_uuid);
	if (!node) {
		rl_printf("Device with UUID %s not found.\n", arg);
		rl_printf("Stale services? Remove device and re-discover\n");
		return;
	}

	/* TODO: add command to remove a node from mesh, i.e., "unprovision" */
	if (node_is_provisioned(node)) {
		rl_printf("Already provisioned with unicast %4.4x\n",
				node_get_primary(node));
		return;
	}

	dev = find_device_by_uuid(default_ctrl->mesh_devices,
				  connection.dev_uuid);
	if (!dev || !dev->proxy) {
		rl_printf("Could not find device proxy\n");
		memset(connection.dev_uuid, 0, 16);
		return;
	}

	proxy = dev->proxy;
	if (discovering)
		g_dbus_proxy_method_call(default_ctrl->proxy, "StopDiscovery",
						NULL, NULL, NULL, NULL);
	forget_mesh_devices();

	connection.type = CONN_TYPE_PROVISION;

	if (g_dbus_proxy_method_call(proxy, "Connect", NULL, connect_reply,
							proxy, NULL) == FALSE) {
		rl_printf("Failed to connect ");
		print_device(proxy, NULL);
		return;
	} else {
		rl_printf("Trying to connect ");
		print_device(proxy, NULL);
	}

}

static void cmd_config(const char *arg)
{
	rl_printf("Switching to Mesh Client configuration menu\n");

	if (!switch_cmd_menu("configure"))
		return;

	set_menu_prompt("config", NULL);

	if (arg && strlen(arg))
		config_set_node(arg);
}

static void cmd_onoff_cli(const char *arg)
{
	rl_printf("Switching to Mesh Generic ON OFF Client menu\n");

	if (!switch_cmd_menu("onoff"))
		return;

	set_menu_prompt("on/off", NULL);

	if (arg && strlen(arg))
		onoff_set_node(arg);
}

static void cmd_print_mesh(const char *arg)
{
	if (!prov_db_show(mesh_prov_db_filename))
		rl_printf("Unavailable\n");

}

 static void cmd_print_local(const char *arg)
{
	if (!prov_db_show(mesh_local_config_filename))
		rl_printf("Unavailable\n");
}

static void disc_quit_cb(DBusMessage *message, void *user_data)
{
	g_main_loop_quit(main_loop);
}

static void cmd_quit(const char *arg)
{
	if (connection.device) {
		disconnect_device(disc_quit_cb, NULL);
		return;
	}

	g_main_loop_quit(main_loop);
}

static const struct menu_entry meshctl_cmd_table[] = {
	{ "list",         NULL,       cmd_list, "List available controllers"},
	{ "show",         "[ctrl]",   cmd_show, "Controller information"},
	{ "select",       "<ctrl>",   cmd_select, "Select default controller"},
	{ "security",     "[0(low)/1(medium)/2(high)]", cmd_security,
				"Display or change provision security level"},
	{ "info",         "[dev]",    cmd_info, "Device information"},
	{ "connect",      "[net_idx]",cmd_connect, "Connect to mesh network"},
	{ "discover-unprovisioned", "<on/off>", cmd_scan_unprovisioned_devices,
					"Look for devices to provision" },
	{ "provision",    "<uuid>",   cmd_start_prov, "Initiate provisioning"},
	{ "power",        "<on/off>", cmd_power, "Set controller power" },
	{ "disconnect",   "[dev]",    cmd_disconn, "Disconnect device"},
	{ "mesh-info",    NULL,       cmd_print_mesh,
					"Mesh networkinfo (provisioner)" },
	{ "local-info",    NULL,      cmd_print_local, "Local mesh node info" },
	{ "configure",    "[dst]",    cmd_config, "Config client model menu"},
	{ "onoff",        "[dst]",    cmd_onoff_cli,
						"Generic On/Off model menu"},
	{ "quit",         NULL,       cmd_quit, "Quit program" },
	{ "exit",         NULL,       cmd_quit },
	{ "help" },
	{ }
};

static void rl_handler(char *input)
{
	char *cmd, *arg;

	if (!input) {
		rl_insert_text("quit");
		rl_redisplay();
		rl_crlf();
		g_main_loop_quit(main_loop);
		return;
	}

	if (!strlen(input))
		goto done;
	else if (!strcmp(input, "q") || !strcmp(input, "quit")
						|| !strcmp(input, "exit")) {
		cmd_quit(NULL);
		goto done;
	}

	if (!rl_release_prompt(input))
		goto done;

	add_history(input);

	cmd = strtok_r(input, " \t\r\n", &arg);
	if (!cmd)
		goto done;

	process_menu_cmd(cmd, arg);

done:
	free(input);
}

static gboolean signal_handler(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	static bool terminated = false;
	struct signalfd_siginfo si;
	ssize_t result;
	int fd;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		g_main_loop_quit(main_loop);
		return FALSE;
	}

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, &si, sizeof(si));
	if (result != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGINT:
		if (input) {
			rl_replace_line("", 0);
			rl_crlf();
			rl_on_new_line();
			rl_redisplay();
			break;
		}

		/*
		 * If input was not yet setup up that means signal was received
		 * while daemon was not yet running. Since user is not able
		 * to terminate client by CTRL-D or typing exit treat this as
		 * exit and fall through.
		 */

		/* fall through */
	case SIGTERM:
		if (!terminated) {
			rl_replace_line("", 0);
			rl_crlf();
			g_main_loop_quit(main_loop);
		}

		terminated = true;
		break;
	}

	return TRUE;
}

static guint setup_signalfd(void)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("Failed to set signal mask");
		return 0;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		perror("Failed to create signal descriptor");
		return 0;
	}

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

static gboolean option_version = FALSE;
static const char *mesh_config_dir;

static GOptionEntry options[] = {
	{ "config", 'c', 0, G_OPTION_ARG_STRING, &mesh_config_dir,
			"Read local mesh config JSON files from <directory>" },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit" },
	{ NULL },
};

static void client_ready(GDBusClient *client, void *user_data)
{
	if (!input)
		input = setup_standard_input();
}

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	GDBusClient *client;
	guint signal;
	int len;
	int extra;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (g_option_context_parse(context, &argc, &argv, &error) == FALSE) {
		if (error != NULL) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		exit(1);
	}

	g_option_context_free(context);

	if (option_version == TRUE) {
		rl_printf("%s\n", VERSION);
		exit(0);
	}

	if (!mesh_config_dir) {
		rl_printf("Local config directory not provided.\n");
		mesh_config_dir = "";
	} else {
		rl_printf("Reading prov_db.json and local_node.json from %s\n",
							mesh_config_dir);
	}

	len = strlen(mesh_config_dir);
	if (len && mesh_config_dir[len - 1] != '/') {
		extra = 1;
		rl_printf("mesh_config_dir[%d] %s\n", len,
						&mesh_config_dir[len - 1]);
	} else {
		extra = 0;
	}
	mesh_local_config_filename = g_malloc(len + strlen("local_node.json")
									+ 2);
	if (!mesh_local_config_filename)
		exit(1);

	mesh_prov_db_filename = g_malloc(len + strlen("prov_db.json") + 2);
	if (!mesh_prov_db_filename) {
		exit(1);
	}

	sprintf(mesh_local_config_filename, "%s", mesh_config_dir);

	if (extra)
		sprintf(mesh_local_config_filename + len , "%c", '/');

	sprintf(mesh_local_config_filename + len + extra, "%s",
							"local_node.json");
	len = len + extra + strlen("local_node.json");
	sprintf(mesh_local_config_filename + len, "%c", '\0');

	if (!prov_db_read_local_node(mesh_local_config_filename, true)) {
		g_printerr("Failed to parse local node configuration file %s\n",
			mesh_local_config_filename);
		exit(1);
	}

	sprintf(mesh_prov_db_filename, "%s", mesh_config_dir);
	len = strlen(mesh_config_dir);
	if (extra)
		sprintf(mesh_prov_db_filename + len , "%c", '/');

	sprintf(mesh_prov_db_filename + len + extra, "%s", "prov_db.json");
	sprintf(mesh_prov_db_filename + len + extra + strlen("prov_db.json"),
								"%c", '\0');

	if (!prov_db_read(mesh_prov_db_filename)) {
		g_printerr("Failed to parse provisioning database file %s\n",
			mesh_prov_db_filename);
		exit(1);
	}

	main_loop = g_main_loop_new(NULL, FALSE);
	dbus_conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);

	setlinebuf(stdout);

	rl_erase_empty_line = 1;
	rl_callback_handler_install(NULL, rl_handler);

	rl_set_prompt(PROMPT_OFF);
	rl_redisplay();

	signal = setup_signalfd();
	client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");

	g_dbus_client_set_connect_watch(client, connect_handler, NULL);
	g_dbus_client_set_disconnect_watch(client, disconnect_handler, NULL);
	g_dbus_client_set_signal_watch(client, message_handler, NULL);

	g_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
							property_changed, NULL);

	g_dbus_client_set_ready_watch(client, client_ready, NULL);

	cmd_menu_init(meshctl_cmd_table);

	if (!config_client_init())
		g_printerr("Failed to initialize mesh configuration client\n");

	if (!config_server_init())
		g_printerr("Failed to initialize mesh configuration server\n");

	if (!onoff_client_init(PRIMARY_ELEMENT_IDX))
		g_printerr("Failed to initialize mesh generic On/Off client\n");

	g_main_loop_run(main_loop);

	g_dbus_client_unref(client);
	g_source_remove(signal);
	if (input > 0)
		g_source_remove(input);

	rl_message("");
	rl_callback_handler_remove();

	dbus_connection_unref(dbus_conn);
	g_main_loop_unref(main_loop);

	node_cleanup();

	g_list_free(char_list);
	g_list_free(service_list);
	g_list_free_full(ctrl_list, proxy_leak);

	rl_release_prompt("");

	return 0;
}
