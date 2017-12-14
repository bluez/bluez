/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2017  Intel Corporation. All rights reserved.
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
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <getopt.h>

#include <ell/ell.h>

#include "src/shared/btp.h"

struct btp_adapter {
	struct l_dbus_proxy *proxy;
	uint8_t index;
	uint32_t supported_settings;
	uint32_t current_settings;
	struct l_queue *devices;
};

struct btp_device {
	struct l_dbus_proxy *proxy;
};

static struct l_queue *adapters;
static char *socket_path;
static struct btp *btp;

static bool gap_service_registered;

static struct btp_adapter *find_adapter_by_proxy(struct l_dbus_proxy *proxy)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(adapters); entry;
							entry = entry->next) {
		struct btp_adapter *adapter = entry->data;

		if (adapter->proxy == proxy)
			return adapter;
	}

	return NULL;
}

static struct btp_adapter *find_adapter_by_index(uint8_t index)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(adapters); entry;
							entry = entry->next) {
		struct btp_adapter *adapter = entry->data;

		if (adapter->index == index)
			return adapter;
	}

	return NULL;
}

static struct btp_adapter *find_adapter_by_path(const char *path)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(adapters); entry;
							entry = entry->next) {
		struct btp_adapter *adapter = entry->data;

		if (!strcmp(l_dbus_proxy_get_path(adapter->proxy), path))
			return adapter;
	}

	return NULL;
}

static void btp_gap_read_commands(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	uint16_t commands = 0;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_GAP_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	commands |= (1 << BTP_OP_GAP_READ_SUPPORTED_COMMANDS);
	commands |= (1 << BTP_OP_GAP_READ_CONTROLLER_INDEX_LIST);
	commands |= (1 << BTP_OP_GAP_READ_COTROLLER_INFO);
	commands |= (1 << BTP_OP_GAP_RESET);
	commands |= (1 << BTP_OP_GAP_SET_POWERED);
	commands |= (1 << BTP_OP_GAP_SET_DISCOVERABLE);
	commands |= (1 << BTP_OP_GAP_SET_BONDABLE);

	commands = L_CPU_TO_LE16(commands);

	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_READ_SUPPORTED_COMMANDS,
			BTP_INDEX_NON_CONTROLLER, sizeof(commands), &commands);
}

static void btp_gap_read_controller_index(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	const struct l_queue_entry *entry;
	struct btp_gap_read_index_rp *rp;
	uint8_t cnt;
	int i;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_GAP_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	cnt = l_queue_length(adapters);

	rp = l_malloc(sizeof(*rp) + cnt);

	rp->num = cnt;

	for (i = 0, entry = l_queue_get_entries(adapters); entry;
						i++, entry = entry->next) {
		struct btp_adapter *adapter = entry->data;

		rp->indexes[i] = adapter->index;
	}

	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_READ_CONTROLLER_INDEX_LIST,
			BTP_INDEX_NON_CONTROLLER, sizeof(*rp) + cnt, rp);
}

static void btp_gap_read_info(uint8_t index, const void *param, uint16_t length,
								void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	struct btp_gap_read_info_rp rp;
	const char *str;
	uint8_t status = BTP_ERROR_FAIL;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	memset(&rp, 0, sizeof(rp));

	if (!l_dbus_proxy_get_property(adapter->proxy, "Address", "s", &str))
		goto failed;

	if (sscanf(str,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&rp.address[5], &rp.address[4], &rp.address[3],
			&rp.address[2], &rp.address[1], &rp.address[0]) != 6)
		goto failed;

	if (!l_dbus_proxy_get_property(adapter->proxy, "Name", "s", &str)) {
		goto failed;
	}

	strncpy((char *) rp.name, str, sizeof(rp.name));
	strncpy((char *) rp.short_name, str, sizeof(rp.short_name));
	rp.supported_settings = L_CPU_TO_LE32(adapter->supported_settings);
	rp.current_settings = L_CPU_TO_LE32(adapter->current_settings);

	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_READ_COTROLLER_INFO, index,
							sizeof(rp), &rp);

	return;
failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

static void remove_device_setup(struct l_dbus_message *message,
							void *user_data)
{
	struct btp_device *device = user_data;

	l_dbus_message_set_arguments(message, "o",
					l_dbus_proxy_get_path(device->proxy));
}

static void remove_device_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	struct btp_device *device = user_data;
	struct btp_adapter *adapter = find_adapter_by_proxy(proxy);

	if (!adapter)
		return;

	if (l_dbus_message_is_error(result)) {
		const char *name;

		l_dbus_message_get_error(result, &name, NULL);

		l_error("Failed to remove device %s (%s)",
					l_dbus_proxy_get_path(device->proxy),
					name);
		return;
	}

	l_queue_remove(adapter->devices, device);
}

static void btp_gap_reset(uint8_t index, const void *param, uint16_t length,
								void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct l_queue_entry *entry;
	uint8_t status;
	bool prop;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	/* Adapter needs to be powered to be able to remove devices */
	if (!l_dbus_proxy_get_property(adapter->proxy, "Powered", "b", &prop) ||
									!prop) {
		status = BTP_ERROR_FAIL;
		goto failed;
	}

	for (entry = l_queue_get_entries(adapter->devices); entry;
							entry = entry->next) {
		struct btp_device *device = entry->data;

		l_dbus_proxy_method_call(adapter->proxy, "RemoveDevice",
						remove_device_setup,
						remove_device_reply, device,
						NULL);
	}

	/* TODO for we assume all went well */
	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_RESET, index, 0, NULL);
	return;

failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

struct set_setting_data {
	struct btp_adapter *adapter;
	uint8_t opcode;
	uint32_t setting;
	bool value;
};

static void set_setting_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *result, void *user_data)
{
	struct set_setting_data *data = user_data;
	struct btp_adapter *adapter = data->adapter;
	uint32_t settings;

	if (l_dbus_message_is_error(result)) {
		btp_send_error(btp, BTP_GAP_SERVICE, data->adapter->index,
								BTP_ERROR_FAIL);
		return;
	}

	if (data->value)
		adapter->current_settings |= data->setting;
	else
		adapter->current_settings &= ~data->setting;

	settings = L_CPU_TO_LE32(adapter->current_settings);

	btp_send(btp, BTP_GAP_SERVICE, data->opcode, adapter->index,
						sizeof(settings), &settings);
}

static void btp_gap_set_powered(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_gap_set_powered_cp *cp = param;
	uint8_t status = BTP_ERROR_FAIL;
	struct set_setting_data *data;

	if (length < sizeof(*cp))
		goto failed;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	data = l_new(struct set_setting_data, 1);
	data->adapter = adapter;
	data->opcode = BTP_OP_GAP_SET_POWERED;
	data->setting = BTP_GAP_SETTING_POWERED;
	data->value = cp->powered;

	if (l_dbus_proxy_set_property(adapter->proxy, set_setting_reply,
					data, l_free, "Powered", "b",
					data->value))
		return;

	l_free(data);

failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

static void btp_gap_set_discoverable(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_gap_set_discoverable_cp *cp = param;
	uint8_t status = BTP_ERROR_FAIL;
	struct set_setting_data *data;

	if (length < sizeof(*cp))
		goto failed;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	data = l_new(struct set_setting_data, 1);
	data->adapter = adapter;
	data->opcode = BTP_OP_GAP_SET_DISCOVERABLE;
	data->setting = BTP_GAP_SETTING_DISCOVERABLE;
	data->value = cp->discoverable;

	if (l_dbus_proxy_set_property(adapter->proxy, set_setting_reply,
					data, l_free, "Discoverable", "b",
					data->value))
		return;

	l_free(data);

failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

static void btp_gap_set_bondable(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_gap_set_bondable_cp *cp = param;
	uint8_t status = BTP_ERROR_FAIL;
	struct set_setting_data *data;

	if (length < sizeof(*cp))
		goto failed;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	data = l_new(struct set_setting_data, 1);
	data->adapter = adapter;
	data->opcode = BTP_OP_GAP_SET_BONDABLE;
	data->setting = BTP_GAP_SETTING_BONDABLE;
	data->value = cp->bondable;

	if (l_dbus_proxy_set_property(adapter->proxy, set_setting_reply,
					data, l_free, "Pairable", "b",
					data->value))
		return;

	l_free(data);

failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

static void register_gap_service(void)
{
	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_READ_SUPPORTED_COMMANDS,
					btp_gap_read_commands, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE,
				BTP_OP_GAP_READ_CONTROLLER_INDEX_LIST,
				btp_gap_read_controller_index, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_READ_COTROLLER_INFO,
						btp_gap_read_info, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_RESET,
						btp_gap_reset, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_SET_POWERED,
					btp_gap_set_powered, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_SET_DISCOVERABLE,
					btp_gap_set_discoverable, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_SET_BONDABLE,
					btp_gap_set_bondable, NULL, NULL);
}

static void btp_core_read_commands(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	uint8_t commands = 0;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_CORE_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	commands |= (1 << BTP_OP_CORE_READ_SUPPORTED_COMMANDS);
	commands |= (1 << BTP_OP_CORE_READ_SUPPORTED_SERVICES);
	commands |= (1 << BTP_OP_CORE_REGISTER);
	commands |= (1 << BTP_OP_CORE_UNREGISTER);

	btp_send(btp, BTP_CORE_SERVICE, BTP_OP_CORE_READ_SUPPORTED_COMMANDS,
			BTP_INDEX_NON_CONTROLLER, sizeof(commands), &commands);
}

static void btp_core_read_services(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	uint8_t services = 0;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_CORE_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	services |= (1 << BTP_CORE_SERVICE);
	services |= (1 << BTP_GAP_SERVICE);

	btp_send(btp, BTP_CORE_SERVICE, BTP_OP_CORE_READ_SUPPORTED_SERVICES,
			BTP_INDEX_NON_CONTROLLER, sizeof(services), &services);
}

static void btp_core_register(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	const struct btp_core_register_cp  *cp = param;

	if (length < sizeof(*cp))
		goto failed;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_CORE_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	switch (cp->service_id) {
	case BTP_GAP_SERVICE:
		if (gap_service_registered)
			goto failed;

		register_gap_service();
		gap_service_registered = true;
		break;
	case BTP_GATT_SERVICE:
	case BTP_L2CAP_SERVICE:
	case BTP_MESH_NODE_SERVICE:
	case BTP_CORE_SERVICE:
	default:
		goto failed;
	}

	btp_send(btp, BTP_CORE_SERVICE, BTP_OP_CORE_REGISTER,
					BTP_INDEX_NON_CONTROLLER, 0, NULL);
	return;

failed:
	btp_send_error(btp, BTP_CORE_SERVICE, index, BTP_ERROR_FAIL);
}

static void btp_core_unregister(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	const struct btp_core_unregister_cp  *cp = param;

	if (length < sizeof(*cp))
		goto failed;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_CORE_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	switch (cp->service_id) {
	case BTP_GAP_SERVICE:
		if (!gap_service_registered)
			goto failed;

		btp_unregister_service(btp, BTP_GAP_SERVICE);
		gap_service_registered = false;
		break;
	case BTP_GATT_SERVICE:
	case BTP_L2CAP_SERVICE:
	case BTP_MESH_NODE_SERVICE:
	case BTP_CORE_SERVICE:
	default:
		goto failed;
	}

	btp_send(btp, BTP_CORE_SERVICE, BTP_OP_CORE_UNREGISTER,
					BTP_INDEX_NON_CONTROLLER, 0, NULL);
	return;

failed:
	btp_send_error(btp, BTP_CORE_SERVICE, index, BTP_ERROR_FAIL);
}

static void register_core_service(void)
{
	btp_register(btp, BTP_CORE_SERVICE,
					BTP_OP_CORE_READ_SUPPORTED_COMMANDS,
					btp_core_read_commands, NULL, NULL);

	btp_register(btp, BTP_CORE_SERVICE,
					BTP_OP_CORE_READ_SUPPORTED_SERVICES,
					btp_core_read_services, NULL, NULL);

	btp_register(btp, BTP_CORE_SERVICE, BTP_OP_CORE_REGISTER,
						btp_core_register, NULL, NULL);

	btp_register(btp, BTP_CORE_SERVICE, BTP_OP_CORE_UNREGISTER,
					btp_core_unregister, NULL, NULL);
}

static void signal_handler(struct l_signal *signal, uint32_t signo,
							void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminating");
		l_main_quit();
		break;
	}
}

static void btp_device_free(struct btp_device *device)
{
	l_free(device);
}

static void btp_adapter_free(struct btp_adapter *adapter)
{
	l_queue_destroy(adapter->devices,
				(l_queue_destroy_func_t)btp_device_free);
	l_free(adapter);
}

static void extract_settings(struct l_dbus_proxy *proxy, uint32_t *current,
						uint32_t *supported)
{
	bool prop;

	*supported = 0;
	*current = 0;

	/* TODO not all info is available via D-Bus API */
	*supported |=  BTP_GAP_SETTING_POWERED;
	*supported |=  BTP_GAP_SETTING_CONNECTABLE;
	*supported |=  BTP_GAP_SETTING_DISCOVERABLE;
	*supported |=  BTP_GAP_SETTING_BONDABLE;
	*supported |=  BTP_GAP_SETTING_SSP;
	*supported |=  BTP_GAP_SETTING_BREDR;
	*supported |=  BTP_GAP_SETTING_LE;
	*supported |=  BTP_GAP_SETTING_ADVERTISING;
	*supported |=  BTP_GAP_SETTING_SC;
	*supported |=  BTP_GAP_SETTING_PRIVACY;
	/* *supported |=  BTP_GAP_SETTING_STATIC_ADDRESS; */

	/* TODO not all info is availbe via D-Bus API so some are assumed to be
	 * enabled by bluetoothd or simply hardcoded until API is extended
	 */
	*current |=  BTP_GAP_SETTING_CONNECTABLE;
	*current |=  BTP_GAP_SETTING_SSP;
	*current |=  BTP_GAP_SETTING_BREDR;
	*current |=  BTP_GAP_SETTING_LE;
	*current |=  BTP_GAP_SETTING_PRIVACY;
	*current |=  BTP_GAP_SETTING_SC;
	/* *supported |=  BTP_GAP_SETTING_STATIC_ADDRESS; */

	if (l_dbus_proxy_get_property(proxy, "Powered", "b", &prop) && prop)
		*current |=  BTP_GAP_SETTING_POWERED;

	if (l_dbus_proxy_get_property(proxy, "Discoverable", "b", &prop) &&
									prop)
		*current |=  BTP_GAP_SETTING_DISCOVERABLE;

	if (l_dbus_proxy_get_property(proxy, "Pairable", "b", &prop) && prop)
		*current |=  BTP_GAP_SETTING_BONDABLE;
}

static void proxy_added(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	l_info("Proxy added: %s (%s)", interface, path);

	if (!strcmp(interface, "org.bluez.Adapter1")) {
		struct btp_adapter *adapter;

		adapter = l_new(struct btp_adapter, 1);
		adapter->proxy = proxy;
		adapter->index = l_queue_length(adapters);
		adapter->devices = l_queue_new();

		extract_settings(proxy, &adapter->current_settings,
						&adapter->supported_settings);

		l_queue_push_tail(adapters, adapter);
		return;
	}

	if (!strcmp(interface, "org.bluez.Device1")) {
		struct btp_adapter *adapter;
		struct btp_device *device;
		char *str;

		if (!l_dbus_proxy_get_property(proxy, "Adapter", "o", &str))
			return;

		adapter = find_adapter_by_path(str);
		if (!adapter)
			return;

		device = l_new(struct btp_device, 1);
		device->proxy = proxy;

		l_queue_push_tail(adapter->devices, device);
		return;
	}
}

static bool device_match_by_proxy(const void *a, const void *b)
{
	const struct btp_device *device = a;
	const struct l_dbus_proxy *proxy = b;

	return device->proxy == proxy;
}

static void proxy_removed(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	l_info("Proxy removed: %s (%s)", interface, path);

	if (!strcmp(interface, "org.bluez.Adapter1")) {
		l_info("Adapter removed, terminating.");
		l_main_quit();
		return;
	}

	if (!strcmp(interface, "org.bluez.Device1")) {
		struct btp_adapter *adapter;
		char *str;

		if (!l_dbus_proxy_get_property(proxy, "Adapter", "o", &str))
			return;

		adapter = find_adapter_by_path(str);
		if (!adapter)
			return;

		l_queue_remove_if(adapter->devices, device_match_by_proxy,
									proxy);

		return;
	}
}

static void update_current_settings(struct btp_adapter *adapter,
							uint32_t new_settings)
{
	struct btp_new_settings_ev ev;

	adapter->current_settings = new_settings;

	ev.current_settings = L_CPU_TO_LE32(adapter->current_settings);

	btp_send(btp, BTP_GAP_SERVICE, BTP_EV_GAP_NEW_SETTINGS, adapter->index,
							sizeof(ev), &ev);
}

static void property_changed(struct l_dbus_proxy *proxy, const char *name,
				struct l_dbus_message *msg, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	l_info("property_changed %s %s %s", name, path, interface);

	if (!strcmp(interface, "org.bluez.Adapter1")) {
		struct btp_adapter *adapter = find_adapter_by_proxy(proxy);
		uint32_t new_settings;

		if (!adapter)
			return;

		new_settings = adapter->current_settings;

		if (!strcmp(name, "Powered")) {
			bool prop;

			if (!l_dbus_message_get_arguments(msg, "b", &prop))
				return;

			if (prop)
				new_settings |= BTP_GAP_SETTING_POWERED;
			else
				new_settings &= ~BTP_GAP_SETTING_POWERED;
		} else if (!strcmp(name, "Discoverable")) {
			bool prop;

			if (!l_dbus_message_get_arguments(msg, "b", &prop))
				return;

			if (prop)
				new_settings |= BTP_GAP_SETTING_DISCOVERABLE;
			else
				new_settings &= ~BTP_GAP_SETTING_DISCOVERABLE;
		}

		if (!strcmp(name, "Pairable")) {
			bool prop;

			if (!l_dbus_message_get_arguments(msg, "b", &prop))
				return;

			if (prop)
				new_settings |= BTP_GAP_SETTING_BONDABLE;
			else
				new_settings &= ~BTP_GAP_SETTING_BONDABLE;
		}

		if (new_settings != adapter->current_settings)
			update_current_settings(adapter, new_settings);

		return;
	}
}

static void client_connected(struct l_dbus *dbus, void *user_data)
{
	l_info("D-Bus client connected");
}

static void client_disconnected(struct l_dbus *dbus, void *user_data)
{
	l_info("D-Bus client disconnected, terminated");
	l_main_quit();
}

static void client_ready(struct l_dbus_client *client, void *user_data)
{
	l_info("D-Bus client ready, connecting BTP");

	btp = btp_new(socket_path);
	if (!btp) {
		l_error("Failed to connect BTP, terminating");
		l_main_quit();
		return;
	}

	register_core_service();

	btp_send(btp, BTP_CORE_SERVICE, BTP_EV_CORE_READY,
					BTP_INDEX_NON_CONTROLLER, 0, NULL);
}

static void usage(void)
{
	l_info("btpclient - Bluetooth tester");
	l_info("Usage:");
	l_info("\tbtpclient [options]");
	l_info("options:\n"
	"\t-s, --socket <socket>  Socket to use for BTP\n"
	"\t-q, --quiet            Don't emit any logs\n"
	"\t-v, --version          Show version\n"
	"\t-h, --help             Show help options");
}

static const struct option options[] = {
	{ "socket",	1, 0, 's' },
	{ "quiet",	0, 0, 'q' },
	{ "version",	0, 0, 'v' },
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct l_dbus_client *client;
	struct l_signal *signal;
	struct l_dbus *dbus;
	sigset_t mask;
	int opt;

	l_log_set_stderr();

	while ((opt = getopt_long(argc, argv, "+hs:vq", options, NULL)) != -1) {
		switch (opt) {
		case 's':
			socket_path = l_strdup(optarg);
			break;
		case 'q':
			l_log_set_null();
			break;
		case 'd':
			break;
		case 'v':
			l_info("%s", VERSION);
			return EXIT_SUCCESS;
		case 'h':
		default:
			usage();
			return EXIT_SUCCESS;
		}
	}

	if (!socket_path) {
		l_info("Socket option is required");
		l_info("Type --help for usage");
		return EXIT_FAILURE;
	}

	if (!l_main_init())
		return EXIT_FAILURE;


	adapters = l_queue_new();

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	client = l_dbus_client_new(dbus, "org.bluez", "/org/bluez");

	l_dbus_client_set_connect_handler(client, client_connected, NULL, NULL);
	l_dbus_client_set_disconnect_handler(client, client_disconnected, NULL,
									NULL);

	l_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
						property_changed, NULL, NULL);

	l_dbus_client_set_ready_handler(client, client_ready, NULL, NULL);

	l_main_run();

	l_dbus_client_destroy(client);
	l_dbus_destroy(dbus);
	l_signal_remove(signal);
	btp_cleanup(btp);

	l_queue_destroy(adapters, (l_queue_destroy_func_t)btp_adapter_free);

	l_free(socket_path);

	l_main_exit();

	return EXIT_SUCCESS;
}
