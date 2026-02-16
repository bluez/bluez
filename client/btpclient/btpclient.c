// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2017  Intel Corporation. All rights reserved.
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
#include <signal.h>
#include <time.h>

#include <ell/ell.h>

#include "bluetooth/bluetooth.h"
#include "src/shared/btp.h"
#include "btpclient.h"
#include "core.h"
#include "gap.h"

static struct l_dbus *dbus;

static struct l_queue *adapters;

static char *socket_path;
static struct btp *btp;

static struct btp_agent ag;

struct l_queue *get_adapters_list(void)
{
	return adapters;
}

struct btp_agent *get_agent(void)
{
	return &ag;
}


static bool match_dev_addr_type(const char *addr_type_str, uint8_t addr_type)
{
	if (addr_type == BTP_GAP_ADDR_PUBLIC && strcmp(addr_type_str, "public"))
		return false;

	if (addr_type == BTP_GAP_ADDR_RANDOM && strcmp(addr_type_str, "random"))
		return false;

	return true;
}

struct btp_adapter *find_adapter_by_proxy(struct l_dbus_proxy *proxy)
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

struct btp_adapter *find_adapter_by_index(uint8_t index)
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

struct btp_adapter *find_adapter_by_path(const char *path)
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

struct btp_device *find_device_by_address(struct btp_adapter *adapter,
							const bdaddr_t *addr,
							uint8_t addr_type)
{
	const struct l_queue_entry *entry;
	const char *str;
	char addr_str[18];

	if (!ba2str(addr, addr_str))
		return NULL;

	for (entry = l_queue_get_entries(adapter->devices); entry;
							entry = entry->next) {
		struct btp_device *device = entry->data;

		l_dbus_proxy_get_property(device->proxy, "Address", "s", &str);
		if (strcmp(str, addr_str))
			continue;

		l_dbus_proxy_get_property(device->proxy, "AddressType", "s",
									&str);
		if (match_dev_addr_type(str, addr_type))
			return device;
	}

	return NULL;
}

static bool match_device_paths(const void *device, const void *path)
{
	const struct btp_device *dev = device;

	return !strcmp(l_dbus_proxy_get_path(dev->proxy), path);
}

struct btp_device *find_device_by_path(const char *path)
{
	const struct l_queue_entry *entry;
	struct btp_device *device;

	for (entry = l_queue_get_entries(adapters); entry;
							entry = entry->next) {
		struct btp_adapter *adapter = entry->data;

		device = l_queue_find(adapter->devices, match_device_paths,
									path);
		if (device)
			return device;
	}

	return NULL;
}

static bool match_adapter_dev_proxy(const void *device, const void *proxy)
{
	const struct btp_device *d = device;

	return d->proxy == proxy;
}

static bool match_adapter_dev(const void *device_a, const void *device_b)
{
	return device_a == device_b;
}

struct btp_adapter *find_adapter_by_device(struct btp_device *device)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(adapters); entry;
							entry = entry->next) {
		struct btp_adapter *adapter = entry->data;

		if (l_queue_find(adapter->devices, match_adapter_dev, device))
			return adapter;
	}

	return NULL;
}

struct btp_device *find_device_by_proxy(struct l_dbus_proxy *proxy)
{
	const struct l_queue_entry *entry;
	struct btp_device *device;

	for (entry = l_queue_get_entries(adapters); entry;
							entry = entry->next) {
		struct btp_adapter *adapter = entry->data;

		device = l_queue_find(adapter->devices, match_adapter_dev_proxy,
									proxy);

		if (device)
			return device;
	}

	return NULL;
}

static void signal_handler(uint32_t signo, void *user_data)
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

	/* TODO not all info is available via D-Bus API so some are assumed to
	 * be enabled by bluetoothd or simply hardcoded until API is extended
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

		adapter->default_settings = adapter->current_settings;

		l_queue_push_tail(adapters, adapter);
		return;
	}

	if (!strcmp(interface, "org.bluez.Device1")) {
		struct btp_adapter *adapter;
		struct btp_device *device;
		char *str, *str_addr, *str_addr_type;

		if (!l_dbus_proxy_get_property(proxy, "Adapter", "o", &str))
			return;

		adapter = find_adapter_by_path(str);
		if (!adapter)
			return;

		device = l_new(struct btp_device, 1);
		device->proxy = proxy;

		l_queue_push_tail(adapter->devices, device);

		if (!l_dbus_proxy_get_property(proxy, "Address", "s",
								&str_addr))
			return;

		if (!l_dbus_proxy_get_property(proxy, "AddressType", "s",
								&str_addr_type))
			return;

		device->address_type = strcmp(str_addr_type, "public") ?
							BTP_GAP_ADDR_RANDOM :
							BTP_GAP_ADDR_PUBLIC;
		if (str2ba(str_addr, &device->address) < 0)
			return;

		if (gap_is_service_registered())
			gap_proxy_added(proxy, user_data);

		return;
	}

	if (!strcmp(interface, "org.bluez.LEAdvertisingManager1")) {
		struct btp_adapter *adapter;

		adapter = find_adapter_by_path(path);
		if (!adapter)
			return;

		adapter->ad_proxy = proxy;

		return;
	}

	if (!strcmp(interface, "org.bluez.AgentManager1")) {
		ag.proxy = proxy;

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

static void property_changed(struct l_dbus_proxy *proxy, const char *name,
				struct l_dbus_message *msg, void *user_data)
{
	if (gap_is_service_registered())
		gap_property_changed(proxy, name, msg, user_data);
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

static void btp_disconnect_handler(struct btp *btp, void *user_data)
{
	l_info("btp disconnected");
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

	btp_set_disconnect_handler(btp, btp_disconnect_handler, NULL, NULL);

	core_register_service(btp, dbus, client);

	btp_send(btp, BTP_CORE_SERVICE, BTP_EV_CORE_READY,
					BTP_INDEX_NON_CONTROLLER, 0, NULL);
}

static void ready_callback(void *user_data)
{
	if (!l_dbus_object_manager_enable(dbus, "/"))
		l_info("Unable to register the ObjectManager");
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

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	l_dbus_set_ready_handler(dbus, ready_callback, NULL, NULL);
	client = l_dbus_client_new(dbus, "org.bluez", "/org/bluez");

	l_dbus_client_set_connect_handler(client, client_connected, NULL, NULL);
	l_dbus_client_set_disconnect_handler(client, client_disconnected, NULL,
									NULL);

	l_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
						property_changed, NULL, NULL);

	l_dbus_client_set_ready_handler(client, client_ready, NULL, NULL);

	l_main_run_with_signal(signal_handler, NULL);

	l_dbus_client_destroy(client);
	l_dbus_destroy(dbus);
	btp_cleanup(btp);

	l_queue_destroy(adapters, (l_queue_destroy_func_t)btp_adapter_free);

	l_free(socket_path);

	l_main_exit();

	return EXIT_SUCCESS;
}
