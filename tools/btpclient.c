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
};

struct btp_device {
	struct l_dbus_proxy *proxy;
};

static struct l_queue *adapters;
static struct l_queue *devices;
static char *socket_path;
static struct btp *btp;

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

	btp_send(btp, BTP_CORE_SERVICE, BTP_OP_CORE_READ_SUPPORTED_SERVICES,
			BTP_INDEX_NON_CONTROLLER, sizeof(services), &services);
}

static void btp_core_register(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_CORE_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	btp_send_error(btp, BTP_CORE_SERVICE, index, BTP_ERROR_FAIL);
}

static void btp_core_unregister(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_CORE_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

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

static void btp_adapter_free(struct btp_adapter *adapter)
{
	l_free(adapter);
}

static void btp_device_free(struct btp_device *device)
{
	l_free(device);
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

		l_queue_push_tail(adapters, adapter);
		return;
	}

	if (!strcmp(interface, "org.bluez.Device1")) {
		struct btp_device *device;

		device = l_new(struct btp_device, 1);
		device->proxy = proxy;

		l_queue_push_tail(devices, device);
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
		l_queue_remove_if(devices, device_match_by_proxy, proxy);

		return;
	}
}

static void property_changed(struct l_dbus_proxy *proxy, const char *name,
				struct l_dbus_message *msg, void *user_data)
{
	l_info("property_changed %s %s %s", name, l_dbus_proxy_get_path(proxy),
			l_dbus_proxy_get_interface(proxy));
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
	devices = l_queue_new();

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

	l_queue_destroy(devices, (l_queue_destroy_func_t)btp_device_free);
	l_queue_destroy(adapters, (l_queue_destroy_func_t)btp_adapter_free);

	l_free(socket_path);

	l_main_exit();

	return EXIT_SUCCESS;
}
