/*
 * Copyright (C) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>

#include <hardware/bluetooth.h>
#include <hardware/bt_sock.h>
#include <hardware/bt_hh.h>
#include <hardware/bt_pan.h>

#include <cutils/properties.h>

#include "hal-log.h"
#include "hal.h"
#include "hal-msg.h"

#define SERVICE_NAME "bluetoothd"
#define CONNECT_TIMEOUT (5 * 1000)

bt_callbacks_t *bt_hal_cbacks = NULL;

static int cmd_sk = -1;
static int notif_sk = -1;

static bool interface_ready(void)
{
	return bt_hal_cbacks != NULL;
}

static int accept_connection(int sk)
{
	int err;
	struct pollfd pfd;
	int new_sk;

	memset(&pfd, 0 , sizeof(pfd));
	pfd.fd = sk;
	pfd.events = POLLIN;

	err = poll(&pfd, 1, CONNECT_TIMEOUT);
	if (err < 0) {
		err = errno;
		error("Failed to poll: %d (%s)", err, strerror(err));
		return -1;
	}

	if (err == 0) {
		error("bluetoothd connect timeout");
		return -1;
	}

	new_sk = accept(sk, NULL, NULL);
	if (new_sk < 0) {
		err = errno;
		error("Failed to accept socket: %d (%s)", err, strerror(err));
		return -1;
	}

	return new_sk;
}

static bool start_daemon(void)
{
	struct sockaddr_un addr;
	int sk;
	int err;

	sk = socket(AF_LOCAL, SOCK_SEQPACKET, 0);
	if (sk < 0) {
		err = errno;
		error("Failed to create socket: %d (%s)", err,
							strerror(err));
		return false;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	memcpy(addr.sun_path, BLUEZ_HAL_SK_PATH, sizeof(BLUEZ_HAL_SK_PATH));

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		error("Failed to bind socket: %d (%s)", err, strerror(err));
		close(sk);
		return false;
	}

	if (listen(sk, 2) < 0) {
		err = errno;
		error("Failed to listen on socket: %d (%s)", err,
								strerror(err));
		close(sk);
		return false;
	}

	/* Start Android Bluetooth daemon service */
	property_set("ctl.start", SERVICE_NAME);

	cmd_sk = accept_connection(sk);
	if (cmd_sk < 0) {
		close(sk);
		return false;
	}

	notif_sk = accept_connection(sk);
	if (notif_sk < 0) {
		close(sk);
		close(cmd_sk);
		cmd_sk = -1;
		return false;
	}

	info("bluetoothd connected");

	close(sk);

	return true;
}

static void stop_daemon(void)
{
	close(cmd_sk);
	cmd_sk = -1;

	close(notif_sk);
	notif_sk = -1;
}

static int init(bt_callbacks_t *callbacks)
{
	DBG("");

	if (interface_ready())
		return BT_STATUS_SUCCESS;

	if (!start_daemon())
		return BT_STATUS_FAIL;

	bt_hal_cbacks = callbacks;

	return BT_STATUS_SUCCESS;
}

static int enable(void)
{
	DBG("");

	return BT_STATUS_UNSUPPORTED;
}

static int disable(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static void cleanup(void)
{
	DBG("");

	if (!interface_ready())
		return;

	stop_daemon();

	bt_hal_cbacks = NULL;
}

static int get_adapter_properties(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int get_adapter_property(bt_property_type_t type)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int set_adapter_property(const bt_property_t *property)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (property == NULL)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static int get_remote_device_properties(bt_bdaddr_t *remote_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int get_remote_device_property(bt_bdaddr_t *remote_addr,
						bt_property_type_t type)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int set_remote_device_property(bt_bdaddr_t *remote_addr,
						const bt_property_t *property)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int get_remote_service_record(bt_bdaddr_t *remote_addr, bt_uuid_t *uuid)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int get_remote_services(bt_bdaddr_t *remote_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int start_discovery(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int cancel_discovery(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int create_bond(const bt_bdaddr_t *bd_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static int cancel_bond(const bt_bdaddr_t *bd_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int remove_bond(const bt_bdaddr_t *bd_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int pin_reply(const bt_bdaddr_t *bd_addr, uint8_t accept,
				uint8_t pin_len, bt_pin_code_t *pin_code)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int ssp_reply(const bt_bdaddr_t *bd_addr, bt_ssp_variant_t variant,
					uint8_t accept, uint32_t passkey)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static const void *get_profile_interface(const char *profile_id)
{
	DBG("%s: %s", __func__, profile_id);

	if (!interface_ready())
		return NULL;

	if (!strcmp(profile_id, BT_PROFILE_SOCKETS_ID))
		return bt_get_sock_interface();

	if (!strcmp(profile_id, BT_PROFILE_HIDHOST_ID))
		return bt_get_hidhost_interface();

	if (!strcmp(profile_id, BT_PROFILE_PAN_ID))
		return bt_get_pan_interface();

	return NULL;
}

static int dut_mode_configure(uint8_t enable)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int dut_mode_send(uint16_t opcode, uint8_t *buf, uint8_t len)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static const bt_interface_t bluetooth_if = {
	.size = sizeof(bt_interface_t),
	.init = init,
	.enable = enable,
	.disable = disable,
	.cleanup = cleanup,
	.get_adapter_properties = get_adapter_properties,
	.get_adapter_property = get_adapter_property,
	.set_adapter_property = set_adapter_property,
	.get_remote_device_properties = get_remote_device_properties,
	.get_remote_device_property = get_remote_device_property,
	.set_remote_device_property = set_remote_device_property,
	.get_remote_service_record = get_remote_service_record,
	.get_remote_services = get_remote_services,
	.start_discovery = start_discovery,
	.cancel_discovery = cancel_discovery,
	.create_bond = create_bond,
	.remove_bond = remove_bond,
	.cancel_bond = cancel_bond,
	.pin_reply = pin_reply,
	.ssp_reply = ssp_reply,
	.get_profile_interface = get_profile_interface,
	.dut_mode_configure = dut_mode_configure,
	.dut_mode_send = dut_mode_send
};

static const bt_interface_t *get_bluetooth_interface(void)
{
	DBG("");

	return &bluetooth_if;
}

static int close_bluetooth(struct hw_device_t *device)
{
	DBG("");

	cleanup();

	return 0;
}

static int open_bluetooth(const struct hw_module_t *module, char const *name,
					struct hw_device_t **device)
{
	bluetooth_device_t *dev = malloc(sizeof(bluetooth_device_t));

	DBG("");

	memset(dev, 0, sizeof(bluetooth_device_t));
	dev->common.tag = HARDWARE_DEVICE_TAG;
	dev->common.version = 0;
	dev->common.module = (struct hw_module_t *) module;
	dev->common.close = close_bluetooth;
	dev->get_bluetooth_interface = get_bluetooth_interface;

	*device = (struct hw_device_t *) dev;

	return 0;
}

static struct hw_module_methods_t bluetooth_module_methods = {
	.open = open_bluetooth,
};

struct hw_module_t HAL_MODULE_INFO_SYM = {
	.tag = HARDWARE_MODULE_TAG,
	.version_major = 1,
	.version_minor = 0,
	.id = BT_HARDWARE_MODULE_ID,
	.name = "BlueZ Bluetooth stack",
	.author = "Intel Corporation",
	.methods = &bluetooth_module_methods
};
