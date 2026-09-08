// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Collabora Ltd.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include <ell/ell.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"
#include "src/shared/btp.h"
#include "btpclient.h"
#include "bap.h"

static struct btp *btp;
static bool bap_service_registered;

static void btp_bap_read_commands(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	const uint8_t supported_commands[] = {
		BTP_OP_BAP_READ_SUPPORTED_COMMANDS,
		BTP_OP_BAP_DISCOVER,
	};
	uint8_t *commands = NULL;
	size_t commands_len = 0;
	size_t i;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_BAP_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	for (i = 0; i < L_ARRAY_SIZE(supported_commands); i++) {
		if (!add_supported_command(&commands, &commands_len,
						supported_commands[i]))
			goto failed;
	}

	btp_send(btp, BTP_BAP_SERVICE, BTP_OP_BAP_READ_SUPPORTED_COMMANDS,
			BTP_INDEX_NON_CONTROLLER, commands_len, commands);

	l_free(commands);

	return;

failed:
	l_free(commands);
	btp_send_error(btp, BTP_BAP_SERVICE, index, BTP_ERROR_FAIL);
}

static void btp_bap_discover(uint8_t index, const void *param, uint16_t length,
								void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_bap_discover_cp *cp = param;
	uint8_t status = BTP_ERROR_FAIL;
	struct btp_device *dev;
	struct btp_bap_discovery_completed_ev ev;
	bool prop;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	btp_send(btp, BTP_BAP_SERVICE, BTP_OP_BAP_DISCOVER, index, 0, NULL);

	dev = find_device_by_address(adapter, &cp->address, cp->address_type);

	/* Services should have been resolved during connection */
	if (!l_dbus_proxy_get_property(dev->proxy, "ServicesResolved", "b",
					&prop) || !prop)
		goto failed;

	memcpy(&ev.address, &dev->address, sizeof(ev.address));
	ev.address_type = dev->address_type;
	ev.status = 0;

	btp_send(btp, BTP_BAP_SERVICE, BTP_EV_BAP_DISCOVERY_COMPLETED,
			adapter->index, sizeof(ev), &ev);

	return;

failed:
	btp_send_error(btp, BTP_BAP_SERVICE, index, status);
}

static void bap_charac_read_setup(struct l_dbus_message *message,
							void *user_data)
{
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(message);
	l_dbus_message_builder_enter_array(builder, "{sv}");
	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_leave_dict(builder);
	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void bap_read_ase_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	struct btp_ase *ase = user_data;
	struct btp_device *device = ase->device;
	struct btp_adapter *adapter = find_adapter_by_device(device);
	struct btp_bap_ase_found_ev *rp;
	struct l_dbus_message_iter iter;
	uint8_t *data;
	uint32_t n;

	if (l_dbus_message_is_error(result)) {
		const char *name, *desc;

		l_dbus_message_get_error(result, &name, &desc);
		l_error("Failed to read value (%s), %s", name, desc);

		btp_send_error(btp, BTP_BAP_SERVICE, adapter->index,
							BTP_ERROR_FAIL);
		return;
	}

	if (!l_dbus_message_get_arguments(result, "ay", &iter))
		goto failed;

	if (!l_dbus_message_iter_get_fixed_array(&iter, &data, &n)) {
		l_debug("Cannot read value");
		goto failed;
	}

	ase->ase_id = data[0];

	rp = l_new(struct btp_bap_ase_found_ev, 1);
	rp->address_type = device->address_type;
	rp->address = device->address;
	rp->dir = ase->dir;
	rp->ase_id = data[0];

	btp_send(btp, BTP_BAP_SERVICE, BTP_EV_BAP_ASE_FOUND, adapter->index,
				sizeof(struct btp_bap_ase_found_ev), rp);

	free(rp);

	return;

failed:
	btp_send_error(btp, BTP_BAP_SERVICE, adapter->index, BTP_ERROR_FAIL);
}

void bap_proxy_added(struct l_dbus_proxy *proxy, void *user_data)
{
	struct btp_device *device = user_data;
	const char *interface = l_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.GattCharacteristic1")) {
		char *str, str_uuid[MAX_LEN_UUID_STR];
		bt_uuid_t uuid;
		struct btp_ase *ase;

		if (!l_dbus_proxy_get_property(proxy, "UUID", "s", &str))
			return;

		bt_uuid16_create(&uuid, ASE_SINK_UUID);
		bt_uuid_to_string(&uuid, str_uuid, MAX_LEN_UUID_STR);
		if (!bt_uuid_strcmp(str, str_uuid)) {
			ase = l_new(struct btp_ase, 1);
			ase->device = device;
			ase->dir = BTP_BAP_DIR_SINK;
			ase->uuid = uuid;
			l_queue_push_tail(device->ases, ase);

			l_dbus_proxy_method_call(proxy, "ReadValue",
						bap_charac_read_setup,
						bap_read_ase_reply,
						ase, NULL);
		}

		bt_uuid16_create(&uuid, ASE_SOURCE_UUID);
		bt_uuid_to_string(&uuid, str_uuid, MAX_LEN_UUID_STR);
		if (!bt_uuid_strcmp(str, str_uuid)) {
			ase = l_new(struct btp_ase, 1);
			ase->device = device;
			ase->dir = BTP_BAP_DIR_SOURCE;
			ase->uuid = uuid;
			l_queue_push_tail(device->ases, ase);

			l_dbus_proxy_method_call(proxy, "ReadValue",
						bap_charac_read_setup,
						bap_read_ase_reply,
						ase, NULL);
		}
	}
}

bool bap_register_service(struct btp *btp_, struct l_dbus *dbus_,
					struct l_dbus_client *client)
{
	btp = btp_;

	btp_register(btp, BTP_BAP_SERVICE, BTP_OP_BAP_READ_SUPPORTED_COMMANDS,
					btp_bap_read_commands, NULL, NULL);

	btp_register(btp, BTP_BAP_SERVICE, BTP_OP_BAP_DISCOVER,
					btp_bap_discover, NULL, NULL);

	bap_service_registered = true;

	return true;
}

void bap_unregister_service(struct btp *btp)
{
	btp_unregister_service(btp, BTP_BAP_SERVICE);
	bap_service_registered = false;
}

bool bap_is_service_registered(void)
{
	return bap_service_registered;
}
