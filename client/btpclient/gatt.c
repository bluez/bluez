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
#include "gatt.h"

static struct btp *btp;
static bool gatt_service_registered;

static int create_uuid(bt_uuid_t *btuuid, uint8_t len, const uint8_t *data)
{
	if (len == 2)
		bt_uuid16_create(btuuid, bt_get_le16(data));
	else if (len == 4)
		bt_uuid32_create(btuuid, bt_get_le32(data));
	else if (len == 16) {
		uint128_t uint128;

		btoh128((uint128_t *)data, &uint128);
		bt_uuid128_create(btuuid, uint128);
	} else
		return -EINVAL;

	return 0;
}

static void btp_gatt_read_commands(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	uint16_t commands = 0;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_GATT_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	commands |= (1 << BTP_OP_GATT_READ_SUPPORTED_COMMANDS);
	commands |= (1 << BTP_OP_GATT_READ_UUID);

	commands = L_CPU_TO_LE16(commands);

	btp_send(btp, BTP_GATT_SERVICE, BTP_OP_GATT_READ_SUPPORTED_COMMANDS,
			BTP_INDEX_NON_CONTROLLER, sizeof(commands), &commands);
}

static bool match_attribute_uuid(const void *attr, const void *uuid)
{
	const struct gatt_attribute *attribute = attr;

	return !bt_uuid_cmp(&attribute->uuid, uuid);
}

static void gatt_read_setup(struct l_dbus_message *message,
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

static void gatt_read_uuid_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	struct btp_adapter *adapter = user_data;
	struct btp_gatt_read_uuid_rp *rp;
	struct l_dbus_message_iter iter;
	uint8_t *data;
	uint32_t n;
	uint16_t handle, rp_len;
	struct btp_gatt_char_value *value;

	if (l_dbus_message_is_error(result)) {
		const char *name, *desc;

		l_dbus_message_get_error(result, &name, &desc);
		l_error("Failed to read value (%s), %s", name, desc);

		btp_send_error(btp, BTP_GATT_SERVICE, adapter->index,
							BTP_ERROR_FAIL);
		return;
	}

	if (!l_dbus_message_get_arguments(result, "ay", &iter))
		goto failed;

	if (!l_dbus_message_iter_get_fixed_array(&iter, &data, &n)) {
		l_debug("Cannot read value");
		goto failed;
	}

	if (!l_dbus_proxy_get_property(proxy, "Handle", "q", &handle))
		goto failed;

	rp_len = sizeof(struct btp_gatt_read_uuid_rp) +
				sizeof(struct btp_gatt_char_value) + n;
	rp = malloc(rp_len);
	rp->att_response = 0;
	rp->values_count = 1;
	value = rp->values;
	value->handle = handle;
	value->data_len = n;
	memcpy(value->data, data, n);

	btp_send(btp, BTP_GATT_SERVICE, BTP_OP_GATT_READ_UUID, adapter->index,
								rp_len, rp);

	free(rp);

	return;

failed:
	btp_send_error(btp, BTP_GATT_SERVICE, adapter->index, BTP_ERROR_FAIL);
}

static void btp_gatt_read_uuid(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	struct btp_device *device;
	const struct btp_gatt_read_uuid_cp *cp = param;
	uint8_t status = BTP_ERROR_FAIL;
	bool prop;
	bt_uuid_t uuid;
	struct gatt_attribute *attribute;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	/* Adapter needs to be powered to be able to read UUID */
	if (!l_dbus_proxy_get_property(adapter->proxy, "Powered", "b",
					&prop) || !prop) {
		goto failed;
	}

	device = find_device_by_address(adapter, &cp->address,
							cp->address_type);
	if (!device)
		goto failed;

	if (create_uuid(&uuid, cp->uuid_len, cp->uuid))
		goto failed;

	attribute = l_queue_find(device->characteristics, match_attribute_uuid,
								&uuid);
	if (!attribute)
		attribute = l_queue_find(device->descriptors,
							match_attribute_uuid,
							&uuid);

	if (!attribute)
		goto failed;

	l_dbus_proxy_method_call(attribute->proxy, "ReadValue",
					gatt_read_setup, gatt_read_uuid_reply,
					adapter, NULL);

	return;

failed:
	btp_send_error(btp, BTP_GATT_SERVICE, index, status);
}

bool gatt_register_service(struct btp *btp_, struct l_dbus *dbus_,
					struct l_dbus_client *client)
{
	btp = btp_;

	btp_register(btp, BTP_GATT_SERVICE, BTP_OP_GATT_READ_SUPPORTED_COMMANDS,
					btp_gatt_read_commands, NULL, NULL);

	btp_register(btp, BTP_GATT_SERVICE, BTP_OP_GATT_READ_UUID,
					btp_gatt_read_uuid, NULL, NULL);

	gatt_service_registered = true;

	return true;
}

void gatt_unregister_service(struct btp *btp)
{
	btp_unregister_service(btp, BTP_GATT_SERVICE);
	gatt_service_registered = false;
}

bool gatt_is_service_registered(void)
{
	return gatt_service_registered;
}
