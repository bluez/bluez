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
	uint16_t commands = 0;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_BAP_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	commands |= (1 << BTP_OP_BAP_READ_SUPPORTED_COMMANDS);
	commands |= (1 << BTP_OP_BAP_DISCOVER);

	commands = L_CPU_TO_LE16(commands);

	btp_send(btp, BTP_BAP_SERVICE, BTP_OP_BAP_READ_SUPPORTED_COMMANDS,
			BTP_INDEX_NON_CONTROLLER, sizeof(commands), &commands);
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
