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

#include <ell/ell.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"
#include "src/shared/btp.h"
#include "btpclient.h"
#include "ascs.h"
#include "vendor.h"

static struct btp *btp;
static bool vendor_service_registered;

static void btp_vendor_read_commands(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	const uint8_t supported_commands[] = {
		BTP_OP_VENDOR_READ_SUPPORTED_COMMANDS,
		BTP_OP_VENDOR_ASCS_SETUP,
	};
	uint8_t *commands = NULL;
	size_t commands_len = 0;
	size_t i;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_VENDOR_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	for (i = 0; i < L_ARRAY_SIZE(supported_commands); i++) {
		if (!add_supported_command(&commands, &commands_len,
						supported_commands[i]))
			goto failed;
	}

	btp_send(btp, BTP_VENDOR_SERVICE, BTP_OP_VENDOR_READ_SUPPORTED_COMMANDS,
			BTP_INDEX_NON_CONTROLLER, commands_len, commands);

	l_free(commands);

	return;

failed:
	l_free(commands);
	btp_send_error(btp, BTP_VENDOR_SERVICE, index, BTP_ERROR_FAIL);
}

static void btp_vendor_ascs_setup(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_vendor_ascs_setup_cp *cp = param;

	adapter->target_latency = cp->target_latency;

	ascs_setup(adapter);

	btp_send(btp, BTP_VENDOR_SERVICE, BTP_OP_VENDOR_ASCS_SETUP, index, 0,
									NULL);
}

bool vendor_register_service(struct btp *btp_, struct l_dbus *dbus_,
					struct l_dbus_client *client)
{
	btp = btp_;

	btp_register(btp, BTP_VENDOR_SERVICE,
					BTP_OP_VENDOR_READ_SUPPORTED_COMMANDS,
					btp_vendor_read_commands, NULL, NULL);

	btp_register(btp, BTP_VENDOR_SERVICE,
					BTP_OP_VENDOR_ASCS_SETUP,
					btp_vendor_ascs_setup, NULL, NULL);

	vendor_service_registered = true;

	return true;
}

void vendor_unregister_service(struct btp *btp)
{
	btp_unregister_service(btp, BTP_VENDOR_SERVICE);
	vendor_service_registered = false;
}

bool vendor_is_service_registered(void)
{
	return vendor_service_registered;
}
