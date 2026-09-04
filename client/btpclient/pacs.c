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
#include "pacs.h"

static struct btp *btp;
static bool pacs_service_registered;

static void btp_pacs_read_commands(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	const uint8_t supported_commands[] = {
		BTP_OP_PACS_READ_SUPPORTED_COMMANDS,
		BTP_OP_PACS_SET_LOCATION,
	};
	uint8_t *commands = NULL;
	size_t commands_len = 0;
	size_t i;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_PACS_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	for (i = 0; i < L_ARRAY_SIZE(supported_commands); i++) {
		if (!add_supported_command(&commands, &commands_len,
						supported_commands[i]))
			goto failed;
	}

	btp_send(btp, BTP_PACS_SERVICE, BTP_OP_PACS_READ_SUPPORTED_COMMANDS,
			BTP_INDEX_NON_CONTROLLER, commands_len, commands);

	l_free(commands);

	return;

failed:
	l_free(commands);
	btp_send_error(btp, BTP_PACS_SERVICE, index, BTP_ERROR_FAIL);
}

static void btp_pacs_set_location(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_pacs_set_location_cp *cp = param;

	switch (cp->dir) {
	case BTP_BAP_DIR_SINK:
		adapter->sink_locations = cp->location;
		break;
	case BTP_BAP_DIR_SOURCE:
		adapter->source_locations = cp->location;
		break;
	default:
		btp_send_error(btp, BTP_PACS_SERVICE, index, BTP_ERROR_FAIL);
		return;
	}

	btp_send(btp, BTP_PACS_SERVICE, BTP_OP_PACS_SET_LOCATION, index, 0,
									NULL);
}

bool pacs_register_service(struct btp *btp_, struct l_dbus *dbus_,
					struct l_dbus_client *client)
{
	btp = btp_;

	btp_register(btp, BTP_PACS_SERVICE, BTP_OP_PACS_READ_SUPPORTED_COMMANDS,
					btp_pacs_read_commands, NULL, NULL);

	btp_register(btp, BTP_PACS_SERVICE, BTP_OP_PACS_SET_LOCATION,
					btp_pacs_set_location, NULL, NULL);

	pacs_service_registered = true;

	return true;
}

void pacs_unregister_service(struct btp *btp)
{
	btp_unregister_service(btp, BTP_PACS_SERVICE);
	pacs_service_registered = false;
}

bool pacs_is_service_registered(void)
{
	return pacs_service_registered;
}
