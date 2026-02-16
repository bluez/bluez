// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2017  Intel Corporation. All rights reserved.
 *
 */

#include <ell/ell.h>

#include "bluetooth/bluetooth.h"
#include "src/shared/btp.h"
#include "btpclient.h"
#include "core.h"

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
		if (gap_is_service_registered())
			goto failed;

		if (!gap_register_service())
			goto failed;

		return;
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
		if (!gap_is_service_registered())
			goto failed;

		gap_unregister_service();
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

void core_register_service(struct btp *btp_)
{
	btp = btp_;

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
