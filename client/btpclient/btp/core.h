// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2017  Intel Corporation. All rights reserved.
 *
 */

#define BTP_OP_CORE_READ_SUPPORTED_COMMANDS	0x01

#define BTP_OP_CORE_READ_SUPPORTED_SERVICES	0x02

#define BTP_OP_CORE_REGISTER			0x03
struct btp_core_register_cp {
	uint8_t service_id;
} __packed;

#define BTP_OP_CORE_UNREGISTER			0x04
struct btp_core_unregister_cp {
	uint8_t service_id;
} __packed;

#define BTP_EV_CORE_READY			0x80
