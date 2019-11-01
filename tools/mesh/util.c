/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017, 2019  Intel Corporation. All rights reserved.
 *
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>

#include <ell/ell.h>

#include "src/shared/shell.h"
#include "src/shared/util.h"

#include "mesh/mesh-defs.h"

#include "tools/mesh/util.h"

void set_menu_prompt(const char *name, const char *id)
{
	char *prompt;

	prompt = l_strdup_printf(COLOR_BLUE "[%s%s%s]" COLOR_OFF "# ", name,
					id ? ": Target = " : "", id ? id : "");
	bt_shell_set_prompt(prompt);
	l_free(prompt);
}

uint16_t mesh_opcode_set(uint32_t opcode, uint8_t *buf)
{
	if (opcode <= 0x7e) {
		buf[0] = opcode;
		return 1;
	} else if (opcode >= 0x8000 && opcode <= 0xbfff) {
		put_be16(opcode, buf);
		return 2;
	} else if (opcode >= 0xc00000 && opcode <= 0xffffff) {
		buf[0] = (opcode >> 16) & 0xff;
		put_be16(opcode, buf + 1);
		return 3;
	}

	bt_shell_printf("Illegal Opcode %x", opcode);
	return 0;
}

bool mesh_opcode_get(const uint8_t *buf, uint16_t sz, uint32_t *opcode, int *n)
{
	if (!n || !opcode || sz < 1)
		return false;

	switch (buf[0] & 0xc0) {
	case 0x00:
	case 0x40:
		/* RFU */
		if (buf[0] == 0x7f)
			return false;

		*n = 1;
		*opcode = buf[0];
		break;

	case 0x80:
		if (sz < 2)
			return false;

		*n = 2;
		*opcode = get_be16(buf);
		break;

	case 0xc0:
		if (sz < 3)
			return false;

		*n = 3;
		*opcode = get_be16(buf + 1);
		*opcode |= buf[0] << 16;
		break;

	default:
		bt_shell_printf("Bad opcode");
		return false;
	}

	return true;
}

const char *mesh_status_str(uint8_t status)
{
	switch (status) {
	case MESH_STATUS_SUCCESS: return "Success";
	case MESH_STATUS_INVALID_ADDRESS: return "Invalid Address";
	case MESH_STATUS_INVALID_MODEL: return "Invalid Model";
	case MESH_STATUS_INVALID_APPKEY: return "Invalid AppKey";
	case MESH_STATUS_INVALID_NETKEY: return "Invalid NetKey";
	case MESH_STATUS_INSUFF_RESOURCES: return "Insufficient Resources";
	case MESH_STATUS_IDX_ALREADY_STORED: return "Key Idx Already Stored";
	case MESH_STATUS_INVALID_PUB_PARAM: return "Invalid Publish Parameters";
	case MESH_STATUS_NOT_SUB_MOD: return "Not a Subscribe Model";
	case MESH_STATUS_STORAGE_FAIL: return "Storage Failure";
	case MESH_STATUS_FEATURE_NO_SUPPORT: return "Feature Not Supported";
	case MESH_STATUS_CANNOT_UPDATE: return "Cannot Update";
	case MESH_STATUS_CANNOT_REMOVE: return "Cannot Remove";
	case MESH_STATUS_CANNOT_BIND: return "Cannot bind";
	case MESH_STATUS_UNABLE_CHANGE_STATE: return "Unable to change state";
	case MESH_STATUS_CANNOT_SET: return "Cannot set";
	case MESH_STATUS_UNSPECIFIED_ERROR: return "Unspecified error";
	case MESH_STATUS_INVALID_BINDING: return "Invalid Binding";

	default: return "Unknown";
	}
}

void swap_u256_bytes(uint8_t *u256)
{
	int i;

	/* End-to-End byte reflection of 32 octet buffer */
	for (i = 0; i < 16; i++) {
		u256[i] ^= u256[31 - i];
		u256[31 - i] ^= u256[i];
		u256[i] ^= u256[31 - i];
	}
}
