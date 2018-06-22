/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdbool.h>

struct mesh_publication;

#define OP_UNRELIABLE			0x0100

void set_menu_prompt(const char *name, const char *id);
void print_byte_array(const char *prefix, const void *ptr, int len);
bool str2hex(const char *str, uint16_t in_len, uint8_t *out_buf,
		uint16_t out_len);
size_t hex2str(uint8_t *in, size_t in_len, char *out,
		size_t out_len);
uint16_t mesh_opcode_set(uint32_t opcode, uint8_t *buf);
bool mesh_opcode_get(const uint8_t *buf, uint16_t sz, uint32_t *opcode, int *n);
const char *mesh_status_str(uint8_t status);
void print_model_pub(uint16_t ele_addr, uint32_t mod_id,
						struct mesh_publication *pub);
void swap_u256_bytes(uint8_t *u256);
