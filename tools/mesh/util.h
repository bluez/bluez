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

#include <stdbool.h>

struct mesh_publication;

void set_menu_prompt(const char *name, const char *id);
void print_byte_array(const char *prefix, const void *ptr, int len);
uint16_t mesh_opcode_set(uint32_t opcode, uint8_t *buf);
bool mesh_opcode_get(const uint8_t *buf, uint16_t sz, uint32_t *opcode, int *n);
const char *mesh_status_str(uint8_t status);
void swap_u256_bytes(uint8_t *u256);
