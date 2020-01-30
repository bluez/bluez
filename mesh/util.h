/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

uint32_t get_timestamp_secs(void);
bool str2hex(const char *str, uint16_t in_len, uint8_t *out,
							uint16_t out_len);
size_t hex2str(uint8_t *in, size_t in_len, char *out, size_t out_len);
void print_packet(const char *label, const void *data, uint16_t size);
int create_dir(const char *dir_name);
void del_path(const char *path);
