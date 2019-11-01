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

#define KR_PHASE_NONE		0x00
#define KR_PHASE_ONE		0x01
#define KR_PHASE_TWO		0x02
#define KR_PHASE_INVALID	0xff

bool keys_app_key_add(uint16_t net_idx, uint16_t app_idx, uint8_t *key,
		      bool update);
bool keys_net_key_add(uint16_t index, uint8_t *key, bool update);
uint16_t keys_app_key_get_bound(uint16_t app_idx);
uint8_t *keys_app_key_get(uint16_t app_idx, bool current);
uint8_t *keys_net_key_get(uint16_t net_idx, bool current);
bool keys_app_key_delete(uint16_t app_idx);
bool keys_net_key_delete(uint16_t net_idx);
uint8_t keys_get_kr_phase(uint16_t net_idx);
bool keys_set_kr_phase(uint16_t index, uint8_t phase);
void keys_cleanup_all(void);
