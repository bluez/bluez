/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  ARRI Lighting. All rights reserved.
 *
 *
 */

#include <stdbool.h>
#include <stdint.h>

typedef void (*pb_gatt_destroy_cb)(void *user_data);

bool pb_gatt_reg(mesh_prov_open_func_t open_cb, mesh_prov_close_func_t close_cb,
		mesh_prov_receive_func_t rx_cb, mesh_prov_ack_func_t ack_cb,
		const uint8_t *uuid, uint16_t oob_info, void *user_data);
void pb_gatt_unreg(void *user_data, pb_gatt_destroy_cb destroy_cb,
							void *destroy_data);
