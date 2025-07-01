/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  ARRI Lighting. All rights reserved.
 *
 *
 */

#include <stdint.h>

enum proxy_msg_type;
struct gatt_proxy_service;

void gatt_proxy_service_create(void);
void gatt_proxy_service_destroy(void);
void gatt_proxy_service_start(void);
void gatt_proxy_service_stop(void);
void gatt_proxy_service_set_current_adv_key(uint32_t id);
void gatt_proxy_service_register_recv_cb(struct gatt_proxy_service *gatt_proxy,
					enum proxy_msg_type msg_type,
					mesh_io_recv_func_t cb,
					void *user_data);
void
gatt_proxy_service_deregister_recv_cb(struct gatt_proxy_service *gatt_proxy,
						enum proxy_msg_type msg_type);
void gatt_proxy_service_send(enum proxy_msg_type msg_type,
						const void *data, uint8_t len);
