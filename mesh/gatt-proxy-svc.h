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
struct gatt_proxy_svc;

void gatt_proxy_svc_create(void);
void gatt_proxy_svc_destroy(void);
void gatt_proxy_svc_start(void);
void gatt_proxy_svc_stop(void);
void gatt_proxy_svc_set_current_adv_key(uint32_t id);
void gatt_proxy_svc_register_recv_cb(struct gatt_proxy_svc *gatt_proxy,
					enum proxy_msg_type msg_type,
					mesh_io_recv_func_t cb,
					void *user_data);
void gatt_proxy_svc_deregister_recv_cb(struct gatt_proxy_svc *gatt_proxy,
						enum proxy_msg_type msg_type);

void gatt_proxy_svc_filter_set_type(struct gatt_proxy_svc *gatt_proxy,
							uint8_t filter_type);
void gatt_proxy_svc_filter_add(struct gatt_proxy_svc *gatt_proxy,
								uint16_t addr);
void gatt_proxy_svc_filter_remove(struct gatt_proxy_svc *gatt_proxy,
								uint16_t addr);
unsigned gatt_proxy_svc_filter_count(struct gatt_proxy_svc *gatt_proxy,
							uint8_t *filter_type);
void gatt_proxy_svc_filter_pdu_rcvd(struct gatt_proxy_svc *gatt_proxy,
								uint16_t src);

void gatt_proxy_svc_send_net(uint16_t dst, const void *data, uint8_t len);
void gatt_proxy_svc_send_proxy_cfg(const void *data, uint8_t len);
