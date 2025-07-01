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

/* MshPRT_v1.1, section 6.3.1 */
enum proxy_msg_type {
	PROXY_MSG_TYPE_NETWORK_PDU = 0x00,
	PROXY_MSG_TYPE_MESH_BEACON = 0x01,
	PROXY_MSG_TYPE_PROXY_CFG   = 0x02,
	PROXY_MSG_TYPE_PROV_PDU    = 0x03
};

typedef void (*gatt_service_notify_acquired_cb)(void *user_data);
typedef void (*gatt_service_notify_stopped_cb)(void *user_data);
typedef void (*gatt_service_rx_cb)(void *user_data,
					enum proxy_msg_type messageType,
					const void *data, uint16_t len);
typedef bool (*gatt_service_tx_cmplt_cb)(void *user_data);
typedef bool (*gatt_service_fill_adv_service_data_cb)(void *user_data,
					struct l_dbus_message_builder *builder);

typedef void (*gatt_destroy_cb)(void *user_data);

struct gatt_service;

struct gatt_service *
gatt_service_create(
		const char *svc_uuid,
		const char *chrc_data_in_uuid,
		const char *chrc_data_out_uuid,
		uint8_t max_pdu_len,
		gatt_service_notify_acquired_cb notify_acquired_cb,
		gatt_service_notify_stopped_cb notify_stopped_cb,
		gatt_service_rx_cb rx_cb,
		gatt_service_tx_cmplt_cb tx_cmplt_cb,
		gatt_service_fill_adv_service_data_cb fill_adv_service_data_cb,
		void *user_data);

void gatt_service_destroy(struct gatt_service *service,
				gatt_destroy_cb destroy_cb, void *user_data);

void gatt_service_tx(struct gatt_service *service, uint8_t msg_type,
						const void *data, uint16_t len);
void gatt_service_adv_updated(struct gatt_service *service);
