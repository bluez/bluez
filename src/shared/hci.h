/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014  Intel Corporation. All rights reserved.
 *
 *
 */

#include <stdbool.h>
#include <stdint.h>

typedef void (*bt_hci_destroy_func_t)(void *user_data);

struct bt_hci_conn_info {
	uint16_t handle;
	uint8_t  bdaddr[6];
	uint8_t  type;
	uint8_t  out;
	uint16_t state;
	uint32_t link_mode;
};

struct bt_hci;

struct bt_hci *bt_hci_new(int fd);
struct bt_hci *bt_hci_new_user_channel(uint16_t index);
struct bt_hci *bt_hci_new_raw_device(uint16_t index);

struct bt_hci *bt_hci_ref(struct bt_hci *hci);
void bt_hci_unref(struct bt_hci *hci);

bool bt_hci_set_close_on_unref(struct bt_hci *hci, bool do_close);

typedef void (*bt_hci_callback_func_t)(const void *data, uint8_t size,
							void *user_data);

unsigned int bt_hci_send(struct bt_hci *hci, uint16_t opcode,
				const void *data, uint8_t size,
				bt_hci_callback_func_t callback,
				void *user_data, bt_hci_destroy_func_t destroy);
bool bt_hci_cancel(struct bt_hci *hci, unsigned int id);
bool bt_hci_flush(struct bt_hci *hci);

bool bt_hci_send_data(struct bt_hci *hci, uint8_t type, uint16_t handle,
				const void *data, uint8_t size);

unsigned int bt_hci_register(struct bt_hci *hci, uint8_t event,
				bt_hci_callback_func_t callback,
				void *user_data, bt_hci_destroy_func_t destroy);
bool bt_hci_unregister(struct bt_hci *hci, unsigned int id);

bool bt_hci_get_conn_info(struct bt_hci *hci, uint16_t handle,
				struct bt_hci_conn_info *info);
