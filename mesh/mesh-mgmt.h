/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  SILVAIR sp. z o.o. All rights reserved.
 *
 *
 */
#include <stdbool.h>

typedef void (*mesh_mgmt_read_info_func_t)(int index, bool added, bool powered,
						bool mesh, void *user_data);

bool mesh_mgmt_list(mesh_mgmt_read_info_func_t cb, void *user_data);
unsigned int mesh_mgmt_send(uint16_t opcode, uint16_t index,
				uint16_t length, const void *param,
				mgmt_request_func_t callback,
				void *user_data, mgmt_destroy_func_t destroy);
unsigned int mesh_mgmt_register(uint16_t event, uint16_t index,
				mgmt_notify_func_t callback,
				void *user_data, mgmt_destroy_func_t destroy);
bool mesh_mgmt_unregister(unsigned int id);
void mesh_mgmt_destroy(void);
void mesh_mgmt_clear(void);
