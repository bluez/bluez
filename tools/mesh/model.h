/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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
 *
 */

#define OP_UNRELIABLE	0x0100
#define VENDOR_ID_INVALID	0xFFFF

typedef bool (*model_send_msg_func_t) (void *user_data, uint16_t dst,
				uint16_t app_idx, uint8_t *data, uint16_t len);
typedef bool (*model_send_pub_func_t) (void *user_data, uint16_t vendor_id,
				uint16_t mod_id, uint8_t *data, uint16_t len);
typedef bool (*model_set_send_func_t)(model_send_msg_func_t func,
							void *user_data);
typedef bool (*model_set_pub_func_t)(model_send_pub_func_t func,
							void *user_data);

typedef bool (*model_recv_func_t)(uint16_t src, uint16_t app_idx,
						uint8_t *data, uint16_t len);
typedef int (*model_bind_func_t)(uint16_t app_idx, int action);

struct model_pub {
	uint16_t app_idx;
	union {
		uint16_t addr16;
		uint8_t va_128[16];
	} u;
	uint8_t ttl;
	uint8_t credential;
	uint8_t period;
	uint8_t retransmit;
};

typedef int (*model_pub_func_t)(struct model_pub *pub);

struct model_ops {
	model_set_send_func_t set_send_func;
	model_set_pub_func_t set_pub_func;
	model_recv_func_t recv;
	model_bind_func_t bind;
	model_pub_func_t pub;
};

struct model_info {
	struct model_ops ops;
	uint16_t mod_id;
	uint16_t vendor_id;
};
