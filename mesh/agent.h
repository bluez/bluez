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

struct mesh_agent;

struct mesh_agent_prov_caps {
	uint32_t uri_hash;
	uint16_t oob_info;
	uint16_t output_action;
	uint16_t input_action;
	uint8_t pub_type;
	uint8_t static_type;
	uint8_t output_size;
	uint8_t input_size;
};

typedef void (*mesh_agent_cb_t) (void *user_data, int err);

typedef void (*mesh_agent_key_cb_t) (void *user_data, int err, uint8_t *key,
								uint32_t len);

typedef void (*mesh_agent_number_cb_t) (void *user_data, int err,
							uint32_t number);

void mesh_agent_init(void);
void mesh_agent_cleanup(void);
struct mesh_agent *mesh_agent_create(const char *path, const char *owner,
					struct l_dbus_message_iter *properties);

void mesh_agent_remove(struct mesh_agent *agent);
void mesh_agent_cancel(struct mesh_agent *agent);

struct mesh_agent_prov_caps *mesh_agent_get_caps(struct mesh_agent *agent);

int mesh_agent_display_number(struct mesh_agent *agent, bool initiator,
					uint8_t action, uint32_t count,
					mesh_agent_cb_t cb, void *user_data);
int mesh_agent_prompt_number(struct mesh_agent *agent, bool initiator,
				uint8_t action, mesh_agent_number_cb_t cb,
				void *user_data);
int mesh_agent_prompt_alpha(struct mesh_agent *agent, bool initiator,
				mesh_agent_key_cb_t cb, void *user_data);
int mesh_agent_request_static(struct mesh_agent *agent, mesh_agent_key_cb_t cb,
							void *user_data);
int mesh_agent_request_private_key(struct mesh_agent *agent,
							mesh_agent_key_cb_t cb,
							void *user_data);
int mesh_agent_request_public_key(struct mesh_agent *agent,
							mesh_agent_key_cb_t cb,
							void *user_data);
int mesh_agent_display_string(struct mesh_agent *agent, const char *str,
							mesh_agent_cb_t cb,
							void *user_data);
