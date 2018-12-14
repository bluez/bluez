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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"

#include "mesh/mesh-defs.h"

#include "mesh/mesh-io.h"
#include "mesh/mesh-io-api.h"

/* List of Mesh-IO Type headers */
#include "mesh/mesh-io-generic.h"

/* List of Supported Mesh-IO Types */
static const struct mesh_io_table table[] = {
	{MESH_IO_TYPE_GENERIC,	&mesh_io_generic}
};

static struct l_queue *io_list;

static bool match_by_io(const void *a, const void *b)
{
	return a == b;
}

static bool match_by_index(const void *a, const void *b)
{
	const struct mesh_io *io = a;

	return io->index == L_PTR_TO_UINT(b);
}

struct mesh_io *mesh_io_new(uint16_t index, enum mesh_io_type type)
{
	const struct mesh_io_api *api = NULL;
	struct mesh_io *io;
	uint16_t i;

	l_info("%s %d\n", __func__, type);

	for (i = 0; i < L_ARRAY_SIZE(table); i++) {
		if (table[i].type == type) {
			api = table[i].api;
			break;
		}
	}

	io = l_queue_find(io_list, match_by_index, L_UINT_TO_PTR(index));

	if (!api || !api->init || io)
		return NULL;

	io = l_new(struct mesh_io, 1);

	if (!io)
		return NULL;

	io->type = type;
	io->index = index;
	io->api = api;
	if (!api->init(index, io))
		goto fail;

	if (!io_list)
		io_list = l_queue_new();

	if (api->set) {
		uint8_t pkt = MESH_AD_TYPE_NETWORK;
		uint8_t bec = MESH_AD_TYPE_BEACON;
		uint8_t prv = MESH_AD_TYPE_PROVISION;

		api->set(io, 1, &bec, 1, NULL, NULL);
		api->set(io, 2, &prv, 1, NULL, NULL);
		api->set(io, 3, &pkt, 1, NULL, NULL);
	}

	if (l_queue_push_head(io_list, io))
		return io;

fail:
	if (api->destroy)
		api->destroy(io);

	l_free(io);
	return NULL;
}

void mesh_io_destroy(struct mesh_io *io)
{
	io = l_queue_remove_if(io_list, match_by_io, io);

	if (io && io->api && io->api->destroy)
		io->api->destroy(io);

	l_free(io);

	if (l_queue_isempty(io_list)) {
		l_queue_destroy(io_list, NULL);
		io_list = NULL;
	}
}

bool mesh_io_get_caps(struct mesh_io *io, struct mesh_io_caps *caps)
{
	io = l_queue_find(io_list, match_by_io, io);

	if (io && io->api && io->api->caps)
		return io->api->caps(io, caps);

	return false;
}

bool mesh_io_register_recv_cb(struct mesh_io *io, uint8_t filter_id,
				mesh_io_recv_func_t cb, void *user_data)
{
	io = l_queue_find(io_list, match_by_io, io);

	if (io && io->api && io->api->reg)
		return io->api->reg(io, filter_id, cb, user_data);

	return false;
}

bool mesh_io_deregister_recv_cb(struct mesh_io *io, uint8_t filter_id)
{
	io = l_queue_find(io_list, match_by_io, io);

	if (io && io->api && io->api->dereg)
		return io->api->dereg(io, filter_id);

	return false;
}

bool mesh_set_filter(struct mesh_io *io, uint8_t filter_id,
				const uint8_t *data, uint8_t len,
				mesh_io_status_func_t cb, void *user_data)
{
	io = l_queue_find(io_list, match_by_io, io);

	if (io && io->api && io->api->set)
		return io->api->set(io, filter_id, data, len, cb, user_data);

	return false;
}

bool mesh_io_send(struct mesh_io *io, struct mesh_io_send_info *info,
					const uint8_t *data, uint16_t len)
{
	io = l_queue_find(io_list, match_by_io, io);

	if (io && io->api && io->api->send)
		return io->api->send(io, info, data, len);

	return false;
}

bool mesh_io_send_cancel(struct mesh_io *io, const uint8_t *pattern,
								uint8_t len)
{
	io = l_queue_find(io_list, match_by_io, io);

	if (io && io->api && io->api->cancel)
		return io->api->cancel(io, pattern, len);

	return false;
}
