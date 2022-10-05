// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"
#include "src/shared/mgmt.h"

#include "mesh/mesh-defs.h"
#include "mesh/mesh-mgmt.h"
#include "mesh/mesh-io.h"
#include "mesh/mesh-io-api.h"

/* List of Mesh-IO Type headers */
#include "mesh/mesh-io-mgmt.h"
#include "mesh/mesh-io-generic.h"
#include "mesh/mesh-io-unit.h"

struct mesh_io_reg {
	mesh_io_recv_func_t cb;
	void *user_data;
	uint8_t len;
	uint8_t filter[];
} packed;

/* List of Supported Mesh-IO Types */
static const struct mesh_io_table table[] = {
	{MESH_IO_TYPE_MGMT,	&mesh_io_mgmt},
	{MESH_IO_TYPE_GENERIC,	&mesh_io_generic},
	{MESH_IO_TYPE_UNIT_TEST, &mesh_io_unit},
};

static struct mesh_io *default_io;

static const struct mesh_io_api *io_api(enum mesh_io_type type)
{
	uint16_t i;

	for (i = 0; i < L_ARRAY_SIZE(table); i++) {
		if (table[i].type == type)
			return table[i].api;
	}

	return NULL;
}

static void refresh_rx(void *a, void *b)
{
	struct mesh_io_reg *rx_reg = a;
	struct mesh_io *io = b;

	if (io->api && io->api->reg)
		io->api->reg(io, rx_reg->filter, rx_reg->len, rx_reg->cb,
							rx_reg->user_data);
}

static void ctl_alert(int index, bool up, bool pwr, bool mesh, void *user_data)
{
	enum mesh_io_type type = L_PTR_TO_UINT(user_data);
	const struct mesh_io_api *api = NULL;

	l_warn("up:%d pwr: %d mesh: %d", up, pwr, mesh);

	/* If specific IO controller requested, honor it */
	if (default_io->favored_index != MGMT_INDEX_NONE &&
					default_io->favored_index != index)
		return;

	if (!up && default_io->index == index) {
		/* Our controller has disappeared */
		if (default_io->api && default_io->api->destroy) {
			default_io->api->destroy(default_io);
			default_io->api = NULL;
		}

		/* Re-enumerate controllers */
		mesh_mgmt_list(ctl_alert, user_data);
		return;
	}

	/* If we already have an API, keep using it */
	if (!up || default_io->api)
		return;

	if (mesh && type != MESH_IO_TYPE_GENERIC)
		api = io_api(MESH_IO_TYPE_MGMT);

	else if (!pwr)
		api = io_api(MESH_IO_TYPE_GENERIC);

	if (api) {
		default_io->index = index;
		default_io->api = api;
		api->init(default_io, &index, default_io->user_data);

		l_queue_foreach(default_io->rx_regs, refresh_rx, default_io);
	}
}

static void free_io(struct mesh_io *io)
{
	if (io) {
		if (io->api && io->api->destroy)
			io->api->destroy(io);

		l_queue_destroy(io->rx_regs, l_free);
		io->rx_regs = NULL;
		l_free(io);
		l_warn("Destroy %p", io);
	}
}

struct mesh_io *mesh_io_new(enum mesh_io_type type, void *opts,
				mesh_io_ready_func_t cb, void *user_data)
{
	const struct mesh_io_api *api = NULL;

	/* Only allow one IO */
	if (default_io)
		return NULL;

	default_io = l_new(struct mesh_io, 1);
	default_io->ready = cb;
	default_io->user_data = user_data;
	default_io->favored_index = *(int *) opts;
	default_io->rx_regs = l_queue_new();

	if (type >= MESH_IO_TYPE_AUTO) {
		if (!mesh_mgmt_list(ctl_alert, L_UINT_TO_PTR(type)))
			goto fail;

		return default_io;
	}

	api = io_api(type);

	if (!api || !api->init)
		goto fail;

	default_io->api = api;

	if (!api->init(default_io, opts, user_data))
		goto fail;

	return default_io;

fail:
	free_io(default_io);
	default_io = NULL;
	return NULL;
}

void mesh_io_destroy(struct mesh_io *io)
{
}

bool mesh_io_get_caps(struct mesh_io *io, struct mesh_io_caps *caps)
{
	if (io != default_io)
		return false;

	if (io && io->api && io->api->caps)
		return io->api->caps(io, caps);

	return false;
}

bool mesh_io_register_recv_cb(struct mesh_io *io, const uint8_t *filter,
				uint8_t len, mesh_io_recv_func_t cb,
				void *user_data)
{
	struct mesh_io_reg *rx_reg;

	if (io != default_io)
		return false;

	rx_reg = l_malloc(sizeof(struct mesh_io_reg) + len);
	rx_reg->cb = cb;
	rx_reg->len = len;
	rx_reg->user_data = user_data;
	memcpy(rx_reg->filter, filter, len);
	l_queue_push_head(io->rx_regs, rx_reg);

	if (io && io->api && io->api->reg)
		return io->api->reg(io, filter, len, cb, user_data);

	return false;
}

static bool by_filter(const void *a, const void *b)
{
	const struct mesh_io_reg *rx_reg = a;
	const uint8_t *filter = b;

	return rx_reg->filter[0] == filter[0];
}

bool mesh_io_deregister_recv_cb(struct mesh_io *io, const uint8_t *filter,
								uint8_t len)
{
	struct mesh_io_reg *rx_reg;

	if (io != default_io)
		return false;

	rx_reg = l_queue_remove_if(io->rx_regs, by_filter, filter);
	l_free(rx_reg);

	if (io && io->api && io->api->dereg)
		return io->api->dereg(io, filter, len);

	return false;
}

bool mesh_io_send(struct mesh_io *io, struct mesh_io_send_info *info,
					const uint8_t *data, uint16_t len)
{
	if (io && io != default_io)
		return false;

	if (!io)
		io = default_io;

	if (io && io->api && io->api->send)
		return io->api->send(io, info, data, len);

	return false;
}

bool mesh_io_send_cancel(struct mesh_io *io, const uint8_t *pattern,
								uint8_t len)
{
	if (io && io != default_io)
		return false;

	if (!io)
		io = default_io;

	if (io && io->api && io->api->cancel)
		return io->api->cancel(io, pattern, len);

	return false;
}
