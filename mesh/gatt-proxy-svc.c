// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  ARRI Lighting. All rights reserved.
 *
 *
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>			// memcpy()

#include <ell/dbus.h>
#include <ell/queue.h>
#include <ell/timeout.h>
#include <ell/util.h>			// ell_new(), l_free(), l_malloc()

#include "mesh/gatt-service.h"
#include "mesh/mesh-io.h"		// mesh_io_recv_func_t
#include "mesh/net.h"			// mesh_net_attach_gatt(),
					// mesh_net_detach_gatt()
#include "mesh/net-keys.h"		// net_key_fill_adv_service_data(),
					// net_key_get_next_id()
#include "mesh/util.h"			// print_packet()
#include "mesh/gatt-proxy-svc.h"

#define MESH_GATT_PROXY_SVC_UUID "0x1828"
#define MESH_GATT_PROXY_CHRC_DATA_IN  "0x2ADD"
#define MESH_GATT_PROXY_CHRC_DATA_OUT "0x2ADE"

#define MAX_PROXY_PDU_LEN 66  /* MshPRT_v1.1, section 7.2.2.2.7 */

struct gatt_io_reg {
	mesh_io_recv_func_t cb;
	void *user_data;
	enum proxy_msg_type msg_type;
};

struct gatt_proxy_service {
	struct gatt_service *gatt_service;
	uint32_t current_adv_key_id;
	struct l_timeout *adv_key_cycle_to;
	bool txing;
	struct l_queue *tx_deferred;
	struct l_queue *rx_regs;
};

struct process_data {
	enum proxy_msg_type msg_type;
	const uint8_t *data;
	uint8_t len;
};

static struct gatt_proxy_service *gatt_proxy_service;

struct tx_deferred {
	enum proxy_msg_type msg_type;
	uint16_t len;
	uint8_t data[];
};

static struct gatt_io_reg *find_by_filter(struct l_queue *rx_regs,
						enum proxy_msg_type msg_type)
{
	const struct l_queue_entry *entry;

	entry = l_queue_get_entries(rx_regs);

	for (; entry; entry = entry->next) {
		struct gatt_io_reg *rx_reg = entry->data;

		if (rx_reg->msg_type == msg_type)
			return rx_reg;
	}

	return NULL;
}

void gatt_proxy_service_register_recv_cb(struct gatt_proxy_service *gatt_proxy,
					enum proxy_msg_type msg_type,
					mesh_io_recv_func_t cb,
					void *user_data)
{
	struct gatt_io_reg *rx_reg;

	if (gatt_proxy != gatt_proxy_service || !cb)
		return;

	rx_reg = find_by_filter(gatt_proxy->rx_regs, msg_type);

	l_free(rx_reg);
	l_queue_remove(gatt_proxy->rx_regs, rx_reg);

	rx_reg = l_malloc(sizeof(struct gatt_io_reg));
	rx_reg->cb = cb;
	rx_reg->msg_type = msg_type;
	rx_reg->user_data = user_data;

	l_queue_push_head(gatt_proxy->rx_regs, rx_reg);
}

void
gatt_proxy_service_deregister_recv_cb(struct gatt_proxy_service *gatt_proxy,
						enum proxy_msg_type msg_type)
{
	struct gatt_io_reg *rx_reg;

	if (gatt_proxy != gatt_proxy_service)
		return;

	rx_reg = find_by_filter(gatt_proxy->rx_regs, msg_type);

	l_queue_remove(gatt_proxy->rx_regs, rx_reg);
	l_free(rx_reg);
}

void gatt_proxy_service_send(enum proxy_msg_type msg_type,
						const void *data, uint8_t len)
{
	if (!gatt_proxy_service)
		return;

	if (!gatt_proxy_service->txing) {
		gatt_proxy_service->txing = true;
		gatt_service_tx(gatt_proxy_service->gatt_service, msg_type,
								data, len);
	} else {
		struct tx_deferred *tx_deferred;

//		print_packet("TX-Defer", data, len);
		tx_deferred = l_malloc(len + sizeof(struct tx_deferred));
		tx_deferred->msg_type = msg_type;
		tx_deferred->len = len;
		memcpy(tx_deferred->data, data, len);
		l_queue_push_tail(gatt_proxy_service->tx_deferred, tx_deferred);
	}
}

static void process_rx_callbacks(void *a, void *b)
{
	struct gatt_io_reg *rx_reg = a;
	struct process_data *rx = b;

	if (rx->msg_type == rx_reg->msg_type)
		rx_reg->cb(rx_reg->user_data, NULL, rx->data, rx->len);
}

static void gatt_service_rx(void *user_data, enum proxy_msg_type msg_type,
						const void *data, uint16_t len)
{
	struct gatt_proxy_service *gatt_proxy = user_data;
	struct process_data rx = {
		.msg_type = msg_type,
		.data = data,
		.len = len,
	};

	if (gatt_proxy != gatt_proxy_service)
		return;

	print_packet("RX", data, len);
	l_queue_foreach(gatt_proxy->rx_regs, process_rx_callbacks, &rx);
}

static bool gatt_service_tx_cmplt(void *user_data)
{
	struct gatt_proxy_service *gatt_proxy = user_data;
	struct tx_deferred *tx_deferred;

//	l_info("gatt_service_tx_cmplt");

	if (gatt_proxy_service != gatt_proxy)
		return false;

	if (!gatt_proxy->txing)
		return false;

	gatt_proxy->txing = false;

	tx_deferred = l_queue_pop_head(gatt_proxy->tx_deferred);
	if (!tx_deferred)
		return false;

	gatt_proxy_service_send(tx_deferred->msg_type,
					tx_deferred->data, tx_deferred->len);
	l_free(tx_deferred);
	return true;
}

static bool gatt_service_fill_adv_service_data(void *user_data,
					struct l_dbus_message_builder *builder)
{
	struct gatt_proxy_service *gatt_service = user_data;

	if (gatt_service != gatt_proxy_service)
		return false;

	return net_key_fill_adv_service_data(gatt_service->current_adv_key_id,
								builder);
}

static void gatt_proxy_service_cycle_adv(struct l_timeout *timeout,
						void *user_data)
{
	struct gatt_proxy_service *gatt_proxy = user_data;
	uint32_t next_adv_key_id;

	if (gatt_proxy_service != gatt_proxy)
		return;

	next_adv_key_id = net_key_get_next_id(gatt_proxy->current_adv_key_id);
	if (!next_adv_key_id)
		return;

	if (gatt_proxy->current_adv_key_id != next_adv_key_id) {
		gatt_proxy->current_adv_key_id = next_adv_key_id;
		gatt_service_adv_updated(gatt_proxy_service->gatt_service);
	}

	l_timeout_modify(gatt_proxy->adv_key_cycle_to, 3);
}

void gatt_proxy_service_set_current_adv_key(uint32_t id)
{
	if (!gatt_proxy_service)
		return;

	gatt_proxy_service->current_adv_key_id = id;
	gatt_service_adv_updated(gatt_proxy_service->gatt_service);
}

void gatt_proxy_service_start(void)
{
	if (!gatt_proxy_service || gatt_proxy_service->gatt_service)
		return;

	gatt_proxy_service->gatt_service = gatt_service_create(
					MESH_GATT_PROXY_SVC_UUID,
					MESH_GATT_PROXY_CHRC_DATA_IN,
					MESH_GATT_PROXY_CHRC_DATA_OUT,
					MAX_PROXY_PDU_LEN,
					NULL, NULL,
					gatt_service_rx,
					gatt_service_tx_cmplt,
					gatt_service_fill_adv_service_data,
					gatt_proxy_service);

	gatt_proxy_service->adv_key_cycle_to = l_timeout_create(3,
						gatt_proxy_service_cycle_adv,
						gatt_proxy_service, NULL);

	mesh_net_attach_gatt(gatt_proxy_service);
}

void gatt_proxy_service_stop(void)
{
	if (!gatt_proxy_service || !gatt_proxy_service->gatt_service)
		return;

	mesh_net_detach_gatt(gatt_proxy_service);
	l_timeout_remove(gatt_proxy_service->adv_key_cycle_to);
	gatt_service_destroy(gatt_proxy_service->gatt_service, NULL, NULL);
}

void gatt_proxy_service_create(void)
{
	if (gatt_proxy_service)
		return;

	gatt_proxy_service = l_new(struct gatt_proxy_service, 1);
	gatt_proxy_service->tx_deferred = l_queue_new();
	gatt_proxy_service->rx_regs = l_queue_new();

	/* Check whether we have at least one key */
	if (!net_key_get_next_id(0))
		return;

	gatt_proxy_service_start();
}

void gatt_proxy_service_destroy(void)
{
	if (!gatt_proxy_service)
		return;

	gatt_proxy_service_stop();

	l_queue_destroy(gatt_proxy_service->rx_regs, l_free);
	l_queue_destroy(gatt_proxy_service->tx_deferred, l_free);
	l_free(gatt_proxy_service);
	gatt_proxy_service = NULL;
}
