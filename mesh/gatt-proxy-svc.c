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
#include <string.h>			// memcpy(), memmove()

#include <ell/dbus.h>
#include <ell/log.h>			// l_warn()
#include <ell/queue.h>
#include <ell/timeout.h>
#include <ell/util.h>			// ell_new(), l_free(), l_malloc(),
					// L_ARRAY_SIZE

#include "mesh/mesh-defs.h"		// UNASSIGNED_ADDRESS
#include "mesh/gatt-service.h"
#include "mesh/mesh-io.h"		// mesh_io_recv_func_t
#include "mesh/net.h"			// PROXY_FILTER_ACCEPT_LIST,
					// PROXY_FILTER_REJECT_LIST
					// mesh_net_attach_gatt(),
					// mesh_net_detach_gatt(),
					// mesh_net_send_all_beacons_gatt()
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

struct gatt_proxy_svc {
	struct gatt_service *gatt_service;
	uint32_t current_adv_key_id;
	struct l_timeout *adv_key_cycle_to;
	bool connected;
	bool txing;
	struct l_queue *tx_deferred;
	struct l_queue *rx_regs;
	uint8_t filter_type;
	uint16_t filter_addrs[32];
	unsigned filter_count;
};

struct process_data {
	enum proxy_msg_type msg_type;
	const uint8_t *data;
	uint8_t len;
};

static struct gatt_proxy_svc *gatt_proxy_svc;

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

void gatt_proxy_svc_register_recv_cb(struct gatt_proxy_svc *gatt_proxy,
					enum proxy_msg_type msg_type,
					mesh_io_recv_func_t cb,
					void *user_data)
{
	struct gatt_io_reg *rx_reg;

	if (gatt_proxy != gatt_proxy_svc || !cb)
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

void gatt_proxy_svc_deregister_recv_cb(struct gatt_proxy_svc *gatt_proxy,
						enum proxy_msg_type msg_type)
{
	struct gatt_io_reg *rx_reg;

	if (gatt_proxy != gatt_proxy_svc)
		return;

	rx_reg = find_by_filter(gatt_proxy->rx_regs, msg_type);

	l_queue_remove(gatt_proxy->rx_regs, rx_reg);
	l_free(rx_reg);
}

void gatt_proxy_svc_filter_set_type(struct gatt_proxy_svc *gatt_proxy,
							uint8_t filter_type)
{
	if (!gatt_proxy || gatt_proxy != gatt_proxy_svc)
		return;

	/* Behavior not specified in MshPRT, section 6.7 */
	if (filter_type != PROXY_FILTER_ACCEPT_LIST &&
					filter_type != PROXY_FILTER_REJECT_LIST)
		return;

	/*
	 * MshPRT_v1.1, section 6.7 - Proxy Server behavior
	 * If a Proxy Server receives a Set Filter Type message, it shall set
	 * the proxy filter type as requested in the message parameter, and it
	 * shall clear the proxy filter list.
	 */
	gatt_proxy->filter_type = filter_type;
	gatt_proxy->filter_count = 0;
}

void gatt_proxy_svc_filter_add(struct gatt_proxy_svc *gatt_proxy,
								uint16_t addr)
{
	int i;

	if (!gatt_proxy || gatt_proxy != gatt_proxy_svc)
		return;

	/*
	 * MshPRT_v1.1, section 6.7 - Proxy Server behavior
	 * If the AddressArray field contains the unassigned address, the Proxy
	 * Server shall ignore that address.
	 */
	if (addr == UNASSIGNED_ADDRESS)
		return;

	/*
	 * MshPRT_v1.1, section 6.7 - Proxy Server behavior
	 * If the Proxy Server runs out of space in the proxy filter list,
	 * the Proxy Server shall not add these addresses.
	 */
	if (gatt_proxy->filter_count == L_ARRAY_SIZE(gatt_proxy->filter_addrs))
		return;

	/*
	 * MshPRT_v1.1, section 6.7 - Proxy Server behavior
	 * If one or more addresses contained in the message are already in the
	 * list, the Proxy Server shall not add these addresses.
	 */
	for (i = 0; i < gatt_proxy->filter_count; i++)
		if (gatt_proxy->filter_addrs[i] == addr)
			return;

	gatt_proxy->filter_addrs[gatt_proxy->filter_count++] = addr;
}

void gatt_proxy_svc_filter_remove(struct gatt_proxy_svc *gatt_proxy,
								uint16_t addr)
{
	int i;

	if (!gatt_proxy || gatt_proxy != gatt_proxy_svc)
		return;

	/*
	 * MshPRT_v1.1, section 6.7 - Proxy Server behavior
	 * If the AddressArray field contains the unassigned address, the Proxy
	 * Server shall ignore that address.
	 */
	if (addr == UNASSIGNED_ADDRESS)
		return;

	/*
	 * MshPRT_v1.1, section 6.7 - Proxy Server behavior
	 * If one or more addresses contained in the message were not in the
	 * list, the Proxy Server shall ignore these addresses.
	 */
	for (i = 0; i < gatt_proxy->filter_count; i++)
		if (gatt_proxy->filter_addrs[i] == addr)
			break;

	if (i == gatt_proxy->filter_count)
		return;

	memmove(gatt_proxy->filter_addrs + i, gatt_proxy->filter_addrs + i + 1,
			gatt_proxy->filter_count - i - 1);
	gatt_proxy->filter_count--;
}

unsigned gatt_proxy_svc_filter_count(struct gatt_proxy_svc *gatt_proxy,
							uint8_t *filter_type)
{
	if (!gatt_proxy || gatt_proxy != gatt_proxy_svc)
		return 0;

	*filter_type = gatt_proxy->filter_type;

	return gatt_proxy->filter_count;
}

void gatt_proxy_svc_filter_pdu_rcvd(struct gatt_proxy_svc *gatt_proxy,
								uint16_t src)
{
	if (!gatt_proxy || gatt_proxy != gatt_proxy_svc)
		return;

	if (gatt_proxy->filter_type == PROXY_FILTER_ACCEPT_LIST) {
		/*
		 * MshPRT_v1.1, section 6.7 - Proxy Server behavior
		 * If the proxy filter is an accept list filter, upon receiving
		 * a Proxy PDU containing a valid Network PDU from the Proxy
		 * Client, the Proxy Server shall add the unicast address
		 * contained in the SRC field of the Network PDU to the accept
		 * list.
		 */
		gatt_proxy_svc_filter_add(gatt_proxy, src);
	} else {
		/*
		 * MshPRT_v1.1, section 6.7 - Proxy Server behavior
		 * If the proxy filter is a reject list filter, upon receiving a
		 * Proxy PDU containing a valid Network PDU from the Proxy
		 * Client, the Proxy Server shall remove the unicast address
		 * contained in the SRC field of the Network PDU from the reject
		 * list.
		 */
		gatt_proxy_svc_filter_remove(gatt_proxy, src);
	}
}

static void gatt_proxy_svc_send(enum proxy_msg_type msg_type, const void *data,
								uint8_t len)
{
	if (!gatt_proxy_svc)
		return;

	if (!gatt_proxy_svc->connected) {
		l_warn("Not connected, dropping TX message...");
		return;
	}

	if (!gatt_proxy_svc->txing) {
		gatt_proxy_svc->txing = true;
		gatt_service_tx(gatt_proxy_svc->gatt_service, msg_type,
								data, len);
	} else {
		struct tx_deferred *tx_deferred;

//		print_packet("TX-Defer", data, len);
		tx_deferred = l_malloc(len + sizeof(struct tx_deferred));
		tx_deferred->msg_type = msg_type;
		tx_deferred->len = len;
		memcpy(tx_deferred->data, data, len);
		l_queue_push_tail(gatt_proxy_svc->tx_deferred, tx_deferred);
	}
}

void gatt_proxy_svc_send_beacon(const void *data, uint8_t len)
{
	gatt_proxy_svc_send(PROXY_MSG_TYPE_MESH_BEACON, data, len);
}

void gatt_proxy_svc_send_net(uint16_t dst, const void *data, uint8_t len)
{
	int i;

	if (!gatt_proxy_svc)
		return;

	/*
	 * MshPRT_v1.1, section 6.4 - Proxy filtering
	 * The output filter of the network interface (see Section 3.4.5) [...]
	 * can be configured by the Proxy Client. This allows the Proxy Client
	 * to explicitly request to receive only mesh messages with certain
	 * *destination* addresses.
	 */
	for (i = 0; i < gatt_proxy_svc->filter_count; i++)
		if (gatt_proxy_svc->filter_addrs[i] == dst)
			break;

	if (gatt_proxy_svc->filter_type == PROXY_FILTER_ACCEPT_LIST) {
		if (i == gatt_proxy_svc->filter_count)  // not found
			return;
	} else {  /* PROXY_FILTER_REJECT_LIST */
		if (i != gatt_proxy_svc->filter_count)  // found
			return;
	}

	gatt_proxy_svc_send(PROXY_MSG_TYPE_NETWORK_PDU, data, len);
}

void gatt_proxy_svc_send_proxy_cfg(const void *data, uint8_t len)
{
	gatt_proxy_svc_send(PROXY_MSG_TYPE_PROXY_CFG, data, len);
}

static void gatt_service_notify_acquired(void *user_data)
{
	struct gatt_proxy_svc *gatt_proxy = user_data;

	if (gatt_proxy != gatt_proxy_svc)
		return;

	gatt_proxy->connected = true;

	/*
	 * MshPRT_v1.1, section 6.7 - Proxy Server behavior
	 * Upon connection, the Proxy Server shall initialize the proxy filter
	 * as an accept list filter and the accept list shall be empty.
	 */
	gatt_proxy->filter_type = PROXY_FILTER_ACCEPT_LIST;
	gatt_proxy->filter_count = 0;

	/*
	 * MshPRT_v1.1, section 6.7 - Proxy Server behavior
	 * Upon connection, [...] The Proxy Server shall send a mesh
	 * beacon for each known subnet to the Proxy Client, [...]
	 *
	 * MshPRT_v1.1, section 7.2.3.2.1 - Characteristic behavior
	 * [...] the client will enable notifications [...] to the
	 * Mesh Proxy Data Out Client Characteristic Configuration
	 * Descriptor after a connection is established.
	 */
	mesh_net_send_all_beacons_gatt();
}

static void gatt_service_notify_stopped(void *user_data)
{
	struct gatt_proxy_svc *gatt_proxy = user_data;

	if (gatt_proxy != gatt_proxy_svc)
		return;

	gatt_proxy->connected = false;
	gatt_proxy->txing = false;
	l_queue_clear(gatt_proxy->tx_deferred, l_free);
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
	struct gatt_proxy_svc *gatt_proxy = user_data;
	struct process_data rx = {
		.msg_type = msg_type,
		.data = data,
		.len = len,
	};

	if (gatt_proxy != gatt_proxy_svc)
		return;

	l_queue_foreach(gatt_proxy->rx_regs, process_rx_callbacks, &rx);
}

static bool gatt_service_tx_cmplt(void *user_data)
{
	struct gatt_proxy_svc *gatt_proxy = user_data;
	struct tx_deferred *tx_deferred;

//	l_info("gatt_service_tx_cmplt");

	if (gatt_proxy_svc != gatt_proxy)
		return false;

	if (!gatt_proxy->connected || !gatt_proxy->txing)
		return false;

	gatt_proxy->txing = false;

	tx_deferred = l_queue_pop_head(gatt_proxy->tx_deferred);
	if (!tx_deferred)
		return false;

	gatt_proxy_svc_send(tx_deferred->msg_type, tx_deferred->data,
							tx_deferred->len);
	l_free(tx_deferred);
	return true;
}

static bool gatt_service_fill_adv_service_data(void *user_data,
					struct l_dbus_message_builder *builder)
{
	struct gatt_proxy_svc *gatt_service = user_data;

	if (gatt_service != gatt_proxy_svc)
		return false;

	return net_key_fill_adv_service_data(gatt_service->current_adv_key_id,
								builder);
}

static void gatt_proxy_svc_cycle_adv(struct l_timeout *timeout,
						void *user_data)
{
	struct gatt_proxy_svc *gatt_proxy = user_data;
	uint32_t next_adv_key_id;

	if (gatt_proxy_svc != gatt_proxy)
		return;

	next_adv_key_id = net_key_get_next_id(gatt_proxy->current_adv_key_id);
	if (!next_adv_key_id)
		return;

	if (gatt_proxy->current_adv_key_id != next_adv_key_id) {
		gatt_proxy->current_adv_key_id = next_adv_key_id;
		gatt_service_adv_updated(gatt_proxy_svc->gatt_service);
	}

	l_timeout_modify(gatt_proxy->adv_key_cycle_to, 3);
}

void gatt_proxy_svc_set_current_adv_key(uint32_t id)
{
	if (!gatt_proxy_svc)
		return;

	gatt_proxy_svc->current_adv_key_id = id;
	gatt_service_adv_updated(gatt_proxy_svc->gatt_service);
}

void gatt_proxy_svc_start(void)
{
	if (!gatt_proxy_svc || gatt_proxy_svc->gatt_service)
		return;

	gatt_proxy_svc->gatt_service = gatt_service_create(
					MESH_GATT_PROXY_SVC_UUID,
					MESH_GATT_PROXY_CHRC_DATA_IN,
					MESH_GATT_PROXY_CHRC_DATA_OUT,
					MAX_PROXY_PDU_LEN,
					gatt_service_notify_acquired,
					gatt_service_notify_stopped,
					gatt_service_rx,
					gatt_service_tx_cmplt,
					gatt_service_fill_adv_service_data,
					gatt_proxy_svc);

	gatt_proxy_svc->adv_key_cycle_to = l_timeout_create(3,
						gatt_proxy_svc_cycle_adv,
						gatt_proxy_svc, NULL);

	mesh_net_attach_gatt(gatt_proxy_svc);
}

void gatt_proxy_svc_stop(void)
{
	if (!gatt_proxy_svc || !gatt_proxy_svc->gatt_service)
		return;

	mesh_net_detach_gatt(gatt_proxy_svc);
	l_timeout_remove(gatt_proxy_svc->adv_key_cycle_to);
	gatt_service_destroy(gatt_proxy_svc->gatt_service, NULL, NULL);
}

void gatt_proxy_svc_create(void)
{
	if (gatt_proxy_svc)
		return;

	gatt_proxy_svc = l_new(struct gatt_proxy_svc, 1);
	gatt_proxy_svc->tx_deferred = l_queue_new();
	gatt_proxy_svc->rx_regs = l_queue_new();

	/* Check whether we have at least one key */
	if (!net_key_get_next_id(0))
		return;

	gatt_proxy_svc_start();
}

void gatt_proxy_svc_destroy(void)
{
	if (!gatt_proxy_svc)
		return;

	gatt_proxy_svc_stop();

	l_queue_destroy(gatt_proxy_svc->rx_regs, l_free);
	l_queue_destroy(gatt_proxy_svc->tx_deferred, l_free);
	l_free(gatt_proxy_svc);
	gatt_proxy_svc = NULL;
}
