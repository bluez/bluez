// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <ell/ell.h>

#include "monitor/bt.h"
#include "bluetooth/bluetooth.h"
#include "bluetooth/bluetooth.h"
#include "bluetooth/mgmt.h"
#include "src/shared/ad.h"
#include "src/shared/mgmt.h"

#include "mesh/mesh-defs.h"
#include "mesh/util.h"
#include "mesh/mesh-mgmt.h"
#include "mesh/mesh-io.h"
#include "mesh/mesh-io-api.h"
#include "mesh/mesh-io-mgmt.h"

struct mesh_io_private {
	struct mesh_io *io;
	void *user_data;
	struct l_timeout *tx_timeout;
	struct l_timeout *dup_timeout;
	struct l_queue *dup_filters;
	struct l_queue *tx_pkts;
	struct tx_pkt *tx;
	unsigned int tx_id;
	unsigned int rx_id;
	uint16_t send_idx;
	uint16_t interval;
	uint8_t handle;
	bool sending;
	bool active;
};

struct process_data {
	struct mesh_io_private		*pvt;
	const uint8_t			*data;
	uint8_t				len;
	struct mesh_io_recv_info	info;
};

struct tx_pkt {
	struct mesh_io_send_info	info;
	bool				delete;
	uint8_t				len;
	uint8_t				pkt[MESH_AD_MAX_LEN];
};

struct tx_pattern {
	const uint8_t			*data;
	uint8_t				len;
};

#define DUP_FILTER_TIME        1000
/* Accept one instance of unique message a second */
struct dup_filter {
	uint64_t data;
	uint32_t instant;
	uint8_t addr[6];
} __packed;

static const uint8_t zero_addr[] = {0, 0, 0, 0, 0, 0};

static struct mesh_io_private *pvt;

static uint32_t get_instant(void)
{
	struct timeval tm;
	uint32_t instant;

	gettimeofday(&tm, NULL);
	instant = tm.tv_sec * 1000;
	instant += tm.tv_usec / 1000;

	return instant;
}

static uint32_t instant_remaining_ms(uint32_t instant)
{
	instant -= get_instant();

	return instant;
}

static bool find_by_addr(const void *a, const void *b)
{
	const struct dup_filter *filter = a;

	return !memcmp(filter->addr, b, 6);
}

static bool find_by_adv(const void *a, const void *b)
{
	const struct dup_filter *filter = a;
	uint64_t data = l_get_be64(b);

	return !memcmp(filter->addr, zero_addr, 6) && filter->data == data;
}

static void filter_timeout(struct l_timeout *timeout, void *user_data)
{
	struct dup_filter *filter;
	uint32_t instant, delta;

	if (!pvt)
		goto done;

	instant = get_instant();

	filter = l_queue_peek_tail(pvt->dup_filters);
	while (filter) {
		delta = instant - filter->instant;
		if (delta >= DUP_FILTER_TIME) {
			l_queue_remove(pvt->dup_filters, filter);
			l_free(filter);
		} else {
			l_timeout_modify(timeout, 1);
			return;
		}

		filter = l_queue_peek_tail(pvt->dup_filters);
	}

	pvt->dup_timeout = NULL;

done:
	l_timeout_remove(timeout);
}

/* Ignore consecutive duplicate advertisements within timeout period */
static bool filter_dups(const uint8_t *addr, const uint8_t *adv,
							uint32_t instant)
{
	struct dup_filter *filter;
	uint32_t instant_delta;
	uint64_t data = l_get_be64(adv);

	if (!addr)
		addr = zero_addr;

	if (adv[1] == BT_AD_MESH_PROV) {
		filter = l_queue_find(pvt->dup_filters, find_by_adv, adv);

		if (!filter && addr != zero_addr)
			return false;

		l_queue_remove(pvt->dup_filters, filter);

	} else {
		filter = l_queue_remove_if(pvt->dup_filters, find_by_addr,
									addr);
	}

	if (!filter) {
		filter = l_new(struct dup_filter, 1);
		memcpy(filter->addr, addr, 6);
	}

	/* Start filter expiration timer */
	if (!l_queue_length(pvt->dup_filters))
		pvt->dup_timeout = l_timeout_create(1, filter_timeout, NULL,
									NULL);

	l_queue_push_head(pvt->dup_filters, filter);
	instant_delta = instant - filter->instant;

	if (instant_delta >= DUP_FILTER_TIME || data != filter->data) {
		filter->instant = instant;
		filter->data = data;
		return false;
	}

	return true;
}

static void process_rx_callbacks(void *v_reg, void *v_rx)
{
	struct mesh_io_reg *rx_reg = v_reg;
	struct process_data *rx = v_rx;

	if (!memcmp(rx->data, rx_reg->filter, rx_reg->len))
		rx_reg->cb(rx_reg->user_data, &rx->info, rx->data, rx->len);
}

static void process_rx(uint16_t index, struct mesh_io_private *pvt, int8_t rssi,
					uint32_t instant, const uint8_t *addr,
					const uint8_t *data, uint8_t len)
{
	struct process_data rx = {
		.pvt = pvt,
		.data = data,
		.len = len,
		.info.instant = instant,
		.info.addr = addr,
		.info.chan = 7,
		.info.rssi = rssi,
	};

	/* Accept all traffic except beacons from any controller */
	if (index != pvt->send_idx && data[0] == BT_AD_MESH_BEACON)
		return;

	print_packet("RX", data, len);
	l_queue_foreach(pvt->io->rx_regs, process_rx_callbacks, &rx);
}

static void send_cmplt(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	/* print_packet("Mesh Send Complete", param, length); */
}

static void event_device_found(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_ev_mesh_device_found *ev = param;
	struct mesh_io_private *pvt = user_data;
	const uint8_t *adv;
	const uint8_t *addr;
	uint32_t instant;
	uint16_t adv_len;
	uint16_t len = 0;

	if (ev->addr.type < 1 || ev->addr.type > 2)
		return;

	instant = get_instant();
	adv = ev->eir;
	adv_len = ev->eir_len;
	addr = ev->addr.bdaddr.b;

	if (filter_dups(addr, adv, instant))
		return;

	while (len < adv_len - 1) {
		uint8_t field_len = adv[0];

		/* Check for the end of advertising data */
		if (field_len == 0)
			break;

		len += field_len + 1;

		/* Do not continue data parsing if got incorrect length */
		if (len > adv_len)
			break;

		if (adv[1] >= BT_AD_MESH_PROV && adv[1] <= BT_AD_MESH_BEACON)
			process_rx(index, pvt, ev->rssi, instant, addr,
							adv + 1, adv[0]);

		adv += field_len + 1;
	}
}

static bool simple_match(const void *a, const void *b)
{
	return a == b;
}

static bool find_by_ad_type(const void *a, const void *b)
{
	const struct tx_pkt *tx = a;
	uint8_t ad_type = L_PTR_TO_UINT(b);

	return !ad_type || ad_type == tx->pkt[0];
}

static bool find_by_pattern(const void *a, const void *b)
{
	const struct tx_pkt *tx = a;
	const struct tx_pattern *pattern = b;

	if (tx->len < pattern->len)
		return false;

	return (!memcmp(tx->pkt, pattern->data, pattern->len));
}

static bool find_active(const void *a, const void *b)
{
	const struct mesh_io_reg *rx_reg = a;

	/* Mesh specific AD types do *not* require active scanning,
	 * so do not turn on Active Scanning on their account.
	 */
	if (rx_reg->filter[0] < BT_AD_MESH_PROV ||
					rx_reg->filter[0] > BT_AD_MESH_BEACON)
		return true;

	return false;
}

static void mesh_up(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int index = L_PTR_TO_UINT(user_data);

	l_debug("HCI%d Mesh up status: %d", index, status);
}

static void le_up(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int index = L_PTR_TO_UINT(user_data);

	l_debug("HCI%d LE up status: %d", index, status);
}

static void ctl_up(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	int index = L_PTR_TO_UINT(user_data);
	uint16_t len;
	struct mgmt_cp_set_mesh *mesh;
	uint8_t mesh_ad_types[] = { BT_AD_MESH_DATA, BT_AD_MESH_BEACON,
							BT_AD_MESH_PROV };

	l_debug("HCI%d is up status: %d", index, status);
	if (status)
		return;

	len = sizeof(struct mgmt_cp_set_mesh) + sizeof(mesh_ad_types);
	mesh = l_malloc(len);

	mesh->enable = 1;
	mesh->window = L_CPU_TO_LE16(0x1000);
	mesh->period = L_CPU_TO_LE16(0x1000);
	mesh->num_ad_types = sizeof(mesh_ad_types);
	memcpy(mesh->ad_types, mesh_ad_types, sizeof(mesh_ad_types));

	pvt->rx_id = mesh_mgmt_register(MGMT_EV_MESH_DEVICE_FOUND,
				MGMT_INDEX_NONE, event_device_found, pvt,
				NULL);
	pvt->tx_id = mesh_mgmt_register(MGMT_EV_MESH_PACKET_CMPLT,
					index, send_cmplt, pvt, NULL);

	mesh_mgmt_send(MGMT_OP_SET_MESH_RECEIVER, index, len, mesh,
			mesh_up, L_UINT_TO_PTR(index), NULL);
	l_debug("done %d mesh startup", index);

	l_free(mesh);

	if (pvt->send_idx == MGMT_INDEX_NONE) {
		pvt->send_idx = index;
		if (pvt && pvt->io && pvt->io->ready) {
			pvt->io->ready(pvt->io->user_data, true);
			pvt->io->ready = NULL;
		}
	}
}

static void read_info_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	unsigned char le[] = { 0x01 };
	int index = L_PTR_TO_UINT(user_data);
	const struct mgmt_rp_read_info *rp = param;
	uint32_t current_settings, supported_settings;

	l_debug("hci %u status 0x%02x", index, status);

	if (!pvt)
		return;

	if (status != MGMT_STATUS_SUCCESS) {
		l_error("Failed to read info for hci index %u: %s (0x%02x)",
				index, mgmt_errstr(status), status);
		return;
	}

	if (length < sizeof(*rp)) {
		l_error("Read info response too short");
		return;
	}

	current_settings = btohl(rp->current_settings);
	supported_settings = btohl(rp->supported_settings);

	if (!(supported_settings & MGMT_SETTING_LE)) {
		l_info("Controller hci %u does not support LE", index);
		return;
	}

	if (!(current_settings & MGMT_SETTING_POWERED)) {
		unsigned char power[] = { 0x01 };

		/* TODO: Initialize this HCI controller */
		l_info("Controller hci %u not in use", index);

		mesh_mgmt_send(MGMT_OP_SET_LE, index,
				sizeof(le), &le,
				le_up, L_UINT_TO_PTR(index), NULL);

		mesh_mgmt_send(MGMT_OP_SET_POWERED, index,
				sizeof(power), &power,
				ctl_up, L_UINT_TO_PTR(index), NULL);
	} else {

		l_info("Controller hci %u already in use (%x)",
						index, current_settings);

		/* Share this controller with bluetoothd */
		mesh_mgmt_send(MGMT_OP_SET_LE, index,
				sizeof(le), &le,
				ctl_up, L_UINT_TO_PTR(index), NULL);

	}
}

static bool dev_init(struct mesh_io *io, void *opts, void *user_data)
{
	uint16_t index = *(int *)opts;

	if (!io || pvt)
		return false;

	pvt = l_new(struct mesh_io_private, 1);

	pvt->send_idx = MGMT_INDEX_NONE;

	mesh_mgmt_send(MGMT_OP_READ_INFO, index, 0, NULL,
				read_info_cb, L_UINT_TO_PTR(index), NULL);

	pvt->dup_filters = l_queue_new();
	pvt->tx_pkts = l_queue_new();

	pvt->io = io;
	io->pvt = pvt;

	return true;
}

static bool dev_destroy(struct mesh_io *io)
{
	unsigned char param[] = { 0x00 };

	if (io->pvt != pvt)
		return true;

	mesh_mgmt_send(MGMT_OP_SET_POWERED, io->index, sizeof(param), &param,
							NULL, NULL, NULL);

	mesh_mgmt_unregister(pvt->rx_id);
	mesh_mgmt_unregister(pvt->tx_id);
	l_timeout_remove(pvt->tx_timeout);
	l_timeout_remove(pvt->dup_timeout);
	l_queue_destroy(pvt->dup_filters, l_free);
	l_queue_destroy(pvt->tx_pkts, l_free);
	io->pvt = NULL;
	l_free(pvt);
	pvt = NULL;

	return true;
}

static bool dev_caps(struct mesh_io *io, struct mesh_io_caps *caps)
{
	struct mesh_io_private *pvt = io->pvt;

	if (!pvt || !caps)
		return false;

	caps->max_num_filters = 255;
	caps->window_accuracy = 50;

	return true;
}

static void send_cancel(struct mesh_io_private *pvt)
{
	struct mgmt_cp_mesh_send_cancel remove;

	if (!pvt)
		return;

	if (pvt->handle) {
		remove.handle = pvt->handle;
		/* l_debug("Cancel TX"); */
		mesh_mgmt_send(MGMT_OP_MESH_SEND_CANCEL, pvt->send_idx,
						sizeof(remove), &remove,
						NULL, NULL, NULL);
	}
}

static void tx_to(struct l_timeout *timeout, void *user_data);
static void send_queued(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct tx_pkt *tx = user_data;

	if (status)
		l_debug("Mesh Send Failed: %d", status);
	else if (param && length >= 1)
		pvt->handle = *(uint8_t *) param;

	if (tx->delete) {
		l_queue_remove_if(pvt->tx_pkts, simple_match, tx);
		l_free(tx);
		pvt->tx = NULL;
	}
}

static void send_pkt(struct mesh_io_private *pvt, struct tx_pkt *tx,
							uint16_t interval)
{
	uint8_t buffer[sizeof(struct mgmt_cp_mesh_send) + tx->len + 1];
	struct mgmt_cp_mesh_send *send = (void *) buffer;
	uint16_t index;
	size_t len;

	if (!pvt)
		return;

	index = pvt->send_idx;

	len = sizeof(buffer);
	memset(send, 0, len);
	send->addr.type = BDADDR_LE_RANDOM;
	send->instant = 0;
	send->delay = 0;
	send->cnt = 1;
	send->adv_data_len = tx->len + 1;
	send->adv_data[0] = tx->len;
	memcpy(send->adv_data + 1, tx->pkt, tx->len);

	/* Filter looped back Provision packets */
	if (tx->pkt[0] == BT_AD_MESH_PROV)
		filter_dups(NULL, send->adv_data, get_instant());

	mesh_mgmt_send(MGMT_OP_MESH_SEND, index,
			len, send, send_queued, tx, NULL);
	/* print_packet("Mesh Send Start", tx->pkt, tx->len); */
	pvt->tx = tx;
}

static void tx_to(struct l_timeout *timeout, void *user_data)
{
	struct mesh_io_private *pvt = user_data;
	struct tx_pkt *tx;
	uint16_t ms;
	uint8_t count;

	if (!pvt)
		return;

	tx = l_queue_pop_head(pvt->tx_pkts);
	if (!tx) {
		l_timeout_remove(timeout);
		pvt->tx_timeout = NULL;
		send_cancel(pvt);
		pvt->tx = NULL;
		return;
	}

	if (tx->info.type == MESH_IO_TIMING_TYPE_GENERAL) {
		ms = tx->info.u.gen.interval;
		count = tx->info.u.gen.cnt;
		if (count != MESH_IO_TX_COUNT_UNLIMITED)
			tx->info.u.gen.cnt--;
	} else {
		ms = 25;
		count = 1;
	}

	tx->delete = (count == 1);

	send_pkt(pvt, tx, ms);

	if (count == 1) {
		/* Recalculate wakeup if we are responding to POLL */
		tx = l_queue_peek_head(pvt->tx_pkts);

		if (tx && tx->info.type == MESH_IO_TIMING_TYPE_POLL_RSP) {
			ms = instant_remaining_ms(tx->info.u.poll_rsp.instant +
						tx->info.u.poll_rsp.delay);
		}
	} else
		l_queue_push_tail(pvt->tx_pkts, tx);

	if (timeout) {
		pvt->tx_timeout = timeout;
		l_timeout_modify_ms(timeout, ms);
	} else
		pvt->tx_timeout = l_timeout_create_ms(ms, tx_to, pvt, NULL);
}

static void tx_worker(void *user_data)
{
	struct mesh_io_private *pvt = user_data;
	struct tx_pkt *tx;
	uint32_t delay;

	tx = l_queue_peek_head(pvt->tx_pkts);
	if (!tx)
		return;

	switch (tx->info.type) {
	case MESH_IO_TIMING_TYPE_GENERAL:
		if (tx->info.u.gen.min_delay == tx->info.u.gen.max_delay)
			delay = tx->info.u.gen.min_delay;
		else {
			l_getrandom(&delay, sizeof(delay));
			delay %= tx->info.u.gen.max_delay -
						tx->info.u.gen.min_delay;
			delay += tx->info.u.gen.min_delay;
		}
		break;

	case MESH_IO_TIMING_TYPE_POLL:
		if (tx->info.u.poll.min_delay == tx->info.u.poll.max_delay)
			delay = tx->info.u.poll.min_delay;
		else {
			l_getrandom(&delay, sizeof(delay));
			delay %= tx->info.u.poll.max_delay -
						tx->info.u.poll.min_delay;
			delay += tx->info.u.poll.min_delay;
		}
		break;

	case MESH_IO_TIMING_TYPE_POLL_RSP:
		/* Delay until Instant + Delay */
		delay = instant_remaining_ms(tx->info.u.poll_rsp.instant +
						tx->info.u.poll_rsp.delay);
		if (delay > 255)
			delay = 0;
		break;

	default:
		return;
	}

	if (!delay)
		tx_to(pvt->tx_timeout, pvt);
	else if (pvt->tx_timeout)
		l_timeout_modify_ms(pvt->tx_timeout, delay);
	else
		pvt->tx_timeout = l_timeout_create_ms(delay, tx_to, pvt, NULL);
}

static bool send_tx(struct mesh_io *io, struct mesh_io_send_info *info,
					const uint8_t *data, uint16_t len)
{
	struct tx_pkt *tx;
	bool sending = false;

	if (!info || !data || !len || len > sizeof(tx->pkt))
		return false;

	tx = l_new(struct tx_pkt, 1);

	memcpy(&tx->info, info, sizeof(tx->info));
	memcpy(&tx->pkt, data, len);
	tx->len = len;

	if (info->type == MESH_IO_TIMING_TYPE_POLL_RSP)
		l_queue_push_head(pvt->tx_pkts, tx);
	else {
		if (pvt->tx)
			sending = true;
		else
			sending = !l_queue_isempty(pvt->tx_pkts);

		l_queue_push_tail(pvt->tx_pkts, tx);
	}

	if (!sending) {
		l_timeout_remove(pvt->tx_timeout);
		pvt->tx_timeout = NULL;
		l_idle_oneshot(tx_worker, pvt, NULL);
	}

	return true;
}

static bool tx_cancel(struct mesh_io *io, const uint8_t *data, uint8_t len)
{
	struct mesh_io_private *pvt = io->pvt;
	struct tx_pkt *tx;

	if (!data)
		return false;

	if (len == 1) {
		do {
			tx = l_queue_remove_if(pvt->tx_pkts, find_by_ad_type,
							L_UINT_TO_PTR(data[0]));
			l_free(tx);

			if (tx == pvt->tx)
				pvt->tx = NULL;

		} while (tx);
	} else {
		struct tx_pattern pattern = {
			.data = data,
			.len = len
		};

		do {
			tx = l_queue_remove_if(pvt->tx_pkts, find_by_pattern,
								&pattern);
			l_free(tx);

			if (tx == pvt->tx)
				pvt->tx = NULL;

		} while (tx);
	}

	if (l_queue_isempty(pvt->tx_pkts)) {
		send_cancel(pvt);
		l_timeout_remove(pvt->tx_timeout);
		pvt->tx_timeout = NULL;
	}

	return true;
}

static bool recv_register(struct mesh_io *io, const uint8_t *filter,
			uint8_t len, mesh_io_recv_func_t cb, void *user_data)
{
	bool active = false;

	if (io->pvt != pvt)
		return false;

	/* Look for any AD types requiring Active Scanning */
	if (l_queue_find(io->rx_regs, find_active, NULL))
		active = true;

	if (pvt->active != active) {
		pvt->active = active;
		/* TODO: Request active or passive scanning */
	}

	return true;
}

static bool recv_deregister(struct mesh_io *io, const uint8_t *filter,
								uint8_t len)
{
	bool active = false;

	if (io->pvt != pvt)
		return false;

	/* Look for any AD types requiring Active Scanning */
	if (l_queue_find(io->rx_regs, find_active, NULL))
		active = true;

	if (active != pvt->active) {
		pvt->active = active;
		/* TODO: Request active or passive scanning */
	}

	return true;
}

const struct mesh_io_api mesh_io_mgmt = {
	.init = dev_init,
	.destroy = dev_destroy,
	.caps = dev_caps,
	.send = send_tx,
	.reg = recv_register,
	.dereg = recv_deregister,
	.cancel = tx_cancel,
};
