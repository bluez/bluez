// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2021  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <ell/ell.h>

#include "mesh/mesh-defs.h"
#include "mesh/dbus.h"
#include "mesh/mesh-io.h"
#include "mesh/mesh-io-api.h"
#include "mesh/mesh-io-generic.h"

struct mesh_io_private {
	struct l_io *sio;
	void *user_data;
	char *unique_name;
	mesh_io_ready_func_t ready_callback;
	struct l_timeout *tx_timeout;
	struct l_queue *rx_regs;
	struct l_queue *tx_pkts;
	struct sockaddr_un addr;
	int fd;
	uint16_t interval;
};

struct pvt_rx_reg {
	mesh_io_recv_func_t cb;
	void *user_data;
	uint8_t len;
	uint8_t filter[0];
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
	uint8_t				pkt[30];
};

struct tx_pattern {
	const uint8_t			*data;
	uint8_t				len;
};

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

static void process_rx_callbacks(void *v_reg, void *v_rx)
{
	struct pvt_rx_reg *rx_reg = v_reg;
	struct process_data *rx = v_rx;

	if (!memcmp(rx->data, rx_reg->filter, rx_reg->len))
		rx_reg->cb(rx_reg->user_data, &rx->info, rx->data, rx->len);
}

static void process_rx(struct mesh_io_private *pvt, int8_t rssi,
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

	l_queue_foreach(pvt->rx_regs, process_rx_callbacks, &rx);
}

static bool incoming(struct l_io *sio, void *user_data)
{
	struct mesh_io_private *pvt = user_data;
	uint32_t instant;
	uint8_t buf[31];
	size_t size;

	instant = get_instant();

	size = recv(pvt->fd, buf, sizeof(buf), MSG_DONTWAIT);

	if (size > 9 && buf[0]) {
		process_rx(pvt, -20, instant, NULL, buf + 1, (uint8_t)size);
	} else if (size == 1 && !buf[0] && pvt->unique_name) {

		/* Return DBUS unique name */
		size = strlen(pvt->unique_name);

		if (size > sizeof(buf) - 2)
			return true;

		buf[0] = 0;
		memcpy(buf + 1, pvt->unique_name, size + 1);
		if (send(pvt->fd, buf, size + 2, MSG_DONTWAIT) < 0)
			l_error("Failed to send(%d)", errno);
	}

	return true;
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

static void free_socket(struct mesh_io_private *pvt)
{
	l_io_destroy(pvt->sio);
	close(pvt->fd);
	unlink(pvt->addr.sun_path);
}

static void hello_callback(struct l_dbus_message *msg, void *user_data)
{
	struct mesh_io_private *pvt = user_data;

	pvt->unique_name = l_strdup(l_dbus_message_get_destination(msg));
	l_debug("User-Daemon unique name: %s", pvt->unique_name);
}

static void get_name(struct l_timeout *timeout, void *user_data)
{
	struct mesh_io_private *pvt = user_data;
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *msg;

	l_timeout_remove(timeout);
	if (!dbus) {
		l_timeout_create_ms(20, get_name, pvt, NULL);
		return;
	}

	/* Retrieve unique name */
	msg = l_dbus_message_new_method_call(dbus, "org.freedesktop.DBus",
							"/org/freedesktop/DBus",
							"org.freedesktop.DBus",
							"GetId");

	l_dbus_message_set_arguments(msg, "");

	l_dbus_send_with_reply(dbus, msg, hello_callback, pvt, NULL);
}

static void unit_up(void *user_data)
{
	struct mesh_io_private *pvt = user_data;

	l_debug("Started io-unit");

	if (pvt->ready_callback)
		pvt->ready_callback(pvt->user_data, true);

	l_timeout_create_ms(1, get_name, pvt, NULL);
}

static bool unit_init(struct mesh_io *io, void *opt,
				mesh_io_ready_func_t cb, void *user_data)
{
	struct mesh_io_private *pvt;
	char *sk_path;
	size_t size;

	l_debug("Starting Unit test IO");
	if (!io || io->pvt)
		return false;

	sk_path = (char *) opt;

	pvt = l_new(struct mesh_io_private, 1);

	pvt->addr.sun_family = AF_LOCAL;
	snprintf(pvt->addr.sun_path, sizeof(pvt->addr.sun_path), "%s",
								sk_path);

	pvt->fd = socket(PF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (pvt->fd < 0)
		goto fail;

	unlink(pvt->addr.sun_path);
	size = offsetof(struct sockaddr_un, sun_path) +
						strlen(pvt->addr.sun_path);

	if (bind(pvt->fd, (struct sockaddr *) &pvt->addr, size) < 0)
		goto fail;

	/* Setup socket handlers */
	pvt->sio = l_io_new(pvt->fd);
	if (!l_io_set_read_handler(pvt->sio, incoming, pvt, NULL))
		goto fail;

	pvt->rx_regs = l_queue_new();
	pvt->tx_pkts = l_queue_new();

	pvt->ready_callback = cb;
	pvt->user_data = user_data;

	io->pvt = pvt;

	l_idle_oneshot(unit_up, pvt, NULL);

	return true;

fail:
	l_error("Failed to bind Unit Test socket");
	free_socket(pvt);
	l_free(pvt);

	return false;
}

static bool unit_destroy(struct mesh_io *io)
{
	struct mesh_io_private *pvt = io->pvt;

	if (!pvt)
		return true;

	l_free(pvt->unique_name);
	l_timeout_remove(pvt->tx_timeout);
	l_queue_destroy(pvt->rx_regs, l_free);
	l_queue_destroy(pvt->tx_pkts, l_free);

	free_socket(pvt);

	l_free(pvt);
	io->pvt = NULL;

	return true;
}

static bool unit_caps(struct mesh_io *io, struct mesh_io_caps *caps)
{
	struct mesh_io_private *pvt = io->pvt;

	if (!pvt || !caps)
		return false;

	caps->max_num_filters = 255;
	caps->window_accuracy = 50;

	return true;
}

static bool simple_match(const void *a, const void *b)
{
	return a == b;
}

static void send_pkt(struct mesh_io_private *pvt, struct tx_pkt *tx,
							uint16_t interval)
{
	if (send(pvt->fd, tx->pkt, tx->len, MSG_DONTWAIT) < 0)
		l_error("Failed to send(%d)", errno);

	if (tx->delete) {
		l_queue_remove_if(pvt->tx_pkts, simple_match, tx);
		l_free(tx);
	}
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

	tx->delete = !!(count == 1);

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
	struct mesh_io_private *pvt = io->pvt;
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

		} while (tx);
	}

	if (l_queue_isempty(pvt->tx_pkts)) {
		l_timeout_remove(pvt->tx_timeout);
		pvt->tx_timeout = NULL;
	}

	return true;
}

static bool find_by_filter(const void *a, const void *b)
{
	const struct pvt_rx_reg *rx_reg = a;
	const uint8_t *filter = b;

	return !memcmp(rx_reg->filter, filter, rx_reg->len);
}

static bool recv_register(struct mesh_io *io, const uint8_t *filter,
			uint8_t len, mesh_io_recv_func_t cb, void *user_data)
{
	struct mesh_io_private *pvt = io->pvt;
	struct pvt_rx_reg *rx_reg;

	if (!cb || !filter || !len)
		return false;

	rx_reg = l_queue_remove_if(pvt->rx_regs, find_by_filter, filter);

	l_free(rx_reg);
	rx_reg = l_malloc(sizeof(*rx_reg) + len);

	memcpy(rx_reg->filter, filter, len);
	rx_reg->len = len;
	rx_reg->cb = cb;
	rx_reg->user_data = user_data;

	l_queue_push_head(pvt->rx_regs, rx_reg);

	return true;
}

static bool recv_deregister(struct mesh_io *io, const uint8_t *filter,
								uint8_t len)
{
	return true;
}

const struct mesh_io_api mesh_io_unit = {
	.init = unit_init,
	.destroy = unit_destroy,
	.caps = unit_caps,
	.send = send_tx,
	.reg = recv_register,
	.dereg = recv_deregister,
	.cancel = tx_cancel,
};
