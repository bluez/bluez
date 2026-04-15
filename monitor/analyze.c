// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "bluetooth/bluetooth.h"

#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/btsnoop.h"
#include "monitor/bt.h"
#include "monitor/display.h"
#include "monitor/packet.h"
#include "monitor/analyze.h"

#define TIMEVAL_MSEC(_tv) \
	(long long)((_tv)->tv_sec * 1000 + (_tv)->tv_usec / 1000)

struct hci_dev {
	uint16_t index;
	uint8_t type;
	uint8_t bdaddr[6];
	struct timeval time_added;
	struct timeval time_removed;
	unsigned long num_hci;
	unsigned long num_cmd;
	unsigned long num_evt;
	unsigned long num_acl;
	unsigned long num_sco;
	unsigned long num_iso;
	unsigned long vendor_diag;
	unsigned long system_note;
	unsigned long user_log;
	unsigned long ctrl_msg;
	unsigned long unknown;
	uint16_t manufacturer;
	struct queue *conn_list;
};

struct hci_stats {
	size_t bytes;
	size_t num;
	size_t num_comp;
	struct packet_latency latency;
	struct queue *plot;
	uint16_t min;
	uint16_t max;
	/* Wall-clock throughput tracking */
	struct timeval first_ts;
	struct timeval last_ts;
	/* Windowed throughput (1-second windows) */
	struct timeval window_start;
	size_t window_bytes;
	long long speed_min;	/* Kb/s, 0 = not set */
	long long speed_max;	/* Kb/s */
};

struct hci_conn {
	uint16_t handle;
	uint16_t link;
	uint8_t type;
	uint8_t bdaddr[6];
	uint8_t bdaddr_type;
	bool setup_seen;
	bool terminated;
	uint8_t disconnect_reason;
	unsigned long frame_connected;
	unsigned long frame_disconnected;
	struct queue *tx_queue;
	struct timeval last_rx;
	struct queue *chan_list;
	struct hci_stats rx;
	struct hci_stats tx;
};

struct hci_conn_tx {
	struct timeval tv;
	struct l2cap_chan *chan;
};

struct plot {
	long long x_msec;
	size_t y_count;
};

struct l2cap_chan {
	uint16_t cid;
	uint16_t psm;
	uint16_t mtu;
	uint16_t mps;
	uint8_t mode;
	bool out;
	struct timeval last_rx;
	struct hci_stats rx;
	struct hci_stats tx;
};

static struct queue *dev_list;

static void tmp_write(void *data, void *user_data)
{
	struct plot *plot = data;
	FILE *tmp = user_data;

	fprintf(tmp, "%lld %zu\n", plot->x_msec, plot->y_count);
}

static void plot_draw(struct queue *queue, const char *title)
{
	FILE *gplot;

	if (queue_length(queue) < 2)
		return;

	gplot = popen("gnuplot", "w");
	if (!gplot)
		return;

	fprintf(gplot, "$data << EOD\n");
	queue_foreach(queue, tmp_write, gplot);
	fprintf(gplot, "EOD\n");

	fprintf(gplot, "set terminal dumb enhanced ansi\n");
	fprintf(gplot, "set xlabel 'Latency (ms)'\n");
	fprintf(gplot, "set tics out nomirror\n");
	fprintf(gplot, "set log y\n");
	fprintf(gplot, "set yrange [0.5:*]\n");
	fprintf(gplot, "plot $data using 1:2 t '%s' w impulses\n", title);
	fflush(gplot);

	pclose(gplot);
}

static void print_stats(struct hci_stats *stats, const char *label)
{
	long long duration_ms;

	if (!stats->num)
		return;

	print_field("%s packets: %zu/%zu", label, stats->num, stats->num_comp);
	print_field("%s Latency: %lld-%lld msec (~%lld msec)", label,
			TV_MSEC(stats->latency.min),
			TV_MSEC(stats->latency.max),
			TV_MSEC(stats->latency.med));
	print_field("%s size: %u-%u octets (~%zd octets)", label,
			stats->min, stats->max, stats->bytes / stats->num);

	/* Compute wall-clock speed from first/last packet timestamps */
	duration_ms = TV_MSEC(stats->last_ts) - TV_MSEC(stats->first_ts);
	if (duration_ms > 0) {
		long long avg_speed = stats->bytes * 8 / duration_ms;

		/* Close the last window for min/max if it has data */
		if (stats->window_bytes > 0 && stats->num > 1) {
			struct timeval delta;
			long long last_win_ms;

			timersub(&stats->last_ts, &stats->window_start,
								&delta);
			last_win_ms = TV_MSEC(delta);
			if (last_win_ms > 0) {
				long long speed;

				speed = stats->window_bytes * 8 /
								last_win_ms;
				if (!stats->speed_min ||
						speed < stats->speed_min)
					stats->speed_min = speed;
				if (speed > stats->speed_max)
					stats->speed_max = speed;
			}
		}

		if (stats->speed_min && stats->speed_max)
			print_field("%s speed: ~%lld Kb/s "
				"(min ~%lld Kb/s max ~%lld Kb/s)",
				label, avg_speed,
				stats->speed_min, stats->speed_max);
		else
			print_field("%s speed: ~%lld Kb/s", label,
								avg_speed);
	}

	plot_draw(stats->plot, label);
}

static const char *fixed_channel_name(uint16_t cid)
{
	switch (cid) {
	case 0x0001:
		return "L2CAP Signaling (BR/EDR)";
	case 0x0002:
		return "Connectionless";
	case 0x0003:
		return "AMP Manager";
	case 0x0004:
		return "ATT";
	case 0x0005:
		return "L2CAP Signaling (LE)";
	case 0x0006:
		return "SMP (LE)";
	case 0x0007:
		return "SMP (BR/EDR)";
	default:
		return NULL;
	}
}

static const char *l2cap_mode_name(uint8_t mode)
{
	switch (mode) {
	case 0x00:
		return "Basic";
	case 0x01:
		return "Retransmission";
	case 0x02:
		return "Flow Control";
	case 0x03:
		return "ERTM";
	case 0x04:
		return "Streaming";
	case 0x80:
		return "LE Credit";
	case 0x81:
		return "Enhanced Credit";
	default:
		return "Unknown";
	}
}

static void chan_destroy(void *data)
{
	struct l2cap_chan *chan = data;
	const char *fixed;

	if (!chan->rx.num && !chan->tx.num)
		goto done;

	fixed = fixed_channel_name(chan->cid);
	if (fixed)
		printf("  Found %s L2CAP channel with CID %u (%s)\n",
					chan->out ? "TX" : "RX", chan->cid,
					fixed);
	else
		printf("  Found %s L2CAP channel with CID %u\n",
					chan->out ? "TX" : "RX", chan->cid);

	if (chan->psm)
		print_field("PSM %u (0x%04x)", chan->psm, chan->psm);
	if (!fixed) {
		print_field("Mode: %s", l2cap_mode_name(chan->mode));
		if (chan->mtu)
			print_field("MTU: %u", chan->mtu);
		if (chan->mps)
			print_field("MPS: %u", chan->mps);
	}

	print_stats(&chan->rx, "RX");
	print_stats(&chan->tx, "TX");

done:
	free(chan);
}

static struct l2cap_chan *chan_alloc(struct hci_conn *conn, uint16_t cid,
								bool out)
{
	struct l2cap_chan *chan;

	chan = new0(struct l2cap_chan, 1);

	chan->cid = cid;
	chan->out = out;
	chan->rx.plot = queue_new();
	chan->tx.plot = queue_new();

	return chan;
}

static bool chan_match_cid(const void *a, const void *b)
{
	const struct l2cap_chan *chan = a;
	uint32_t val = PTR_TO_UINT(b);
	uint16_t cid = val & 0xffff;
	bool out = val & 0x10000;

	return chan->cid == cid && chan->out == out;
}

static struct l2cap_chan *chan_lookup(struct hci_conn *conn, uint16_t cid,
								bool out)
{
	struct l2cap_chan *chan;
	uint32_t val = cid | (out ? 0x10000 : 0);

	chan = queue_find(conn->chan_list, chan_match_cid, UINT_TO_PTR(val));
	if (!chan) {
		chan = chan_alloc(conn, cid, out);
		queue_push_tail(conn->chan_list, chan);
	}

	return chan;
}

static void conn_destroy(void *data)
{
	struct hci_conn *conn = data;
	const char *str;

	switch (conn->type) {
	case BTMON_CONN_ACL:
		str = "BR-ACL";
		break;
	case BTMON_CONN_LE:
		str = "LE-ACL";
		break;
	case BTMON_CONN_SCO:
		str = "BR-SCO";
		break;
	case BTMON_CONN_ESCO:
		str = "BR-ESCO";
		break;
	case BTMON_CONN_CIS:
		str = "LE-CIS";
		break;
	case BTMON_CONN_BIS:
		str = "LE-BIS";
		break;
	default:
		str = "unknown";
		break;
	}

	printf("  Found %s connection with handle %u\n", str, conn->handle);
	packet_print_addr("Address", conn->bdaddr, conn->bdaddr_type);
	if (!conn->setup_seen)
		print_field("Connection setup missing");
	print_stats(&conn->rx, "RX");
	print_stats(&conn->tx, "TX");

	if (conn->setup_seen) {
		print_field("Connected: #%lu", conn->frame_connected);
		if (conn->terminated) {
			print_field("Disconnected: #%lu",
					conn->frame_disconnected);
			print_field("Disconnect Reason: 0x%02x",
						conn->disconnect_reason);
		}
	}

	queue_destroy(conn->rx.plot, free);
	queue_destroy(conn->tx.plot, free);
	queue_destroy(conn->chan_list, chan_destroy);

	queue_destroy(conn->tx_queue, free);
	free(conn);
}

static struct hci_conn *conn_alloc(struct hci_dev *dev, uint16_t handle,
								uint8_t type)
{
	struct hci_conn *conn;

	conn = new0(struct hci_conn, 1);

	conn->handle = handle;
	conn->type = type;
	conn->tx_queue = queue_new();
	conn->tx.plot = queue_new();
	conn->rx.plot = queue_new();

	conn->chan_list = queue_new();

	return conn;
}

static bool conn_match_handle(const void *a, const void *b)
{
	const struct hci_conn *conn = a;
	uint16_t handle = PTR_TO_UINT(b);

	return (conn->handle == handle && !conn->terminated);
}

static struct hci_conn *conn_lookup(struct hci_dev *dev, uint16_t handle)
{
	return queue_find(dev->conn_list, conn_match_handle,
						UINT_TO_PTR(handle));
}

static bool link_match_handle(const void *a, const void *b)
{
	const struct hci_conn *conn = a;
	uint16_t handle = PTR_TO_UINT(b);

	return (conn->link == handle && !conn->terminated);
}

static struct hci_conn *link_lookup(struct hci_dev *dev, uint16_t handle)
{
	return queue_find(dev->conn_list, link_match_handle,
						UINT_TO_PTR(handle));
}

static struct hci_conn *conn_lookup_type(struct hci_dev *dev, uint16_t handle,
								uint8_t type)
{
	struct hci_conn *conn;

	conn = queue_find(dev->conn_list, conn_match_handle,
						UINT_TO_PTR(handle));
	if (!conn || (type && conn->type != type)) {
		conn = conn_alloc(dev, handle, type);
		queue_push_tail(dev->conn_list, conn);
	}

	return conn;
}

static void dev_destroy(void *data)
{
	struct hci_dev *dev = data;
	const char *str;

	switch (dev->type) {
	case 0x00:
		str = "BR/EDR";
		break;
	case 0x01:
		str = "AMP";
		break;
	default:
		str = "unknown";
		break;
	}

	printf("Found %s controller with index %u\n", str, dev->index);
	printf("  BD_ADDR %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
			dev->bdaddr[5], dev->bdaddr[4], dev->bdaddr[3],
			dev->bdaddr[2], dev->bdaddr[1], dev->bdaddr[0]);
	if (dev->manufacturer != 0xffff)
		printf(" (%s)", bt_compidtostr(dev->manufacturer));
	printf("\n");


	printf("  %lu commands\n", dev->num_cmd);
	printf("  %lu events\n", dev->num_evt);
	printf("  %lu ACL packets\n", dev->num_acl);
	printf("  %lu SCO packets\n", dev->num_sco);
	printf("  %lu ISO packets\n", dev->num_iso);
	printf("  %lu vendor diagnostics\n", dev->vendor_diag);
	printf("  %lu system notes\n", dev->system_note);
	printf("  %lu user logs\n", dev->user_log);
	printf("  %lu control messages \n", dev->ctrl_msg);
	printf("  %lu unknown opcodes\n", dev->unknown);
	queue_destroy(dev->conn_list, conn_destroy);
	printf("\n");

	free(dev);
}

static struct hci_dev *dev_alloc(uint16_t index)
{
	struct hci_dev *dev;

	dev = new0(struct hci_dev, 1);

	dev->index = index;
	dev->manufacturer = 0xffff;

	dev->conn_list = queue_new();

	return dev;
}

static bool dev_match_index(const void *a, const void *b)
{
	const struct hci_dev *dev = a;
	uint16_t index = PTR_TO_UINT(b);

	return dev->index == index;
}

static struct hci_dev *dev_lookup(uint16_t index)
{
	struct hci_dev *dev;

	dev = queue_find(dev_list, dev_match_index, UINT_TO_PTR(index));
	if (!dev) {
		dev = dev_alloc(index);
		queue_push_tail(dev_list, dev);
	}

	return dev;
}

static void l2cap_sig(struct hci_conn *conn, bool out,
					const void *data, uint16_t size)
{
	const struct bt_l2cap_hdr_sig *hdr = data;
	struct l2cap_chan *chan;
	uint16_t psm, scid, dcid;

	switch (hdr->code) {
	case BT_L2CAP_PDU_CONN_REQ:
		psm = get_le16(data + 4);
		scid = get_le16(data + 6);
		chan = chan_lookup(conn, scid, out);
		if (chan)
			chan->psm = psm;
		break;
	case BT_L2CAP_PDU_CONN_RSP:
		dcid = get_le16(data + 4);
		scid = get_le16(data + 6);
		chan = chan_lookup(conn, scid, !out);
		if (chan) {
			psm = chan->psm;
			chan = chan_lookup(conn, dcid, out);
			if (chan)
				chan->psm = psm;
		}
		break;
	case BT_L2CAP_PDU_CONFIG_REQ:
	{
		const struct bt_l2cap_pdu_config_req *pdu = data + 4;
		const uint8_t *opts;
		uint16_t opts_len;

		dcid = le16_to_cpu(pdu->dcid);
		/* Options start after the 4-byte config req header */
		opts = data + 4 + sizeof(*pdu);
		opts_len = size - 4 - sizeof(*pdu);

		chan = chan_lookup(conn, dcid, !out);
		if (!chan)
			break;

		while (opts_len >= 2) {
			uint8_t type = opts[0];
			uint8_t len = opts[1];

			if (opts_len < (uint16_t)(2 + len))
				break;

			switch (type) {
			case 0x01: /* MTU */
				if (len >= 2)
					chan->mtu = get_le16(opts + 2);
				break;
			case 0x04: /* Retransmission and Flow Control */
				if (len >= 1)
					chan->mode = opts[2];
				break;
			}

			opts += 2 + len;
			opts_len -= 2 + len;
		}
		break;
	}
	case BT_L2CAP_PDU_CONFIG_RSP:
	{
		const struct bt_l2cap_pdu_config_rsp *pdu = data + 4;
		const uint8_t *opts;
		uint16_t opts_len;

		scid = le16_to_cpu(pdu->scid);
		/* Options start after the 6-byte config rsp header */
		opts = data + 4 + sizeof(*pdu);
		opts_len = size - 4 - sizeof(*pdu);

		chan = chan_lookup(conn, scid, out);
		if (!chan)
			break;

		while (opts_len >= 2) {
			uint8_t type = opts[0];
			uint8_t len = opts[1];

			if (opts_len < (uint16_t)(2 + len))
				break;

			switch (type) {
			case 0x01: /* MTU */
				if (len >= 2)
					chan->mtu = get_le16(opts + 2);
				break;
			case 0x04: /* Retransmission and Flow Control */
				if (len >= 1)
					chan->mode = opts[2];
				break;
			}

			opts += 2 + len;
			opts_len -= 2 + len;
		}
		break;
	}
	}
}

static void l2cap_le_sig(struct hci_conn *conn, bool out,
					const void *data, uint16_t size)
{
	const struct bt_l2cap_hdr_sig *hdr = data;
	struct l2cap_chan *chan;
	uint16_t psm, scid, dcid;

	switch (hdr->code) {
	case BT_L2CAP_PDU_LE_CONN_REQ:
	{
		const struct bt_l2cap_pdu_le_conn_req *pdu = data + 4;

		psm = le16_to_cpu(pdu->psm);
		scid = le16_to_cpu(pdu->scid);
		chan = chan_lookup(conn, scid, out);
		if (chan) {
			chan->psm = psm;
			chan->mtu = le16_to_cpu(pdu->mtu);
			chan->mps = le16_to_cpu(pdu->mps);
			chan->mode = 0x80; /* LE Credit */
		}
		break;
	}
	case BT_L2CAP_PDU_LE_CONN_RSP:
	{
		const struct bt_l2cap_pdu_le_conn_rsp *pdu = data + 4;

		dcid = le16_to_cpu(pdu->dcid);

		/* The response's dcid is the responder's CID.  Its MTU/MPS
		 * belong to the responder, so set them on the channel for
		 * that direction (out).  Also propagate PSM from the
		 * requester's channel (!out) if available.
		 */
		chan = chan_lookup(conn, dcid, out);
		if (chan) {
			struct l2cap_chan *req_chan;

			chan->mtu = le16_to_cpu(pdu->mtu);
			chan->mps = le16_to_cpu(pdu->mps);
			chan->mode = 0x80; /* LE Credit */

			/* Propagate PSM from the request channel */
			req_chan = queue_find(conn->chan_list,
					chan_match_cid,
					UINT_TO_PTR(dcid |
						(!out ? 0x10000 : 0)));
			if (req_chan && req_chan->psm)
				chan->psm = req_chan->psm;
		}
		break;
	}
	case BT_L2CAP_PDU_ECRED_CONN_REQ:
	{
		const struct bt_l2cap_pdu_ecred_conn_req *pdu = data + 4;
		uint16_t req_len = le16_to_cpu(hdr->len);
		int num_cids;
		int i;

		psm = le16_to_cpu(pdu->psm);
		num_cids = (req_len - sizeof(*pdu)) / sizeof(uint16_t);

		for (i = 0; i < num_cids; i++) {
			scid = le16_to_cpu(pdu->scid[i]);
			chan = chan_lookup(conn, scid, out);
			if (chan) {
				chan->psm = psm;
				chan->mtu = le16_to_cpu(pdu->mtu);
				chan->mps = le16_to_cpu(pdu->mps);
				chan->mode = 0x81; /* Enhanced Credit */
			}
		}
		break;
	}
	}
}

static void new_index(struct timeval *tv, uint16_t index,
					const void *data, uint16_t size)
{
	const struct btsnoop_opcode_new_index *ni = data;
	struct hci_dev *dev;

	dev = dev_alloc(index);

	dev->type = ni->type;
	memcpy(dev->bdaddr, ni->bdaddr, 6);

	queue_push_tail(dev_list, dev);
}

static void del_index(struct timeval *tv, uint16_t index,
					const void *data, uint16_t size)
{
	struct hci_dev *dev;

	dev = queue_remove_if(dev_list, dev_match_index, UINT_TO_PTR(index));
	if (!dev) {
		fprintf(stderr, "Remove for an unexisting device\n");
		return;
	}

	dev_destroy(dev);
}

static void command_pkt(struct timeval *tv, uint16_t index,
					const void *data, uint16_t size)
{
	struct hci_dev *dev;

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->num_hci++;
	dev->num_cmd++;
}

static void evt_conn_complete(struct hci_dev *dev, struct timeval *tv,
					unsigned long frame,
					const void *data, uint16_t size)
{
	const struct bt_hci_evt_conn_complete *evt = data;
	struct hci_conn *conn;

	if (evt->status)
		return;

	conn = conn_lookup_type(dev, le16_to_cpu(evt->handle), BTMON_CONN_ACL);
	if (!conn)
		return;

	memcpy(conn->bdaddr, evt->bdaddr, 6);
	conn->frame_connected = frame;
	conn->setup_seen = true;
}

static void evt_disconnect_complete(struct hci_dev *dev, struct timeval *tv,
					unsigned long frame,
					const void *data, uint16_t size)
{
	const struct bt_hci_evt_disconnect_complete *evt = data;
	struct hci_conn *conn;

	if (evt->status)
		return;

	conn = conn_lookup(dev, le16_to_cpu(evt->handle));
	if (!conn)
		return;

	conn->frame_disconnected = frame;
	conn->disconnect_reason = evt->reason;
	conn->terminated = true;
}

static void rsp_read_bd_addr(struct hci_dev *dev, struct timeval *tv,
					const void *data, uint16_t size)
{
	const struct bt_hci_rsp_read_bd_addr *rsp = data;

	if (rsp->status)
		return;

	memcpy(dev->bdaddr, rsp->bdaddr, 6);
}

static void evt_cmd_complete(struct hci_dev *dev, struct timeval *tv,
					const void *data, uint16_t size)
{
	const struct bt_hci_evt_cmd_complete *evt = data;
	uint16_t opcode;

	data += sizeof(*evt);
	size -= sizeof(*evt);

	opcode = le16_to_cpu(evt->opcode);

	switch (opcode) {
	case BT_HCI_CMD_READ_BD_ADDR:
		rsp_read_bd_addr(dev, tv, data, size);
		break;
	}
}

static bool match_plot_latency(const void *data, const void *user_data)
{
	const struct plot *plot = data;
	const struct timeval *latency = user_data;

	return TIMEVAL_MSEC(latency) == plot->x_msec;
}

static void plot_add(struct queue *queue, struct timeval *latency,
						uint16_t count)
{
	struct plot *plot;

	/* Use LRU ordering */
	plot = queue_remove_if(queue, match_plot_latency, latency);
	if (plot) {
		plot->y_count += count;
		queue_push_head(queue, plot);
		return;
	}

	plot = new0(struct plot, 1);
	plot->x_msec = TIMEVAL_MSEC(latency);
	plot->y_count = count;

	queue_push_tail(queue, plot);
}

static void evt_le_conn_complete(struct hci_dev *dev, struct timeval *tv,
					unsigned long frame,
					struct iovec *iov)
{
	const struct bt_hci_evt_le_conn_complete *evt;
	struct hci_conn *conn;

	evt = util_iov_pull_mem(iov, sizeof(*evt));
	if (!evt || evt->status)
		return;

	conn = conn_lookup_type(dev, le16_to_cpu(evt->handle), BTMON_CONN_LE);
	if (!conn)
		return;

	memcpy(conn->bdaddr, evt->peer_addr, 6);
	conn->bdaddr_type = evt->peer_addr_type;
	conn->frame_connected = frame;
	conn->setup_seen = true;
}

static void evt_le_enh_conn_complete(struct hci_dev *dev, struct timeval *tv,
					unsigned long frame,
					struct iovec *iov)
{
	const struct bt_hci_evt_le_enhanced_conn_complete *evt;
	struct hci_conn *conn;

	evt = util_iov_pull_mem(iov, sizeof(*evt));
	if (!evt || evt->status)
		return;

	conn = conn_lookup_type(dev, le16_to_cpu(evt->handle), BTMON_CONN_LE);
	if (!conn)
		return;

	memcpy(conn->bdaddr, evt->peer_addr, 6);
	conn->bdaddr_type = evt->peer_addr_type;
	conn->frame_connected = frame;
	conn->setup_seen = true;
}

static void evt_num_completed_packets(struct hci_dev *dev, struct timeval *tv,
					const void *data, uint16_t size)
{
	struct iovec iov = { .iov_base = (void *)data, .iov_len = size };
	uint8_t num_handles;
	int i;

	if (!util_iov_pull_u8(&iov, &num_handles))
		return;

	for (i = 0; i < num_handles; i++) {
		uint16_t handle, count;
		struct hci_conn *conn;
		struct timeval res;
		struct hci_conn_tx *last_tx;
		int j;

		if (!util_iov_pull_le16(&iov, &handle))
			return;
		if (!util_iov_pull_le16(&iov, &count))
			return;

		conn = conn_lookup(dev, handle);
		if (!conn)
			continue;

		conn->tx.num_comp += count;

		for (j = 0; j < count; j++) {
			last_tx = queue_pop_head(conn->tx_queue);
			if (last_tx) {
				struct l2cap_chan *chan = last_tx->chan;

				timersub(tv, &last_tx->tv, &res);

				packet_latency_add(&conn->tx.latency, &res);
				plot_add(conn->tx.plot, &res, 1);

				if (chan) {
					chan->tx.num_comp += count;
					packet_latency_add(&chan->tx.latency,
									&res);
					plot_add(chan->tx.plot, &res, 1);
				}

				free(last_tx);
			}
		}
	}
}

static void evt_sync_conn_complete(struct hci_dev *dev, struct timeval *tv,
					unsigned long frame,
					const void *data, uint16_t size)
{
	const struct bt_hci_evt_sync_conn_complete *evt = data;
	struct hci_conn *conn;

	if (evt->status)
		return;

	conn = conn_lookup_type(dev, le16_to_cpu(evt->handle), evt->link_type);
	if (!conn)
		return;

	memcpy(conn->bdaddr, evt->bdaddr, 6);
	conn->frame_connected = frame;
	conn->setup_seen = true;
}

static void evt_le_cis_established(struct hci_dev *dev, struct timeval *tv,
					unsigned long frame,
					struct iovec *iov)
{
	const struct bt_hci_evt_le_cis_established *evt;
	struct hci_conn *conn, *link;

	evt = util_iov_pull_mem(iov, sizeof(*evt));
	if (!evt || evt->status)
		return;

	conn = conn_lookup_type(dev, le16_to_cpu(evt->conn_handle),
						BTMON_CONN_CIS);
	if (!conn)
		return;

	conn->frame_connected = frame;
	conn->setup_seen = true;

	link = link_lookup(dev, conn->handle);
	if (link)
		memcpy(conn->bdaddr, link->bdaddr, 6);
}

static void evt_le_cis_req(struct hci_dev *dev, struct timeval *tv,
					struct iovec *iov)
{
	const struct bt_hci_evt_le_cis_req *evt;
	struct hci_conn *conn;

	evt = util_iov_pull_mem(iov, sizeof(*evt));
	if (!evt)
		return;

	conn = conn_lookup(dev, le16_to_cpu(evt->acl_handle));
	if (!conn)
		return;

	conn->link = le16_to_cpu(evt->cis_handle);
}

static void evt_le_big_complete(struct hci_dev *dev, struct timeval *tv,
					unsigned long frame,
					struct iovec *iov)
{
	const struct bt_hci_evt_le_big_complete *evt;
	int i;

	evt = util_iov_pull_mem(iov, sizeof(*evt));
	if (!evt || evt->status)
		return;

	for (i = 0; i < evt->num_bis; i++) {
		struct hci_conn *conn;
		uint16_t handle;

		if (!util_iov_pull_le16(iov, &handle))
			return;

		conn = conn_lookup_type(dev, handle, BTMON_CONN_BIS);
		if (conn) {
			conn->setup_seen = true;
			conn->frame_connected = frame;
		}
	}
}

static void evt_le_big_sync_established(struct hci_dev *dev, struct timeval *tv,
					unsigned long frame,
					struct iovec *iov)
{
	const struct bt_hci_evt_le_big_sync_estabilished *evt;
	int i;

	evt = util_iov_pull_mem(iov, sizeof(*evt));
	if (!evt || evt->status)
		return;

	for (i = 0; i < evt->num_bis; i++) {
		struct hci_conn *conn;
		uint16_t handle;

		if (!util_iov_pull_le16(iov, &handle))
			return;

		conn = conn_lookup_type(dev, handle, BTMON_CONN_BIS);
		if (conn) {
			conn->setup_seen = true;
			conn->frame_connected = frame;
		}
	}
}

static void evt_le_meta_event(struct hci_dev *dev, struct timeval *tv,
					unsigned long frame,
					const void *data, uint16_t size)
{
	struct iovec iov = {
		.iov_base = (void *)data,
		.iov_len = size,
	};
	uint8_t subevt;

	if (!util_iov_pull_u8(&iov, &subevt))
		return;

	switch (subevt) {
	case BT_HCI_EVT_LE_CONN_COMPLETE:
		evt_le_conn_complete(dev, tv, frame, &iov);
		break;
	case BT_HCI_EVT_LE_ENHANCED_CONN_COMPLETE:
		evt_le_enh_conn_complete(dev, tv, frame, &iov);
		break;
	case BT_HCI_EVT_LE_CIS_ESTABLISHED:
		evt_le_cis_established(dev, tv, frame, &iov);
		break;
	case BT_HCI_EVT_LE_CIS_REQ:
		evt_le_cis_req(dev, tv, &iov);
		break;
	case BT_HCI_EVT_LE_BIG_COMPLETE:
		evt_le_big_complete(dev, tv, frame, &iov);
		break;
	case BT_HCI_EVT_LE_BIG_SYNC_ESTABILISHED:
		evt_le_big_sync_established(dev, tv, frame, &iov);
		break;
	}
}

static void event_pkt(struct timeval *tv, uint16_t index,
					unsigned long frame,
					const void *data, uint16_t size)
{
	const struct bt_hci_evt_hdr *hdr = data;
	struct hci_dev *dev;

	data += sizeof(*hdr);
	size -= sizeof(*hdr);

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->num_hci++;
	dev->num_evt++;

	switch (hdr->evt) {
	case BT_HCI_EVT_CONN_COMPLETE:
		evt_conn_complete(dev, tv, frame, data, size);
		break;
	case BT_HCI_EVT_DISCONNECT_COMPLETE:
		evt_disconnect_complete(dev, tv, frame, data, size);
		break;
	case BT_HCI_EVT_CMD_COMPLETE:
		evt_cmd_complete(dev, tv, data, size);
		break;
	case BT_HCI_EVT_NUM_COMPLETED_PACKETS:
		evt_num_completed_packets(dev, tv, data, size);
		break;
	case BT_HCI_EVT_SYNC_CONN_COMPLETE:
		evt_sync_conn_complete(dev, tv, frame, data, size);
		break;
	case BT_HCI_EVT_LE_META_EVENT:
		evt_le_meta_event(dev, tv, frame, data, size);
		break;
	}
}

static void stats_add(struct hci_stats *stats, struct timeval *tv,
							uint16_t size)
{
	stats->num++;
	stats->bytes += size;

	if (!stats->min || size < stats->min)
		stats->min = size;
	if (!stats->max || size > stats->max)
		stats->max = size;

	/* Wall-clock timestamp tracking */
	if (!timerisset(&stats->first_ts))
		stats->first_ts = *tv;
	stats->last_ts = *tv;

	/* Windowed throughput: 1-second windows */
	if (!timerisset(&stats->window_start)) {
		stats->window_start = *tv;
		stats->window_bytes = size;
	} else {
		struct timeval delta;

		timersub(tv, &stats->window_start, &delta);
		if (TV_MSEC(delta) >= 1000) {
			/* Close current window, compute speed */
			long long speed;

			speed = stats->window_bytes * 8 /
						TV_MSEC(delta);

			if (!stats->speed_min || speed < stats->speed_min)
				stats->speed_min = speed;
			if (speed > stats->speed_max)
				stats->speed_max = speed;

			/* Start new window */
			stats->window_start = *tv;
			stats->window_bytes = size;
		} else {
			stats->window_bytes += size;
		}
	}
}

static void conn_pkt_tx(struct hci_conn *conn, struct timeval *tv,
				uint16_t size, struct l2cap_chan *chan)
{
	struct hci_conn_tx *last_tx;

	last_tx = new0(struct hci_conn_tx, 1);
	memcpy(last_tx, tv, sizeof(*tv));
	last_tx->chan = chan;
	queue_push_tail(conn->tx_queue, last_tx);

	stats_add(&conn->tx, tv, size);

	if (chan)
		stats_add(&chan->tx, tv, size);
}

static void conn_pkt_rx(struct hci_conn *conn, struct timeval *tv,
				uint16_t size, struct l2cap_chan *chan)
{
	struct timeval res;

	if (timerisset(&conn->last_rx)) {
		timersub(tv, &conn->last_rx, &res);
		packet_latency_add(&conn->rx.latency, &res);
		plot_add(conn->rx.plot, &res, 1);
	}

	conn->last_rx = *tv;

	stats_add(&conn->rx, tv, size);
	conn->rx.num_comp++;

	if (chan) {
		if (timerisset(&chan->last_rx)) {
			timersub(tv, &chan->last_rx, &res);
			packet_latency_add(&chan->rx.latency, &res);
			plot_add(chan->rx.plot, &res, 1);
		}

		chan->last_rx = *tv;

		stats_add(&chan->rx, tv, size);
		chan->rx.num_comp++;
	}
}

static void acl_pkt(struct timeval *tv, uint16_t index, bool out,
					const void *data, uint16_t size)
{
	const struct bt_hci_acl_hdr *hdr = data;
	struct hci_dev *dev;
	struct hci_conn *conn;
	struct l2cap_chan *chan = NULL;
	uint16_t cid;

	data += sizeof(*hdr);
	size -= sizeof(*hdr);

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->num_hci++;
	dev->num_acl++;

	conn = conn_lookup_type(dev, le16_to_cpu(hdr->handle) & 0x0fff, 0x00);
	if (!conn)
		return;

	switch (le16_to_cpu(hdr->handle) >> 12) {
	case 0x00:
	case 0x02:
		cid = get_le16(data + 2);
		chan = chan_lookup(conn, cid, out);
		if (cid == 1)
			l2cap_sig(conn, out, data + 4, size - 4);
		else if (cid == 5)
			l2cap_le_sig(conn, out, data + 4, size - 4);
		break;
	}

	if (out) {
		conn_pkt_tx(conn, tv, size, chan);
	} else {
		conn_pkt_rx(conn, tv, size, chan);
	}
}

static void sco_pkt(struct timeval *tv, uint16_t index, bool out,
					const void *data, uint16_t size)
{
	const struct bt_hci_acl_hdr *hdr = data;
	struct hci_dev *dev;
	struct hci_conn *conn;

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->num_hci++;
	dev->num_sco++;

	conn = conn_lookup_type(dev, le16_to_cpu(hdr->handle) & 0x0fff,
							BTMON_CONN_SCO);
	if (!conn) {
		conn = conn_lookup_type(dev, le16_to_cpu(hdr->handle) & 0x0fff,
							BTMON_CONN_ESCO);
		if (!conn)
			return;
	}

	if (out) {
		conn_pkt_tx(conn, tv, size - sizeof(*hdr), NULL);
	} else {
		conn_pkt_rx(conn, tv, size - sizeof(*hdr), NULL);
	}
}

static void info_index(struct timeval *tv, uint16_t index,
					const void *data, uint16_t size)
{
	const struct btsnoop_opcode_index_info *hdr = data;
	struct hci_dev *dev;

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->manufacturer = hdr->manufacturer;
}

static void vendor_diag(struct timeval *tv, uint16_t index,
					const void *data, uint16_t size)
{
	struct hci_dev *dev;

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->vendor_diag++;
}

static void system_note(struct timeval *tv, uint16_t index,
					const void *data, uint16_t size)
{
	struct hci_dev *dev;

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->system_note++;
}

static void user_log(struct timeval *tv, uint16_t index,
					const void *data, uint16_t size)
{
	struct hci_dev *dev;

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->user_log++;
}

static void ctrl_msg(struct timeval *tv, uint16_t index,
					const void *data, uint16_t size)
{
	struct hci_dev *dev;

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->ctrl_msg++;
}

static void iso_pkt(struct timeval *tv, uint16_t index, bool out,
					const void *data, uint16_t size)
{
	const struct bt_hci_iso_hdr *hdr = data;
	struct hci_conn *conn;
	struct hci_dev *dev;

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->num_hci++;
	dev->num_iso++;

	conn = conn_lookup_type(dev, le16_to_cpu(hdr->handle) & 0x0fff,
							BTMON_CONN_CIS);
	if (!conn) {
		conn = conn_lookup_type(dev, le16_to_cpu(hdr->handle) & 0x0fff,
							BTMON_CONN_BIS);
		if (!conn)
			return;
	}

	if (out) {
		conn_pkt_tx(conn, tv, size - sizeof(*hdr), NULL);
	} else {
		conn_pkt_rx(conn, tv, size - sizeof(*hdr), NULL);
	}
}

static void unknown_opcode(struct timeval *tv, uint16_t index,
					const void *data, uint16_t size)
{
	struct hci_dev *dev;

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->unknown++;
}

void analyze_trace(const char *path)
{
	struct btsnoop *btsnoop_file;
	unsigned long num_packets = 0;
	unsigned long num_frames = 0;
	uint32_t format;

	btsnoop_file = btsnoop_open(path, BTSNOOP_FLAG_PKLG_SUPPORT);
	if (!btsnoop_file)
		return;

	format = btsnoop_get_format(btsnoop_file);

	switch (format) {
	case BTSNOOP_FORMAT_HCI:
	case BTSNOOP_FORMAT_UART:
	case BTSNOOP_FORMAT_MONITOR:
		break;
	default:
		fprintf(stderr, "Unsupported packet format\n");
		goto done;
	}

	dev_list = queue_new();

	while (1) {
		unsigned char buf[BTSNOOP_MAX_PACKET_SIZE];
		struct timeval tv;
		uint16_t index, opcode, pktlen;

		if (!btsnoop_read_hci(btsnoop_file, &tv, &index, &opcode,
								buf, &pktlen))
			break;

		switch (opcode) {
		case BTSNOOP_OPCODE_NEW_INDEX:
			new_index(&tv, index, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_DEL_INDEX:
			del_index(&tv, index, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_COMMAND_PKT:
			num_frames++;
			command_pkt(&tv, index, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_EVENT_PKT:
			num_frames++;
			event_pkt(&tv, index, num_frames, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_ACL_TX_PKT:
			num_frames++;
			acl_pkt(&tv, index, true, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_ACL_RX_PKT:
			num_frames++;
			acl_pkt(&tv, index, false, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_SCO_TX_PKT:
			num_frames++;
			sco_pkt(&tv, index, true, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_SCO_RX_PKT:
			num_frames++;
			sco_pkt(&tv, index, false, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_OPEN_INDEX:
		case BTSNOOP_OPCODE_CLOSE_INDEX:
			break;
		case BTSNOOP_OPCODE_INDEX_INFO:
			info_index(&tv, index, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_VENDOR_DIAG:
			vendor_diag(&tv, index, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_SYSTEM_NOTE:
			system_note(&tv, index, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_USER_LOGGING:
			user_log(&tv, index, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_CTRL_OPEN:
		case BTSNOOP_OPCODE_CTRL_CLOSE:
		case BTSNOOP_OPCODE_CTRL_COMMAND:
		case BTSNOOP_OPCODE_CTRL_EVENT:
			ctrl_msg(&tv, index, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_ISO_TX_PKT:
			num_frames++;
			iso_pkt(&tv, index, true, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_ISO_RX_PKT:
			num_frames++;
			iso_pkt(&tv, index, false, buf, pktlen);
			break;
		default:
			unknown_opcode(&tv, index, buf, pktlen);
			break;
		}

		num_packets++;
	}

	printf("Trace contains %lu packets\n\n", num_packets);

	queue_destroy(dev_list, dev_destroy);

done:
	btsnoop_unref(btsnoop_file);
}
