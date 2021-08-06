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

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "lib/bluetooth.h"

#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/btsnoop.h"
#include "monitor/bt.h"
#include "analyze.h"

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

#define CONN_BR_ACL	0x01
#define CONN_BR_SCO	0x02
#define CONN_BR_ESCO	0x03
#define CONN_LE_ACL	0x04
#define CONN_LE_ISO	0x05

struct hci_conn {
	uint16_t handle;
	uint8_t type;
	uint8_t bdaddr[6];
	bool setup_seen;
	bool terminated;
	unsigned long rx_num;
	unsigned long tx_num;
	unsigned long tx_num_comp;
	struct timeval last_tx;
	struct timeval last_tx_comp;
	struct timeval tx_lat_min;
	struct timeval tx_lat_max;
	struct timeval tx_lat_med;
	uint16_t tx_pkt_min;
	uint16_t tx_pkt_max;
	uint16_t tx_pkt_med;
};

static struct queue *dev_list;

static void conn_destroy(void *data)
{
	struct hci_conn *conn = data;
	const char *str;

	switch (conn->type) {
	case CONN_BR_ACL:
		str = "BR-ACL";
		break;
	case CONN_BR_SCO:
		str = "BR-SCO";
		break;
	case CONN_BR_ESCO:
		str = "BR-ESCO";
		break;
	case CONN_LE_ACL:
		str = "LE-ACL";
		break;
	case CONN_LE_ISO:
		str = "LE-ISO";
		break;
	default:
		str = "unknown";
		break;
	}

	printf("  Found %s connection with handle %u\n", str, conn->handle);
	printf("    BD_ADDR %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",
			conn->bdaddr[5], conn->bdaddr[4], conn->bdaddr[3],
			conn->bdaddr[2], conn->bdaddr[1], conn->bdaddr[0]);
	if (!conn->setup_seen)
		printf("    Connection setup missing\n");
	printf("    %lu RX packets\n", conn->rx_num);
	printf("    %lu TX packets\n", conn->tx_num);
	printf("    %lu TX completed packets\n", conn->tx_num_comp);
	printf("    %ld.%06ld seconds min latency\n",
			conn->tx_lat_min.tv_sec, conn->tx_lat_min.tv_usec);
	printf("    %ld.%06ld seconds max latency\n",
			conn->tx_lat_max.tv_sec, conn->tx_lat_max.tv_usec);
	printf("    %ld.%06ld seconds median latency\n",
			conn->tx_lat_med.tv_sec, conn->tx_lat_med.tv_usec);
	printf("    %u octets TX min packet size\n", conn->tx_pkt_min);
	printf("    %u octets TX max packet size\n", conn->tx_pkt_max);
	printf("    %u octets TX median packet size\n", conn->tx_pkt_med);

	free(conn);
}

static struct hci_conn *conn_alloc(struct hci_dev *dev, uint16_t handle,
								uint8_t type)
{
	struct hci_conn *conn;

	conn = new0(struct hci_conn, 1);

	conn->handle = handle;
	conn->type = type;

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

static struct hci_conn *conn_lookup_type(struct hci_dev *dev, uint16_t handle,
								uint8_t type)
{
	struct hci_conn *conn;

	conn = queue_find(dev->conn_list, conn_match_handle,
						UINT_TO_PTR(handle));
	if (!conn || conn->type != type) {
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
	const struct bt_hci_cmd_hdr *hdr = data;
	struct hci_dev *dev;

	data += sizeof(*hdr);
	size -= sizeof(*hdr);

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->num_hci++;
	dev->num_cmd++;
}

static void evt_conn_complete(struct hci_dev *dev, struct timeval *tv,
					const void *data, uint16_t size)
{
	const struct bt_hci_evt_conn_complete *evt = data;
	struct hci_conn *conn;

	data += sizeof(*evt);
	size -= sizeof(*evt);

	if (evt->status)
		return;

	conn = conn_lookup_type(dev, le16_to_cpu(evt->handle), CONN_BR_ACL);
	if (!conn)
		return;

	memcpy(conn->bdaddr, evt->bdaddr, 6);
	conn->setup_seen = true;
}

static void evt_disconnect_complete(struct hci_dev *dev, struct timeval *tv,
					const void *data, uint16_t size)
{
	const struct bt_hci_evt_disconnect_complete *evt = data;
	struct hci_conn *conn;

	data += sizeof(*evt);
	size -= sizeof(*evt);

	if (evt->status)
		return;

	conn = conn_lookup(dev, le16_to_cpu(evt->handle));
	if (!conn)
		return;

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

static void evt_num_completed_packets(struct hci_dev *dev, struct timeval *tv,
					const void *data, uint16_t size)
{
	uint8_t num_handles = get_u8(data);
	int i;

	data += sizeof(num_handles);
	size -= sizeof(num_handles);

	for (i = 0; i < num_handles; i++) {
		uint16_t handle = get_le16(data);
		uint16_t count = get_le16(data + 2);
		struct hci_conn *conn;
		struct timeval res;

		data += 4;
		size -= 4;

		conn = conn_lookup(dev, handle);
		if (!conn)
			continue;

		conn->tx_num_comp += count;
		conn->last_tx_comp = *tv;

		if (timerisset(&conn->last_tx)) {
			timersub(&conn->last_tx_comp, &conn->last_tx, &res);

			if (!timerisset(&conn->tx_lat_min) ||
					timercmp(&res, &conn->tx_lat_min, <))
				conn->tx_lat_min = res;

			if (!timerisset(&conn->tx_lat_max) ||
					timercmp(&res, &conn->tx_lat_max, >))
				conn->tx_lat_max = res;

			if (timerisset(&conn->tx_lat_med)) {
				struct timeval tmp;

				timeradd(&conn->tx_lat_med, &res, &tmp);

				tmp.tv_sec /= 2;
				tmp.tv_usec /= 2;
				if (tmp.tv_sec % 2) {
					tmp.tv_usec += 500000;
					if (tmp.tv_usec >= 1000000) {
						tmp.tv_sec++;
						tmp.tv_usec -= 1000000;
					}
				}
			} else
				conn->tx_lat_med = res;

			timerclear(&conn->last_tx);
		}
	}
}

static void evt_le_meta_event(struct hci_dev *dev, struct timeval *tv,
					const void *data, uint16_t size)
{
	uint8_t subtype = get_u8(data);

	data += sizeof(subtype);
	size -= sizeof(subtype);

	switch (subtype) {
	}
}

static void event_pkt(struct timeval *tv, uint16_t index,
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
		evt_conn_complete(dev, tv, data, size);
		break;
	case BT_HCI_EVT_DISCONNECT_COMPLETE:
		evt_disconnect_complete(dev, tv, data, size);
		break;
	case BT_HCI_EVT_CMD_COMPLETE:
		evt_cmd_complete(dev, tv, data, size);
		break;
	case BT_HCI_EVT_NUM_COMPLETED_PACKETS:
		evt_num_completed_packets(dev, tv, data, size);
		break;
	case BT_HCI_EVT_LE_META_EVENT:
		evt_le_meta_event(dev, tv, data, size);
		break;
	}
}

static void acl_pkt(struct timeval *tv, uint16_t index, bool out,
					const void *data, uint16_t size)
{
	const struct bt_hci_acl_hdr *hdr = data;
	struct hci_dev *dev;
	struct hci_conn *conn;

	data += sizeof(*hdr);
	size -= sizeof(*hdr);

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->num_hci++;
	dev->num_acl++;

	conn = conn_lookup_type(dev, le16_to_cpu(hdr->handle) & 0x0fff,
								CONN_BR_ACL);
	if (!conn)
		return;

	if (out) {
		conn->tx_num++;
		conn->last_tx = *tv;

		if (!conn->tx_pkt_min || size < conn->tx_pkt_min)
			conn->tx_pkt_min = size;
		if (!conn->tx_pkt_max || size > conn->tx_pkt_max)
			conn->tx_pkt_max = size;
		if (conn->tx_pkt_med) {
			conn->tx_pkt_med += (size + 1);
			conn->tx_pkt_med /= 2;
		} else
			conn->tx_pkt_med = size;
	} else {
		conn->rx_num++;
	}
}

static void sco_pkt(struct timeval *tv, uint16_t index,
					const void *data, uint16_t size)
{
	const struct bt_hci_sco_hdr *hdr = data;
	struct hci_dev *dev;

	data += sizeof(*hdr);
	size -= sizeof(*hdr);

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->num_hci++;
	dev->num_sco++;
}

static void info_index(struct timeval *tv, uint16_t index,
					const void *data, uint16_t size)
{
	const struct btsnoop_opcode_index_info *hdr = data;
	struct hci_dev *dev;

	data += sizeof(*hdr);
	size -= sizeof(*hdr);

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

static void iso_pkt(struct timeval *tv, uint16_t index,
					const void *data, uint16_t size)
{
	const struct bt_hci_iso_hdr *hdr = data;
	struct hci_dev *dev;

	data += sizeof(*hdr);
	size -= sizeof(*hdr);

	dev = dev_lookup(index);
	if (!dev)
		return;

	dev->num_hci++;
	dev->num_iso++;
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
			command_pkt(&tv, index, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_EVENT_PKT:
			event_pkt(&tv, index, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_ACL_TX_PKT:
			acl_pkt(&tv, index, true, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_ACL_RX_PKT:
			acl_pkt(&tv, index, false, buf, pktlen);
			break;
		case BTSNOOP_OPCODE_SCO_TX_PKT:
		case BTSNOOP_OPCODE_SCO_RX_PKT:
			sco_pkt(&tv, index, buf, pktlen);
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
		case BTSNOOP_OPCODE_ISO_RX_PKT:
			iso_pkt(&tv, index, buf, pktlen);
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
