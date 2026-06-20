// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <errno.h>
#include <endian.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "src/shared/btsnoop.h"

struct btsnoop_hdr {
	uint8_t		id[8];		/* Identification Pattern */
	uint32_t	version;	/* Version Number = 1 */
	uint32_t	type;		/* Datalink Type */
} __attribute__ ((packed));
#define BTSNOOP_HDR_SIZE (sizeof(struct btsnoop_hdr))

struct btsnoop_pkt {
	uint32_t	size;		/* Original Length */
	uint32_t	len;		/* Included Length */
	uint32_t	flags;		/* Packet Flags */
	uint32_t	drops;		/* Cumulative Drops */
	uint64_t	ts;		/* Timestamp microseconds */
	uint8_t		data[0];	/* Packet Data */
} __attribute__ ((packed));
#define BTSNOOP_PKT_SIZE (sizeof(struct btsnoop_pkt))

static const uint8_t btsnoop_id[] = { 0x62, 0x74, 0x73, 0x6e,
				      0x6f, 0x6f, 0x70, 0x00 };

static const uint32_t btsnoop_version = 1;

#define BTSNOOP_EPOCH_OFFSET 0x00E03AB44A676000ull
#define BTSNOOP_UNIX_TIME_OFFSET 946684800ll

struct pklg_pkt {
	uint32_t	len;
	uint64_t	ts;
	uint8_t		type;
} __attribute__ ((packed));
#define PKLG_PKT_SIZE (sizeof(struct pklg_pkt))
#define PKLG_PAYLOAD_OFFSET (PKLG_PKT_SIZE - sizeof(uint32_t))

struct btsnoop {
	int ref_count;
	int fd;
	unsigned long flags;
	uint32_t format;
	uint16_t index;
	bool aborted;
	bool pklg_format;
	bool pklg_v2;
	const char *path;
	size_t max_size;
	size_t cur_size;
	unsigned int max_count;
	unsigned int cur_count;
};

struct btsnoop *btsnoop_open(const char *path, unsigned long flags)
{
	struct btsnoop *btsnoop;
	struct btsnoop_hdr hdr;
	ssize_t len;

	btsnoop = calloc(1, sizeof(*btsnoop));
	if (!btsnoop)
		return NULL;

	btsnoop->fd = open(path, O_RDONLY | O_CLOEXEC);
	if (btsnoop->fd < 0) {
		free(btsnoop);
		return NULL;
	}

	btsnoop->flags = flags;

	len = read(btsnoop->fd, &hdr, BTSNOOP_HDR_SIZE);
	if (len < 0 || len != BTSNOOP_HDR_SIZE)
		goto failed;

	if (!memcmp(hdr.id, btsnoop_id, sizeof(btsnoop_id))) {
		/* Check for BTSnoop version 1 format */
		if (be32toh(hdr.version) != btsnoop_version)
			goto failed;

		btsnoop->format = be32toh(hdr.type);
		btsnoop->index = 0xffff;
	} else {
		if (!(btsnoop->flags & BTSNOOP_FLAG_PKLG_SUPPORT))
			goto failed;

		if (hdr.id[0] == 0x00 &&
				(hdr.id[1] == 0x00 || hdr.id[1] == 0x01)) {
			/* Apple Packet Logger format (big-endian) */
			btsnoop->format = BTSNOOP_FORMAT_MONITOR;
			btsnoop->index = 0xffff;
			btsnoop->pklg_format = true;
			btsnoop->pklg_v2 = false;
		} else if (hdr.id[3] == 0x00 &&
				(hdr.id[2] == 0x00 || hdr.id[2] == 0x01)) {
			/* Apple Packet Logger format (little-endian) */
			btsnoop->format = BTSNOOP_FORMAT_MONITOR;
			btsnoop->index = 0xffff;
			btsnoop->pklg_format = true;
			btsnoop->pklg_v2 = true;
		} else {
			goto failed;
		}

		/* Apple Packet Logger format has no header */
		lseek(btsnoop->fd, 0, SEEK_SET);
	}

	return btsnoop_ref(btsnoop);

failed:
	close(btsnoop->fd);
	free(btsnoop);

	return NULL;
}

struct btsnoop *btsnoop_create(const char *path, size_t max_size,
					unsigned int max_count, uint32_t format)
{
	struct btsnoop *btsnoop;
	struct btsnoop_hdr hdr;
	const char *real_path;
	char tmp[PATH_MAX];
	ssize_t written;

	if (!max_size && max_count)
		return NULL;

	btsnoop = calloc(1, sizeof(*btsnoop));
	if (!btsnoop)
		return NULL;

	/* If max file size is specified, always add counter to file path */
	if (max_size) {
		snprintf(tmp, PATH_MAX, "%s.0", path);
		real_path = tmp;
	} else {
		real_path = path;
	}

	btsnoop->fd = open(real_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
									0644);
	if (btsnoop->fd < 0) {
		free(btsnoop);
		return NULL;
	}

	btsnoop->format = format;
	btsnoop->index = 0xffff;
	btsnoop->path = path;
	btsnoop->max_count = max_count;
	btsnoop->max_size = max_size;

	memcpy(hdr.id, btsnoop_id, sizeof(btsnoop_id));
	hdr.version = htobe32(btsnoop_version);
	hdr.type = htobe32(btsnoop->format);

	written = write(btsnoop->fd, &hdr, BTSNOOP_HDR_SIZE);
	if (written < 0) {
		close(btsnoop->fd);
		free(btsnoop);
		return NULL;
	}

	btsnoop->cur_size = BTSNOOP_HDR_SIZE;

	return btsnoop_ref(btsnoop);
}

struct btsnoop *btsnoop_ref(struct btsnoop *btsnoop)
{
	if (!btsnoop)
		return NULL;

	__sync_fetch_and_add(&btsnoop->ref_count, 1);

	return btsnoop;
}

void btsnoop_unref(struct btsnoop *btsnoop)
{
	if (!btsnoop)
		return;

	if (__sync_sub_and_fetch(&btsnoop->ref_count, 1))
		return;

	if (btsnoop->fd >= 0)
		close(btsnoop->fd);

	free(btsnoop);
}

uint32_t btsnoop_get_format(struct btsnoop *btsnoop)
{
	if (!btsnoop)
		return BTSNOOP_FORMAT_INVALID;

	return btsnoop->format;
}

static bool btsnoop_rotate(struct btsnoop *btsnoop)
{
	struct btsnoop_hdr hdr;
	char path[PATH_MAX];
	ssize_t written;

	close(btsnoop->fd);

	/* Check if max number of log files has been reached */
	if (btsnoop->max_count && btsnoop->cur_count >= btsnoop->max_count) {
		snprintf(path, PATH_MAX, "%s.%u", btsnoop->path,
				btsnoop->cur_count - btsnoop->max_count);
		unlink(path);
	}

	snprintf(path, PATH_MAX,"%s.%u", btsnoop->path, btsnoop->cur_count);
	btsnoop->cur_count++;

	btsnoop->fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
									0644);
	if (btsnoop->fd < 0)
		return false;

	memcpy(hdr.id, btsnoop_id, sizeof(btsnoop_id));
	hdr.version = htobe32(btsnoop_version);
	hdr.type = htobe32(btsnoop->format);

	written = write(btsnoop->fd, &hdr, BTSNOOP_HDR_SIZE);
	if (written < 0)
		return false;

	btsnoop->cur_size = BTSNOOP_HDR_SIZE;

	return true;
}

bool btsnoop_write(struct btsnoop *btsnoop, struct timeval *tv,
			uint32_t flags, uint32_t drops, const void *data,
			uint16_t size)
{
	struct btsnoop_pkt pkt;
	uint64_t ts;
	ssize_t written;

	if (!btsnoop || !tv)
		return false;

	if (btsnoop->max_size && btsnoop->max_size <=
			btsnoop->cur_size + size + BTSNOOP_PKT_SIZE)
		if (!btsnoop_rotate(btsnoop))
			return false;

	ts = (tv->tv_sec - BTSNOOP_UNIX_TIME_OFFSET) * 1000000ll +
								tv->tv_usec;

	pkt.size  = htobe32(size);
	pkt.len   = htobe32(size);
	pkt.flags = htobe32(flags);
	pkt.drops = htobe32(drops);
	pkt.ts    = htobe64(ts + BTSNOOP_EPOCH_OFFSET);

	written = write(btsnoop->fd, &pkt, BTSNOOP_PKT_SIZE);
	if (written < 0)
		return false;

	btsnoop->cur_size += BTSNOOP_PKT_SIZE;

	if (data && size > 0) {
		written = write(btsnoop->fd, data, size);
		if (written < 0)
			return false;
	}

	btsnoop->cur_size += size;

	return true;
}

static uint32_t get_flags_from_opcode(uint16_t opcode)
{
	switch (opcode) {
	case BTSNOOP_OPCODE_NEW_INDEX:
	case BTSNOOP_OPCODE_DEL_INDEX:
		break;
	case BTSNOOP_OPCODE_COMMAND_PKT:
		return 0x02;
	case BTSNOOP_OPCODE_EVENT_PKT:
		return 0x03;
	case BTSNOOP_OPCODE_ACL_TX_PKT:
		return 0x00;
	case BTSNOOP_OPCODE_ACL_RX_PKT:
		return 0x01;
	case BTSNOOP_OPCODE_SCO_TX_PKT:
	case BTSNOOP_OPCODE_SCO_RX_PKT:
		break;
	case BTSNOOP_OPCODE_ISO_TX_PKT:
	case BTSNOOP_OPCODE_ISO_RX_PKT:
		break;
	case BTSNOOP_OPCODE_OPEN_INDEX:
	case BTSNOOP_OPCODE_CLOSE_INDEX:
		break;
	}

	return 0xff;
}

static ssize_t read_exact(int fd, void *data, size_t size)
{
	uint8_t *ptr = data;
	size_t offset = 0;

	while (offset < size) {
		ssize_t len;

		len = read(fd, ptr + offset, size - offset);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		if (len == 0)
			break;

		offset += len;
	}

	return offset;
}

static bool read_packet_data(struct btsnoop *btsnoop, void *data,
				uint16_t data_size, uint32_t toread,
				uint16_t *size)
{
	ssize_t len;

	if (!size || (!data && toread)) {
		btsnoop->aborted = true;
		return false;
	}

	if (toread > data_size) {
		btsnoop->aborted = true;
		return false;
	}

	len = read_exact(btsnoop->fd, data, toread);
	if (len != (ssize_t) toread) {
		btsnoop->aborted = true;
		return false;
	}

	*size = toread;

	return true;
}

static bool decode_btsnoop_timestamp(uint64_t raw_ts, struct timeval *tv)
{
	uint64_t ts;

	if (raw_ts < BTSNOOP_EPOCH_OFFSET)
		return false;

	ts = raw_ts - BTSNOOP_EPOCH_OFFSET;
	tv->tv_sec = (ts / 1000000ll) + BTSNOOP_UNIX_TIME_OFFSET;
	tv->tv_usec = ts % 1000000ll;

	return true;
}

static void get_pklg_opcode(uint8_t type, uint16_t *index, uint16_t *opcode)
{
	switch (type) {
	case 0x00:
		*index = 0x0000;
		*opcode = BTSNOOP_OPCODE_COMMAND_PKT;
		break;
	case 0x01:
		*index = 0x0000;
		*opcode = BTSNOOP_OPCODE_EVENT_PKT;
		break;
	case 0x02:
		*index = 0x0000;
		*opcode = BTSNOOP_OPCODE_ACL_TX_PKT;
		break;
	case 0x03:
		*index = 0x0000;
		*opcode = BTSNOOP_OPCODE_ACL_RX_PKT;
		break;
	case 0x08:
		*index = 0x0000;
		*opcode = BTSNOOP_OPCODE_SCO_TX_PKT;
		break;
	case 0x09:
		*index = 0x0000;
		*opcode = BTSNOOP_OPCODE_SCO_RX_PKT;
		break;
	case 0x12:
		*index = 0x0000;
		*opcode = BTSNOOP_OPCODE_ISO_TX_PKT;
		break;
	case 0x13:
		*index = 0x0000;
		*opcode = BTSNOOP_OPCODE_ISO_RX_PKT;
		break;
	case 0x0b:
		*index = 0x0000;
		*opcode = BTSNOOP_OPCODE_VENDOR_DIAG;
		break;
	case 0xfc:
		*index = 0xffff;
		*opcode = BTSNOOP_OPCODE_SYSTEM_NOTE;
		break;
	default:
		*index = 0xffff;
		*opcode = 0xffff;
		break;
	}
}

bool btsnoop_write_hci(struct btsnoop *btsnoop, struct timeval *tv,
			uint16_t index, uint16_t opcode, uint32_t drops,
			const void *data, uint16_t size)
{
	uint32_t flags;

	if (!btsnoop)
		return false;

	switch (btsnoop->format) {
	case BTSNOOP_FORMAT_HCI:
		if (btsnoop->index == 0xffff)
			btsnoop->index = index;

		if (index != btsnoop->index)
			return false;

		flags = get_flags_from_opcode(opcode);
		if (flags == 0xff)
			return false;
		break;

	case BTSNOOP_FORMAT_MONITOR:
		flags = ((uint32_t)index << 16) | opcode;
		break;

	default:
		return false;
	}

	return btsnoop_write(btsnoop, tv, flags, drops, data, size);
}

bool btsnoop_write_phy(struct btsnoop *btsnoop, struct timeval *tv,
			uint16_t frequency, const void *data, uint16_t size)
{
	uint32_t flags;

	if (!btsnoop)
		return false;

	switch (btsnoop->format) {
	case BTSNOOP_FORMAT_SIMULATOR:
		flags = (1 << 16) | frequency;
		break;

	default:
		return false;
	}

	return btsnoop_write(btsnoop, tv, flags, 0, data, size);
}

static bool pklg_read_hci(struct btsnoop *btsnoop,
			struct timeval *tv, uint16_t *index, uint16_t *opcode,
			void *data, uint16_t data_size, uint16_t *size)
{
	struct pklg_pkt pkt;
	uint32_t pkt_len;
	uint32_t toread;
	uint64_t ts;
	ssize_t len;

	len = read_exact(btsnoop->fd, &pkt, PKLG_PKT_SIZE);
	if (len == 0)
		return false;

	if (len != PKLG_PKT_SIZE) {
		btsnoop->aborted = true;
		return false;
	}

	if (btsnoop->pklg_v2) {
		pkt_len = le32toh(pkt.len);

		ts = le64toh(pkt.ts);
		tv->tv_sec = ts & 0xffffffff;
		tv->tv_usec = ts >> 32;
	} else {
		pkt_len = be32toh(pkt.len);

		ts = be64toh(pkt.ts);
		tv->tv_sec = ts >> 32;
		tv->tv_usec = ts & 0xffffffff;
	}

	if (pkt_len < PKLG_PAYLOAD_OFFSET) {
		btsnoop->aborted = true;
		return false;
	}

	toread = pkt_len - PKLG_PAYLOAD_OFFSET;
	if (toread > BTSNOOP_MAX_PACKET_SIZE) {
		btsnoop->aborted = true;
		return false;
	}

	get_pklg_opcode(pkt.type, index, opcode);

	return read_packet_data(btsnoop, data, data_size, toread, size);
}

static uint16_t get_opcode_from_flags(uint8_t type, uint32_t flags)
{
	switch (type) {
	case 0x01:
		return BTSNOOP_OPCODE_COMMAND_PKT;
	case 0x02:
		if (flags & 0x01)
			return BTSNOOP_OPCODE_ACL_RX_PKT;
		else
			return BTSNOOP_OPCODE_ACL_TX_PKT;
	case 0x03:
		if (flags & 0x01)
			return BTSNOOP_OPCODE_SCO_RX_PKT;
		else
			return BTSNOOP_OPCODE_SCO_TX_PKT;
	case 0x04:
		return BTSNOOP_OPCODE_EVENT_PKT;
	case 0x05:
		if (flags & 0x01)
			return BTSNOOP_OPCODE_ISO_RX_PKT;
		else
			return BTSNOOP_OPCODE_ISO_TX_PKT;
	case 0xff:
		if (flags & 0x02) {
			if (flags & 0x01)
				return BTSNOOP_OPCODE_EVENT_PKT;
			else
				return BTSNOOP_OPCODE_COMMAND_PKT;
		} else {
			if (flags & 0x01)
				return BTSNOOP_OPCODE_ACL_RX_PKT;
			else
				return BTSNOOP_OPCODE_ACL_TX_PKT;
		}
		break;
	}

	return 0xffff;
}

static bool read_uart_type(struct btsnoop *btsnoop, uint32_t *toread,
								uint8_t *type)
{
	ssize_t len;

	if (!*toread) {
		btsnoop->aborted = true;
		return false;
	}

	len = read_exact(btsnoop->fd, type, 1);
	if (len != 1) {
		btsnoop->aborted = true;
		return false;
	}

	(*toread)--;

	return true;
}

static bool decode_btsnoop_record(struct btsnoop *btsnoop, uint32_t flags,
					uint32_t *toread, uint16_t *index,
					uint16_t *opcode)
{
	uint8_t pkt_type;

	switch (btsnoop->format) {
	case BTSNOOP_FORMAT_HCI:
		*index = 0;
		*opcode = get_opcode_from_flags(0xff, flags);
		return true;
	case BTSNOOP_FORMAT_UART:
		if (!read_uart_type(btsnoop, toread, &pkt_type))
			return false;

		*index = 0;
		*opcode = get_opcode_from_flags(pkt_type, flags);
		return true;
	case BTSNOOP_FORMAT_MONITOR:
		*index = flags >> 16;
		*opcode = flags & 0xffff;
		return true;
	default:
		btsnoop->aborted = true;
		return false;
	}
}

bool btsnoop_read_hci(struct btsnoop *btsnoop,
			struct timeval *tv, uint16_t *index, uint16_t *opcode,
			void *data, uint16_t data_size, uint16_t *size)
{
	struct btsnoop_pkt pkt;
	uint32_t toread, flags;
	ssize_t len;

	if (!btsnoop || !tv || !index || !opcode || !size || btsnoop->aborted)
		return false;

	if (btsnoop->pklg_format)
		return pklg_read_hci(btsnoop, tv, index, opcode,
							data, data_size, size);

	len = read_exact(btsnoop->fd, &pkt, BTSNOOP_PKT_SIZE);
	if (len == 0)
		return false;

	if (len != BTSNOOP_PKT_SIZE) {
		btsnoop->aborted = true;
		return false;
	}

	toread = be32toh(pkt.len);
	if (toread > BTSNOOP_MAX_PACKET_SIZE) {
		btsnoop->aborted = true;
		return false;
	}

	flags = be32toh(pkt.flags);

	if (!decode_btsnoop_timestamp(be64toh(pkt.ts), tv)) {
		btsnoop->aborted = true;
		return false;
	}

	if (!decode_btsnoop_record(btsnoop, flags, &toread, index, opcode))
		return false;

	return read_packet_data(btsnoop, data, data_size, toread, size);
}

bool btsnoop_read_phy(struct btsnoop *btsnoop, struct timeval *tv,
				uint16_t *frequency, void *data, uint16_t *size)
{
	(void) btsnoop;
	(void) tv;
	(void) frequency;
	(void) data;
	(void) size;

	return false;
}
