/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "btsnoop.h"

static inline uint64_t ntoh64(uint64_t n)
{
	uint64_t h;
	uint64_t tmp = ntohl(n & 0x00000000ffffffff);

	h = ntohl(n >> 32);
	h |= tmp << 32;

	return h;
}

#define hton64(x) ntoh64(x)

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

struct btsnoop {
	int ref_count;
	int fd;
	uint32_t type;
};

struct btsnoop *btsnoop_open(const char *path)
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

	len = read(btsnoop->fd, &hdr, BTSNOOP_HDR_SIZE);
	if (len < 0 || len != BTSNOOP_HDR_SIZE)
		goto failed;

	if (memcmp(hdr.id, btsnoop_id, sizeof(btsnoop_id)))
		goto failed;

	if (ntohl(hdr.version) != btsnoop_version)
		goto failed;

	btsnoop->type = ntohl(hdr.type);

	return btsnoop_ref(btsnoop);

failed:
	close(btsnoop->fd);
	free(btsnoop);

	return NULL;
}

struct btsnoop *btsnoop_create(const char *path, uint32_t type)
{
	struct btsnoop *btsnoop;
	struct btsnoop_hdr hdr;
	ssize_t written;

	btsnoop = calloc(1, sizeof(*btsnoop));
	if (!btsnoop)
		return NULL;

	btsnoop->fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (btsnoop->fd < 0) {
		free(btsnoop);
		return NULL;
	}

	btsnoop->type = type;

	memcpy(hdr.id, btsnoop_id, sizeof(btsnoop_id));
	hdr.version = htonl(btsnoop_version);
	hdr.type = htonl(btsnoop->type);

	written = write(btsnoop->fd, &hdr, BTSNOOP_HDR_SIZE);
	if (written < 0) {
		close(btsnoop->fd);
		free(btsnoop);
		return NULL;
	}

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

uint32_t btsnoop_get_type(struct btsnoop *btsnoop)
{
	if (!btsnoop)
		return BTSNOOP_TYPE_INVALID;

	return btsnoop->type;
}

bool btsnoop_write(struct btsnoop *btsnoop, struct timeval *tv,
			uint32_t flags, const void *data, uint16_t size)
{
	struct btsnoop_pkt pkt;
	uint64_t ts;
	ssize_t written;

	if (!btsnoop || !tv)
		return false;

	ts = (tv->tv_sec - 946684800ll) * 1000000ll + tv->tv_usec;

	pkt.size  = htonl(size);
	pkt.len   = htonl(size);
	pkt.flags = htonl(flags);
	pkt.drops = htonl(0);
	pkt.ts    = hton64(ts + 0x00E03AB44A676000ll);

	written = write(btsnoop->fd, &pkt, BTSNOOP_PKT_SIZE);
	if (written < 0)
		return false;

	if (data && size > 0) {
		written = write(btsnoop->fd, data, size);
		if (written < 0)
			return false;
	}

	return true;
}

bool btsnoop_write_phy(struct btsnoop *btsnoop, struct timeval *tv,
			uint16_t frequency, const void *data, uint16_t size)
{
	uint32_t flags;

	if (!btsnoop)
		return false;

	switch (btsnoop->type) {
	case BTSNOOP_TYPE_SIMULATOR:
		flags = (1 << 16) | frequency;
		break;

	default:
		return false;
	}

	return btsnoop_write(btsnoop, tv, flags, data, size);
}
