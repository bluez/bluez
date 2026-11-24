// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Intel Corporation
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "src/shared/mainloop.h"
#include "src/shared/util.h"

#include "vhost.h"

/* vhost-user messages, see docs/interop/vhost-user.rst in QEMU */
#define VHOST_USER_GET_FEATURES			1
#define VHOST_USER_SET_FEATURES			2
#define VHOST_USER_SET_OWNER			3
#define VHOST_USER_RESET_OWNER			4
#define VHOST_USER_SET_MEM_TABLE		5
#define VHOST_USER_SET_VRING_NUM		8
#define VHOST_USER_SET_VRING_ADDR		9
#define VHOST_USER_SET_VRING_BASE		10
#define VHOST_USER_GET_VRING_BASE		11
#define VHOST_USER_SET_VRING_KICK		12
#define VHOST_USER_SET_VRING_CALL		13
#define VHOST_USER_SET_VRING_ERR		14
#define VHOST_USER_GET_PROTOCOL_FEATURES	15
#define VHOST_USER_SET_PROTOCOL_FEATURES	16
#define VHOST_USER_SET_VRING_ENABLE		18
#define VHOST_USER_SET_SLAVE_REQ_FD		21
#define VHOST_USER_GET_CONFIG			24
#define VHOST_USER_SET_CONFIG			25
#define VHOST_USER_VRING_KICK			35

/* Back-end to front-end requests */
#define VHOST_USER_SLAVE_VRING_CALL		4

#define VHOST_USER_VERSION		0x1
#define VHOST_USER_FLAG_REPLY		(1 << 2)
#define VHOST_USER_FLAG_NEED_REPLY	(1 << 3)

#define VHOST_USER_VRING_INDEX_MASK	0xff
#define VHOST_USER_VRING_NOFD_MASK	(1 << 8)

#define VHOST_USER_F_PROTOCOL_FEATURES	30
#define VHOST_USER_PROTOCOL_F_SLAVE_REQ		5
#define VHOST_USER_PROTOCOL_F_CONFIG		9
#define VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS	14

/* How long to wait for the front-end to acknowledge a notification */
#define VHOST_USER_REPLY_TIMEOUT	5000

#define VIRTIO_F_VERSION_1		32

#define VRING_DESC_F_NEXT		1
#define VRING_DESC_F_WRITE		2
#define VRING_DESC_F_INDIRECT		4

#define VHOST_USER_MAX_FDS		8
#define VHOST_USER_MAX_REGIONS		8
#define VHOST_USER_MAX_QUEUES		8
#define VHOST_USER_MAX_CONFIG		256

struct vhost_hdr {
	uint32_t request;
	uint32_t flags;
	uint32_t size;
} __attribute__((packed));

struct vhost_vring_state {
	uint32_t index;
	uint32_t num;
} __attribute__((packed));

struct vhost_vring_addr {
	uint32_t index;
	uint32_t flags;
	uint64_t desc;
	uint64_t used;
	uint64_t avail;
	uint64_t log;
} __attribute__((packed));

struct vhost_region {
	uint64_t guest_addr;
	uint64_t size;
	uint64_t user_addr;
	uint64_t mmap_offset;
} __attribute__((packed));

struct vhost_mem {
	uint32_t num;
	uint32_t padding;
	struct vhost_region regions[VHOST_USER_MAX_REGIONS];
} __attribute__((packed));

struct vhost_config {
	uint32_t offset;
	uint32_t size;
	uint32_t flags;
	uint8_t payload[VHOST_USER_MAX_CONFIG];
} __attribute__((packed));

struct vhost_msg {
	struct vhost_hdr hdr;
	union {
		uint64_t u64;
		struct vhost_vring_state state;
		struct vhost_vring_addr addr;
		struct vhost_mem mem;
		struct vhost_config config;
	} payload;
} __attribute__((packed));

struct vring_desc {
	uint64_t addr;
	uint32_t len;
	uint16_t flags;
	uint16_t next;
} __attribute__((packed));

struct vring_avail {
	uint16_t flags;
	uint16_t idx;
	uint16_t ring[];
} __attribute__((packed));

struct vring_used_elem {
	uint32_t id;
	uint32_t len;
} __attribute__((packed));

struct vring_used {
	uint16_t flags;
	uint16_t idx;
	struct vring_used_elem ring[];
} __attribute__((packed));

struct region {
	uint64_t guest_addr;
	uint64_t user_addr;
	uint64_t size;
	void *map;
	size_t map_len;
	uint8_t *base;
};

struct queue {
	unsigned int num;
	struct vring_desc *desc;
	struct vring_avail *avail;
	struct vring_used *used;
	uint16_t last_avail;
	int kick_fd;
	int call_fd;
	bool enabled;
	/* A notification is held back by the can_notify callback */
	bool notify_pending;
};

struct vhost {
	int fd;
	const struct vhost_ops *ops;
	void *user_data;
	uint64_t features;
	uint64_t protocol_features;
	int slave_fd;
	struct region regions[VHOST_USER_MAX_REGIONS];
	unsigned int num_regions;
	struct queue queues[VHOST_USER_MAX_QUEUES];
	/* Message being received, which may arrive in several parts */
	struct vhost_msg rx;
	size_t rx_len;
	int rx_fds[VHOST_USER_MAX_FDS];
	unsigned int rx_num_fds;
	bool processing;
	bool freeing;
	vhost_debug_func_t debug_callback;
	void *debug_data;
};

static void vu_debug(struct vhost *vu, const char *format, ...)
{
	char str[128];
	va_list ap;

	if (!vu->debug_callback)
		return;

	va_start(ap, format);
	vsnprintf(str, sizeof(str), format, ap);
	va_end(ap);

	vu->debug_callback(str, vu->debug_data);
}

static void *gpa_to_va(struct vhost *vu, uint64_t addr, uint64_t len)
{
	unsigned int i;

	for (i = 0; i < vu->num_regions; i++) {
		struct region *r = &vu->regions[i];

		if (addr >= r->guest_addr && len <= r->size &&
					addr - r->guest_addr <= r->size - len)
			return r->base + (addr - r->guest_addr);
	}

	return NULL;
}

static void *uva_to_va(struct vhost *vu, uint64_t addr)
{
	unsigned int i;

	for (i = 0; i < vu->num_regions; i++) {
		struct region *r = &vu->regions[i];

		if (addr >= r->user_addr && addr - r->user_addr < r->size)
			return r->base + (addr - r->user_addr);
	}

	return NULL;
}

static void unmap_regions(struct vhost *vu)
{
	unsigned int i;

	for (i = 0; i < vu->num_regions; i++)
		munmap(vu->regions[i].map, vu->regions[i].map_len);

	vu->num_regions = 0;
}

static void close_queue_fds(struct queue *q)
{
	if (q->kick_fd >= 0) {
		mainloop_remove_fd(q->kick_fd);
		close(q->kick_fd);
		q->kick_fd = -1;
	}

	if (q->call_fd >= 0) {
		close(q->call_fd);
		q->call_fd = -1;
	}
}

static void reset_queue(struct queue *q)
{
	close_queue_fds(q);
	q->desc = NULL;
	q->avail = NULL;
	q->used = NULL;
	q->num = 0;
	q->last_avail = 0;
	q->enabled = false;
}

static bool queue_ready(struct queue *q)
{
	return q->enabled && q->desc && q->avail && q->used && q->num;
}

/* Send a VRING_CALL request on the back-end channel and wait for the
 * front-end to acknowledge it. While waiting, the wait callback lets the
 * caller serve the front-end, e.g. as its time travel calendar.
 */
static void notify_inband(struct vhost *vu, unsigned int index)
{
	struct vhost_msg msg = {
		.hdr.request = VHOST_USER_SLAVE_VRING_CALL,
		.hdr.flags = VHOST_USER_VERSION | VHOST_USER_FLAG_NEED_REPLY,
		.hdr.size = sizeof(msg.payload.state),
		.payload.state.index = index,
	};
	struct pollfd pfd = { .fd = vu->slave_fd, .events = POLLIN };
	unsigned int waited = 0;

	if (write(vu->slave_fd, &msg, sizeof(msg.hdr) + msg.hdr.size) < 0) {
		vu_debug(vu, "queue %u: notification failed", index);
		return;
	}

	while (waited < VHOST_USER_REPLY_TIMEOUT) {
		int ret = poll(&pfd, 1, 1);

		if (ret > 0) {
			if (read(vu->slave_fd, &msg, sizeof(msg.hdr) +
					sizeof(msg.payload.u64)) < 0)
				vu_debug(vu, "queue %u: no reply", index);
			return;
		}

		if (ret < 0 && errno != EINTR)
			break;

		if (vu->ops->wait)
			vu->ops->wait(vu, vu->user_data);

		waited++;
	}

	vu_debug(vu, "queue %u: notification not acknowledged", index);
}

static void notify_driver(struct vhost *vu, unsigned int index)
{
	struct queue *q = &vu->queues[index];
	uint64_t val = 1;

	if (vu->ops->can_notify && !vu->ops->can_notify(vu, vu->user_data)) {
		q->notify_pending = true;
		return;
	}

	q->notify_pending = false;

	if (q->call_fd >= 0) {
		if (write(q->call_fd, &val, sizeof(val)) < 0)
			vu_debug(vu, "queue %u: notification failed", index);
		return;
	}

	if (vu->slave_fd >= 0 && (vu->protocol_features &
			(1ULL << VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS)))
		notify_inband(vu, index);
}

static void kick_callback(int fd, uint32_t events, void *user_data)
{
	struct vhost *vu = user_data;
	unsigned int i;
	uint64_t val;

	if (read(fd, &val, sizeof(val)) < 0)
		return;

	for (i = 0; i < vu->ops->num_queues; i++) {
		if (vu->queues[i].kick_fd != fd)
			continue;

		if (vu->ops->queue_notify)
			vu->ops->queue_notify(vu, i, vu->user_data);
		break;
	}
}

/* Return the descriptor chain head of the next available buffer */
static int next_avail(struct queue *q)
{
	uint16_t head;

	if (!queue_ready(q))
		return -1;

	if (q->last_avail == le16_to_cpu(q->avail->idx))
		return -1;

	__sync_synchronize();

	head = le16_to_cpu(q->avail->ring[q->last_avail % q->num]);
	if (head >= q->num)
		return -1;

	q->last_avail++;

	return head;
}

static void add_used(struct vhost *vu, unsigned int index, uint16_t head,
								uint32_t len)
{
	struct queue *q = &vu->queues[index];
	uint16_t idx = le16_to_cpu(q->used->idx);

	q->used->ring[idx % q->num].id = cpu_to_le32(head);
	q->used->ring[idx % q->num].len = cpu_to_le32(len);

	__sync_synchronize();

	q->used->idx = cpu_to_le16(idx + 1);

	notify_driver(vu, index);
}

ssize_t vhost_pop(struct vhost *vu, unsigned int index,
						void *buf, size_t len)
{
	struct queue *q;
	unsigned int count = 0;
	size_t offset = 0;
	int head, i;

	if (index >= vu->ops->num_queues)
		return -1;

	q = &vu->queues[index];

	head = next_avail(q);
	if (head < 0)
		return 0;

	for (i = head;; i = le16_to_cpu(q->desc[i].next)) {
		struct vring_desc *d = &q->desc[i];
		uint32_t dlen = le32_to_cpu(d->len);
		void *data;

		if (le16_to_cpu(d->flags) & (VRING_DESC_F_WRITE |
						VRING_DESC_F_INDIRECT) ||
				dlen > len - offset || ++count > q->num) {
			vu_debug(vu, "queue %u: invalid buffer", index);
			add_used(vu, index, head, 0);
			return -1;
		}

		data = gpa_to_va(vu, le64_to_cpu(d->addr), dlen);
		if (!data) {
			vu_debug(vu, "queue %u: invalid address", index);
			add_used(vu, index, head, 0);
			return -1;
		}

		memcpy(buf + offset, data, dlen);
		offset += dlen;

		if (!(le16_to_cpu(d->flags) & VRING_DESC_F_NEXT))
			break;

		if (le16_to_cpu(d->next) >= q->num) {
			add_used(vu, index, head, 0);
			return -1;
		}
	}

	add_used(vu, index, head, 0);

	return offset;
}

bool vhost_push(struct vhost *vu, unsigned int index,
					const struct iovec *iov, int iovcnt)
{
	struct queue *q;
	size_t total = 0, len, offset = 0, space = 0;
	unsigned int count = 0;
	uint16_t saved;
	int head, i, v = 0;

	if (index >= vu->ops->num_queues)
		return false;

	q = &vu->queues[index];

	for (i = 0; i < iovcnt; i++)
		total += iov[i].iov_len;

	len = total;
	saved = q->last_avail;

	head = next_avail(q);
	if (head < 0)
		return false;

	/* Check that the whole packet fits before writing it */
	for (i = head;; i = le16_to_cpu(q->desc[i].next)) {
		struct vring_desc *d = &q->desc[i];
		uint16_t flags = le16_to_cpu(d->flags);

		if (!(flags & VRING_DESC_F_WRITE) ||
				(flags & VRING_DESC_F_INDIRECT) ||
				++count > q->num)
			goto invalid;

		space += le32_to_cpu(d->len);

		if (!(le16_to_cpu(d->flags) & VRING_DESC_F_NEXT))
			break;

		if (le16_to_cpu(d->next) >= q->num)
			goto invalid;
	}

	if (space < len) {
		vu_debug(vu, "queue %u: %zu bytes do not fit in %zu",
							index, total, space);
		/* Leave the buffer to the driver, the packet is dropped */
		q->last_avail = saved;
		return false;
	}

	for (i = head; len; i = le16_to_cpu(q->desc[i].next)) {
		struct vring_desc *d = &q->desc[i];
		uint32_t dlen = le32_to_cpu(d->len);
		uint8_t *data;
		size_t done = 0;

		data = gpa_to_va(vu, le64_to_cpu(d->addr), dlen);
		if (!data)
			goto invalid;

		while (done < dlen && v < iovcnt) {
			size_t n = MIN(dlen - done, iov[v].iov_len - offset);

			memcpy(data + done, iov[v].iov_base + offset, n);
			done += n;
			offset += n;
			len -= n;

			if (offset == iov[v].iov_len) {
				offset = 0;
				v++;
			}
		}

		if (!len)
			break;
	}

	add_used(vu, index, head, total);

	return true;

invalid:
	vu_debug(vu, "queue %u: invalid buffer", index);
	add_used(vu, index, head, 0);
	return false;
}

static int send_reply(struct vhost *vu, struct vhost_msg *msg,
								size_t size)
{
	msg->hdr.flags = VHOST_USER_VERSION | VHOST_USER_FLAG_REPLY;
	msg->hdr.size = size;

	if (write(vu->fd, msg, sizeof(msg->hdr) + size) < 0)
		return -errno;

	return 0;
}

static int send_u64(struct vhost *vu, struct vhost_msg *msg,
								uint64_t val)
{
	msg->payload.u64 = val;

	return send_reply(vu, msg, sizeof(msg->payload.u64));
}

static int set_mem_table(struct vhost *vu, struct vhost_msg *msg,
						int *fds, unsigned int num_fds)
{
	unsigned int i;

	if (msg->payload.mem.num > VHOST_USER_MAX_REGIONS ||
					msg->payload.mem.num != num_fds)
		return -EINVAL;

	unmap_regions(vu);

	for (i = 0; i < msg->payload.mem.num; i++) {
		struct vhost_region *m = &msg->payload.mem.regions[i];
		struct region *r = &vu->regions[i];

		r->map_len = m->size + m->mmap_offset;
		r->map = mmap(NULL, r->map_len, PROT_READ | PROT_WRITE,
						MAP_SHARED, fds[i], 0);
		if (r->map == MAP_FAILED) {
			vu_debug(vu, "failed to map region %u: %s", i,
							strerror(errno));
			unmap_regions(vu);
			return -errno;
		}

		r->guest_addr = m->guest_addr;
		r->user_addr = m->user_addr;
		r->size = m->size;
		r->base = r->map + m->mmap_offset;
		vu->num_regions++;
	}

	return 0;
}

static int set_vring_fd(struct vhost *vu, struct vhost_msg *msg,
						int *fds, unsigned int num_fds)
{
	unsigned int index = msg->payload.u64 & VHOST_USER_VRING_INDEX_MASK;
	bool nofd = msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK;
	struct queue *q;
	int fd = -1;

	if (index >= vu->ops->num_queues)
		return -EINVAL;

	if (!nofd) {
		if (num_fds != 1)
			return -EINVAL;
		fd = fds[0];
		fds[0] = -1;
	}

	q = &vu->queues[index];

	switch (msg->hdr.request) {
	case VHOST_USER_SET_VRING_KICK:
		if (q->kick_fd >= 0) {
			mainloop_remove_fd(q->kick_fd);
			close(q->kick_fd);
		}
		q->kick_fd = fd;
		if (fd >= 0 && mainloop_add_fd(fd, EPOLLIN, kick_callback,
							vu, NULL) < 0)
			return -EIO;
		/* Without VHOST_USER_F_PROTOCOL_FEATURES queues are enabled
		 * once they have a kick file descriptor.
		 */
		if (!(vu->features & (1ULL << VHOST_USER_F_PROTOCOL_FEATURES)))
			q->enabled = true;
		break;
	case VHOST_USER_SET_VRING_CALL:
		if (q->call_fd >= 0)
			close(q->call_fd);
		q->call_fd = fd;
		break;
	default:
		if (fd >= 0)
			close(fd);
		break;
	}

	return 0;
}

static int get_config(struct vhost *vu, struct vhost_msg *msg)
{
	struct vhost_config *c = &msg->payload.config;
	uint32_t size = c->size;

	if (size > VHOST_USER_MAX_CONFIG)
		return -EINVAL;

	memset(c->payload, 0, size);

	if (c->offset < vu->ops->config_len)
		memcpy(c->payload, vu->ops->config + c->offset,
				MIN(size, vu->ops->config_len - c->offset));

	return send_reply(vu, msg, offsetof(struct vhost_config,
							payload) + size);
}

static int handle_msg(struct vhost *vu, struct vhost_msg *msg,
						int *fds, unsigned int num_fds)
{
	struct queue *q;
	unsigned int index;

	vu_debug(vu, "request %u size %u", msg->hdr.request, msg->hdr.size);

	switch (msg->hdr.request) {
	case VHOST_USER_GET_FEATURES:
		return send_u64(vu, msg, vu->ops->features |
				(1ULL << VIRTIO_F_VERSION_1) |
				(1ULL << VHOST_USER_F_PROTOCOL_FEATURES));
	case VHOST_USER_SET_FEATURES:
		vu->features = msg->payload.u64;
		return 0;
	case VHOST_USER_GET_PROTOCOL_FEATURES:
		return send_u64(vu, msg,
			(1ULL << VHOST_USER_PROTOCOL_F_CONFIG) |
			(1ULL << VHOST_USER_PROTOCOL_F_SLAVE_REQ) |
			(1ULL << VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS));
	case VHOST_USER_SET_PROTOCOL_FEATURES:
		vu->protocol_features = msg->payload.u64;
		return 0;
	case VHOST_USER_SET_OWNER:
		return 0;
	case VHOST_USER_RESET_OWNER:
		for (index = 0; index < vu->ops->num_queues; index++)
			reset_queue(&vu->queues[index]);
		unmap_regions(vu);
		return 0;
	case VHOST_USER_SET_MEM_TABLE:
		return set_mem_table(vu, msg, fds, num_fds);
	case VHOST_USER_SET_VRING_KICK:
	case VHOST_USER_SET_VRING_CALL:
	case VHOST_USER_SET_VRING_ERR:
		return set_vring_fd(vu, msg, fds, num_fds);
	case VHOST_USER_SET_SLAVE_REQ_FD:
		if (num_fds != 1)
			return -EINVAL;
		if (vu->slave_fd >= 0)
			close(vu->slave_fd);
		vu->slave_fd = fds[0];
		fds[0] = -1;
		return 0;
	case VHOST_USER_GET_CONFIG:
		return get_config(vu, msg);
	case VHOST_USER_SET_CONFIG:
		return 0;
	}

	index = msg->payload.state.index;
	if (index >= vu->ops->num_queues)
		return -EINVAL;

	q = &vu->queues[index];

	switch (msg->hdr.request) {
	case VHOST_USER_SET_VRING_NUM:
		if (!msg->payload.state.num ||
				msg->payload.state.num > 32768 ||
				msg->payload.state.num &
				(msg->payload.state.num - 1))
			return -EINVAL;
		q->num = msg->payload.state.num;
		return 0;
	case VHOST_USER_SET_VRING_BASE:
		q->last_avail = msg->payload.state.num;
		return 0;
	case VHOST_USER_GET_VRING_BASE:
		/* The driver stops the queue */
		q->enabled = false;
		close_queue_fds(q);
		msg->payload.state.num = q->last_avail;
		return send_reply(vu, msg, sizeof(msg->payload.state));
	case VHOST_USER_SET_VRING_ADDR:
		q->desc = uva_to_va(vu, msg->payload.addr.desc);
		q->avail = uva_to_va(vu, msg->payload.addr.avail);
		q->used = uva_to_va(vu, msg->payload.addr.used);
		if (!q->desc || !q->avail || !q->used)
			return -EINVAL;
		return 0;
	case VHOST_USER_VRING_KICK:
		if (vu->ops->queue_notify)
			vu->ops->queue_notify(vu, index, vu->user_data);
		return 0;
	case VHOST_USER_SET_VRING_ENABLE:
		q->enabled = msg->payload.state.num;
		if (q->enabled && vu->ops->queue_notify)
			vu->ops->queue_notify(vu, index, vu->user_data);
		return 0;
	}

	vu_debug(vu, "unsupported request %u", msg->hdr.request);

	return -EOPNOTSUPP;
}

static void close_rx_fds(struct vhost *vu)
{
	unsigned int i;

	for (i = 0; i < vu->rx_num_fds; i++)
		close(vu->rx_fds[i]);

	vu->rx_num_fds = 0;
}

/* Receive the next part of the message without blocking. Returns 0 once
 * the message is complete, with its file descriptors moved to fds.
 */
static int recv_msg(struct vhost *vu, struct vhost_msg *msg,
				int *fds, unsigned int *num_fds)
{
	char control[CMSG_SPACE(sizeof(int) * VHOST_USER_MAX_FDS)];
	size_t hdr_len = sizeof(vu->rx.hdr);
	struct iovec iov;
	struct msghdr mh = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg;
	size_t total;
	ssize_t len;

	if (vu->rx_len < hdr_len)
		total = hdr_len;
	else
		total = hdr_len + vu->rx.hdr.size;

	iov.iov_base = (uint8_t *) &vu->rx + vu->rx_len;
	iov.iov_len = total - vu->rx_len;

	len = recvmsg(vu->fd, &mh, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
	if (len < 0 && (errno == EAGAIN || errno == EINTR))
		return -EAGAIN;
	if (len <= 0)
		return -EIO;

	for (cmsg = CMSG_FIRSTHDR(&mh); cmsg; cmsg = CMSG_NXTHDR(&mh, cmsg)) {
		unsigned int n, i;
		int *cfds;

		if (cmsg->cmsg_level != SOL_SOCKET ||
					cmsg->cmsg_type != SCM_RIGHTS)
			continue;

		n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		cfds = (int *) CMSG_DATA(cmsg);

		for (i = 0; i < n; i++) {
			if (vu->rx_num_fds < VHOST_USER_MAX_FDS)
				vu->rx_fds[vu->rx_num_fds++] = cfds[i];
			else
				close(cfds[i]);
		}
	}

	vu->rx_len += len;

	if (vu->rx_len == hdr_len && vu->rx.hdr.size > sizeof(vu->rx.payload))
		return -EINVAL;

	if (vu->rx_len < hdr_len || vu->rx_len < hdr_len + vu->rx.hdr.size)
		return -EAGAIN;

	memcpy(msg, &vu->rx, vu->rx_len);
	memcpy(fds, vu->rx_fds, vu->rx_num_fds * sizeof(int));
	*num_fds = vu->rx_num_fds;

	memset(&vu->rx, 0, sizeof(vu->rx));
	vu->rx_len = 0;
	vu->rx_num_fds = 0;

	return 0;
}

static bool process_msg(struct vhost *vu, bool *failed)
{
	struct vhost_msg msg;
	int fds[VHOST_USER_MAX_FDS];
	unsigned int num_fds, i;
	bool need_reply;
	int err;

	memset(&msg, 0, sizeof(msg));

	err = recv_msg(vu, &msg, fds, &num_fds);
	if (err == -EAGAIN)
		return true;
	if (err < 0) {
		*failed = true;
		return false;
	}

	need_reply = msg.hdr.flags & VHOST_USER_FLAG_NEED_REPLY;

	err = handle_msg(vu, &msg, fds, num_fds);

	/* File descriptors taken over are set to -1, the memory mappings
	 * keep the memory referenced.
	 */
	for (i = 0; i < num_fds; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}

	if (need_reply && msg.hdr.request != VHOST_USER_GET_FEATURES &&
			msg.hdr.request != VHOST_USER_GET_PROTOCOL_FEATURES &&
			msg.hdr.request != VHOST_USER_GET_VRING_BASE &&
			msg.hdr.request != VHOST_USER_GET_CONFIG)
		send_u64(vu, &msg, err < 0 ? 1 : 0);

	if (err < 0)
		vu_debug(vu, "request %u failed: %s", msg.hdr.request,
							strerror(-err));

	return true;
}

/* Handle the pending messages. A message may trigger the calendar, which
 * processes the connections before advancing time, this one included, so
 * a nested call returns right away and leaves its messages to the outer
 * one, which alone may remove the connection, once done with it.
 */
static void process_msgs(struct vhost *vu)
{
	bool failed = false;
	int avail;

	if (vu->fd < 0 || vu->processing)
		return;

	vu->processing = true;

	while (process_msg(vu, &failed)) {
		if (ioctl(vu->fd, FIONREAD, &avail) < 0 || avail <= 0)
			break;
	}

	vu->processing = false;

	if (failed)
		mainloop_remove_fd(vu->fd);
}

static void read_callback(int fd, uint32_t events, void *user_data)
{
	struct vhost *vu = user_data;

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_remove_fd(vu->fd);
		return;
	}

	process_msgs(vu);
}

void vhost_flush_notify(struct vhost *vu)
{
	unsigned int i;

	for (i = 0; i < vu->ops->num_queues; i++) {
		if (vu->queues[i].notify_pending)
			notify_driver(vu, i);
	}
}

void vhost_process(struct vhost *vu)
{
	process_msgs(vu);
}

static void vu_destroy(void *user_data)
{
	struct vhost *vu = user_data;
	unsigned int i;

	for (i = 0; i < VHOST_USER_MAX_QUEUES; i++)
		reset_queue(&vu->queues[i]);

	unmap_regions(vu);
	close_rx_fds(vu);

	if (vu->slave_fd >= 0) {
		close(vu->slave_fd);
		vu->slave_fd = -1;
	}

	close(vu->fd);
	vu->fd = -1;

	if (!vu->freeing && vu->ops->disconnect)
		vu->ops->disconnect(vu, vu->user_data);
}

struct vhost *vhost_new(int fd, const struct vhost_ops *ops,
							void *user_data)
{
	struct vhost *vu;
	unsigned int i;

	if (ops->num_queues > VHOST_USER_MAX_QUEUES ||
				ops->config_len > VHOST_USER_MAX_CONFIG)
		return NULL;

	vu = new0(struct vhost, 1);
	vu->fd = fd;
	vu->slave_fd = -1;
	vu->ops = ops;
	vu->user_data = user_data;

	for (i = 0; i < VHOST_USER_MAX_QUEUES; i++) {
		vu->queues[i].kick_fd = -1;
		vu->queues[i].call_fd = -1;
	}

	if (mainloop_add_fd(fd, EPOLLIN, read_callback, vu, vu_destroy) < 0) {
		free(vu);
		return NULL;
	}

	return vu;
}

void vhost_free(struct vhost *vu)
{
	if (!vu)
		return;

	vu->freeing = true;

	if (vu->fd >= 0)
		mainloop_remove_fd(vu->fd);

	free(vu);
}

void vhost_set_debug(struct vhost *vu,
				vhost_debug_func_t callback, void *user_data)
{
	vu->debug_callback = callback;
	vu->debug_data = user_data;
}
