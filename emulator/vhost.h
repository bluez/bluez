/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Intel Corporation
 *
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/uio.h>

struct vhost;

struct vhost_ops {
	/* Device specific virtio feature bits, VERSION_1 is always offered */
	uint64_t features;
	unsigned int num_queues;
	/* Device configuration space, read with VHOST_USER_GET_CONFIG */
	const void *config;
	size_t config_len;
	/* The driver made buffers available on a queue */
	void (*queue_notify)(struct vhost *vu, unsigned int index,
							void *user_data);
	/* The connection was closed */
	void (*disconnect)(struct vhost *vu, void *user_data);
	/* Called repeatedly while waiting for the front-end to acknowledge
	 * an in-band notification
	 */
	void (*wait)(struct vhost *vu, void *user_data);
	/* If set and returning false, notifications to the driver are held
	 * back until vhost_flush_notify()
	 */
	bool (*can_notify)(struct vhost *vu, void *user_data);
};

struct vhost *vhost_new(int fd, const struct vhost_ops *ops,
							void *user_data);
void vhost_free(struct vhost *vu);

/* Send the notifications held back by can_notify */
void vhost_flush_notify(struct vhost *vu);

/* Process the messages pending on the connection without blocking */
void vhost_process(struct vhost *vu);

typedef void (*vhost_debug_func_t)(const char *str, void *user_data);
void vhost_set_debug(struct vhost *vu,
				vhost_debug_func_t callback, void *user_data);

/* Read the next buffer the driver made available on a driver-to-device
 * queue into buf. Returns the number of bytes read, 0 if no buffer is
 * available or -1 on error.
 */
ssize_t vhost_pop(struct vhost *vu, unsigned int index,
						void *buf, size_t len);

/* Write the data into the next buffer the driver made available on a
 * device-to-driver queue and notify the driver. Returns false if no buffer
 * is available or the data does not fit.
 */
bool vhost_push(struct vhost *vu, unsigned int index,
					const struct iovec *iov, int iovcnt);
