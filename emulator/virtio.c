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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "src/shared/mainloop.h"
#include "src/shared/queue.h"
#include "src/shared/util.h"

#include "btdev.h"
#include "vhost.h"
#include "virtio.h"

/* Virtio device ID 40, see include/uapi/linux/virtio_bt.h in Linux */
#define VTIO_F_MSFT_EXT	1

#define VTIO_VQ_TX		0
#define VTIO_VQ_RX		1
#define VTIO_NUM_VQS	2

#define VTIO_MSFT_OPCODE	0xfc1e

/* The Linux driver posts receive buffers of this size */
#define VTIO_MAX_PKT	1000

struct vtio_config {
	uint8_t  type;
	uint16_t vendor;
	uint16_t msft_opcode;
} __attribute__((packed));

struct vtio {
	enum btdev_type type;
	int fd;
	struct queue *clients;
	vtio_debug_func_t debug_callback;
	void *debug_data;
};

struct client {
	struct vtio *vtio;
	struct vhost *vu;
	struct btdev *btdev;
	/* Packets for the driver, waiting for receive buffers */
	struct queue *pending;
};

struct packet {
	size_t len;
	uint8_t data[];
};

static struct vtio_config config;

static void vtio_debug(struct vtio *vtio, const char *format, ...)
{
	char str[128];
	va_list ap;

	if (!vtio || !vtio->debug_callback)
		return;

	va_start(ap, format);
	vsnprintf(str, sizeof(str), format, ap);
	va_end(ap);

	vtio->debug_callback(str, vtio->debug_data);
}

static void client_free(void *data)
{
	struct client *client = data;

	vhost_free(client->vu);
	btdev_destroy(client->btdev);
	queue_destroy(client->pending, free);
	free(client);
}

static void flush_pending(struct client *client)
{
	struct packet *pkt;

	while ((pkt = queue_peek_head(client->pending))) {
		struct iovec iov = { pkt->data, pkt->len };

		if (!vhost_push(client->vu, VTIO_VQ_RX, &iov, 1))
			break;

		queue_pop_head(client->pending);
		free(pkt);
	}
}

static void btdev_send(const struct iovec *iov, int iovlen, void *user_data)
{
	struct client *client = user_data;
	struct packet *pkt;
	size_t len = 0;
	int i;

	for (i = 0; i < iovlen; i++)
		len += iov[i].iov_len;

	if (len > VTIO_MAX_PKT) {
		vtio_debug(client->vtio, "dropping %zu bytes packet", len);
		return;
	}

	pkt = malloc(sizeof(*pkt) + len);
	if (!pkt)
		return;

	pkt->len = 0;
	for (i = 0; i < iovlen; i++) {
		memcpy(pkt->data + pkt->len, iov[i].iov_base, iov[i].iov_len);
		pkt->len += iov[i].iov_len;
	}

	/* The driver may have no receive buffer posted, e.g. for back to
	 * back events, so keep the packet until it posts one.
	 */
	queue_push_tail(client->pending, pkt);
	flush_pending(client);
}

static void queue_notify(struct vhost *vu, unsigned int index,
							void *user_data)
{
	struct client *client = user_data;
	uint8_t buf[VTIO_MAX_PKT + 4];
	ssize_t len;

	switch (index) {
	case VTIO_VQ_TX:
		while ((len = vhost_pop(vu, index, buf, sizeof(buf)))) {
			if (len > 0)
				btdev_receive_h4(client->btdev, buf, len);
		}
		break;
	case VTIO_VQ_RX:
		flush_pending(client);
		break;
	}
}

static void disconnect(struct vhost *vu, void *user_data)
{
	struct client *client = user_data;

	vtio_debug(client->vtio, "client disconnected");

	/* vu is being torn down by the mainloop and freed by client_free */
	if (client->vtio)
		queue_remove(client->vtio->clients, client);

	client_free(client);
}

static const struct vhost_ops vhost_ops = {
	.features = 1ULL << VTIO_F_MSFT_EXT,
	.num_queues = VTIO_NUM_VQS,
	.config = &config,
	.config_len = sizeof(config),
	.queue_notify = queue_notify,
	.disconnect = disconnect,
};

static void vu_debug(const char *str, void *user_data)
{
	struct client *client = user_data;

	vtio_debug(client->vtio, "vhost-user: %s", str);
}

static void accept_callback(int fd, uint32_t events, void *user_data)
{
	struct vtio *vtio = user_data;
	struct client *client;
	int nfd;

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_remove_fd(vtio->fd);
		return;
	}

	nfd = accept(vtio->fd, NULL, NULL);
	if (nfd < 0)
		return;

	client = new0(struct client, 1);
	client->vtio = vtio;
	client->pending = queue_new();

	client->btdev = btdev_create(vtio->type, 0x42);
	if (!client->btdev)
		goto fail;

	btdev_set_msft_opcode(client->btdev, VTIO_MSFT_OPCODE);
	btdev_set_send_handler(client->btdev, btdev_send, client);

	client->vu = vhost_new(nfd, &vhost_ops, client);
	if (!client->vu)
		goto fail;

	vhost_set_debug(client->vu, vu_debug, client);

	queue_push_tail(vtio->clients, client);

	vtio_debug(vtio, "client connected");

	return;

fail:
	close(nfd);
	btdev_destroy(client->btdev);
	queue_destroy(client->pending, free);
	free(client);
}

static void detach_client(void *data)
{
	struct client *client = data;

	client->vtio = NULL;
}

static void vtio_destroy(void *user_data)
{
	struct vtio *vtio = user_data;

	queue_destroy(vtio->clients, detach_client);
	close(vtio->fd);
	free(vtio);
}

struct vtio *vtio_open(enum btdev_type type, const char *path)
{
	struct vtio *vtio;
	struct sockaddr_un addr;

	if (strlen(path) >= sizeof(addr.sun_path))
		return NULL;

	config.msft_opcode = cpu_to_le16(VTIO_MSFT_OPCODE);

	vtio = new0(struct vtio, 1);
	vtio->type = type;
	vtio->clients = queue_new();

	vtio->fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (vtio->fd < 0) {
		perror("Failed to open vhost-user socket");
		goto fail;
	}

	unlink(path);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, path, strlen(path));

	if (bind(vtio->fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to bind vhost-user socket");
		goto fail;
	}

	if (listen(vtio->fd, 5) < 0) {
		perror("Failed to listen on vhost-user socket");
		goto fail;
	}

	if (mainloop_add_fd(vtio->fd, EPOLLIN, accept_callback, vtio,
							vtio_destroy) < 0)
		goto fail;

	return vtio;

fail:
	if (vtio->fd >= 0)
		close(vtio->fd);
	queue_destroy(vtio->clients, NULL);
	free(vtio);
	return NULL;
}

void vtio_close(struct vtio *vtio)
{
	if (!vtio)
		return;

	mainloop_remove_fd(vtio->fd);
}

bool vtio_set_debug(struct vtio *vtio,
			vtio_debug_func_t callback, void *user_data)
{
	if (!vtio)
		return false;

	vtio->debug_callback = callback;
	vtio->debug_data = user_data;

	return true;
}
