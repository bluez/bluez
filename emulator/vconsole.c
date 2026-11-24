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

#include "vhost.h"
#include "timetravel.h"
#include "ttclient.h"
#include "vconsole.h"

/* Virtio console, see include/uapi/linux/virtio_console.h in Linux */
#define VCON_F_MULTIPORT	1

#define VCON_DEVICE_READY	0
#define VCON_DEVICE_ADD		1
#define VCON_PORT_READY		3
#define VCON_PORT_OPEN		6
#define VCON_PORT_NAME		7

/* Queues: port 0 receive/transmit, control receive/transmit, then a
 * receive/transmit pair for each further port.
 */
#define VCON_CTRL_RX		2
#define VCON_CTRL_TX		3

#define VCON_MAX_PORTS		3
#define VCON_MAX_NAME		64
/* The Linux driver posts receive buffers of a page */
#define VCON_CHUNK		4096
/* Data from the guest kept while no peer is connected */
#define VCON_MAX_BACKLOG	(1024 * 1024)

struct vcon_config {
	uint16_t cols;
	uint16_t rows;
	uint32_t max_nr_ports;
	uint32_t emerg_wr;
} __attribute__((packed));

struct vcon_ctrl {
	uint32_t id;
	uint16_t event;
	uint16_t value;
} __attribute__((packed));

struct packet {
	size_t len;
	uint8_t data[];
};

struct port {
	struct vcon *vcon;
	unsigned int id;
	char name[VCON_MAX_NAME];
	bool sync;
	int listen_fd;
	int client_fd;
	/* Data for the guest, waiting for receive buffers */
	struct queue *to_guest;
	/* Data from the guest, waiting for a peer */
	struct queue *to_peer;
	size_t to_peer_len;
	/* The peer sent a request the guest has not answered yet */
	bool outstanding;
	/* The driver discards data of ports nobody opened in the guest */
	bool guest_open;
};

struct vcon {
	char path[108];
	int fd;
	struct vhost *vu;
	struct vhost_ops ops;
	struct vcon_config config;
	struct port ports[VCON_MAX_PORTS];
	unsigned int num_ports;
	/* Control messages waiting for receive buffers */
	struct queue *ctrl;
	vcon_debug_func_t debug_callback;
	void *debug_data;
};

static struct queue *vcons;

static void vcon_debug(struct vcon *vcon, const char *format, ...)
{
	char str[160];
	va_list ap;

	if (!vcon->debug_callback)
		return;

	va_start(ap, format);
	vsnprintf(str, sizeof(str), format, ap);
	va_end(ap);

	vcon->debug_callback(str, vcon->debug_data);
}

static unsigned int rx_queue(unsigned int port)
{
	return port ? 2 + 2 * port : 0;
}

static struct packet *packet_new(const void *data, size_t len)
{
	struct packet *pkt;

	pkt = malloc(sizeof(*pkt) + len);
	if (!pkt)
		return NULL;

	pkt->len = len;
	memcpy(pkt->data, data, len);

	return pkt;
}

/* Push pending packets to a receive queue while it has buffers */
static void flush_queue(struct vcon *vcon, struct queue *pending,
							unsigned int index)
{
	struct packet *pkt;

	if (!vcon->vu || queue_isempty(pending))
		return;

	/* As time travel client, only inject while the calendar lets it run,
	 * so no guest has run past that time.
	 */
	if (!ttc_running())
		return;

	while ((pkt = queue_peek_head(pending))) {
		struct iovec iov = { pkt->data, pkt->len };

		if (!vhost_push(vcon->vu, index, &iov, 1))
			break;


		queue_pop_head(pending);
		free(pkt);
	}
}

static void send_ctrl(struct vcon *vcon, unsigned int id, uint16_t event,
					uint16_t value, const char *name)
{
	uint8_t buf[sizeof(struct vcon_ctrl) + VCON_MAX_NAME];
	struct vcon_ctrl *ctrl = (void *) buf;
	size_t len = sizeof(*ctrl);
	struct packet *pkt;

	ctrl->id = cpu_to_le32(id);
	ctrl->event = cpu_to_le16(event);
	ctrl->value = cpu_to_le16(value);

	if (name) {
		memcpy(buf + len, name, strlen(name));
		len += strlen(name);
	}

	pkt = packet_new(buf, len);
	if (!pkt)
		return;

	queue_push_tail(vcon->ctrl, pkt);
	flush_queue(vcon, vcon->ctrl, VCON_CTRL_RX);
}

static void flush_port(struct port *port)
{
	if (port->guest_open)
		flush_queue(port->vcon, port->to_guest, rx_queue(port->id));
}

static void handle_ctrl(struct vcon *vcon, const struct vcon_ctrl *ctrl)
{
	unsigned int id = le32_to_cpu(ctrl->id);
	struct port *port;
	unsigned int i;

	switch (le16_to_cpu(ctrl->event)) {
	case VCON_DEVICE_READY:
		for (i = 0; i < vcon->num_ports; i++)
			send_ctrl(vcon, i, VCON_DEVICE_ADD, 1, NULL);
		break;
	case VCON_PORT_READY:
		if (id >= vcon->num_ports)
			break;
		send_ctrl(vcon, id, VCON_PORT_NAME, 1, vcon->ports[id].name);
		/* Data from the guest is kept until a peer connects */
		send_ctrl(vcon, id, VCON_PORT_OPEN, 1, NULL);
		break;
	case VCON_PORT_OPEN:
		if (id >= vcon->num_ports)
			break;
		port = &vcon->ports[id];
		port->guest_open = le16_to_cpu(ctrl->value);
		vcon_debug(vcon, "%s: guest %s", port->name,
				port->guest_open ? "opened" : "closed");
		flush_port(port);
		break;
	}
}

static void write_peer(struct port *port, const uint8_t *data, size_t len)
{
	while (len) {
		ssize_t n = write(port->client_fd, data, len);

		if (n < 0)
			return;

		data += n;
		len -= n;
	}
}

static void from_guest(struct port *port, const uint8_t *data, size_t len)
{
	struct packet *pkt;

	/* The guest answered */
	port->outstanding = false;

	if (port->client_fd >= 0) {
		write_peer(port, data, len);
		return;
	}

	/* Answers of a sync port belong to the peer that asked, other ports
	 * keep the guest's output (e.g. logs) until a peer connects.
	 */
	if (port->sync || port->to_peer_len + len > VCON_MAX_BACKLOG)
		return;

	pkt = packet_new(data, len);
	if (!pkt)
		return;

	queue_push_tail(port->to_peer, pkt);
	port->to_peer_len += len;
}

static void queue_notify(struct vhost *vu, unsigned int index,
							void *user_data)
{
	struct vcon *vcon = user_data;
	static uint8_t buf[65536];
	unsigned int i;
	ssize_t len;

	if (index == VCON_CTRL_TX) {
		while ((len = vhost_pop(vu, index, buf, sizeof(buf)))) {
			if (len >= (ssize_t) sizeof(struct vcon_ctrl))
				handle_ctrl(vcon, (void *) buf);
		}
		goto done;
	}

	if (index == VCON_CTRL_RX) {
		flush_queue(vcon, vcon->ctrl, VCON_CTRL_RX);
		goto done;
	}

	for (i = 0; i < vcon->num_ports; i++) {
		struct port *port = &vcon->ports[i];

		if (index == rx_queue(i)) {
			flush_port(port);
			break;
		}

		if (index == rx_queue(i) + 1) {
			while ((len = vhost_pop(vu, index, buf, sizeof(buf)))) {
				if (len > 0)
					from_guest(port, buf, len);
			}
			break;
		}
	}

done:
	tt_schedule();
}

static void run_vcon(void *data, void *user_data)
{
	struct vcon *vcon = data;
	unsigned int i;

	if (!vcon->vu)
		return;

	flush_queue(vcon, vcon->ctrl, VCON_CTRL_RX);

	for (i = 0; i < vcon->num_ports; i++)
		flush_port(&vcon->ports[i]);

	vhost_flush_notify(vcon->vu);
}

/* The calendar lets the time travel client run: deliver what is pending */
static void run(void *user_data)
{
	queue_foreach(vcons, run_vcon, NULL);
}

static bool can_notify(struct vhost *vu, void *user_data)
{
	return ttc_running();
}

static void vhost_wait(struct vhost *vu, void *user_data)
{
	tt_process();
	ttc_process();
}

static void disconnect(struct vhost *vu, void *user_data)
{
	struct vcon *vcon = user_data;
	unsigned int i;

	vcon_debug(vcon, "guest disconnected");

	vhost_free(vcon->vu);
	vcon->vu = NULL;
	queue_remove_all(vcon->ctrl, NULL, NULL, free);

	for (i = 0; i < vcon->num_ports; i++)
		vcon->ports[i].guest_open = false;

	tt_schedule();
}

static void vu_debug(const char *str, void *user_data)
{
	struct vcon *vcon = user_data;

	vcon_debug(vcon, "vhost-user: %s", str);
}

static void accept_guest(int fd, uint32_t events, void *user_data)
{
	struct vcon *vcon = user_data;
	int nfd;

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_remove_fd(fd);
		return;
	}

	nfd = accept(fd, NULL, NULL);
	if (nfd < 0)
		return;

	if (vcon->vu) {
		vcon_debug(vcon, "already serving a guest");
		close(nfd);
		return;
	}

	vcon->vu = vhost_new(nfd, &vcon->ops, vcon);
	if (!vcon->vu) {
		close(nfd);
		return;
	}

	vhost_set_debug(vcon->vu, vu_debug, vcon);

	vcon_debug(vcon, "guest connected");
}

static void peer_read(int fd, uint32_t events, void *user_data)
{
	struct port *port = user_data;
	uint8_t buf[VCON_CHUNK];
	struct packet *pkt;
	ssize_t len;

	len = read(fd, buf, sizeof(buf));
	if (len <= 0) {
		mainloop_remove_fd(fd);
		return;
	}

	pkt = packet_new(buf, len);
	if (!pkt)
		return;

	if (port->sync)
		port->outstanding = true;

	queue_push_tail(port->to_guest, pkt);
	flush_port(port);

	tt_schedule();
}

static void peer_destroy(void *user_data)
{
	struct port *port = user_data;

	vcon_debug(port->vcon, "%s: peer disconnected", port->name);

	close(port->client_fd);
	port->client_fd = -1;
	port->outstanding = false;

	/* Requests of the peer that left are not delivered anymore */
	queue_remove_all(port->to_guest, NULL, NULL, free);

	tt_schedule();
}

static void accept_peer(int fd, uint32_t events, void *user_data)
{
	struct port *port = user_data;
	struct packet *pkt;
	int nfd;

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_remove_fd(fd);
		return;
	}

	nfd = accept(fd, NULL, NULL);
	if (nfd < 0)
		return;

	if (port->client_fd >= 0) {
		close(nfd);
		return;
	}

	port->client_fd = nfd;

	if (mainloop_add_fd(nfd, EPOLLIN, peer_read, port, peer_destroy) < 0) {
		close(nfd);
		port->client_fd = -1;
		return;
	}

	vcon_debug(port->vcon, "%s: peer connected", port->name);

	while ((pkt = queue_pop_head(port->to_peer))) {
		write_peer(port, pkt->data, pkt->len);
		free(pkt);
	}

	port->to_peer_len = 0;
}

static int listen_unix(const char *path)
{
	struct sockaddr_un addr;
	int fd;

	if (strlen(path) >= sizeof(addr.sun_path))
		return -1;

	fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	unlink(path);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, path, strlen(path));

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
							listen(fd, 5) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static void sync_state(void *data, void *user_data)
{
	struct vcon *vcon = data;
	unsigned int *state = user_data;
	unsigned int i;

	for (i = 0; i < vcon->num_ports; i++) {
		struct port *port = &vcon->ports[i];

		if (!port->sync || port->client_fd < 0)
			continue;

		state[0]++;
		if (port->outstanding)
			state[1]++;
	}
}

/* Hold time while a peer is connected to a sync port but has no request
 * outstanding on any of them: it is between requests, so the guests must
 * not run ahead of it, time then advances at most at real time.
 */
static bool hold(void *user_data)
{
	unsigned int state[2] = { 0, 0 };

	queue_foreach(vcons, sync_state, state);

	return state[0] && !state[1];
}

static void flush(void *user_data)
{
	struct vcon *vcon = user_data;

	if (vcon->vu)
		vhost_process(vcon->vu);
}

static bool parse_spec(struct vcon *vcon, const char *spec)
{
	char *str, *tok, *save = NULL;
	bool ok = false;

	str = strdup(spec);
	if (!str)
		return false;

	tok = strtok_r(str, ":", &save);
	if (!tok || strlen(tok) >= sizeof(vcon->path))
		goto done;

	memcpy(vcon->path, tok, strlen(tok) + 1);

	while ((tok = strtok_r(NULL, ":", &save))) {
		struct port *port;
		char *opt;

		if (vcon->num_ports == VCON_MAX_PORTS)
			goto done;

		port = &vcon->ports[vcon->num_ports];

		opt = strchr(tok, '=');
		if (opt) {
			*opt++ = '\0';
			if (strcmp(opt, "sync"))
				goto done;
			port->sync = true;
		}

		if (!*tok || strlen(tok) >= sizeof(port->name))
			goto done;

		memcpy(port->name, tok, strlen(tok) + 1);
		port->id = vcon->num_ports++;
	}

	ok = vcon->num_ports > 0;

done:
	free(str);
	return ok;
}

struct vcon *vcon_open(const char *spec)
{
	struct vcon *vcon;
	unsigned int i;

	vcon = new0(struct vcon, 1);
	vcon->fd = -1;

	for (i = 0; i < VCON_MAX_PORTS; i++) {
		vcon->ports[i].listen_fd = -1;
		vcon->ports[i].client_fd = -1;
	}

	if (!parse_spec(vcon, spec)) {
		free(vcon);
		return NULL;
	}

	vcon->ctrl = queue_new();
	vcon->config.max_nr_ports = cpu_to_le32(vcon->num_ports);
	vcon->ops.features = 1ULL << VCON_F_MULTIPORT;
	vcon->ops.num_queues = 2 + 2 * vcon->num_ports;
	vcon->ops.config = &vcon->config;
	vcon->ops.config_len = sizeof(vcon->config);
	vcon->ops.queue_notify = queue_notify;
	vcon->ops.disconnect = disconnect;
	vcon->ops.wait = vhost_wait;
	vcon->ops.can_notify = can_notify;

	vcon->fd = listen_unix(vcon->path);
	if (vcon->fd < 0 || mainloop_add_fd(vcon->fd, EPOLLIN, accept_guest,
							vcon, NULL) < 0)
		goto fail;

	for (i = 0; i < vcon->num_ports; i++) {
		struct port *port = &vcon->ports[i];
		char path[sizeof(vcon->path) + VCON_MAX_NAME + 1];

		port->vcon = vcon;
		port->to_guest = queue_new();
		port->to_peer = queue_new();

		snprintf(path, sizeof(path), "%s-%s", vcon->path, port->name);
		port->listen_fd = listen_unix(path);
		if (port->listen_fd < 0 || mainloop_add_fd(port->listen_fd,
				EPOLLIN, accept_peer, port, NULL) < 0)
			goto fail;
	}

	if (!vcons) {
		vcons = queue_new();
		tt_set_hold(hold, NULL);
		ttc_set_pace(hold, NULL);
		ttc_set_run(run, NULL);
	}

	queue_push_tail(vcons, vcon);
	tt_add_flush(flush, vcon);

	return vcon;

fail:
	fprintf(stderr, "Failed to open console %s\n", vcon->path);
	vcon_close(vcon);
	return NULL;
}

void vcon_close(struct vcon *vcon)
{
	unsigned int i;

	if (!vcon)
		return;

	queue_remove(vcons, vcon);

	for (i = 0; i < vcon->num_ports; i++) {
		struct port *port = &vcon->ports[i];

		if (port->client_fd >= 0)
			mainloop_remove_fd(port->client_fd);
		if (port->listen_fd >= 0) {
			mainloop_remove_fd(port->listen_fd);
			close(port->listen_fd);
		}
		queue_destroy(port->to_guest, free);
		queue_destroy(port->to_peer, free);
	}

	vhost_free(vcon->vu);

	if (vcon->fd >= 0) {
		mainloop_remove_fd(vcon->fd);
		close(vcon->fd);
	}

	tt_remove_flush(flush, vcon);
	queue_destroy(vcon->ctrl, free);
	free(vcon);
}

bool vcon_set_debug(struct vcon *vcon, vcon_debug_func_t callback,
							void *user_data)
{
	if (!vcon)
		return false;

	vcon->debug_callback = callback;
	vcon->debug_data = user_data;

	return true;
}
