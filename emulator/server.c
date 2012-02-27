/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#include "mainloop.h"
#include "btdev.h"
#include "server.h"

struct server {
	uint16_t id;
	int fd;
};

struct client {
	int fd;
	struct btdev *btdev;
	uint8_t *pkt_data;
	uint8_t pkt_type;
	uint16_t pkt_expect;
	uint16_t pkt_len;
	uint16_t pkt_offset;
};

static void server_destroy(void *user_data)
{
	struct server *server = user_data;

	close(server->fd);

	free(server);
}

static void client_destroy(void *user_data)
{
	struct client *client = user_data;

	btdev_destroy(client->btdev);

	close(client->fd);

	free(client);
}

static void client_write_callback(const void *data, uint16_t len,
							void *user_data)
{
	struct client *client = user_data;
	ssize_t written;

	written = send(client->fd, data, len, MSG_DONTWAIT);
	if (written < 0)
		return;
}

static void client_read_callback(int fd, uint32_t events, void *user_data)
{
	struct client *client = user_data;
	static uint8_t buf[4096];
	uint8_t *ptr = buf;
	ssize_t len;
	uint16_t count;

	if (events & (EPOLLERR | EPOLLHUP))
		return;

again:
	len = recv(fd, buf + client->pkt_offset,
			sizeof(buf) - client->pkt_offset, MSG_DONTWAIT);
	if (len < 0) {
		if (errno == EAGAIN)
			goto again;
		return;
	}

	count = client->pkt_offset + len;

	while (count > 0) {
		hci_command_hdr *cmd_hdr;

		if (!client->pkt_data) {
			client->pkt_type = ptr[0];

			switch (client->pkt_type) {
			case HCI_COMMAND_PKT:
				if (count < HCI_COMMAND_HDR_SIZE + 1) {
					client->pkt_offset += len;
					return;
				}
				cmd_hdr = (hci_command_hdr *) (ptr + 1);
				client->pkt_expect = HCI_COMMAND_HDR_SIZE +
							cmd_hdr->plen + 1;
				client->pkt_data = malloc(client->pkt_expect);
				client->pkt_len = 0;
				break;
			default:
				printf("packet error\n");
				return;
			}

			client->pkt_offset = 0;
		}

		if (count >= client->pkt_expect) {
			memcpy(client->pkt_data + client->pkt_len,
						ptr, client->pkt_expect);
			ptr += client->pkt_expect;
			count -= client->pkt_expect;

			btdev_receive_h4(client->btdev, client->pkt_data,
					client->pkt_len + client->pkt_expect);

			free(client->pkt_data);
			client->pkt_data = NULL;
		} else {
			memcpy(client->pkt_data + client->pkt_len, ptr, count);
			client->pkt_len += count;
			client->pkt_expect -= count;
			count = 0;
		}
	}
}

static int accept_client(int fd)
{
	struct sockaddr_un addr;
	socklen_t len;
	int nfd;

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);

	if (getsockname(fd, (struct sockaddr *) &addr, &len) < 0) {
		perror("Failed to get socket name");
		return -1;
	}

	printf("Request for %s\n", addr.sun_path);

	nfd = accept(fd, (struct sockaddr *) &addr, &len);
	if (nfd < 0) {
		perror("Failed to accept client socket");
		return -1;
	}

	return nfd;
}

static void server_accept_callback(int fd, uint32_t events, void *user_data)
{
	struct server *server = user_data;
	struct client *client;

	if (events & (EPOLLERR | EPOLLHUP))
		return;

	client = malloc(sizeof(*client));
	if (!client)
		return;

	memset(client, 0, sizeof(*client));

	client->fd = accept_client(server->fd);
	if (client->fd < 0) {
		free(client);
		return;
	}

	client->btdev = btdev_create(server->id);
	if (!client->btdev) {
		close(client->fd);
		free(client);
		return;
	}

	btdev_set_send_handler(client->btdev, client_write_callback, client);

	if (mainloop_add_fd(client->fd, EPOLLIN, client_read_callback,
						client, client_destroy) < 0) {
		btdev_destroy(client->btdev);
		close(client->fd);
		free(client);
	}
}

static int open_server(const char *path)
{
	struct sockaddr_un addr;
	int fd;

	unlink(path);

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("Failed to open server socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to bind server socket");
		close(fd);
		return -1;
	}

	if (listen(fd, 5) < 0) {
		perror("Failed to listen server socket");
		close(fd);
		return -1;
	}

	return fd;
}

struct server *server_open_unix(const char *path, uint16_t id)
{
	struct server *server;

	server = malloc(sizeof(*server));
	if (!server)
		return NULL;

	memset(server, 0, sizeof(*server));
	server->id = id;

	server->fd = open_server(path);
	if (server->fd < 0) {
		free(server);
		return NULL;
	}

	if (mainloop_add_fd(server->fd, EPOLLIN, server_accept_callback,
						server, server_destroy) < 0) {
		close(server->fd);
		free(server);
		return NULL;
	}

	return server;
}

void server_close(struct server *server)
{
	if (!server)
		return;

	mainloop_remove_fd(server->fd);
}
