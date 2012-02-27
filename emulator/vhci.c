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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "mainloop.h"
#include "btdev.h"
#include "vhci.h"

struct vhci {
	enum vhci_type type;
	int fd;
	struct btdev *btdev;
};

static void vhci_destroy(void *user_data)
{
	struct vhci *vhci = user_data;

	btdev_destroy(vhci->btdev);

	close(vhci->fd);

	free(vhci);
}

static void vhci_write_callback(const void *data, uint16_t len, void *user_data)
{
	struct vhci *vhci = user_data;
	ssize_t written;

	written = write(vhci->fd, data, len);
	if (written < 0)
		return;
}

static void vhci_read_callback(int fd, uint32_t events, void *user_data)
{
	struct vhci *vhci = user_data;
	unsigned char buf[4096];
	ssize_t len;

	if (events & (EPOLLERR | EPOLLHUP))
		return;

	len = read(vhci->fd, buf, sizeof(buf));
	if (len < 0)
		return;

	btdev_receive_h4(vhci->btdev, buf, len);
}

struct vhci *vhci_open(enum vhci_type type, uint16_t id)
{
	struct vhci *vhci;

	switch (type) {
	case VHCI_TYPE_BREDR:
		break;
	case VHCI_TYPE_AMP:
		return NULL;
	}

	vhci = malloc(sizeof(*vhci));
	if (!vhci)
		return NULL;

	memset(vhci, 0, sizeof(*vhci));
	vhci->type = type;

	vhci->fd = open("/dev/vhci", O_RDWR | O_NONBLOCK);
	if (vhci->fd < 0) {
		free(vhci);
		return NULL;
	}

	vhci->btdev = btdev_create(id);
	if (!vhci->btdev) {
		close(vhci->fd);
		free(vhci);
		return NULL;
	}

	btdev_set_send_handler(vhci->btdev, vhci_write_callback, vhci);

	if (mainloop_add_fd(vhci->fd, EPOLLIN, vhci_read_callback,
						vhci, vhci_destroy) < 0) {
		btdev_destroy(vhci->btdev);
		close(vhci->fd);
		free(vhci);
		return NULL;
	}

	return vhci;
}

void vhci_close(struct vhci *vhci)
{
	if (!vhci)
		return;

	mainloop_remove_fd(vhci->fd);
}
