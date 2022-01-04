// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
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
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"

#include "src/shared/io.h"
#include "monitor/bt.h"
#include "btdev.h"
#include "vhci.h"

#define DEBUGFS_PATH "/sys/kernel/debug/bluetooth"

struct vhci {
	enum btdev_type type;
	uint16_t index;
	struct io *io;
	struct btdev *btdev;
};

static void vhci_destroy(void *user_data)
{
	struct vhci *vhci = user_data;

	btdev_destroy(vhci->btdev);
	io_destroy(vhci->io);

	free(vhci);
}

static void vhci_write_callback(const struct iovec *iov, int iovlen,
							void *user_data)
{
	struct vhci *vhci = user_data;
	ssize_t written;

	written = io_send(vhci->io, iov, iovlen);
	if (written < 0)
		return;
}

static bool vhci_read_callback(struct io *io, void *user_data)
{
	struct vhci *vhci = user_data;
	int fd = io_get_fd(vhci->io);
	unsigned char buf[4096];
	ssize_t len;

	len = read(fd, buf, sizeof(buf));
	if (len < 1)
		return false;

	switch (buf[0]) {
	case BT_H4_CMD_PKT:
	case BT_H4_ACL_PKT:
	case BT_H4_SCO_PKT:
	case BT_H4_ISO_PKT:
		btdev_receive_h4(vhci->btdev, buf, len);
		break;
	}

	return true;
}

bool vhci_set_debug(struct vhci *vhci, vhci_debug_func_t callback,
			void *user_data, vhci_destroy_func_t destroy)
{
	if (!vhci)
		return false;

	return btdev_set_debug(vhci->btdev, callback, user_data, destroy);
}

struct vhci_create_req {
	uint8_t  pkt_type;
	uint8_t  opcode;
} __attribute__((packed));

struct vhci_create_rsp {
	uint8_t  pkt_type;
	uint8_t  opcode;
	uint16_t index;
} __attribute__((packed));

struct vhci *vhci_open(uint8_t type)
{
	struct vhci *vhci;
	struct vhci_create_req req;
	struct vhci_create_rsp rsp;
	int fd;

	fd = open("/dev/vhci", O_RDWR | O_NONBLOCK);
	if (fd < 0)
		return NULL;

	memset(&req, 0, sizeof(req));
	req.pkt_type = HCI_VENDOR_PKT;

	switch (type) {
	case BTDEV_TYPE_AMP:
		req.opcode = HCI_AMP;
		break;
	default:
		req.opcode = HCI_PRIMARY;
		break;
	}

	if (write(fd, &req, sizeof(req)) < 0) {
		close(fd);
		return NULL;
	}

	memset(&rsp, 0, sizeof(rsp));

	if (read(fd, &rsp, sizeof(rsp)) < 0) {
		close(fd);
		return NULL;
	}

	vhci = malloc(sizeof(*vhci));
	if (!vhci) {
		close(fd);
		return NULL;
	}

	memset(vhci, 0, sizeof(*vhci));
	vhci->type = type;
	vhci->index = rsp.index;
	vhci->io = io_new(fd);

	io_set_close_on_destroy(vhci->io, true);

	vhci->btdev = btdev_create(type, rsp.index);
	if (!vhci->btdev) {
		vhci_destroy(vhci);
		return NULL;
	}

	btdev_set_send_handler(vhci->btdev, vhci_write_callback, vhci);

	if (!io_set_read_handler(vhci->io, vhci_read_callback, vhci, NULL)) {
		vhci_destroy(vhci);
		return NULL;
	}

	return vhci;
}

void vhci_close(struct vhci *vhci)
{
	if (!vhci)
		return;

	vhci_destroy(vhci);
}

struct btdev *vhci_get_btdev(struct vhci *vhci)
{
	if (!vhci)
		return NULL;

	return vhci->btdev;
}

static int vhci_debugfs_write(struct vhci *vhci, char *option, void *data,
			      size_t len)
{
	char path[64];
	int fd, err;
	size_t n;

	if (!vhci)
		return -EINVAL;

	memset(path, 0, sizeof(path));
	sprintf(path, DEBUGFS_PATH "/hci%d/%s", vhci->index, option);

	fd = open(path, O_RDWR);
	if (fd < 0)
		return -errno;

	n = write(fd, data, len);
	if (n == len)
		err = 0;
	else
		err = -errno;

	close(fd);

	return err;
}

int vhci_set_force_suspend(struct vhci *vhci, bool enable)
{
	char val;

	val = (enable) ? 'Y' : 'N';

	return vhci_debugfs_write(vhci, "force_suspend", &val, sizeof(val));
}

int vhci_set_force_wakeup(struct vhci *vhci, bool enable)
{
	char val;

	val = (enable) ? 'Y' : 'N';

	return vhci_debugfs_write(vhci, "force_wakeup", &val, sizeof(val));
}

int vhci_set_msft_opcode(struct vhci *vhci, uint16_t opcode)
{
	int err;
	char val[7];

	snprintf(val, sizeof(val), "0x%4x", opcode);

	err = vhci_debugfs_write(vhci, "msft_opcode", &val, sizeof(val));
	if (err)
		return err;

	return btdev_set_msft_opcode(vhci->btdev, opcode);
}

int vhci_set_aosp_capable(struct vhci *vhci, bool enable)
{
	char val;

	val = (enable) ? 'Y' : 'N';

	return vhci_debugfs_write(vhci, "aosp_capable", &val, sizeof(val));
}

int vhci_set_emu_opcode(struct vhci *vhci, uint16_t opcode)
{
	return btdev_set_emu_opcode(vhci->btdev, opcode);
}
