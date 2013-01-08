/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
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
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/mgmt.h>

#include "log.h"
#include "adapter.h"
#include "device.h"
#include "eir.h"
#include "storage.h"
#include "mgmt.h"

#define MGMT_BUF_SIZE 1024

static int mgmt_sock = -1;
static guint mgmt_watch = 0;

static bool get_adapter_and_device(uint16_t index,
					struct mgmt_addr_info *addr,
					struct btd_adapter **adapter,
					struct btd_device **device,
					bool create)
{
	char peer_addr[18];

	*adapter = adapter_find_by_id(index);
	if (!*adapter) {
		error("Unable to find matching adapter");
		return false;
	}

	ba2str(&addr->bdaddr, peer_addr);

	if (create)
		*device = adapter_get_device(*adapter, peer_addr, addr->type);
	else
		*device = adapter_find_device(*adapter, peer_addr);

	if (create && !*device) {
		error("Unable to get device object!");
		return false;
	}

	return true;
}

int mgmt_passkey_reply(int index, const bdaddr_t *bdaddr, uint8_t bdaddr_type,
							uint32_t passkey)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_user_passkey_reply)];
	struct mgmt_hdr *hdr = (void *) buf;
	size_t buf_len;
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("index %d addr %s passkey %06u", index, addr, passkey);

	memset(buf, 0, sizeof(buf));

	hdr->index = htobs(index);
	if (passkey == INVALID_PASSKEY) {
		struct mgmt_cp_user_passkey_neg_reply *cp;

		hdr->opcode = htobs(MGMT_OP_USER_PASSKEY_NEG_REPLY);
		hdr->len = htobs(sizeof(*cp));

		cp = (void *) &buf[sizeof(*hdr)];
		bacpy(&cp->addr.bdaddr, bdaddr);
		cp->addr.type = bdaddr_type;

		buf_len = sizeof(*hdr) + sizeof(*cp);
	} else {
		struct mgmt_cp_user_passkey_reply *cp;

		hdr->opcode = htobs(MGMT_OP_USER_PASSKEY_REPLY);
		hdr->len = htobs(sizeof(*cp));

		cp = (void *) &buf[sizeof(*hdr)];
		bacpy(&cp->addr.bdaddr, bdaddr);
		cp->addr.type = bdaddr_type;
		cp->passkey = htobl(passkey);

		buf_len = sizeof(*hdr) + sizeof(*cp);
	}

	if (write(mgmt_sock, buf, buf_len) < 0)
		return -errno;

	return 0;
}

static void mgmt_passkey_request(uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_user_passkey_request *ev = buf;
	struct btd_adapter *adapter;
	struct btd_device *device;
	char addr[18];
	int err;

	if (len < sizeof(*ev)) {
		error("Too small passkey_request event");
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);

	DBG("hci%u %s", index, addr);

	if (!get_adapter_and_device(index, &ev->addr, &adapter, &device, true))
		return;

	err = device_request_passkey(device);
	if (err < 0) {
		error("device_request_passkey: %s", strerror(-err));
		mgmt_passkey_reply(index, &ev->addr.bdaddr, ev->addr.type,
							INVALID_PASSKEY);
	}
}

static void mgmt_passkey_notify(uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_passkey_notify *ev = buf;
	struct btd_adapter *adapter;
	struct btd_device *device;
	uint32_t passkey;
	char addr[18];
	int err;

	if (len < sizeof(*ev)) {
		error("Too small passkey_notify event");
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);

	DBG("hci%u %s", index, addr);

	if (!get_adapter_and_device(index, &ev->addr, &adapter, &device, true))
		return;

	passkey = bt_get_le32(&ev->passkey);

	DBG("passkey %06u entered %u", passkey, ev->entered);

	err = device_notify_passkey(device, passkey, ev->entered);
	if (err < 0)
		error("device_notify_passkey: %s", strerror(-err));
}

static void mgmt_cmd_complete(uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_cmd_complete *ev = buf;
	uint16_t opcode;

	if (len < sizeof(*ev)) {
		error("Too small management command complete event packet");
		return;
	}

	opcode = bt_get_le16(&ev->opcode);

	len -= sizeof(*ev);

	DBG("%s (0x%04x) status 0x%02x len %zu", mgmt_opstr(opcode), opcode,
							ev->status, len);
}

static void mgmt_cmd_status(uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_cmd_status *ev = buf;
	uint16_t opcode;

	if (len < sizeof(*ev)) {
		error("Too small management command status event packet");
		return;
	}

	opcode = bt_get_le16(&ev->opcode);

	DBG("hci%u: %s (0x%04x) status: %s (0x%02x)", index,
			mgmt_opstr(opcode), opcode, mgmt_errstr(ev->status),
			ev->status);
}

static gboolean mgmt_event(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	char buf[MGMT_BUF_SIZE];
	struct mgmt_hdr *hdr = (void *) buf;
	ssize_t ret;
	uint16_t len, opcode, index;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		error("Error on management socket");
		return FALSE;
	}

	ret = read(mgmt_sock, buf, sizeof(buf));
	if (ret < 0) {
		error("Unable to read from management socket: %s (%d)",
						strerror(errno), errno);
		return TRUE;
	}

	if (ret < MGMT_HDR_SIZE) {
		error("Too small Management packet");
		return TRUE;
	}

	opcode = bt_get_le16(&hdr->opcode);
	len = bt_get_le16(&hdr->len);
	index = bt_get_le16(&hdr->index);

	if (ret != MGMT_HDR_SIZE + len) {
		error("Packet length mismatch. ret %zd len %u", ret, len);
		return TRUE;
	}

	switch (opcode) {
	case MGMT_EV_CMD_COMPLETE:
		mgmt_cmd_complete(index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_CMD_STATUS:
		mgmt_cmd_status(index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_CONTROLLER_ERROR:
		DBG("controller_error event");
		break;
	case MGMT_EV_INDEX_ADDED:
		DBG("index_added event");
		break;
	case MGMT_EV_INDEX_REMOVED:
		DBG("index_removed event");
		break;
	case MGMT_EV_NEW_SETTINGS:
		DBG("new_settings event");
		break;
	case MGMT_EV_CLASS_OF_DEV_CHANGED:
		DBG("class_of_dev_changed event");
		break;
	case MGMT_EV_LOCAL_NAME_CHANGED:
		DBG("local_name_changed event");
		break;
	case MGMT_EV_NEW_LINK_KEY:
		DBG("new_link_key event");
		break;
	case MGMT_EV_DEVICE_CONNECTED:
		DBG("device_connected event");
		break;
	case MGMT_EV_DEVICE_DISCONNECTED:
		DBG("device_disconnected event");
		break;
	case MGMT_EV_CONNECT_FAILED:
		DBG("connect_failed event");
		break;
	case MGMT_EV_PIN_CODE_REQUEST:
		DBG("pin_code_request event");
		break;
	case MGMT_EV_USER_CONFIRM_REQUEST:
		DBG("user_confirm_request event");
		break;
	case MGMT_EV_AUTH_FAILED:
		DBG("auth_failed event");
		break;
	case MGMT_EV_DEVICE_FOUND:
		DBG("device_found event");
		break;
	case MGMT_EV_DISCOVERING:
		DBG("discovering event");
		break;
	case MGMT_EV_DEVICE_BLOCKED:
		DBG("device_blocked event");
		break;
	case MGMT_EV_DEVICE_UNBLOCKED:
		DBG("device_unblocked event");
		break;
	case MGMT_EV_DEVICE_UNPAIRED:
		DBG("device_unpaired event");
		break;
	case MGMT_EV_USER_PASSKEY_REQUEST:
		mgmt_passkey_request(index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_PASSKEY_NOTIFY:
		mgmt_passkey_notify(index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_NEW_LONG_TERM_KEY:
		DBG("new_long_term_key event");
		break;
	default:
		error("Unknown Management opcode %u (index %u)", opcode, index);
		break;
	}

	return TRUE;
}

int mgmt_setup(void)
{
	struct mgmt_hdr hdr;
	struct sockaddr_hci addr;
	GIOChannel *io;
	GIOCondition condition;
	int dd, err;

	dd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (dd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	addr.hci_channel = HCI_CHANNEL_CONTROL;

	if (bind(dd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = -errno;
		goto fail;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = htobs(MGMT_OP_READ_INDEX_LIST);
	hdr.index = htobs(MGMT_INDEX_NONE);
	if (write(dd, &hdr, sizeof(hdr)) < 0) {
		err = -errno;
		goto fail;
	}

	io = g_io_channel_unix_new(dd);
	condition = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	mgmt_watch = g_io_add_watch(io, condition, mgmt_event, NULL);
	g_io_channel_unref(io);

	mgmt_sock = dd;

	return 0;

fail:
	close(dd);
	return err;
}

void mgmt_cleanup(void)
{
	if (mgmt_sock >= 0) {
		close(mgmt_sock);
		mgmt_sock = -1;
	}

	if (mgmt_watch > 0) {
		g_source_remove(mgmt_watch);
		mgmt_watch = 0;
	}
}
