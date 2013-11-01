/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <glib.h>

#include "btio/btio.h"
#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "lib/uuid.h"
#include "src/shared/mgmt.h"
#include "src/sdp-client.h"
#include "src/glib-helper.h"
#include "profiles/input/uhid_copy.h"

#include "log.h"
#include "hal-msg.h"
#include "ipc.h"
#include "hid.h"
#include "adapter.h"
#include "utils.h"

#define L2CAP_PSM_HIDP_CTRL	0x11
#define L2CAP_PSM_HIDP_INTR	0x13
#define UHID_DEVICE_FILE	"/dev/uhid"

static GIOChannel *notification_io = NULL;
static GIOChannel *ctrl_io = NULL;
static GIOChannel *intr_io = NULL;
static GSList *devices = NULL;

struct hid_device {
	bdaddr_t	dst;
	uint8_t		state;
	uint16_t	vendor;
	uint16_t	product;
	uint16_t	version;
	uint8_t		country;
	int		rd_size;
	void		*rd_data;
	GIOChannel	*ctrl_io;
	GIOChannel	*intr_io;
	guint		ctrl_watch;
	guint		intr_watch;
	int		uhid_fd;
	guint		uhid_watch_id;
};

static int device_cmp(gconstpointer s, gconstpointer user_data)
{
	const struct hid_device *dev = s;
	const bdaddr_t *dst = user_data;

	return bacmp(&dev->dst, dst);
}

static void uhid_destroy(int fd)
{
	struct uhid_event ev;

	/* destroy uHID device */
	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_DESTROY;

	if (write(fd, &ev, sizeof(ev)) < 0)
		error("Failed to destroy uHID device: %s (%d)",
						strerror(errno), errno);

	close(fd);
}

static void hid_device_free(struct hid_device *dev)
{
	if (dev->ctrl_watch > 0)
		g_source_remove(dev->ctrl_watch);

	if (dev->intr_watch > 0)
		g_source_remove(dev->intr_watch);

	if (dev->intr_io)
		g_io_channel_unref(dev->intr_io);

	if (dev->ctrl_io)
		g_io_channel_unref(dev->ctrl_io);

	if (dev->uhid_watch_id) {
		g_source_remove(dev->uhid_watch_id);
		dev->uhid_watch_id = 0;
	}

	if (dev->uhid_fd > 0)
		uhid_destroy(dev->uhid_fd);

	g_free(dev->rd_data);

	devices = g_slist_remove(devices, dev);
	g_free(dev);
}

static gboolean uhid_event_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct hid_device *dev = user_data;
	struct uhid_event ev;
	ssize_t bread;
	int fd;

	DBG("");

	if (cond & (G_IO_ERR | G_IO_NVAL))
		goto failed;

	fd = g_io_channel_unix_get_fd(io);
	memset(&ev, 0, sizeof(ev));

	bread = read(fd, &ev, sizeof(ev));
	if (bread < 0) {
		DBG("read: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	DBG("uHID event type %d received", ev.type);
	/* TODO Handle events */

	return TRUE;

failed:
	dev->uhid_watch_id = 0;
	return FALSE;
}

static gboolean intr_io_watch_cb(GIOChannel *chan, gpointer data)
{
	struct hid_device *dev = data;
	uint8_t buf[UHID_DATA_MAX];
	struct uhid_event ev;
	int fd, bread;

	/* Wait uHID if not ready */
	if (dev->uhid_fd < 0)
		return TRUE;

	fd = g_io_channel_unix_get_fd(chan);
	bread = read(fd, buf, sizeof(buf));
	if (bread < 0) {
		error("read: %s(%d)", strerror(errno), -errno);
		return TRUE;
	}

	/* Discard non-data packets */
	if (bread == 0 || buf[0] != 0xA1)
		return TRUE;

	/* send data to uHID device skipping HIDP header byte */
	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_INPUT;
	ev.u.input.size = bread - 1;
	memcpy(ev.u.input.data, &buf[1], ev.u.input.size);

	if (write(dev->uhid_fd, &ev, sizeof(ev)) < 0)
		DBG("write: %s (%d)", strerror(errno), errno);

	return TRUE;
}

static void bt_hid_set_state(struct hid_device *dev, uint8_t state)
{
	struct hal_ev_hid_conn_state ev;
	char address[18];

	if (dev->state == state)
		return;

	dev->state = state;

	ba2str(&dev->dst, address);
	DBG("device %s state %u", address, state);

	bdaddr2android(&dev->dst, ev.bdaddr);
	ev.state = state;

	ipc_send(notification_io, HAL_SERVICE_ID_HIDHOST,
				HAL_EV_HID_CONN_STATE, sizeof(ev), &ev, -1);
}

static gboolean intr_watch_cb(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	struct hid_device *dev = data;

	if (cond & G_IO_IN)
		return intr_io_watch_cb(chan, data);

	/* Checking for ctrl_watch avoids a double g_io_channel_shutdown since
	 * it's likely that ctrl_watch_cb has been queued for dispatching in
	 * this mainloop iteration */
	if ((cond & (G_IO_HUP | G_IO_ERR)) && dev->ctrl_watch)
		g_io_channel_shutdown(chan, TRUE, NULL);

	dev->intr_watch = 0;

	if (dev->intr_io) {
		g_io_channel_unref(dev->intr_io);
		dev->intr_io = NULL;
	}

	/* Close control channel */
	if (dev->ctrl_io && !(cond & G_IO_NVAL))
		g_io_channel_shutdown(dev->ctrl_io, TRUE, NULL);

	return FALSE;
}

static gboolean ctrl_watch_cb(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	struct hid_device *dev = data;
	char address[18];

	ba2str(&dev->dst, address);
	bt_hid_set_state(dev, HAL_HID_STATE_DISCONNECTED);

	/* Checking for intr_watch avoids a double g_io_channel_shutdown since
	 * it's likely that intr_watch_cb has been queued for dispatching in
	 * this mainloop iteration */
	if ((cond & (G_IO_HUP | G_IO_ERR)) && dev->intr_watch)
		g_io_channel_shutdown(chan, TRUE, NULL);

	if (dev->intr_io && !(cond & G_IO_NVAL))
		g_io_channel_shutdown(dev->intr_io, TRUE, NULL);

	hid_device_free(dev);

	return FALSE;
}

static int uhid_create(struct hid_device *dev)
{
	GIOCondition cond = G_IO_IN | G_IO_ERR | G_IO_NVAL;
	GIOChannel *io;
	struct uhid_event ev;

	dev->uhid_fd = open(UHID_DEVICE_FILE, O_RDWR | O_CLOEXEC);
	if (dev->uhid_fd < 0) {
		error("Failed to open uHID device: %s", strerror(errno));
		return -errno;
	}

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_CREATE;
	strcpy((char *) ev.u.create.name, "bluez-input-device");
	ev.u.create.bus = BUS_BLUETOOTH;
	ev.u.create.vendor = dev->vendor;
	ev.u.create.product = dev->product;
	ev.u.create.version = dev->version;
	ev.u.create.country = dev->country;
	ev.u.create.rd_size = dev->rd_size;
	ev.u.create.rd_data = dev->rd_data;

	if (write(dev->uhid_fd, &ev, sizeof(ev)) < 0) {
		error("Failed to create uHID device: %s", strerror(errno));
		close(dev->uhid_fd);
		dev->uhid_fd = -1;
		return -errno;
	}

	io = g_io_channel_unix_new(dev->uhid_fd);
	g_io_channel_set_encoding(io, NULL, NULL);
	dev->uhid_watch_id = g_io_add_watch(io, cond, uhid_event_cb, dev);
	g_io_channel_unref(io);

	return 0;
}

static void interrupt_connect_cb(GIOChannel *chan, GError *conn_err,
							gpointer user_data)
{
	struct hid_device *dev = user_data;

	DBG("");

	if (conn_err)
		goto failed;

	if (uhid_create(dev) < 0)
		goto failed;

	dev->intr_watch = g_io_add_watch(dev->intr_io,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				intr_watch_cb, dev);

	bt_hid_set_state(dev, HAL_HID_STATE_CONNECTED);

	return;

failed:
	/* So we guarantee the interrupt channel is closed before the
	 * control channel (if we only do unref GLib will close it only
	 * after returning control to the mainloop */
	if (!conn_err)
		g_io_channel_shutdown(dev->intr_io, FALSE, NULL);

	g_io_channel_unref(dev->intr_io);
	dev->intr_io = NULL;

	if (dev->ctrl_io) {
		g_io_channel_unref(dev->ctrl_io);
		dev->ctrl_io = NULL;
	}
}

static void control_connect_cb(GIOChannel *chan, GError *conn_err,
							gpointer user_data)
{
	struct hid_device *dev = user_data;
	GError *err = NULL;
	const bdaddr_t *src = bt_adapter_get_address();

	DBG("");

	if (conn_err) {
		bt_hid_set_state(dev, HAL_HID_STATE_DISCONNECTED);
		error("%s", conn_err->message);
		goto failed;
	}

	/* Connect to the HID interrupt channel */
	dev->intr_io = bt_io_connect(interrupt_connect_cb, dev, NULL, &err,
					BT_IO_OPT_SOURCE_BDADDR, src,
					BT_IO_OPT_DEST_BDADDR, &dev->dst,
					BT_IO_OPT_PSM, L2CAP_PSM_HIDP_INTR,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);
	if (!dev->intr_io) {
		error("%s", err->message);
		g_error_free(err);
		goto failed;
	}

	dev->ctrl_watch = g_io_add_watch(dev->ctrl_io,
					G_IO_HUP | G_IO_ERR | G_IO_NVAL,
					ctrl_watch_cb, dev);

	return;

failed:
	hid_device_free(dev);
}

static void hid_sdp_search_cb(sdp_list_t *recs, int err, gpointer data)
{
	struct hid_device *dev = data;
	sdp_list_t *list;
	GError *gerr = NULL;
	const bdaddr_t *src = bt_adapter_get_address();

	DBG("");

	if (err < 0) {
		error("Unable to get SDP record: %s", strerror(-err));
		goto fail;
	}

	if (!recs || !recs->data) {
		error("No SDP records found");
		goto fail;
	}

	for (list = recs; list != NULL; list = list->next) {
		sdp_record_t *rec = list->data;
		sdp_data_t *data;

		data = sdp_data_get(rec, SDP_ATTR_VENDOR_ID);
		if (data)
			dev->vendor = data->val.uint16;

		data = sdp_data_get(rec, SDP_ATTR_PRODUCT_ID);
		if (data)
			dev->product = data->val.uint16;

		data = sdp_data_get(rec, SDP_ATTR_VERSION);
		if (data)
			dev->version = data->val.uint16;

		data = sdp_data_get(rec, SDP_ATTR_HID_COUNTRY_CODE);
		if (data)
			dev->country = data->val.uint8;

		data = sdp_data_get(rec, SDP_ATTR_HID_DESCRIPTOR_LIST);
		if (data) {
			if (!SDP_IS_SEQ(data->dtd))
				goto fail;

			/* First HIDDescriptor */
			data = data->val.dataseq;
			if (!SDP_IS_SEQ(data->dtd))
				goto fail;

			/* ClassDescriptorType */
			data = data->val.dataseq;
			if (data->dtd != SDP_UINT8)
				goto fail;

			/* ClassDescriptorData */
			data = data->next;
			if (!data || !SDP_IS_TEXT_STR(data->dtd))
				goto fail;

			dev->rd_size = data->unitSize;
			dev->rd_data = g_memdup(data->val.str, data->unitSize);
		}
	}

	if (dev->ctrl_io) {
		if (uhid_create(dev) < 0)
			goto fail;
		return;
	}

	dev->ctrl_io = bt_io_connect(control_connect_cb, dev, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, src,
					BT_IO_OPT_DEST_BDADDR, &dev->dst,
					BT_IO_OPT_PSM, L2CAP_PSM_HIDP_CTRL,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);
	if (gerr) {
		error("%s", gerr->message);
		g_error_free(gerr);
		goto fail;
	}

	return;

fail:
	bt_hid_set_state(dev, HAL_HID_STATE_DISCONNECTED);
	hid_device_free(dev);
}

static uint8_t bt_hid_connect(struct hal_cmd_hid_connect *cmd, uint16_t len)
{
	struct hid_device *dev;
	char addr[18];
	bdaddr_t dst;
	GSList *l;
	const bdaddr_t *src = bt_adapter_get_address();
	uuid_t uuid;

	DBG("");

	if (len < sizeof(*cmd))
		return HAL_STATUS_INVALID;

	android2bdaddr(&cmd->bdaddr, &dst);

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (l)
		return HAL_STATUS_FAILED;

	dev = g_new0(struct hid_device, 1);
	bacpy(&dev->dst, &dst);
	dev->uhid_fd = -1;

	ba2str(&dev->dst, addr);
	DBG("connecting to %s", addr);

	bt_string2uuid(&uuid, HID_UUID);
	if (bt_search_service(src, &dev->dst, &uuid, hid_sdp_search_cb, dev,
								NULL) < 0) {
		error("Failed to search sdp details");
		hid_device_free(dev);
		return HAL_STATUS_FAILED;
	}

	devices = g_slist_append(devices, dev);
	bt_hid_set_state(dev, HAL_HID_STATE_CONNECTING);

	return HAL_STATUS_SUCCESS;
}

static uint8_t bt_hid_disconnect(struct hal_cmd_hid_disconnect *cmd,
								uint16_t len)
{
	struct hid_device *dev;
	GSList *l;
	bdaddr_t dst;

	DBG("");

	if (len < sizeof(*cmd))
		return HAL_STATUS_INVALID;

	android2bdaddr(&cmd->bdaddr, &dst);

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (!l)
		return HAL_STATUS_FAILED;

	dev = l->data;

	/* Wait either channels to HUP */
	if (dev->intr_io)
		g_io_channel_shutdown(dev->intr_io, TRUE, NULL);

	if (dev->ctrl_io)
		g_io_channel_shutdown(dev->ctrl_io, TRUE, NULL);

	bt_hid_set_state(dev, HAL_HID_STATE_DISCONNECTING);

	return HAL_STATUS_SUCCESS;
}

void bt_hid_handle_cmd(GIOChannel *io, uint8_t opcode, void *buf, uint16_t len)
{
	uint8_t status = HAL_STATUS_FAILED;

	switch (opcode) {
	case HAL_OP_HID_CONNECT:
		status = bt_hid_connect(buf, len);
		break;
	case HAL_OP_HID_DISCONNECT:
		status = bt_hid_disconnect(buf, len);
		break;
	default:
		DBG("Unhandled command, opcode 0x%x", opcode);
		break;
	}

	ipc_send_rsp(io, HAL_SERVICE_ID_HIDHOST, status);
}

static void connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct hid_device *dev;
	bdaddr_t dst;
	char address[18];
	uint16_t psm;
	GError *gerr = NULL;
	GSList *l;
	const bdaddr_t *src = bt_adapter_get_address();
	uuid_t uuid;

	if (err) {
		error("%s", err->message);
		return;
	}

	bt_io_get(chan, &err,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_PSM, &psm,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", gerr->message);
		g_io_channel_shutdown(chan, TRUE, NULL);
		return;
	}

	ba2str(&dst, address);
	DBG("Incoming connection from %s on PSM %d", address, psm);

	switch (psm) {
	case L2CAP_PSM_HIDP_CTRL:
		l = g_slist_find_custom(devices, &dst, device_cmp);
		if (l)
			return;

		dev = g_new0(struct hid_device, 1);
		bacpy(&dev->dst, &dst);
		dev->ctrl_io = g_io_channel_ref(chan);
		dev->uhid_fd = -1;

		bt_string2uuid(&uuid, HID_UUID);
		if (bt_search_service(src, &dev->dst, &uuid,
					hid_sdp_search_cb, dev, NULL) < 0) {
			error("failed to search sdp details");
			hid_device_free(dev);
			return;
		}

		devices = g_slist_append(devices, dev);

		dev->ctrl_watch = g_io_add_watch(dev->ctrl_io,
					G_IO_HUP | G_IO_ERR | G_IO_NVAL,
					ctrl_watch_cb, dev);
		bt_hid_set_state(dev, HAL_HID_STATE_CONNECTING);
		break;

	case L2CAP_PSM_HIDP_INTR:
		l = g_slist_find_custom(devices, &dst, device_cmp);
		if (!l)
			return;

		dev = l->data;
		dev->intr_io = g_io_channel_ref(chan);
		dev->intr_watch = g_io_add_watch(dev->intr_io,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				intr_watch_cb, dev);
		bt_hid_set_state(dev, HAL_HID_STATE_CONNECTED);
		break;
	}
}

bool bt_hid_register(GIOChannel *io, const bdaddr_t *addr)
{
	GError *err = NULL;

	DBG("");

	notification_io = g_io_channel_ref(io);

	ctrl_io = bt_io_listen(connect_cb, NULL, NULL, NULL, &err,
				BT_IO_OPT_PSM, L2CAP_PSM_HIDP_CTRL,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);
	if (!ctrl_io) {
		error("Failed to listen on ctrl channel: %s", err->message);
		g_error_free(err);
		return false;
	}

	intr_io = bt_io_listen(connect_cb, NULL, NULL, NULL, &err,
				BT_IO_OPT_PSM, L2CAP_PSM_HIDP_INTR,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);
	if (!intr_io) {
		error("Failed to listen on intr channel: %s", err->message);
		g_io_channel_unref(ctrl_io);
		g_error_free(err);
		return false;
	}

	return true;
}

void bt_hid_unregister(void)
{
	DBG("");

	g_io_channel_unref(notification_io);
	notification_io = NULL;

	if (ctrl_io) {
		g_io_channel_shutdown(ctrl_io, TRUE, NULL);
		g_io_channel_unref(ctrl_io);
		ctrl_io = NULL;
	}

	if (intr_io) {
		g_io_channel_shutdown(intr_io, TRUE, NULL);
		g_io_channel_unref(intr_io);
		intr_io = NULL;
	}
}
